//! `factorseal wsl-keyring`: `org.freedesktop.secrets` in a WSL distro,
//! served by the FactorSeal vault on Windows.
//!
//! The collection is the distro's keyring in the Windows vault, reached
//! through the WSL broker that `wsl-setup` configured. Each program's access
//! is approved in FactorSeal Desktop's popup, for the program this host
//! resolves and declares (the vault cannot see it), and lasts until the
//! vault seals. The distro must be switched on in Desktop (Settings → WSL
//! keyrings), which grants the broker its keyring.
//!
//! While the vault is sealed the collection reports locked; a client's
//! unlock brings Desktop forward and installs the collection once the vault
//! is unsealed. While installed, the vault's state is checked by its idle
//! deadline (a `Status` does not extend the lease) and whenever a request
//! finds the vault sealed. Those checks never bring Desktop forward
//! (`relay --no-desktop`); only a client's request or unlock does.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use factorseal::{
    SecretServiceHost, SecretServiceHostOptions, SecretServicePrompter, VaultAction, VaultClient,
    VaultError, VaultRequest, VaultResponse, VaultResponseBody, VaultResponseErrorCode,
    VaultResult,
};

use super::CliError;
use super::wsl::WslConfig;

/// How long the host waits; shorter in tests.
#[derive(Clone, Copy, Debug)]
struct Timing {
    /// Longest wait between checks of an unsealed vault, so a seal from
    /// Desktop shows as locked within this time even without a request.
    max_check: Duration,
    /// How long an unlock request waits for the person to unseal the vault.
    unlock_wait: Duration,
    unlock_poll: Duration,
    /// First wait before trying again a keyring that is not available
    /// (switched off in Desktop, or not installed); it doubles each time,
    /// up to `max_retry`, and a client's unlock tries at once.
    first_retry: Duration,
    max_retry: Duration,
}

const TIMING: Timing = Timing {
    max_check: Duration::from_secs(30),
    unlock_wait: Duration::from_mins(2),
    unlock_poll: Duration::from_secs(1),
    first_retry: Duration::from_secs(30),
    max_retry: Duration::from_mins(10),
};

/// Why the host loop wakes up early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// A client asked to unlock the collection.
    Unlock,
    /// A request found the vault sealed.
    Sealed,
    /// The vault refused the host's own read of the keyring's index without
    /// asking anyone: the distro is switched off in Desktop.
    Unavailable,
}

/// What a `Status` through the broker says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observed {
    Unsealed { idle_deadline: u64 },
    Sealed,
}

/// What the host does next.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Install,
    Uninstall,
    /// Check the vault again after this long, or on a wake.
    Check(Duration),
    /// Report locked until a client asks to unlock.
    AwaitUnlock,
}

fn next(installed: bool, observed: Observed, now: u64, max_check: Duration) -> Next {
    match (observed, installed) {
        (Observed::Unsealed { .. }, false) => Next::Install,
        (Observed::Unsealed { idle_deadline }, true) => Next::Check(
            Duration::from_secs(idle_deadline.saturating_sub(now).saturating_add(1)).min(max_check),
        ),
        (Observed::Sealed, true) => Next::Uninstall,
        (Observed::Sealed, false) => Next::AwaitUnlock,
    }
}

fn is_sealed(result: &VaultResult<VaultResponse>) -> bool {
    match result {
        Ok(response) => response
            .result
            .as_ref()
            .is_err_and(|error| error.code == VaultResponseErrorCode::Sealed),
        Err(VaultError::Sealed | VaultError::AgentUnreachable(_)) => true,
        Err(_) => false,
    }
}

/// Whether the vault refused the host's own read of the keyring's index
/// outright: only the broker's host grant, which Desktop's switch gives and
/// takes, allows that read, and no approval can stand in for it.
fn is_unavailable(request: &VaultRequest, result: &VaultResult<VaultResponse>) -> bool {
    matches!(
        &request.action,
        VaultAction::Get { address, .. }
            if address.item == factorseal::vault::wsl_relay::SECRET_SERVICE_INDEX_ITEM
                && address.field.is_none()
    ) && matches!(
        result,
        Ok(VaultResponse { result: Err(error), .. })
            if error.code == VaultResponseErrorCode::AuthorizationRequired
                && error.interaction.is_none()
    )
}

/// The host's client: the broker, telling the loop when a request finds the
/// vault sealed or the keyring switched off.
struct HostClient {
    inner: Box<dyn VaultClient>,
    wake: Mutex<Sender<Wake>>,
}

impl VaultClient for HostClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        let result = self.inner.request(request);
        let wake = if is_sealed(&result) {
            Some(Wake::Sealed)
        } else if is_unavailable(request, &result) {
            Some(Wake::Unavailable)
        } else {
            None
        };
        if let Some(wake) = wake
            && let Ok(sender) = self.wake.lock()
        {
            let _ = sender.send(wake);
        }
        result
    }
}

/// A client's unlock wakes the loop; approvals happen in Desktop's popup.
struct WslPrompter {
    wake: Mutex<Sender<Wake>>,
}

impl SecretServicePrompter for WslPrompter {
    fn request_unlock(&self) {
        if let Ok(wake) = self.wake.lock() {
            let _ = wake.send(Wake::Unlock);
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The vault's state through `client`. Anything but an answer counts as
/// sealed; an unexpected error is reported once per kind of message.
fn observe(
    client: &dyn VaultClient,
    reported: &mut Option<String>,
    log: &mut dyn FnMut(String),
) -> Observed {
    let outcome =
        VaultRequest::new(VaultAction::Status).and_then(|request| client.request(&request));
    let problem = match outcome {
        Ok(VaultResponse {
            result: Ok(VaultResponseBody::Status { idle_deadline, .. }),
            ..
        }) => {
            *reported = None;
            return Observed::Unsealed { idle_deadline };
        }
        Ok(VaultResponse {
            result: Err(error), ..
        }) if error.code == VaultResponseErrorCode::Sealed => None,
        Ok(VaultResponse {
            result: Err(error), ..
        }) => Some(error.message),
        Ok(_) => Some("unexpected status answer".to_owned()),
        Err(VaultError::Sealed | VaultError::AgentUnreachable(_)) => None,
        Err(error) => Some(error.to_string()),
    };
    if let Some(problem) = problem
        && reported.as_ref() != Some(&problem)
    {
        log(format!("the Windows vault did not answer: {problem}"));
        *reported = Some(problem);
    }
    Observed::Sealed
}

/// Where the host's broker clients come from.
trait Brokers {
    /// For the host's own checks of the vault: never brings Desktop forward.
    fn monitor(&self) -> Result<Box<dyn VaultClient>, CliError>;
    /// On a client's behalf (the store, an unlock): brings Desktop forward
    /// when the vault is sealed or not running.
    fn client(&self) -> Result<Box<dyn VaultClient>, CliError>;
}

impl Brokers for WslConfig {
    fn monitor(&self) -> Result<Box<dyn VaultClient>, CliError> {
        Ok(Box::new(self.clone().monitor_client()?))
    }

    fn client(&self) -> Result<Box<dyn VaultClient>, CliError> {
        Ok(Box::new(self.clone().client()?))
    }
}

/// What the loop does with the Secret Service host.
trait Host {
    fn install(&self, client: Box<dyn VaultClient>) -> VaultResult<()>;
    fn uninstall(&self) -> VaultResult<()>;
    fn dismiss_prompts(&self) -> VaultResult<()>;
}

/// The host serving one distro's keyring.
struct DistroHost {
    host: SecretServiceHost,
    distro: String,
}

impl Host for DistroHost {
    fn install(&self, client: Box<dyn VaultClient>) -> VaultResult<()> {
        self.host.install_wsl(client, &self.distro)
    }

    fn uninstall(&self) -> VaultResult<()> {
        self.host.uninstall()
    }

    fn dismiss_prompts(&self) -> VaultResult<()> {
        self.host.dismiss_prompts()
    }
}

/// The host loop: follows the vault, installs the collection while the
/// vault is unsealed and the distro's keyring is available, and reports it
/// locked otherwise.
struct HostLoop<'a> {
    host: &'a dyn Host,
    brokers: &'a dyn Brokers,
    distro: String,
    wake: Sender<Wake>,
    woken: Receiver<Wake>,
    timing: Timing,
    clock: &'a dyn Fn() -> u64,
    log: Box<dyn FnMut(String) + 'a>,
    monitor: Box<dyn VaultClient>,
    reported: Option<String>,
    installed: bool,
    observed: Observed,
    /// While the keyring is not available: the next wait before trying
    /// again. `None` while it is, so the hint is logged once per change.
    retry: Option<Duration>,
}

impl<'a> HostLoop<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: &'a dyn Host,
        brokers: &'a dyn Brokers,
        distro: String,
        (wake, woken): (Sender<Wake>, Receiver<Wake>),
        timing: Timing,
        clock: &'a dyn Fn() -> u64,
        mut log: Box<dyn FnMut(String) + 'a>,
    ) -> Result<Self, CliError> {
        // The monitor checks the vault by itself: its broker never brings
        // Desktop forward. A client's request (the store's broker) or
        // unlock (`await_unseal`) does.
        let monitor = brokers.monitor()?;
        let mut reported = None;
        let observed = observe(monitor.as_ref(), &mut reported, &mut log);
        Ok(Self {
            host,
            brokers,
            distro,
            wake,
            woken,
            timing,
            clock,
            log,
            monitor,
            reported,
            installed: false,
            observed,
            retry: None,
        })
    }

    fn observe(&mut self) {
        self.observed = observe(self.monitor.as_ref(), &mut self.reported, &mut self.log);
    }

    /// The keyring is not available: report it locked, say once how to
    /// switch it on, and wait longer each time before trying again.
    fn unavailable(&mut self, error: Option<&VaultError>) -> Result<(), CliError> {
        if self.installed {
            self.host.uninstall()?;
            self.installed = false;
        }
        let wait = match self.retry {
            None => {
                let reason = error.map_or_else(String::new, |error| format!(" ({error})"));
                (self.log)(format!(
                    "the keyring of {} is not available{reason}; switch it on in FactorSeal \
                     Desktop, Settings, WSL keyrings",
                    self.distro
                ));
                self.timing.first_retry
            }
            Some(retry) => retry,
        };
        self.retry = Some(wait.saturating_mul(2).min(self.timing.max_retry));
        wait_for_unlock(&self.woken, wait);
        Ok(())
    }

    /// One turn of the loop. False when no client can wake it any more.
    fn step(&mut self) -> Result<bool, CliError> {
        match next(
            self.installed,
            self.observed,
            (self.clock)(),
            self.timing.max_check,
        ) {
            Next::Install => {
                let client = HostClient {
                    inner: self.brokers.client()?,
                    wake: Mutex::new(self.wake.clone()),
                };
                match self.host.install(Box::new(client)) {
                    Ok(()) => {
                        self.installed = true;
                        if self.retry.take().is_some() {
                            (self.log)(format!("the keyring of {} is available", self.distro));
                        }
                        // The install's own reads may have woken the loop
                        // before it succeeded; those wakes are stale.
                        while self.woken.try_recv().is_ok() {}
                    }
                    Err(error) => self.unavailable(Some(&error))?,
                }
                self.observe();
            }
            Next::Uninstall => {
                self.host.uninstall()?;
                self.installed = false;
            }
            Next::Check(after) => {
                if wait_for(&self.woken, after) == Some(Wake::Unavailable) {
                    self.unavailable(None)?;
                }
                self.observe();
            }
            Next::AwaitUnlock => {
                if !await_wake(&self.woken, Wake::Unlock) {
                    return Ok(false);
                }
                self.observed =
                    await_unseal(self.brokers, self.timing, &mut self.reported, &mut self.log);
                if self.observed == Observed::Sealed {
                    self.host.dismiss_prompts()?;
                }
            }
        }
        Ok(true)
    }
}

/// After a client's unlock: ask through a new broker, which brings Desktop
/// forward when the vault is sealed, then wait for the person to unseal.
fn await_unseal(
    brokers: &dyn Brokers,
    timing: Timing,
    reported: &mut Option<String>,
    log: &mut dyn FnMut(String),
) -> Observed {
    let Ok(client) = brokers.client() else {
        return Observed::Sealed;
    };
    let started = Instant::now();
    loop {
        let observed = observe(client.as_ref(), reported, log);
        if observed != Observed::Sealed || started.elapsed() >= timing.unlock_wait {
            return observed;
        }
        std::thread::sleep(timing.unlock_poll);
    }
}

/// `factorseal wsl-keyring`: serve the distro's keyring until stopped.
pub(super) fn serve() -> Result<(), CliError> {
    let config = super::wsl::load()?
        .ok_or_else(|| CliError::WslSetup("run `factorseal wsl-setup` first".to_owned()))?;
    let (wake, woken) = mpsc::channel();
    let host = DistroHost {
        host: SecretServiceHost::start_with_options(
            Arc::new(WslPrompter {
                wake: Mutex::new(wake.clone()),
            }),
            SecretServiceHostOptions {
                network_manager: false,
            },
        )?,
        distro: config.distro().to_owned(),
    };
    let mut host_loop = HostLoop::new(
        &host,
        &config,
        config.distro().to_owned(),
        (wake, woken),
        TIMING,
        &unix_now,
        Box::new(|message| eprintln!("factorseal wsl-keyring: {message}")),
    )?;
    while host_loop.step()? {}
    Ok(())
}

/// Wait up to `timeout` or until any wake, and say which.
fn wait_for(woken: &Receiver<Wake>, timeout: Duration) -> Option<Wake> {
    woken.recv_timeout(timeout).ok()
}

/// Wait up to `timeout` or until a client's unlock, dropping other wakes:
/// each failing request of a switched-off keyring sends one.
fn wait_for_unlock(woken: &Receiver<Wake>, timeout: Duration) {
    let until = Instant::now() + timeout;
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        match woken.recv_timeout(left) {
            Ok(Wake::Unlock) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Wait for a wake of kind `wanted`, dropping others. False if no wake can
/// come any more.
fn await_wake(woken: &Receiver<Wake>, wanted: Wake) -> bool {
    loop {
        match woken.recv() {
            Ok(wake) if wake == wanted => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_follows_the_vault_and_checks_by_its_idle_deadline() {
        let unsealed = Observed::Unsealed {
            idle_deadline: 1000,
        };
        let max = TIMING.max_check;
        assert_eq!(next(false, unsealed, 990, max), Next::Install);
        assert_eq!(
            next(true, unsealed, 990, max),
            Next::Check(Duration::from_secs(11))
        );
        // Never longer than the cap, never zero.
        assert_eq!(next(true, unsealed, 0, max), Next::Check(max));
        assert_eq!(
            next(true, unsealed, 2000, max),
            Next::Check(Duration::from_secs(1))
        );
        assert_eq!(next(true, Observed::Sealed, 990, max), Next::Uninstall);
        assert_eq!(next(false, Observed::Sealed, 990, max), Next::AwaitUnlock);
    }

    struct Answering(VaultResult<VaultResponseErrorCode>);

    impl VaultClient for Answering {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            let code = match &self.0 {
                Ok(code) => *code,
                Err(VaultError::Sealed) => return Err(VaultError::Sealed),
                Err(_) => return Err(VaultError::Protocol("broken".to_owned())),
            };
            Ok(VaultResponse::failure(
                request.request_id(),
                factorseal::VaultResponseError {
                    code,
                    message: "test".to_owned(),
                    interaction: None,
                },
            ))
        }
    }

    #[test]
    fn a_request_that_finds_the_vault_sealed_wakes_the_host() {
        for (answer, wakes) in [
            (Ok(VaultResponseErrorCode::Sealed), true),
            (Err(VaultError::Sealed), true),
            (Ok(VaultResponseErrorCode::AuthorizationRequired), false),
            (Err(VaultError::Protocol(String::new())), false),
        ] {
            let (wake, woken) = mpsc::channel();
            let client = HostClient {
                inner: Box::new(Answering(answer)),
                wake: Mutex::new(wake),
            };
            let _ = client.request(&VaultRequest::new(VaultAction::Status).unwrap());
            assert_eq!(woken.try_recv().ok(), wakes.then_some(Wake::Sealed));
        }
    }

    /// Only the host's own index read, refused without asking anyone, says
    /// the keyring is switched off; a program's refused access does not.
    #[test]
    fn a_refused_index_read_says_the_keyring_is_unavailable() {
        let index = VaultAction::Get {
            namespace: b"factorseal/wsl-secret-service/v1/NixOS".to_vec(),
            address: factorseal::WireSecretAddress::new(
                factorseal::vault::wsl_relay::SECRET_SERVICE_INDEX_ITEM,
                None,
            ),
        };
        let item = VaultAction::Get {
            namespace: b"factorseal/wsl-secret-service/v1/NixOS".to_vec(),
            address: factorseal::WireSecretAddress::new(
                "item/0123456789abcdef0123456789abcdef",
                None,
            ),
        };
        for (action, answer, wakes) in [
            (
                index,
                VaultResponseErrorCode::AuthorizationRequired,
                Some(Wake::Unavailable),
            ),
            (item, VaultResponseErrorCode::AuthorizationRequired, None),
            (
                VaultAction::Status,
                VaultResponseErrorCode::Sealed,
                Some(Wake::Sealed),
            ),
        ] {
            let (wake, woken) = mpsc::channel();
            let client = HostClient {
                inner: Box::new(Answering(Ok(answer))),
                wake: Mutex::new(wake),
            };
            let _ = client.request(&VaultRequest::new(action).unwrap());
            assert_eq!(woken.try_recv().ok(), wakes);
        }
    }

    #[test]
    fn an_unlock_waits_past_other_wakes() {
        let (wake, woken) = mpsc::channel();
        wake.send(Wake::Sealed).unwrap();
        wake.send(Wake::Sealed).unwrap();
        wake.send(Wake::Unlock).unwrap();
        assert!(await_wake(&woken, Wake::Unlock));
        assert!(woken.try_recv().is_err());
        drop(wake);
        assert!(!await_wake(&woken, Wake::Unlock));
    }

    struct Unsealed;
    impl VaultClient for Unsealed {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            Ok(VaultResponse::success(
                request.request_id(),
                VaultResponseBody::Status {
                    installation_id: String::new(),
                    device_vault_id: String::new(),
                    device_key_id: String::new(),
                    hardware_backend: String::new(),
                    idle_deadline: 1000,
                    absolute_deadline: 2000,
                },
            ))
        }
    }

    #[test]
    fn only_a_status_answer_is_an_unsealed_vault() {
        let mut reported = None;
        assert_eq!(
            observe(
                &Answering(Ok(VaultResponseErrorCode::Sealed)),
                &mut reported,
                &mut |_| {}
            ),
            Observed::Sealed
        );
        assert_eq!(reported, None);
        assert_eq!(
            observe(
                &Answering(Ok(VaultResponseErrorCode::InvalidRequest)),
                &mut reported,
                &mut |_| {}
            ),
            Observed::Sealed
        );
        assert_eq!(reported.as_deref(), Some("test"));

        assert_eq!(
            observe(&Unsealed, &mut reported, &mut |_| {}),
            Observed::Unsealed {
                idle_deadline: 1000
            }
        );
        assert_eq!(reported, None);
    }

    /// The Windows vault as the loop's fakes see it.
    #[derive(Default)]
    struct FakeVault {
        sealed: bool,
        switched_on: bool,
        /// Each request: which kind of broker client sent it, and what.
        requests: Vec<(&'static str, &'static str)>,
    }

    struct FakeClient {
        kind: &'static str,
        vault: Arc<Mutex<FakeVault>>,
    }

    impl VaultClient for FakeClient {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            let mut vault = self.vault.lock().unwrap();
            let refuse = |code| {
                Ok(VaultResponse::failure(
                    request.request_id(),
                    factorseal::VaultResponseError {
                        code,
                        message: "test".to_owned(),
                        interaction: None,
                    },
                ))
            };
            let what = match request.action {
                VaultAction::Status => "status",
                VaultAction::Get { .. } => "index",
                _ => "other",
            };
            vault.requests.push((self.kind, what));
            if vault.sealed {
                return refuse(VaultResponseErrorCode::Sealed);
            }
            match what {
                "status" => Unsealed.request(request),
                "index" if vault.switched_on => Ok(VaultResponse::success(
                    request.request_id(),
                    VaultResponseBody::Secret { value: None },
                )),
                _ => refuse(VaultResponseErrorCode::AuthorizationRequired),
            }
        }
    }

    struct FakeBrokers(Arc<Mutex<FakeVault>>);

    impl Brokers for FakeBrokers {
        fn monitor(&self) -> Result<Box<dyn VaultClient>, CliError> {
            Ok(Box::new(FakeClient {
                kind: "monitor",
                vault: Arc::clone(&self.0),
            }))
        }

        fn client(&self) -> Result<Box<dyn VaultClient>, CliError> {
            Ok(Box::new(FakeClient {
                kind: "client",
                vault: Arc::clone(&self.0),
            }))
        }
    }

    /// Installs as the real host does: by reading the index through the
    /// client, which it then keeps for the collection's requests.
    #[derive(Default)]
    struct FakeHost {
        calls: Mutex<Vec<&'static str>>,
        installed: Mutex<Option<Box<dyn VaultClient>>>,
    }

    impl FakeHost {
        fn calls(&self) -> Vec<&'static str> {
            std::mem::take(&mut self.calls.lock().unwrap())
        }

        /// A program's request through the installed collection, which
        /// reads the index first.
        fn read(&self) {
            let installed = self.installed.lock().unwrap();
            let client = installed.as_ref().expect("installed");
            let _ = client.request(&VaultRequest::new(index_read()).unwrap());
        }
    }

    fn index_read() -> VaultAction {
        VaultAction::Get {
            namespace: b"factorseal/wsl-secret-service/v1/NixOS".to_vec(),
            address: factorseal::WireSecretAddress::new(
                factorseal::vault::wsl_relay::SECRET_SERVICE_INDEX_ITEM,
                None,
            ),
        }
    }

    impl Host for FakeHost {
        fn install(&self, client: Box<dyn VaultClient>) -> VaultResult<()> {
            let response = client.request(&VaultRequest::new(index_read()).unwrap())?;
            if response.result.is_err() {
                self.calls.lock().unwrap().push("install failed");
                return Err(VaultError::Protocol(
                    "application authorization is required".to_owned(),
                ));
            }
            self.calls.lock().unwrap().push("installed");
            *self.installed.lock().unwrap() = Some(client);
            Ok(())
        }

        fn uninstall(&self) -> VaultResult<()> {
            self.calls.lock().unwrap().push("uninstalled");
            *self.installed.lock().unwrap() = None;
            Ok(())
        }

        fn dismiss_prompts(&self) -> VaultResult<()> {
            self.calls.lock().unwrap().push("prompts dismissed");
            Ok(())
        }
    }

    const FAST: Timing = Timing {
        max_check: Duration::from_millis(20),
        unlock_wait: Duration::from_millis(20),
        unlock_poll: Duration::from_millis(1),
        first_retry: Duration::from_millis(1),
        max_retry: Duration::from_millis(4),
    };

    struct Fixture {
        vault: Arc<Mutex<FakeVault>>,
        brokers: FakeBrokers,
        host: FakeHost,
        logged: Arc<Mutex<Vec<String>>>,
    }

    impl Fixture {
        fn new(switched_on: bool) -> Self {
            let vault = Arc::new(Mutex::new(FakeVault {
                switched_on,
                ..FakeVault::default()
            }));
            Self {
                brokers: FakeBrokers(Arc::clone(&vault)),
                vault,
                host: FakeHost::default(),
                logged: Arc::default(),
            }
        }

        fn start(&self) -> (HostLoop<'_>, Sender<Wake>) {
            let channel = mpsc::channel();
            let wake = channel.0.clone();
            let logged = Arc::clone(&self.logged);
            let host_loop = HostLoop::new(
                &self.host,
                &self.brokers,
                "NixOS".to_owned(),
                channel,
                FAST,
                &|| 990,
                Box::new(move |message| logged.lock().unwrap().push(message)),
            )
            .unwrap();
            (host_loop, wake)
        }

        fn hints(&self) -> usize {
            self.logged
                .lock()
                .unwrap()
                .iter()
                .filter(|message| message.contains("switch it on"))
                .count()
        }

        fn requests(&self) -> Vec<(&'static str, &'static str)> {
            std::mem::take(&mut self.vault.lock().unwrap().requests)
        }
    }

    /// A keyring that is not available (switched off) is tried again,
    /// waiting longer each time, with one hint per change; once switched
    /// on it is installed. The host's own status checks go through the
    /// monitor, which never brings Desktop forward.
    #[test]
    fn the_host_retries_an_unavailable_keyring_and_says_so_once() {
        let fixture = Fixture::new(false);
        let (mut host_loop, _wake) = fixture.start();
        for retry in [2, 4, 4] {
            assert!(host_loop.step().unwrap());
            assert_eq!(host_loop.retry, Some(Duration::from_millis(retry)));
        }
        assert_eq!(fixture.host.calls(), ["install failed"; 3]);
        assert_eq!(fixture.hints(), 1);
        assert!(!host_loop.installed);

        fixture.vault.lock().unwrap().switched_on = true;
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["installed"]);
        assert!(host_loop.installed && host_loop.retry.is_none());
        assert_eq!(fixture.hints(), 1);
        for (kind, what) in fixture.requests() {
            assert_eq!(
                kind,
                if what == "status" {
                    "monitor"
                } else {
                    "client"
                }
            );
        }
    }

    /// A request that finds the vault sealed wakes the host, which checks
    /// through the monitor and reports the collection locked.
    #[test]
    fn a_sealed_wake_uninstalls_the_collection() {
        let fixture = Fixture::new(true);
        let (mut host_loop, _wake) = fixture.start();
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["installed"]);

        fixture.vault.lock().unwrap().sealed = true;
        fixture.host.read();
        let started = Instant::now();
        assert!(host_loop.step().unwrap());
        // Woken, not waiting out the check.
        assert!(started.elapsed() < FAST.max_check);
        assert_eq!(host_loop.observed, Observed::Sealed);
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["uninstalled"]);
        assert!(!host_loop.installed);
    }

    /// Switched off in Desktop while installed: the collection reports
    /// locked instead of failing each call, the hint is logged once, and a
    /// client's unlock after switching it on installs it at once.
    #[test]
    fn a_keyring_switched_off_while_installed_reports_locked() {
        let fixture = Fixture::new(true);
        let (mut host_loop, wake) = fixture.start();
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["installed"]);

        fixture.vault.lock().unwrap().switched_on = false;
        fixture.host.read();
        fixture.host.read();
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["uninstalled"]);
        assert!(!host_loop.installed);
        assert_eq!(fixture.hints(), 1);
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["install failed"]);
        assert_eq!(fixture.hints(), 1);

        fixture.vault.lock().unwrap().switched_on = true;
        wake.send(Wake::Unlock).unwrap();
        assert!(host_loop.step().unwrap());
        assert_eq!(fixture.host.calls(), ["installed"]);
    }
}
