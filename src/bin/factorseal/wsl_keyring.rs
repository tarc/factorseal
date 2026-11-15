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
//! finds the vault sealed.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use factorseal::{
    SecretServiceHost, SecretServiceHostOptions, SecretServicePrompter, VaultAction, VaultClient,
    VaultError, VaultRequest, VaultResponse, VaultResponseBody, VaultResponseErrorCode,
    VaultResult,
};

use super::CliError;
use super::wsl::WslConfig;

/// Longest wait between checks of an unsealed vault, so a seal from
/// Desktop shows as locked within this time even without a request.
const MAX_CHECK: Duration = Duration::from_secs(30);
/// How long an unlock request waits for the person to unseal the vault.
const UNLOCK_WAIT: Duration = Duration::from_mins(2);
const UNLOCK_POLL: Duration = Duration::from_secs(1);

/// Why the host loop wakes up early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// A client asked to unlock the collection.
    Unlock,
    /// A request found the vault sealed.
    Sealed,
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

fn next(installed: bool, observed: Observed, now: u64) -> Next {
    match (observed, installed) {
        (Observed::Unsealed { .. }, false) => Next::Install,
        (Observed::Unsealed { idle_deadline }, true) => Next::Check(
            Duration::from_secs(idle_deadline.saturating_sub(now).saturating_add(1)).min(MAX_CHECK),
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

/// The host's client: the broker, telling the loop when a request finds the
/// vault sealed.
struct HostClient<C> {
    inner: C,
    wake: Mutex<Sender<Wake>>,
}

impl<C: VaultClient> VaultClient for HostClient<C> {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        let result = self.inner.request(request);
        if is_sealed(&result)
            && let Ok(wake) = self.wake.lock()
        {
            let _ = wake.send(Wake::Sealed);
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
fn observe(client: &dyn VaultClient, reported: &mut Option<String>) -> Observed {
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
        eprintln!("factorseal wsl-keyring: the Windows vault did not answer: {problem}");
        *reported = Some(problem);
    }
    Observed::Sealed
}

/// After a client's unlock: ask through a new broker, which brings Desktop
/// forward when the vault is sealed, then wait for the person to unseal.
fn await_unseal(config: &WslConfig, reported: &mut Option<String>) -> Observed {
    let Ok(client) = config.clone().client() else {
        return Observed::Sealed;
    };
    let started = Instant::now();
    loop {
        let observed = observe(&client, reported);
        if observed != Observed::Sealed || started.elapsed() >= UNLOCK_WAIT {
            return observed;
        }
        std::thread::sleep(UNLOCK_POLL);
    }
}

/// `factorseal wsl-keyring`: serve the distro's keyring until stopped.
pub(super) fn serve() -> Result<(), CliError> {
    let config = super::wsl::load()?
        .ok_or_else(|| CliError::WslSetup("run `factorseal wsl-setup` first".to_owned()))?;
    let distro = config.distro().to_owned();
    let (wake, woken) = mpsc::channel();
    let host = SecretServiceHost::start_with_options(
        Arc::new(WslPrompter {
            wake: Mutex::new(wake.clone()),
        }),
        SecretServiceHostOptions {
            network_manager: false,
        },
    )?;
    let monitor = config.clone().client()?;
    let mut reported = None;
    let mut installed = false;
    let mut observed = observe(&monitor, &mut reported);
    loop {
        match next(installed, observed, unix_now()) {
            Next::Install => {
                let client = HostClient {
                    inner: config.clone().client()?,
                    wake: Mutex::new(wake.clone()),
                };
                match host.install_wsl(Box::new(client), &distro) {
                    Ok(()) => installed = true,
                    Err(error) => {
                        eprintln!(
                            "factorseal wsl-keyring: the keyring of {distro} is not available \
                             ({error}); switch it on in FactorSeal Desktop, Settings, WSL keyrings"
                        );
                        wait(&woken, MAX_CHECK);
                    }
                }
                observed = observe(&monitor, &mut reported);
            }
            Next::Uninstall => {
                host.uninstall()?;
                installed = false;
            }
            Next::Check(after) => {
                wait(&woken, after);
                observed = observe(&monitor, &mut reported);
            }
            Next::AwaitUnlock => {
                if await_wake(&woken, Wake::Unlock) {
                    observed = await_unseal(&config, &mut reported);
                } else {
                    return Ok(());
                }
                if observed == Observed::Sealed {
                    host.dismiss_prompts()?;
                }
            }
        }
    }
}

/// Wait up to `timeout` or until any wake.
fn wait(woken: &Receiver<Wake>, timeout: Duration) {
    match woken.recv_timeout(timeout) {
        Ok(_) | Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
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
        assert_eq!(next(false, unsealed, 990), Next::Install);
        assert_eq!(
            next(true, unsealed, 990),
            Next::Check(Duration::from_secs(11))
        );
        // Never longer than the cap, never zero.
        assert_eq!(next(true, unsealed, 0), Next::Check(MAX_CHECK));
        assert_eq!(
            next(true, unsealed, 2000),
            Next::Check(Duration::from_secs(1))
        );
        assert_eq!(next(true, Observed::Sealed, 990), Next::Uninstall);
        assert_eq!(next(false, Observed::Sealed, 990), Next::AwaitUnlock);
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
                inner: Answering(answer),
                wake: Mutex::new(wake),
            };
            let _ = client.request(&VaultRequest::new(VaultAction::Status).unwrap());
            assert_eq!(woken.try_recv().ok(), wakes.then_some(Wake::Sealed));
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
                &mut reported
            ),
            Observed::Sealed
        );
        assert_eq!(reported, None);
        assert_eq!(
            observe(
                &Answering(Ok(VaultResponseErrorCode::InvalidRequest)),
                &mut reported
            ),
            Observed::Sealed
        );
        assert_eq!(reported.as_deref(), Some("test"));

        assert_eq!(
            observe(&Unsealed, &mut reported),
            Observed::Unsealed {
                idle_deadline: 1000
            }
        );
        assert_eq!(reported, None);
    }
}
