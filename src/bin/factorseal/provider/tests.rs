use super::*;
use factorseal::{
    CallerIdentity, CallerPlatform, HardwareBackend, KeyProtector, KeyProtectorFactory,
    PermissionChange, PermissionState, SecretSpecAddress, UnlockCredentials, UnlockFactorKind,
    UnlockGroup, UnlockPolicy, UnsealLeasePolicy, Vault, VaultInteractionReference, VaultPlatform,
    VaultResponse, VaultResponseError, VaultService,
};
use secretspec_ipc::client::Client;
use secretspec_ipc::protocol::provider::{
    AddressParams, ApplicationContext, Coordinates, DeletedResult, DescribeWriteTargetResult,
    EmptyResult, ExistsResult, GetResult, InitializeApplication, InitializedApplication,
    SetExpiringParams, SetParams, StoredResult,
};
use secretspec_ipc::protocol::{
    InitializeParams, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

type CacheKey = (String, SecretSpecAddress);

#[cfg(target_os = "linux")]
#[test]
fn provider_runtime_drives_async_sockets() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    provider_runtime().unwrap().block_on(async {
        let (mut writer, mut reader) = tokio::net::UnixStream::pair().unwrap();
        writer.write_all(b"provider-io").await.unwrap();
        let mut response = [0; 11];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"provider-io");
    });
}

fn application_context() -> VaultApplicationContext {
    VaultApplicationContext::new(
        Some("demo".to_owned()),
        Some("default".to_owned()),
        Some(without_verbatim_prefix(
            &std::env::current_dir()
                .and_then(std::fs::canonicalize)
                .unwrap()
                .to_string_lossy(),
        )),
        Some("test".to_owned()),
    )
    .and_then(|context| context.with_declared_launch_chain(launch_chain::launch_chain()))
    .unwrap()
}

#[derive(Default)]
struct MemoryVault {
    values: Mutex<HashMap<CacheKey, Vec<u8>>>,
    last_evict_at: Mutex<Option<u64>>,
    dialog_writes: AtomicU64,
}

impl VaultClient for MemoryVault {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        assert_eq!(request.application(), Some(&application_context()));
        let body = match &request.action {
            VaultAction::GetCache { project, address } => {
                assert_eq!(project, "demo");
                VaultResponseBody::Secret {
                    value: self
                        .values
                        .lock()
                        .unwrap()
                        .get(&(project.clone(), address.clone()))
                        .cloned()
                        .map(|value| WireSecret::new(value).unwrap()),
                }
            }
            VaultAction::WriteCacheFromDialog {
                project,
                address,
                value,
                evict_at,
            }
            | VaultAction::PutCache {
                project,
                address,
                value,
                evict_at,
            } => {
                assert_eq!(project, "demo");
                if matches!(request.action, VaultAction::WriteCacheFromDialog { .. }) {
                    self.dialog_writes.fetch_add(1, Ordering::Relaxed);
                }
                self.values
                    .lock()
                    .unwrap()
                    .insert((project.clone(), address.clone()), value.expose().to_vec());
                *self.last_evict_at.lock().unwrap() = *evict_at;
                VaultResponseBody::Stored
            }
            VaultAction::DeleteCache { project, address } => {
                assert_eq!(project, "demo");
                let existed = self
                    .values
                    .lock()
                    .unwrap()
                    .remove(&(project.clone(), address.clone()))
                    .is_some();
                VaultResponseBody::Deleted { existed }
            }
            _ => {
                return Err(VaultError::Protocol(
                    "provider used a non-cache vault action".to_owned(),
                ));
            }
        };
        Ok(VaultResponse::success(request.request_id(), body))
    }
}

fn address() -> Address {
    Address::Convention {
        project: "demo".to_owned(),
        profile: "production".to_owned(),
        key: "TOKEN".to_owned(),
    }
}

fn deadline() -> u64 {
    unix_time_ms().unwrap() + 2_000
}

fn native_address() -> Address {
    Address::Native {
        coordinates: Coordinates {
            item: "database".to_owned(),
            field: Some("password".to_owned()),
            vault: Some("Production".to_owned()),
            section: Some("credentials".to_owned()),
            version: Some("3".to_owned()),
        },
    }
}

async fn store(client: &Client, address: Address, value: &str) {
    let stored: StoredResult = client
        .call(
            wire::method::SET,
            &SetParams {
                address,
                value: value.to_owned(),
            },
            deadline(),
        )
        .await
        .unwrap();
    assert!(stored.stored);
}

async fn get(client: &Client, address: Address) -> GetResult {
    client
        .call(wire::method::GET, &AddressParams { address }, deadline())
        .await
        .unwrap()
}

async fn delete(client: &Client, address: Address) {
    let deleted: DeletedResult = client
        .call(wire::method::DELETE, &AddressParams { address }, deadline())
        .await
        .unwrap();
    assert!(deleted.deleted);
}

async fn store_expiring(client: &Client, address: Address) {
    let stored: StoredResult = client
        .call(
            wire::method::SET_EXPIRING,
            &SetExpiringParams {
                address,
                value: "expiring".to_owned(),
                ttl_ms: 2_500,
            },
            deadline(),
        )
        .await
        .unwrap();
    assert!(stored.stored);
}

async fn exists(client: &Client, address: Address) -> bool {
    client
        .call::<_, ExistsResult>(wire::method::EXISTS, &AddressParams { address }, deadline())
        .await
        .unwrap()
        .exists
}

async fn check_address_methods(client: &Client) {
    for address in [address(), native_address()] {
        let params = AddressParams {
            address: address.clone(),
        };
        let resolved: ResolveAddressResult = client
            .call(wire::method::RESOLVE_ADDRESS, &params, deadline())
            .await
            .unwrap();
        let expected = match address {
            Address::Convention { .. } => Coordinates {
                item: "TOKEN".to_owned(),
                field: None,
                vault: Some("demo".to_owned()),
                section: Some("production".to_owned()),
                version: None,
            },
            Address::Native { coordinates } => coordinates,
        };
        assert_eq!(resolved.coordinates, expected);
        for method in [wire::method::CHECK_WRITABLE, wire::method::CHECK_DELETABLE] {
            client
                .call::<_, EmptyResult>(method, &params, deadline())
                .await
                .unwrap();
        }
        let target: DescribeWriteTargetResult = client
            .call(wire::method::DESCRIBE_WRITE_TARGET, &params, deadline())
            .await
            .unwrap();
        assert_eq!(target.description, "Factorseal device cache");
    }
}

async fn reject_cross_project_addresses(client: &Client) {
    let params = AddressParams {
        address: Address::Convention {
            project: "another-project".to_owned(),
            profile: "production".to_owned(),
            key: "TOKEN".to_owned(),
        },
    };
    for method in [
        wire::method::EXISTS,
        wire::method::CHECK_WRITABLE,
        wire::method::CHECK_DELETABLE,
        wire::method::DESCRIBE_WRITE_TARGET,
    ] {
        let error = client
            .call::<_, serde_json::Value>(method, &params, deadline())
            .await
            .unwrap_err();
        assert_eq!(error.rpc_kind(), Some(ErrorKind::InvalidParams), "{method}");
    }
}

/// Serve `provider` over an in-memory stream and initialize it as
/// SecretSpec would for project `demo` in the current folder.
async fn connected(
    provider: FactorsealProvider,
) -> (
    Client,
    tokio::task::JoinHandle<Result<(), secretspec_ipc::error::Error>>,
) {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        provider,
        ServerConfig::default(),
    ));
    let initialize = InitializeParams {
        protocol: PROVIDER_PROTOCOL.to_owned(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "factorseal-provider-test".to_owned(),
            version: "1".to_owned(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 8,
        },
        client_methods: Vec::new(),
        application: InitializeApplication {
            scheme: "factorseal".to_owned(),
            uri: PROVIDER_URI.to_owned(),
            context: ApplicationContext {
                project: Some("demo".to_owned()),
                profile: Some("default".to_owned()),
                base_dir: application_context().base_dir,
                reason: Some("test".to_owned()),
                requested_authorization_duration_ms: None,
            },
        },
    };
    let (client, _) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        initialize,
        deadline(),
    )
    .await
    .unwrap();
    (client, server)
}

/// Through the WSL broker the vault is the Windows one: a write takes the
/// grant path even when a Linux Desktop on this session could show its
/// secure-entry dialog, since that dialog belongs to no vault here.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_relayed_provider_writes_through_grants_not_the_linux_dialog() {
    let vault = Arc::new(MemoryVault::default());
    let mut provider = FactorsealProvider::with_client(vault.clone());
    provider.relayed = true;
    let (client, server) = connected(provider).await;
    store(&client, address(), "secret").await;
    assert_eq!(vault.dialog_writes.load(Ordering::Relaxed), 0);
    assert_eq!(vault.values.lock().unwrap().len(), 1);
    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

/// A Windows vault behind the WSL broker that stays sealed for its first
/// `sealed_for` requests, then answers.
#[cfg(target_os = "linux")]
struct SealedWindowsVault {
    sealed_for: u64,
    requests: AtomicU64,
    actions: Mutex<Vec<&'static str>>,
}

#[cfg(target_os = "linux")]
impl VaultClient for SealedWindowsVault {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        let action = match &request.action {
            VaultAction::Status => "status",
            VaultAction::GetCache { .. } => "get",
            _ => "other",
        };
        self.actions.lock().unwrap().push(action);
        if self.requests.fetch_add(1, Ordering::Relaxed) < self.sealed_for {
            return Ok(VaultResponse::failure(
                request.request_id(),
                VaultResponseError {
                    code: VaultResponseErrorCode::Sealed,
                    message: "unlock FactorSeal Desktop on Windows, then try again".to_owned(),
                    interaction: None,
                },
            ));
        }
        let body = match &request.action {
            VaultAction::Status => VaultResponseBody::Status {
                installation_id: "windows".to_owned(),
                device_vault_id: "vault".to_owned(),
                device_key_id: "key".to_owned(),
                hardware_backend: "test".to_owned(),
                idle_deadline: 1,
                absolute_deadline: 2,
            },
            VaultAction::GetCache { .. } => VaultResponseBody::Secret { value: None },
            _ => return Err(VaultError::Protocol("unexpected action".to_owned())),
        };
        Ok(VaultResponse::success(request.request_id(), body))
    }
}

/// A Linux FactorSeal host on the session bus: counts the unlock and
/// finish calls the provider makes to it.
#[cfg(target_os = "linux")]
struct LinuxDesktop(Arc<AtomicU64>);

#[cfg(target_os = "linux")]
#[zbus::interface(name = "org.freedesktop.Secret.Service")]
#[allow(clippy::needless_pass_by_value)] // D-Bus dispatch methods.
impl LinuxDesktop {
    fn unlock_for_ipc(&self, attributes: HashMap<String, String>) {
        let _ = attributes;
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn finish_ipc_access(&self, attributes: HashMap<String, String>) {
        let _ = attributes;
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Run `secretspec get` through a relayed provider against `vault`, with a
/// Linux Desktop on the private session bus when the test runs under
/// `scripts/test-with-dbus.sh`. Returns the result and the calls the Linux
/// Desktop received.
#[cfg(target_os = "linux")]
async fn relayed_get(
    vault: Arc<SealedWindowsVault>,
    within_ms: u64,
) -> (Result<GetResult, secretspec_ipc::Error>, u64) {
    let calls = Arc::new(AtomicU64::new(0));
    let _desktop = if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_some() {
        Some(
            zbus::connection::Builder::session()
                .name("org.freedesktop.secrets")
                .serve_at("/org/freedesktop/secrets", LinuxDesktop(Arc::clone(&calls)))
                .build()
                .await
                .unwrap(),
        )
    } else {
        None
    };
    let mut provider = FactorsealProvider::with_client(vault);
    provider.relayed = true;
    let (client, server) = connected(provider).await;
    let result = client
        .call::<_, GetResult>(
            wire::method::GET,
            &AddressParams { address: address() },
            unix_time_ms().unwrap() + within_ms,
        )
        .await;
    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
    (result, calls.load(Ordering::Relaxed))
}

/// The Windows vault is sealed: the broker brings Windows Desktop forward,
/// so the relayed provider waits for the unseal and retries once. It never
/// asks a Linux Desktop on the WSL session bus, which hosts another vault.
/// One test, since both cases own the same name on the private bus.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_relayed_provider_waits_for_the_windows_unseal_not_a_linux_desktop() {
    let sealed = |sealed_for| {
        Arc::new(SealedWindowsVault {
            sealed_for,
            requests: AtomicU64::new(0),
            actions: Mutex::new(Vec::new()),
        })
    };
    let vault = sealed(2);
    let (result, linux_calls) = relayed_get(Arc::clone(&vault), 10_000).await;
    assert_eq!(linux_calls, 0);
    assert_eq!(result.unwrap(), GetResult::Missing);
    assert_eq!(
        *vault.actions.lock().unwrap(),
        ["get", "status", "status", "get"]
    );

    // Left sealed, it asks for interaction before the caller's deadline.
    let vault = sealed(u64::MAX);
    let started = std::time::Instant::now();
    let (result, linux_calls) = relayed_get(Arc::clone(&vault), 3_000).await;
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(linux_calls, 0);
    let Err(secretspec_ipc::Error::Remote(error)) = result else {
        panic!("expected the provider to ask for interaction, got {result:?}");
    };
    assert_eq!(error.data.kind, ErrorKind::InteractionRequired);
    assert!(error.data.interaction.is_none());
    let actions = vault.actions.lock().unwrap();
    assert_eq!(actions.first(), Some(&"get"));
    assert!(actions.len() > 2);
    assert!(actions[1..].iter().all(|action| *action == "status"));
}

/// With a WSL setup and no explicit socket, the provider talks to the
/// Windows vault through the broker; an explicit socket names a Linux vault
/// and wins; a damaged setup is an error, not a silent Linux fallback.
#[cfg(target_os = "linux")]
#[test]
fn wsl_setup_selects_the_relayed_client_unless_a_socket_is_given() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("wsl.json");
    let load = || super::super::wsl::load_from(&config);
    let root = directory.path().join("root");
    let socket = directory.path().join("factorseal.sock");

    assert!(
        !FactorsealProvider::select(&root, None, load)
            .unwrap()
            .relayed
    );
    std::fs::write(
        &config,
        r#"{"broker":"/mnt/c/FactorSeal/factorseal-wsl-broker.exe","pipe":"\\\\.\\pipe\\factorseal-abc","distro":"NixOS"}"#,
    )
    .unwrap();
    assert!(
        FactorsealProvider::select(&root, None, load)
            .unwrap()
            .relayed
    );
    assert!(
        !FactorsealProvider::select(&root, Some(&socket), load)
            .unwrap()
            .relayed
    );
    std::fs::write(&config, b"{not json").unwrap();
    assert!(matches!(
        FactorsealProvider::select(&root, None, load),
        Err(CliError::WslSetup(_))
    ));
    // An explicit socket never reads the setup.
    assert!(FactorsealProvider::select(&root, Some(&socket), load).is_ok());
}

#[tokio::test]
async fn provider_uses_cache_actions_for_crud_and_expiry() {
    let vault = Arc::new(MemoryVault::default());
    let provider = FactorsealProvider::with_client(vault.clone());
    assert!(
        !provider
            .capabilities()
            .contains(&wire::method::CLEAR.to_owned())
    );
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        provider,
        ServerConfig::default(),
    ));
    let initialize = InitializeParams {
        protocol: PROVIDER_PROTOCOL.to_owned(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "factorseal-provider-test".to_owned(),
            version: "1".to_owned(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 8,
        },
        client_methods: Vec::new(),
        application: InitializeApplication {
            scheme: "factorseal".to_owned(),
            uri: PROVIDER_URI.to_owned(),
            context: ApplicationContext {
                project: Some("demo".to_owned()),
                profile: Some("default".to_owned()),
                base_dir: application_context().base_dir,
                reason: Some("test".to_owned()),
                requested_authorization_duration_ms: None,
            },
        },
    };
    let (client, initialized) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        initialize,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(initialized.application.provider.name, "factorseal");

    check_address_methods(&client).await;
    reject_cross_project_addresses(&client).await;
    assert!(vault.values.lock().unwrap().is_empty());
    assert!(!exists(&client, address()).await);
    store(&client, address(), "secret").await;
    assert!(exists(&client, address()).await);
    assert_eq!(
        get(&client, address()).await,
        GetResult::Found {
            value: "secret".to_owned(),
            expires_at_unix_ms: None,
            revision: None,
        }
    );

    let native = native_address();
    store(&client, native.clone(), "native").await;
    assert!(exists(&client, native.clone()).await);
    delete(&client, native.clone()).await;
    assert!(!exists(&client, native.clone()).await);
    assert_eq!(get(&client, native).await, GetResult::Missing);

    store_expiring(&client, address()).await;
    assert!(vault.last_evict_at.lock().unwrap().is_some());
    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[test]
fn accepts_registered_bare_provider_uri() {
    assert!(super::accepts_provider_uri("factorseal://"));
    assert!(super::accepts_provider_uri(super::PROVIDER_URI));
    assert!(!super::accepts_provider_uri("other://"));
}

#[test]
fn convention_addresses_expose_displayable_coordinates() {
    let first = address::coordinates(Address::Convention {
        project: "a/b".to_owned(),
        profile: "c".to_owned(),
        key: "d".to_owned(),
    });
    let second = address::coordinates(Address::Convention {
        project: "a".to_owned(),
        profile: "b/c".to_owned(),
        key: "d".to_owned(),
    });

    assert_eq!(first.item, "d");
    assert_eq!(first.vault.as_deref(), Some("a/b"));
    assert_eq!(first.section.as_deref(), Some("c"));
    assert_eq!(second.item, "d");
    assert_eq!(second.vault.as_deref(), Some("a"));
    assert_eq!(second.section.as_deref(), Some("b/c"));
    assert_ne!(
        (first.item, first.vault, first.section),
        (second.item, second.vault, second.section)
    );
}

struct ApprovalVault;

impl VaultClient for ApprovalVault {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        Ok(VaultResponse::failure(
            request.request_id(),
            VaultResponseError {
                code: VaultResponseErrorCode::AuthorizationRequired,
                message: "application authorization is required".to_owned(),
                interaction: Some(VaultInteractionReference {
                    id: "prm_provider_test".to_owned(),
                    expires_at: 1_800_000_000,
                }),
            },
        ))
    }
}

#[test]
fn provider_maps_pending_approval_to_structured_interaction() {
    let error = request(
        &ApprovalVault,
        VaultAction::GetCache {
            project: "demo".to_owned(),
            address: SecretSpecAddress::convention("demo", "default", "TOKEN").unwrap(),
        },
        application_context(),
    )
    .unwrap_err();
    assert_eq!(error.data.kind, ErrorKind::InteractionRequired);
    let interaction = error.data.interaction.unwrap();
    assert_eq!(interaction.id, "prm_provider_test");
    assert_eq!(interaction.expires_at_unix_ms, Some(1_800_000_000_000));
}

#[test]
fn provider_maps_an_unavailable_agent_to_required_interaction() {
    for error in [
        VaultError::Sealed,
        VaultError::WorkerUnavailable,
        VaultError::AgentUnreachable("/run/user/1000/factorseal.sock".to_owned()),
    ] {
        assert_eq!(
            map_vault_error(&error).data.kind,
            ErrorKind::InteractionRequired
        );
    }
}

struct IntegrationProtector {
    key: u8,
}

impl KeyProtector for IntegrationProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::AndroidTrustedEnvironment
    }

    fn wrap(&self, plaintext: &[u8]) -> factorseal::VaultResult<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> factorseal::VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ self.key).collect(),
        ))
    }

    fn delete(&self) -> factorseal::VaultResult<()> {
        Ok(())
    }
}

struct IntegrationProtectorFactory;

impl KeyProtectorFactory for IntegrationProtectorFactory {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        self.open(root, label, biometric)
    }

    fn open(
        &self,
        _root: &Path,
        label: &str,
        _biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        let key = if label.contains("-wrap-") { 0x35 } else { 0x97 };
        Ok(Box::new(IntegrationProtector { key }))
    }
}

struct ServiceVaultClient {
    service: Arc<VaultService>,
    caller: CallerIdentity,
    now: AtomicU64,
}

impl VaultClient for ServiceVaultClient {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        // Exercise the native protocol codec as a transport would, rather than
        // handing the service the provider's in-memory request directly.
        let request = VaultRequest::decode(&request.encode()?)?;
        Ok(self.service.handle(
            &self.caller,
            request,
            self.now.fetch_add(1, Ordering::Relaxed),
        ))
    }
}

struct ApprovalIntegrationFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    unlock_group: UnlockGroup,
    service: Arc<VaultService>,
    manager: CallerIdentity,
    now: u64,
}

impl ApprovalIntegrationFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unlock_group = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
        let policy = UnlockPolicy::new([unlock_group.clone()]).unwrap();
        let unsealed = Vault::create_with_key_protector_policy(
            &root,
            VaultPlatform::Android,
            &policy,
            UnlockCredentials::none(),
            &IntegrationProtectorFactory,
        )
        .unwrap();
        let now = unix_time_ms().unwrap() / 1_000;
        let service = Arc::new(
            VaultService::open(&root, unsealed, now, UnsealLeasePolicy::default()).unwrap(),
        );
        let manager = CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "dev.factorseal.cli",
            [9; 32],
            None,
        )
        .unwrap();
        service.authorize_permission_manager(&manager, now).unwrap();
        Self {
            _directory: directory,
            root,
            unlock_group,
            service,
            manager,
            now,
        }
    }

    fn provider(&self) -> FactorsealProvider {
        FactorsealProvider::with_client(Arc::new(ServiceVaultClient {
            service: Arc::clone(&self.service),
            caller: CallerIdentity::new(
                CallerPlatform::Linux,
                "uid:1000",
                "dev.factorseal.provider",
                [7; 32],
                None,
            )
            .unwrap(),
            now: AtomicU64::new(self.now + 1),
        }))
    }
}

fn approval_initialize() -> InitializeParams<InitializeApplication> {
    InitializeParams {
        protocol: PROVIDER_PROTOCOL.to_owned(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "approval-integration-test".to_owned(),
            version: "1".to_owned(),
        },
        limits: Limits {
            max_frame_bytes: 32 * 1024,
            max_in_flight: 8,
        },
        client_methods: Vec::new(),
        application: InitializeApplication {
            scheme: "factorseal".to_owned(),
            uri: PROVIDER_URI.to_owned(),
            context: ApplicationContext {
                project: Some("demo".to_owned()),
                profile: Some("production".to_owned()),
                base_dir: None,
                reason: Some("deploy".to_owned()),
                requested_authorization_duration_ms: Some(8 * 60 * 60 * 1_000),
            },
        },
    }
}

#[tokio::test]
async fn secretspec_request_waits_for_approval_and_completes() {
    let fixture = ApprovalIntegrationFixture::new();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        fixture.provider(),
        ServerConfig::default(),
    ));
    let (client, _) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        approval_initialize(),
        deadline(),
    )
    .await
    .unwrap();

    let request_client = client.clone();
    let pending_request = tokio::spawn(async move {
        request_client
            .call::<_, GetResult>(
                wire::method::GET,
                &AddressParams { address: address() },
                unix_time_ms().unwrap() + 10_000,
            )
            .await
    });
    let service = Arc::clone(&fixture.service);
    let manager = fixture.manager.clone();
    let now = fixture.now;
    let listed = tokio::task::spawn_blocking(move || {
        service.handle(
            &manager,
            VaultRequest::new(VaultAction::WaitPermissions {
                after_revision: 0,
                timeout_ms: 5_000,
            })
            .unwrap(),
            now + 2,
        )
    })
    .await
    .unwrap();
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = listed.result else {
        panic!("expected one pending approval");
    };
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].application.project.as_deref(), Some("demo"));
    assert_eq!(permissions[0].application.reason.as_deref(), Some("deploy"));
    assert_eq!(
        permissions[0]
            .application
            .requested_permission_duration_seconds,
        Some(8 * 60 * 60)
    );
    // The test harness launched this process, so the provider names it.
    let chain = &permissions[0].application.declared_launch_chain;
    assert_ne!(chain.len(), 0);
    assert_eq!(chain, &launch_chain::launch_chain());

    let unsealed = Vault::unseal_with_key_protector_group(
        &fixture.root,
        &fixture.unlock_group,
        UnlockCredentials::none(),
        &IntegrationProtectorFactory,
    )
    .unwrap();
    let PermissionState::Pending { challenge, .. } = &permissions[0].state else {
        panic!("expected a pending permission");
    };
    let signature = unsealed
        .sign_permission_challenge(&permissions[0].id, challenge, Some(8 * 60 * 60))
        .unwrap();
    let approved = fixture.service.handle(
        &fixture.manager,
        VaultRequest::new(VaultAction::ApprovePermission {
            id: permissions[0].id.clone(),
            signature,
            duration_seconds: Some(8 * 60 * 60),
            single_use: false,
        })
        .unwrap(),
        fixture.now + 3,
    );
    assert!(matches!(
        approved.result,
        Ok(VaultResponseBody::PermissionChanged {
            status: PermissionChange::Granted
        })
    ));
    assert_eq!(pending_request.await.unwrap().unwrap(), GetResult::Missing);

    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn secretspec_request_left_pending_asks_for_interaction_before_its_deadline() {
    let fixture = ApprovalIntegrationFixture::new();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        fixture.provider(),
        ServerConfig::default(),
    ));
    let (client, _) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        approval_initialize(),
        deadline(),
    )
    .await
    .unwrap();

    let started = std::time::Instant::now();
    let result = client
        .call::<_, GetResult>(
            wire::method::GET,
            &AddressParams { address: address() },
            unix_time_ms().unwrap() + 3_000,
        )
        .await;
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "the provider must answer before the caller's deadline"
    );
    let Err(secretspec_ipc::Error::Remote(error)) = result else {
        panic!("expected the provider to ask for interaction, got {result:?}");
    };
    assert_eq!(error.data.kind, ErrorKind::InteractionRequired);
    let interaction = error.data.interaction.expect("the pending approval");
    assert!(interaction.id.starts_with("prm_"));

    // The approval stays pending for a retry once it is granted.
    let listed = fixture.service.handle(
        &fixture.manager,
        VaultRequest::new(VaultAction::ListPermissions).unwrap(),
        fixture.now + 5,
    );
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = listed.result else {
        panic!("expected permissions");
    };
    assert!(
        permissions
            .iter()
            .any(|permission| permission.id == interaction.id
                && matches!(permission.state, PermissionState::Pending { .. }))
    );

    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn cancelled_input_shuts_down_all_private_channel_clones() {
    use std::io::Read as _;
    let (local, mut remote) = std::os::unix::net::UnixStream::pair().unwrap();
    remote
        .set_read_timeout(Some(std::time::Duration::from_millis(250)))
        .unwrap();
    let guard = InputChannelGuard(local.try_clone().unwrap());
    drop(guard);
    assert_eq!(remote.read(&mut [0_u8; 1]).unwrap(), 0);
    drop(local);
}

#[test]
fn canonical_base_directories_lose_the_windows_verbatim_prefix() {
    assert_eq!(
        super::without_verbatim_prefix(r"\\?\C:\work\app"),
        r"C:\work\app"
    );
    assert_eq!(
        super::without_verbatim_prefix(r"\\?\UNC\host\share\app"),
        r"\\host\share\app"
    );
    assert_eq!(
        super::without_verbatim_prefix(r"C:\work\app"),
        r"C:\work\app"
    );
    assert_eq!(super::without_verbatim_prefix("/work/app"), "/work/app");
    assert_eq!(super::without_verbatim_prefix(r"\\?\pipe\x"), r"\\?\pipe\x");
}
