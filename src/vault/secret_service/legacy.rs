//! Read another Secret Service (gnome-keyring, usually) on the session bus.
//!
//! The Wi-Fi migration searches only NetworkManager's attributes through it.
//! The keyring import lists every item ([`Legacy::inventory`]), never
//! unlocking and never reading a secret, or reads every item with its secret
//! ([`Legacy::read_all`]), unlocking locked collections one at a time only
//! when the caller asks.

use std::collections::{HashMap, HashSet};
use std::future::Future as _;
use std::os::unix::ffi::OsStrExt as _;
use std::time::Duration;

use zbus::export::futures_core::Stream;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Variant, fdo};
use zeroize::Zeroizing;

const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SESSION_COLLECTION: &str = "/org/freedesktop/secrets/collection/session";
const ALIAS_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
const SECRETS_BATCH: usize = 32;

/// A session on the Secret Service that owns `org.freedesktop.secrets`.
pub(crate) struct Legacy {
    pub(in crate::vault::secret_service) connection: Connection,
    pub(in crate::vault::secret_service) owner: String,
    pub(in crate::vault::secret_service) session: OwnedObjectPath,
    /// How long an unlock prompt may stay unanswered. A gcr prompt with no
    /// display never appears, and nothing else would end the wait.
    pub(in crate::vault::secret_service) unlock_timeout: Duration,
    /// How long the best-effort Dismiss of a timed-out prompt may take.
    pub(in crate::vault::secret_service) dismiss_timeout: Duration,
}

/// What became of one collection's unlock.
enum Unlock {
    Unlocked,
    Dismissed,
    TimedOut,
}

const UNLOCK_TIMEOUT: Duration = Duration::from_secs(300);
const DISMISS_TIMEOUT: Duration = Duration::from_secs(5);

/// `future`'s output, or `None` once `limit` passes. The timer is a thread,
/// not a Tokio timer: callers may run on zbus's own executor.
async fn within<T>(limit: Duration, future: impl std::future::Future<Output = T>) -> Option<T> {
    let (sender, mut expired) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        let _ = sender.send(());
    });
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(context) {
            return std::task::Poll::Ready(Some(output));
        }
        match std::pin::Pin::new(&mut expired).poll(context) {
            std::task::Poll::Ready(_) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

/// One item of the other Secret Service, as it reported it: on a locked
/// gnome-keyring item, no label, no modified time, hashed attribute values
/// under `gkr:compat:hashed:<name>` and a placeholder `xdg:schema`.
pub(crate) type LegacyItem = crate::vault::KeyringSourceItem;

/// What a read of another Secret Service found, and the collections it
/// could not read with why.
#[derive(Default)]
pub struct SecretServiceRead {
    pub items: Vec<crate::vault::KeyringSourceItem>,
    pub skipped_collections: Vec<(String, String)>,
    /// In an inventory, the collections that are locked, empty ones too:
    /// reading values prompts once for each of them.
    pub locked_collections: Vec<String>,
    /// In an inventory, every collection visited: any of them may be
    /// locked by the time values are read.
    pub collections: Vec<String>,
}

/// Read the Secret Service on the session bus, refusing FactorSeal itself:
/// with `values`, every item with its secret, unlocking each locked
/// collection through its own prompt; without, every item's metadata only,
/// never unlocking.
///
/// # Errors
///
/// No session bus, no Secret Service on it, FactorSeal owning it, or a
/// failed D-Bus call.
pub fn read_secret_service(values: bool) -> Result<SecretServiceRead, String> {
    zbus::block_on(async {
        let legacy = Legacy::connect_foreign().await?;
        let read = if values {
            legacy.read_all(true).await
        } else {
            legacy.inventory().await
        };
        legacy.close().await;
        read.map_err(|error| format!("cannot read the Secret Service: {error}"))
    })
}

pub(crate) async fn proxy<'a>(
    connection: &'a Connection,
    owner: &'a str,
    path: &'a str,
    interface: &'a str,
) -> zbus::Result<zbus::Proxy<'a>> {
    zbus::proxy::Builder::new(connection)
        .destination(owner)
        .path(path)
        .interface(interface)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
}

fn collection_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

/// Whether the D-Bus connection `owner` is a FactorSeal process, judged by
/// its executable's file name (never its path: NixOS store paths change per
/// build).
pub(crate) async fn is_factorseal(connection: &Connection, owner: &str) -> zbus::Result<bool> {
    let bus = fdo::DBusProxy::new(connection).await?;
    let pid = bus
        .get_connection_unix_process_id(owner.try_into()?)
        .await?;
    is_factorseal_process(pid).map_err(|error| zbus::Error::Failure(error.to_string()))
}

/// Whether process `pid` is FactorSeal, by its executable's file name.
///
/// A process that isn't dumpable hides `/proc/<pid>/exe` even from its own
/// user: gnome-keyring behind NixOS's capability wrapper (`cap_ipc_lock`),
/// and FactorSeal's own agent (`harden_key_owner`). Then the names that stay
/// readable decide: `comm` and the first word of `cmdline`, FactorSeal if
/// either looks like it. The process sets both itself; the check guards
/// against reading FactorSeal's own items by accident, and erring toward
/// FactorSeal only refuses.
pub(crate) fn is_factorseal_process(pid: u32) -> std::io::Result<bool> {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(executable) => Ok(executable.file_name().is_some_and(is_factorseal_executable)),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let comm = std::fs::read(format!("/proc/{pid}/comm"))?;
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))?;
            Ok(readable_names(&comm, &cmdline)
                .iter()
                .any(|name| is_factorseal_executable(name.as_ref())))
        }
        Err(error) => Err(error),
    }
}

/// The process names `comm` (one line) and `cmdline` (NUL-separated
/// arguments, the first being the program as started) give.
fn readable_names(comm: &[u8], cmdline: &[u8]) -> Vec<String> {
    let comm = String::from_utf8_lossy(comm)
        .trim_end_matches('\n')
        .to_owned();
    let program = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
    let program = std::path::Path::new(std::ffi::OsStr::from_bytes(program))
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    vec![comm, program]
}

/// Whether an executable file name is FactorSeal's. Nix wraps programs by
/// moving each to `.<name>-wrapped` (once per wrapper hook), so a NixOS
/// Desktop runs as `.factorseal-desktop-wrapped`; those are unwrapped first.
/// A FactorSeal started through the dynamic loader (`ld-linux… factorseal`)
/// shows the loader's name and is not recognized; no packaging here does
/// that, and the miss only means its own items would be read back.
pub(crate) fn is_factorseal_executable(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    let mut name = name.trim_start_matches('.');
    while let Some(inner) = name.strip_suffix("-wrapped") {
        name = inner;
    }
    name.starts_with("factorseal")
}

impl Legacy {
    pub(crate) async fn connect() -> zbus::Result<Self> {
        let connection = Connection::session().await?;
        let owner = Self::owner(&connection).await?;
        Self::connect_on(connection, owner).await
    }

    /// [`Self::connect`], refusing when FactorSeal itself owns the name:
    /// it would read FactorSeal's own items back.
    pub(crate) async fn connect_foreign() -> Result<Self, String> {
        let connection = Connection::session()
            .await
            .map_err(|error| format!("no session bus: {error}"))?;
        Self::start(&connection).await?;
        let owner = Self::owner(&connection)
            .await
            .map_err(|_| "no Secret Service on the session bus".to_owned())?;
        if is_factorseal(&connection, &owner)
            .await
            .map_err(|error| format!("cannot identify the Secret Service: {error}"))?
        {
            return Err(
                "the Secret Service on the session bus is FactorSeal itself, not gnome-keyring"
                    .to_owned(),
            );
        }
        Self::connect_on(connection, owner)
            .await
            .map_err(|error| format!("cannot open a Secret Service session: {error}"))
    }

    /// Start the Secret Service if D-Bus can activate it and it isn't
    /// running yet, as gnome-keyring after WSL starts a distro. It starts
    /// locked, so this asks nothing. `GetNameOwner` alone never activates.
    /// Without a service file dbus-daemon answers `ServiceUnknown` even
    /// while the name has an owner, so that leaves the owner lookup to
    /// decide.
    async fn start(connection: &Connection) -> Result<(), String> {
        let bus = fdo::DBusProxy::new(connection)
            .await
            .map_err(|error| format!("no session bus: {error}"))?;
        let name = "org.freedesktop.secrets"
            .try_into()
            .map_err(|error: zbus::Error| error.to_string())?;
        match bus.start_service_by_name(name, 0).await {
            Ok(_) | Err(fdo::Error::ServiceUnknown(_)) => Ok(()),
            Err(error) => Err(format!("the Secret Service could not be started: {error}")),
        }
    }

    async fn owner(connection: &Connection) -> zbus::Result<String> {
        let bus = fdo::DBusProxy::new(connection).await?;
        Ok(bus
            .get_name_owner("org.freedesktop.secrets".try_into()?)
            .await?
            .to_string())
    }

    pub(crate) async fn connect_on(connection: Connection, owner: String) -> zbus::Result<Self> {
        let service = proxy(
            &connection,
            &owner,
            SERVICE_PATH,
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let (_, session): (OwnedVariant, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Variant::from("")))
            .await?;
        drop(service);
        Ok(Self {
            connection,
            owner,
            session,
            unlock_timeout: UNLOCK_TIMEOUT,
            dismiss_timeout: DISMISS_TIMEOUT,
        })
    }

    pub(crate) async fn close(self) {
        if let Ok(session) = proxy(
            &self.connection,
            &self.owner,
            self.session.as_str(),
            "org.freedesktop.Secret.Session",
        )
        .await
        {
            let _ = session.call::<_, _, ()>("Close", &()).await;
        }
    }

    /// Each persistent collection once: never the in-memory `session` one,
    /// and never an alias of another.
    async fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>> {
        let service = proxy(
            &self.connection,
            &self.owner,
            SERVICE_PATH,
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await?;
        let mut seen = HashSet::new();
        Ok(paths
            .into_iter()
            .filter(|path| {
                path.as_str() != SESSION_COLLECTION && !path.as_str().starts_with(ALIAS_PREFIX)
            })
            .filter(|path| seen.insert(path.clone()))
            .collect())
    }

    async fn collection_locked(&self, path: &OwnedObjectPath) -> zbus::Result<bool> {
        proxy(
            &self.connection,
            &self.owner,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )
        .await?
        .get_property("Locked")
        .await
    }

    /// The collection's items with their metadata, no secrets.
    async fn items(
        &self,
        path: &OwnedObjectPath,
    ) -> zbus::Result<Vec<(OwnedObjectPath, LegacyItem)>> {
        let collection = proxy(
            &self.connection,
            &self.owner,
            path.as_str(),
            "org.freedesktop.Secret.Collection",
        )
        .await?;
        let paths: Vec<OwnedObjectPath> = collection.get_property("Items").await?;
        let mut seen = HashSet::new();
        let mut items = Vec::new();
        for item_path in paths {
            if !seen.insert(item_path.clone()) {
                continue;
            }
            let item = proxy(
                &self.connection,
                &self.owner,
                item_path.as_str(),
                "org.freedesktop.Secret.Item",
            )
            .await?;
            let label: String = item.get_property("Label").await?;
            let modified: u64 = item.get_property("Modified").await?;
            let read = LegacyItem {
                collection: collection_name(path.as_str()),
                locked: item.get_property("Locked").await?,
                label: Some(label).filter(|label| !label.is_empty()),
                modified: Some(modified).filter(|modified| *modified != 0),
                attributes: item.get_property("Attributes").await?,
                secret: None,
            };
            drop(item);
            items.push((item_path, read));
        }
        Ok(items)
    }

    /// Every item of every collection, locked ones included, with what the
    /// service shows without an unlock, and which collections are locked.
    /// Never unlocks, never reads a secret.
    pub(crate) async fn inventory(&self) -> zbus::Result<SecretServiceRead> {
        let mut read = SecretServiceRead::default();
        for path in self.collections().await? {
            read.collections.push(collection_name(path.as_str()));
            if self.collection_locked(&path).await? {
                read.locked_collections.push(collection_name(path.as_str()));
            }
            read.items
                .extend(self.items(&path).await?.into_iter().map(|(_, item)| item));
        }
        Ok(read)
    }

    /// Every item with its secret. A locked collection is unlocked only when
    /// `unlock` is set, one collection at a time, so each password-protected
    /// collection gets its own prompt; a dismissed prompt skips that
    /// collection and the others continue.
    pub(crate) async fn read_all(&self, unlock: bool) -> zbus::Result<SecretServiceRead> {
        let mut read = SecretServiceRead::default();
        for path in self.collections().await? {
            let name = collection_name(path.as_str());
            if self.collection_locked(&path).await? {
                if !unlock {
                    read.skipped_collections.push((name, "locked".to_owned()));
                    continue;
                }
                match self.unlock(&path).await? {
                    Unlock::Unlocked => {}
                    Unlock::Dismissed => {
                        read.skipped_collections
                            .push((name, "unlock dismissed".to_owned()));
                        continue;
                    }
                    Unlock::TimedOut => {
                        read.skipped_collections
                            .push((name, "unlock timed out".to_owned()));
                        continue;
                    }
                }
                if self.collection_locked(&path).await? {
                    read.skipped_collections
                        .push((name, "still locked after the unlock".to_owned()));
                    continue;
                }
            }
            let items = self.items(&path).await?;
            let mut secrets = HashMap::new();
            for batch in items.chunks(SECRETS_BATCH) {
                let paths: Vec<&OwnedObjectPath> = batch.iter().map(|(path, _)| path).collect();
                secrets.extend(self.secrets(&paths).await?);
            }
            for (item_path, mut item) in items {
                item.secret = secrets.remove(&item_path);
                read.items.push(item);
            }
        }
        Ok(read)
    }

    async fn secrets(
        &self,
        paths: &[&OwnedObjectPath],
    ) -> zbus::Result<HashMap<OwnedObjectPath, (Zeroizing<Vec<u8>>, String)>> {
        let service = proxy(
            &self.connection,
            &self.owner,
            SERVICE_PATH,
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let secrets: HashMap<OwnedObjectPath, super::Secret> =
            service.call("GetSecrets", &(paths, &self.session)).await?;
        let mut result = HashMap::new();
        for (path, (session, parameters, value, content_type)) in secrets {
            let value = Zeroizing::new(value);
            if session != self.session || !parameters.is_empty() {
                return Err(zbus::Error::Failure(
                    "invalid Secret Service session reply".to_owned(),
                ));
            }
            result.insert(path, (value, content_type));
        }
        Ok(result)
    }

    /// Unlock one collection, through its prompt if the service asks for
    /// one. A prompt unanswered for [`Self::unlock_timeout`] is dismissed.
    async fn unlock(&self, path: &OwnedObjectPath) -> zbus::Result<Unlock> {
        let service = proxy(
            &self.connection,
            &self.owner,
            SERVICE_PATH,
            "org.freedesktop.Secret.Service",
        )
        .await?;
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            service.call("Unlock", &(vec![path],)).await?;
        if prompt.as_str() == "/" {
            return Ok(Unlock::Unlocked);
        }
        let prompt = proxy(
            &self.connection,
            &self.owner,
            prompt.as_str(),
            "org.freedesktop.Secret.Prompt",
        )
        .await?;
        // Subscribe before prompting, or a quick Completed is lost.
        let mut completed = prompt.receive_signal("Completed").await?;
        prompt.call::<_, _, ()>("Prompt", &("",)).await?;
        let next =
            std::future::poll_fn(|context| std::pin::Pin::new(&mut completed).poll_next(context));
        let Some(signal) = within(self.unlock_timeout, next).await else {
            // Best effort, and bounded: the service that left the prompt
            // unanswered may not answer this either.
            let _ = within(
                self.dismiss_timeout,
                prompt.call::<_, _, ()>("Dismiss", &()),
            )
            .await;
            return Ok(Unlock::TimedOut);
        };
        let signal =
            signal.ok_or_else(|| zbus::Error::Failure("the unlock prompt vanished".to_owned()))?;
        let (dismissed, _): (bool, OwnedVariant) = signal.body().deserialize()?;
        Ok(if dismissed {
            Unlock::Dismissed
        } else {
            Unlock::Unlocked
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
