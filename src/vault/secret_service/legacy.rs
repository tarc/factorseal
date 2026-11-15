//! Read another Secret Service (gnome-keyring, usually) on the session bus.
//!
//! The Wi-Fi migration searches only NetworkManager's attributes through it.
//! The keyring import lists every item ([`Legacy::inventory`]), never
//! unlocking and never reading a secret, or reads every item with its secret
//! ([`Legacy::read_all`]), unlocking locked collections one at a time only
//! when the caller asks.

// Until `factorseal export-secret-service` uses it.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

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
}

/// One item of the other Secret Service, as it reported it: on a locked
/// gnome-keyring item, no label, no modified time, hashed attribute values
/// under `gkr:compat:hashed:<name>` and a placeholder `xdg:schema`.
pub(crate) type LegacyItem = crate::vault::KeyringSourceItem;

/// What a read found, and the collections it could not read with why.
#[derive(Default)]
pub(crate) struct LegacyRead {
    pub(crate) items: Vec<LegacyItem>,
    pub(crate) skipped_collections: Vec<(String, String)>,
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
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|error| zbus::Error::Failure(error.to_string()))?;
    Ok(executable
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("factorseal")))
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
    /// service shows without an unlock. Never unlocks, never reads a secret.
    pub(crate) async fn inventory(&self) -> zbus::Result<LegacyRead> {
        let mut read = LegacyRead::default();
        for path in self.collections().await? {
            read.items
                .extend(self.items(&path).await?.into_iter().map(|(_, item)| item));
        }
        Ok(read)
    }

    /// Every item with its secret. A locked collection is unlocked only when
    /// `unlock` is set, one collection at a time, so each password-protected
    /// collection gets its own prompt; a dismissed prompt skips that
    /// collection and the others continue.
    pub(crate) async fn read_all(&self, unlock: bool) -> zbus::Result<LegacyRead> {
        let mut read = LegacyRead::default();
        for path in self.collections().await? {
            let name = collection_name(path.as_str());
            if self.collection_locked(&path).await? {
                if !unlock {
                    read.skipped_collections.push((name, "locked".to_owned()));
                    continue;
                }
                if !self.unlock(&path).await? {
                    read.skipped_collections
                        .push((name, "unlock dismissed".to_owned()));
                    continue;
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
    /// one. Returns whether it was not dismissed.
    async fn unlock(&self, path: &OwnedObjectPath) -> zbus::Result<bool> {
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
            return Ok(true);
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
        let signal =
            std::future::poll_fn(|context| std::pin::Pin::new(&mut completed).poll_next(context))
                .await
                .ok_or_else(|| zbus::Error::Failure("the unlock prompt vanished".to_owned()))?;
        let (dismissed, _): (bool, OwnedVariant) = signal.body().deserialize()?;
        Ok(!dismissed)
    }
}

#[cfg(test)]
pub(crate) mod tests;
