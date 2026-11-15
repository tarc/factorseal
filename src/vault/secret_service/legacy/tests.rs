//! A fake gnome-keyring on the private test bus: a `login` collection and a
//! second one, both locked and password-protected, the in-memory `session`
//! collection, and the `aliases/default` alias of `login`. A locked item
//! shows what gnome-keyring shows before its collection was ever unlocked:
//! no label, modified 0, hashed attributes and a placeholder `xdg:schema`.

use super::*;
use std::sync::{Arc, Mutex};
use zbus::object_server::SignalEmitter;

const ROOT: &str = "/org/freedesktop/secrets";

struct FakeItem {
    label: &'static str,
    attributes: &'static [(&'static str, &'static str)],
    hashed: &'static [(&'static str, &'static str)],
    modified: u64,
    value: &'static [u8],
}

struct FakeCollection {
    name: &'static str,
    locked: bool,
    dismiss: bool,
    /// The prompt never completes, as when gcr has no display.
    hang: bool,
    items: Vec<FakeItem>,
}

#[derive(Default)]
struct Calls {
    unlocks: usize,
    prompts: Vec<&'static str>,
    dismissed: Vec<&'static str>,
    get_secrets: usize,
}

struct Fake {
    collections: Vec<FakeCollection>,
    calls: Calls,
    /// Dismiss never replies, as from a wedged service.
    wedged_dismiss: bool,
}

type Shared = Arc<Mutex<Fake>>;

fn path(value: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(value).unwrap()
}

fn collection_path(name: &str) -> String {
    format!("{ROOT}/collection/{name}")
}

struct Service(Shared);
struct Collection(Shared, usize);
struct Item(Shared, usize, usize);
struct Prompt(Shared, usize);
struct Session;

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
#[allow(clippy::unused_self, clippy::needless_pass_by_value)] // D-Bus dispatch methods.
impl Service {
    fn open_session(&self, algorithm: &str, input: Variant<'_>) -> (OwnedVariant, OwnedObjectPath) {
        let _ = input;
        assert_eq!(algorithm, "plain");
        (
            OwnedVariant::try_from(Variant::from("")).unwrap(),
            path("/session"),
        )
    }
    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        let mut paths: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .collections
            .iter()
            .map(|collection| path(&collection_path(collection.name)))
            .collect();
        paths.insert(1, path(&format!("{ROOT}/aliases/default")));
        paths
    }
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        assert_eq!(objects.len(), 1, "one collection per unlock");
        let index = {
            let mut fake = self.0.lock().unwrap();
            fake.calls.unlocks += 1;
            fake.collections
                .iter()
                .position(|collection| collection_path(collection.name) == objects[0].as_str())
                .unwrap()
        };
        let prompt = format!("{ROOT}/prompt/{index}");
        server
            .at(prompt.as_str(), Prompt(Arc::clone(&self.0), index))
            .await
            .unwrap();
        (Vec::new(), path(&prompt))
    }
    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> HashMap<OwnedObjectPath, crate::vault::secret_service::Secret> {
        let mut fake = self.0.lock().unwrap();
        fake.calls.get_secrets += 1;
        let mut secrets = HashMap::new();
        for item in items {
            for collection in &fake.collections {
                for (index, fake_item) in collection.items.iter().enumerate() {
                    if format!("{}/{index}", collection_path(collection.name)) == item.as_str()
                        && !collection.locked
                    {
                        secrets.insert(
                            item.clone(),
                            (
                                session.clone(),
                                Vec::new(),
                                fake_item.value.to_vec(),
                                "text/plain".to_owned(),
                            ),
                        );
                    }
                }
            }
        }
        secrets
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        let fake = self.0.lock().unwrap();
        let collection = &fake.collections[self.1];
        (0..collection.items.len())
            .map(|index| path(&format!("{}/{index}", collection_path(collection.name))))
            .collect()
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().collections[self.1].locked
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    fn label(&self) -> String {
        let fake = self.0.lock().unwrap();
        let collection = &fake.collections[self.1];
        if collection.locked {
            String::new()
        } else {
            collection.items[self.2].label.to_owned()
        }
    }
    #[zbus(property)]
    fn modified(&self) -> u64 {
        let fake = self.0.lock().unwrap();
        let collection = &fake.collections[self.1];
        if collection.locked {
            0
        } else {
            collection.items[self.2].modified
        }
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        self.0.lock().unwrap().collections[self.1].locked
    }
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        let fake = self.0.lock().unwrap();
        let collection = &fake.collections[self.1];
        let item = &collection.items[self.2];
        if collection.locked {
            let mut attributes: HashMap<String, String> = item
                .hashed
                .iter()
                .map(|(name, hash)| (format!("gkr:compat:hashed:{name}"), (*hash).to_owned()))
                .collect();
            attributes.insert(
                "xdg:schema".to_owned(),
                "org.freedesktop.Secret.Generic".to_owned(),
            );
            attributes
        } else {
            item.attributes
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect()
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        window_id: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        let _ = window_id;
        let dismissed = {
            let mut fake = self.0.lock().unwrap();
            let name = fake.collections[self.1].name;
            fake.calls.prompts.push(name);
            let collection = &mut fake.collections[self.1];
            if collection.hang {
                return Ok(());
            }
            if !collection.dismiss {
                collection.locked = false;
            }
            collection.dismiss
        };
        Self::completed(
            &emitter,
            dismissed,
            OwnedVariant::try_from(Variant::from(Vec::<OwnedObjectPath>::new())).unwrap(),
        )
        .await
        .unwrap();
        Ok(())
    }
    async fn dismiss(&self) {
        let wedged = {
            let mut fake = self.0.lock().unwrap();
            let name = fake.collections[self.1].name;
            fake.calls.dismissed.push(name);
            fake.wedged_dismiss
        };
        if wedged {
            std::future::pending::<()>().await;
        }
    }
    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedVariant,
    ) -> zbus::Result<()>;
}

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
#[allow(clippy::unused_self)] // D-Bus dispatch method.
impl Session {
    fn close(&self) {}
}

fn fake(dismiss_other: bool) -> Fake {
    Fake {
        collections: vec![
            FakeCollection {
                name: "login",
                locked: true,
                dismiss: false,
                hang: false,
                items: vec![
                    FakeItem {
                        label: "GitHub CLI",
                        attributes: &[("service", "gh:github.com"), ("username", "octo")],
                        hashed: &[
                            ("service", "5c6f1a3e9e4e4f0c5b0b5a4a7d0e3c1b"),
                            ("username", "1d8a7b2f6c4e3d5a9b0c1e2f3a4b5c6d"),
                        ],
                        modified: 1_700_000_000,
                        value: b"gho_token",
                    },
                    FakeItem {
                        label: "Port",
                        attributes: &[("xdg:schema", "test.int"), ("port", "8080")],
                        hashed: &[
                            ("xdg:schema", "7675a45f00000000000000000000000a"),
                            ("port", "d4a973e300000000000000000000000b"),
                        ],
                        modified: 1_700_000_001,
                        value: b"port secret",
                    },
                ],
            },
            FakeCollection {
                name: "session",
                locked: false,
                dismiss: false,
                hang: false,
                items: vec![FakeItem {
                    label: "in memory",
                    attributes: &[("temporary", "yes")],
                    hashed: &[],
                    modified: 1,
                    value: b"never read",
                }],
            },
            FakeCollection {
                name: "other",
                locked: true,
                dismiss: dismiss_other,
                hang: false,
                items: vec![FakeItem {
                    label: "VS Code",
                    attributes: &[("service", "vscode")],
                    hashed: &[("service", "0123456789abcdef0123456789abcdef")],
                    modified: 1_700_000_002,
                    value: b"vscode secret",
                }],
            },
        ],
        calls: Calls::default(),
        wedged_dismiss: false,
    }
}

/// Serves `fake` on its own connection to the private bus and returns a
/// reader connected to it, with the fake's state for assertions.
async fn serve(fake: Fake) -> (Connection, Legacy, Shared) {
    let shared = Arc::new(Mutex::new(fake));
    let server = Connection::session().await.unwrap();
    let objects = server.object_server();
    objects
        .at(ROOT, Service(Arc::clone(&shared)))
        .await
        .unwrap();
    objects.at("/session", Session).await.unwrap();
    let collections: Vec<_> = shared
        .lock()
        .unwrap()
        .collections
        .iter()
        .map(|collection| (collection.name, collection.items.len()))
        .collect();
    for (index, (name, items)) in collections.into_iter().enumerate() {
        objects
            .at(
                collection_path(name).as_str(),
                Collection(Arc::clone(&shared), index),
            )
            .await
            .unwrap();
        if name == "login" {
            objects
                .at(
                    format!("{ROOT}/aliases/default").as_str(),
                    Collection(Arc::clone(&shared), index),
                )
                .await
                .unwrap();
        }
        for item in 0..items {
            objects
                .at(
                    format!("{}/{item}", collection_path(name)).as_str(),
                    Item(Arc::clone(&shared), index, item),
                )
                .await
                .unwrap();
        }
    }
    let legacy = Legacy::connect_on(
        Connection::session().await.unwrap(),
        server.unique_name().unwrap().to_string(),
    )
    .await
    .unwrap();
    (server, legacy, shared)
}

fn private_bus() -> bool {
    std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_some()
}

/// Collection, locked, label, modified and value of each item.
type Summary = (String, bool, Option<String>, Option<u64>, Option<Vec<u8>>);

fn summary(read: &SecretServiceRead) -> Vec<Summary> {
    read.items
        .iter()
        .map(|item| {
            (
                item.collection.clone(),
                item.locked,
                item.label.clone(),
                item.modified,
                item.secret.as_ref().map(|(value, _)| value.to_vec()),
            )
        })
        .collect()
}

#[tokio::test]
async fn inventory_lists_locked_items_without_unlocking_or_reading_secrets() {
    if !private_bus() {
        return;
    }
    let (_server, legacy, shared) = serve(fake(false)).await;
    let read = legacy.inventory().await.unwrap();
    // login once despite its alias, no session collection, both locked.
    assert_eq!(
        summary(&read),
        [
            ("login".to_owned(), true, None, None, None),
            ("login".to_owned(), true, None, None, None),
            ("other".to_owned(), true, None, None, None),
        ]
    );
    assert_eq!(
        read.items[0].attributes,
        HashMap::from([
            (
                "gkr:compat:hashed:service".to_owned(),
                "5c6f1a3e9e4e4f0c5b0b5a4a7d0e3c1b".to_owned()
            ),
            (
                "gkr:compat:hashed:username".to_owned(),
                "1d8a7b2f6c4e3d5a9b0c1e2f3a4b5c6d".to_owned()
            ),
            (
                "xdg:schema".to_owned(),
                "org.freedesktop.Secret.Generic".to_owned()
            ),
        ])
    );
    assert_eq!(read.skipped_collections, []);
    {
        let fake = shared.lock().unwrap();
        assert_eq!(fake.calls.unlocks, 0);
        assert_eq!(fake.calls.get_secrets, 0);
    }
    legacy.close().await;
}

#[tokio::test]
async fn read_all_without_unlock_skips_locked_collections() {
    if !private_bus() {
        return;
    }
    let mut unlocked = fake(false);
    unlocked.collections[0].locked = false;
    let (_server, legacy, shared) = serve(unlocked).await;
    let read = legacy.read_all(false).await.unwrap();
    assert_eq!(
        summary(&read),
        [
            (
                "login".to_owned(),
                false,
                Some("GitHub CLI".to_owned()),
                Some(1_700_000_000),
                Some(b"gho_token".to_vec())
            ),
            (
                "login".to_owned(),
                false,
                Some("Port".to_owned()),
                Some(1_700_000_001),
                Some(b"port secret".to_vec())
            ),
        ]
    );
    assert_eq!(
        read.items[1].attributes,
        HashMap::from([
            ("xdg:schema".to_owned(), "test.int".to_owned()),
            ("port".to_owned(), "8080".to_owned()),
        ])
    );
    assert_eq!(
        read.skipped_collections,
        [("other".to_owned(), "locked".to_owned())]
    );
    assert_eq!(shared.lock().unwrap().calls.unlocks, 0);
    legacy.close().await;
}

#[tokio::test]
async fn read_all_prompts_once_per_locked_collection() {
    if !private_bus() {
        return;
    }
    let (_server, legacy, shared) = serve(fake(false)).await;
    let read = legacy.read_all(true).await.unwrap();
    assert_eq!(
        summary(&read)
            .into_iter()
            .map(|(collection, _, label, _, value)| (collection, label, value))
            .collect::<Vec<_>>(),
        [
            (
                "login".to_owned(),
                Some("GitHub CLI".to_owned()),
                Some(b"gho_token".to_vec())
            ),
            (
                "login".to_owned(),
                Some("Port".to_owned()),
                Some(b"port secret".to_vec())
            ),
            (
                "other".to_owned(),
                Some("VS Code".to_owned()),
                Some(b"vscode secret".to_vec())
            ),
        ]
    );
    assert_eq!(read.skipped_collections, []);
    assert_eq!(shared.lock().unwrap().calls.prompts, ["login", "other"]);
    legacy.close().await;
}

#[tokio::test]
async fn a_dismissed_unlock_skips_only_that_collection() {
    if !private_bus() {
        return;
    }
    let (_server, legacy, shared) = serve(fake(true)).await;
    let read = legacy.read_all(true).await.unwrap();
    assert_eq!(
        read.items
            .iter()
            .map(|item| item.collection.as_str())
            .collect::<Vec<_>>(),
        ["login", "login"]
    );
    assert!(read.items.iter().all(|item| item.secret.is_some()));
    assert_eq!(
        read.skipped_collections,
        [("other".to_owned(), "unlock dismissed".to_owned())]
    );
    assert_eq!(shared.lock().unwrap().calls.prompts, ["login", "other"]);
    legacy.close().await;
}

#[tokio::test]
async fn factorseal_is_recognized_by_its_executable_name() {
    if !private_bus() {
        return;
    }
    let (server, legacy, _shared) = serve(fake(false)).await;
    // The fake is served by this test binary, `factorseal-<hash>`.
    assert!(
        is_factorseal(&legacy.connection, server.unique_name().unwrap().as_str())
            .await
            .unwrap()
    );
    // The bus daemon is not.
    assert!(
        !is_factorseal(&legacy.connection, "org.freedesktop.DBus")
            .await
            .unwrap()
    );
    legacy.close().await;
}

#[test]
fn wrapped_factorseal_executables_are_recognized() {
    for name in [
        "factorseal",
        "factorseal-desktop",
        ".factorseal-desktop-wrapped",
        "..factorseal-desktop-wrapped-wrapped",
        "factorseal-0a1b2c3d",
    ] {
        assert!(is_factorseal_executable(name.as_ref()), "{name}");
    }
    for name in [
        "gnome-keyring-daemon",
        ".gnome-keyring-daemon-wrapped",
        "kwalletd6",
    ] {
        assert!(!is_factorseal_executable(name.as_ref()), "{name}");
    }
}

#[tokio::test]
async fn an_unlock_prompt_that_never_completes_times_out_and_is_dismissed() {
    if !private_bus() {
        return;
    }
    let mut hanging = fake(false);
    hanging.collections[2].hang = true;
    let (_server, mut legacy, shared) = serve(hanging).await;
    legacy.unlock_timeout = std::time::Duration::from_millis(300);
    let read = legacy.read_all(true).await.unwrap();
    assert_eq!(
        read.items
            .iter()
            .map(|item| item.collection.as_str())
            .collect::<Vec<_>>(),
        ["login", "login"]
    );
    assert_eq!(
        read.skipped_collections,
        [("other".to_owned(), "unlock timed out".to_owned())]
    );
    assert_eq!(shared.lock().unwrap().calls.dismissed, ["other"]);
    legacy.close().await;
}

#[tokio::test]
async fn secrets_are_read_in_batches_across_the_boundary() {
    if !private_bus() {
        return;
    }
    let mut many = fake(false);
    many.collections[0].locked = false;
    let item = || FakeItem {
        label: "many",
        attributes: &[("service", "many")],
        hashed: &[],
        modified: 1,
        value: b"many value",
    };
    many.collections[0].items = (0..=SECRETS_BATCH).map(|_| item()).collect();
    let (_server, legacy, shared) = serve(many).await;
    let read = legacy.read_all(false).await.unwrap();
    assert_eq!(read.items.len(), SECRETS_BATCH + 1);
    assert!(read.items.iter().all(|item| {
        item.secret
            .as_ref()
            .is_some_and(|(value, _)| &**value == b"many value")
    }));
    assert_eq!(shared.lock().unwrap().calls.get_secrets, 2);
    legacy.close().await;
}

#[tokio::test]
async fn a_wedged_dismiss_does_not_hold_up_the_read() {
    if !private_bus() {
        return;
    }
    let mut hanging = fake(false);
    hanging.collections[2].hang = true;
    hanging.wedged_dismiss = true;
    let (_server, mut legacy, _shared) = serve(hanging).await;
    legacy.unlock_timeout = std::time::Duration::from_millis(300);
    legacy.dismiss_timeout = std::time::Duration::from_millis(300);
    let read = tokio::time::timeout(std::time::Duration::from_secs(20), legacy.read_all(true))
        .await
        .expect("the read finishes")
        .unwrap();
    assert_eq!(
        read.skipped_collections,
        [("other".to_owned(), "unlock timed out".to_owned())]
    );
}

#[tokio::test]
async fn a_prompt_answered_within_the_limit_unlocks() {
    if !private_bus() {
        return;
    }
    let (_server, mut legacy, shared) = serve(fake(false)).await;
    legacy.unlock_timeout = std::time::Duration::from_secs(5);
    let read = legacy.read_all(true).await.unwrap();
    assert_eq!(read.skipped_collections, []);
    assert_eq!(read.items.len(), 3);
    assert_eq!(shared.lock().unwrap().calls.dismissed, Vec::<&str>::new());
    legacy.close().await;
}
