use super::*;

fn attributes(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// As a locked gnome-keyring item shows `pairs`: each value as an MD5 under
/// `gkr:compat:hashed:<name>`, and a plain `xdg:schema`, the generic one.
/// gnome-keyring leaves the generic schema itself unhashed.
fn hashed(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    let mut hashed: HashMap<String, String> = pairs
        .iter()
        .filter(|(name, value)| !(*name == "xdg:schema" && *value == GENERIC))
        .map(|(name, value)| {
            (
                format!("gkr:compat:hashed:{name}"),
                hex::encode(Md5::digest(value.as_bytes())),
            )
        })
        .collect();
    hashed.insert("xdg:schema".to_owned(), GENERIC.to_owned());
    hashed
}

const GENERIC: &str = "org.freedesktop.Secret.Generic";

fn item(
    collection: &str,
    label: &str,
    modified: u64,
    attributes: HashMap<String, String>,
    value: Option<&[u8]>,
) -> KeyringSourceItem {
    KeyringSourceItem {
        collection: collection.to_owned(),
        locked: false,
        label: Some(label.to_owned()),
        modified: Some(modified),
        attributes,
        secret: value.map(|value| (Zeroizing::new(value.to_vec()), "text/plain".to_owned())),
    }
}

fn locked(collection: &str, attributes: HashMap<String, String>) -> KeyringSourceItem {
    KeyringSourceItem {
        collection: collection.to_owned(),
        locked: true,
        label: None,
        modified: None,
        attributes,
        secret: None,
    }
}

const PORT: &[(&str, &str)] = &[
    ("xdg:schema", "test.int"),
    ("port", "8080"),
    ("host", "example.org"),
];

fn reasons(import: &KeyringImport) -> Vec<(&str, KeyringSkipReason)> {
    import
        .skipped
        .iter()
        .map(|skipped| (skipped.label.as_deref().unwrap_or("?"), skipped.reason))
        .collect()
}

fn labels(import: &KeyringImport) -> Vec<&str> {
    import
        .items
        .iter()
        .map(|item| item.label.as_deref().unwrap_or("?"))
        .collect()
}

#[test]
fn the_fingerprint_is_pinned() {
    // Computed independently (Python hashlib) from the encoding in the plan.
    assert_eq!(
        hex::encode(keyring_fingerprint(&attributes(PORT)).unwrap()),
        "786097a0da05fd756c858c9f65ec38f3fd9485f684d626d40504649cbdf8cbc7"
    );
}

#[test]
fn hashed_and_plain_attributes_give_the_same_fingerprint() {
    // The integer attribute reaches gnome-keyring as the string "8080", and
    // the locked item's plain xdg:schema is a placeholder, ignored; its real
    // value is in the hashed set.
    assert_eq!(
        keyring_fingerprint(&hashed(PORT)),
        keyring_fingerprint(&attributes(PORT))
    );
    // A reserved name never counts in a plain set.
    let mut plain = attributes(PORT);
    plain.insert("gkr:compat:other".to_owned(), "x".to_owned());
    assert_eq!(
        keyring_fingerprint(&plain),
        keyring_fingerprint(&attributes(PORT))
    );
    // Values and names both count.
    assert_ne!(
        keyring_fingerprint(&attributes(&[("port", "8081")])),
        keyring_fingerprint(&attributes(&[("port", "8080")]))
    );
    assert_ne!(
        keyring_fingerprint(&attributes(&[("ab", "c")])),
        keyring_fingerprint(&attributes(&[("a", "bc")]))
    );
}

#[test]
fn items_without_attributes_have_no_fingerprint_and_are_skipped() {
    assert_eq!(keyring_fingerprint(&HashMap::new()), None);
    assert_eq!(
        keyring_fingerprint(&attributes(&[("gkr:compat:x", "y")])),
        None
    );
    let import = map_keyring_items(vec![item("login", "bare", 1, HashMap::new(), None)], false);
    assert_eq!(
        reasons(&import),
        [("bare", KeyringSkipReason::NoAttributes)]
    );
    assert_eq!(import.items, []);
}

#[test]
fn a_malformed_hash_is_unreadable() {
    let mut broken = hashed(PORT);
    broken.insert("gkr:compat:hashed:port".to_owned(), "not hex".to_owned());
    let import = map_keyring_items(vec![locked("login", broken)], false);
    assert_eq!(reasons(&import), [("?", KeyringSkipReason::Unreadable)]);
}

#[test]
fn duplicates_collapse_to_the_most_recently_modified() {
    let gh = &[("service", "gh:github.com")];
    let import = map_keyring_items(
        vec![
            item("login", "older", 5, attributes(gh), Some(b"one")),
            item("other", "newer", 9, attributes(gh), Some(b"two")),
            item("login", "tie", 9, attributes(gh), Some(b"three")),
        ],
        true,
    );
    assert_eq!(labels(&import), ["newer"]);
    assert_eq!(
        reasons(&import),
        [
            ("older", KeyringSkipReason::Duplicate),
            ("tie", KeyringSkipReason::Duplicate)
        ]
    );
    assert_eq!(import.portable[0].1.as_slice(), b"two");
}

#[test]
fn wi_fi_passwords_are_left_to_their_own_move_even_when_locked() {
    let nm = &[
        ("connection-uuid", "4f2c"),
        ("setting-name", "802-11-wireless-security"),
        ("setting-key", "psk"),
    ];
    let import = map_keyring_items(
        vec![
            item("login", "wifi", 1, attributes(nm), None),
            locked("login", hashed(nm)),
        ],
        false,
    );
    assert_eq!(
        reasons(&import),
        [
            ("wifi", KeyringSkipReason::NetworkManager),
            ("?", KeyringSkipReason::NetworkManager)
        ]
    );
}

#[test]
fn value_rules_apply_only_with_values() {
    let large = vec![b'x'; MAX_IMPORTED_VALUE_BYTES + 1];
    let at_limit = vec![b'x'; MAX_IMPORTED_VALUE_BYTES];
    let items = || {
        vec![
            item("login", "large", 1, attributes(&[("a", "1")]), Some(&large)),
            item(
                "login",
                "fits",
                1,
                attributes(&[("a", "2")]),
                Some(&at_limit),
            ),
            item("login", "unread", 1, attributes(&[("a", "3")]), None),
        ]
    };
    let inventory = map_keyring_items(items(), false);
    assert_eq!(labels(&inventory), ["large", "fits", "unread"]);
    assert_eq!(inventory.skipped, []);
    let export = map_keyring_items(items(), true);
    assert_eq!(labels(&export), ["fits"]);
    assert_eq!(
        reasons(&export),
        [
            ("large", KeyringSkipReason::TooLarge),
            ("unread", KeyringSkipReason::Unreadable)
        ]
    );
}

#[test]
fn a_value_beside_hashed_attributes_is_not_imported() {
    let mut item = locked("login", hashed(PORT));
    item.secret = Some((Zeroizing::new(b"x".to_vec()), String::new()));
    let import = map_keyring_items(vec![item], true);
    assert_eq!(reasons(&import), [("?", KeyringSkipReason::Unreadable)]);
}

#[test]
fn inventory_and_export_agree_on_fingerprints() {
    let gh = &[
        ("service", "gh:github.com"),
        ("username", "octo"),
        ("xdg:schema", GENERIC),
    ];
    let inventory = map_keyring_items(
        vec![locked("login", hashed(gh)), locked("login", hashed(PORT))],
        false,
    );
    let export = map_keyring_items(
        vec![
            item("login", "gh", 3, attributes(gh), Some(b"token")),
            item("login", "port", 4, attributes(PORT), Some(b"p")),
        ],
        true,
    );
    let fingerprints = |import: &KeyringImport| {
        import
            .items
            .iter()
            .map(|item| item.fingerprint.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(fingerprints(&inventory), fingerprints(&export));
    assert!(
        inventory
            .items
            .iter()
            .all(|item| item.locked && item.label.is_none())
    );
}

#[cfg(all(feature = "key-protection", feature = "vault-client"))]
#[test]
fn exported_items_become_valid_archive_entries_with_fingerprint_ids() {
    let mut source = item("login", "port", 4, attributes(PORT), Some(b"p"));
    source
        .attributes
        .insert("gkr:compat:stray".to_owned(), "x".to_owned());
    source.secret = Some((Zeroizing::new(b"p".to_vec()), String::new()));
    let import = map_keyring_items(vec![source], true);
    let fingerprint = import.items[0].fingerprint.clone();
    let partition = crate::vault::wsl_relay::wsl_keyring_namespace("NixOS").unwrap();
    let entries = import.archive_entries(&partition).unwrap();
    let archive = crate::vault::VaultArchive::new(1, entries);
    archive.validate().unwrap();
    let entry = &archive.entries[0];
    let portable =
        super::super::PortableItem::decode(entry.value.expose(), &entry.metadata.address).unwrap();
    assert_eq!(portable.item.id, fingerprint[..32]);
    assert_eq!(portable.item.attributes, attributes(PORT));
    assert_eq!(portable.item.content_type, "text/plain");
    assert_eq!((portable.item.created, portable.item.modified), (4, 4));
    assert_eq!(portable.item.label, "port");
    assert_eq!(portable.value.expose(), b"p");
    // The vault computes the same fingerprint from the stored attributes.
    assert_eq!(
        hex::encode(keyring_fingerprint(&portable.item.attributes).unwrap()),
        fingerprint
    );
}

#[cfg(all(feature = "key-protection", feature = "vault-client"))]
#[test]
fn an_item_at_the_size_limit_fits_in_one_restore_request() {
    let value = vec![0xff_u8; MAX_IMPORTED_VALUE_BYTES];
    let import = map_keyring_items(
        vec![item("login", "big", 1, attributes(PORT), Some(&value))],
        true,
    );
    let entry = import
        .archive_entries(crate::vault::secret_service_data::NAMESPACE)
        .unwrap()
        .pop()
        .unwrap();
    crate::vault::VaultRequest::new(crate::vault::VaultAction::ImportVaultEntry {
        entry: entry.metadata,
        value: entry.value,
        evict_at: None,
        replace_existing: false,
    })
    .unwrap()
    .encode()
    .unwrap();
}

#[test]
fn a_locked_generic_item_shows_its_schema_plainly() {
    // gnome-keyring 50.0, seen in scripts/test-keyring-import.sh: an item
    // stored with the generic schema (as secret-tool does) has no hashed
    // xdg:schema when locked; the plain one is its real schema.
    let plain = &[
        ("service", "gh:github.com"),
        ("username", "octo"),
        ("xdg:schema", "org.freedesktop.Secret.Generic"),
    ];
    let locked = HashMap::from([
        (
            "gkr:compat:hashed:service".to_owned(),
            "e84fbf1a5a27f8b9b1f84fcc621b14b1".to_owned(),
        ),
        (
            "gkr:compat:hashed:username".to_owned(),
            "39eafcc8caa450a7bd41a961c137bc2c".to_owned(),
        ),
        (
            "xdg:schema".to_owned(),
            "org.freedesktop.Secret.Generic".to_owned(),
        ),
    ]);
    assert_eq!(
        keyring_fingerprint(&locked),
        keyring_fingerprint(&attributes(plain))
    );
}
