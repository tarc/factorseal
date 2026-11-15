//! Map another Secret Service's items (gnome-keyring's) to FactorSeal
//! keyring items, and fingerprint keyring items so both sides can tell which
//! ones FactorSeal already has.
//!
//! The fingerprint is SHA-256 over a tag and the item's attributes as sorted
//! pairs (name, MD5 of the value), length-prefixed:
//! `factorseal-keyring-fingerprint-v1 \0` then, per pair, the name's length
//! (4 bytes, big-endian), the name, and the 16 MD5 bytes. MD5 is there only
//! because a locked gnome-keyring item shows nothing else of its values
//! (`gkr:compat:hashed:<name>`), not for security.
//!
//! One mapping serves the inventory (no values) and the export (values), so
//! both apply the same rules and count the same items.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use md5::{Digest as _, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::IndexItem;

const TAG: &[u8] = b"factorseal-keyring-fingerprint-v1\0";
const HASHED_PREFIX: &str = "gkr:compat:hashed:";
const RESERVED_PREFIX: &str = "gkr:compat:";
const SCHEMA: &str = "xdg:schema";
const HASHED_SCHEMA: &str = "gkr:compat:hashed:xdg:schema";

/// The largest value an import carries. Its restore request holds the value
/// base64-encoded twice (in the portable item, then on the wire), and must
/// fit in one protocol message.
pub const MAX_IMPORTED_VALUE_BYTES: usize = 256 * 1024;

/// The largest frame body `export-secret-service --framed` writes, and so
/// what Desktop reads of its output: an archive at its 256 MiB limit,
/// base64 twice over (≈455 MiB), leaves room for some 350,000 listed
/// items. The CLI refuses a larger export rather than have Desktop cut it.
pub const MAX_KEYRING_FRAME_BYTES: usize = 512 * 1024 * 1024;

/// The pairs a fingerprint covers, or `None` when a hashed value is not an
/// MD5. A locked gnome-keyring item lists its attributes hashed under
/// `gkr:compat:hashed:<name>`, beside a plain `xdg:schema`; then the hashed
/// ones count, and the plain `xdg:schema` only when it has no hashed one
/// (gnome-keyring leaves the generic schema unhashed, and shows the generic
/// schema as a placeholder for every other). Otherwise every attribute
/// counts except the names gnome-keyring reserves (`gkr:compat:*`).
///
/// `source` says the attributes come from another Secret Service; the
/// vault's own items always take the plain rule over every attribute,
/// `gkr:compat:*` included: FactorSeal does not reserve the prefix, a
/// program may store such a name, and a restore compares the whole
/// attributes, so Check must count such an item apart as Move does.
fn pairs<S: BuildHasher>(
    attributes: &HashMap<String, String, S>,
    source: bool,
) -> Option<BTreeMap<&str, [u8; 16]>> {
    let hashed = source
        && attributes
            .keys()
            .any(|name| name.starts_with(HASHED_PREFIX));
    // A locked item's plain xdg:schema is its real schema only when
    // gnome-keyring did not hash it (the generic schema); otherwise it is
    // a placeholder.
    let hashed_schema = attributes.contains_key(HASHED_SCHEMA);
    let mut pairs = BTreeMap::new();
    for (name, value) in attributes {
        if hashed {
            if let Some(name) = name.strip_prefix(HASHED_PREFIX) {
                let mut digest = [0_u8; 16];
                hex::decode_to_slice(value, &mut digest).ok()?;
                pairs.insert(name, digest);
            } else if name == SCHEMA && !hashed_schema {
                pairs.insert(name.as_str(), Md5::digest(value.as_bytes()).into());
            }
        } else if !(source && name.starts_with(RESERVED_PREFIX)) {
            pairs.insert(name.as_str(), Md5::digest(value.as_bytes()).into());
        }
    }
    Some(pairs)
}

fn digest(pairs: &BTreeMap<&str, [u8; 16]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    sha2::Digest::update(&mut hasher, TAG);
    for (name, value) in pairs {
        let length = u32::try_from(name.len()).expect("attribute names fit in memory");
        sha2::Digest::update(&mut hasher, length.to_be_bytes());
        sha2::Digest::update(&mut hasher, name.as_bytes());
        sha2::Digest::update(&mut hasher, value);
    }
    sha2::Digest::finalize(hasher).into()
}

/// The fingerprint of an item with these attributes, plain or as a locked
/// gnome-keyring item shows them. `None` for an item without attributes
/// (every such item would share one fingerprint) or with a malformed hash.
#[must_use]
pub fn keyring_fingerprint<S: BuildHasher>(
    attributes: &HashMap<String, String, S>,
) -> Option<[u8; 32]> {
    pairs(attributes, true)
        .filter(|pairs| !pairs.is_empty())
        .map(|pairs| digest(&pairs))
}

/// The fingerprint of a FactorSeal keyring item: always the plain rule,
/// over every attribute. `None` without attributes.
#[must_use]
pub fn vault_keyring_fingerprint<S: BuildHasher>(
    attributes: &HashMap<String, String, S>,
) -> Option<[u8; 32]> {
    pairs(attributes, false)
        .filter(|pairs| !pairs.is_empty())
        .map(|pairs| digest(&pairs))
}

/// An item as another Secret Service reported it.
pub struct KeyringSourceItem {
    /// The collection's name, such as `login`.
    pub collection: String,
    pub locked: bool,
    /// Unknown on a locked item never unlocked since the daemon started.
    pub label: Option<String>,
    pub modified: Option<u64>,
    pub attributes: HashMap<String, String>,
    /// The value and its content type, when the read included secrets.
    pub secret: Option<(Zeroizing<Vec<u8>>, String)>,
}

/// Why an item is not imported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringSkipReason {
    /// No program can look it up by attributes.
    NoAttributes,
    /// Another item has the same attributes and a later modified time.
    Duplicate,
    /// A Wi-Fi password: moved by "Move existing Wi-Fi passwords" instead.
    NetworkManager,
    /// Its value exceeds [`MAX_IMPORTED_VALUE_BYTES`].
    TooLarge,
    /// The service gave no value for it, or a malformed hashed attribute.
    Unreadable,
}

impl std::fmt::Display for KeyringSkipReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NoAttributes => "no attributes",
            Self::Duplicate => "duplicate",
            Self::NetworkManager => "Wi-Fi password; use \"Move existing Wi-Fi passwords\"",
            Self::TooLarge => "too large",
            Self::Unreadable => "unreadable",
        })
    }
}

/// An item the import brings, without its value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyringImportItem {
    /// 64 lowercase hex digits.
    pub fingerprint: String,
    pub collection: String,
    pub locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<u64>,
}

/// An item the import leaves out, and why.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyringSkippedItem {
    pub collection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub reason: KeyringSkipReason,
}

/// What an import brings and what it leaves out.
#[derive(Default)]
pub struct KeyringImport {
    pub items: Vec<KeyringImportItem>,
    pub skipped: Vec<KeyringSkippedItem>,
    /// With values: each of `items` as a FactorSeal keyring item.
    portable: Vec<(IndexItem, Zeroizing<Vec<u8>>)>,
}

impl KeyringImport {
    /// The import's items as archive entries for the keyring in
    /// `partition`, which a restore takes like a backup's.
    #[cfg(all(feature = "key-protection", feature = "vault-client"))]
    pub fn archive_entries(
        self,
        partition: &[u8],
    ) -> crate::vault::VaultResult<Vec<crate::vault::VaultArchiveEntry>> {
        use crate::vault::{DocumentKind, VaultEntryMetadata, WireSecret};
        self.portable
            .into_iter()
            .map(|(item, value)| {
                let address = item.address()?;
                let value = super::PortableItem::new(item, WireSecret::new(value.to_vec())?);
                Ok(crate::vault::VaultArchiveEntry {
                    metadata: VaultEntryMetadata {
                        access_project: None,
                        display_name: None,
                        display_type: None,
                        display_username: None,
                        display_website: None,
                        updated_at: None,
                        favorite: false,
                        document_kind: DocumentKind::LinuxSecretService,
                        partition: partition.to_vec(),
                        address,
                    },
                    value: value.encode()?,
                    evict_at: None,
                })
            })
            .collect()
    }
}

fn is_network_manager(pairs: &BTreeMap<&str, [u8; 16]>) -> bool {
    pairs.contains_key("connection-uuid") && pairs.contains_key("setting-name")
}

/// Why an item's value can't be imported, if it can't. A value beside
/// hashed attributes would be stored under the placeholder ones, answering
/// no program's lookup.
fn value_rules(item: &KeyringSourceItem) -> Result<(), KeyringSkipReason> {
    let hashed = item
        .attributes
        .keys()
        .any(|name| name.starts_with(HASHED_PREFIX));
    match &item.secret {
        None => Err(KeyringSkipReason::Unreadable),
        Some(_) if hashed => Err(KeyringSkipReason::Unreadable),
        Some((value, _)) if value.len() > MAX_IMPORTED_VALUE_BYTES => {
            Err(KeyringSkipReason::TooLarge)
        }
        Some(_) => Ok(()),
    }
}

/// Map `items` to what an import brings and leaves out. With `with_values`
/// (an export), items also need a readable value no larger than
/// [`MAX_IMPORTED_VALUE_BYTES`]; without (an inventory), values are not
/// looked at.
#[must_use]
pub fn map_keyring_items(items: Vec<KeyringSourceItem>, with_values: bool) -> KeyringImport {
    let mut import = KeyringImport::default();
    let skip = |import: &mut KeyringImport, item: &KeyringSourceItem, reason| {
        import.skipped.push(KeyringSkippedItem {
            collection: item.collection.clone(),
            label: item.label.clone(),
            reason,
        });
    };
    // Attribute rules first; then one item per fingerprint: the most
    // recently modified (the first seen on a tie), or in an export the most
    // recent one that passes the value rules. The inventory and the export
    // thus count the same items, up to fingerprints none of whose items
    // has a usable value.
    let mut groups: Vec<([u8; 32], Vec<KeyringSourceItem>)> = Vec::new();
    for item in items {
        let Some(pairs) = pairs(&item.attributes, true) else {
            skip(&mut import, &item, KeyringSkipReason::Unreadable);
            continue;
        };
        if pairs.is_empty() {
            skip(&mut import, &item, KeyringSkipReason::NoAttributes);
            continue;
        }
        if is_network_manager(&pairs) {
            skip(&mut import, &item, KeyringSkipReason::NetworkManager);
            continue;
        }
        let fingerprint = digest(&pairs);
        drop(pairs);
        match groups.iter_mut().find(|(other, _)| *other == fingerprint) {
            Some((_, group)) => group.push(item),
            None => groups.push((fingerprint, vec![item])),
        }
    }
    for (fingerprint, mut group) in groups {
        // Stable: equal times keep their order.
        group.sort_by_key(|item| std::cmp::Reverse(item.modified.unwrap_or(0)));
        let chosen = if with_values {
            let checked: Vec<_> = group.iter().map(value_rules).collect();
            checked.iter().position(Result::is_ok)
        } else {
            Some(0)
        };
        let Some(chosen) = chosen else {
            for item in group {
                let reason = value_rules(&item)
                    .err()
                    .unwrap_or(KeyringSkipReason::Unreadable);
                skip(&mut import, &item, reason);
            }
            continue;
        };
        let mut item = group.remove(chosen);
        // Newest first: those before the chosen one are newer but failed
        // the value rules, and say why; those after are older duplicates.
        for (position, other) in group.iter().enumerate() {
            let reason = if position < chosen {
                value_rules(other)
                    .err()
                    .unwrap_or(KeyringSkipReason::Duplicate)
            } else {
                KeyringSkipReason::Duplicate
            };
            skip(&mut import, other, reason);
        }
        if with_values {
            // Checked by the value rules.
            let Some((value, content_type)) = item.secret.take() else {
                skip(&mut import, &item, KeyringSkipReason::Unreadable);
                continue;
            };
            let modified = item.modified.unwrap_or(0);
            import.portable.push((
                IndexItem {
                    id: hex::encode(&fingerprint[..16]),
                    label: item.label.clone().unwrap_or_default(),
                    attributes: item
                        .attributes
                        .iter()
                        .filter(|(name, _)| !name.starts_with(RESERVED_PREFIX))
                        .map(|(name, value)| (name.clone(), value.clone()))
                        .collect(),
                    content_type: if content_type.is_empty() {
                        "text/plain".to_owned()
                    } else {
                        content_type
                    },
                    created: modified,
                    modified,
                },
                value,
            ));
        }
        import.items.push(KeyringImportItem {
            fingerprint: hex::encode(fingerprint),
            collection: item.collection,
            locked: item.locked,
            label: item.label,
            modified: item.modified,
        });
    }
    import
}

#[cfg(test)]
mod tests;
