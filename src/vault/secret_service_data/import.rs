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
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::IndexItem;

const TAG: &[u8] = b"factorseal-keyring-fingerprint-v1\0";
const HASHED_PREFIX: &str = "gkr:compat:hashed:";
const RESERVED_PREFIX: &str = "gkr:compat:";

/// The largest value an import carries. Its restore request holds the value
/// base64-encoded twice (in the portable item, then on the wire), and must
/// fit in one protocol message.
pub const MAX_IMPORTED_VALUE_BYTES: usize = 256 * 1024;

/// The pairs a fingerprint covers, or `None` when a hashed value is not an
/// MD5. A locked gnome-keyring item lists its attributes hashed under
/// `gkr:compat:hashed:<name>`, beside a placeholder `xdg:schema`; then only
/// the hashed ones count. Otherwise every attribute counts except the names
/// gnome-keyring reserves (`gkr:compat:*`).
fn pairs<S: BuildHasher>(
    attributes: &HashMap<String, String, S>,
) -> Option<BTreeMap<&str, [u8; 16]>> {
    let hashed = attributes
        .keys()
        .any(|name| name.starts_with(HASHED_PREFIX));
    let mut pairs = BTreeMap::new();
    for (name, value) in attributes {
        if hashed {
            if let Some(name) = name.strip_prefix(HASHED_PREFIX) {
                let mut digest = [0_u8; 16];
                hex::decode_to_slice(value, &mut digest).ok()?;
                pairs.insert(name, digest);
            }
        } else if !name.starts_with(RESERVED_PREFIX) {
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
    pairs(attributes)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
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
    // Attribute rules first; then, per fingerprint, the most recently
    // modified item (the first seen on a tie); then the value rules, so the
    // inventory and the export count the same items up to those.
    let mut kept: Vec<([u8; 32], KeyringSourceItem)> = Vec::new();
    for item in items {
        let Some(pairs) = pairs(&item.attributes) else {
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
        match kept.iter().position(|(other, _)| *other == fingerprint) {
            Some(position)
                if item.modified.unwrap_or(0) > kept[position].1.modified.unwrap_or(0) =>
            {
                let (_, older) = std::mem::replace(&mut kept[position], (fingerprint, item));
                skip(&mut import, &older, KeyringSkipReason::Duplicate);
            }
            Some(_) => skip(&mut import, &item, KeyringSkipReason::Duplicate),
            None => kept.push((fingerprint, item)),
        }
    }
    for (fingerprint, mut item) in kept {
        if with_values {
            // A value with hashed attributes would be stored under the
            // placeholder ones, answering no program's lookup.
            let hashed = item
                .attributes
                .keys()
                .any(|name| name.starts_with(HASHED_PREFIX));
            let Some((value, content_type)) = item.secret.take().filter(|_| !hashed) else {
                skip(&mut import, &item, KeyringSkipReason::Unreadable);
                continue;
            };
            if value.len() > MAX_IMPORTED_VALUE_BYTES {
                skip(&mut import, &item, KeyringSkipReason::TooLarge);
                continue;
            }
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
