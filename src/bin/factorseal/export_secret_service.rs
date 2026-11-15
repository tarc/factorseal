//! `factorseal export-secret-service`: read gnome-keyring (or whatever other
//! Secret Service owns `org.freedesktop.secrets`) and write its items as a
//! FactorSeal archive of keyring items, restored like a backup.
//!
//! `--inventory` reads no secrets and never unlocks. `--framed` wraps the
//! output for FactorSeal Desktop, which runs this through `wsl.exe` and
//! takes only what is between the frame lines, whatever a login shell or
//! `wsl.exe` prints around them:
//!
//! ```text
//! FACTORSEAL-FRAME v1 <kind> <length>
//! <length> characters of base64 of a JSON record>
//! FACTORSEAL-FRAME end
//! ```
//!
//! The record has `target`, `items`, `skipped` and `skipped_collections`,
//! and also `locked_collections` and `collections` in an inventory, and
//! `archive` in an export.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use factorseal::vault::{
    KeyringImportItem, KeyringSkippedItem, SecretServiceRead, VaultArchive, encrypt_vault_archive,
    map_keyring_items,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::CliError;

pub(super) const FRAME_START: &str = "FACTORSEAL-FRAME v1";
pub(super) const FRAME_END: &str = "FACTORSEAL-FRAME end";

/// Which FactorSeal keyring the items are for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Wsl(String),
    Native,
}

impl Target {
    /// `--wsl-distro`, `--native`, or else this WSL distro.
    pub(super) fn choose(
        wsl_distro: Option<String>,
        native: bool,
        this_distro: Option<String>,
    ) -> Result<Self, CliError> {
        match (wsl_distro, native, this_distro) {
            (Some(distro), _, _) => Ok(Self::Wsl(distro)),
            (None, true, _) => Ok(Self::Native),
            (None, false, Some(distro)) if !distro.is_empty() => Ok(Self::Wsl(distro)),
            _ => Err(CliError::SecretServiceExport(
                "not in WSL ($WSL_DISTRO_NAME is not set): pass --native or --wsl-distro NAME"
                    .to_owned(),
            )),
        }
    }

    fn partition(&self) -> Result<Vec<u8>, CliError> {
        match self {
            Self::Wsl(distro) => Ok(factorseal::vault::wsl_relay::wsl_keyring_namespace(distro)?),
            Self::Native => Ok(factorseal::vault::SECRET_SERVICE_NAMESPACE.to_vec()),
        }
    }

    fn name(&self) -> String {
        match self {
            Self::Wsl(distro) => format!("wsl:{distro}"),
            Self::Native => "native".to_owned(),
        }
    }
}

/// Where the output goes.
pub(super) enum Output {
    /// The inventory as JSON, framed or not.
    Inventory { framed: bool },
    /// The archive in a file, with a passphrase from a file or the terminal.
    File {
        file: PathBuf,
        passphrase_file: Option<PathBuf>,
    },
    /// The archive in a frame, encrypted with the first line of stdin.
    Framed,
}

#[derive(Serialize)]
struct SkippedCollection<'a> {
    collection: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct Record<'a> {
    target: String,
    items: &'a [KeyringImportItem],
    skipped: &'a [KeyringSkippedItem],
    skipped_collections: Vec<SkippedCollection<'a>>,
    /// In an inventory, the locked collections: a move prompts once for
    /// each, which Desktop's time limit on it counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    locked_collections: Option<&'a [String]>,
    /// In an inventory, every collection: any may be locked by the move.
    #[serde(skip_serializing_if = "Option::is_none")]
    collections: Option<&'a [String]>,
    /// The encrypted archive, base64, in an export.
    #[serde(skip_serializing_if = "Option::is_none")]
    archive: Option<String>,
}

fn record<'a>(
    target: &Target,
    items: &'a [KeyringImportItem],
    skipped: &'a [KeyringSkippedItem],
    skipped_collections: &'a [(String, String)],
    collections: Option<(&'a [String], &'a [String])>,
    archive: Option<String>,
) -> Record<'a> {
    Record {
        target: target.name(),
        items,
        skipped,
        skipped_collections: skipped_collections
            .iter()
            .map(|(collection, reason)| SkippedCollection { collection, reason })
            .collect(),
        locked_collections: collections.map(|(locked, _)| locked),
        collections: collections.map(|(_, all)| all),
        archive,
    }
}

pub(super) fn write_frame(
    stdout: &mut dyn Write,
    kind: &str,
    content: &[u8],
) -> std::io::Result<()> {
    write_frame_within(
        stdout,
        kind,
        content,
        factorseal::vault::MAX_KEYRING_FRAME_BYTES,
    )
}

/// [`write_frame`], refusing a body longer than `limit`: Desktop reads no
/// more, and would cut the frame after the password prompts.
fn write_frame_within(
    stdout: &mut dyn Write,
    kind: &str,
    content: &[u8],
    limit: usize,
) -> std::io::Result<()> {
    let encoded = Zeroizing::new(STANDARD.encode(content));
    if encoded.len() > limit {
        return Err(std::io::Error::other(format!(
            "the {kind} is {} MiB, more than FactorSeal Desktop reads ({} MiB); \
             export to a file instead",
            encoded.len().div_ceil(1024 * 1024),
            limit / (1024 * 1024)
        )));
    }
    write!(
        stdout,
        "{FRAME_START} {kind} {}\n{}\n{FRAME_END}\n",
        encoded.len(),
        encoded.as_str()
    )?;
    stdout.flush()
}

fn summary(
    stderr: &mut dyn Write,
    items: &[KeyringImportItem],
    skipped: &[KeyringSkippedItem],
    skipped_collections: &[(String, String)],
) {
    let _ = writeln!(
        stderr,
        "Secret Service: {} item(s) to import, {} skipped",
        items.len(),
        skipped.len()
    );
    for skipped in skipped {
        let _ = writeln!(
            stderr,
            "  skipped {} in {}: {}",
            skipped.label.as_deref().unwrap_or("(locked item)"),
            skipped.collection,
            skipped.reason
        );
    }
    for (collection, reason) in skipped_collections {
        let _ = writeln!(stderr, "  skipped collection {collection}: {reason}");
    }
}

/// The first line of `stdin`, without its line ending.
fn passphrase_line(stdin: &mut dyn BufRead) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut line = Zeroizing::new(Vec::new());
    stdin
        .read_until(b'\n', &mut line)
        .map_err(|error| CliError::ArchivePassphrase(error.to_string()))?;
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    if line.is_empty() {
        return Err(CliError::ArchivePassphrase(
            "no archive passphrase on standard input".to_owned(),
        ));
    }
    Ok(line)
}

fn transfer_error(error: impl std::fmt::Display) -> CliError {
    CliError::Transfer(error.to_string())
}

/// Run the command with `read` as the Secret Service reader (its argument
/// says whether to read values).
pub(super) fn run(
    target: &Target,
    output: &Output,
    read: impl FnOnce(bool) -> Result<SecretServiceRead, String>,
    stdin: &mut dyn BufRead,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), CliError> {
    let partition = target.partition()?;
    if let Output::Inventory { framed } = output {
        let read = read(false).map_err(CliError::SecretServiceExport)?;
        let import = map_keyring_items(read.items, false);
        summary(
            stderr,
            &import.items,
            &import.skipped,
            &read.skipped_collections,
        );
        let json = serde_json::to_vec_pretty(&record(
            target,
            &import.items,
            &import.skipped,
            &read.skipped_collections,
            Some((&read.locked_collections, &read.collections)),
            None,
        ))
        .map_err(transfer_error)?;
        if *framed {
            write_frame(stdout, "inventory", &json)
        } else {
            stdout.write_all(&json).and_then(|()| writeln!(stdout))
        }
        .map_err(transfer_error)?;
        return Ok(());
    }
    // Ask for the passphrase before any gnome-keyring prompt.
    let passphrase = match output {
        Output::Framed => passphrase_line(stdin)?,
        Output::File {
            passphrase_file, ..
        } => Zeroizing::new(
            super::factor::read_archive_passphrase(passphrase_file.as_deref(), true)?
                .as_slice()
                .to_vec(),
        ),
        Output::Inventory { .. } => unreachable!("handled above"),
    };
    factorseal::security::validate_new_password(&passphrase)
        .map_err(CliError::ArchivePassphrase)?;
    let read = read(true).map_err(CliError::SecretServiceExport)?;
    let skipped_collections = read.skipped_collections;
    let mut import = map_keyring_items(read.items, true);
    let items = std::mem::take(&mut import.items);
    let skipped = std::mem::take(&mut import.skipped);
    summary(stderr, &items, &skipped, &skipped_collections);
    let entries = import.archive_entries(&partition)?;
    let archive = encrypt_vault_archive(
        &VaultArchive::new(super::commands::unix_time()?, entries),
        &passphrase,
    )?;
    match output {
        Output::Framed => {
            let json = Zeroizing::new(
                serde_json::to_vec(&record(
                    target,
                    &items,
                    &skipped,
                    &skipped_collections,
                    None,
                    Some(STANDARD.encode(&*archive)),
                ))
                .map_err(transfer_error)?,
            );
            write_frame(stdout, "export", &json).map_err(transfer_error)?;
        }
        Output::File { file, .. } => {
            write(file, &archive)?;
            let _ = writeln!(
                stderr,
                "Wrote {}. Restore it in FactorSeal (on Windows: factorseal.exe import {} \
                 --dry-run, then Desktop's restore), then delete it.",
                file.display(),
                file.display()
            );
        }
        Output::Inventory { .. } => unreachable!("handled above"),
    }
    Ok(())
}

fn write(file: &Path, archive: &[u8]) -> Result<(), CliError> {
    factorseal::transfer::write_private_file(file, archive).map_err(transfer_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser as _;
    use factorseal::vault::{KeyringSourceItem, decrypt_vault_archive};
    use std::collections::HashMap;

    const PASSPHRASE: &str = "opal nebula lantern saffron velocity";

    fn source(label: &str, attributes: &[(&str, &str)], value: Option<&[u8]>) -> KeyringSourceItem {
        KeyringSourceItem {
            collection: "login".to_owned(),
            locked: value.is_none(),
            label: value.map(|_| label.to_owned()),
            modified: value.map(|_| 7),
            attributes: attributes
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            secret: value.map(|value| (Zeroizing::new(value.to_vec()), "text/plain".to_owned())),
        }
    }

    /// gnome-keyring as the export sees it after the unlock: a `gh` token,
    /// a bare item, and the `other` collection's prompt dismissed.
    #[allow(clippy::unnecessary_wraps)] // The reader's signature.
    fn unlocked(values: bool) -> Result<SecretServiceRead, String> {
        assert!(values, "an export reads values");
        Ok(SecretServiceRead {
            items: vec![
                source("gh", &[("service", "gh:github.com")], Some(b"gho_secret")),
                source("bare", &[], Some(b"bare_secret")),
            ],
            skipped_collections: vec![("other".to_owned(), "unlock dismissed".to_owned())],
            locked_collections: Vec::new(),
            collections: Vec::new(),
        })
    }

    #[allow(clippy::unnecessary_wraps)] // The reader's signature.
    fn locked(values: bool) -> Result<SecretServiceRead, String> {
        assert!(!values, "an inventory never reads values");
        let mut hashed: HashMap<String, String> = HashMap::from([(
            "xdg:schema".to_owned(),
            "org.freedesktop.Secret.Generic".to_owned(),
        )]);
        // md5("gh:github.com")
        hashed.insert(
            "gkr:compat:hashed:service".to_owned(),
            "e84fbf1a5a27f8b9b1f84fcc621b14b1".to_owned(),
        );
        let mut item = source("gh", &[], None);
        item.attributes = hashed;
        Ok(SecretServiceRead {
            items: vec![item],
            skipped_collections: Vec::new(),
            locked_collections: vec!["login".to_owned()],
            collections: vec!["login".to_owned(), "other".to_owned()],
        })
    }

    /// The record between the frame lines, ignoring anything around them,
    /// as Desktop reads it.
    fn unframe(output: &[u8]) -> (String, serde_json::Value) {
        let text = String::from_utf8_lossy(output);
        let mut lines = text.lines();
        let header = lines
            .by_ref()
            .find(|line| line.starts_with(FRAME_START))
            .expect("a frame");
        let mut fields = header[FRAME_START.len()..].split_whitespace();
        let kind = fields.next().unwrap().to_owned();
        let length: usize = fields.next().unwrap().parse().unwrap();
        let body = lines.next().unwrap();
        assert_eq!(body.len(), length);
        assert_eq!(lines.next(), Some(FRAME_END));
        (
            kind,
            serde_json::from_slice(&STANDARD.decode(body).unwrap()).unwrap(),
        )
    }

    fn run_with(
        target: &Target,
        output: &Output,
        read: impl FnOnce(bool) -> Result<SecretServiceRead, String>,
        stdin: &[u8],
    ) -> Result<(Vec<u8>, String), CliError> {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        run(
            target,
            output,
            read,
            &mut &stdin[..],
            &mut stdout,
            &mut stderr,
        )?;
        Ok((stdout, String::from_utf8(stderr).unwrap()))
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn the_command_line_takes_one_output_and_one_target() {
        for args in [
            &["--inventory"][..],
            &["--inventory", "--framed", "--native"],
            &["--framed", "--passphrase-stdin", "--wsl-distro", "NixOS"],
            &["/tmp/keyring.fsarchive", "--passphrase-file", "/tmp/p"],
        ] {
            let cli =
                Cli::try_parse_from(["factorseal", "export-secret-service"].iter().chain(args))
                    .unwrap_or_else(|error| panic!("{args:?}: {error}"));
            assert!(matches!(cli.command, Command::ExportSecretService { .. }));
        }
        for args in [
            &[][..],
            &["/tmp/k", "--inventory"],
            &["/tmp/k", "--framed"],
            &["--passphrase-stdin"],
            &["--inventory", "--framed", "--passphrase-stdin"],
            &["--inventory", "--native", "--wsl-distro", "NixOS"],
            &["--inventory", "--passphrase-file", "/tmp/p"],
        ] {
            assert!(
                Cli::try_parse_from(["factorseal", "export-secret-service"].iter().chain(args))
                    .is_err(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn the_target_defaults_to_this_wsl_distro() {
        let this = || Some("Ubuntu".to_owned());
        assert_eq!(
            Target::choose(None, false, this()).unwrap(),
            Target::Wsl("Ubuntu".to_owned())
        );
        assert_eq!(
            Target::choose(Some("NixOS".to_owned()), false, this()).unwrap(),
            Target::Wsl("NixOS".to_owned())
        );
        assert_eq!(Target::choose(None, true, this()).unwrap(), Target::Native);
        assert!(Target::choose(None, false, None).is_err());
        assert!(Target::choose(None, false, Some(String::new())).is_err());
    }

    #[test]
    fn a_framed_inventory_carries_fingerprints_and_no_secrets() {
        let (stdout, stderr) = run_with(
            &Target::Wsl("NixOS".to_owned()),
            &Output::Inventory { framed: true },
            locked,
            b"",
        )
        .unwrap();
        let (kind, record) = unframe(&stdout);
        assert_eq!(kind, "inventory");
        assert_eq!(record["target"], "wsl:NixOS");
        assert_eq!(record["items"].as_array().unwrap().len(), 1);
        assert_eq!(record["items"][0]["locked"], true);
        assert_eq!(
            record["items"][0]["fingerprint"].as_str().unwrap().len(),
            64
        );
        assert!(record.get("archive").is_none());
        assert_eq!(record["locked_collections"], serde_json::json!(["login"]));
        assert_eq!(record["collections"], serde_json::json!(["login", "other"]));
        assert!(stderr.contains("1 item(s) to import"), "{stderr}");
    }

    #[test]
    fn a_plain_inventory_is_json_on_stdout() {
        let (stdout, _) = run_with(
            &Target::Native,
            &Output::Inventory { framed: false },
            locked,
            b"",
        )
        .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(record["target"], "native");
    }

    #[test]
    fn a_frame_larger_than_desktop_reads_is_refused() {
        // 3 MiB and 3 bytes encode to just over 4 MiB.
        let content = vec![7_u8; 3 * 1024 * 1024 + 3];
        let mut stdout = Vec::new();
        let error =
            write_frame_within(&mut stdout, "export", &content, 4 * 1024 * 1024).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("more than FactorSeal Desktop reads (4 MiB)"),
            "{error}"
        );
        assert!(stdout.is_empty(), "no partial frame");
        write_frame_within(&mut stdout, "export", &content, 5 * 1024 * 1024).unwrap();
        assert!(stdout.starts_with(FRAME_START.as_bytes()));
    }

    #[test]
    fn a_framed_export_carries_the_archive_and_the_skip_reasons() {
        let (stdout, stderr) = run_with(
            &Target::Wsl("NixOS".to_owned()),
            &Output::Framed,
            unlocked,
            format!("{PASSPHRASE}\r\nignored\n").as_bytes(),
        )
        .unwrap();
        assert!(!contains(&stdout, b"gho_secret"));
        assert!(!stderr.contains("gho_secret"));
        let (kind, record) = unframe(&stdout);
        assert_eq!(kind, "export");
        assert!(record.get("locked_collections").is_none());
        assert!(record.get("collections").is_none());
        assert_eq!(record["items"][0]["label"], "gh");
        assert_eq!(record["skipped"][0]["label"], "bare");
        assert_eq!(record["skipped"][0]["reason"], "no_attributes");
        assert_eq!(record["skipped_collections"][0]["collection"], "other");
        assert_eq!(
            record["skipped_collections"][0]["reason"],
            "unlock dismissed"
        );
        let archive = STANDARD
            .decode(record["archive"].as_str().unwrap())
            .unwrap();
        let archive = decrypt_vault_archive(&archive, PASSPHRASE.as_bytes()).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert_eq!(
            archive.entries[0].metadata.partition,
            factorseal::vault::wsl_relay::wsl_keyring_namespace("NixOS").unwrap()
        );
        assert!(
            contains(archive.entries[0].value.expose(), b"gho_secret") || {
                // The portable item holds the value base64-encoded.
                contains(
                    archive.entries[0].value.expose(),
                    STANDARD.encode(b"gho_secret").as_bytes(),
                )
            }
        );
    }

    #[test]
    fn a_file_export_is_private_and_restorable() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let passphrase_file = directory.path().join("passphrase");
        factorseal::security::write_private_file(&passphrase_file, PASSPHRASE.as_bytes()).unwrap();
        let file = directory.path().join("keyring.fsarchive");
        let (stdout, stderr) = run_with(
            &Target::Native,
            &Output::File {
                file: file.clone(),
                passphrase_file: Some(passphrase_file),
            },
            unlocked,
            b"",
        )
        .unwrap();
        assert_eq!(stdout, Vec::<u8>::new());
        assert!(stderr.contains("then delete it"), "{stderr}");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let archive =
            decrypt_vault_archive(&std::fs::read(&file).unwrap(), PASSPHRASE.as_bytes()).unwrap();
        assert_eq!(
            archive.entries[0].metadata.partition,
            factorseal::vault::SECRET_SERVICE_NAMESPACE
        );
    }

    #[test]
    fn a_weak_or_missing_passphrase_is_refused_before_reading_the_keyring() {
        let never = |_: bool| -> Result<SecretServiceRead, String> {
            panic!("the keyring must not be read")
        };
        for stdin in [&b""[..], b"\n", b"short\n"] {
            assert!(
                run_with(&Target::Native, &Output::Framed, never, stdin).is_err(),
                "{stdin:?}"
            );
        }
    }
}
