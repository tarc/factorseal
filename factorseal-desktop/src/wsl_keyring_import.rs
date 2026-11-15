//! Settings, WSL keyrings: check how many of a distro's gnome-keyring items
//! the vault lacks, and move them (`docs/plans/gnome-keyring-import.md`,
//! step 6).
//!
//! Desktop runs `factorseal export-secret-service` in the distro through
//! `wsl.exe` and reads the one framed record it prints, ignoring whatever a
//! login shell or `wsl.exe` prints around it. Check compares the record's
//! fingerprints with the vault's (`ListKeyringFingerprints`). Move hands the
//! command a one-time passphrase on stdin, decrypts the archive it returns
//! in memory, and restores the whole archive without replacing: items
//! already in the vault stay as they are, which also covers changes between
//! Check and Move.

use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use factorseal::vault::{KeyringImportItem, KeyringSkipReason, KeyringSkippedItem};
use factorseal::{DocumentKind, VaultArchive};
use serde::Deserialize;
use zeroize::Zeroizing;

const FRAME_START: &[u8] = b"FACTORSEAL-FRAME v1 ";
const FRAME_END: &[u8] = b"FACTORSEAL-FRAME end";

/// The most standard output kept: the largest frame, an archive of at most
/// 256 MiB base64 twice over (in the record, then the record in the frame,
/// ≈455 MiB), with room for the record's lists.
#[cfg(windows)]
const MAX_STDOUT_BYTES: u64 = 464 * 1024 * 1024;

/// The most standard error kept, from its end: only its lines for a
/// message are used, and the CLI's error comes last.
#[cfg(any(windows, test))]
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// The last `cap` bytes of `pipe`, read to its end: a login shell's output
/// comes before the CLI's error, which a message needs.
#[cfg_attr(not(windows), allow(dead_code))] // The Windows runner and tests.
fn read_tail(mut pipe: impl std::io::Read, cap: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => kept.extend_from_slice(&chunk[..read]),
        }
        // Trimmed now and then, not on every read, to stay linear.
        if kept.len() > 2 * cap {
            kept.drain(..kept.len() - cap);
        }
    }
    if kept.len() > cap {
        kept.drain(..kept.len() - cap);
    }
    kept
}

/// The first `cap` bytes of `pipe`, reading the rest to its end and
/// dropping it, so a child writing more is not blocked on a full pipe
/// until the time limit kills it.
#[cfg_attr(not(windows), allow(dead_code))] // The Windows runner and tests.
fn read_capped(mut pipe: impl std::io::Read, cap: u64) -> Vec<u8> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    let _ = (&mut pipe).take(cap).read_to_end(&mut bytes);
    let _ = std::io::copy(&mut pipe, &mut std::io::sink());
    bytes
}

/// How long an inventory may take: WSL may have to start the distro, and
/// no prompt is involved.
pub(crate) const INVENTORY_LIMIT: Duration = Duration::from_mins(3);

/// The CLI dismisses an unlock prompt left unanswered for five minutes and
/// waits at most five seconds for the Dismiss (step 2 of the plan).
const PROMPT_LIMIT: Duration = Duration::from_secs(5 * 60 + 5);

/// How long a move may take: an inventory's time for starting WSL,
/// reading values and the archive's key derivation, plus one prompt's
/// limit per collection that may prompt, since the prompts come one after
/// another.
pub(crate) fn move_limit(prompt_collections: usize) -> Duration {
    INVENTORY_LIMIT + PROMPT_LIMIT * u32::try_from(prompt_collections).unwrap_or(u32::MAX / 400)
}

/// The script `sh -lc` runs. The distro is `$1`, never pasted into the
/// script: distro names are letters, digits, `.`, `-` and `_`, so the
/// unquoted expansion stays one word, and no quote reaches `wsl.exe`'s
/// command-line parsing.
const INVENTORY_SCRIPT: &str =
    "exec factorseal export-secret-service --inventory --framed --wsl-distro $1";
const EXPORT_SCRIPT: &str =
    "exec factorseal export-secret-service --framed --passphrase-stdin --wsl-distro $1";

/// The arguments of `wsl.exe`. `--exec` runs `sh` directly; with `--`, WSL
/// would hand the line to the user's login shell, which expands it first.
fn wsl_args(distro: &str, script: &str) -> Vec<String> {
    ["-d", distro, "--exec", "sh", "-lc", script, "sh", distro]
        .map(str::to_owned)
        .to_vec()
}

/// What a finished `wsl.exe` left.
#[derive(Debug, Default)]
pub(crate) struct RunOutput {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
// Made only by the Windows runner and the tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum RunError {
    Start(String),
    TimedOut,
    Cancelled,
}

/// Runs `wsl.exe` with `args`, writing `stdin` to it when given, killing
/// it when `limit` passes or `cancel` is set.
pub(crate) trait Wsl {
    fn run(
        &self,
        args: &[String],
        stdin: Option<&[u8]>,
        limit: Duration,
        cancel: &AtomicBool,
    ) -> Result<RunOutput, RunError>;
}

/// The first well-formed frame in `output`, as `(kind, content)`.
///
/// The frame may follow anything, on the same line too: a login shell's
/// output, nix or direnv warnings, `wsl.exe`'s UTF-16 messages. Its lines
/// may end in `\r\n`. The body must be exactly the announced length.
fn unframe(output: &[u8]) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let mut search = 0;
    while let Some(found) = find(&output[search..], FRAME_START) {
        let start = search + found + FRAME_START.len();
        search = start;
        if let Some(frame) = frame_at(&output[start..]) {
            return Some(frame);
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The line ending at the start of `bytes`, and what follows it.
fn after_line_end(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .strip_prefix(b"\r\n")
        .or_else(|| bytes.strip_prefix(b"\n"))
}

/// The longest `<kind> <length>\r` a header can have. Looking no further
/// for its newline keeps the scan linear however many start markers the
/// output holds.
const MAX_HEADER_BYTES: usize = 64;

/// The frame whose header's `<kind> <length>` starts `bytes`.
fn frame_at(bytes: &[u8]) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let header_end = bytes
        .iter()
        .take(MAX_HEADER_BYTES)
        .position(|byte| *byte == b'\n')?;
    let header = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let header = header.strip_suffix('\r').unwrap_or(header);
    let (kind, length) = header.split_once(' ')?;
    if kind.is_empty()
        || !kind.bytes().all(|byte| byte.is_ascii_lowercase())
        || length.is_empty()
        || !length.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let length: usize = length.parse().ok()?;
    let body_start = header_end + 1;
    let body = bytes.get(body_start..body_start.checked_add(length)?)?;
    let rest = after_line_end(&bytes[body_start + length..])?;
    let rest = rest.strip_prefix(FRAME_END)?;
    if !(rest.is_empty() || after_line_end(rest).is_some()) {
        return None;
    }
    // Checked before decoding, which first allocates and zeroes a buffer
    // the size of the body: that costs time on Windows even for a body that
    // fails at its first bytes, and candidates packed before one end line
    // would add up. The check stops at the first byte that can't be
    // base64, such as the `-` of a later start marker.
    if !body
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    let content = Zeroizing::new(STANDARD.decode(body).ok()?);
    Some((kind.to_owned(), content))
}

/// Console output as text: `wsl.exe` writes its own messages in UTF-16LE,
/// programs in the distro write UTF-8.
fn console_text(bytes: &[u8]) -> String {
    let odd_zeros = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    if bytes.len() >= 2 && odd_zeros * 2 >= bytes.len() / 2 {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .filter(|unit| *unit != 0xfeff)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// The lines of `bytes` that say what went wrong, for an error message:
/// the CLI's own (`factorseal: …`, or `error: …` from its argument
/// parser), else the last few. A login shell's output comes first and the
/// CLI's error last.
fn error_lines(bytes: &[u8]) -> Vec<String> {
    let lines: Vec<String> = console_text(bytes)
        .lines()
        .map(|line| line.trim().trim_matches('\0').to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    let own: Vec<String> = lines
        .iter()
        .filter(|line| line.starts_with("factorseal:") || line.starts_with("error:"))
        .cloned()
        .collect();
    let chosen = if own.is_empty() { lines } else { own };
    chosen[chosen.len().saturating_sub(3)..].to_vec()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct SkippedCollection {
    pub(crate) collection: String,
    pub(crate) reason: String,
}

/// The record `export-secret-service --framed` prints.
#[derive(Deserialize)]
struct Record {
    target: String,
    items: Vec<KeyringImportItem>,
    skipped: Vec<KeyringSkippedItem>,
    skipped_collections: Vec<SkippedCollection>,
    /// Absent from a CLI older than Desktop's check.
    #[serde(default)]
    locked_collections: Option<Vec<String>>,
    /// Every collection the inventory visited; absent from an older CLI.
    #[serde(default)]
    collections: Option<Vec<String>>,
    #[serde(default)]
    archive: Option<String>,
}

/// Why a run in the distro gave no record, worded for the distro's row.
fn failure(distro: &str, output: &RunOutput) -> String {
    let stderr = console_text(&output.stderr);
    if output.code == Some(127) {
        return format!(
            "FactorSeal is not installed in {distro}. Add the factorseal package to it, then check again."
        );
    }
    if stderr.contains("no Secret Service on the session bus") || stderr.contains("no session bus")
    {
        return format!(
            "No Secret Service runs on {distro}'s session bus, and none can be started there, so there is no gnome-keyring to read."
        );
    }
    if stderr.contains("unrecognized subcommand") {
        return format!(
            "The factorseal in {distro} is too old to export its keyring. Update it, then check again."
        );
    }
    let mut lines = error_lines(&output.stderr);
    if lines.is_empty() {
        lines = error_lines(&output.stdout);
    }
    if lines.is_empty() {
        format!("{distro} gave no answer FactorSeal could read.")
    } else {
        format!(
            "{distro} gave no answer FactorSeal could read: {}",
            lines.join(" ")
        )
    }
}

fn run_failure(distro: &str, error: RunError, limit: Duration) -> String {
    match error {
        RunError::Start(error) => format!("Could not start WSL: {error}"),
        RunError::TimedOut => format!(
            "{distro} did not answer within {} minutes.",
            limit.as_secs().div_ceil(60)
        ),
        RunError::Cancelled => "Cancelled.".to_owned(),
    }
}

/// Run `script` in `distro` and read its record of `kind`.
fn record(
    wsl: &dyn Wsl,
    distro: &str,
    script: &str,
    kind: &str,
    stdin: Option<&[u8]>,
    limit: Duration,
    cancel: &AtomicBool,
) -> Result<Record, String> {
    let output = wsl
        .run(&wsl_args(distro, script), stdin, limit, cancel)
        .map_err(|error| run_failure(distro, error, limit))?;
    let Some((found, content)) = unframe(&output.stdout) else {
        return Err(failure(distro, &output));
    };
    // The frame's content is all that is needed from here on.
    drop(output);
    if found != kind {
        return Err(format!(
            "{distro} answered with a {found} instead of an {kind}."
        ));
    }
    let record: Record = serde_json::from_slice(&content)
        .map_err(|error| format!("{distro} answered with an unreadable {kind}: {error}"))?;
    let expected = format!("wsl:{distro}");
    if record.target != expected {
        return Err(format!(
            "{distro} answered for the keyring {}, not its own.",
            record.target
        ));
    }
    Ok(record)
}

/// What Check found: the items a move would bring, which of them the
/// vault lacks, and what a move leaves out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Check {
    pub(crate) items: Vec<KeyringImportItem>,
    /// Items whose fingerprint is not in the vault, in the record's order.
    pub(crate) missing: Vec<KeyringImportItem>,
    pub(crate) skipped: Vec<KeyringSkippedItem>,
    pub(crate) skipped_collections: Vec<SkippedCollection>,
    /// How many collections are locked now.
    pub(crate) locked_collections: usize,
    /// How many password prompts a move may bring: every collection, since
    /// any may be locked by then, and at least one.
    pub(crate) prompt_collections: usize,
}

/// Compare an inventory with the vault's fingerprints. Only fingerprints
/// count: the collection and label of a duplicate may differ between
/// Check and Move.
fn compare(record: Record, vault: &HashSet<String>) -> Check {
    let locked = record.locked_collections.clone().unwrap_or_else(|| {
        // An older CLI: the collections of its locked items.
        record
            .items
            .iter()
            .filter(|item| item.locked)
            .map(|item| item.collection.clone())
            .collect()
    });
    let locked_collections = locked.iter().collect::<BTreeSet<_>>().len();
    // Every collection seen may be locked by the time of the move.
    let prompt_collections = record
        .collections
        .iter()
        .flatten()
        .chain(&locked)
        .chain(record.items.iter().map(|item| &item.collection))
        .chain(record.skipped.iter().map(|item| &item.collection))
        .collect::<BTreeSet<_>>()
        .len()
        .max(1);
    let missing = record
        .items
        .iter()
        .filter(|item| !vault.contains(&item.fingerprint))
        .cloned()
        .collect();
    Check {
        items: record.items,
        missing,
        skipped: record.skipped,
        skipped_collections: record.skipped_collections,
        locked_collections,
        prompt_collections,
    }
}

/// Run the inventory in `distro` and compare it with the fingerprints
/// `vault` returns.
pub(crate) fn check(
    wsl: &dyn Wsl,
    distro: &str,
    vault: impl FnOnce() -> Result<HashSet<String>, String>,
    cancel: &AtomicBool,
) -> Result<Check, String> {
    let record = record(
        wsl,
        distro,
        INVENTORY_SCRIPT,
        "inventory",
        None,
        INVENTORY_LIMIT,
        cancel,
    )?;
    let vault = vault()?;
    Ok(compare(record, &vault))
}

/// What a move did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MoveReport {
    pub(crate) added: usize,
    pub(crate) kept: usize,
    pub(crate) skipped: Vec<KeyringSkippedItem>,
    pub(crate) skipped_collections: Vec<SkippedCollection>,
}

/// A passphrase used once, for the archive on the `wsl.exe` pipe: 32
/// letters and digits from the OS random source, which pass the archive's
/// strength check, and nothing a line-based read could split.
fn one_time_passphrase() -> Result<Zeroizing<String>, String> {
    use factorseal::personal::generator::{Options, Style, generate};
    generate(Options {
        style: Style::Random,
        length: 32,
        words: 12,
        digits: true,
        symbols: false,
    })
    .map_err(|error| format!("no random passphrase: {error}"))
}

/// Refuse an archive holding anything but keyring items of `distro`: a
/// process in the distro must not be able to add other vault entries.
fn check_entries(archive: &VaultArchive, distro: &str) -> Result<(), String> {
    let partition = factorseal::vault::wsl_relay::wsl_keyring_namespace(distro)
        .map_err(|error| error.to_string())?;
    if archive.entries.iter().all(|entry| {
        entry.metadata.partition == partition
            && entry.metadata.document_kind == DocumentKind::LinuxSecretService
    }) {
        Ok(())
    } else {
        Err(format!(
            "{distro} sent entries outside its keyring; nothing was moved."
        ))
    }
}

/// Why a move ended without a report.
#[derive(Debug)]
pub(crate) struct MoveFailure {
    pub(crate) message: String,
    /// Cancelled before anything was restored: nothing changed.
    pub(crate) cancelled: bool,
    /// The restore ran and failed, possibly after adding some items.
    pub(crate) restored: bool,
}

/// Export `distro`'s gnome-keyring, unlocking it, and decrypt and check
/// the archive.
fn export(
    wsl: &dyn Wsl,
    distro: &str,
    prompt_collections: usize,
    cancel: &AtomicBool,
) -> Result<(Record, VaultArchive), String> {
    let passphrase = one_time_passphrase()?;
    let mut stdin = Zeroizing::new(passphrase.as_bytes().to_vec());
    stdin.push(b'\n');
    let mut record = record(
        wsl,
        distro,
        EXPORT_SCRIPT,
        "export",
        Some(&stdin),
        move_limit(prompt_collections),
        cancel,
    )?;
    let encrypted = record
        .archive
        .take()
        .ok_or_else(|| format!("{distro} sent no archive."))
        .and_then(|archive| {
            STANDARD
                .decode(archive)
                .map_err(|error| format!("{distro} sent an unreadable archive: {error}"))
        })?;
    let archive = factorseal::decrypt_vault_archive(&encrypted, passphrase.as_bytes())
        .map_err(|error| format!("{distro} sent an unreadable archive: {error}"))?;
    check_entries(&archive, distro)?;
    Ok((record, archive))
}

/// Export `distro`'s gnome-keyring, unlocking it, and restore the archive
/// through `restore`, which returns how many items it added and kept. A
/// Cancel stops the move up to the restore, not the restore itself.
pub(crate) fn move_items(
    wsl: &dyn Wsl,
    distro: &str,
    prompt_collections: usize,
    restore: impl FnOnce(VaultArchive) -> Result<(usize, usize), String>,
    cancel: &AtomicBool,
) -> Result<MoveReport, MoveFailure> {
    let before_restore = |message| MoveFailure {
        message,
        cancelled: cancel.load(Ordering::SeqCst),
        restored: false,
    };
    let (record, archive) =
        export(wsl, distro, prompt_collections, cancel).map_err(before_restore)?;
    if cancel.load(Ordering::SeqCst) {
        return Err(before_restore("Cancelled.".to_owned()));
    }
    let (added, kept) = restore(archive).map_err(|message| MoveFailure {
        message,
        cancelled: false,
        restored: true,
    })?;
    Ok(MoveReport {
        added,
        kept,
        skipped: record.skipped,
        skipped_collections: record.skipped_collections,
    })
}

/// A skipped item, for the row: its label when gnome-keyring showed one.
pub(crate) fn skipped_line(item: &KeyringSkippedItem) -> String {
    let reason = match item.reason {
        KeyringSkipReason::NetworkManager => "a Wi-Fi password, not moved".to_owned(),
        KeyringSkipReason::Duplicate => {
            "the same item as another one, which is the one moved".to_owned()
        }
        reason => reason.to_string(),
    };
    format!(
        "{} in {}: {reason}",
        item.label.as_deref().unwrap_or("A locked item"),
        item.collection
    )
}

/// A collection a move could not read, for the row. A prompt nobody
/// answered reads differently from one dismissed.
pub(crate) fn skipped_collection_line(skipped: &SkippedCollection) -> String {
    let collection = &skipped.collection;
    match skipped.reason.as_str() {
        "unlock dismissed" => {
            format!("{collection}: its password prompt was cancelled, so it was not read.")
        }
        "unlock timed out" => format!(
            "{collection}: nobody answered its password prompt within five minutes, so it was not read. The prompt needs WSLg's display."
        ),
        "locked" => format!("{collection}: locked."),
        reason => format!("{collection}: {reason}."),
    }
}

/// The system's `wsl.exe`; none off Windows.
#[cfg_attr(windows, allow(clippy::unnecessary_wraps))] // None elsewhere.
pub(crate) fn system() -> Option<&'static (dyn Wsl + Sync)> {
    #[cfg(windows)]
    {
        Some(&SystemWsl)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Runs the system's `wsl.exe`.
#[cfg(windows)]
pub(crate) struct SystemWsl;

#[cfg(windows)]
impl Wsl for SystemWsl {
    fn run(
        &self,
        args: &[String],
        stdin: Option<&[u8]>,
        limit: Duration,
        cancel: &AtomicBool,
    ) -> Result<RunOutput, RunError> {
        use std::io::Write as _;
        use std::os::windows::process::CommandExt as _;
        use std::process::{Command, Stdio};
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let mut child = Command::new(crate::wsl_distros::system_exe(
            std::env::var_os("SystemRoot"),
            "wsl.exe",
        ))
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| RunError::Start(error.to_string()))?;
        // Written on its own thread, so a child that never reads can't
        // hold this one up; closing the pipe ends the input.
        let writer = child.stdin.take().zip(stdin).map(|(mut pipe, input)| {
            let input = Zeroizing::new(input.to_vec());
            std::thread::spawn(move || {
                let _ = pipe.write_all(&input);
            })
        });
        let stdout = child
            .stdout
            .take()
            .map(|pipe| std::thread::spawn(move || read_capped(pipe, MAX_STDOUT_BYTES)));
        let stderr = child
            .stderr
            .take()
            .map(|pipe| std::thread::spawn(move || read_tail(pipe, MAX_STDERR_BYTES)));
        let started = std::time::Instant::now();
        let outcome = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status.code()),
                Ok(None) => {}
                Err(error) => break Err(RunError::Start(error.to_string())),
            }
            if cancel.load(Ordering::SeqCst) {
                break Err(RunError::Cancelled);
            }
            if started.elapsed() >= limit {
                break Err(RunError::TimedOut);
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        if outcome.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(writer) = writer {
            let _ = writer.join();
        }
        let stdout = stdout
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default();
        let stderr = stderr
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default();
        Ok(RunOutput {
            code: outcome?,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn framed(kind: &str, json: &serde_json::Value) -> String {
        let body = STANDARD.encode(serde_json::to_vec(json).unwrap());
        format!(
            "FACTORSEAL-FRAME v1 {kind} {}\n{body}\nFACTORSEAL-FRAME end\n",
            body.len()
        )
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn a_frame_is_found_after_garbage_utf16_text_and_crlf() {
        let json = serde_json::json!({"a": 1});
        let frame = framed("inventory", &json).replace('\n', "\r\n");
        let mut output = utf16("Aviso: o WSL está atualizando.\r\n");
        output.extend_from_slice(b"direnv: loading ~/.envrc\nwarning: Git tree is dirty");
        output.extend_from_slice(frame.as_bytes());
        output.extend_from_slice(b"trailing noise\n");
        let (kind, content) = unframe(&output).unwrap();
        assert_eq!(kind, "inventory");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&content).unwrap(),
            json
        );
    }

    #[test]
    fn a_frame_needs_its_exact_length_and_end_line() {
        let json = serde_json::json!({"a": 1});
        let good = framed("export", &json);
        assert!(unframe(good.as_bytes()).is_some());
        assert!(unframe(good.trim_end().as_bytes()).is_some(), "end at EOF");
        let header_end = good.find('\n').unwrap();
        let (header, rest) = good.split_at(header_end);
        let length: usize = header.rsplit(' ').next().unwrap().parse().unwrap();
        // Off by a whole base64 group, the body still decodes.
        for wrong in [length - 4, length - 1, length + 1, length + 4] {
            let changed = format!("FACTORSEAL-FRAME v1 export {wrong}{rest}");
            assert!(unframe(changed.as_bytes()).is_none(), "length {wrong}");
        }
        for broken in [
            good.replace("FACTORSEAL-FRAME end", "FACTORSEAL-FRAME ende"),
            good.replace("FACTORSEAL-FRAME end\n", ""),
            good.replace("\nFACTORSEAL-FRAME end", "FACTORSEAL-FRAME end"),
            good.replace(" export ", " export  "),
            good.replace(" export ", " Export "),
            good.replace(&format!(" {length}\n"), " +1\n"),
            good[..good.len() - 30].to_owned(),
        ] {
            assert!(unframe(broken.as_bytes()).is_none(), "{broken:?}");
        }
        assert!(unframe(b"").is_none());
        assert!(unframe(b"FACTORSEAL-FRAME v1 ").is_none());
    }

    #[test]
    fn a_broken_frame_before_a_good_one_is_passed_over() {
        let json = serde_json::json!({"b": 2});
        let output = format!(
            "echo FACTORSEAL-FRAME v1 inventory 999\n{}",
            framed("inventory", &json)
        );
        let (_, content) = unframe(output.as_bytes()).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&content).unwrap(),
            json
        );
    }

    /// Output from the distro can't make the parser slow: many start
    /// markers without a newline, or many candidates that all announce a
    /// length ending at the same end line, repeated. The decoder's zeroed
    /// buffer makes the latter slow on Windows only (glibc hands out fresh
    /// zero pages), so `build-windows.sh check` is where it bites.
    #[test]
    fn many_frame_markers_parse_in_linear_time() {
        let markers = "FACTORSEAL-FRAME v1 ".repeat(1 << 16);
        // Built from the back: each header announces exactly the bytes up
        // to the one end line, so every candidate reaches its body check.
        // The last body byte isn't base64, so no candidate is a frame.
        let mut shared_end = "!\nFACTORSEAL-FRAME end\n".to_owned();
        let mut body = 1;
        for _ in 0..30_000 {
            let header = format!("FACTORSEAL-FRAME v1 inventory {body}\n");
            body += header.len();
            shared_end.insert_str(0, &header);
        }
        assert!(frame_at(&shared_end.as_bytes()[FRAME_START.len()..]).is_none());
        for output in [markers, shared_end.repeat(20)] {
            let started = std::time::Instant::now();
            assert!(unframe(output.as_bytes()).is_none());
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{} bytes took {:?}",
                output.len(),
                started.elapsed()
            );
        }
    }

    /// Past the stderr cap, the CLI's error, which comes last, is still
    /// what the row shows.
    #[test]
    fn stderr_keeps_its_end_for_the_message() {
        let mut noise = String::new();
        for line in 0..3000 {
            use std::fmt::Write as _;
            let _ = writeln!(
                noise,
                "warning: profile line {line} of a verbose login shell"
            );
        }
        noise.push_str("factorseal: no Secret Service on the session bus\n");
        assert!(noise.len() > 2 * MAX_STDERR_BYTES);
        let mut pipe = std::io::Cursor::new(noise.clone().into_bytes());
        let stderr = read_tail(&mut pipe, MAX_STDERR_BYTES);
        assert_eq!(pipe.position(), noise.len() as u64, "read to the end");
        assert!(stderr.len() <= MAX_STDERR_BYTES);
        assert!(noise.as_bytes().ends_with(&stderr));
        let row = failure(
            "NixOS",
            &RunOutput {
                code: Some(1),
                stdout: Vec::new(),
                stderr,
            },
        );
        assert!(row.starts_with("No Secret Service runs on NixOS"), "{row}");
        assert_eq!(
            read_tail(std::io::Cursor::new(b"short".to_vec()), 64),
            b"short"
        );
    }

    #[test]
    fn output_past_the_cap_is_read_to_the_end_and_dropped() {
        let mut pipe = std::io::Cursor::new(vec![7_u8; 10]);
        assert_eq!(read_capped(&mut pipe, 4), [7, 7, 7, 7]);
        assert_eq!(
            pipe.position(),
            10,
            "drained, so the child is never blocked"
        );
        assert_eq!(read_capped(std::io::Cursor::new(b"ab".to_vec()), 4), b"ab");
    }

    #[test]
    fn console_text_reads_utf16_and_utf8() {
        assert_eq!(
            console_text(&utf16("Não há distribuição")),
            "Não há distribuição"
        );
        assert_eq!(console_text("plain é".as_bytes()), "plain é");
        assert_eq!(
            error_lines(&utf16("\u{feff}\r\nfirst\r\n\r\nsecond\r\nthird\r\nfourth")),
            ["second", "third", "fourth"]
        );
    }

    /// The arguments, stdin and limit of one run.
    type Call = (Vec<String>, Option<Vec<u8>>, Duration);

    /// A fake `wsl.exe`: records each call and answers from a list.
    struct FakeWsl {
        calls: RefCell<Vec<Call>>,
        answers: RefCell<Vec<Result<RunOutput, RunError>>>,
    }

    impl FakeWsl {
        fn new(answers: Vec<Result<RunOutput, RunError>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                answers: RefCell::new(answers),
            }
        }
    }

    impl Wsl for FakeWsl {
        fn run(
            &self,
            args: &[String],
            stdin: Option<&[u8]>,
            limit: Duration,
            _cancel: &AtomicBool,
        ) -> Result<RunOutput, RunError> {
            self.calls
                .borrow_mut()
                .push((args.to_vec(), stdin.map(<[u8]>::to_vec), limit));
            self.answers.borrow_mut().remove(0)
        }
    }

    #[allow(clippy::unnecessary_wraps)] // The runner's answer.
    fn output(stdout: impl Into<Vec<u8>>, stderr: &str, code: i32) -> Result<RunOutput, RunError> {
        Ok(RunOutput {
            code: Some(code),
            stdout: stdout.into(),
            stderr: stderr.as_bytes().to_vec(),
        })
    }

    fn fingerprint(digit: char) -> String {
        std::iter::repeat_n(digit, 64).collect()
    }

    fn inventory() -> serde_json::Value {
        serde_json::json!({
            "target": "wsl:NixOS",
            "items": [
                {"fingerprint": fingerprint('a'), "collection": "login", "locked": true},
                {"fingerprint": fingerprint('b'), "collection": "login", "locked": false,
                 "label": "GitHub CLI", "modified": 7},
                {"fingerprint": fingerprint('c'), "collection": "other", "locked": true},
            ],
            "skipped": [
                {"collection": "login", "label": "bare", "reason": "no_attributes"},
            ],
            "skipped_collections": [],
            "locked_collections": ["login", "other", "empty"],
            "collections": ["login", "other", "empty", "unlocked"],
        })
    }

    #[test]
    fn check_runs_the_inventory_through_sh_and_compares_fingerprints() {
        let mut stdout = utf16("wsl: aviso\r\n");
        stdout.extend_from_slice(b"login shell says hi\n");
        stdout.extend_from_slice(framed("inventory", &inventory()).as_bytes());
        let wsl = FakeWsl::new(vec![output(stdout, "", 0)]);
        let check = check(
            &wsl,
            "NixOS",
            || Ok(HashSet::from([fingerprint('b'), fingerprint('f')])),
            &AtomicBool::new(false),
        )
        .unwrap();
        let calls = wsl.calls.borrow();
        assert_eq!(
            calls[0].0,
            [
                "-d",
                "NixOS",
                "--exec",
                "sh",
                "-lc",
                "exec factorseal export-secret-service --inventory --framed --wsl-distro $1",
                "sh",
                "NixOS"
            ]
        );
        assert_eq!(calls[0].1, None, "an inventory gets no stdin");
        assert_eq!(calls[0].2, INVENTORY_LIMIT);
        assert_eq!(check.items.len(), 3);
        assert_eq!(
            check
                .missing
                .iter()
                .map(|item| item.fingerprint.clone())
                .collect::<Vec<_>>(),
            [fingerprint('a'), fingerprint('c')]
        );
        assert_eq!(check.skipped.len(), 1);
        assert_eq!(check.locked_collections, 3);
        assert_eq!(check.prompt_collections, 4, "the unlocked one may lock");
    }

    #[test]
    fn a_move_may_prompt_for_every_collection_even_unlocked_ones() {
        let unlocked = serde_json::json!({
            "target": "wsl:NixOS",
            "items": [
                {"fingerprint": fingerprint('a'), "collection": "login", "locked": false, "label": "gh"},
            ],
            "skipped": [{"collection": "other", "label": "bare", "reason": "no_attributes"}],
            "skipped_collections": [],
            "locked_collections": [],
            "collections": ["login", "other", "empty"],
        });
        let wsl = FakeWsl::new(vec![output(framed("inventory", &unlocked), "", 0)]);
        let first = check(
            &wsl,
            "NixOS",
            || Ok(HashSet::new()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(first.locked_collections, 0);
        assert_eq!(first.prompt_collections, 3);
        let mut empty = unlocked;
        empty["items"] = serde_json::json!([]);
        empty["skipped"] = serde_json::json!([]);
        empty["collections"] = serde_json::json!([]);
        let wsl = FakeWsl::new(vec![output(framed("inventory", &empty), "", 0)]);
        let check = check(
            &wsl,
            "NixOS",
            || Ok(HashSet::new()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(check.prompt_collections, 1, "at least one");
    }

    #[test]
    fn an_older_cli_counts_every_collection_with_an_item() {
        let mut record = inventory();
        let record_map = record.as_object_mut().unwrap();
        record_map.remove("locked_collections");
        record_map.remove("collections");
        record["skipped"][0]["collection"] = "third".into();
        let wsl = FakeWsl::new(vec![output(framed("inventory", &record), "", 0)]);
        let check = check(
            &wsl,
            "NixOS",
            || Ok(HashSet::new()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(
            check.locked_collections, 2,
            "login and other have locked items"
        );
        assert_eq!(check.prompt_collections, 3);
        assert_eq!(check.missing.len(), 3);
    }

    #[test]
    fn check_explains_what_went_wrong() {
        let cases: Vec<(Result<RunOutput, RunError>, &str)> = vec![
            (
                output("", "sh: line 1: exec: factorseal: not found\n", 127),
                "Add the factorseal package",
            ),
            (
                output("", "factorseal: no Secret Service on the session bus\n", 1),
                "No Secret Service runs on NixOS's session bus, and none can be started there",
            ),
            (
                output("", "factorseal: no session bus: No such file\n", 1),
                "No Secret Service runs on NixOS's session bus",
            ),
            (
                output(
                    "",
                    "error: unrecognized subcommand 'export-secret-service'\n",
                    2,
                ),
                "too old",
            ),
            (
                output(
                    "",
                    "factorseal: cannot identify the Secret Service: Permission denied\nmore\n",
                    1,
                ),
                "gave no answer FactorSeal could read: factorseal: cannot identify the Secret Service: Permission denied",
            ),
            (
                output(
                    "",
                    "warning: a\nwarning: b\nwarning: c\nfactorseal: cannot identify the Secret Service: Permission denied\n",
                    1,
                ),
                "could read: factorseal: cannot identify the Secret Service: Permission denied",
            ),
            (
                output("", "one\ntwo\nthree\nfour\n", 1),
                "could read: two three four",
            ),
            (
                output(
                    utf16("There is no distribution with the supplied name.\r\n"),
                    "",
                    1,
                ),
                "There is no distribution with the supplied name.",
            ),
            (
                output("", "", 0),
                "NixOS gave no answer FactorSeal could read.",
            ),
            (
                output(framed("export", &inventory()), "", 0),
                "answered with a export instead of an inventory",
            ),
            (
                output(
                    framed("inventory", &serde_json::json!({"target": "wsl:NixOS"})),
                    "",
                    0,
                ),
                "unreadable inventory",
            ),
            (
                output(
                    framed("inventory", &{
                        let mut record = inventory();
                        record["target"] = "wsl:Debian".into();
                        record
                    }),
                    "",
                    0,
                ),
                "answered for the keyring wsl:Debian",
            ),
            (Err(RunError::TimedOut), "did not answer within 3 minutes"),
            (Err(RunError::Cancelled), "Cancelled."),
            (
                Err(RunError::Start("file not found".to_owned())),
                "Could not start WSL: file not found",
            ),
        ];
        for (answer, expected) in cases {
            let wsl = FakeWsl::new(vec![answer]);
            let error = check(
                &wsl,
                "NixOS",
                || panic!("the vault is asked only after a good inventory"),
                &AtomicBool::new(false),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error:?} lacks {expected:?}");
        }
    }

    #[test]
    fn the_one_time_passphrase_passes_the_archive_check() {
        let mut seen = HashSet::new();
        for _ in 0..32 {
            let passphrase = one_time_passphrase().unwrap();
            assert_eq!(passphrase.len(), 32);
            assert!(passphrase.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            factorseal::security::validate_new_password(passphrase.as_bytes()).unwrap();
            assert!(seen.insert(passphrase.to_string()), "repeated");
        }
    }

    #[test]
    fn the_move_limit_grows_with_each_locked_collection() {
        assert_eq!(move_limit(0), INVENTORY_LIMIT);
        assert_eq!(
            move_limit(2),
            INVENTORY_LIMIT + Duration::from_secs(2 * (300 + 5))
        );
        assert!(move_limit(usize::MAX) > move_limit(1000));
    }

    /// A fake whose export encrypts `entries` with the passphrase it is
    /// handed on stdin, as the CLI does.
    struct ExportingWsl {
        inner: FakeWsl,
        entries: RefCell<Option<Vec<factorseal::VaultArchiveEntry>>>,
        target: &'static str,
    }

    impl Wsl for ExportingWsl {
        fn run(
            &self,
            args: &[String],
            stdin: Option<&[u8]>,
            limit: Duration,
            cancel: &AtomicBool,
        ) -> Result<RunOutput, RunError> {
            self.inner.run(args, stdin, limit, cancel)?;
            let line = stdin.expect("the passphrase comes on stdin");
            let passphrase = line.strip_suffix(b"\n").expect("one line");
            let archive = factorseal::encrypt_vault_archive(
                &VaultArchive::new(1, self.entries.borrow_mut().take().unwrap()),
                passphrase,
            )
            .unwrap();
            let record = serde_json::json!({
                "target": self.target,
                "items": [{"fingerprint": fingerprint('a'), "collection": "login", "locked": false, "label": "gh"}],
                "skipped": [
                    {"collection": "login", "label": "huge", "reason": "too_large"},
                    {"collection": "other", "label": "gh", "reason": "duplicate"},
                ],
                "skipped_collections": [{"collection": "third", "reason": "unlock timed out"}],
                "archive": STANDARD.encode(&*archive),
            });
            output(format!("motd\n{}", framed("export", &record)), "", 0)
        }
    }

    /// `count` keyring items for `partition`, made as the CLI makes them.
    fn keyring_entries(partition: &[u8], count: usize) -> Vec<factorseal::VaultArchiveEntry> {
        let items = (0..count)
            .map(|n| factorseal::vault::KeyringSourceItem {
                collection: "login".to_owned(),
                locked: false,
                label: Some(format!("item {n}")),
                modified: Some(1),
                attributes: std::collections::HashMap::from([(
                    "service".to_owned(),
                    format!("service {n}"),
                )]),
                secret: Some((Zeroizing::new(b"value".to_vec()), "text/plain".to_owned())),
            })
            .collect();
        factorseal::vault::map_keyring_items(items, true)
            .archive_entries(partition)
            .unwrap()
    }

    fn nixos_keyring() -> Vec<u8> {
        factorseal::vault::wsl_relay::wsl_keyring_namespace("NixOS").unwrap()
    }

    #[test]
    fn move_sends_a_passphrase_decrypts_and_restores_the_whole_archive() {
        let wsl = ExportingWsl {
            inner: FakeWsl::new(vec![Ok(RunOutput::default())]),
            entries: RefCell::new(Some(keyring_entries(&nixos_keyring(), 2))),
            target: "wsl:NixOS",
        };
        let mut restored = 0;
        let report = move_items(
            &wsl,
            "NixOS",
            2,
            |archive| {
                restored = archive.entries.len();
                Ok((1, 1))
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(restored, 2, "the whole archive, no filter");
        assert_eq!(report.added, 1);
        assert_eq!(report.kept, 1);
        assert_eq!(report.skipped.len(), 2);
        assert_eq!(skipped_line(&report.skipped[0]), "huge in login: too large");
        assert!(skipped_line(&report.skipped[1]).contains("the one moved"));
        assert!(
            skipped_collection_line(&report.skipped_collections[0])
                .contains("nobody answered its password prompt within five minutes")
        );
        let calls = wsl.inner.calls.borrow();
        let (args, stdin, limit) = &calls[0];
        assert_eq!(
            args[5],
            "exec factorseal export-secret-service --framed --passphrase-stdin --wsl-distro $1"
        );
        assert_eq!(args[7], "NixOS");
        let stdin = stdin.as_ref().unwrap();
        assert_eq!(stdin.len(), 33);
        assert_eq!(*limit, move_limit(2));
    }

    #[test]
    fn move_refuses_entries_outside_the_distros_keyring() {
        let mut local = keyring_entries(&nixos_keyring(), 1).remove(0);
        local.metadata.document_kind = DocumentKind::LocalKeyring;
        local.value = factorseal::WireSecret::new(b"value".to_vec()).unwrap();
        let debian = factorseal::vault::wsl_relay::wsl_keyring_namespace("Debian").unwrap();
        for entry in [
            local,
            keyring_entries(&debian, 1).remove(0),
            // The native keyring (its constant is exported on Linux only).
            keyring_entries(b"factorseal/secret-service/v1", 1).remove(0),
        ] {
            let wsl = ExportingWsl {
                inner: FakeWsl::new(vec![Ok(RunOutput::default())]),
                entries: RefCell::new(Some({
                    let mut entries = keyring_entries(&nixos_keyring(), 1);
                    entries.push(entry);
                    entries
                })),
                target: "wsl:NixOS",
            };
            let error = move_items(
                &wsl,
                "NixOS",
                1,
                |_| panic!("nothing is restored"),
                &AtomicBool::new(false),
            )
            .unwrap_err()
            .message;
            assert!(error.contains("outside its keyring"), "{error}");
        }
    }

    #[test]
    fn move_refuses_another_distros_record() {
        let wsl = ExportingWsl {
            inner: FakeWsl::new(vec![Ok(RunOutput::default())]),
            entries: RefCell::new(Some(Vec::new())),
            target: "wsl:Debian",
        };
        let error = move_items(
            &wsl,
            "NixOS",
            1,
            |_| panic!("nothing is restored"),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.message.contains("wsl:Debian"), "{error:?}");
        assert!(!error.cancelled && !error.restored);
    }

    #[test]
    fn a_failed_restore_is_reported_even_after_a_late_cancel() {
        let wsl = ExportingWsl {
            inner: FakeWsl::new(vec![Ok(RunOutput::default())]),
            entries: RefCell::new(Some(keyring_entries(&nixos_keyring(), 2))),
            target: "wsl:NixOS",
        };
        let cancel = AtomicBool::new(false);
        let error = move_items(
            &wsl,
            "NixOS",
            1,
            |_| {
                // Cancel pressed while the restore runs, which then fails.
                cancel.store(true, Ordering::SeqCst);
                Err("Import interrupted after 1 confirmed items".to_owned())
            },
            &cancel,
        )
        .unwrap_err();
        assert!(error.restored, "the vault must be read again");
        assert!(!error.cancelled, "the error must be shown");
        assert!(error.message.contains("after 1 confirmed items"));
    }

    #[test]
    fn a_cancel_before_the_restore_changes_nothing() {
        let wsl = FakeWsl::new(vec![Err(RunError::Cancelled)]);
        let error = move_items(
            &wsl,
            "NixOS",
            1,
            |_| panic!("nothing is restored"),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(error.cancelled && !error.restored, "{error:?}");
    }

    #[test]
    fn skipped_collections_tell_dismissed_from_unanswered() {
        let line = |reason: &str| {
            skipped_collection_line(&SkippedCollection {
                collection: "login".to_owned(),
                reason: reason.to_owned(),
            })
        };
        assert!(line("unlock dismissed").contains("was cancelled"));
        assert!(line("unlock timed out").contains("nobody answered"));
        assert_eq!(
            line("still locked after the unlock"),
            "login: still locked after the unlock."
        );
    }
}
