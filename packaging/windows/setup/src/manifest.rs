//! The release manifest, `factorseal-release.json`, and its verification.
//!
//! A manifest names the release's files with their SHA-256 and lists the
//! install steps, from the installer's fixed vocabulary ([`Step`]). The
//! installer reads it, refuses anything outside its rules, and hashes
//! every file before anything stops or changes:
//!
//! - a manifest that needs a newer installer (`requires_setup`) is refused
//!   as such, before the rest is read;
//! - unknown fields and step types are refused;
//! - file paths stay inside the release folder (relative, no `..`, no
//!   links out);
//! - commands run only executables among the release's files;
//! - registry keys stay under the listed HKCU prefixes;
//! - paths uninstall may offer to delete stay under FactorSeal's own
//!   folders, and never touch the vault.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The manifest format this installer reads.
pub const SCHEMA: u32 = 1;

/// The installer capabilities this build has. A release that needs a step
/// type added later raises its `requires_setup` past this, and this
/// installer refuses it instead of guessing. Capabilities are cumulative.
pub const SETUP_CAPABILITY: u32 = 1;

/// The manifest's file name in a release folder.
pub const MANIFEST_FILE: &str = "factorseal-release.json";

/// The product a manifest must describe.
pub const PRODUCT: &str = "FactorSeal";

/// The installer's own name in the install folder. A release never lists
/// it: the installer copies itself there (step 4 of the plan).
pub const SETUP_EXE: &str = "factorseal-setup.exe";

/// The installer's record in the install folder; never a release file.
pub const RECORD_FILE: &str = "install.json";

/// Larger manifests are refused before parsing.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// The HKCU keys a `registry` step or `registry_cleanup` may touch: a key
/// is accepted when it is one of these or lies under one. The browser hosts
/// are the four Desktop registers (`src/browser/registration.rs`).
const REGISTRY_PREFIXES: [&str; 5] = [
    r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser",
    r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\dev.factorseal.browser",
    r"HKCU\Software\Google\Chrome\NativeMessagingHosts\dev.factorseal.browser",
    r"HKCU\Software\Chromium\NativeMessagingHosts\dev.factorseal.browser",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal",
];

/// The Installed apps entry.
pub const UNINSTALL_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal";

/// The folders `ask_to_delete` paths must lie in.
const DELETABLE_ROOTS: [&str; 2] = [r"%APPDATA%\Factorseal", r"%LOCALAPPDATA%\Factorseal"];

/// The default vault root. No `ask_to_delete` path may be it, contain it
/// or lie inside it.
const VAULT_ROOT: &str = r"%LOCALAPPDATA%\Factorseal\Factorseal\data";

/// A release manifest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The manifest format, [`SCHEMA`].
    pub schema: u32,
    /// Always [`PRODUCT`].
    pub product: String,
    /// The release's version, shown to the user.
    pub version: String,
    /// The installer capability this release needs.
    pub requires_setup: u32,
    /// Every file the release installs.
    pub files: Vec<FileEntry>,
    /// How this version is stopped, once it is the installed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Stop>,
    /// What installing does, in order.
    pub steps: Vec<Step>,
    /// What uninstalling this version removes, besides what install did.
    #[serde(default)]
    pub uninstall: Uninstall,
}

/// One file of the release.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Relative to the manifest's folder, with `/` between folders.
    pub path: String,
    /// Lowercase hex.
    pub sha256: String,
}

/// How a version is stopped.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    /// A release executable and its arguments, such as
    /// `factorseal-desktop.exe --quit`.
    pub command: Vec<String>,
    /// Release executables whose processes the installer also waits for
    /// (and stops) before replacing files.
    #[serde(default)]
    pub also_stop: Vec<String>,
}

/// An install step: the installer's whole vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// Copy the release's files into the install folder.
    InstallFiles {},
    /// Create a shortcut to a release executable.
    Shortcut(Shortcut),
    /// Set up the WSL distros that have FactorSeal, with the installer's
    /// own fixed commands.
    Wsl {},
    /// Launch the new version once, at the end.
    Start(Start),
    /// Write string values under the allowed HKCU keys.
    Registry(Registry),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Shortcut {
    /// The shortcut's file name, without `.lnk`.
    pub name: String,
    /// A release executable.
    pub target: String,
    /// Where the shortcut always goes.
    #[serde(default)]
    pub places: Vec<Place>,
    /// Where it goes if the user chooses.
    #[serde(default)]
    pub optional_places: Vec<Place>,
    /// The arguments of the shortcut in the Startup folder.
    #[serde(default)]
    pub startup_args: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Place {
    StartMenu,
    Startup,
    Desktop,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// The launch, such as `factorseal-desktop.exe --open wsl-keyrings`.
    pub command: Vec<String>,
    /// The launch under `--no-open` or `--quiet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_command: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub values: Vec<RegistryValue>,
}

/// A `REG_SZ` value.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryValue {
    /// Such as `HKCU\Software\…`, under an allowed prefix.
    pub key: String,
    /// Empty for the key's default value.
    #[serde(default)]
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Uninstall {
    /// HKCU keys to delete, under the allowed prefixes.
    #[serde(default)]
    pub registry_cleanup: Vec<String>,
    /// Folders uninstall offers to delete, under FactorSeal's own.
    #[serde(default)]
    pub ask_to_delete: Vec<String>,
    /// Shown when uninstall ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_note: Option<String>,
}

/// Why a manifest or release was refused.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "this release needs a newer installer (it requires setup capability {required}, \
         this installer has {supported})"
    )]
    NeedsNewerSetup { required: u64, supported: u32 },
    #[error("the release manifest is invalid: {0}")]
    Invalid(String),
    #[error("{0} in the release folder does not match the manifest's hash")]
    HashMismatch(String),
}

fn invalid(message: impl Into<String>) -> ManifestError {
    ManifestError::Invalid(message.into())
}

impl Manifest {
    /// Parse and check a manifest. A release needing a newer installer is
    /// refused as such before its fields are read, since they may be ones
    /// this installer doesn't know.
    pub fn parse(text: &[u8]) -> Result<Self, ManifestError> {
        let value: serde_json::Value =
            serde_json::from_slice(text).map_err(|error| invalid(format!("not JSON: {error}")))?;
        let header = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| invalid(format!("no {name} number")))
        };
        let required = header("requires_setup")?;
        if required > u64::from(SETUP_CAPABILITY) {
            return Err(ManifestError::NeedsNewerSetup {
                required,
                supported: SETUP_CAPABILITY,
            });
        }
        let schema = header("schema")?;
        if schema != u64::from(SCHEMA) {
            return Err(invalid(format!(
                "schema {schema}, but this installer reads schema {SCHEMA}"
            )));
        }
        let manifest: Self =
            serde_json::from_value(value).map_err(|error| invalid(error.to_string()))?;
        manifest.check()?;
        Ok(manifest)
    }

    /// The rules that need no file system.
    fn check(&self) -> Result<(), ManifestError> {
        if self.product != PRODUCT {
            return Err(invalid(format!("the product is {:?}", self.product)));
        }
        check_version(&self.version)?;
        self.check_files()?;
        self.check_steps()?;
        if let Some(stop) = &self.stop {
            self.check_command("stop", &stop.command)?;
            for name in &stop.also_stop {
                self.check_executable("also_stop", name)?;
            }
        }
        for key in &self.uninstall.registry_cleanup {
            check_registry_key(key)?;
        }
        for path in &self.uninstall.ask_to_delete {
            check_deletable(path)?;
        }
        if let Some(note) = &self.uninstall.keep_note {
            check_text("keep_note", note, 500)?;
        }
        Ok(())
    }

    fn check_files(&self) -> Result<(), ManifestError> {
        if self.files.is_empty() {
            return Err(invalid("no files"));
        }
        let mut seen = std::collections::HashSet::new();
        for file in &self.files {
            check_release_path(&file.path)?;
            if !is_sha256(&file.sha256) {
                return Err(invalid(format!(
                    "{}: sha256 must be 64 lowercase hex digits",
                    file.path
                )));
            }
            // Windows paths ignore case, so two entries may not differ by
            // case only.
            if !seen.insert(file.path.to_ascii_lowercase()) {
                return Err(invalid(format!("{} is listed twice", file.path)));
            }
            if [SETUP_EXE, RECORD_FILE]
                .iter()
                .any(|own| file.path.eq_ignore_ascii_case(own))
            {
                return Err(invalid(format!(
                    "{} is the installer's own file, not a release file",
                    file.path
                )));
            }
        }
        Ok(())
    }

    fn check_steps(&self) -> Result<(), ManifestError> {
        let count =
            |wanted: fn(&Step) -> bool| self.steps.iter().filter(|step| wanted(step)).count();
        // Later steps run the installed files, so copying comes first.
        if !matches!(self.steps.first(), Some(Step::InstallFiles {}))
            || count(|step| matches!(step, Step::InstallFiles {})) != 1
        {
            return Err(invalid("install_files must be the first step, once"));
        }
        if count(|step| matches!(step, Step::Wsl {})) > 1 {
            return Err(invalid("wsl may appear once"));
        }
        // One launch, last, so nothing races it for Desktop's instance lock.
        let starts = count(|step| matches!(step, Step::Start(_)));
        if starts > 1 || (starts == 1 && !matches!(self.steps.last(), Some(Step::Start(_)))) {
            return Err(invalid("start may appear once, as the last step"));
        }
        for step in &self.steps {
            match step {
                Step::InstallFiles {} | Step::Wsl {} => {}
                Step::Shortcut(shortcut) => self.check_shortcut(shortcut)?,
                Step::Start(start) => {
                    self.check_command("start", &start.command)?;
                    if let Some(quiet) = &start.quiet_command {
                        self.check_command("quiet_command", quiet)?;
                    }
                }
                Step::Registry(registry) => {
                    for value in &registry.values {
                        check_registry_key(&value.key)?;
                        check_text("registry value name", &value.name, 255)?;
                        check_text("registry value", &value.value, 4096)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn check_shortcut(&self, shortcut: &Shortcut) -> Result<(), ManifestError> {
        let name = &shortcut.name;
        if !(1..=100).contains(&name.chars().count())
            || name
                .chars()
                .any(|c| c.is_control() || r#"<>:"/\|?*"#.contains(c))
            || name.ends_with(['.', ' '])
        {
            return Err(invalid(format!("{name:?} is not a shortcut name")));
        }
        self.check_executable("shortcut target", &shortcut.target)?;
        let mut places = shortcut.places.clone();
        places.extend(&shortcut.optional_places);
        for (index, place) in places.iter().enumerate() {
            if places[..index].contains(place) {
                return Err(invalid(format!("{name}: a place is listed twice")));
            }
        }
        check_arguments("startup_args", &shortcut.startup_args)
    }

    /// A command: a release executable and plain arguments, run without a
    /// shell.
    fn check_command(&self, what: &str, command: &[String]) -> Result<(), ManifestError> {
        let Some((program, arguments)) = command.split_first() else {
            return Err(invalid(format!("{what}: empty command")));
        };
        self.check_executable(what, program)?;
        check_arguments(what, arguments)
    }

    /// `name` must be a listed `.exe`: the manifest can't name a system
    /// program or any path outside the release.
    fn check_executable(&self, what: &str, name: &str) -> Result<(), ManifestError> {
        let listed = self
            .files
            .iter()
            .any(|file| file.path.eq_ignore_ascii_case(name));
        if !listed || !name.to_ascii_lowercase().ends_with(".exe") {
            return Err(invalid(format!(
                "{what}: {name:?} is not an executable of the release"
            )));
        }
        Ok(())
    }
}

fn check_version(version: &str) -> Result<(), ManifestError> {
    let plain = (1..=64).contains(&version.len())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte));
    if plain {
        Ok(())
    } else {
        Err(invalid(format!("{version:?} is not a version")))
    }
}

fn check_text(what: &str, text: &str, limit: usize) -> Result<(), ManifestError> {
    if text.chars().count() > limit || text.contains('\0') {
        return Err(invalid(format!("{what} is too long or holds a NUL")));
    }
    Ok(())
}

fn check_arguments(what: &str, arguments: &[String]) -> Result<(), ManifestError> {
    if arguments.len() > 32 {
        return Err(invalid(format!("{what}: too many arguments")));
    }
    arguments
        .iter()
        .try_for_each(|argument| check_text(what, argument, 1024))
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A release file's path: relative, `/` between plain folder and file
/// names that mean the same file on Windows as they say.
pub(crate) fn check_release_path(path: &str) -> Result<(), ManifestError> {
    let refuse = |reason: &str| Err(invalid(format!("file path {path:?}: {reason}")));
    if path.is_empty() || path.len() > 200 {
        return refuse("empty or too long");
    }
    if path.contains('\\') {
        return refuse("use / between folders");
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return refuse("must stay inside the release folder");
        }
        if segment
            .chars()
            .any(|c| c.is_control() || r#"<>:"|?*"#.contains(c))
        {
            return refuse("holds a character Windows paths can't");
        }
        // Windows drops trailing dots and spaces, so "a.exe." is "a.exe".
        if segment.ends_with(['.', ' ']) {
            return refuse("ends with a dot or space");
        }
        let stem = segment.split('.').next().unwrap_or(segment);
        let device = ["CON", "PRN", "AUX", "NUL"]
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name))
            || (stem.len() == 4
                && ["COM", "LPT"].iter().any(|name| {
                    stem.get(..3)
                        .is_some_and(|start| start.eq_ignore_ascii_case(name))
                })
                && stem.as_bytes()[3].is_ascii_digit());
        if device {
            return refuse("names a Windows device");
        }
    }
    Ok(())
}

/// The `\`-separated parts of a Windows path or registry key, compared
/// without regard to case. `None` for empty, `.` or `..` parts and for
/// `/`, which would mean another path.
fn segments(path: &str) -> Option<Vec<String>> {
    path.split('\\')
        .map(|segment| {
            let plain = !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.contains(['/', '\0']);
            plain.then(|| segment.to_ascii_lowercase())
        })
        .collect()
}

fn starts_with(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

fn check_registry_key(key: &str) -> Result<(), ManifestError> {
    let allowed = segments(key).is_some_and(|key| {
        REGISTRY_PREFIXES
            .iter()
            .any(|prefix| starts_with(&key, &segments(prefix).unwrap_or_default()))
    });
    if allowed {
        Ok(())
    } else {
        Err(invalid(format!(
            "registry key {key:?} is outside the keys the installer may change"
        )))
    }
}

fn check_deletable(path: &str) -> Result<(), ManifestError> {
    let refuse = |reason: &str| Err(invalid(format!("ask_to_delete {path:?}: {reason}")));
    let Some(parts) = segments(path) else {
        return refuse("not a plain path");
    };
    // Only the root's own variable expands; a `%` elsewhere would be
    // another one.
    if parts.iter().skip(1).any(|part| part.contains('%')) {
        return refuse("not a plain path");
    }
    let under_root = DELETABLE_ROOTS
        .iter()
        .any(|root| starts_with(&parts, &segments(root).unwrap_or_default()));
    if !under_root {
        return refuse("outside FactorSeal's folders");
    }
    let vault = segments(VAULT_ROOT).unwrap_or_default();
    if starts_with(&parts, &vault) || starts_with(&vault, &parts) {
        return refuse("the vault is always kept");
    }
    Ok(())
}

/// A verified file of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseFile {
    /// As the manifest names it.
    pub path: String,
    /// Where it is in the release folder.
    pub source: PathBuf,
    pub sha256: String,
    pub len: u64,
}

/// A release whose manifest passed every rule and whose files all match
/// their hashes.
#[derive(Clone, Debug)]
pub struct Release {
    /// The release folder, canonical.
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// In the manifest's order.
    pub files: Vec<ReleaseFile>,
}

impl Release {
    /// Read the manifest at `manifest_path` and verify the release folder
    /// it is in: every file present, inside the folder, not reached
    /// through a link, and matching its hash. Nothing is changed.
    pub fn open(manifest_path: &Path) -> Result<Self, ManifestError> {
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| ManifestError::Io { path, source }
        };
        let file = File::open(manifest_path).map_err(io(manifest_path))?;
        let mut text = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut text)
            .map_err(io(manifest_path))?;
        if text.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(invalid("larger than 1 MiB"));
        }
        let manifest = Manifest::parse(&text)?;
        let folder = manifest_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = folder.canonicalize().map_err(io(folder))?;
        let files = manifest
            .files
            .iter()
            .map(|entry| verify_file(&dir, entry))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            dir,
            manifest,
            files,
        })
    }
}

/// The SHA-256 of what `reader` yields, as lowercase hex, and its length.
pub fn sha256_hex(mut reader: impl std::io::Read) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut len = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len += read as u64;
    }
    Ok((to_hex(&hasher.finalize()), len))
}

/// Bytes as lowercase hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn verify_file(dir: &Path, entry: &FileEntry) -> Result<ReleaseFile, ManifestError> {
    let refuse = |reason: &str| Err(invalid(format!("{}: {reason}", entry.path)));
    let mut source = dir.to_owned();
    let mut is_file = false;
    for segment in entry.path.split('/') {
        source.push(segment);
        // A link anywhere on the way could lead out of the release.
        match std::fs::symlink_metadata(&source) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return refuse("is reached through a link");
            }
            Ok(metadata) => is_file = metadata.is_file(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return refuse("is missing from the release folder");
            }
            Err(source_error) => {
                return Err(ManifestError::Io {
                    path: source,
                    source: source_error,
                });
            }
        }
    }
    // Before opening it: Windows refuses to open a folder as a file.
    if !is_file {
        return refuse("is not a file");
    }
    let canonical = source.canonicalize().map_err(|error| ManifestError::Io {
        path: source.clone(),
        source: error,
    })?;
    if !canonical.starts_with(dir) {
        return refuse("lies outside the release folder");
    }
    let file = File::open(&canonical).map_err(|error| ManifestError::Io {
        path: canonical.clone(),
        source: error,
    })?;
    let (sha256, len) = sha256_hex(file).map_err(|error| ManifestError::Io {
        path: canonical.clone(),
        source: error,
    })?;
    if sha256 != entry.sha256 {
        return Err(ManifestError::HashMismatch(entry.path.clone()));
    }
    Ok(ReleaseFile {
        path: entry.path.clone(),
        source: canonical,
        sha256,
        len,
    })
}

#[cfg(test)]
mod tests;
