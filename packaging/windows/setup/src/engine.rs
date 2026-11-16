//! The `install_files` step: stage the release beside the install folder,
//! then swap it in, keeping the old folder until the install commits.
//!
//! 1. Leftovers of an interrupted run are cleared first: an install folder
//!    renamed aside and never replaced is put back.
//! 2. Every file is copied into `<install folder>.new` and hashed while it
//!    is copied, so a file changed in the release folder after
//!    verification aborts. The staged copies are hashed again.
//! 3. The installer copies itself in when it is newer than the installed
//!    copy, and carries the installed copy over otherwise.
//! 4. The swap renames the install folder to `<install folder>.old` and the
//!    staging folder into its place. If either rename fails, the old
//!    folder is put back.
//! 5. [`Pending::commit`] removes the old folder and the shortcuts the old
//!    record lists that this install didn't make again;
//!    [`Pending::rollback`] restores the old folder.
//!
//! What Windows allows (checked 2026-11-16): a folder can be renamed while
//! a program started from it runs, but that program's file can't be
//! deleted; a process whose working directory is in the folder, or a file
//! open in it without delete sharing, stops the rename. So a running
//! FactorSeal only keeps the old folder from being removed: it is moved
//! to a unique name (`<install folder>.old-…`) and removed by a later run.
//! Renames and removals are retried for a few seconds, since a process
//! that just exited, or an antivirus scan of new files, holds them
//! briefly.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::manifest::{Release, SETUP_EXE, sha256_hex, to_hex};
use crate::record::{
    DESKTOP_EXE, Existing, InstallRecord, RECORD_FORMAT, RecordedFile, RecordedValue, is_newer,
};
use crate::registry::Registry;

/// How far below a shortcut folder adoption looks for shortcuts.
const SHORTCUT_DEPTH: usize = 2;

pub struct Options {
    /// Where FactorSeal is installed, `%LOCALAPPDATA%\Programs\FactorSeal`.
    pub install_dir: PathBuf,
    /// The running installer, copied into the install folder when it is
    /// newer than the copy there.
    pub setup_exe: PathBuf,
    /// The running installer's version.
    pub setup_version: String,
    /// Take over a hand-made install (the user agreed).
    pub adopt: bool,
    /// Where a hand-made install's shortcuts are looked for: the Start
    /// menu, Startup and Desktop folders.
    pub shortcut_dirs: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error(
        "{0} holds FactorSeal installed by hand; it can be taken over (its UNINSTALL.txt \
         goes, its shortcuts are recorded)"
    )]
    NeedsAdoption(PathBuf),
    #[error("cannot read the install record in {path}: {source}")]
    Record {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0} changed in the release folder after it was verified")]
    Changed(String),
    #[error("cannot {what} {path}: {source}")]
    Io {
        what: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "cannot replace {path}: {source}. A program may be running from it; quit FactorSeal \
         and try again"
    )]
    Swap {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn io(what: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> InstallError {
    let path = path.to_owned();
    move |source| InstallError::Io { what, path, source }
}

/// The staging and set-aside folders beside `install_dir`.
fn siblings(install_dir: &Path) -> (PathBuf, PathBuf) {
    let name = install_dir
        .file_name()
        .map_or_else(|| "FactorSeal".into(), std::ffi::OsStr::to_os_string);
    let with = |suffix: &str| {
        let mut sibling = name.clone();
        sibling.push(suffix);
        install_dir.with_file_name(sibling)
    };
    (with(".new"), with(".old"))
}

/// Clear what an interrupted run left: a staging folder goes, and a folder
/// set aside goes back if the install folder is missing (the run stopped
/// between the two renames), or goes if not (it stopped before removing
/// it).
pub fn recover(install_dir: &Path) -> Result<(), InstallError> {
    let (staging, old) = siblings(install_dir);
    remove_stuck(install_dir);
    if old.exists() {
        if !install_dir.exists() {
            retrying(|| std::fs::rename(&old, install_dir)).map_err(io("restore", &old))?;
        } else if retrying(|| std::fs::remove_dir_all(&old)).is_err() {
            // A program still runs from it: out of the way, for later.
            std::fs::rename(&old, stuck_name(install_dir)).map_err(io("move aside", &old))?;
        }
    }
    if staging.exists() {
        retrying(|| std::fs::remove_dir_all(&staging)).map_err(io("remove", &staging))?;
    }
    Ok(())
}

/// A unique name beside `install_dir` for an old folder that can't be
/// removed yet.
fn stuck_name(install_dir: &Path) -> PathBuf {
    let (_, old) = siblings(install_dir);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut name = old.into_os_string();
    name.push(format!("-{}-{nanos}", std::process::id()));
    PathBuf::from(name)
}

/// Remove old folders an earlier run had to leave; one still in use stays.
fn remove_stuck(install_dir: &Path) {
    let (_, old) = siblings(install_dir);
    let (Some(parent), Some(prefix)) = (old.parent(), old.file_name()) else {
        return;
    };
    let mut prefix = prefix.to_os_string();
    prefix.push("-");
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// How long a rename or removal is retried.
const RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(5);

/// Run `operation` until it succeeds or [`RETRY_FOR`] has passed.
pub(crate) fn retrying(mut operation: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + RETRY_FOR;
    loop {
        match operation() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(error),
            Err(error) if std::time::Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(250)),
        }
    }
}

/// An install swapped in but not committed yet: later steps run against
/// the new folder, then it commits or rolls back.
#[derive(Debug)]
pub struct Pending {
    install_dir: PathBuf,
    /// The previous install, set aside; `None` for a fresh install.
    old: Option<PathBuf>,
    /// The shortcuts the previous record listed (or adoption found).
    old_shortcuts: Vec<PathBuf>,
    /// Shortcuts this install made.
    made_shortcuts: Vec<PathBuf>,
    /// The registry values the previous record listed.
    old_values: Vec<RecordedValue>,
    /// Registry values this install wrote.
    written_values: Vec<RecordedValue>,
    record: InstallRecord,
}

impl Pending {
    #[must_use]
    pub fn install_dir(&self) -> &Path {
        &self.install_dir
    }

    #[must_use]
    pub fn record(&self) -> &InstallRecord {
        &self.record
    }

    /// Record a shortcut this install made, so the commit keeps it.
    pub fn made_shortcut(&mut self, path: PathBuf) {
        self.made_shortcuts.push(path);
    }

    /// Whether the previous install had a shortcut at `path`.
    #[must_use]
    pub fn had_shortcut(&self, path: &Path) -> bool {
        self.old_shortcuts.iter().any(|old| old == path)
    }

    /// Record a registry value this install wrote, so the commit keeps it.
    pub fn wrote_value(&mut self, value: RecordedValue) {
        self.written_values.push(value);
    }

    /// Finish: remove the old shortcuts this install didn't make again,
    /// record what is installed now, and remove the old folder. Returns
    /// where the old folder is if it couldn't be removed (a program still
    /// runs from it); a later run removes it.
    pub fn commit(mut self, registry: &dyn Registry) -> Result<Option<PathBuf>, InstallError> {
        for value in &self.old_values {
            if !self.written_values.contains(value) {
                registry
                    .delete_value(&value.key, &value.name)
                    .map_err(io("remove a registry value under", Path::new(&value.key)))?;
            }
        }
        self.record.registry.clone_from(&self.written_values);
        let made: HashSet<_> = self.made_shortcuts.iter().collect();
        for shortcut in &self.old_shortcuts {
            if made.contains(shortcut) {
                continue;
            }
            match std::fs::remove_file(shortcut) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io("remove", shortcut)(error)),
            }
        }
        self.record.shortcuts.clone_from(&self.made_shortcuts);
        self.record
            .write(&self.install_dir)
            .map_err(io("write the install record in", &self.install_dir))?;
        let Some(old) = self.old else {
            return Ok(None);
        };
        if retrying(|| std::fs::remove_dir_all(&old)).is_ok() {
            return Ok(None);
        }
        let stuck = stuck_name(&self.install_dir);
        Ok(Some(if std::fs::rename(&old, &stuck).is_ok() {
            stuck
        } else {
            old
        }))
    }

    /// Undo the swap: the previous install comes back as it was. Shortcuts
    /// and registry values this install added go; the previous ones were
    /// never removed (a shortcut made again at the same path stays, and
    /// points at the same install folder).
    pub fn rollback(self, registry: &dyn Registry) -> Result<(), InstallError> {
        for shortcut in &self.made_shortcuts {
            if !self.old_shortcuts.contains(shortcut) {
                let _ = std::fs::remove_file(shortcut);
            }
        }
        for value in &self.written_values {
            if !self.old_values.contains(value) {
                let _ = registry.delete_value(&value.key, &value.name);
            }
        }
        retrying(|| std::fs::remove_dir_all(&self.install_dir))
            .map_err(io("remove", &self.install_dir))?;
        if let Some(old) = &self.old {
            retrying(|| std::fs::rename(old, &self.install_dir)).map_err(io("restore", old))?;
        }
        Ok(())
    }
}

/// Stage `release` and swap it into `options.install_dir`.
pub fn install_files(release: &Release, options: &Options) -> Result<Pending, InstallError> {
    install_files_with(release, options, &|from, to| {
        retrying(|| std::fs::rename(from, to))
    })
}

fn install_files_with(
    release: &Release,
    options: &Options,
    rename: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<Pending, InstallError> {
    let install_dir = &options.install_dir;
    recover(install_dir)?;
    let existing = Existing::detect(install_dir).map_err(|source| InstallError::Record {
        path: InstallRecord::path(install_dir),
        source,
    })?;
    let (old_shortcuts, carried) = match &existing {
        Existing::Fresh => (Vec::new(), None),
        // A recorded path that isn't a shortcut in the shortcut folders is
        // neither removed nor kept in the record.
        Existing::Recorded(record) => (
            record
                .shortcuts
                .iter()
                .filter(|path| in_shortcut_folders(path, &options.shortcut_dirs))
                .cloned()
                .collect(),
            Some(&**record),
        ),
        Existing::HandMade if !options.adopt => {
            return Err(InstallError::NeedsAdoption(install_dir.clone()));
        }
        Existing::HandMade => (
            find_shortcuts(&install_dir.join(DESKTOP_EXE), &options.shortcut_dirs),
            None,
        ),
    };

    let (staging, old) = siblings(install_dir);
    let staged = stage(release, options, carried, &staging);
    let record = match staged {
        Ok(setup_version) => InstallRecord {
            format: RECORD_FORMAT,
            version: release.manifest.version.clone(),
            setup_version,
            files: release
                .files
                .iter()
                .map(|file| RecordedFile {
                    path: file.path.clone(),
                    sha256: file.sha256.clone(),
                })
                .collect(),
            // Still on disk until the commit, so still recorded: a crash
            // before it leaves them for the next run to remove.
            shortcuts: old_shortcuts.clone(),
            registry: carried
                .map(|record| record.registry.clone())
                .unwrap_or_default(),
            distros: carried
                .map(|record| record.distros.clone())
                .unwrap_or_default(),
            stop: release.manifest.stop.clone(),
            uninstall: release.manifest.uninstall.clone(),
        },
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) = record.write(&staging) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(io("write the install record in", &staging)(error));
    }

    let set_aside = if install_dir.exists() {
        if let Err(source) = rename(install_dir, &old) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(InstallError::Swap {
                path: install_dir.clone(),
                source,
            });
        }
        Some(old)
    } else {
        if let Some(parent) = install_dir.parent() {
            std::fs::create_dir_all(parent).map_err(io("create", parent))?;
        }
        None
    };
    if let Err(source) = rename(&staging, install_dir) {
        if let Some(old) = &set_aside {
            let _ = retrying(|| std::fs::rename(old, install_dir));
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(InstallError::Swap {
            path: install_dir.clone(),
            source,
        });
    }
    Ok(Pending {
        install_dir: install_dir.clone(),
        old: set_aside,
        old_shortcuts,
        made_shortcuts: Vec::new(),
        old_values: record.registry.clone(),
        written_values: Vec::new(),
        record,
    })
}

/// Copy the release and the installer into `staging`; returns the version
/// of the installer copy staged.
fn stage(
    release: &Release,
    options: &Options,
    installed: Option<&InstallRecord>,
    staging: &Path,
) -> Result<String, InstallError> {
    std::fs::create_dir_all(staging).map_err(io("create", staging))?;
    for file in &release.files {
        let target = staged_path(staging, &file.path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(io("create", parent))?;
        }
        let copied = copy_hashing(&file.source, &target).map_err(io("copy", &file.source))?;
        if copied != file.sha256 {
            return Err(InstallError::Changed(file.path.clone()));
        }
    }

    // The newer installer serves later updates and uninstall.
    let installed_copy = options.install_dir.join(SETUP_EXE);
    let (setup, setup_version) = match installed {
        Some(record)
            if installed_copy.is_file()
                && !is_newer(&options.setup_version, &record.setup_version) =>
        {
            (installed_copy, record.setup_version.clone())
        }
        _ => (options.setup_exe.clone(), options.setup_version.clone()),
    };
    let target = staging.join(SETUP_EXE);
    copy_hashing(&setup, &target).map_err(io("copy", &setup))?;

    // The staged copies, read back.
    for file in &release.files {
        let target = staged_path(staging, &file.path);
        let (sha256, _) = File::open(&target)
            .and_then(sha256_hex)
            .map_err(io("read", &target))?;
        if sha256 != file.sha256 {
            return Err(InstallError::Changed(file.path.clone()));
        }
    }
    Ok(setup_version)
}

fn staged_path(staging: &Path, path: &str) -> PathBuf {
    path.split('/')
        .fold(staging.to_owned(), |path, part| path.join(part))
}

/// Copy `from` to `to`, hashing what was read; returns the hash.
fn copy_hashing(from: &Path, to: &Path) -> std::io::Result<String> {
    let mut source = File::open(from)?;
    let mut target = File::create(to)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        target.write_all(&buffer[..read])?;
    }
    target.sync_all()?;
    Ok(to_hex(&hasher.finalize()))
}

/// Whether `path` may be removed as one of the installer's shortcuts: a
/// `.lnk` file below one of `dirs`, reached without `..`, compared without
/// regard to case as Windows does. The record listing the shortcuts sits
/// in the user's folder, so its paths are checked before any is deleted.
#[must_use]
pub fn in_shortcut_folders(path: &Path, dirs: &[PathBuf]) -> bool {
    use std::path::Component;
    let parts = |path: &Path| -> Option<Vec<String>> {
        path.components()
            .map(|component| match component {
                Component::ParentDir | Component::CurDir => None,
                other => Some(other.as_os_str().to_string_lossy().to_lowercase()),
            })
            .collect()
    };
    let link = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"));
    let Some(path) = parts(path).filter(|_| link) else {
        return false;
    };
    dirs.iter()
        .filter_map(|dir| parts(dir))
        .any(|dir| path.len() > dir.len() && path[..dir.len()] == dir[..])
}

/// The shortcuts (`.lnk`) under `dirs` that point at `target`. A shortcut
/// stores its target's path as text (UTF-16, and as ANSI when it fits), so
/// a shortcut whose bytes hold the path, compared without regard to
/// ASCII case, is taken as one to it.
#[must_use]
pub fn find_shortcuts(target: &Path, dirs: &[PathBuf]) -> Vec<PathBuf> {
    let target = target.to_string_lossy().to_lowercase();
    let mut found = Vec::new();
    let mut pending: Vec<(PathBuf, usize)> = dirs.iter().map(|dir| (dir.clone(), 0)).collect();
    while let Some((dir, depth)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() && depth < SHORTCUT_DEPTH {
                pending.push((path, depth + 1));
            } else if kind.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("lnk"))
                && std::fs::read(&path).is_ok_and(|bytes| holds_path(&bytes, &target))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Whether `bytes` hold `path` (already lowercase) as UTF-16LE at either
/// alignment, or as ASCII when it is ASCII.
pub(crate) fn holds_path(bytes: &[u8], path: &str) -> bool {
    let wide: Vec<u16> = path.encode_utf16().collect();
    let lower = |unit: u16| match u8::try_from(unit) {
        Ok(byte) => u16::from(byte.to_ascii_lowercase()),
        Err(_) => unit,
    };
    let utf16 = (0..2).any(|offset| {
        let units: Vec<u16> = bytes[offset.min(bytes.len())..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| lower(u16::from_le_bytes(*pair)))
            .collect();
        !wide.is_empty() && units.windows(wide.len()).any(|window| window == wide)
    });
    utf16
        || (path.is_ascii()
            && !path.is_empty()
            && bytes
                .windows(path.len())
                .any(|window| window.eq_ignore_ascii_case(path.as_bytes())))
}

#[cfg(test)]
mod tests;
