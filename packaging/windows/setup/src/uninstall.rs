//! Uninstall (Flows, "Uninstall", of `docs/plans/windows-installer.md`):
//! everything `install.json` recorded is undone, after the installed
//! version was stopped the way it recorded.
//!
//! The record sits in the user's folder, so each entry is checked as the
//! manifest's were before anything is deleted: release paths stay inside
//! the install folder, shortcuts are `.lnk` files in the shortcut folders,
//! registry keys lie under the allowed prefixes, and `ask_to_delete`
//! folders lie in FactorSeal's own folders and never reach the vault. An
//! entry outside those rules is left alone and named.
//!
//! The release's files go first: when one can't be removed, nothing else
//! has changed (apart from the WSL removals, which repeat harmlessly), the
//! record and the Installed apps entry stay, and running the uninstall
//! again finishes it. The folder itself goes only when nothing the
//! installer didn't put there is left in it. **The vault is always kept.**

use std::path::{Path, PathBuf};

use crate::engine::{in_shortcut_folders, retrying};
use crate::manifest::{
    SETUP_EXE, UNINSTALL_KEY, check_deletable, check_registry_key, check_release_path, check_text,
};
use crate::record::InstallRecord;
use crate::registry::Registry;
use crate::wsl::{self, Wsl};

/// Where `%APPDATA%` and `%LOCALAPPDATA%` are.
#[derive(Clone, Debug)]
pub struct Folders {
    pub appdata: PathBuf,
    pub local_appdata: PathBuf,
}

/// What the user chose.
#[derive(Clone, Debug, Default)]
pub struct Choices {
    /// The recorded distros to remove FactorSeal's setup from; the others
    /// keep it.
    pub distros: Vec<String>,
    /// Delete the record's `ask_to_delete` folders.
    pub delete_listed: bool,
}

/// The system the uninstall changes.
pub struct System<'a> {
    pub registry: &'a dyn Registry,
    pub wsl: &'a mut dyn Wsl,
    /// The folders shortcuts may be removed from.
    pub shortcut_dirs: &'a [PathBuf],
    pub folders: &'a Folders,
}

/// What an uninstall that went through left undone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Distros whose setup couldn't be removed.
    pub wsl_problems: Vec<String>,
    /// Anything else that couldn't be removed.
    pub problems: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "cannot remove {}: {source}; FactorSeal is still installed and recorded, so running the \
     uninstall again finishes it",
    path.display()
)]
pub struct UninstallError {
    pub path: PathBuf,
    pub source: std::io::Error,
}

/// Undo what `record` says the installer did in `install_dir`. The
/// installed version must have been stopped.
pub fn uninstall(
    install_dir: &Path,
    record: &InstallRecord,
    choices: &Choices,
    system: &mut System<'_>,
    say: &mut dyn FnMut(&str),
) -> Result<Report, UninstallError> {
    let mut report = Report::default();

    let (chosen, kept): (Vec<String>, Vec<String>) =
        record.distros.iter().cloned().partition(|distro| {
            choices
                .distros
                .iter()
                .any(|choice| choice.eq_ignore_ascii_case(distro))
        });
    report.wsl_problems = wsl::remove(&chosen, system.wsl, say);
    for distro in &kept {
        say(&format!(
            "WSL distro {distro} keeps FactorSeal's setup; run `factorseal wsl-setup --remove` in \
             it to undo it"
        ));
    }

    for file in &record.files {
        if check_release_path(&file.path).is_err() {
            say(&format!(
                "left {:?}: not a file inside the install folder",
                file.path
            ));
            continue;
        }
        remove(&installed(install_dir, &file.path))
            .map_err(|(path, source)| UninstallError { path, source })?;
    }

    for shortcut in &record.shortcuts {
        if !in_shortcut_folders(shortcut, system.shortcut_dirs) {
            say(&format!(
                "left {}: not a shortcut in the Start menu or on the desktop",
                shortcut.display()
            ));
            continue;
        }
        if let Err((path, error)) = remove(shortcut) {
            report
                .problems
                .push(format!("cannot remove {}: {error}", path.display()));
        }
    }

    remove_registry(record, system.registry, &mut report, say);

    for path in [
        install_dir.join(SETUP_EXE),
        InstallRecord::path(install_dir),
    ] {
        if let Err((path, error)) = remove(&path) {
            report
                .problems
                .push(format!("cannot remove {}: {error}", path.display()));
        }
    }
    remove_folders(install_dir, record, &mut report, say);

    delete_listed(record, choices, system.folders, &mut report, say);

    if let Some(note) = &record.uninstall.keep_note
        && check_text("keep_note", note, 500).is_ok()
    {
        say(note);
    }
    Ok(report)
}

/// The recorded registry values, the `registry_cleanup` keys and the
/// Installed apps entry.
fn remove_registry(
    record: &InstallRecord,
    registry: &dyn Registry,
    report: &mut Report,
    say: &mut dyn FnMut(&str),
) {
    for value in &record.registry {
        if check_registry_key(&value.key).is_err() {
            say(&format!(
                "left {}\\{}: outside the keys the installer may change",
                value.key, value.name
            ));
            continue;
        }
        if let Err(error) = registry.delete_value(&value.key, &value.name) {
            report.problems.push(format!(
                "cannot remove {}\\{}: {error}",
                value.key, value.name
            ));
        }
    }
    let cleanup = record.uninstall.registry_cleanup.iter().map(String::as_str);
    for key in cleanup.chain([UNINSTALL_KEY]) {
        if check_registry_key(key).is_err() {
            say(&format!(
                "left {key}: outside the keys the installer may change"
            ));
            continue;
        }
        if let Err(error) = registry.delete_key(key) {
            report
                .problems
                .push(format!("cannot remove {key}: {error}"));
        }
    }
}

/// The record's `ask_to_delete` folders, deleted only when the user chose
/// to.
fn delete_listed(
    record: &InstallRecord,
    choices: &Choices,
    folders: &Folders,
    report: &mut Report,
    say: &mut dyn FnMut(&str),
) {
    for listed in &record.uninstall.ask_to_delete {
        let Some(target) = check_deletable(listed)
            .ok()
            .and_then(|()| expand(listed, folders))
        else {
            say(&format!("left {listed}: outside FactorSeal's own folders"));
            continue;
        };
        if !target.exists() {
            continue;
        }
        if !choices.delete_listed {
            say(&format!(
                "kept {}; the uninstall deletes it only when asked to",
                target.display()
            ));
            continue;
        }
        let removed = if target.is_dir() {
            retrying(|| std::fs::remove_dir_all(&target))
        } else {
            retrying(|| std::fs::remove_file(&target))
        };
        match removed {
            Ok(()) => say(&format!("deleted {}", target.display())),
            Err(error) => report
                .problems
                .push(format!("cannot delete {}: {error}", target.display())),
        }
    }
}

/// The record's `ask_to_delete` folders that pass the rules and exist,
/// expanded: what the uninstall would delete when asked to.
#[must_use]
pub fn listed_folders(record: &InstallRecord, folders: &Folders) -> Vec<PathBuf> {
    record
        .uninstall
        .ask_to_delete
        .iter()
        .filter(|listed| check_deletable(listed).is_ok())
        .filter_map(|listed| expand(listed, folders))
        .filter(|path| path.exists())
        .collect()
}

/// Remove a file the installer made; one already gone is fine.
fn remove(path: &Path) -> Result<(), (PathBuf, std::io::Error)> {
    match retrying(|| std::fs::remove_file(path)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err((path.to_owned(), error)),
    }
}

/// The release's folders inside `install_dir`, deepest first, then the
/// install folder itself, each removed only when empty.
fn remove_folders(
    install_dir: &Path,
    record: &InstallRecord,
    report: &mut Report,
    say: &mut dyn FnMut(&str),
) {
    let mut folders: Vec<PathBuf> = record
        .files
        .iter()
        .filter(|file| check_release_path(&file.path).is_ok())
        .flat_map(|file| {
            let parts: Vec<&str> = file.path.split('/').collect();
            (1..parts.len())
                .map(|depth| installed(install_dir, &parts[..depth].join("/")))
                .collect::<Vec<_>>()
        })
        .collect();
    folders.sort_by_key(|folder| std::cmp::Reverse(folder.components().count()));
    folders.dedup();
    for folder in folders {
        let _ = std::fs::remove_dir(&folder);
    }
    let left: Vec<String> = match std::fs::read_dir(install_dir) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            report
                .problems
                .push(format!("cannot read {}: {error}", install_dir.display()));
            return;
        }
    };
    if left.is_empty() {
        if let Err(error) = retrying(|| std::fs::remove_dir(install_dir)) {
            report
                .problems
                .push(format!("cannot remove {}: {error}", install_dir.display()));
        }
    } else {
        say(&format!(
            "kept {}: it holds what the installer didn't put there ({})",
            install_dir.display(),
            left.join(", ")
        ));
    }
}

/// The installed copy of the release file `path`.
fn installed(install_dir: &Path, path: &str) -> PathBuf {
    path.split('/')
        .fold(install_dir.to_owned(), |path, part| path.join(part))
}

/// An `ask_to_delete` path (already checked) with its folder variable
/// replaced.
fn expand(path: &str, folders: &Folders) -> Option<PathBuf> {
    let mut parts = path.split('\\');
    let root = match parts.next()?.to_ascii_uppercase().as_str() {
        "%APPDATA%" => &folders.appdata,
        "%LOCALAPPDATA%" => &folders.local_appdata,
        _ => return None,
    };
    Some(parts.fold(root.clone(), |path, part| path.join(part)))
}

#[cfg(test)]
mod tests;
