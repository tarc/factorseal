//! `install.json`: what the installer did, in the install folder. Updates
//! and uninstall undo from this record, never from a new manifest, which
//! may be newer or gone.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::manifest::{RECORD_FILE, Stop, Uninstall};

/// The record format this installer writes and reads.
pub const RECORD_FORMAT: u32 = 1;

/// The executable whose presence marks a hand-made install (one extracted
/// from the ZIP, with no record).
pub const DESKTOP_EXE: &str = "factorseal-desktop.exe";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRecord {
    pub format: u32,
    /// The installed release's version.
    pub version: String,
    /// The version of the installer copy in the install folder.
    pub setup_version: String,
    pub files: Vec<RecordedFile>,
    /// Shortcuts the installer made or adopted, removed by the next
    /// update unless it makes them again, and by uninstall.
    #[serde(default)]
    pub shortcuts: Vec<PathBuf>,
    /// Registry values the installer wrote.
    #[serde(default)]
    pub registry: Vec<RecordedValue>,
    /// WSL distros the installer set up.
    #[serde(default)]
    pub distros: Vec<String>,
    /// How the installed version is stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Stop>,
    /// What uninstalling the installed version removes.
    #[serde(default)]
    pub uninstall: Uninstall,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedValue {
    pub key: String,
    pub name: String,
}

/// What is in the install folder before an install.
#[derive(Debug, PartialEq, Eq)]
pub enum Existing {
    /// Nothing, or a folder without FactorSeal in it.
    Fresh,
    /// An install this installer made.
    Recorded(Box<InstallRecord>),
    /// FactorSeal extracted by hand: Desktop without a record.
    HandMade,
}

impl InstallRecord {
    #[must_use]
    pub fn path(install_dir: &Path) -> PathBuf {
        install_dir.join(RECORD_FILE)
    }

    /// Write the record into `install_dir`, replacing any, through a
    /// temporary file so a crash leaves the old or the new one.
    pub fn write(&self, install_dir: &Path) -> std::io::Result<()> {
        let text = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let temporary = install_dir.join(format!("{RECORD_FILE}.new"));
        std::fs::write(&temporary, text)?;
        std::fs::rename(&temporary, Self::path(install_dir))
    }

    /// Add `distros` to the record in `install_dir`: the `wsl` step runs
    /// after the install committed its record. Names already there (in any
    /// case, as WSL compares them) are not repeated.
    pub fn add_distros(install_dir: &Path, distros: &[String]) -> std::io::Result<()> {
        let mut record = Self::read(&Self::path(install_dir))?;
        for distro in distros {
            if !record
                .distros
                .iter()
                .any(|known| known.eq_ignore_ascii_case(distro))
            {
                record.distros.push(distro.clone());
            }
        }
        record.write(install_dir)
    }

    fn read(path: &Path) -> std::io::Result<Self> {
        let record: Self = serde_json::from_slice(&std::fs::read(path)?)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if record.format != RECORD_FORMAT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "install record format {} (this installer reads {RECORD_FORMAT})",
                    record.format
                ),
            ));
        }
        Ok(record)
    }
}

impl Existing {
    /// Look at `install_dir`. A record that can't be read is an error, not
    /// a fresh install: undo depends on it.
    pub fn detect(install_dir: &Path) -> std::io::Result<Self> {
        let record = InstallRecord::path(install_dir);
        if record.exists() {
            return InstallRecord::read(&record).map(|record| Self::Recorded(Box::new(record)));
        }
        if install_dir.join(DESKTOP_EXE).is_file() {
            return Ok(Self::HandMade);
        }
        Ok(Self::Fresh)
    }
}

/// Whether installer version `candidate` is newer than `installed`, both
/// as dotted numbers (`0.1.0`). An unreadable installed version counts as
/// older, so a working copy replaces it.
#[must_use]
pub fn is_newer(candidate: &str, installed: &str) -> bool {
    let parse = |version: &str| {
        version
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
    };
    match (parse(candidate), parse(installed)) {
        (Some(candidate), Some(installed)) => candidate > installed,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> InstallRecord {
        InstallRecord {
            format: RECORD_FORMAT,
            version: "0.1.0".to_owned(),
            setup_version: "0.1.0".to_owned(),
            files: vec![RecordedFile {
                path: "factorseal.exe".to_owned(),
                sha256: "0".repeat(64),
            }],
            shortcuts: vec![PathBuf::from("/start/FactorSeal Desktop.lnk")],
            registry: Vec::new(),
            distros: vec!["NixOS".to_owned()],
            stop: None,
            uninstall: Uninstall::default(),
        }
    }

    #[test]
    fn the_record_round_trips_and_marks_the_install() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Existing::detect(dir.path()).unwrap(), Existing::Fresh);
        std::fs::write(dir.path().join(DESKTOP_EXE), b"exe").unwrap();
        assert_eq!(Existing::detect(dir.path()).unwrap(), Existing::HandMade);
        record().write(dir.path()).unwrap();
        assert_eq!(
            Existing::detect(dir.path()).unwrap(),
            Existing::Recorded(Box::new(record()))
        );
        assert!(!dir.path().join("install.json.new").exists());
    }

    #[test]
    fn an_unreadable_record_is_an_error_not_a_fresh_install() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(InstallRecord::path(dir.path()), b"{").unwrap();
        assert!(Existing::detect(dir.path()).is_err());
        let mut newer = record();
        newer.format = RECORD_FORMAT + 1;
        newer.write(dir.path()).unwrap();
        let error = Existing::detect(dir.path()).unwrap_err().to_string();
        assert!(error.contains("format 2"), "{error}");
    }

    #[test]
    fn distros_set_up_are_added_once_and_the_rest_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        record().write(dir.path()).unwrap();
        InstallRecord::add_distros(dir.path(), &["nixos".to_owned(), "Ubuntu".to_owned()]).unwrap();
        let Existing::Recorded(updated) = Existing::detect(dir.path()).unwrap() else {
            panic!("the record is gone");
        };
        assert_eq!(updated.distros, ["NixOS", "Ubuntu"]);
        assert_eq!(
            InstallRecord {
                distros: record().distros,
                ..*updated
            },
            record()
        );
    }

    #[test]
    fn installer_versions_compare_as_numbers() {
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(is_newer("0.1.0", "garbage"));
        assert!(!is_newer("garbage", "0.1.0"));
    }
}
