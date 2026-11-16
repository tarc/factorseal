use std::collections::BTreeMap;

use super::*;
use crate::manifest::Uninstall;
use crate::record::{RECORD_FORMAT, RecordedFile, RecordedValue};
use crate::registry::MemoryRegistry;
use crate::wsl::{Line, Output};

const MOZILLA: &str = r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser";
const EDGE: &str = r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\dev.factorseal.browser";
const OTHER: &str = r"HKCU\Software\Other";
const NOTE: &str = "The vault stays in %LOCALAPPDATA%\\Factorseal.";

/// A WSL that answers every line alike, recording the calls.
struct FakeWsl {
    answer: Result<Output, String>,
    calls: Vec<(String, Line)>,
}

impl FakeWsl {
    fn answering(success: bool) -> Self {
        Self {
            answer: Ok(Output {
                success,
                stdout: if success { "Removed wsl.json\n" } else { "" }.to_owned(),
                stderr: if success { "" } else { "permission denied\n" }.to_owned(),
            }),
            calls: Vec::new(),
        }
    }
}

impl Wsl for FakeWsl {
    fn run(&mut self, distro: &str, line: Line, _: &[String]) -> Result<Output, String> {
        self.calls.push((distro.to_owned(), line));
        self.answer.clone()
    }
}

/// An install as the installer leaves it, with its shortcuts, registry
/// values, a settings folder and a vault.
struct World {
    root: tempfile::TempDir,
    registry: MemoryRegistry,
}

impl World {
    fn new() -> Self {
        let world = Self {
            root: tempfile::tempdir().unwrap(),
            registry: MemoryRegistry::default(),
        };
        for (path, contents) in [
            ("Programs/FactorSeal/factorseal-desktop.exe", "desktop"),
            (
                "Programs/FactorSeal/helpers/factorseal-parser.exe",
                "parser",
            ),
            ("Programs/FactorSeal/factorseal-setup.exe", "setup"),
            ("start/FactorSeal Desktop.lnk", "link"),
            ("start/Startup/FactorSeal Desktop.lnk", "link"),
            ("Roaming/Factorseal/settings/settings.json", "{}"),
            ("Local/Factorseal/Factorseal/data/vault.bin", "vault"),
        ] {
            let path = world.path(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        world.record().write(&world.install_dir()).unwrap();
        for (key, name) in [
            (MOZILLA, ""),
            (EDGE, ""),
            (UNINSTALL_KEY, "DisplayName"),
            (OTHER, "Kept"),
        ] {
            world.registry.set_string(key, name, "value").unwrap();
        }
        world
    }

    fn path(&self, relative: &str) -> PathBuf {
        installed(self.root.path(), relative)
    }

    fn install_dir(&self) -> PathBuf {
        self.path("Programs/FactorSeal")
    }

    fn record(&self) -> InstallRecord {
        InstallRecord {
            format: RECORD_FORMAT,
            version: "1.0.0".to_owned(),
            setup_version: "0.1.0".to_owned(),
            files: ["factorseal-desktop.exe", "helpers/factorseal-parser.exe"]
                .map(|path| RecordedFile {
                    path: path.to_owned(),
                    sha256: "0".repeat(64),
                })
                .to_vec(),
            shortcuts: vec![
                self.path("start/FactorSeal Desktop.lnk"),
                self.path("start/Startup/FactorSeal Desktop.lnk"),
            ],
            registry: vec![RecordedValue {
                key: MOZILLA.to_owned(),
                name: String::new(),
            }],
            distros: vec!["NixOS".to_owned()],
            stop: None,
            uninstall: Uninstall {
                registry_cleanup: vec![EDGE.to_owned()],
                ask_to_delete: vec![r"%APPDATA%\Factorseal\settings".to_owned()],
                keep_note: Some(NOTE.to_owned()),
            },
        }
    }

    fn folders(&self) -> Folders {
        Folders {
            appdata: self.path("Roaming"),
            local_appdata: self.path("Local"),
        }
    }

    fn uninstall(
        &self,
        record: &InstallRecord,
        choices: &Choices,
        wsl: &mut FakeWsl,
    ) -> (Result<Report, UninstallError>, Vec<String>) {
        let shortcut_dirs = [self.path("start"), self.path("desktop")];
        let folders = self.folders();
        let mut said = Vec::new();
        let result = uninstall(
            &self.install_dir(),
            record,
            choices,
            &mut System {
                registry: &self.registry,
                wsl,
                shortcut_dirs: &shortcut_dirs,
                folders: &folders,
            },
            &mut |line: &str| said.push(line.to_owned()),
        );
        (result, said)
    }

    /// The values left, keys in lowercase as the memory registry keeps them.
    fn keys(&self) -> BTreeMap<(String, String), String> {
        self.registry.snapshot()
    }
}

fn everything() -> Choices {
    Choices {
        distros: vec!["nixos".to_owned()],
        delete_listed: true,
    }
}

#[test]
fn everything_recorded_is_removed_and_the_vault_stays() {
    let world = World::new();
    let mut wsl = FakeWsl::answering(true);
    let (result, said) = world.uninstall(&world.record(), &everything(), &mut wsl);
    assert_eq!(result.unwrap(), Report::default());

    assert!(!world.install_dir().exists());
    assert!(!world.path("start/FactorSeal Desktop.lnk").exists());
    assert!(!world.path("start/Startup/FactorSeal Desktop.lnk").exists());
    assert!(!world.path("Roaming/Factorseal/settings").exists());
    assert!(
        world
            .path("Local/Factorseal/Factorseal/data/vault.bin")
            .exists()
    );
    assert_eq!(
        world.keys().into_keys().collect::<Vec<_>>(),
        [(OTHER.to_ascii_lowercase(), "Kept".to_owned())]
    );
    assert_eq!(wsl.calls, [("NixOS".to_owned(), Line::Remove)]);
    assert!(
        said.contains(&"NixOS: Removed wsl.json".to_owned()),
        "{said:?}"
    );
    assert_eq!(said.last().map(String::as_str), Some(NOTE));
}

#[test]
fn listed_folders_stay_without_consent_and_unchosen_distros_keep_their_setup() {
    let world = World::new();
    let mut wsl = FakeWsl::answering(true);
    let (result, said) = world.uninstall(&world.record(), &Choices::default(), &mut wsl);
    assert_eq!(result.unwrap(), Report::default());
    assert!(!world.install_dir().exists());
    assert!(
        world
            .path("Roaming/Factorseal/settings/settings.json")
            .exists()
    );
    assert_eq!(wsl.calls, Vec::new());
    let said = said.join("\n");
    assert!(
        said.contains("WSL distro NixOS keeps FactorSeal's setup"),
        "{said}"
    );
    assert!(said.contains("deletes it only when asked"), "{said}");
}

#[test]
fn record_entries_outside_the_rules_are_left_alone() {
    let world = World::new();
    for file in [
        "precious.lnk",
        "start/notes.txt",
        "precious.txt",
        "Roaming/Other/x",
    ] {
        let path = world.path(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "keep").unwrap();
    }
    std::fs::write(world.install_dir().join("my notes.txt"), "mine").unwrap();
    let mut record = world.record();
    record.files.push(RecordedFile {
        path: "../../precious.txt".to_owned(),
        sha256: "0".repeat(64),
    });
    record.shortcuts = vec![world.path("precious.lnk"), world.path("start/notes.txt")];
    record.registry.push(RecordedValue {
        key: OTHER.to_owned(),
        name: "Kept".to_owned(),
    });
    record.uninstall = Uninstall {
        registry_cleanup: vec![OTHER.to_owned()],
        ask_to_delete: vec![
            r"%LOCALAPPDATA%\Factorseal\Factorseal\data".to_owned(),
            r"%LOCALAPPDATA%\Factorseal".to_owned(),
            r"%APPDATA%\Other".to_owned(),
        ],
        keep_note: Some("x".repeat(501)),
    };

    let (result, said) = world.uninstall(&record, &everything(), &mut FakeWsl::answering(true));
    assert_eq!(result.unwrap(), Report::default());
    for kept in [
        "precious.lnk",
        "start/notes.txt",
        "precious.txt",
        "Roaming/Other/x",
        "Local/Factorseal/Factorseal/data/vault.bin",
        "Programs/FactorSeal/my notes.txt",
    ] {
        assert!(world.path(kept).exists(), "{kept} was removed");
    }
    assert!(
        !world
            .path("Programs/FactorSeal/factorseal-desktop.exe")
            .exists()
    );
    assert!(
        world
            .keys()
            .contains_key(&(OTHER.to_ascii_lowercase(), "Kept".to_owned()))
    );
    let said = said.join("\n");
    for named in [
        "precious.txt\": not a file inside the install folder",
        "precious.lnk: not a shortcut",
        "notes.txt: not a shortcut",
        r"Other\Kept: outside the keys",
        r"left HKCU\Software\Other: outside the keys",
        r"left %LOCALAPPDATA%\Factorseal\Factorseal\data: outside",
        r"left %LOCALAPPDATA%\Factorseal: outside",
        r"left %APPDATA%\Other: outside",
        "it holds what the installer didn't put there (my notes.txt)",
    ] {
        assert!(said.contains(named), "{named:?} not in:\n{said}");
    }
    assert!(!said.contains(&"x".repeat(501)), "the long note was shown");
}

#[test]
fn a_failed_wsl_removal_is_reported_with_the_command_to_run_and_the_rest_goes_on() {
    let world = World::new();
    let (result, _) = world.uninstall(
        &world.record(),
        &everything(),
        &mut FakeWsl::answering(false),
    );
    let report = result.unwrap();
    assert_eq!(report.problems, Vec::<String>::new());
    assert_eq!(
        report.wsl_problems,
        [
            "removing FactorSeal's setup from WSL distro NixOS failed: permission denied; run \
          `factorseal wsl-setup --remove` in it"
        ]
    );
    assert!(!world.install_dir().exists());
}

/// A release file that can't be removed stops the uninstall before the
/// shortcuts, the registry and the record change, so running it again
/// finishes the job.
#[test]
fn a_file_that_cant_be_removed_stops_the_uninstall_before_anything_else() {
    let world = World::new();
    let locked = world.install_dir().join("factorseal-desktop.exe");
    #[cfg(unix)]
    let _hold = {
        use std::os::unix::fs::PermissionsExt as _;
        // A folder without write permission keeps its entries.
        let mode = |mode| std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(world.install_dir(), mode(0o555)).unwrap();
        Restore(world.install_dir(), mode(0o755))
    };
    #[cfg(windows)]
    let _hold = {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Open without sharing delete access.
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)
            .unwrap()
    };
    let keys = world.keys();
    let (result, _) = world.uninstall(
        &world.record(),
        &everything(),
        &mut FakeWsl::answering(true),
    );
    let error = result.unwrap_err();
    assert_eq!(error.path, locked);
    assert!(
        error.to_string().contains("running the uninstall again"),
        "{error}"
    );
    assert!(InstallRecord::path(&world.install_dir()).exists());
    assert!(world.path("start/FactorSeal Desktop.lnk").exists());
    assert!(world.path("Roaming/Factorseal/settings").exists());
    assert_eq!(world.keys(), keys);
}

/// Gives a folder its permissions back when dropped, so the temporary
/// folder can be removed.
#[cfg(unix)]
struct Restore(PathBuf, std::fs::Permissions);

#[cfg(unix)]
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, self.1.clone());
    }
}

#[test]
fn folder_variables_expand_to_the_users_folders() {
    let folders = Folders {
        appdata: PathBuf::from("/roaming"),
        local_appdata: PathBuf::from("/local"),
    };
    assert_eq!(
        expand(r"%AppData%\Factorseal\settings", &folders),
        Some(PathBuf::from("/roaming/Factorseal/settings"))
    );
    assert_eq!(
        expand(r"%LOCALAPPDATA%\Factorseal\cache", &folders),
        Some(PathBuf::from("/local/Factorseal/cache"))
    );
    assert_eq!(expand(r"C:\Factorseal", &folders), None);
}
