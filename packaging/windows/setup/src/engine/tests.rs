use std::cell::Cell;

use serde_json::json;

use super::*;
use crate::manifest::MANIFEST_FILE;

const SETUP_V1: &[u8] = b"setup 0.1.0";
const SETUP_V2: &[u8] = b"setup 0.2.0";

/// A release folder in `root/<version>` with `files`, verified.
fn release(root: &Path, version: &str, files: &[(&str, &[u8])]) -> Release {
    let dir = root.join(version);
    let entries: Vec<_> = files
        .iter()
        .map(|(path, contents)| {
            let target = staged_path(&dir, path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(&target, contents).unwrap();
            json!({ "path": path, "sha256": sha256_hex(*contents).unwrap().0 })
        })
        .collect();
    let manifest = json!({
        "schema": 1,
        "product": "FactorSeal",
        "version": version,
        "requires_setup": 1,
        "files": entries,
        "stop": { "command": ["factorseal-desktop.exe", "--quit"] },
        "steps": [{ "install_files": {} }],
    });
    std::fs::write(dir.join(MANIFEST_FILE), manifest.to_string()).unwrap();
    Release::open(&dir.join(MANIFEST_FILE)).unwrap()
}

fn v1(root: &Path) -> Release {
    release(
        root,
        "1.0.0",
        &[
            ("factorseal-desktop.exe", b"desktop 1"),
            ("factorseal.exe", b"cli 1"),
            ("licenses/LICENSE.txt", b"license"),
        ],
    )
}

fn v2(root: &Path) -> Release {
    release(
        root,
        "2.0.0",
        &[
            ("factorseal-desktop.exe", b"desktop 2"),
            ("factorseal.exe", b"cli 2"),
            ("factorseal-wsl-broker.exe", b"broker 2"),
        ],
    )
}

struct World {
    root: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let world = Self {
            root: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(world.path("shortcuts/start")).unwrap();
        std::fs::create_dir_all(world.path("shortcuts/desktop")).unwrap();
        std::fs::write(world.path("setup-v1.exe"), SETUP_V1).unwrap();
        std::fs::write(world.path("setup-v2.exe"), SETUP_V2).unwrap();
        world
    }

    fn path(&self, relative: &str) -> PathBuf {
        staged_path(self.root.path(), relative)
    }

    fn install_dir(&self) -> PathBuf {
        self.path("Programs/FactorSeal")
    }

    fn options(&self, setup_version: &str) -> Options {
        let setup = if setup_version == "0.2.0" {
            "setup-v2.exe"
        } else {
            "setup-v1.exe"
        };
        Options {
            install_dir: self.install_dir(),
            setup_exe: self.path(setup),
            setup_version: setup_version.to_owned(),
            adopt: false,
            shortcut_dirs: vec![self.path("shortcuts/start"), self.path("shortcuts/desktop")],
        }
    }

    fn releases(&self) -> PathBuf {
        self.path("releases")
    }

    fn installed(&self, relative: &str) -> Option<Vec<u8>> {
        std::fs::read(staged_path(&self.install_dir(), relative)).ok()
    }

    fn record(&self) -> InstallRecord {
        match Existing::detect(&self.install_dir()).unwrap() {
            Existing::Recorded(record) => *record,
            other => panic!("no record: {other:?}"),
        }
    }

    /// Nothing beside the install folder but the install folder.
    fn assert_no_leftovers(&self) {
        let (staging, old) = siblings(&self.install_dir());
        assert!(!staging.exists(), "staging folder left");
        assert!(!old.exists(), "old folder left");
    }
}

#[test]
fn a_fresh_install_copies_the_release_the_installer_and_the_record() {
    let world = World::new();
    let release = v1(&world.releases());
    let pending = install_files(&release, &world.options("0.1.0")).unwrap();
    assert_eq!(pending.install_dir(), world.install_dir());
    assert_eq!(pending.commit().unwrap(), None);

    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    assert_eq!(world.installed("licenses/LICENSE.txt").unwrap(), b"license");
    assert_eq!(world.installed(SETUP_EXE).unwrap(), SETUP_V1);
    let record = world.record();
    assert_eq!(record.version, "1.0.0");
    assert_eq!(record.setup_version, "0.1.0");
    assert_eq!(record.files.len(), 3);
    assert_eq!(record.files[1].sha256, release.files[1].sha256);
    assert_eq!(record.stop, release.manifest.stop);
    world.assert_no_leftovers();
}

#[test]
fn an_update_replaces_the_files_and_drops_what_the_new_release_lacks() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let mut record = world.record();
    record.distros = vec!["NixOS".to_owned()];
    record.write(&world.install_dir()).unwrap();

    install_files(&v2(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 2");
    assert_eq!(
        world.installed("factorseal-wsl-broker.exe").unwrap(),
        b"broker 2"
    );
    assert_eq!(world.installed("licenses/LICENSE.txt"), None);
    let record = world.record();
    assert_eq!(record.version, "2.0.0");
    // What earlier steps did stays recorded until a step undoes it.
    assert_eq!(record.distros, ["NixOS"]);
    world.assert_no_leftovers();
}

#[test]
fn the_installed_installer_is_replaced_only_by_a_newer_one() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.2.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(world.installed(SETUP_EXE).unwrap(), SETUP_V2);
    // An older installer installs a release but keeps the newer copy.
    install_files(&v2(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(world.installed(SETUP_EXE).unwrap(), SETUP_V2);
    assert_eq!(world.record().setup_version, "0.2.0");
    // A newer one replaces it.
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    install_files(&v2(&world.releases()), &world.options("0.2.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(world.installed(SETUP_EXE).unwrap(), SETUP_V2);
    assert_eq!(world.record().setup_version, "0.2.0");
}

#[test]
fn a_file_changed_after_verification_aborts_and_leaves_the_install() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let release = v2(&world.releases());
    // Between Release::open and the copy.
    std::fs::write(&release.files[2].source, b"tampered broker").unwrap();
    match install_files(&release, &world.options("0.1.0")) {
        Err(InstallError::Changed(path)) => assert_eq!(path, "factorseal-wsl-broker.exe"),
        other => panic!("expected Changed, got {other:?}"),
    }
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    assert_eq!(world.record().version, "1.0.0");
    world.assert_no_leftovers();
}

#[test]
fn a_failed_swap_puts_the_old_install_back() {
    for failing_call in [1, 2] {
        let world = World::new();
        install_files(&v1(&world.releases()), &world.options("0.1.0"))
            .unwrap()
            .commit()
            .unwrap();
        let calls = Cell::new(0);
        let rename = |from: &Path, to: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == failing_call {
                Err(std::io::Error::other("injected"))
            } else {
                std::fs::rename(from, to)
            }
        };
        let error = install_files_with(&v2(&world.releases()), &world.options("0.1.0"), &rename)
            .unwrap_err();
        assert!(matches!(error, InstallError::Swap { .. }), "{error}");
        assert!(error.to_string().contains("quit FactorSeal"), "{error}");
        assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
        assert_eq!(world.record().version, "1.0.0");
        world.assert_no_leftovers();
    }
}

#[test]
fn a_rollback_restores_the_previous_install() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let pending = install_files(&v2(&world.releases()), &world.options("0.1.0")).unwrap();
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 2");
    pending.rollback().unwrap();
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    assert_eq!(world.record().version, "1.0.0");
    world.assert_no_leftovers();

    // A fresh install rolled back leaves nothing.
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .rollback()
        .unwrap();
    assert!(!world.install_dir().exists());
}

#[test]
fn an_interrupted_run_is_recovered() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let (staging, old) = siblings(&world.install_dir());
    // Stopped between the renames: the install folder is aside.
    std::fs::rename(world.install_dir(), &old).unwrap();
    std::fs::create_dir(&staging).unwrap();
    recover(&world.install_dir()).unwrap();
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    world.assert_no_leftovers();
    // Stopped before removing the old folder.
    std::fs::create_dir(&old).unwrap();
    recover(&world.install_dir()).unwrap();
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    world.assert_no_leftovers();
}

#[test]
fn an_update_whose_release_drops_a_shortcut_still_removes_the_old_one() {
    let world = World::new();
    let kept = world.path("shortcuts/start/FactorSeal Desktop.lnk");
    let dropped = world.path("shortcuts/desktop/FactorSeal Desktop.lnk");
    let mut pending = install_files(&v1(&world.releases()), &world.options("0.1.0")).unwrap();
    for shortcut in [&kept, &dropped] {
        std::fs::write(shortcut, b"lnk").unwrap();
        pending.made_shortcut(shortcut.clone());
    }
    pending.commit().unwrap();
    assert_eq!(world.record().shortcuts, [kept.clone(), dropped.clone()]);

    // The new release makes only one of them again.
    let mut pending = install_files(&v2(&world.releases()), &world.options("0.1.0")).unwrap();
    // Until the commit both are still there, and recorded.
    assert!(dropped.exists());
    assert_eq!(pending.record().shortcuts.len(), 2);
    pending.made_shortcut(kept.clone());
    pending.commit().unwrap();
    assert!(kept.exists());
    assert!(!dropped.exists());
    assert_eq!(world.record().shortcuts, std::slice::from_ref(&kept));

    // A rolled-back update touches no shortcut.
    let pending = install_files(&v1(&world.releases()), &world.options("0.1.0")).unwrap();
    pending.rollback().unwrap();
    assert!(kept.exists());
}

/// A shortcut file holding `target` the way Windows stores it: UTF-16LE,
/// at an odd offset, after other bytes.
fn shortcut_to(target: &Path) -> Vec<u8> {
    let mut bytes = b"L\0\0\0\x01\x14\x02\0garbage".to_vec();
    for unit in target.to_string_lossy().to_uppercase().encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(b"\0\0trailer");
    bytes
}

#[test]
fn a_hand_made_install_needs_consent_and_its_shortcuts_are_adopted() {
    let world = World::new();
    let install_dir = world.install_dir();
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join(DESKTOP_EXE), b"desktop 0").unwrap();
    std::fs::write(install_dir.join("UNINSTALL.txt"), b"steps").unwrap();
    let desktop = install_dir.join(DESKTOP_EXE);
    let start = world.path("shortcuts/start/FactorSeal.lnk");
    let startup = world.path("shortcuts/start/Startup/FactorSeal (tray).lnk");
    let ascii = world.path("shortcuts/desktop/FactorSeal.lnk");
    let other = world.path("shortcuts/desktop/Other app.lnk");
    std::fs::create_dir_all(startup.parent().unwrap()).unwrap();
    std::fs::write(&start, shortcut_to(&desktop)).unwrap();
    std::fs::write(&startup, shortcut_to(&desktop)).unwrap();
    let mut plain = b"\x01ansi:".to_vec();
    plain.extend_from_slice(desktop.to_string_lossy().as_bytes());
    std::fs::write(&ascii, plain).unwrap();
    std::fs::write(&other, shortcut_to(&world.path("Other/app.exe"))).unwrap();

    let release = v1(&world.releases());
    let error = install_files(&release, &world.options("0.1.0")).unwrap_err();
    assert!(matches!(error, InstallError::NeedsAdoption(_)), "{error}");
    assert_eq!(world.installed(DESKTOP_EXE).unwrap(), b"desktop 0");

    let mut options = world.options("0.1.0");
    options.adopt = true;
    let pending = install_files(&release, &options).unwrap();
    let mut adopted = pending.record().shortcuts.clone();
    adopted.sort();
    let mut expected = vec![start.clone(), startup.clone(), ascii.clone()];
    expected.sort();
    assert_eq!(adopted, expected);
    pending.commit().unwrap();
    // Not made again by this release (it has no shortcut step), so gone;
    // the unrelated one stays, and so does nothing of the hand-made folder.
    assert!(!start.exists() && !startup.exists() && !ascii.exists());
    assert!(other.exists());
    assert_eq!(world.installed("UNINSTALL.txt"), None);
    assert_eq!(world.installed(DESKTOP_EXE).unwrap(), b"desktop 1");
    world.assert_no_leftovers();
}

#[test]
fn a_shortcut_holds_a_path_in_either_text_form() {
    let path = r"c:\users\me\appdata\local\programs\factorseal\factorseal-desktop.exe";
    let wide = |offset: usize| {
        let mut bytes = vec![7_u8; offset];
        for unit in path.to_uppercase().encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    };
    assert!(holds_path(&wide(0), path));
    assert!(holds_path(&wide(1), path));
    assert!(holds_path(path.to_uppercase().as_bytes(), path));
    assert!(!holds_path(&wide(1)[..wide(1).len() - 2], path));
    assert!(!holds_path(b"", path));
    let accented = r"c:\users\josé\factorseal-desktop.exe";
    let bytes: Vec<u8> = accented.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(holds_path(&bytes, accented));
}

/// Old folders moved aside under a unique name, beside the install folder.
fn stuck_folders(world: &World) -> Vec<PathBuf> {
    let parent = world.install_dir().parent().unwrap().to_owned();
    let mut found: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("FactorSeal.old-")
        })
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found
}

/// An old folder that can't be removed at the commit is moved aside under
/// a unique name, and a later run removes it.
#[cfg(unix)]
#[test]
fn an_old_folder_that_cant_be_removed_is_moved_aside_and_removed_later() {
    use std::os::unix::fs::PermissionsExt as _;
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let pending = install_files(&v2(&world.releases()), &world.options("0.1.0")).unwrap();
    // Its contents can't be removed, as a running program's file on Windows.
    let (_, old) = siblings(&world.install_dir());
    let locked = old.join("licenses");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    let left = pending
        .commit()
        .unwrap()
        .expect("the old folder was removed");
    assert!(left.starts_with(world.install_dir().parent().unwrap()));
    assert_eq!(stuck_folders(&world), std::slice::from_ref(&left));
    assert!(
        !old.exists(),
        "{} should be free for the next update",
        old.display()
    );
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 2");

    std::fs::set_permissions(
        left.join("licenses"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(stuck_folders(&world), Vec::<PathBuf>::new());
    world.assert_no_leftovers();
}

/// Windows: a process whose working directory is in the install folder (as
/// one started from a shortcut there) stops the rename, so the update
/// stops before changing anything.
#[cfg(windows)]
#[test]
fn a_working_directory_in_the_install_folder_stops_the_update_cleanly() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let mut child = std::process::Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .current_dir(world.install_dir())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let result = install_files(&v2(&world.releases()), &world.options("0.1.0"));
    let _ = child.kill();
    let _ = child.wait();
    let error = result.unwrap_err();
    assert!(matches!(error, InstallError::Swap { .. }), "{error}");
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 1");
    assert_eq!(world.record().version, "1.0.0");
    world.assert_no_leftovers();
}

/// Windows: a program started from the install folder doesn't stop the
/// rename, but its file can't be deleted, so the old folder is moved aside
/// until it exits, and a later run removes it.
#[cfg(windows)]
#[test]
fn a_program_running_from_the_install_folder_only_delays_removing_the_old_one() {
    let world = World::new();
    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    let system = std::env::var_os("SystemRoot").unwrap();
    let running = world.install_dir().join("running.exe");
    std::fs::copy(
        Path::new(&system).join("System32").join("cmd.exe"),
        &running,
    )
    .unwrap();
    let mut child = std::process::Command::new(&running)
        .args(["/c", "ping", "-n", "30", "127.0.0.1"])
        .current_dir(world.root.path())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let committed =
        install_files(&v2(&world.releases()), &world.options("0.1.0")).and_then(Pending::commit);
    let _ = child.kill();
    let _ = child.wait();
    let left = committed
        .unwrap()
        .expect("the old folder was removed while in use");
    assert_eq!(stuck_folders(&world), [left]);
    assert_eq!(world.installed("factorseal.exe").unwrap(), b"cli 2");
    assert_eq!(world.record().version, "2.0.0");

    install_files(&v1(&world.releases()), &world.options("0.1.0"))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(stuck_folders(&world), Vec::<PathBuf>::new());
    world.assert_no_leftovers();
}
