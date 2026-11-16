//! The installer binary run unattended (`--quiet`), as our harness will.

use std::path::{Path, PathBuf};
use std::process::Command;

use factorseal_setup::manifest::sha256_hex;
use serde_json::json;

const SETUP: &str = env!("CARGO_BIN_EXE_factorseal-setup");

/// A release folder `root/<version>` with Desktop, the CLI and the browser
/// host, stopped by Desktop's `--quit`; returns its manifest's path.
fn release(root: &Path, version: &str, requires_setup: u32) -> PathBuf {
    let dir = root.join(version);
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    for (name, contents) in [
        ("factorseal-desktop.exe", format!("desktop {version}")),
        ("factorseal.exe", format!("cli {version}")),
        ("factorseal-browser.exe", format!("browser {version}")),
    ] {
        std::fs::write(dir.join(name), &contents).unwrap();
        files.push(json!({ "path": name, "sha256": sha256_hex(contents.as_bytes()).unwrap().0 }));
    }
    let manifest = json!({
        "schema": 1,
        "product": "FactorSeal",
        "version": version,
        "requires_setup": requires_setup,
        "files": files,
        "stop": {
            "command": ["factorseal-desktop.exe", "--quit"],
            "also_stop": ["factorseal-browser.exe"],
        },
        "steps": [{ "install_files": {} }],
    });
    let path = dir.join("factorseal-release.json");
    std::fs::write(&path, manifest.to_string()).unwrap();
    path
}

/// A test registry key per sandbox, under one parent the tests remove.
fn registry_root(sandbox: &Path) -> String {
    let name = sandbox.file_name().unwrap().to_string_lossy().into_owned();
    format!(r"HKCU\Software\FactorSeal-setup-test\{name}")
}

/// Removes a sandbox's test registry key when dropped (Windows).
#[cfg_attr(not(windows), allow(dead_code))] // Nothing to remove elsewhere.
struct RegistryCleanup(PathBuf);

impl Drop for RegistryCleanup {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            use factorseal_setup::registry::{Registry as _, Root, SystemRegistry};
            let _ = SystemRegistry {
                root: Root::CurrentUser,
            }
            .delete_key(&registry_root(&self.0));
        }
    }
}

struct Run {
    code: Option<i32>,
    log: String,
}

fn setup(program: &Path, manifest: &Path, install_dir: &Path, log: &Path, extra: &[&str]) -> Run {
    setup_in(program, manifest, install_dir, log, extra, Path::new("."))
}

fn setup_in(
    program: &Path,
    manifest: &Path,
    install_dir: &Path,
    log: &Path,
    extra: &[&str],
    cwd: &Path,
) -> Run {
    // Never the user's shortcut folders or registry keys.
    let sandbox = log.parent().unwrap();
    let status = Command::new(program)
        .current_dir(cwd)
        .arg("--shortcut-root")
        .arg(sandbox.join("shortcuts"))
        .arg("--registry-root")
        .arg(registry_root(sandbox))
        .arg("--quiet")
        .arg("--manifest")
        .arg(manifest)
        .arg("--install-dir")
        .arg(install_dir)
        .arg("--log")
        .arg(log)
        .args(extra)
        // Relaunched copies go here, not into the real temporary folder.
        .env("TMP", log.parent().unwrap())
        .env("TEMP", log.parent().unwrap())
        .env("TMPDIR", log.parent().unwrap())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    Run {
        code: status.code(),
        log: std::fs::read_to_string(log).unwrap_or_default(),
    }
}

fn installed_version(install_dir: &Path) -> Option<String> {
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(install_dir.join("install.json")).ok()?).ok()?;
    record["version"].as_str().map(str::to_owned)
}

#[test]
fn quiet_installs_and_reports_through_exit_codes_and_the_log() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let manifest = release(root.path(), "1.0.0", 1);

    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(run.log.contains("result: installed 1.0.0"), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
    assert!(install_dir.join("factorseal-setup.exe").is_file());

    let newer = release(root.path(), "9.0.0", 99);
    let run = setup(Path::new(SETUP), &newer, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(4), "{}", run.log);
    assert!(run.log.contains("needs a newer installer"), "{}", run.log);

    let broken = release(root.path(), "2.0.0", 1);
    std::fs::write(broken.parent().unwrap().join("factorseal.exe"), b"changed").unwrap();
    let run = setup(Path::new(SETUP), &broken, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(3), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));

    let missing = Command::new(SETUP)
        .args(["--quiet", "--log"])
        .arg(&log)
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(missing.code(), Some(2));
}

#[test]
fn a_hand_made_install_is_updated_only_with_adopt() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("FactorSeal");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join("factorseal-desktop.exe"), b"by hand").unwrap();
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let manifest = release(root.path(), "1.0.0", 1);

    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(6), "{}", run.log);
    assert_eq!(
        std::fs::read(install_dir.join("factorseal-desktop.exe")).unwrap(),
        b"by hand"
    );
    let run = setup(
        Path::new(SETUP),
        &manifest,
        &install_dir,
        &log,
        &["--adopt"],
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
}

/// A process started from `program`, killed when dropped.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Put a program that runs until stopped in place of the installed `name`,
/// and start it from there.
fn run_installed(install_dir: &Path, name: &str) -> Running {
    #[cfg(windows)]
    let (program, arguments) = (
        Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\PING.EXE"),
        ["-n", "120", "127.0.0.1"],
    );
    // A shell builtin waiting on its standard input.
    #[cfg(not(windows))]
    let (program, arguments) = (
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join("sh"))
            .find(|path| path.is_file())
            .unwrap(),
        ["-c", "read line"],
    );
    let path = install_dir.join(name);
    std::fs::copy(&program, &path).unwrap();
    Running(
        Command::new(&path)
            .args(arguments)
            .current_dir(install_dir.parent().unwrap())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

/// An update waits for what runs from the install folder: the CLI is
/// waited for (here in vain, so nothing changes, exit 7), the browser host
/// is terminated.
#[test]
fn an_update_waits_for_the_folders_processes_and_stops_the_browser_host() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let first = release(root.path(), "1.0.0", 1);
    assert_eq!(
        setup(Path::new(SETUP), &first, &install_dir, &log, &[]).code,
        Some(0)
    );
    let second = release(root.path(), "2.0.0", 1);

    let cli = run_installed(&install_dir, "factorseal.exe");
    let run = setup(
        Path::new(SETUP),
        &second,
        &install_dir,
        &log,
        &["--wait-for-quit", "1"],
    );
    assert_eq!(run.code, Some(7), "{}", run.log);
    let pid = cli.0.id();
    assert!(
        run.log.contains("quit FactorSeal from its tray icon")
            && run.log.contains(&format!("factorseal.exe (process {pid})")),
        "{}",
        run.log
    );
    // Desktop here is no program: its stop command fails, and the user is
    // asked instead.
    assert!(
        run.log.contains("the stop command didn't stop FactorSeal"),
        "{}",
        run.log
    );
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
    drop(cli);

    let mut host = run_installed(&install_dir, "factorseal-browser.exe");
    let run = setup(Path::new(SETUP), &second, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(
        run.log.contains(&format!(
            "stopping factorseal-browser.exe (process {}); a browser fill",
            host.0.id()
        )),
        "{}",
        run.log
    );
    assert!(host.0.wait().is_ok_and(|status| !status.success()));
    assert_eq!(installed_version(&install_dir).as_deref(), Some("2.0.0"));
}

/// Windows: the installed copy, run from the install folder with it as the
/// working directory (as from its Start menu shortcut), continues from a
/// copy in the temporary folder, which finishes the update and removes the
/// old folder once the first copy has exited.
#[cfg(windows)]
#[test]
fn an_update_run_from_inside_the_install_folder_succeeds_through_the_relaunch() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let temp = root.path().join("temp");
    std::fs::create_dir_all(&temp).unwrap();
    let log = temp.join("setup.log");
    let _cleanup = RegistryCleanup(temp.clone());
    let first = release(root.path(), "1.0.0", 1);
    assert_eq!(
        setup(Path::new(SETUP), &first, &install_dir, &log, &[]).code,
        Some(0)
    );

    let installed_setup = install_dir.join("factorseal-setup.exe");
    let second = release(root.path(), "2.0.0", 1);
    let run = setup_in(
        &installed_setup,
        &second,
        &install_dir,
        &log,
        &[],
        &install_dir,
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(run.log.contains("continuing from"), "{}", run.log);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let log_text = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("result: installed 2.0.0") || text.contains("result: failed") {
            break text;
        }
        assert!(std::time::Instant::now() < deadline, "no result: {text}");
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert!(log_text.contains("result: installed 2.0.0"), "{log_text}");
    assert_eq!(installed_version(&install_dir).as_deref(), Some("2.0.0"));
    assert_eq!(
        std::fs::read(install_dir.join("factorseal.exe")).unwrap(),
        b"cli 2.0.0"
    );
    // Nothing left beside the install folder.
    let parent = install_dir.parent().unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "FactorSeal")
        .collect();
    assert!(
        leftovers.is_empty(),
        "left beside the install folder: {leftovers:?}"
    );
    // The relaunched copy ran from the temporary folder given.
    assert!(
        std::fs::read_dir(&temp)
            .unwrap()
            .flatten()
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("factorseal-setup-")),
        "no relaunched copy in {}",
        temp.display()
    );
}
