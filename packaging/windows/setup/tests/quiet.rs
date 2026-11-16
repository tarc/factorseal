//! The installer binary run unattended (`--quiet`), as our harness will.

use std::path::{Path, PathBuf};
use std::process::Command;

use factorseal_setup::manifest::sha256_hex;
use serde_json::json;

const SETUP: &str = env!("CARGO_BIN_EXE_factorseal-setup");

/// Linux refuses to run a file some process has open for writing
/// (`ETXTBSY`), and a child forked by one test thread holds the file
/// another thread is writing until it runs its program. Writing an
/// executable and starting a process hold this lock, so the two never
/// overlap; waiting for a process doesn't.
fn exec_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Start `command` under the exec lock and wait for it outside.
fn status(command: &mut Command) -> std::process::ExitStatus {
    let mut child = {
        let _exec = exec_lock();
        command.spawn().unwrap()
    };
    child.wait().unwrap()
}

/// A release folder `root/<version>` with Desktop, the CLI and the browser
/// host, stopped by Desktop's `--quit`; returns its manifest's path.
fn release(root: &Path, version: &str, requires_setup: u32) -> PathBuf {
    release_with_steps(
        root,
        version,
        requires_setup,
        &json!([{ "install_files": {} }]),
    )
}

/// The same, with these steps.
fn release_with_steps(
    root: &Path,
    version: &str,
    requires_setup: u32,
    steps: &serde_json::Value,
) -> PathBuf {
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
        "steps": steps,
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
    setup_in(
        program,
        Some(manifest),
        install_dir,
        log,
        extra,
        Path::new("."),
    )
}

/// `--uninstall` instead of a manifest.
fn uninstall(program: &Path, install_dir: &Path, log: &Path, extra: &[&str]) -> Run {
    setup_in(program, None, install_dir, log, extra, Path::new("."))
}

fn setup_in(
    program: &Path,
    manifest: Option<&Path>,
    install_dir: &Path,
    log: &Path,
    extra: &[&str],
    cwd: &Path,
) -> Run {
    // Never the user's shortcut folders, registry keys or AppData.
    let sandbox = log.parent().unwrap();
    let mut command = Command::new(program);
    match manifest {
        Some(manifest) => command.arg("--manifest").arg(manifest),
        None => command.arg("--uninstall"),
    };
    command
        .current_dir(cwd)
        .arg("--appdata-root")
        .arg(sandbox.join("appdata"))
        .arg("--shortcut-root")
        .arg(sandbox.join("shortcuts"))
        .arg("--registry-root")
        .arg(registry_root(sandbox))
        .arg("--quiet")
        .arg("--install-dir")
        .arg(install_dir)
        .arg("--log")
        .arg(log)
        .args(extra)
        // Relaunched copies go here, not into the real temporary folder.
        .env("TMP", log.parent().unwrap())
        .env("TEMP", log.parent().unwrap())
        .env("TMPDIR", log.parent().unwrap())
        .stderr(std::process::Stdio::null());
    let status = status(&mut command);
    Run {
        code: status.code(),
        log: std::fs::read_to_string(log).unwrap_or_default(),
    }
}

fn installed_record(install_dir: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(install_dir.join("install.json")).ok()?).ok()
}

fn installed_version(install_dir: &Path) -> Option<String> {
    installed_record(install_dir)?["version"]
        .as_str()
        .map(str::to_owned)
}

fn recorded_distros(install_dir: &Path) -> Vec<String> {
    installed_record(install_dir)
        .and_then(|record| serde_json::from_value(record["distros"].clone()).ok())
        .unwrap_or_default()
}

/// A release whose steps include `wsl`.
fn wsl_release(root: &Path, version: &str) -> PathBuf {
    release_with_steps(
        root,
        version,
        1,
        &json!([{ "install_files": {} }, { "wsl": {} }]),
    )
}

#[test]
fn a_release_that_sets_up_wsl_needs_wsl_or_no_wsl_under_quiet() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let manifest = wsl_release(root.path(), "1.0.0");

    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &[]);
    assert_eq!(run.code, Some(2), "{}", run.log);
    assert!(run.log.contains("pass --wsl DISTRO"), "{}", run.log);
    assert_eq!(installed_version(&install_dir), None);

    let bad_name = setup(
        Path::new(SETUP),
        &manifest,
        &install_dir,
        &log,
        &["--wsl", "a b"],
    );
    assert_eq!(bad_name.code, Some(2));
    assert_eq!(installed_version(&install_dir), None);

    let run = setup(
        Path::new(SETUP),
        &manifest,
        &install_dir,
        &log,
        &["--no-wsl"],
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
    assert_eq!(recorded_distros(&install_dir), Vec::<String>::new());
}

/// Unix: a stand-in for `wsl.exe` in `root` that runs the installer's
/// lines with a real `sh`, where the distro `Bare` has no `factorseal` and
/// the others a fake one appending `<distro> <arguments>` to the calls
/// file. Returns the stand-in and that file.
#[cfg(unix)]
fn wsl_stand_in(root: &Path) -> (String, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = |path: &Path, text: &str| {
        let _exec = exec_lock();
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let (with, bare) = (root.join("bin"), root.join("bare"));
    std::fs::create_dir_all(&with).unwrap();
    std::fs::create_dir_all(&bare).unwrap();
    let calls = root.join("calls");
    executable(
        &with.join("factorseal"),
        &format!(
            "#!/bin/sh\nprintf '%s %s\\n' \"$WSL_DISTRO\" \"$*\" >> '{}'\necho \"Wrote config\"\n",
            calls.display()
        ),
    );
    for bin in [&with, &bare] {
        executable(
            &bin.join("wslpath"),
            "#!/bin/sh\n[ \"$1\" = -u ] || exit 2\nprintf '/mnt/c%s\\n' \"$2\"\n",
        );
    }
    let stand_in = root.join("wsl.exe");
    executable(
        &stand_in,
        &format!(
            "#!/bin/sh\n[ \"$1\" = -d ] && [ \"$3\" = --exec ] || exit 9\n\
             if [ \"$2\" = Bare ]; then bin='{}'; else bin='{}'; fi\n\
             distro=$2; shift 5\nWSL_DISTRO=$distro PATH=$bin exec /bin/sh -c \"$@\"\n",
            bare.display(),
            with.display()
        ),
    );
    let stand_in = stand_in.to_string_lossy().into_owned();
    (stand_in, calls)
}

/// Unix: the installer's own lines, run by a real `sh` through a stand-in
/// for `wsl.exe` whose distro `Bare` has no `factorseal`: the distro with
/// it is set up and recorded, `Bare` gets the hint, and the run says so
/// through exit code 8, with the install kept.
#[cfg(unix)]
#[test]
fn quiet_sets_up_the_chosen_distros_and_records_those_set_up() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let (stand_in, calls) = wsl_stand_in(root.path());

    let manifest = wsl_release(root.path(), "1.0.0");
    let extra = [
        "--wsl",
        "NixOS",
        "--wsl",
        "Bare",
        "--wsl-program",
        &stand_in,
    ];
    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &extra);
    assert_eq!(run.code, Some(8), "{}", run.log);
    assert!(run.log.contains("set up WSL distro NixOS"), "{}", run.log);
    assert!(
        run.log
            .contains("FactorSeal isn't installed in WSL distro Bare"),
        "{}",
        run.log
    );
    assert!(
        run.log.contains("result: installed 1.0.0 in ")
            && run.log.contains("but WSL was not set up in 1 distro(s)"),
        "{}",
        run.log
    );
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
    assert_eq!(recorded_distros(&install_dir), ["NixOS"]);
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap(),
        format!(
            "NixOS wsl-setup --windows-install /mnt/c{}\n",
            install_dir.display()
        )
    );

    // An update in the same distro: set up again, recorded once.
    let manifest = wsl_release(root.path(), "2.0.0");
    let extra = ["--wsl", "NixOS", "--wsl-program", &stand_in];
    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &extra);
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("2.0.0"));
    assert_eq!(recorded_distros(&install_dir), ["NixOS"]);
    assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 2);
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

    // A log in a folder that doesn't exist yet is written all the same.
    let elsewhere = root.path().join("logs").join("setup.log");
    let run = setup(Path::new(SETUP), &broken, &install_dir, &elsewhere, &[]);
    assert_eq!(run.code, Some(3));
    assert!(
        std::fs::read_to_string(&elsewhere).is_ok_and(|text| text.contains("result: refused")),
        "no log at {}",
        elsewhere.display()
    );

    let missing = status(
        Command::new(SETUP)
            .args(["--quiet", "--log"])
            .arg(&log)
            .stderr(std::process::Stdio::null()),
    );
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
    let _exec = exec_lock();
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
    // The choice about WSL reaches the copy too.
    let second = wsl_release(root.path(), "2.0.0");
    let run = setup_in(
        &installed_setup,
        Some(&second),
        &install_dir,
        &log,
        &["--no-wsl"],
        &install_dir,
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(run.log.contains("continuing from"), "{}", run.log);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let log_text = loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if [
            "result: installed 2.0.0",
            "result: failed",
            "result: refused",
        ]
        .iter()
        .any(|result| text.contains(result))
        {
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

const MOZILLA: &str = r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser";
#[cfg(windows)]
use factorseal_setup::manifest::UNINSTALL_KEY;
const NOTE: &str = "The vault stays; factorseal.exe destroy removes it.";

/// A release with a shortcut, a registry value and an uninstall section.
fn full_release(root: &Path, version: &str) -> PathBuf {
    let manifest = release_with_steps(
        root,
        version,
        1,
        &json!([
            { "install_files": {} },
            { "shortcut": {
                "name": "FactorSeal Desktop",
                "target": "factorseal-desktop.exe",
                "places": ["start-menu"],
                "optional_places": ["desktop"],
            } },
            { "registry": { "values": [{ "key": MOZILLA, "name": "", "value": "host.json" }] } },
        ]),
    );
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    json["uninstall"] = json!({
        "registry_cleanup": [r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\dev.factorseal.browser"],
        "ask_to_delete": [r"%APPDATA%\Factorseal\settings"],
        "keep_note": NOTE,
    });
    std::fs::write(&manifest, json.to_string()).unwrap();
    manifest
}

/// The `.lnk` files under the sandbox's shortcut folders.
fn links(sandbox: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![sandbox.join("shortcuts")];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "lnk") {
                found.push(path);
            }
        }
    }
    found
}

/// Windows: a string value under the sandbox's test registry key.
#[cfg(windows)]
fn test_value(sandbox: &Path, key: &str, name: &str) -> Option<String> {
    use factorseal_setup::registry::{Registry as _, Root, SystemRegistry};
    SystemRegistry {
        root: Root::Test(registry_root(sandbox)),
    }
    .get_string(key, name)
    .unwrap()
}

#[test]
fn quiet_uninstall_removes_what_the_install_made_and_keeps_the_vault() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let settings = root.path().join("appdata/Roaming/Factorseal/settings");
    let vault = root.path().join("appdata/Local/Factorseal/Factorseal/data");
    for folder in [&settings, &vault] {
        std::fs::create_dir_all(folder).unwrap();
        std::fs::write(folder.join("file"), b"data").unwrap();
    }
    let manifest = full_release(root.path(), "1.0.0");
    let extra = ["--no-start", "--optional-place", "desktop"];
    let run = setup(Path::new(SETUP), &manifest, &install_dir, &log, &extra);
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert_eq!(links(root.path()).len(), 2);
    #[cfg(windows)]
    {
        assert!(test_value(root.path(), MOZILLA, "").is_some());
        assert!(test_value(root.path(), UNINSTALL_KEY, "DisplayName").is_some());
    }

    // While the CLI runs from the folder, nothing is removed.
    let cli = run_installed(&install_dir, "factorseal.exe");
    let extra = ["--also-delete", "--wait-for-quit", "1"];
    let run = uninstall(Path::new(SETUP), &install_dir, &log, &extra);
    assert_eq!(run.code, Some(7), "{}", run.log);
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));
    assert_eq!(links(root.path()).len(), 2);
    assert!(settings.exists());
    drop(cli);

    let run = uninstall(Path::new(SETUP), &install_dir, &log, &["--also-delete"]);
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(
        run.log
            .contains("result: uninstalled FactorSeal 1.0.0 from"),
        "{}",
        run.log
    );
    assert!(run.log.contains(NOTE), "{}", run.log);
    assert!(!install_dir.exists(), "{}", run.log);
    assert_eq!(links(root.path()), Vec::<PathBuf>::new());
    assert!(!settings.exists());
    assert!(vault.join("file").exists());
    #[cfg(windows)]
    {
        assert_eq!(test_value(root.path(), MOZILLA, ""), None);
        assert_eq!(test_value(root.path(), UNINSTALL_KEY, "DisplayName"), None);
    }

    // Nothing left to uninstall.
    let run = uninstall(Path::new(SETUP), &install_dir, &log, &[]);
    assert_eq!(run.code, Some(9), "{}", run.log);
    assert!(run.log.contains("is not installed in"), "{}", run.log);
}

/// Unix: an install recorded in a distro needs a choice about it, naming
/// only recorded distros; the chosen one gets the removal line.
#[cfg(unix)]
#[test]
fn quiet_uninstall_removes_the_wsl_setup_from_the_chosen_recorded_distros() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let log = root.path().join("setup.log");
    let _cleanup = RegistryCleanup(root.path().to_owned());
    let (stand_in, calls) = wsl_stand_in(root.path());
    let manifest = wsl_release(root.path(), "1.0.0");
    let run = setup(
        Path::new(SETUP),
        &manifest,
        &install_dir,
        &log,
        &["--wsl", "NixOS", "--wsl-program", &stand_in],
    );
    assert_eq!(run.code, Some(0), "{}", run.log);

    let program = ["--wsl-program", stand_in.as_str()];
    let run = uninstall(Path::new(SETUP), &install_dir, &log, &program);
    assert_eq!(run.code, Some(2), "{}", run.log);
    assert!(run.log.contains("was set up in WSL (NixOS)"), "{}", run.log);
    let run = uninstall(
        Path::new(SETUP),
        &install_dir,
        &log,
        &[&program[..], &["--wsl", "Ubuntu"]].concat(),
    );
    assert_eq!(run.code, Some(2), "{}", run.log);
    assert!(
        run.log.contains("not set up in WSL distro Ubuntu"),
        "{}",
        run.log
    );
    assert_eq!(installed_version(&install_dir).as_deref(), Some("1.0.0"));

    let run = uninstall(
        Path::new(SETUP),
        &install_dir,
        &log,
        &[&program[..], &["--wsl", "nixos"]].concat(),
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(!install_dir.exists());
    let calls = std::fs::read_to_string(&calls).unwrap();
    assert_eq!(
        calls.lines().last(),
        Some("NixOS wsl-setup --remove"),
        "{calls}"
    );
}

/// Windows: the installed copy, run with --uninstall from the install
/// folder (as Installed apps runs it), continues from a copy in the
/// temporary folder, which removes the folder with the installed copy in
/// it and then deletes itself.
#[cfg(windows)]
#[test]
fn an_uninstall_run_from_the_install_folder_removes_it_and_the_copy_deletes_itself() {
    let root = tempfile::tempdir().unwrap();
    let install_dir = root.path().join("Programs").join("FactorSeal");
    let temp = root.path().join("temp");
    std::fs::create_dir_all(&temp).unwrap();
    let log = temp.join("setup.log");
    let _cleanup = RegistryCleanup(temp.clone());
    let manifest = full_release(root.path(), "1.0.0");
    let run = setup(
        Path::new(SETUP),
        &manifest,
        &install_dir,
        &log,
        &["--no-start"],
    );
    assert_eq!(run.code, Some(0), "{}", run.log);

    let run = setup_in(
        &install_dir.join("factorseal-setup.exe"),
        None,
        &install_dir,
        &log,
        &[],
        &install_dir,
    );
    assert_eq!(run.code, Some(0), "{}", run.log);
    assert!(run.log.contains("continuing from"), "{}", run.log);
    let copies = || -> Vec<String> {
        std::fs::read_dir(&temp)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("factorseal-setup-"))
            .collect()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let ended = ["result: uninstalled", "result: failed", "result: refused"]
            .iter()
            .any(|result| text.contains(result));
        if ended && copies().is_empty() {
            assert!(
                text.contains("result: uninstalled FactorSeal 1.0.0"),
                "{text}"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "copies left: {:?}\n{text}",
            copies()
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    assert!(!install_dir.exists());
    assert_eq!(test_value(&temp, UNINSTALL_KEY, "DisplayName"), None);
}
