//! Windows: the steps after the files, for real. Desktop is a copy of
//! cmd.exe here, so a launch leaves a file behind; shortcuts go to a test
//! folder and registry keys under a test key.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use factorseal_setup::manifest::{UNINSTALL_KEY, sha256_hex};
use factorseal_setup::registry::{Registry as _, Root, SystemRegistry};
use serde_json::json;

const SETUP: &str = env!("CARGO_BIN_EXE_factorseal-setup");
const BROWSER_KEY: &str = r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser";

fn wait_for(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// What Windows itself reads from a shortcut, through WScript.Shell.
fn resolve(link: &Path) -> Vec<String> {
    let script = format!(
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); \
         $s.TargetPath; $s.Arguments; $s.WorkingDirectory",
        link.display()
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim_end().to_owned())
        .collect()
}

struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = SystemRegistry {
            root: Root::CurrentUser,
        }
        .delete_key(&self.0);
    }
}

/// A release in `dir` whose Desktop is cmd.exe, with every step type.
fn write_release(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let system = std::env::var_os("SystemRoot").unwrap();
    let cmd = std::fs::read(Path::new(&system).join("System32").join("cmd.exe")).unwrap();
    std::fs::write(dir.join("factorseal-desktop.exe"), &cmd).unwrap();
    let manifest = json!({
        "schema": 1,
        "product": "FactorSeal",
        "version": "1.2.3",
        "requires_setup": 1,
        "files": [{ "path": "factorseal-desktop.exe", "sha256": sha256_hex(&cmd[..]).unwrap().0 }],
        "steps": [
            { "install_files": {} },
            { "shortcut": {
                "name": "FactorSeal Desktop",
                "target": "factorseal-desktop.exe",
                "places": ["start-menu"],
                "optional_places": ["startup", "desktop"],
                "startup_args": ["/c", "type", "nul", ">", "from-link.txt"],
            } },
            { "registry": { "values": [{ "key": BROWSER_KEY, "name": "", "value": "host.json" }] } },
            { "start": {
                "command": ["factorseal-desktop.exe", "/c", "type", "nul", ">", "opened.txt"],
                "quiet_command": ["factorseal-desktop.exe", "/c", "type", "nul", ">", "started.txt"],
            } },
        ],
    });
    std::fs::write(dir.join("factorseal-release.json"), manifest.to_string()).unwrap();
}

/// The sandbox of one run: every path the installer may touch.
struct Sandbox {
    root: tempfile::TempDir,
    test_root: String,
}

impl Sandbox {
    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    /// Install the release quietly, with Startup chosen; returns the log.
    fn install(&self) -> String {
        let log = self.path("setup.log");
        let status = Command::new(SETUP)
            .arg("--quiet")
            .arg("--manifest")
            .arg(self.path("release").join("factorseal-release.json"))
            .arg("--install-dir")
            .arg(self.path("Programs").join("FactorSeal"))
            .args(["--optional-place", "startup"])
            .arg("--shortcut-root")
            .arg(self.path("shortcuts"))
            .arg("--registry-root")
            .arg(&self.test_root)
            .arg("--working-dir")
            .arg(self.path("home"))
            .arg("--log")
            .arg(&log)
            .env("TMP", self.root.path())
            .env("TEMP", self.root.path())
            .status()
            .unwrap();
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "{text}");
        text
    }
}

#[test]
fn shortcuts_registry_and_start_work_on_windows() {
    let root = tempfile::tempdir().unwrap();
    let name = root
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let sandbox = Sandbox {
        test_root: format!(r"HKCU\Software\FactorSeal-setup-test\{name}"),
        root,
    };
    let _cleanup = Cleanup(sandbox.test_root.clone());
    write_release(&sandbox.path("release"));
    let home = sandbox.path("home");
    std::fs::create_dir_all(&home).unwrap();
    let install_dir = sandbox.path("Programs").join("FactorSeal");
    let shortcuts = sandbox.path("shortcuts");
    let test_root = sandbox.test_root.clone();
    let log_text = sandbox.install();

    // start: the quiet launch ran the installed copy, in the working folder.
    assert!(wait_for(&home.join("started.txt")), "no launch: {log_text}");
    assert!(!home.join("opened.txt").exists());

    // Registry, under the test key only.
    let test = SystemRegistry {
        root: Root::Test(test_root.clone()),
    };
    assert_eq!(
        test.get_string(BROWSER_KEY, "").unwrap().as_deref(),
        Some("host.json")
    );
    assert_eq!(
        test.get_string(UNINSTALL_KEY, "DisplayVersion")
            .unwrap()
            .as_deref(),
        Some("1.2.3")
    );
    let uninstall = test
        .get_string(UNINSTALL_KEY, "UninstallString")
        .unwrap()
        .unwrap();
    assert!(
        uninstall.ends_with(r#"factorseal-setup.exe" --uninstall"#),
        "{uninstall}"
    );

    // Shortcuts Windows reads as written, and opens.
    let desktop_exe = install_dir.join("factorseal-desktop.exe");
    let start_menu = shortcuts.join("start-menu").join("FactorSeal Desktop.lnk");
    let startup: PathBuf = shortcuts
        .join("start-menu")
        .join("Startup")
        .join("FactorSeal Desktop.lnk");
    assert!(
        !shortcuts
            .join("desktop")
            .join("FactorSeal Desktop.lnk")
            .exists()
    );
    let read = resolve(&start_menu);
    assert_eq!(
        read.first().map(String::as_str),
        Some(desktop_exe.to_str().unwrap()),
        "{read:?}"
    );
    assert_eq!(read.get(1).map(String::as_str), Some(""), "{read:?}");
    assert_eq!(
        read.get(2).map(String::as_str),
        Some(home.to_str().unwrap()),
        "{read:?}"
    );
    let read = resolve(&startup);
    assert_eq!(
        read.get(1).map(String::as_str),
        Some("/c type nul > from-link.txt"),
        "{read:?}"
    );
    // Opened as Explorer opens it (ShellExecute), with a time limit.
    let opened = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command"])
        .arg(format!("Start-Process -FilePath '{}'", startup.display()))
        .status()
        .unwrap();
    assert!(opened.success());
    assert!(
        wait_for(&home.join("from-link.txt")),
        "the shortcut did not run its target"
    );
}
