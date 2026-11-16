use serde_json::{Value, json};

use super::*;
use crate::engine::{Options, install_files};
use crate::manifest::{MANIFEST_FILE, sha256_hex};
use crate::registry::MemoryRegistry;

const BROWSER_KEY: &str = r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser";

fn shortcut_step(optional: &[&str]) -> Value {
    json!({ "shortcut": {
        "name": "FactorSeal Desktop",
        "target": "factorseal-desktop.exe",
        "places": ["start-menu"],
        "optional_places": optional,
        "startup_args": ["--background"],
    } })
}

fn registry_step(values: &[(&str, &str)]) -> Value {
    let values: Vec<Value> = values
        .iter()
        .map(|(name, value)| json!({ "key": BROWSER_KEY, "name": name, "value": value }))
        .collect();
    json!({ "registry": { "values": values } })
}

struct World {
    root: tempfile::TempDir,
    releases: usize,
}

impl World {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("setup.exe"), b"setup").unwrap();
        Self { root, releases: 0 }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    /// A release with Desktop and these steps after `install_files`.
    fn release(&mut self, steps: &[Value]) -> Release {
        self.releases += 1;
        let dir = self.path(&format!("release-{}", self.releases));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("factorseal-desktop.exe"), b"desktop").unwrap();
        let mut all = vec![json!({ "install_files": {} })];
        all.extend_from_slice(steps);
        let manifest = json!({
            "schema": 1,
            "product": "FactorSeal",
            "version": format!("{}.0.0", self.releases),
            "requires_setup": 1,
            "files": [{
                "path": "factorseal-desktop.exe",
                "sha256": sha256_hex(&b"desktop"[..]).unwrap().0,
            }],
            "steps": all,
        });
        std::fs::write(dir.join(MANIFEST_FILE), manifest.to_string()).unwrap();
        Release::open(&dir.join(MANIFEST_FILE)).unwrap()
    }

    fn install_dir(&self) -> PathBuf {
        self.path("Programs/FactorSeal")
    }

    fn options(&self) -> Options {
        Options {
            install_dir: self.install_dir(),
            setup_exe: self.path("setup.exe"),
            setup_version: "0.1.0".to_owned(),
            adopt: false,
            shortcut_dirs: Vec::new(),
        }
    }

    fn step_options(&self, optional: &[Place]) -> StepOptions {
        StepOptions {
            places: Places {
                start_menu: self.path("start"),
                startup: self.path("start/Startup"),
                desktop: self.path("desktop"),
            },
            optional_places: optional.to_vec(),
            launch: Launch::None,
            working_dir: self.path("home"),
        }
    }

    /// Install `release` with its shortcut and registry steps, and commit.
    fn install(&self, release: &Release, optional: &[Place], registry: &MemoryRegistry) {
        let mut pending = install_files(release, &self.options()).unwrap();
        make_shortcuts(release, &mut pending, &self.step_options(optional)).unwrap();
        write_registry(release, &mut pending, registry).unwrap();
        pending.commit(registry).unwrap();
    }

    fn link(&self, relative: &str) -> Option<Vec<u8>> {
        std::fs::read(self.path(relative)).ok()
    }
}

fn holds(bytes: &[u8], text: &str) -> bool {
    crate::engine::holds_path(bytes, &text.to_lowercase())
}

#[test]
fn shortcuts_go_to_their_places_and_the_startup_one_starts_in_the_tray() {
    let mut world = World::new();
    let release = world.release(&[shortcut_step(&["startup", "desktop"])]);
    world.install(&release, &[Place::Startup], &MemoryRegistry::default());

    let start = world
        .link("start/FactorSeal Desktop.lnk")
        .expect("no Start menu shortcut");
    let startup = world
        .link("start/Startup/FactorSeal Desktop.lnk")
        .expect("no Startup shortcut");
    assert_eq!(world.link("desktop/FactorSeal Desktop.lnk"), None);
    let target = world.install_dir().join("factorseal-desktop.exe");
    for link in [&start, &startup] {
        assert!(holds(link, &target.to_string_lossy()));
        // Working outside the install folder, so the next update can swap it.
        assert!(holds(link, &world.path("home").to_string_lossy()));
    }
    assert!(holds(&startup, "--background"));
    assert!(!holds(&start, "--background"));
    let mut recorded = match crate::record::Existing::detect(&world.install_dir()).unwrap() {
        crate::record::Existing::Recorded(record) => record.shortcuts,
        other => panic!("{other:?}"),
    };
    recorded.sort();
    assert_eq!(
        recorded,
        [
            world.path("start/FactorSeal Desktop.lnk"),
            world.path("start/Startup/FactorSeal Desktop.lnk"),
        ]
    );
}

#[test]
fn an_optional_place_the_previous_install_had_is_kept_without_asking() {
    let mut world = World::new();
    let first = world.release(&[shortcut_step(&["startup", "desktop"])]);
    world.install(&first, &[Place::Desktop], &MemoryRegistry::default());
    assert!(world.link("desktop/FactorSeal Desktop.lnk").is_some());

    // The update chooses nothing: the desktop shortcut stays, Startup
    // still isn't made.
    let second = world.release(&[shortcut_step(&["startup", "desktop"])]);
    world.install(&second, &[], &MemoryRegistry::default());
    assert!(world.link("desktop/FactorSeal Desktop.lnk").is_some());
    assert!(world.link("start/Startup/FactorSeal Desktop.lnk").is_none());

    // A release that no longer has the shortcut step removes them all.
    let third = world.release(&[]);
    world.install(&third, &[], &MemoryRegistry::default());
    assert!(world.link("desktop/FactorSeal Desktop.lnk").is_none());
    assert!(world.link("start/FactorSeal Desktop.lnk").is_none());
}

#[test]
fn registry_values_follow_the_release_and_a_rollback_removes_new_ones() {
    let mut world = World::new();
    let registry = MemoryRegistry::default();
    let first = world.release(&[registry_step(&[("", "host.json"), ("old", "1")])]);
    world.install(&first, &[], &registry);
    assert_eq!(
        registry.get_string(BROWSER_KEY, "old").unwrap().as_deref(),
        Some("1")
    );

    // The update no longer writes "old": the commit removes it.
    let second = world.release(&[registry_step(&[("", "host2.json")])]);
    world.install(&second, &[], &registry);
    assert_eq!(
        registry.get_string(BROWSER_KEY, "").unwrap().as_deref(),
        Some("host2.json")
    );
    assert_eq!(registry.get_string(BROWSER_KEY, "old").unwrap(), None);

    // An update rolled back removes what it added and keeps the rest.
    let third = world.release(&[registry_step(&[("", "host3.json"), ("new", "1")])]);
    let mut pending = install_files(&third, &world.options()).unwrap();
    write_registry(&third, &mut pending, &registry).unwrap();
    pending.rollback(&registry).unwrap();
    assert_eq!(registry.get_string(BROWSER_KEY, "new").unwrap(), None);
    assert!(registry.get_string(BROWSER_KEY, "").unwrap().is_some());
}

#[test]
fn a_rolled_back_update_removes_only_the_shortcuts_it_added() {
    let mut world = World::new();
    let first = world.release(&[shortcut_step(&["desktop"])]);
    world.install(&first, &[], &MemoryRegistry::default());
    let second = world.release(&[shortcut_step(&["desktop"])]);
    let mut pending = install_files(&second, &world.options()).unwrap();
    make_shortcuts(
        &second,
        &mut pending,
        &world.step_options(&[Place::Desktop]),
    )
    .unwrap();
    assert!(world.link("desktop/FactorSeal Desktop.lnk").is_some());
    pending.rollback(&MemoryRegistry::default()).unwrap();
    assert!(world.link("desktop/FactorSeal Desktop.lnk").is_none());
    assert!(world.link("start/FactorSeal Desktop.lnk").is_some());
}

#[test]
fn the_installed_apps_entry_names_the_version_and_the_uninstaller() {
    let mut world = World::new();
    let release = world.release(&[]);
    let registry = MemoryRegistry::default();
    register_installed_app(&release, &world.install_dir(), &registry).unwrap();
    let get = |name: &str| registry.get_string(UNINSTALL_KEY, name).unwrap();
    assert_eq!(get("DisplayName").as_deref(), Some("FactorSeal"));
    assert_eq!(get("DisplayVersion").as_deref(), Some("1.0.0"));
    let setup = world.install_dir().join("factorseal-setup.exe");
    assert_eq!(
        get("UninstallString"),
        Some(format!("\"{}\" --uninstall", setup.to_string_lossy()))
    );
    assert_eq!(get("NoModify").as_deref(), Some("dword:1"));
    assert!(
        get("DisplayIcon")
            .unwrap()
            .ends_with("factorseal-desktop.exe")
    );
}

#[test]
fn the_launch_follows_the_choice() {
    let mut world = World::new();
    let both = world.release(&[json!({ "start": {
        "command": ["factorseal-desktop.exe", "--open", "wsl-keyrings"],
        "quiet_command": ["factorseal-desktop.exe", "--background"],
    } })]);
    assert_eq!(
        launch_command(&both, Launch::Open).unwrap(),
        ["factorseal-desktop.exe", "--open", "wsl-keyrings"]
    );
    assert_eq!(
        launch_command(&both, Launch::Quiet).unwrap(),
        ["factorseal-desktop.exe", "--background"]
    );
    assert_eq!(launch_command(&both, Launch::None), None);
    let open_only = world.release(&[json!({ "start": {
        "command": ["factorseal-desktop.exe"],
    } })]);
    assert_eq!(
        launch_command(&open_only, Launch::Quiet).unwrap(),
        ["factorseal-desktop.exe"]
    );
    let none = world.release(&[]);
    assert_eq!(launch_command(&none, Launch::Open), None);
    assert!(!start(&none, &world.install_dir(), &world.step_options(&[])).unwrap());
}
