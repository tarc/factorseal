use std::path::PathBuf;

use factorseal_setup::manifest::{Uninstall, sha256_hex};
use factorseal_setup::record::{RECORD_FORMAT, RecordedFile};
use serde_json::json;

use super::*;

fn places(root: &Path) -> Places {
    Places {
        start_menu: root.join("start"),
        startup: root.join("start/Startup"),
        desktop: root.join("desktop"),
    }
}

/// A release with a shortcut always in the Start menu and optionally at
/// sign-in and on the desktop.
fn release(root: &Path) -> Release {
    let dir = root.join("release");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("factorseal-desktop.exe"), b"desktop").unwrap();
    let manifest = json!({
        "schema": 1,
        "product": "FactorSeal",
        "version": "2.0.0",
        "requires_setup": 1,
        "files": [{ "path": "factorseal-desktop.exe", "sha256": sha256_hex(&b"desktop"[..]).unwrap().0 }],
        "steps": [
            { "install_files": {} },
            { "shortcut": {
                "name": "FactorSeal Desktop",
                "target": "factorseal-desktop.exe",
                "places": ["start-menu"],
                "optional_places": ["startup", "desktop"],
            } },
        ],
    });
    let path = dir.join("factorseal-release.json");
    std::fs::write(&path, manifest.to_string()).unwrap();
    Release::open(&path).unwrap()
}

fn record(version: &str) -> InstallRecord {
    InstallRecord {
        format: RECORD_FORMAT,
        version: version.to_owned(),
        setup_version: "0.1.0".to_owned(),
        files: vec![RecordedFile {
            path: "factorseal-desktop.exe".to_owned(),
            sha256: "0".repeat(64),
        }],
        shortcuts: Vec::new(),
        registry: Vec::new(),
        distros: Vec::new(),
        stop: None,
        uninstall: Uninstall::default(),
    }
}

fn lines(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| (*line).to_owned()).collect()
}

#[test]
fn places_the_installed_version_has_are_kept_not_offered() {
    let root = tempfile::tempdir().unwrap();
    let release = release(root.path());
    let places = places(root.path());
    assert_eq!(
        optional_places(&release, &Existing::Fresh, &places),
        (vec![Place::Startup, Place::Desktop], Vec::new())
    );
    let mut installed = record("1.0.0");
    installed.shortcuts = vec![root.path().join("desktop/FactorSeal Desktop.lnk")];
    assert_eq!(
        optional_places(&release, &Existing::Recorded(Box::new(installed)), &places),
        (vec![Place::Startup], vec![Place::Desktop])
    );
}

#[test]
fn the_first_page_says_what_happens_to_what_is_installed() {
    let dir = PathBuf::from(r"C:\Users\jo\AppData\Local\Programs\FactorSeal");
    let fresh = install_page("2.0.0", &Existing::Fresh, &dir, &[Place::Desktop], &[]);
    assert_eq!(fresh.heading, "Install FactorSeal 2.0.0");
    assert!(
        fresh.content.contains(r"goes in C:\Users\jo"),
        "{}",
        fresh.content
    );
    assert_eq!(
        fresh.toggles,
        [Toggle::new("Put a shortcut on the desktop", false)]
    );
    assert_eq!(fresh.buttons, Buttons::OkCancel);

    let update = install_page(
        "2.0.0",
        &Existing::Recorded(Box::new(record("1.0.0"))),
        &dir,
        &[],
        &[Place::Startup],
    );
    assert_eq!(update.heading, "Update FactorSeal 1.0.0 to 2.0.0");
    assert!(
        update.content.contains("stopped first"),
        "{}",
        update.content
    );
    assert!(
        update
            .content
            .ends_with("Kept from the installed version: start when you sign in."),
        "{}",
        update.content
    );
    let again = install_page(
        "2.0.0",
        &Existing::Recorded(Box::new(record("2.0.0"))),
        &dir,
        &[],
        &[],
    );
    assert_eq!(again.heading, "Reinstall FactorSeal 2.0.0");
    let by_hand = install_page("2.0.0", &Existing::HandMade, &dir, &[], &[]);
    assert_eq!(
        by_hand.heading,
        "Take over FactorSeal and update it to 2.0.0"
    );
    assert!(
        by_hand.content.contains("UNINSTALL.txt goes"),
        "{}",
        by_hand.content
    );
}

#[test]
fn the_wsl_page_turns_on_the_distros_set_up_before() {
    let page = wsl_page(&lines(&["NixOS", "Ubuntu-24.04"]), &lines(&["nixos"]));
    assert_eq!(
        page.toggles,
        [
            Toggle::new("Set up NixOS", true),
            Toggle::new("Set up Ubuntu-24.04", false)
        ]
    );
    assert!(page.content.contains("starts it"), "{}", page.content);
    assert_eq!(Toggle::new("x", true).text(), "\u{2611}\u{FE0E} x");
    assert_eq!(Toggle::new("x", false).text(), "☐ x");
    assert_eq!(
        Toggle::new("x", false).with_note(r"C:\y").text(),
        "☐ x\nC:\\y"
    );
    assert_eq!(
        chosen(&lines(&["a", "b", "c"]), &[true, false, true]),
        ["a", "c"]
    );
}

#[test]
fn the_done_page_follows_the_exit_code() {
    let run = lines(&["release: x", "result: installed 2.0.0 in C:\\FactorSeal"]);
    let done = install_done(0, "2.0.0", &run, true);
    assert_eq!(done.heading, "FactorSeal 2.0.0 is installed");
    assert_eq!(done.content, "Installed 2.0.0 in C:\\FactorSeal.");
    assert_eq!(done.toggles, [Toggle::new("Open FactorSeal now", true)]);
    assert_eq!((done.icon, done.expanded), (Icon::App, false));
    assert_eq!(done.details.as_deref(), Some(run.join("\n").as_str()));
    assert_eq!(install_done(0, "2.0.0", &run, false).toggles, Vec::new());

    let wsl = install_done(
        8,
        "2.0.0",
        &lines(&["FactorSeal isn't installed in WSL distro Bare: …"]),
        true,
    );
    assert_eq!((wsl.icon, wsl.expanded), (Icon::Warning, true));
    assert_eq!(wsl.toggles.len(), 1);

    let running = install_done(
        7,
        "2.0.0",
        &lines(&["result: failed: FactorSeal still runs from C:\\x: factorseal.exe (process 4)"]),
        true,
    );
    assert_eq!(running.heading, "FactorSeal was not installed");
    assert_eq!(
        running.content,
        "FactorSeal still runs from C:\\x: factorseal.exe (process 4)."
    );
    assert_eq!((running.icon, running.expanded), (Icon::Error, true));
    assert_eq!(running.toggles, Vec::new());
    let silent = install_done(5, "2.0.0", &[], true);
    assert_eq!(silent.content, "The installer stopped without saying why.");
}

#[test]
fn the_uninstall_pages_offer_the_recorded_distros_and_the_listed_folders() {
    let mut installed = record("2.0.0");
    installed.distros = lines(&["NixOS"]);
    installed.uninstall.keep_note = Some("The vault stays.".to_owned());
    let dir = PathBuf::from(r"C:\FactorSeal");
    let page = uninstall_page(&installed, &dir, &lines(&[r"C:\Roaming\Factorseal"]));
    assert_eq!(page.heading, "Uninstall FactorSeal 2.0.0?");
    assert!(
        page.content.ends_with("\n\nThe vault stays."),
        "{}",
        page.content
    );
    assert_eq!(
        page.toggles,
        [
            Toggle::new(
                "Remove FactorSeal's setup from WSL distro NixOS (this starts it)",
                true
            ),
            Toggle::new("Also delete FactorSeal's settings", false)
                .with_note(r"C:\Roaming\Factorseal"),
        ]
    );
    assert_eq!(
        uninstall_page(&record("1.0.0"), &dir, &[]).toggles,
        Vec::new()
    );

    let done = uninstall_done(
        0,
        Some("The vault stays."),
        &lines(&["uninstalling", "The vault stays.", "result: uninstalled"]),
    );
    assert_eq!(
        (done.heading.as_str(), done.content.as_str()),
        ("FactorSeal is uninstalled", "The vault stays.")
    );
    assert_eq!(
        done.details.as_deref(),
        Some("uninstalling\nresult: uninstalled")
    );
    let partly = uninstall_done(
        5,
        None,
        &lines(&[
            "result: uninstalled FactorSeal 2.0.0 from C:\\x, but 1 thing(s) could not be removed; see above",
        ]),
    );
    assert_eq!(
        partly.heading,
        "FactorSeal is uninstalled, but not everything could be removed"
    );
    assert_eq!(
        partly.content,
        "Uninstalled FactorSeal 2.0.0 from C:\\x, but 1 thing(s) could not be removed."
    );
    assert_eq!(partly.icon, Icon::Warning);
    let refused = uninstall_done(
        9,
        None,
        &lines(&["result: refused: FactorSeal is not installed in C:\\x"]),
    );
    assert_eq!(
        (refused.heading.as_str(), refused.icon),
        ("FactorSeal was not uninstalled", Icon::Error)
    );
}
