use super::*;

use serde_json::{Value, json};

const DESKTOP: &[u8] = b"desktop executable";
const CLI: &[u8] = b"cli executable";
const LICENSE: &[u8] = b"license text";

fn sha(bytes: &[u8]) -> String {
    sha256_hex(bytes).unwrap().0
}

/// A manifest like the plan's sketch, for files with `DESKTOP`, `CLI` and
/// `LICENSE` as contents.
fn manifest() -> Value {
    json!({
        "schema": 1,
        "product": "FactorSeal",
        "version": "0.1.0+fdb0cb3",
        "requires_setup": 1,
        "files": [
            { "path": "factorseal-desktop.exe", "sha256": sha(DESKTOP) },
            { "path": "factorseal.exe", "sha256": sha(CLI) },
            { "path": "licenses/LICENSE.txt", "sha256": sha(LICENSE) },
        ],
        "stop": {
            "command": ["factorseal-desktop.exe", "--quit"],
            "also_stop": ["factorseal.exe"],
        },
        "steps": [
            { "install_files": {} },
            { "shortcut": {
                "name": "FactorSeal Desktop",
                "target": "factorseal-desktop.exe",
                "places": ["start-menu"],
                "optional_places": ["startup", "desktop"],
                "startup_args": ["--background"],
            } },
            { "registry": { "values": [{
                "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal",
                "name": "DisplayName",
                "value": "FactorSeal",
            }] } },
            { "wsl": {} },
            { "start": {
                "command": ["factorseal-desktop.exe", "--open", "wsl-keyrings"],
                "quiet_command": ["factorseal-desktop.exe", "--background"],
            } },
        ],
        "uninstall": {
            "registry_cleanup": [
                r"HKCU\Software\Microsoft\Edge\NativeMessagingHosts\dev.factorseal.browser",
            ],
            "ask_to_delete": [r"%APPDATA%\Factorseal"],
            "keep_note": r"The vault stays in %LOCALAPPDATA%\Factorseal.",
        },
    })
}

fn parse(value: &Value) -> Result<Manifest, ManifestError> {
    Manifest::parse(&serde_json::to_vec(value).unwrap())
}

/// The message of an `Invalid` refusal.
fn refusal(value: &Value) -> String {
    match parse(value) {
        Err(ManifestError::Invalid(message)) => message,
        other => panic!("expected an invalid manifest, got {other:?}"),
    }
}

/// A release folder holding the files and `manifest`.
fn release(manifest: &Value) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("factorseal-desktop.exe"), DESKTOP).unwrap();
    std::fs::write(dir.path().join("factorseal.exe"), CLI).unwrap();
    std::fs::create_dir(dir.path().join("licenses")).unwrap();
    std::fs::write(dir.path().join("licenses/LICENSE.txt"), LICENSE).unwrap();
    write_manifest(dir.path(), manifest);
    dir
}

fn write_manifest(dir: &Path, manifest: &Value) {
    std::fs::write(
        dir.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
}

fn open(dir: &Path) -> Result<Release, ManifestError> {
    Release::open(&dir.join(MANIFEST_FILE))
}

#[test]
fn the_sketched_manifest_verifies_with_every_file_hashed() {
    let dir = release(&manifest());
    let release = open(dir.path()).unwrap();
    assert_eq!(release.manifest.version, "0.1.0+fdb0cb3");
    assert_eq!(release.files.len(), 3);
    assert_eq!(release.files[2].path, "licenses/LICENSE.txt");
    assert_eq!(release.files[2].sha256, sha(LICENSE));
    assert_eq!(release.files[2].len, LICENSE.len() as u64);
    assert!(release.files[2].source.starts_with(&release.dir));
    // What install.json will record round-trips.
    let again: Manifest =
        serde_json::from_str(&serde_json::to_string(&release.manifest).unwrap()).unwrap();
    assert_eq!(again, release.manifest);
}

/// A new FactorSeal version is a new manifest, not a new installer: other
/// version, files added and changed, the same schema-1 vocabulary.
#[test]
fn a_later_release_installs_with_this_unchanged_installer() {
    let mut later = manifest();
    later["version"] = json!("0.2.0+abc1234");
    later["files"][0]["sha256"] = json!(sha(b"desktop executable, version 2"));
    later["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "path": "factorseal-wsl-broker.exe", "sha256": sha(b"broker") }));
    later["stop"]["also_stop"]
        .as_array_mut()
        .unwrap()
        .push(json!("factorseal-wsl-broker.exe"));
    let dir = release(&later);
    std::fs::write(
        dir.path().join("factorseal-desktop.exe"),
        b"desktop executable, version 2",
    )
    .unwrap();
    std::fs::write(dir.path().join("factorseal-wsl-broker.exe"), b"broker").unwrap();
    let release = open(dir.path()).unwrap();
    assert_eq!(release.manifest.version, "0.2.0+abc1234");
    assert_eq!(release.files.len(), 4);
}

#[test]
fn a_release_needing_a_newer_installer_is_refused_as_such() {
    let mut newer = manifest();
    newer["requires_setup"] = json!(SETUP_CAPABILITY + 1);
    // What a newer installer may know: new steps, fields, a new schema.
    newer["steps"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({ "service": { "name": "x" } }));
    newer["signature"] = json!("…");
    newer["schema"] = json!(2);
    match parse(&newer) {
        Err(ManifestError::NeedsNewerSetup {
            required,
            supported,
        }) => {
            assert_eq!(required, u64::from(SETUP_CAPABILITY) + 1);
            assert_eq!(supported, SETUP_CAPABILITY);
        }
        other => panic!("expected NeedsNewerSetup, got {other:?}"),
    }
    let message = parse(&newer).unwrap_err().to_string();
    assert!(message.contains("needs a newer installer"), "{message}");
}

#[test]
fn unknown_schemas_steps_and_fields_are_refused() {
    let mut schema = manifest();
    schema["schema"] = json!(2);
    assert!(refusal(&schema).contains("schema 2"));

    let mut step = manifest();
    step["steps"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({ "run": { "command": ["cmd.exe"] } }));
    assert!(refusal(&step).contains("unknown variant `run`"));

    let mut field = manifest();
    field["post_install"] = json!("cmd.exe");
    assert!(refusal(&field).contains("unknown field `post_install`"));

    let mut nested = manifest();
    nested["steps"][4]["start"]["shell"] = json!(true);
    assert!(refusal(&nested).contains("unknown field `shell`"));

    let mut missing = manifest();
    missing.as_object_mut().unwrap().remove("requires_setup");
    assert!(refusal(&missing).contains("requires_setup"));

    assert!(matches!(
        Manifest::parse(b"not json"),
        Err(ManifestError::Invalid(_))
    ));
}

#[test]
fn product_and_version_are_checked() {
    let mut product = manifest();
    product["product"] = json!("Other");
    assert!(refusal(&product).contains("product"));
    for version in ["", "1.0 beta", "1.0\n", &"9".repeat(65)] {
        let mut bad = manifest();
        bad["version"] = json!(version);
        assert!(refusal(&bad).contains("not a version"), "{version:?}");
    }
}

#[test]
fn file_paths_stay_inside_the_release_folder() {
    for path in [
        "../factorseal.exe",
        "licenses/../../x.exe",
        "/factorseal.exe",
        "C:/Windows/System32/cmd.exe",
        "c:cmd.exe",
        r"licenses\LICENSE.txt",
        "./factorseal.exe",
        "licenses//LICENSE.txt",
        "licenses/",
        "",
        "factorseal.exe.",
        "factorseal.exe ",
        "factorseal.exe:stream",
        "NUL.exe",
        "con",
        "lpt1.txt",
        "COM9",
        "a\u{1}.exe",
        "a*.exe",
    ] {
        let mut bad = manifest();
        bad["files"][2]["path"] = json!(path);
        assert!(refusal(&bad).contains("file path"), "{path:?} was accepted");
    }
    // Names that only look like devices are fine.
    let mut fine = manifest();
    fine["files"][2]["path"] = json!("licenses/COM10.txt");
    parse(&fine).unwrap();
    fine["files"][2]["path"] = json!("licenses/conan.txt");
    parse(&fine).unwrap();
    fine["files"][2]["path"] = json!("licenses/Ñull.txt");
    parse(&fine).unwrap();
}

#[test]
fn files_are_listed_once_with_a_hash() {
    let mut twice = manifest();
    twice["files"][2]["path"] = json!("FactorSeal.EXE");
    assert!(refusal(&twice).contains("listed twice"));

    for hash in ["", "abc", &"A".repeat(64), &"g".repeat(64)] {
        let mut bad = manifest();
        bad["files"][0]["sha256"] = json!(hash);
        assert!(refusal(&bad).contains("sha256"), "{hash:?}");
    }

    let mut none = manifest();
    none["files"] = json!([]);
    assert!(refusal(&none).contains("no files"));
}

#[test]
fn commands_run_only_release_executables() {
    let cases: [(&str, Value); 8] = [
        ("/stop/command", json!(["cmd.exe", "/c", "del"])),
        ("/stop/command", json!([])),
        ("/stop/command", json!([r"C:\Windows\System32\cmd.exe"])),
        ("/stop/also_stop", json!(["explorer.exe"])),
        // Listed, but not an executable.
        ("/steps/4/start/command", json!(["licenses/LICENSE.txt"])),
        ("/steps/4/start/quiet_command", json!(["powershell.exe"])),
        ("/steps/1/shortcut/target", json!("cmd.exe")),
        (
            "/steps/1/shortcut/target",
            json!("../factorseal-desktop.exe"),
        ),
    ];
    for (pointer, value) in cases {
        let mut bad = manifest();
        *bad.pointer_mut(pointer).unwrap() = value.clone();
        let message = refusal(&bad);
        assert!(
            message.contains("not an executable of the release") || message.contains("empty"),
            "{pointer} = {value}: {message}"
        );
    }
    // Case doesn't matter on Windows.
    let mut case = manifest();
    case["stop"]["command"][0] = json!("FactorSeal-Desktop.EXE");
    parse(&case).unwrap();
}

#[test]
fn shortcuts_have_plain_names_and_places_once() {
    for name in [
        "",
        r"..\..\Startup\evil",
        "a/b",
        "a:b",
        "trailing.",
        &"x".repeat(101),
    ] {
        let mut bad = manifest();
        bad["steps"][1]["shortcut"]["name"] = json!(name);
        assert!(refusal(&bad).contains("shortcut name"), "{name:?}");
    }
    let mut twice = manifest();
    twice["steps"][1]["shortcut"]["optional_places"] = json!(["start-menu"]);
    assert!(refusal(&twice).contains("listed twice"));
    let mut place = manifest();
    place["steps"][1]["shortcut"]["places"] = json!(["system32"]);
    assert!(refusal(&place).contains("unknown variant `system32`"));
}

#[test]
fn steps_copy_first_and_start_last() {
    let steps = |value: Value| {
        let mut bad = manifest();
        bad["steps"] = value;
        refusal(&bad)
    };
    let start = json!({ "start": { "command": ["factorseal-desktop.exe"] } });
    assert!(steps(json!([{ "wsl": {} }])).contains("install_files"));
    assert!(steps(json!([{ "wsl": {} }, { "install_files": {} }])).contains("install_files"));
    assert!(
        steps(json!([{ "install_files": {} }, { "install_files": {} }])).contains("install_files")
    );
    assert!(steps(json!([{ "install_files": {} }, start, { "wsl": {} }])).contains("start"));
    assert!(steps(json!([{ "install_files": {} }, start, start])).contains("start"));
    assert!(steps(json!([{ "install_files": {} }, { "wsl": {} }, { "wsl": {} }])).contains("wsl"));
    // The smallest release: copy the files, nothing else.
    let mut minimal = manifest();
    minimal["steps"] = json!([{ "install_files": {} }]);
    minimal.as_object_mut().unwrap().remove("stop");
    minimal.as_object_mut().unwrap().remove("uninstall");
    parse(&minimal).unwrap();
}

#[test]
fn registry_keys_stay_under_the_listed_prefixes() {
    let accepted = [
        r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser",
        r"hkcu\software\google\chrome\nativemessaginghosts\dev.factorseal.browser",
        r"HKCU\Software\Chromium\NativeMessagingHosts\dev.factorseal.browser\Sub",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal",
    ];
    let refused = [
        r"HKLM\Software\Microsoft\Edge\NativeMessagingHosts\dev.factorseal.browser",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSealEvil",
        r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser.evil",
        r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser\..\other",
        r"HKCU\Software\Mozilla\NativeMessagingHosts\dev.factorseal.browser\\x",
        "HKCU/Software/Mozilla/NativeMessagingHosts/dev.factorseal.browser",
        "",
    ];
    for (key, ok) in accepted
        .iter()
        .map(|key| (key, true))
        .chain(refused.iter().map(|key| (key, false)))
    {
        for pointer in [
            "/uninstall/registry_cleanup/0",
            "/steps/2/registry/values/0/key",
        ] {
            let mut candidate = manifest();
            *candidate.pointer_mut(pointer).unwrap() = json!(key);
            match parse(&candidate) {
                Ok(_) => assert!(ok, "{pointer} = {key} was accepted"),
                Err(ManifestError::Invalid(message)) => {
                    assert!(!ok, "{pointer} = {key}: {message}");
                    assert!(message.contains("registry key"), "{message}");
                }
                Err(other) => panic!("{other:?}"),
            }
        }
    }
}

#[test]
fn ask_to_delete_stays_in_factorseals_folders_and_never_reaches_the_vault() {
    let accepted = [
        r"%APPDATA%\Factorseal",
        r"%appdata%\factorseal\Factorseal\config",
        r"%LOCALAPPDATA%\Factorseal\Factorseal\cache",
    ];
    let refused = [
        // The vault, a folder holding it, and a folder inside it.
        (r"%LOCALAPPDATA%\Factorseal", "vault"),
        (r"%LOCALAPPDATA%\Factorseal\Factorseal", "vault"),
        (r"%LOCALAPPDATA%\FACTORSEAL\factorseal\DATA", "vault"),
        (r"%LOCALAPPDATA%\Factorseal\Factorseal\data\keys", "vault"),
        (r"%LOCALAPPDATA%\Factorseal-check", "outside"),
        (r"%USERPROFILE%\Documents", "outside"),
        (r"%APPDATA%", "outside"),
        (r"C:\Users\me\AppData\Roaming\Factorseal", "outside"),
        (r"%APPDATA%\Factorseal\..\Microsoft", "plain path"),
        (r"%APPDATA%\Factorseal\%TEMP%", "plain path"),
        ("%APPDATA%/Factorseal", "plain path"),
        ("", "plain path"),
    ];
    for path in accepted {
        let mut fine = manifest();
        fine["uninstall"]["ask_to_delete"][0] = json!(path);
        parse(&fine).unwrap_or_else(|error| panic!("{path}: {error}"));
    }
    for (path, reason) in refused {
        let mut bad = manifest();
        bad["uninstall"]["ask_to_delete"][0] = json!(path);
        let message = refusal(&bad);
        assert!(message.contains(reason), "{path}: {message}");
    }
}

#[test]
fn every_file_is_hashed_before_the_release_is_accepted() {
    let dir = release(&manifest());
    // The last file listed differs: nothing is accepted.
    std::fs::write(dir.path().join("licenses/LICENSE.txt"), b"changed").unwrap();
    match open(dir.path()) {
        Err(ManifestError::HashMismatch(path)) => assert_eq!(path, "licenses/LICENSE.txt"),
        other => panic!("expected a hash mismatch, got {other:?}"),
    }
}

#[test]
fn missing_files_and_folders_are_refused() {
    let dir = release(&manifest());
    std::fs::remove_file(dir.path().join("factorseal.exe")).unwrap();
    let error = open(dir.path()).unwrap_err().to_string();
    assert!(error.contains("factorseal.exe: is missing"), "{error}");

    let dir = release(&manifest());
    std::fs::remove_file(dir.path().join("factorseal.exe")).unwrap();
    std::fs::create_dir(dir.path().join("factorseal.exe")).unwrap();
    let error = open(dir.path()).unwrap_err().to_string();
    assert!(error.contains("is not a file"), "{error}");

    let missing = tempfile::tempdir().unwrap();
    assert!(matches!(
        open(missing.path()),
        Err(ManifestError::Io { .. })
    ));

    let big = tempfile::tempdir().unwrap();
    std::fs::write(
        big.path().join(MANIFEST_FILE),
        vec![b' '; usize::try_from(MAX_MANIFEST_BYTES).unwrap() + 1],
    )
    .unwrap();
    assert!(open(big.path()).unwrap_err().to_string().contains("1 MiB"));
}

#[cfg(unix)]
#[test]
fn files_reached_through_links_are_refused() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("LICENSE.txt"), LICENSE).unwrap();

    // The file itself is a link, even to identical content.
    let dir = release(&manifest());
    let file = dir.path().join("licenses/LICENSE.txt");
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(outside.path().join("LICENSE.txt"), &file).unwrap();
    let error = open(dir.path()).unwrap_err().to_string();
    assert!(error.contains("through a link"), "{error}");

    // A folder on the way is a link.
    let dir = release(&manifest());
    std::fs::remove_dir_all(dir.path().join("licenses")).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("licenses")).unwrap();
    let error = open(dir.path()).unwrap_err().to_string();
    assert!(error.contains("through a link"), "{error}");

    // A link inside the release, to a file of the release, is refused too:
    // links aren't followed at all.
    let dir = release(&manifest());
    std::fs::remove_file(dir.path().join("factorseal.exe")).unwrap();
    std::os::unix::fs::symlink(
        dir.path().join("factorseal-desktop.exe"),
        dir.path().join("factorseal.exe"),
    )
    .unwrap();
    assert!(
        open(dir.path())
            .unwrap_err()
            .to_string()
            .contains("through a link")
    );
}

/// A release folder that is itself reached through a link is fine: the
/// check is about files leading out of the folder, which is resolved first.
#[cfg(unix)]
#[test]
fn a_linked_release_folder_is_resolved_first() {
    let dir = release(&manifest());
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("release");
    std::os::unix::fs::symlink(dir.path(), &link).unwrap();
    let release = open(&link).unwrap();
    assert_eq!(release.dir, dir.path().canonicalize().unwrap());
}

/// Windows: a junction (which needs no privilege, unlike a symbolic link)
/// for a folder of the release leads out of it and is refused.
#[cfg(windows)]
#[test]
fn files_reached_through_a_junction_are_refused() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("LICENSE.txt"), LICENSE).unwrap();
    let dir = release(&manifest());
    let licenses = dir.path().join("licenses");
    std::fs::remove_dir_all(&licenses).unwrap();
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&licenses)
        .arg(outside.path())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");
    let error = open(dir.path()).unwrap_err().to_string();
    assert!(
        error.contains("through a link") || error.contains("outside the release folder"),
        "{error}"
    );
}
