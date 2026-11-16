use std::collections::HashMap;
use std::path::PathBuf;

use super::*;

/// A WSL whose distros answer as scripted, recording every call.
#[derive(Default)]
struct FakeWsl {
    answers: HashMap<(String, Line), Result<Output, String>>,
    calls: Vec<(String, Line, Vec<String>)>,
}

impl FakeWsl {
    fn answer(mut self, distro: &str, line: Line, answer: Result<Output, String>) -> Self {
        self.answers.insert((distro.to_owned(), line), answer);
        self
    }

    fn probe(self, distro: &str, found: bool, id: &str) -> Self {
        let stdout = format!(
            "factorseal={}\nid={id}\n",
            if found { "found" } else { "missing" }
        );
        self.answer(distro, Line::Probe, Ok(success(&stdout)))
    }
}

impl Wsl for FakeWsl {
    fn run(&mut self, distro: &str, line: Line, arguments: &[String]) -> Result<Output, String> {
        self.calls
            .push((distro.to_owned(), line, arguments.to_vec()));
        self.answers
            .get(&(distro.to_owned(), line))
            .cloned()
            .unwrap_or_else(|| Err(format!("unexpected {line:?} in {distro}")))
    }
}

fn success(stdout: &str) -> Output {
    Output {
        success: true,
        stdout: stdout.to_owned(),
        stderr: String::new(),
    }
}

fn failure(stderr: &str) -> Output {
    Output {
        success: false,
        stdout: String::new(),
        stderr: stderr.to_owned(),
    }
}

fn install_dir() -> PathBuf {
    PathBuf::from(r"C:\Users\Jo Ann\AppData\Local\Programs\FactorSeal")
}

fn names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn run(distros: &[&str], wsl: &mut FakeWsl) -> (Report, Vec<String>) {
    let mut said = Vec::new();
    let report = set_up(&names(distros), &install_dir(), wsl, &mut |line: &str| {
        said.push(line.to_owned());
    });
    (report, said)
}

#[test]
fn a_distro_with_factorseal_is_probed_then_set_up_with_the_install_folder_as_its_argument() {
    let mut wsl = FakeWsl::default().probe("NixOS", true, "nixos").answer(
        "NixOS",
        Line::Setup,
        Ok(success("Wrote /home/jo/.config/factorseal/wsl.json\n")),
    );
    let (report, said) = run(&["NixOS"], &mut wsl);
    assert_eq!(report.set_up, ["NixOS"]);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let install = install_dir().to_string_lossy().into_owned();
    assert_eq!(
        wsl.calls,
        [
            ("NixOS".to_owned(), Line::Probe, Vec::new()),
            ("NixOS".to_owned(), Line::Setup, vec![install]),
        ]
    );
    assert!(
        said.contains(&"NixOS: Wrote /home/jo/.config/factorseal/wsl.json".to_owned()),
        "{said:?}"
    );
    assert!(
        said.contains(&"set up WSL distro NixOS".to_owned()),
        "{said:?}"
    );
}

#[test]
fn a_distro_without_factorseal_gets_the_hint_for_its_os_release_id_not_its_name() {
    let mut wsl = FakeWsl::default()
        .probe("Work", false, "nixos")
        .probe("NixOS", false, "ubuntu");
    let (report, said) = run(&["Work", "NixOS"], &mut wsl);
    assert_eq!(report.set_up, Vec::<String>::new());
    let [work, named_nixos] = report.problems.as_slice() else {
        panic!("{:?}", report.problems);
    };
    assert!(work.contains("WSL distro Work"), "{work}");
    assert!(work.contains("NixOS configuration"), "{work}");
    assert!(work.contains("services.factorseal only after"), "{work}");
    assert!(
        named_nixos.contains("install FactorSeal in it"),
        "{named_nixos}"
    );
    assert!(
        !named_nixos.contains("NixOS configuration"),
        "{named_nixos}"
    );
    // Nothing but the probes ran, and the hints were said.
    assert!(wsl.calls.iter().all(|(_, line, _)| *line == Line::Probe));
    assert!(
        said.contains(work) && said.contains(named_nixos),
        "{said:?}"
    );
}

#[test]
fn a_failure_in_one_distro_is_reported_and_the_others_still_run() {
    let mut wsl = FakeWsl::default()
        .answer(
            "Gone",
            Line::Probe,
            Err("There is no distribution with the supplied name.".to_owned()),
        )
        .answer("Broken", Line::Probe, Ok(failure("sh: cannot start\n")))
        .probe("Old", true, "debian")
        .answer(
            "Old",
            Line::Setup,
            Ok(failure(
                "\nError: /mnt/c/x/factorseal-wsl-broker.exe is missing; pass --windows-install\n",
            )),
        )
        .probe("NixOS", true, "nixos")
        .answer("NixOS", Line::Setup, Ok(success("")));
    let (report, _) = run(&["Gone", "Broken", "Old", "NixOS"], &mut wsl);
    assert_eq!(report.set_up, ["NixOS"]);
    assert_eq!(
        report.problems,
        [
            "cannot reach WSL distro Gone: There is no distribution with the supplied name.",
            "cannot check WSL distro Broken: sh: cannot start",
            "setting up WSL distro Old failed: Error: /mnt/c/x/factorseal-wsl-broker.exe is \
             missing; pass --windows-install",
        ]
    );
}

#[test]
fn the_probe_reads_only_plain_ids() {
    assert_eq!(
        Probe::parse("factorseal=found\nid=nixos\n"),
        Probe {
            found: true,
            id: Some("nixos".to_owned())
        }
    );
    for odd in ["id=", "id=Ubuntu", "id=a b", "id=\"x\""] {
        assert_eq!(Probe::parse(odd).id, None, "{odd}");
    }
    assert!(!Probe::parse("factorseal=missing\n").found);
    assert!(!Probe::parse("factorseal=founder\n").found);
}

#[test]
fn distro_names_are_checked() {
    for good in ["NixOS", "Ubuntu-24.04", "my_distro"] {
        assert_eq!(check_distro(good), Ok(()), "{good}");
    }
    for bad in ["", ".", "..", "a b", "a;b", "x/y", &"n".repeat(65)] {
        assert!(check_distro(bad).is_err(), "{bad}");
    }
}

#[test]
fn wsl_text_is_read_as_utf8_or_utf16() {
    assert_eq!(decode("Olá\n".as_bytes()), "Olá\n");
    let utf16: Vec<u8> = "Não há distribuição"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(decode(&utf16), "Não há distribuição");
}

/// Unix: the fixed lines run by a real `sh`, through a stand-in for
/// `wsl.exe` that drops `-d <distro> --exec` and runs the rest with a
/// `PATH` holding only fake `factorseal` and `wslpath` commands (and `-l`
/// dropped, so the host's profile can't change that `PATH`).
#[cfg(unix)]
mod real_shell {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    /// `wsl.run`, holding the exec lock while it starts processes.
    fn run(
        wsl: &mut SystemWsl,
        distro: &str,
        line: Line,
        arguments: &[String],
    ) -> Result<Output, String> {
        let _exec = crate::exec_lock();
        wsl.run(distro, line, arguments)
    }

    fn executable(path: &Path, text: &str) {
        let _exec = crate::exec_lock();
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A stand-in `wsl.exe` in `root`, and the folder of fake commands.
    fn stand_in(root: &Path, with_factorseal: bool) -> SystemWsl {
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let calls = root.join("calls");
        if with_factorseal {
            executable(
                &bin.join("factorseal"),
                &format!(
                    "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\necho \"Wrote config\"\n",
                    calls.display()
                ),
            );
        }
        executable(
            &bin.join("wslpath"),
            "#!/bin/sh\n[ \"$1\" = -u ] || exit 2\nprintf '/mnt/c/%s\\n' \"$2\"\n",
        );
        let program = root.join("wsl.exe");
        executable(
            &program,
            &format!(
                "#!/bin/sh\n[ \"$1\" = -d ] && [ \"$3\" = --exec ] && [ \"$4\" = sh ] && [ \"$5\" = -lc ] || exit 9\n\
                 shift 5\nPATH='{}' exec /bin/sh -c \"$@\"\n",
                bin.display()
            ),
        );
        SystemWsl {
            program,
            working_dir: root.to_owned(),
            timeout: Duration::from_secs(20),
        }
    }

    #[test]
    fn the_setup_line_hands_the_install_folder_over_untouched() {
        let root = tempfile::tempdir().unwrap();
        let mut wsl = stand_in(root.path(), true);
        let probe = run(&mut wsl, "NixOS", Line::Probe, &[]).unwrap();
        assert!(probe.success, "{probe:?}");
        assert!(Probe::parse(&probe.stdout).found, "{probe:?}");

        // Spaces, quotes and shell syntax reach wslpath as one argument
        // and are never run.
        let folder = r#"Users\Jo Ann\$(touch pwned)'";x\FactorSeal"#;
        let setup = run(&mut wsl, "NixOS", Line::Setup, &[folder.to_owned()]).unwrap();
        assert!(setup.success, "{setup:?}");
        assert_eq!(setup.stdout, "Wrote config\n");
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert_eq!(
            calls.lines().collect::<Vec<_>>(),
            [
                "wsl-setup",
                "--windows-install",
                &format!("/mnt/c/{folder}")
            ]
        );
        assert!(!root.path().join("pwned").exists());

        run(&mut wsl, "NixOS", Line::Remove, &[]).unwrap();
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert_eq!(calls, "wsl-setup\n--remove\n");
    }

    #[test]
    fn without_factorseal_the_probe_says_missing_and_setup_fails() {
        let root = tempfile::tempdir().unwrap();
        let mut wsl = stand_in(root.path(), false);
        let probe = run(&mut wsl, "NixOS", Line::Probe, &[]).unwrap();
        assert!(probe.success, "{probe:?}");
        assert!(!Probe::parse(&probe.stdout).found, "{probe:?}");
        let setup = run(&mut wsl, "NixOS", Line::Setup, &["Users\\x".to_owned()]).unwrap();
        assert!(!setup.success, "{setup:?}");
        assert!(!setup.stderr.is_empty(), "{setup:?}");
    }

    #[test]
    fn a_line_that_hangs_is_killed_after_the_timeout() {
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("wsl.exe");
        executable(&program, "#!/bin/sh\nexec sleep 30\n");
        let mut wsl = SystemWsl {
            program,
            working_dir: root.path().to_owned(),
            timeout: Duration::from_secs(1),
        };
        let started = std::time::Instant::now();
        let error = run(&mut wsl, "NixOS", Line::Probe, &[]).unwrap_err();
        assert!(error.contains("didn't return in 1 s"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_bad_distro_name_never_reaches_wsl() {
        let root = tempfile::tempdir().unwrap();
        let mut wsl = stand_in(root.path(), true);
        assert!(run(&mut wsl, "a;b", Line::Probe, &[]).is_err());
    }
}

/// Windows, by hand: the probe in a real distro, and an argument passed
/// through `wsl.exe --exec` intact. Read-only in the distro. Run with
/// `FACTORSEAL_SETUP_WSL_DISTRO=NixOS cargo test -- --ignored real_distro`.
#[cfg(windows)]
#[test]
#[ignore = "needs a WSL distro; read-only"]
fn a_real_distro_runs_the_probe_and_gets_arguments_intact() {
    let distro = std::env::var("FACTORSEAL_SETUP_WSL_DISTRO").unwrap();
    let mut wsl = SystemWsl {
        program: PathBuf::from("wsl.exe"),
        working_dir: std::env::temp_dir(),
        timeout: LINE_TIMEOUT,
    };
    let probe = wsl.run(&distro, Line::Probe, &[]).unwrap();
    eprintln!("probe: {probe:?}");
    assert!(probe.success, "{probe:?}");
    eprintln!("parsed: {:?}", Probe::parse(&probe.stdout));

    let folder = r"C:\Users\Jo Ann\O'Neil & Co\100%\$(x)\FactorSeal".to_owned();
    let echoed = wsl
        .output(wsl.command(
            &distro,
            "printf '%s\\n' \"$1\"; wslpath -u \"$1\"",
            std::slice::from_ref(&folder),
        ))
        .unwrap();
    eprintln!("echoed: {echoed:?}");
    assert!(echoed.success, "{echoed:?}");
    let mut lines = echoed.stdout.lines();
    assert_eq!(lines.next(), Some(folder.as_str()));
    assert_eq!(
        lines.next(),
        Some("/mnt/c/Users/Jo Ann/O'Neil & Co/100%/$(x)/FactorSeal")
    );
    let missing = wsl.run("NoSuchDistro-fs", Line::Probe, &[]);
    eprintln!("missing distro: {missing:?}");
    assert!(missing.is_ok_and(|output| !output.success));
}
