use std::cell::RefCell;
use std::rc::Rc;

use serde_json::{Value, json};

use super::*;
use crate::manifest::{MANIFEST_FILE, Stop, Uninstall};
use crate::record::{RECORD_FORMAT, RecordedFile};

const DESKTOP: &str = "factorseal-desktop.exe";
const WORKER: &str = "factorseal.exe";
const BROKER: &str = "factorseal-wsl-broker.exe";

/// What a fake process does.
#[derive(Clone, Copy, Default)]
struct Behaviour {
    quits_on_command: bool,
    quits_when_asked: bool,
    terminable: bool,
}

#[derive(Default)]
struct World {
    running: Vec<(Holder, Behaviour)>,
    events: Vec<String>,
}

type Shared = Rc<RefCell<World>>;

fn runs(pid: u32, path: &str, behaviour: Behaviour) -> (Holder, Behaviour) {
    let name = path.rsplit('/').next().unwrap().to_owned();
    (
        Holder {
            pid,
            name,
            hold: Hold::Runs(path.to_owned()),
        },
        behaviour,
    )
}

const OBEYS: Behaviour = Behaviour {
    quits_on_command: true,
    quits_when_asked: true,
    terminable: false,
};
const ONLY_ASKED: Behaviour = Behaviour {
    quits_on_command: false,
    quits_when_asked: true,
    terminable: false,
};
const STAYS: Behaviour = Behaviour {
    quits_on_command: false,
    quits_when_asked: false,
    terminable: false,
};
const TERMINABLE: Behaviour = Behaviour {
    quits_on_command: false,
    quits_when_asked: false,
    terminable: true,
};

struct FakeProcesses(Shared);

impl Processes for FakeProcesses {
    fn holding(&mut self, _dir: &Path, _executables: &[String]) -> Vec<Holder> {
        self.0
            .borrow()
            .running
            .iter()
            .map(|(holder, _)| holder.clone())
            .collect()
    }

    fn terminate(&mut self, pid: u32) -> bool {
        let mut world = self.0.borrow_mut();
        let Some(index) = world.running.iter().position(|(h, _)| h.pid == pid) else {
            return false;
        };
        let (holder, behaviour) = world.running[index].clone();
        world.events.push(format!("terminate {}", holder.name));
        if behaviour.terminable {
            world.running.remove(index);
        }
        behaviour.terminable
    }
}

struct FakeRunner {
    world: Shared,
    result: Result<(), String>,
}

impl Runner for FakeRunner {
    fn run(&mut self, program: &Path, arguments: &[String], _: Duration) -> Result<(), String> {
        let mut world = self.world.borrow_mut();
        world.events.push(format!(
            "run {} {}",
            program.file_name().unwrap().to_string_lossy(),
            arguments.join(" ")
        ));
        if self.result.is_ok() {
            world
                .running
                .retain(|(_, behaviour)| !behaviour.quits_on_command);
        }
        self.result.clone()
    }
}

struct FakeUi(Shared);

impl Ui for FakeUi {
    fn say(&mut self, line: &str) {
        self.0.borrow_mut().events.push(format!("say {line}"));
    }

    fn ask_to_quit(&mut self, holders: &[Holder], _: Duration) {
        let mut world = self.0.borrow_mut();
        let names: Vec<&str> = holders.iter().map(|holder| holder.name.as_str()).collect();
        let line = format!("ask {}", names.join(" "));
        world.events.push(line);
        world
            .running
            .retain(|(_, behaviour)| !behaviour.quits_when_asked);
    }
}

const WAITS: Waits = Waits {
    command: Duration::from_secs(1),
    exit: Duration::from_millis(30),
    quit: Duration::from_millis(30),
    poll: Duration::from_millis(1),
};

/// Run `plan` against fake processes; the result and what happened.
fn stop(
    plan: &StopPlan,
    running: Vec<(Holder, Behaviour)>,
    command: Result<(), String>,
) -> (Result<Stopped, StopError>, Vec<String>, Vec<Holder>) {
    let world = Rc::new(RefCell::new(World {
        running,
        events: Vec::new(),
    }));
    let result = stop_running(
        plan,
        &mut FakeProcesses(world.clone()),
        &mut FakeRunner {
            world: world.clone(),
            result: command,
        },
        &mut FakeUi(world.clone()),
        &WAITS,
    );
    let world = Rc::try_unwrap(world).ok().unwrap().into_inner();
    let left = world
        .running
        .into_iter()
        .map(|(holder, _)| holder)
        .collect();
    (result, world.events, left)
}

/// An install folder with Desktop installed, and a release whose `stop`
/// is `stop`.
struct Setup {
    root: tempfile::TempDir,
}

impl Setup {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let install = root.path().join("FactorSeal");
        std::fs::create_dir_all(&install).unwrap();
        for name in [DESKTOP, WORKER, "factorseal-setup.exe", "README.txt"] {
            std::fs::write(install.join(name), name).unwrap();
        }
        Self { root }
    }

    fn install_dir(&self) -> PathBuf {
        self.root.path().join("FactorSeal")
    }

    fn release(&self, stop: Option<Value>) -> Release {
        let dir = self.root.path().join("release");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(DESKTOP), b"new desktop").unwrap();
        std::fs::write(dir.join(BROKER), b"new broker").unwrap();
        let mut manifest = json!({
            "schema": 1,
            "product": "FactorSeal",
            "version": "2.0.0",
            "requires_setup": 1,
            "files": [
                { "path": DESKTOP, "sha256": sha256_hex(&b"new desktop"[..]).unwrap().0 },
                { "path": BROKER, "sha256": sha256_hex(&b"new broker"[..]).unwrap().0 },
            ],
            "steps": [{ "install_files": {} }],
        });
        if let Some(stop) = stop {
            manifest["stop"] = stop;
        }
        std::fs::write(dir.join(MANIFEST_FILE), manifest.to_string()).unwrap();
        Release::open(&dir.join(MANIFEST_FILE)).unwrap()
    }
}

/// The record of the installed version, which stops with `stop`.
fn recorded(stop: Option<Stop>) -> Existing {
    Existing::Recorded(Box::new(InstallRecord {
        format: RECORD_FORMAT,
        version: "1.0.0".to_owned(),
        setup_version: "0.1.0".to_owned(),
        files: [DESKTOP, WORKER]
            .iter()
            .map(|name| RecordedFile {
                path: (*name).to_owned(),
                sha256: sha256_hex(name.as_bytes()).unwrap().0,
            })
            .collect(),
        shortcuts: Vec::new(),
        registry: Vec::new(),
        distros: Vec::new(),
        stop,
        uninstall: Uninstall::default(),
    }))
}

fn quit_stop(also_stop: &[&str]) -> Stop {
    Stop {
        command: vec![DESKTOP.to_owned(), "--quit".to_owned()],
        also_stop: also_stop.iter().map(|path| (*path).to_owned()).collect(),
    }
}

#[test]
fn nothing_running_stops_nothing() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[BROWSER_HOST])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    let (result, events, _) = stop(&plan, Vec::new(), Ok(()));
    assert_eq!(result.unwrap(), Stopped::NothingRan);
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn the_recorded_command_stops_desktop_and_also_stop_is_terminated() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[BROWSER_HOST])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    assert_eq!(
        plan.command.as_deref(),
        Some(&[DESKTOP.to_owned(), "--quit".to_owned()][..])
    );
    let (result, events, _) = stop(
        &plan,
        vec![
            runs(1, DESKTOP, OBEYS),
            runs(2, WORKER, OBEYS),
            runs(3, BROWSER_HOST, TERMINABLE),
        ],
        Ok(()),
    );
    assert_eq!(result.unwrap(), Stopped::ByCommand);
    assert_eq!(
        events,
        [
            "say stopping factorseal-browser.exe (process 3); a browser fill waiting for \
             FactorSeal is cancelled",
            "terminate factorseal-browser.exe",
            "say stopping FactorSeal with: factorseal-desktop.exe --quit",
            "run factorseal-desktop.exe --quit",
        ]
    );
}

#[test]
fn a_changed_stop_executable_is_not_run_and_the_user_is_asked() {
    let setup = Setup::new();
    std::fs::write(setup.install_dir().join(DESKTOP), b"replaced").unwrap();
    let existing = recorded(Some(quit_stop(&[])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    assert_eq!(plan.command, None);
    let (result, events, _) = stop(&plan, vec![runs(1, DESKTOP, OBEYS)], Ok(()));
    assert_eq!(result.unwrap(), Stopped::ByUser);
    assert_eq!(
        events,
        [
            "say factorseal-desktop.exe changed since it was installed",
            "ask factorseal-desktop.exe",
        ]
    );
}

#[test]
fn a_hand_made_install_asks_and_terminates_the_new_releases_also_stop() {
    let setup = Setup::new();
    let release = setup.release(Some(json!({
        "command": [DESKTOP, "--quit"],
        "also_stop": [BROKER],
    })));
    let plan = StopPlan::new(&setup.install_dir(), &Existing::HandMade, &release);
    assert_eq!(plan.command, None);
    assert_eq!(plan.also_stop, [BROKER]);
    let (result, events, _) = stop(
        &plan,
        vec![runs(1, DESKTOP, ONLY_ASKED), runs(2, BROKER, TERMINABLE)],
        Ok(()),
    );
    assert_eq!(result.unwrap(), Stopped::ByUser);
    assert_eq!(
        events,
        [
            "say stopping factorseal-wsl-broker.exe (process 2)",
            "terminate factorseal-wsl-broker.exe",
            "say FactorSeal was installed by hand, so the installer can't stop it",
            "ask factorseal-desktop.exe",
        ]
    );
}

#[test]
fn a_failed_stop_command_falls_back_to_asking() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    let (result, events, _) = stop(
        &plan,
        vec![runs(1, DESKTOP, OBEYS)],
        Err("it exited with exit code: 1".to_owned()),
    );
    assert_eq!(result.unwrap(), Stopped::ByUser);
    assert_eq!(
        events[1..],
        [
            "run factorseal-desktop.exe --quit",
            "say the stop command didn't stop FactorSeal: it exited with exit code: 1",
            "ask factorseal-desktop.exe",
        ]
    );
}

#[test]
fn what_still_runs_after_the_wait_is_named_and_nothing_is_changed() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    let terminal = Holder {
        pid: 7,
        name: "cmd.exe".to_owned(),
        hold: Hold::WorksIn,
    };
    let (result, events, left) = stop(
        &plan,
        vec![runs(1, DESKTOP, STAYS), (terminal, STAYS)],
        Ok(()),
    );
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains(
            "factorseal-desktop.exe (process 1), cmd.exe (process 7) works in the folder"
        ),
        "{error}"
    );
    assert!(error.contains("Nothing was changed"), "{error}");
    assert_eq!(left.len(), 2);
    assert_eq!(events.last().unwrap(), "ask factorseal-desktop.exe cmd.exe");
}

#[test]
fn only_also_stop_processes_are_terminated_without_asking() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[BROWSER_HOST, BROKER])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    let (result, events, _) = stop(&plan, vec![runs(4, BROKER, TERMINABLE)], Ok(()));
    assert_eq!(result.unwrap(), Stopped::Terminated);
    assert_eq!(
        events,
        [
            "say stopping factorseal-wsl-broker.exe (process 4)",
            "terminate factorseal-wsl-broker.exe",
        ]
    );
}

#[test]
fn a_process_that_refuses_to_terminate_is_reported_without_asking() {
    let setup = Setup::new();
    let existing = recorded(Some(quit_stop(&[BROWSER_HOST])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &setup.release(None));
    let elevated = Holder {
        pid: 5,
        name: BROWSER_HOST.to_owned(),
        hold: Hold::Unreadable,
    };
    let (result, events, _) = stop(
        &plan,
        vec![runs(1, DESKTOP, OBEYS), (elevated, STAYS)],
        Ok(()),
    );
    assert!(result.is_err());
    assert!(events.contains(&"say cannot stop factorseal-browser.exe (process 5)".to_owned()));
    assert!(
        !events.iter().any(|event| event.starts_with("ask")),
        "{events:?}"
    );
}

#[test]
fn the_plan_checks_what_the_record_says() {
    let setup = Setup::new();
    let release = setup.release(Some(json!({
        "command": [DESKTOP, "--quit"],
        "also_stop": [BROKER],
    })));
    // The record's paths are checked like the manifest's, and joined with
    // the release's without repeats.
    let existing = recorded(Some(quit_stop(&[
        BROWSER_HOST,
        "FACTORSEAL-WSL-BROKER.EXE",
        "../evil.exe",
        "notes.txt",
    ])));
    let plan = StopPlan::new(&setup.install_dir(), &existing, &release);
    assert_eq!(plan.also_stop, [BROWSER_HOST, "FACTORSEAL-WSL-BROKER.EXE"]);
    let mut executables = plan.executables.clone();
    executables.sort();
    assert_eq!(executables, [DESKTOP, WORKER]);

    let none = StopPlan::new(&setup.install_dir(), &recorded(None), &release);
    assert_eq!(none.command, None);
    assert_eq!(
        none.no_command.as_deref(),
        Some("FactorSeal 1.0.0 recorded no way to stop it")
    );
    let elsewhere = recorded(Some(Stop {
        command: vec!["../factorseal-desktop.exe".to_owned()],
        also_stop: Vec::new(),
    }));
    let plan = StopPlan::new(&setup.install_dir(), &elsewhere, &release);
    assert!(plan.no_command.unwrap().contains("not an installed file"));
    let fresh = StopPlan::new(&setup.install_dir(), &Existing::Fresh, &release);
    assert_eq!((fresh.command, fresh.no_command), (None, None));
}

/// A long-running process started from `program`, killed when dropped.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A program that runs until stopped (Unix: until its standard input
/// closes) and its arguments: a shell or ping (Windows).
fn long_runner() -> (PathBuf, Vec<&'static str>) {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap();
        (
            Path::new(&root).join("System32").join("PING.EXE"),
            vec!["-n", "60", "127.0.0.1"],
        )
    }
    #[cfg(not(windows))]
    {
        let sh = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join("sh"))
            .find(|path| path.is_file())
            .unwrap();
        // A builtin waiting on standard input: no child, which would
        // inherit the working directory.
        (sh.canonicalize().unwrap(), vec!["-c", "read line"])
    }
}

fn start(program: &Path, arguments: &[&str], cwd: &Path) -> Running {
    Running(
        std::process::Command::new(program)
            .args(arguments)
            .current_dir(cwd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn the_system_list_finds_what_runs_from_or_works_in_the_folder() {
    let setup = Setup::new();
    let install_dir = setup.install_dir();
    let (program, arguments) = long_runner();
    let host = install_dir.join(BROWSER_HOST);
    std::fs::copy(&program, &host).unwrap();
    let outside = setup.root.path();
    let mut from_folder = start(&host, &arguments, outside);
    let working_in = start(&program, &arguments, &install_dir);
    let _unrelated = start(&program, &arguments, outside);
    let working_pid = working_in.0.id();

    let mut processes = SystemProcesses::default();
    let mut expected = vec![
        Holder {
            pid: from_folder.0.id(),
            name: BROWSER_HOST.to_owned(),
            hold: Hold::Runs(BROWSER_HOST.to_owned()),
        },
        Holder {
            pid: working_pid,
            name: program.file_name().unwrap().to_string_lossy().into_owned(),
            hold: Hold::WorksIn,
        },
    ];
    expected.sort_by_key(|holder| holder.pid);
    assert_eq!(processes.holding(&install_dir, &[]), expected);

    // The real stop: the browser host is terminated, then only the
    // process working in the folder is left, and named.
    let plan = StopPlan {
        install_dir: install_dir.clone(),
        command: None,
        no_command: None,
        also_stop: vec![BROWSER_HOST.to_owned()],
        executables: Vec::new(),
    };
    let world = Rc::new(RefCell::new(World::default()));
    let result = stop_running(
        &plan,
        &mut processes,
        &mut FakeRunner {
            world: world.clone(),
            result: Ok(()),
        },
        &mut FakeUi(world.clone()),
        &Waits {
            exit: Duration::from_secs(5),
            quit: Duration::from_millis(200),
            ..WAITS
        },
    );
    assert!(from_folder.0.wait().is_ok_and(|status| !status.success()));
    match result {
        Err(StopError::StillRunning { holders, .. }) => {
            assert_eq!(
                holders.iter().map(|holder| holder.pid).collect::<Vec<_>>(),
                [working_pid]
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_command_runner_reports_the_exit_and_a_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let mut runner = CommandRunner {
        working_dir: dir.path().to_owned(),
    };
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/c")
    } else {
        ("sh", "-c")
    };
    let run = |runner: &mut CommandRunner, script: &str, timeout| {
        runner.run(
            Path::new(shell),
            &[flag.to_owned(), script.to_owned()],
            timeout,
        )
    };
    assert_eq!(run(&mut runner, "exit 0", Duration::from_secs(10)), Ok(()));
    let failed = run(&mut runner, "exit 3", Duration::from_secs(10)).unwrap_err();
    assert!(failed.contains('3'), "{failed}");
    let started = Instant::now();
    let slow = if cfg!(windows) {
        let ping = ["-n", "60", "127.0.0.1"].map(str::to_owned);
        runner.run(Path::new("ping"), &ping, Duration::from_millis(300))
    } else {
        run(&mut runner, "sleep 5", Duration::from_millis(300))
    }
    .unwrap_err();
    assert!(slow.contains("didn't return"), "{slow}");
    assert!(started.elapsed() < Duration::from_secs(10));
}
