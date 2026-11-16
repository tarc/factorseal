//! Stopping the installed version before its files change (Flows, step 4,
//! of `docs/plans/windows-installer.md`).
//!
//! The installed version is stopped the way it recorded, never the way the
//! new release says: `install.json` holds the stop command of the manifest
//! that installed it, and that command's executable must still match the
//! hash recorded for it. Without such a command (a hand-made install, a
//! record without one, a changed executable, or a command that failed),
//! the installer asks the user to quit FactorSeal from its tray icon. Our
//! scripts' tray-click simulation is not used: it relies on gpui-tray's
//! private message number, which a fixed installer can't follow.
//!
//! Either way the installer then waits for every process that holds the
//! install folder: one running an executable from it, or one working in
//! it, which would stop the swap (step 4's finding). The `also_stop`
//! executables (the browser host, the WSL broker) are terminated instead,
//! each time they appear, since programs outside FactorSeal start them on
//! demand. Desktop and the vault worker are never terminated: quitting
//! seals the vault first.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::manifest::{Release, SETUP_EXE, check_release_path, sha256_hex};
use crate::record::{Existing, InstallRecord};

/// The browser host: stopping it cancels a browser fill waiting for
/// FactorSeal, which the installer says first.
pub const BROWSER_HOST: &str = "factorseal-browser.exe";

/// A process that keeps the install folder in use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    /// The executable's file name.
    pub name: String,
    pub hold: Hold,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Runs this executable from the folder, as a `/`-separated path
    /// inside it.
    Runs(String),
    /// Works in the folder (its current directory is there).
    WorksIn,
    /// Its path can't be read (it runs elevated), and its name is one of
    /// the folder's executables.
    Unreadable,
}

/// The processes of the system, behind a trait for tests.
pub trait Processes {
    /// The processes holding `dir`, other than this one and installers.
    /// `executables` are the file names of the folder's executables, for
    /// processes whose path can't be read.
    fn holding(&mut self, dir: &Path, executables: &[String]) -> Vec<Holder>;
    /// Terminate a process; whether that worked.
    fn terminate(&mut self, pid: u32) -> bool;
}

/// Runs the recorded stop command, behind a trait for tests.
pub trait Runner {
    /// Run `program` with `arguments` and wait for it, at most `timeout`;
    /// `Ok` when it exited successfully, why not otherwise.
    fn run(
        &mut self,
        program: &Path,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<(), String>;
}

/// What the user is told: a dialog, or the log under `--quiet`.
pub trait Ui {
    fn say(&mut self, line: &str);
    /// Ask the user to quit FactorSeal from its tray icon. `holders` are
    /// what still holds the folder; the installer waits `wait` for them.
    fn ask_to_quit(&mut self, holders: &[Holder], wait: Duration);
}

/// How long each wait lasts.
#[derive(Clone, Copy, Debug)]
pub struct Waits {
    /// For the stop command to return (Desktop's `--quit` waits up to 30 s
    /// itself).
    pub command: Duration,
    /// For the folder's processes to exit after the stop command, and for
    /// terminated ones to go.
    pub exit: Duration,
    /// For the user to quit FactorSeal from its tray icon.
    pub quit: Duration,
    /// Between looks at the processes.
    pub poll: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Self {
            command: Duration::from_secs(45),
            exit: Duration::from_secs(15),
            quit: Duration::from_secs(300),
            poll: Duration::from_millis(250),
        }
    }
}

/// How the installed version was stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    /// Nothing held the install folder.
    NothingRan,
    /// Only `also_stop` processes ran, and they were terminated.
    Terminated,
    /// By the recorded stop command.
    ByCommand,
    /// By the user, after the installer asked.
    ByUser,
}

#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error(
        "FactorSeal still runs from {}: {}. Nothing was changed; quit it and try again",
        dir.display(),
        describe(holders)
    )]
    StillRunning { dir: PathBuf, holders: Vec<Holder> },
}

/// How to stop what runs from an install folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopPlan {
    pub install_dir: PathBuf,
    /// The recorded stop command, its executable checked against the
    /// record; `None` asks the user instead.
    pub command: Option<Vec<String>>,
    /// Why there is no command, for the user.
    pub no_command: Option<String>,
    /// The executables terminated instead of waited for: the record's
    /// `also_stop` and the new release's, as paths inside the folder.
    pub also_stop: Vec<String>,
    /// The file names of the folder's executables.
    pub executables: Vec<String>,
}

impl StopPlan {
    /// The plan for `install_dir`, holding what `existing` found, before
    /// installing `release`.
    #[must_use]
    pub fn new(install_dir: &Path, existing: &Existing, release: &Release) -> Self {
        let new_also_stop = release
            .manifest
            .stop
            .as_ref()
            .map(|stop| stop.also_stop.clone())
            .unwrap_or_default();
        Self::with_also_stop(install_dir, existing, new_also_stop)
    }

    /// The plan for uninstalling the install `record` describes: only what
    /// it recorded.
    #[must_use]
    pub fn for_uninstall(install_dir: &Path, record: &InstallRecord) -> Self {
        Self::with_also_stop(
            install_dir,
            &Existing::Recorded(Box::new(record.clone())),
            Vec::new(),
        )
    }

    fn with_also_stop(install_dir: &Path, existing: &Existing, new_also_stop: Vec<String>) -> Self {
        let (command, no_command, recorded_also_stop) = match existing {
            Existing::Recorded(record) => {
                let also_stop = record
                    .stop
                    .as_ref()
                    .map(|stop| stop.also_stop.clone())
                    .unwrap_or_default();
                match verified_command(install_dir, record) {
                    Ok(command) => (Some(command), None, also_stop),
                    Err(why) => (None, Some(why), also_stop),
                }
            }
            Existing::HandMade => (
                None,
                Some("FactorSeal was installed by hand, so the installer can't stop it".to_owned()),
                Vec::new(),
            ),
            Existing::Fresh => (None, None, Vec::new()),
        };
        let mut also_stop: Vec<String> = Vec::new();
        for path in recorded_also_stop.into_iter().chain(new_also_stop) {
            // The record lives in the user's folder: its paths are checked
            // as the manifest's were.
            let plain = check_release_path(&path).is_ok() && is_exe(&path);
            if plain
                && !also_stop
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&path))
            {
                also_stop.push(path);
            }
        }
        Self {
            install_dir: install_dir.to_owned(),
            command,
            no_command,
            also_stop,
            executables: executables(install_dir),
        }
    }

    /// Whether `holder` is terminated rather than waited for.
    fn terminates(&self, holder: &Holder) -> bool {
        match &holder.hold {
            Hold::Runs(path) => self
                .also_stop
                .iter()
                .any(|stop| stop.eq_ignore_ascii_case(path)),
            Hold::Unreadable => self.also_stop.iter().any(|stop| {
                stop.rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&holder.name))
            }),
            Hold::WorksIn => false,
        }
    }
}

fn is_exe(path: &str) -> bool {
    path.len() > 4
        && path
            .get(path.len() - 4..)
            .is_some_and(|end| end.eq_ignore_ascii_case(".exe"))
}

/// The installed copy of the release file `path`.
fn installed(install_dir: &Path, path: &str) -> PathBuf {
    path.split('/')
        .fold(install_dir.to_owned(), |path, part| path.join(part))
}

/// The record's stop command, if its executable is still the one the
/// record lists.
fn verified_command(install_dir: &Path, record: &InstallRecord) -> Result<Vec<String>, String> {
    let Some(stop) = &record.stop else {
        return Err(format!(
            "FactorSeal {} recorded no way to stop it",
            record.version
        ));
    };
    let Some(program) = stop.command.first() else {
        return Err("the recorded stop command is empty".to_owned());
    };
    let recorded = record
        .files
        .iter()
        .find(|file| file.path.eq_ignore_ascii_case(program))
        .filter(|_| check_release_path(program).is_ok() && is_exe(program))
        .ok_or_else(|| {
            format!("the recorded stop command runs {program}, not an installed file")
        })?;
    let path = installed(install_dir, program);
    let hash = std::fs::File::open(&path)
        .and_then(sha256_hex)
        .map_err(|error| format!("cannot check {}: {error}", path.display()))?
        .0;
    if hash != recorded.sha256 {
        return Err(format!("{program} changed since it was installed"));
    }
    Ok(stop.command.clone())
}

/// The file names of the executables in `install_dir`, the installer's
/// own left out.
fn executables(install_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(install_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| is_exe(name) && !name.eq_ignore_ascii_case(SETUP_EXE))
        .collect()
}

/// `holders` as a list for the user.
#[must_use]
pub fn describe(holders: &[Holder]) -> String {
    holders
        .iter()
        .map(|holder| match holder.hold {
            Hold::WorksIn => format!(
                "{} (process {}) works in the folder",
                holder.name, holder.pid
            ),
            Hold::Runs(_) | Hold::Unreadable => {
                format!("{} (process {})", holder.name, holder.pid)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The fallback's request, for the log or a dialog.
#[must_use]
pub fn ask_text(holders: &[Holder], wait: Duration) -> String {
    format!(
        "quit FactorSeal from its tray icon (right-click it, then Quit), and close any program \
         working in its folder; waiting up to {} s for: {}",
        wait.as_secs(),
        describe(holders)
    )
}

/// Stop what runs from `plan.install_dir`, as the plan says.
pub fn stop_running(
    plan: &StopPlan,
    processes: &mut dyn Processes,
    runner: &mut dyn Runner,
    ui: &mut dyn Ui,
    waits: &Waits,
) -> Result<Stopped, StopError> {
    let mut stopper = Stopper {
        plan,
        processes,
        ui,
        waits,
        announced: HashSet::new(),
    };
    let holders = stopper.sweep();
    if holders.is_empty() {
        return Ok(Stopped::NothingRan);
    }
    if holders.iter().all(|holder| plan.terminates(holder)) {
        let left = stopper.wait(waits.exit);
        return if left.is_empty() {
            Ok(Stopped::Terminated)
        } else {
            Err(stopper.still_running(left))
        };
    }
    match (&plan.command, &plan.no_command) {
        (Some(command), _) => {
            if let Some((program, arguments)) = command.split_first() {
                stopper.ui.say(&format!(
                    "stopping FactorSeal with: {}",
                    crate::shortcut::command_line(command)
                ));
                let program = installed(&plan.install_dir, program);
                match runner.run(&program, arguments, waits.command) {
                    Ok(()) => {
                        if stopper.wait(waits.exit).is_empty() {
                            return Ok(Stopped::ByCommand);
                        }
                    }
                    Err(why) => stopper
                        .ui
                        .say(&format!("the stop command didn't stop FactorSeal: {why}")),
                }
            }
        }
        (None, Some(why)) => stopper.ui.say(why),
        (None, None) => {}
    }
    let left = stopper.sweep();
    let waited: Vec<Holder> = left
        .iter()
        .filter(|holder| !plan.terminates(holder))
        .cloned()
        .collect();
    // Only processes that refused to terminate left: no point asking.
    let wait = if waited.is_empty() {
        waits.exit
    } else {
        stopper.ui.ask_to_quit(&waited, waits.quit);
        waits.quit
    };
    let left = stopper.wait(wait);
    if left.is_empty() {
        Ok(Stopped::ByUser)
    } else {
        Err(stopper.still_running(left))
    }
}

struct Stopper<'a> {
    plan: &'a StopPlan,
    processes: &'a mut dyn Processes,
    ui: &'a mut dyn Ui,
    waits: &'a Waits,
    /// Processes already announced as terminated.
    announced: HashSet<u32>,
}

impl Stopper<'_> {
    /// What holds the folder now, after terminating the `also_stop`
    /// processes among it (which may still show until they are gone).
    fn sweep(&mut self) -> Vec<Holder> {
        let holders = self
            .processes
            .holding(&self.plan.install_dir, &self.plan.executables);
        for holder in &holders {
            if !self.plan.terminates(holder) {
                continue;
            }
            if self.announced.insert(holder.pid) {
                let mut line = format!("stopping {} (process {})", holder.name, holder.pid);
                if holder.name.eq_ignore_ascii_case(BROWSER_HOST) {
                    line.push_str("; a browser fill waiting for FactorSeal is cancelled");
                }
                self.ui.say(&line);
            }
            if !self.processes.terminate(holder.pid) {
                self.ui.say(&format!(
                    "cannot stop {} (process {})",
                    holder.name, holder.pid
                ));
            }
        }
        holders
    }

    /// Sweep until nothing holds the folder or `wait` passes; what is left.
    fn wait(&mut self, wait: Duration) -> Vec<Holder> {
        let deadline = Instant::now() + wait;
        loop {
            let left = self.sweep();
            if left.is_empty() || Instant::now() >= deadline {
                return left;
            }
            std::thread::sleep(self.waits.poll);
        }
    }

    fn still_running(&self, holders: Vec<Holder>) -> StopError {
        StopError::StillRunning {
            dir: self.plan.install_dir.clone(),
            holders,
        }
    }
}

/// The system's processes, through `sysinfo`.
pub struct SystemProcesses {
    system: sysinfo::System,
}

impl Default for SystemProcesses {
    fn default() -> Self {
        Self {
            system: sysinfo::System::new(),
        }
    }
}

/// A path as compared here: without the `\\?\` prefix canonical paths get
/// on Windows, and there without regard to case.
fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    if cfg!(windows) {
        text.replace('/', "\\").to_lowercase()
    } else {
        text.to_owned()
    }
}

/// `path` inside the folder whose key is `dir`, `/`-separated.
fn inside(path: &Path, dir: &str) -> Option<String> {
    let key = path_key(path);
    let rest = key.strip_prefix(dir)?;
    let rest = rest.strip_prefix(std::path::MAIN_SEPARATOR)?;
    Some(rest.replace('\\', "/"))
}

impl Processes for SystemProcesses {
    fn holding(&mut self, dir: &Path, executables: &[String]) -> Vec<Holder> {
        use sysinfo::{ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, UpdateKind};
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::Always),
        );
        let own = std::process::id();
        let dir = path_key(&dir.canonicalize().unwrap_or_else(|_| dir.to_owned()));
        let mut holders = Vec::new();
        for (pid, process) in self.system.processes() {
            let pid = pid.as_u32();
            if pid == own
                || process.thread_kind().is_some()
                || process.status() == ProcessStatus::Zombie
            {
                continue;
            }
            let exe = process.exe().filter(|exe| !exe.as_os_str().is_empty());
            let name = exe
                .and_then(Path::file_name)
                .unwrap_or_else(|| process.name())
                .to_string_lossy()
                .into_owned();
            if name.eq_ignore_ascii_case(SETUP_EXE) {
                // An installer run from the folder that relaunched this
                // copy, and is exiting.
                continue;
            }
            let hold = match exe {
                Some(exe) => inside(exe, &dir).map(Hold::Runs),
                // Only Windows hides a path (an elevated process); a Linux
                // process without one is a kernel thread.
                None if cfg!(windows)
                    && executables
                        .iter()
                        .any(|known| known.eq_ignore_ascii_case(&name)) =>
                {
                    Some(Hold::Unreadable)
                }
                None => None,
            }
            .or_else(|| {
                process.cwd().and_then(|cwd| {
                    (path_key(cwd) == dir || inside(cwd, &dir).is_some()).then_some(Hold::WorksIn)
                })
            });
            if let Some(hold) = hold {
                holders.push(Holder { pid, name, hold });
            }
        }
        holders.sort_by_key(|holder| holder.pid);
        holders
    }

    fn terminate(&mut self, pid: u32) -> bool {
        self.system
            .process(sysinfo::Pid::from_u32(pid))
            .is_some_and(sysinfo::Process::kill)
    }
}

/// Runs the stop command as a child process, working in `working_dir`
/// (never the install folder).
pub struct CommandRunner {
    pub working_dir: PathBuf,
}

impl Runner for CommandRunner {
    fn run(
        &mut self,
        program: &Path,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<(), String> {
        let mut child = std::process::Command::new(program)
            .args(arguments)
            .current_dir(&self.working_dir)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start {}: {error}", program.display()))?;
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(format!("it exited with {status}")),
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("it didn't return in {} s", timeout.as_secs()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests;
