//! `factorseal-setup.exe`: with dialogs on Windows (`gui`, step 10 of
//! `docs/plans/windows-installer.md`), or unattended with `--quiet`, for
//! our harness and scripts. A Windows program, not a console one, so
//! starting it opens no console window; `--quiet` reports through its exit
//! code and log file.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use factorseal_setup::engine::{self, InstallError, Options};
use factorseal_setup::manifest::{ManifestError, Place, Release, Step};
use factorseal_setup::record::{Existing, InstallRecord};
use factorseal_setup::registry::Registry;
use factorseal_setup::steps::{self, Launch, Places, StepOptions};
use factorseal_setup::stop::{self, CommandRunner, StopPlan, Stopped, SystemProcesses, Waits};
use factorseal_setup::uninstall::{self, Choices, Folders, System};
use factorseal_setup::wsl::{self, SystemWsl};

#[cfg(windows)]
mod dialog;
#[cfg(windows)]
mod gui;
#[cfg_attr(not(windows), allow(dead_code))] // Shown only on Windows.
mod ui;

/// Exit codes of `--quiet`; the log says more.
mod exit {
    pub const INSTALLED: u8 = 0;
    pub const USAGE: u8 = 2;
    pub const MANIFEST_REFUSED: u8 = 3;
    pub const NEEDS_NEWER_SETUP: u8 = 4;
    pub const INSTALL_FAILED: u8 = 5;
    pub const NEEDS_ADOPTION: u8 = 6;
    pub const STILL_RUNNING: u8 = 7;
    pub const WSL_INCOMPLETE: u8 = 8;
    pub const NOT_INSTALLED: u8 = 9;
    /// The dialogs were closed before anything changed.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub const CANCELLED: u8 = 10;
}

/// The name a relaunched copy gets in the temporary folder.
const RELAUNCH_PREFIX: &str = "factorseal-setup-";

#[derive(Clone, Debug, Parser)]
#[allow(clippy::struct_excessive_bools)] // Command-line flags.
#[command(
    name = "factorseal-setup",
    version,
    about = "Install, update or uninstall FactorSeal for this Windows user",
    after_help = "With --quiet, the exit code is 0 when installed (or uninstalled), 2 for a \
                  usage error, 3 when the release is refused, 4 when it needs a newer installer, \
                  5 when installing failed (the previous install is kept) or uninstalling \
                  failed (the log says what is left), 6 when a hand-made install needs --adopt, \
                  7 when FactorSeal still runs (nothing changed), 8 when WSL setup or its \
                  removal failed in a distro (the rest was done), 9 when there is no install to \
                  uninstall. Run from inside the install folder, it continues from a copy in \
                  the temporary folder and exits 0 at once; the log has the result. It is a \
                  Windows program: PowerShell waits for it and sets $LASTEXITCODE only through \
                  Start-Process -Wait -PassThru. Without --quiet it shows dialogs, installing \
                  by default the factorseal-release.json beside it."
)]
struct Args {
    /// The release to install: its factorseal-release.json.
    #[arg(long, value_name = "PATH", conflicts_with = "uninstall")]
    manifest: Option<PathBuf>,

    /// Uninstall FactorSeal: what the installer recorded goes, the vault
    /// stays.
    #[arg(long)]
    uninstall: bool,

    /// With --uninstall: also delete the folders the release lists for it
    /// (its settings; never the vault).
    #[arg(long, requires = "uninstall")]
    also_delete: bool,

    /// Where FactorSeal is installed. Defaults to %LOCALAPPDATA%\Programs\FactorSeal.
    #[arg(long, value_name = "DIR")]
    install_dir: Option<PathBuf>,

    /// Install without dialogs, reporting through the exit code and the log.
    #[arg(long)]
    quiet: bool,

    /// Take over FactorSeal installed by hand (from the ZIP): its
    /// UNINSTALL.txt goes, and its shortcuts are recorded and replaced.
    #[arg(long)]
    adopt: bool,

    /// The log. Defaults to factorseal-setup.log in the temporary folder.
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,

    /// Also put the shortcut in this optional place (repeat for more). A
    /// place the previous install had a shortcut in is kept anyway.
    #[arg(long = "optional-place", value_enum, value_name = "PLACE")]
    optional_places: Vec<Place>,

    /// Don't start FactorSeal at the end.
    #[arg(long)]
    no_start: bool,

    /// How long to wait for FactorSeal to be quit from its tray icon, when
    /// the installer can't stop it itself (an install made by hand or
    /// before FactorSeal could be told to quit).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    wait_for_quit: u64,

    /// Set FactorSeal up in this WSL distro (repeat for more); with
    /// --uninstall, remove its setup from this recorded distro. Either
    /// starts the distro. With --quiet, a release that sets up WSL, or an
    /// uninstall of one that did, needs --wsl or --no-wsl.
    #[arg(long = "wsl", value_name = "DISTRO", value_parser = distro_name)]
    wsl: Vec<String>,

    /// Leave WSL alone.
    #[arg(long, conflicts_with = "wsl")]
    no_wsl: bool,

    /// Set on the copy that continues from the temporary folder.
    #[arg(long, hide = true)]
    relaunched: bool,

    /// For tests: write registry keys under this HKCU key instead.
    #[arg(long, hide = true, value_name = "KEY")]
    registry_root: Option<String>,

    /// For tests: the working directory of shortcuts and of the launch,
    /// instead of the user's profile.
    #[arg(long, hide = true, value_name = "DIR")]
    working_dir: Option<PathBuf>,

    /// For tests: shortcut folders under this folder (start-menu,
    /// start-menu\Startup, desktop) instead of the user's.
    #[arg(long, hide = true, value_name = "DIR")]
    shortcut_root: Option<PathBuf>,

    /// For tests: run this instead of wsl.exe.
    #[arg(long, hide = true, value_name = "PATH")]
    wsl_program: Option<PathBuf>,

    /// For tests: %APPDATA% is this folder's Roaming, %LOCALAPPDATA% its
    /// Local.
    #[arg(long, hide = true, value_name = "DIR")]
    appdata_root: Option<PathBuf>,
}

/// Whether the release has the `wsl` step.
fn sets_up_wsl(release: &Release) -> bool {
    release
        .manifest
        .steps
        .iter()
        .any(|step| matches!(step, Step::Wsl {}))
}

fn distro_name(name: &str) -> Result<String, String> {
    wsl::check_distro(name).map(|()| name.to_owned())
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => {
            // A Windows program has no console to print to, unless its
            // output is redirected.
            #[cfg(windows)]
            if !std::env::args().any(|argument| argument == "--quiet") {
                gui::usage(&error.to_string());
            }
            let _ = error.print();
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(exit::USAGE));
        }
    };
    let log_path = args
        .log
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("factorseal-setup.log"));
    let mut log = Log::open(&log_path);
    ExitCode::from(run(&args, &mut log))
}

fn run(args: &Args, log: &mut Log) -> u8 {
    // The dialogs install the release beside the installer by default.
    let manifest = args.manifest.as_deref().map(absolute).or_else(|| {
        (!args.quiet && !args.uninstall)
            .then(release_beside_installer)
            .flatten()
    });
    if args.quiet && manifest.is_none() && !args.uninstall {
        log.line("--quiet needs --manifest or --uninstall");
        return exit::USAGE;
    }
    let Some(install_dir) = args
        .install_dir
        .as_deref()
        .map(absolute)
        .or_else(default_install_dir)
    else {
        log.line("no default install folder; pass --install-dir");
        return exit::USAGE;
    };
    let setup_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            log.line(&format!("cannot find the installer itself: {error}"));
            return exit::INSTALL_FAILED;
        }
    };
    // A working directory inside the install folder would stop its swap.
    let _ = std::env::set_current_dir(std::env::temp_dir());
    if cfg!(windows) && !args.relaunched && inside(&setup_exe, &install_dir) {
        // This executable can't be deleted with the old folder while it
        // runs; a copy elsewhere can finish the update after it exits.
        return relaunch(&setup_exe, args, manifest.as_deref(), &install_dir, log);
    }
    remove_old_relaunch_copies(&setup_exe);
    if !args.quiet {
        return with_dialogs(args, log, manifest, &install_dir, &setup_exe);
    }
    let Some(manifest) = manifest else {
        let code = uninstall(args, log, &install_dir);
        if args.relaunched {
            delete_later(&setup_exe, log);
        }
        return code;
    };

    log.line(&format!("release: {}", manifest.display()));
    let release = match Release::open(&manifest) {
        Ok(release) => release,
        Err(error) => {
            log.line(&format!("result: refused: {error}"));
            return match error {
                ManifestError::NeedsNewerSetup { .. } => exit::NEEDS_NEWER_SETUP,
                _ => exit::MANIFEST_REFUSED,
            };
        }
    };
    let sets_up_wsl = sets_up_wsl(&release);
    if sets_up_wsl && args.wsl.is_empty() && !args.no_wsl {
        log.line(
            "result: refused: this release sets up WSL; pass --wsl DISTRO (repeat for more) or \
             --no-wsl",
        );
        return exit::USAGE;
    }
    if !sets_up_wsl && !args.wsl.is_empty() {
        log.line("this release doesn't set up WSL; --wsl is ignored");
    }
    install(args, log, &release, &install_dir, setup_exe)
}

/// The installer with dialogs; on Windows only.
fn with_dialogs(
    args: &Args,
    log: &mut Log,
    manifest: Option<PathBuf>,
    install_dir: &Path,
    setup_exe: &Path,
) -> u8 {
    #[cfg(windows)]
    {
        if args.uninstall {
            let code = gui::uninstall(args, log, install_dir);
            if args.relaunched {
                delete_later(setup_exe, log);
            }
            code
        } else {
            gui::install(args, log, manifest, install_dir, setup_exe)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (args, manifest, install_dir, setup_exe);
        log.line("the installer's dialogs exist only on Windows; run it with --quiet");
        exit::USAGE
    }
}

/// The `factorseal-release.json` beside this installer, if there is one.
fn release_beside_installer() -> Option<PathBuf> {
    let manifest = std::env::current_exe()
        .ok()?
        .parent()?
        .join(factorseal_setup::manifest::MANIFEST_FILE);
    manifest.is_file().then_some(manifest)
}

/// Install a verified release: the files, shortcuts and registry values
/// (rolled back together on failure), then the Installed apps entry and
/// the launch.
fn install(
    args: &Args,
    log: &mut Log,
    release: &Release,
    install_dir: &Path,
    setup_exe: PathBuf,
) -> u8 {
    let Some(places) = places(args.shortcut_root.as_deref()) else {
        log.line("result: failed: cannot find the Start menu and Desktop folders");
        return exit::INSTALL_FAILED;
    };
    let options = Options {
        install_dir: install_dir.to_owned(),
        setup_exe,
        setup_version: env!("CARGO_PKG_VERSION").to_owned(),
        adopt: args.adopt,
        shortcut_dirs: vec![places.start_menu.clone(), places.desktop.clone()],
    };
    let launch = if args.no_start {
        Launch::None
    } else {
        Launch::Quiet
    };
    let step_options = step_options(args, places, launch);
    let registry = registry(args.registry_root.as_deref());
    if let Err(code) = stop_installed(args, log, release, install_dir, &step_options.working_dir) {
        return code;
    }
    let mut pending = match engine::install_files(release, &options) {
        Ok(pending) => pending,
        Err(error) => {
            log.line(&format!("result: failed: {error}"));
            return match error {
                InstallError::NeedsAdoption(_) => exit::NEEDS_ADOPTION,
                _ => exit::INSTALL_FAILED,
            };
        }
    };
    let made = steps::make_shortcuts(release, &mut pending, &step_options)
        .map_err(|error| format!("cannot make a shortcut: {error}"))
        .and_then(|()| {
            steps::write_registry(release, &mut pending, registry.as_ref())
                .map_err(|error| format!("cannot write the registry: {error}"))
        });
    if let Err(error) = made {
        let rolled_back = pending.rollback(registry.as_ref());
        log.line(&format!(
            "result: failed: {error}; {}",
            match rolled_back {
                Ok(()) => "the previous install is back".to_owned(),
                Err(rollback) => format!("restoring the previous install failed too: {rollback}"),
            }
        ));
        return exit::INSTALL_FAILED;
    }
    match pending.commit(registry.as_ref()) {
        Ok(Some(old)) => log.line(&format!(
            "could not remove {} yet (a program runs from it); a later run removes it",
            old.display()
        )),
        Ok(None) => {}
        Err(error) => {
            log.line(&format!("result: failed: {error}"));
            return exit::INSTALL_FAILED;
        }
    }
    // Installed from here on; what follows only warns.
    if let Err(error) = steps::register_installed_app(release, install_dir, registry.as_ref()) {
        log.line(&format!("could not register in Installed apps: {error}"));
    }
    let wsl_problems = set_up_wsl(args, log, release, install_dir, &step_options.working_dir);
    match steps::start(release, install_dir, &step_options) {
        Ok(true) => log.line("started FactorSeal"),
        Ok(false) => {}
        Err(error) => log.line(&format!("could not start FactorSeal: {error}")),
    }
    let installed = format!(
        "result: installed {} in {}",
        release.manifest.version,
        install_dir.display()
    );
    if wsl_problems > 0 {
        log.line(&format!(
            "{installed}, but WSL was not set up in {wsl_problems} distro(s); see above"
        ));
        return exit::WSL_INCOMPLETE;
    }
    log.line(&installed);
    exit::INSTALLED
}

/// The options of the steps after `install_files`.
fn step_options(args: &Args, places: Places, launch: Launch) -> StepOptions {
    StepOptions {
        places,
        optional_places: args.optional_places.clone(),
        launch,
        working_dir: args
            .working_dir
            .as_deref()
            .map_or_else(working_dir, absolute),
    }
}

/// The `wsl` step, in the distros chosen with `--wsl`, after the install
/// committed: a failure only warns. Returns how many distros weren't set
/// up.
fn set_up_wsl(
    args: &Args,
    log: &mut Log,
    release: &Release,
    install_dir: &Path,
    working_dir: &Path,
) -> usize {
    if !sets_up_wsl(release) || args.wsl.is_empty() {
        return 0;
    }
    let mut system = system_wsl(args, working_dir);
    let report = wsl::set_up(&args.wsl, install_dir, &mut system, &mut |line: &str| {
        log.line(line);
    });
    let mut problems = report.problems.len();
    if !report.set_up.is_empty()
        && let Err(error) = InstallRecord::add_distros(install_dir, &report.set_up)
    {
        log.line(&format!(
            "could not record the WSL distros set up ({}): {error}",
            report.set_up.join(", ")
        ));
        problems += report.set_up.len();
    }
    problems
}

/// Stop the installed version, the way its record says, before anything
/// changes. A hand-made install is checked first, so FactorSeal isn't
/// stopped for an install that will be refused.
fn stop_installed(
    args: &Args,
    log: &mut Log,
    release: &Release,
    install_dir: &Path,
    working_dir: &Path,
) -> Result<(), u8> {
    if let Err(error) = engine::recover(install_dir) {
        log.line(&format!("result: failed: {error}"));
        return Err(exit::INSTALL_FAILED);
    }
    let existing = match Existing::detect(install_dir) {
        Ok(existing) => existing,
        Err(error) => {
            let error = InstallError::Record {
                path: InstallRecord::path(install_dir),
                source: error,
            };
            log.line(&format!("result: failed: {error}"));
            return Err(exit::INSTALL_FAILED);
        }
    };
    if existing == Existing::HandMade && !args.adopt {
        let error = InstallError::NeedsAdoption(install_dir.to_owned());
        log.line(&format!("result: failed: {error}"));
        return Err(exit::NEEDS_ADOPTION);
    }
    stop_with(
        args,
        log,
        &StopPlan::new(install_dir, &existing, release),
        working_dir,
    )
}

/// Stop what `plan` says, or fail with exit 7.
fn stop_with(args: &Args, log: &mut Log, plan: &StopPlan, working_dir: &Path) -> Result<(), u8> {
    let waits = Waits {
        quit: std::time::Duration::from_secs(args.wait_for_quit),
        ..Waits::default()
    };
    let mut runner = CommandRunner {
        working_dir: working_dir.to_owned(),
    };
    match stop::stop_running(
        plan,
        &mut SystemProcesses::default(),
        &mut runner,
        log,
        &waits,
    ) {
        Ok(Stopped::NothingRan) => {}
        Ok(Stopped::Terminated) => log.line("stopped FactorSeal's helpers"),
        Ok(Stopped::ByCommand) => log.line("FactorSeal stopped"),
        Ok(Stopped::ByUser) => log.line("FactorSeal was quit"),
        Err(error) => {
            log.line(&format!("result: failed: {error}"));
            return Err(exit::STILL_RUNNING);
        }
    }
    Ok(())
}

/// Uninstall the install in `install_dir`: stop it the way it recorded,
/// remove its setup from the chosen distros, then everything recorded.
fn uninstall(args: &Args, log: &mut Log, install_dir: &Path) -> u8 {
    log.line(&format!(
        "uninstalling FactorSeal from {}",
        install_dir.display()
    ));
    let record = match recorded_install(log, install_dir) {
        Ok(record) => record,
        Err(code) => return code,
    };
    if let Err(code) = check_distro_choice(args, log, &record) {
        return code;
    }
    let (Some(places), Some(folders)) = (
        places(args.shortcut_root.as_deref()),
        folders(args.appdata_root.as_deref()),
    ) else {
        log.line("result: failed: cannot find the Start menu, Desktop or AppData folders");
        return exit::INSTALL_FAILED;
    };
    let working_dir = args
        .working_dir
        .as_deref()
        .map_or_else(working_dir, absolute);
    if let Err(code) = stop_with(
        args,
        log,
        &StopPlan::for_uninstall(install_dir, &record),
        &working_dir,
    ) {
        return code;
    }

    let registry = registry(args.registry_root.as_deref());
    let mut wsl = system_wsl(args, &working_dir);
    let shortcut_dirs = [places.start_menu, places.desktop];
    let choices = Choices {
        distros: args.wsl.clone(),
        delete_listed: args.also_delete,
    };
    let result = uninstall::uninstall(
        install_dir,
        &record,
        &choices,
        &mut System {
            registry: registry.as_ref(),
            wsl: &mut wsl,
            shortcut_dirs: &shortcut_dirs,
            folders: &folders,
        },
        &mut |line: &str| log.line(line),
    );
    report_uninstall(log, &result, &record, install_dir)
}

/// The record of the install in `install_dir`, after recovering an
/// interrupted run; or the exit code when there is none to undo.
fn recorded_install(log: &mut Log, install_dir: &Path) -> Result<InstallRecord, u8> {
    if let Err(error) = engine::recover(install_dir) {
        log.line(&format!("result: failed: {error}"));
        return Err(exit::INSTALL_FAILED);
    }
    match Existing::detect(install_dir) {
        Ok(Existing::Recorded(record)) => Ok(*record),
        Ok(Existing::HandMade) => {
            log.line(&format!(
                "result: refused: FactorSeal in {} was installed by hand, without a record to \
                 undo; delete that folder as its UNINSTALL.txt says",
                install_dir.display()
            ));
            Err(exit::NOT_INSTALLED)
        }
        Ok(Existing::Fresh) => {
            log.line(&format!(
                "result: refused: FactorSeal is not installed in {}",
                install_dir.display()
            ));
            Err(exit::NOT_INSTALLED)
        }
        Err(error) => {
            let error = InstallError::Record {
                path: InstallRecord::path(install_dir),
                source: error,
            };
            log.line(&format!("result: failed: {error}"));
            Err(exit::INSTALL_FAILED)
        }
    }
}

/// Under `--quiet`, a choice about each recorded distro, naming only
/// recorded ones.
fn check_distro_choice(args: &Args, log: &mut Log, record: &InstallRecord) -> Result<(), u8> {
    if !record.distros.is_empty() && args.wsl.is_empty() && !args.no_wsl {
        log.line(&format!(
            "result: refused: FactorSeal was set up in WSL ({}); pass --wsl DISTRO for each \
             distro to remove that setup from, or --no-wsl",
            record.distros.join(", ")
        ));
        return Err(exit::USAGE);
    }
    if let Some(unknown) = args.wsl.iter().find(|distro| {
        !record
            .distros
            .iter()
            .any(|known| known.eq_ignore_ascii_case(distro))
    }) {
        log.line(&format!(
            "result: refused: FactorSeal was not set up in WSL distro {unknown} (it was in: {})",
            if record.distros.is_empty() {
                "none".to_owned()
            } else {
                record.distros.join(", ")
            }
        ));
        return Err(exit::USAGE);
    }
    Ok(())
}

/// Log how the uninstall ended; its exit code.
fn report_uninstall(
    log: &mut Log,
    result: &Result<uninstall::Report, uninstall::UninstallError>,
    record: &InstallRecord,
    install_dir: &Path,
) -> u8 {
    let done = format!(
        "result: uninstalled FactorSeal {} from {}",
        record.version,
        install_dir.display()
    );
    match result {
        Err(error) => {
            log.line(&format!("result: failed: {error}"));
            exit::INSTALL_FAILED
        }
        Ok(report) if !report.problems.is_empty() => {
            for problem in &report.problems {
                log.line(problem);
            }
            log.line(&format!(
                "{done}, but {} thing(s) could not be removed; see above",
                report.problems.len()
            ));
            exit::INSTALL_FAILED
        }
        Ok(report) if !report.wsl_problems.is_empty() => {
            log.line(&format!(
                "{done}, but its WSL setup is left in {} distro(s); see above",
                report.wsl_problems.len()
            ));
            exit::WSL_INCOMPLETE
        }
        Ok(_) => {
            log.line(&done);
            exit::INSTALLED
        }
    }
}

/// `wsl.exe`, or the test's stand-in.
fn system_wsl(args: &Args, working_dir: &Path) -> SystemWsl {
    SystemWsl {
        program: args
            .wsl_program
            .as_deref()
            .map_or_else(|| PathBuf::from("wsl.exe"), absolute),
        working_dir: working_dir.to_owned(),
        timeout: wsl::LINE_TIMEOUT,
    }
}

/// `%APPDATA%` and `%LOCALAPPDATA%`, or test folders under `root`.
fn folders(root: Option<&Path>) -> Option<Folders> {
    if let Some(root) = root {
        let root = absolute(root);
        return Some(Folders {
            appdata: root.join("Roaming"),
            local_appdata: root.join("Local"),
        });
    }
    let dirs = directories::BaseDirs::new()?;
    Some(Folders {
        appdata: dirs.config_dir().to_owned(),
        local_appdata: dirs.data_local_dir().to_owned(),
    })
}

/// Windows: delete this relaunched copy once it has exited, through
/// `cmd.exe`, which waits a moment and then deletes it. A path `cmd.exe`
/// would read as more than a path (holding `"` or `%`) is left for the next
/// run of the installer, which removes old copies.
fn delete_later(exe: &Path, log: &mut Log) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let path = exe.to_string_lossy();
        if path.contains(['"', '%']) {
            return;
        }
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let cmd = Path::new(&system_root).join("System32").join("cmd.exe");
        let started = std::process::Command::new(cmd)
            .raw_arg(format!(
                "/d /c ping -n 3 127.0.0.1 >nul & del /f /q \"{path}\""
            ))
            .current_dir(std::env::temp_dir())
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Err(error) = started {
            log.line(&format!(
                "could not arrange to delete {}: {error}",
                exe.display()
            ));
        }
    }
    #[cfg(not(windows))]
    let _ = (exe, log);
}

/// The registry: the user's (or a test key) on Windows; elsewhere, where
/// the installer only runs in tests, one in memory.
fn registry(root: Option<&str>) -> Box<dyn Registry> {
    #[cfg(windows)]
    {
        use factorseal_setup::registry::{Root, SystemRegistry};
        Box::new(SystemRegistry {
            root: root.map_or(Root::CurrentUser, |root| Root::Test(root.to_owned())),
        })
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        Box::new(factorseal_setup::registry::MemoryRegistry::default())
    }
}

/// Where shortcuts go: the user's folders, or test folders under `root`.
fn places(root: Option<&Path>) -> Option<Places> {
    if let Some(root) = root {
        let start_menu = root.join("start-menu");
        return Some(Places {
            startup: start_menu.join("Startup"),
            start_menu,
            desktop: root.join("desktop"),
        });
    }
    let start_menu = directories::BaseDirs::new()?
        .data_dir()
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs");
    let desktop = directories::UserDirs::new()?.desktop_dir()?.to_owned();
    Some(Places {
        startup: start_menu.join("Startup"),
        start_menu,
        desktop,
    })
}

/// The working directory of shortcuts and of the launch: the user's
/// profile, never the install folder.
fn working_dir() -> PathBuf {
    directories::BaseDirs::new().map_or_else(std::env::temp_dir, |dirs| dirs.home_dir().to_owned())
}

/// Continue from a copy in the temporary folder, with the same options,
/// and exit so the install folder is free.
fn relaunch(
    setup_exe: &Path,
    args: &Args,
    manifest: Option<&Path>,
    install_dir: &Path,
    log: &mut Log,
) -> u8 {
    let copy = std::env::temp_dir().join(format!("{RELAUNCH_PREFIX}{}.exe", std::process::id()));
    if let Err(error) = std::fs::copy(setup_exe, &copy) {
        log.line(&format!(
            "result: failed: cannot copy the installer to {}: {error}",
            copy.display()
        ));
        return exit::INSTALL_FAILED;
    }
    let mut command = std::process::Command::new(&copy);
    command
        .current_dir(std::env::temp_dir())
        .arg("--relaunched")
        .arg("--install-dir")
        .arg(install_dir)
        .arg("--log")
        .arg(&log.path);
    if args.quiet {
        command.arg("--quiet");
    }
    match manifest {
        Some(manifest) => command.arg("--manifest").arg(manifest),
        None => command.arg("--uninstall"),
    };
    if args.also_delete {
        command.arg("--also-delete");
    }
    if args.adopt {
        command.arg("--adopt");
    }
    if args.no_start {
        command.arg("--no-start");
    }
    command
        .arg("--wait-for-quit")
        .arg(args.wait_for_quit.to_string());
    for distro in &args.wsl {
        command.arg("--wsl").arg(distro);
    }
    if args.no_wsl {
        command.arg("--no-wsl");
    }
    if let Some(program) = &args.wsl_program {
        command.arg("--wsl-program").arg(absolute(program));
    }
    if let Some(root) = &args.appdata_root {
        command.arg("--appdata-root").arg(absolute(root));
    }
    for place in &args.optional_places {
        if let Some(value) = clap::ValueEnum::to_possible_value(place) {
            command.arg("--optional-place").arg(value.get_name());
        }
    }
    if let Some(root) = &args.registry_root {
        command.arg("--registry-root").arg(root);
    }
    if let Some(root) = &args.shortcut_root {
        command.arg("--shortcut-root").arg(absolute(root));
    }
    if let Some(dir) = &args.working_dir {
        command.arg("--working-dir").arg(absolute(dir));
    }
    match command.spawn() {
        Ok(_) => {
            log.line(&format!("continuing from {}", copy.display()));
            exit::INSTALLED
        }
        Err(error) => {
            log.line(&format!(
                "result: failed: cannot start {}: {error}",
                copy.display()
            ));
            exit::INSTALL_FAILED
        }
    }
}

/// Earlier relaunched copies, which couldn't delete themselves. One still
/// running stays (Windows refuses to delete it).
fn remove_old_relaunch_copies(setup_exe: &Path) {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(RELAUNCH_PREFIX)
            && name.ends_with(".exe")
            && !same_file(&path, setup_exe)
        {
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn same_file(one: &Path, other: &Path) -> bool {
    match (one.canonicalize(), other.canonicalize()) {
        (Ok(one), Ok(other)) => one == other,
        _ => false,
    }
}

/// Whether `exe` lies in `dir`.
fn inside(exe: &Path, dir: &Path) -> bool {
    match (exe.canonicalize(), dir.canonicalize()) {
        (Ok(exe), Ok(dir)) => exe.starts_with(dir),
        _ => false,
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_owned())
}

fn default_install_dir() -> Option<PathBuf> {
    directories::BaseDirs::new()
        .map(|dirs| dirs.data_local_dir().join("Programs").join("FactorSeal"))
}

/// Under `--quiet`, the stop's messages and its request to quit go to the
/// log.
impl stop::Ui for Log {
    fn say(&mut self, line: &str) {
        self.line(line);
    }

    fn ask_to_quit(&mut self, holders: &[stop::Holder], wait: std::time::Duration) {
        self.line(&stop::ask_text(holders, wait));
    }
}

/// Appends timestamped lines to the log, to standard error, and to the
/// dialogs' progress page when they run the work.
struct Log {
    path: PathBuf,
    file: Option<std::fs::File>,
    sink: Option<std::sync::mpsc::Sender<String>>,
}

impl Log {
    fn open(path: &Path) -> Self {
        // A log in a folder that doesn't exist yet would be lost.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        Self {
            path: path.to_owned(),
            file,
            sink: None,
        }
    }

    /// Also hand each line, without its time stamp, to `sink`.
    #[cfg_attr(not(windows), allow(dead_code))] // The dialogs' only.
    fn with_sink(mut self, sink: std::sync::mpsc::Sender<String>) -> Self {
        self.sink = Some(sink);
        self
    }

    fn line(&mut self, text: &str) {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let line = format!("{seconds} [{}] {text}", std::process::id());
        eprintln!("{line}");
        if let Some(file) = &mut self.file {
            let _ = writeln!(file, "{line}");
        }
        if let Some(sink) = &self.sink {
            let _ = sink.send(text.to_owned());
        }
    }
}
