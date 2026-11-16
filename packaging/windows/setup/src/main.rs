//! `factorseal-setup.exe`. So far only the unattended form, `--quiet`,
//! for our harness and scripts; the dialogs come with step 10 of
//! `docs/plans/windows-installer.md`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use factorseal_setup::engine::{self, InstallError, Options};
use factorseal_setup::manifest::{ManifestError, Place, Release};
use factorseal_setup::registry::Registry;
use factorseal_setup::steps::{self, Launch, Places, StepOptions};

/// Exit codes of `--quiet`; the log says more.
mod exit {
    pub const INSTALLED: u8 = 0;
    pub const USAGE: u8 = 2;
    pub const MANIFEST_REFUSED: u8 = 3;
    pub const NEEDS_NEWER_SETUP: u8 = 4;
    pub const INSTALL_FAILED: u8 = 5;
    pub const NEEDS_ADOPTION: u8 = 6;
}

/// The name a relaunched copy gets in the temporary folder.
const RELAUNCH_PREFIX: &str = "factorseal-setup-";

#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)] // Command-line flags.
#[command(
    name = "factorseal-setup",
    version,
    about = "Install or update FactorSeal for this Windows user",
    after_help = "With --quiet, the exit code is 0 when installed, 2 for a usage error, 3 when \
                  the release is refused, 4 when it needs a newer installer, 5 when installing \
                  failed (the previous install is kept), 6 when a hand-made install needs \
                  --adopt. Run from inside the install folder, it continues from a copy in the \
                  temporary folder and exits 0 at once; the log has the result."
)]
struct Args {
    /// The release to install: its factorseal-release.json.
    #[arg(long, value_name = "PATH")]
    manifest: Option<PathBuf>,

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
}

fn main() -> ExitCode {
    let args = Args::parse();
    let log_path = args
        .log
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("factorseal-setup.log"));
    let mut log = Log::open(&log_path);
    ExitCode::from(run(&args, &mut log))
}

fn run(args: &Args, log: &mut Log) -> u8 {
    if !args.quiet {
        log.line("the installer's dialogs are not built yet; run it with --quiet");
        return exit::USAGE;
    }
    let Some(manifest) = args.manifest.as_deref().map(absolute) else {
        log.line("--quiet needs --manifest");
        return exit::USAGE;
    };
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
        return relaunch(&setup_exe, args, &manifest, &install_dir, log);
    }
    remove_old_relaunch_copies(&setup_exe);

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
    install(args, log, &release, &install_dir, setup_exe)
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
    let step_options = StepOptions {
        places,
        optional_places: args.optional_places.clone(),
        launch: if args.no_start {
            Launch::None
        } else {
            Launch::Quiet
        },
        working_dir: args
            .working_dir
            .as_deref()
            .map_or_else(working_dir, absolute),
    };
    let registry = registry(args.registry_root.as_deref());
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
    match steps::start(release, install_dir, &step_options) {
        Ok(true) => log.line("started FactorSeal"),
        Ok(false) => {}
        Err(error) => log.line(&format!("could not start FactorSeal: {error}")),
    }
    log.line(&format!(
        "result: installed {} in {}",
        release.manifest.version,
        install_dir.display()
    ));
    exit::INSTALLED
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
    manifest: &Path,
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
        .arg("--quiet")
        .arg("--relaunched")
        .arg("--manifest")
        .arg(manifest)
        .arg("--install-dir")
        .arg(install_dir)
        .arg("--log")
        .arg(&log.path);
    if args.adopt {
        command.arg("--adopt");
    }
    if args.no_start {
        command.arg("--no-start");
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

/// Appends timestamped lines to the log, and to standard error.
struct Log {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl Log {
    fn open(path: &Path) -> Self {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();
        Self {
            path: path.to_owned(),
            file,
        }
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
    }
}
