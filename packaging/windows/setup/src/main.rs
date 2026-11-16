//! `factorseal-setup.exe`. So far only the unattended form, `--quiet`,
//! for our harness and scripts; the dialogs come with step 10 of
//! `docs/plans/windows-installer.md`.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use factorseal_setup::engine::{self, InstallError, Options};
use factorseal_setup::manifest::{ManifestError, Release};

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

    /// Set on the copy that continues from the temporary folder.
    #[arg(long, hide = true)]
    relaunched: bool,
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
    let options = Options {
        install_dir: install_dir.clone(),
        setup_exe,
        setup_version: env!("CARGO_PKG_VERSION").to_owned(),
        adopt: args.adopt,
        shortcut_dirs: shortcut_dirs(),
    };
    let committed = engine::install_files(&release, &options).and_then(engine::Pending::commit);
    match committed {
        Ok(left) => {
            if let Some(old) = left {
                log.line(&format!(
                    "could not remove {} yet; the next run removes it",
                    old.display()
                ));
            }
            log.line(&format!(
                "result: installed {} in {}",
                release.manifest.version,
                install_dir.display()
            ));
            exit::INSTALLED
        }
        Err(error) => {
            log.line(&format!("result: failed: {error}"));
            match error {
                InstallError::NeedsAdoption(_) => exit::NEEDS_ADOPTION,
                _ => exit::INSTALL_FAILED,
            }
        }
    }
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

/// The Start menu (Startup included, below it) and the Desktop, where a
/// hand-made install's shortcuts are.
fn shortcut_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(base) = directories::BaseDirs::new() {
        dirs.push(
            base.data_dir()
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs"),
        );
    }
    if let Some(desktop) =
        directories::UserDirs::new().and_then(|dirs| dirs.desktop_dir().map(Path::to_owned))
    {
        dirs.push(desktop);
    }
    dirs
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
