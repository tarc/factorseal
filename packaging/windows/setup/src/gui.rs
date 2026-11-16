//! The installer with dialogs (step 10 of
//! `docs/plans/windows-installer.md`), on Windows. The pages come from
//! [`crate::ui`] and are shown by [`crate::dialog`]; the choices made there
//! become the same options `--quiet` takes, and the same install and
//! uninstall run with them on a worker thread while a progress page shows
//! what they log. Every choice is made before the work starts, the WSL
//! distros included, so nothing is probed before the user chose.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;

use factorseal_setup::manifest::{ManifestError, Place, Release};
use factorseal_setup::record::{Existing, InstallRecord};
use factorseal_setup::steps::{self, Launch, Places};
use factorseal_setup::uninstall::listed_folders;
use factorseal_setup::wsl;

use crate::dialog::{self, Event, Next};
use crate::{Args, Log, exit, ui};

/// The install or uninstall running on its thread, and what it logged.
struct Work {
    lines: mpsc::Receiver<String>,
    thread: Option<JoinHandle<u8>>,
    logged: Vec<String>,
}

impl Work {
    fn start(log_path: &Path, job: impl FnOnce(&mut Log) -> u8 + Send + 'static) -> Self {
        let (sender, lines) = mpsc::channel();
        let log_path = log_path.to_owned();
        let thread = std::thread::spawn(move || {
            let mut log = Log::open(&log_path).with_sink(sender);
            job(&mut log)
        });
        Self {
            lines,
            thread: Some(thread),
            logged: Vec::new(),
        }
    }

    /// Collect what was logged since; the exit code once the work is done.
    fn poll(&mut self) -> (bool, Option<u8>) {
        let before = self.logged.len();
        let finished = self.thread.as_ref().is_some_and(JoinHandle::is_finished);
        self.logged.extend(self.lines.try_iter());
        let code = if finished {
            self.thread
                .take()
                .map(|thread| thread.join().unwrap_or(exit::INSTALL_FAILED))
        } else {
            None
        };
        (self.logged.len() > before, code)
    }
}

enum Stage {
    Options,
    Distros,
    Working(Work),
    Done,
}

/// The progress page's next step: new text, or the last page.
fn progress(work: &mut Work, done: impl FnOnce(u8, &[String]) -> ui::Page) -> (Next, Option<u8>) {
    match work.poll() {
        (_, Some(code)) => (Next::Page(done(code, &work.logged)), Some(code)),
        (true, None) => (
            Next::Content(work.logged.last().cloned().unwrap_or_default()),
            None,
        ),
        (false, None) => (Next::Stay, None),
    }
}

fn refused(log: &mut Log, page: ui::Page, code: u8) -> u8 {
    log.line(&format!("result: refused: {}", page.content));
    dialog::message(page);
    code
}

/// The release to install, what is installed, and where shortcuts go; or
/// the exit code after a page saying why there is nothing to install.
fn prepare(
    args: &Args,
    log: &mut Log,
    manifest: Option<PathBuf>,
    install_dir: &Path,
) -> Result<(Release, Existing, Places), u8> {
    let Some(manifest) = manifest else {
        let page = ui::error_page(
            "There is no release to install here",
            "Run factorseal-setup.exe from a FactorSeal release folder, which holds \
             factorseal-release.json. To uninstall FactorSeal, use Installed apps in Settings.",
        );
        return Err(refused(log, page, exit::USAGE));
    };
    log.line(&format!("release: {}", manifest.display()));
    let release = match Release::open(&manifest) {
        Ok(release) => release,
        Err(error) => {
            let code = match error {
                ManifestError::NeedsNewerSetup { .. } => exit::NEEDS_NEWER_SETUP,
                _ => exit::MANIFEST_REFUSED,
            };
            let page = ui::error_page("This release can't be installed", format!("{error}."));
            return Err(refused(log, page, code));
        }
    };
    match (
        Existing::detect(install_dir),
        crate::places(args.shortcut_root.as_deref()),
    ) {
        (Ok(existing), Some(places)) => Ok((release, existing, places)),
        (Err(error), _) => {
            let page = ui::error_page(
                "FactorSeal can't be installed",
                format!(
                    "The install record in {} can't be read: {error}.",
                    install_dir.display()
                ),
            );
            Err(refused(log, page, exit::INSTALL_FAILED))
        }
        (_, None) => {
            let page = ui::error_page(
                "FactorSeal can't be installed",
                "Windows doesn't say where the Start menu and the desktop are.",
            );
            Err(refused(log, page, exit::INSTALL_FAILED))
        }
    }
}

/// Install or update the release `manifest` (by default the one beside
/// the installer) in `install_dir`.
pub fn install(
    args: &Args,
    log: &mut Log,
    manifest: Option<PathBuf>,
    install_dir: &Path,
    setup_exe: &Path,
) -> u8 {
    let (release, existing, places) = match prepare(args, log, manifest, install_dir) {
        Ok(prepared) => prepared,
        Err(code) => return code,
    };
    let (offered, kept) = ui::optional_places(&release, &existing, &places);
    let distros = if crate::sets_up_wsl(&release) {
        wsl::registered_distros()
    } else {
        Vec::new()
    };
    let recorded = match &existing {
        Existing::Recorded(record) => record.distros.clone(),
        _ => Vec::new(),
    };
    let version = release.manifest.version.clone();
    let can_open = steps::launch_command(&release, Launch::Open).is_some();
    let log_path = log.path.clone();
    let start = |places: Vec<Place>, chosen: Vec<String>| {
        let mut args = args.clone();
        args.optional_places = places;
        args.no_wsl = chosen.is_empty();
        args.wsl = chosen;
        args.adopt = existing == Existing::HandMade;
        // The last page offers the launch.
        args.no_start = true;
        let (release, install_dir, setup_exe) = (
            release.clone(),
            install_dir.to_owned(),
            setup_exe.to_owned(),
        );
        Work::start(&log_path, move |log| {
            crate::install(&args, log, &release, &install_dir, setup_exe)
        })
    };
    let working = || ui::working_page(format!("Installing FactorSeal {version}…"));

    let mut stage = Stage::Options;
    let mut chosen_places = Vec::new();
    let mut code = exit::CANCELLED;
    let mut open = false;
    let first = ui::install_page(&version, &existing, install_dir, &offered, &kept);
    let shown = dialog::run(first, &mut |event| {
        let mut next_stage = None;
        let next = match (&mut stage, event) {
            (Stage::Options, Event::Ok(states)) => {
                chosen_places = ui::chosen(&offered, states);
                if distros.is_empty() {
                    next_stage = Some(Stage::Working(start(chosen_places.clone(), Vec::new())));
                    Next::Page(working())
                } else {
                    next_stage = Some(Stage::Distros);
                    Next::Page(ui::wsl_page(&distros, &recorded))
                }
            }
            (Stage::Distros, Event::Ok(states)) => {
                let chosen = ui::chosen(&distros, states);
                next_stage = Some(Stage::Working(start(chosen_places.clone(), chosen)));
                Next::Page(working())
            }
            (Stage::Working(work), Event::Timer) => {
                let (next, finished) = progress(work, |code, logged| {
                    ui::install_done(code, &version, logged, can_open && matches!(code, 0 | 8))
                });
                if let Some(finished) = finished {
                    code = finished;
                    next_stage = Some(Stage::Done);
                }
                next
            }
            (Stage::Done, Event::Ok(states) | Event::Cancel(states)) => {
                open = states.first().copied().unwrap_or(false);
                Next::Close
            }
            (Stage::Working(_), _) | (_, Event::Timer) => Next::Stay,
            (_, Event::Cancel(_)) => Next::Close,
        };
        if let Some(stage_now) = next_stage {
            stage = stage_now;
        }
        next
    });
    if let Err(error) = shown {
        log.line(&format!("result: failed: {error}"));
        return exit::INSTALL_FAILED;
    }
    if code == exit::CANCELLED {
        log.line("result: cancelled");
    }
    if open && matches!(code, exit::INSTALLED | exit::WSL_INCOMPLETE) {
        let options = crate::step_options(args, places, Launch::Open);
        match steps::start(&release, install_dir, &options) {
            Ok(true) => log.line("started FactorSeal"),
            Ok(false) => {}
            Err(error) => log.line(&format!("could not start FactorSeal: {error}")),
        }
    }
    code
}

/// Uninstall the install in `install_dir`.
pub fn uninstall(args: &Args, log: &mut Log, install_dir: &Path) -> u8 {
    let record: InstallRecord = match Existing::detect(install_dir) {
        Ok(Existing::Recorded(record)) => *record,
        Ok(Existing::HandMade) => {
            let page = ui::error_page(
                "FactorSeal can't be uninstalled here",
                format!(
                    "FactorSeal in {} was extracted by hand, without a record to undo. Delete \
                     that folder as its UNINSTALL.txt says.",
                    install_dir.display()
                ),
            );
            return refused(log, page, exit::NOT_INSTALLED);
        }
        Ok(Existing::Fresh) => {
            let page = ui::error_page(
                "FactorSeal is not installed",
                format!("There is no FactorSeal in {}.", install_dir.display()),
            );
            return refused(log, page, exit::NOT_INSTALLED);
        }
        Err(error) => {
            let page = ui::error_page(
                "FactorSeal can't be uninstalled",
                format!(
                    "The install record in {} can't be read: {error}.",
                    install_dir.display()
                ),
            );
            return refused(log, page, exit::INSTALL_FAILED);
        }
    };
    let folders = crate::folders(args.appdata_root.as_deref())
        .map(|folders| listed_folders(&record, &folders))
        .unwrap_or_default();
    let folder_names: Vec<String> = folders
        .iter()
        .map(|folder| folder.display().to_string())
        .collect();
    let note = record.uninstall.keep_note.clone();
    let distros = record.distros.clone();

    let log_path = log.path.clone();
    let mut stage = Stage::Options;
    let mut code = exit::CANCELLED;
    let first = ui::uninstall_page(&record, install_dir, &folder_names);
    let shown = dialog::run(first, &mut |event| {
        let mut next_stage = None;
        let next = match (&mut stage, event) {
            (Stage::Options, Event::Ok(states)) => {
                let mut args = args.clone();
                args.wsl = ui::chosen(&distros, states);
                args.no_wsl = args.wsl.is_empty();
                args.also_delete =
                    !folders.is_empty() && states.get(distros.len()).copied().unwrap_or(false);
                let install_dir = install_dir.to_owned();
                next_stage = Some(Stage::Working(Work::start(&log_path, move |log| {
                    crate::uninstall(&args, log, &install_dir)
                })));
                Next::Page(ui::working_page("Uninstalling FactorSeal…"))
            }
            (Stage::Working(work), Event::Timer) => {
                let (next, finished) = progress(work, |code, logged| {
                    ui::uninstall_done(code, note.as_deref(), logged)
                });
                if let Some(finished) = finished {
                    code = finished;
                    next_stage = Some(Stage::Done);
                }
                next
            }
            (Stage::Working(_), _) | (_, Event::Timer) => Next::Stay,
            (_, Event::Ok(_) | Event::Cancel(_)) => Next::Close,
        };
        if let Some(stage_now) = next_stage {
            stage = stage_now;
        }
        next
    });
    if let Err(error) = shown {
        log.line(&format!("result: failed: {error}"));
        return exit::INSTALL_FAILED;
    }
    if code == exit::CANCELLED {
        log.line("result: cancelled");
    }
    code
}

/// What clap says about the command line (an error, the help or the
/// version), when there is no console to print it to.
pub fn usage(text: &str) {
    let mut page = ui::error_page("FactorSeal Setup", text.trim_end().to_owned());
    page.icon = ui::Icon::App;
    dialog::message(page);
}
