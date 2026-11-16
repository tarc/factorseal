//! The steps after `install_files`: `shortcut` and `registry`, which run
//! before the install commits and are undone by a rollback, then the
//! Installed apps entry and `start`, after it.

use std::path::{Path, PathBuf};

use crate::engine::Pending;
use crate::manifest::{Place, Release, SETUP_EXE, Shortcut, Step, UNINSTALL_KEY};
use crate::record::{DESKTOP_EXE, RecordedValue};
use crate::registry::Registry;
use crate::shortcut::Link;

/// The folders shortcuts go to.
#[derive(Clone, Debug)]
pub struct Places {
    /// `%APPDATA%\Microsoft\Windows\Start Menu\Programs`.
    pub start_menu: PathBuf,
    /// The Start menu's `Startup` folder.
    pub startup: PathBuf,
    /// The user's desktop (OneDrive's, when it redirects it).
    pub desktop: PathBuf,
}

impl Places {
    #[must_use]
    pub fn dir(&self, place: Place) -> &Path {
        match place {
            Place::StartMenu => &self.start_menu,
            Place::Startup => &self.startup,
            Place::Desktop => &self.desktop,
        }
    }
}

/// Which launch `start` makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    /// The manifest's `command` (Desktop on its WSL keyrings page).
    Open,
    /// Its `quiet_command` (Desktop in the tray), under `--no-open` or
    /// `--quiet`; the `command` when there is none.
    Quiet,
    /// No launch (`--no-start`).
    None,
}

pub struct StepOptions {
    pub places: Places,
    /// The manifest's optional places the user chose. One the previous
    /// install had a shortcut in is kept without being chosen again.
    pub optional_places: Vec<Place>,
    pub launch: Launch,
    /// The working directory of shortcuts and of the launch: never the
    /// install folder, since a process working there stops the next
    /// update's swap.
    pub working_dir: PathBuf,
}

/// The installed copy of the release file `path`.
fn installed(install_dir: &Path, path: &str) -> PathBuf {
    path.split('/')
        .fold(install_dir.to_owned(), |path, part| path.join(part))
}

/// Make the manifest's shortcuts, recording each in `pending`.
pub fn make_shortcuts(
    release: &Release,
    pending: &mut Pending,
    options: &StepOptions,
) -> std::io::Result<()> {
    for step in &release.manifest.steps {
        if let Step::Shortcut(shortcut) = step {
            make_shortcut(shortcut, pending, options)?;
        }
    }
    Ok(())
}

fn make_shortcut(
    shortcut: &Shortcut,
    pending: &mut Pending,
    options: &StepOptions,
) -> std::io::Result<()> {
    let file_name = format!("{}.lnk", shortcut.name);
    let optional = shortcut.optional_places.iter().filter(|place| {
        options.optional_places.contains(place)
            || pending.had_shortcut(&options.places.dir(**place).join(&file_name))
    });
    let places: Vec<Place> = shortcut.places.iter().chain(optional).copied().collect();
    for place in places {
        let dir = options.places.dir(place);
        std::fs::create_dir_all(dir)?;
        let path = dir.join(&file_name);
        Link {
            target: installed(pending.install_dir(), &shortcut.target),
            arguments: if place == Place::Startup {
                shortcut.startup_args.clone()
            } else {
                Vec::new()
            },
            working_dir: options.working_dir.clone(),
            description: shortcut.name.clone(),
        }
        .write(&path)?;
        pending.made_shortcut(path);
    }
    Ok(())
}

/// Write the manifest's registry values, recording each in `pending`.
pub fn write_registry(
    release: &Release,
    pending: &mut Pending,
    registry: &dyn Registry,
) -> std::io::Result<()> {
    for step in &release.manifest.steps {
        if let Step::Registry(values) = step {
            for value in &values.values {
                registry.set_string(&value.key, &value.name, &value.value)?;
                pending.wrote_value(RecordedValue {
                    key: value.key.clone(),
                    name: value.name.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Register the install in Installed apps, with the installed setup as its
/// uninstaller. Uninstall removes the whole key.
pub fn register_installed_app(
    release: &Release,
    install_dir: &Path,
    registry: &dyn Registry,
) -> std::io::Result<()> {
    let setup = install_dir.join(SETUP_EXE);
    let size_kib = release.files.iter().map(|file| file.len).sum::<u64>() / 1024;
    let strings = [
        ("DisplayName", "FactorSeal".to_owned()),
        ("DisplayVersion", release.manifest.version.clone()),
        ("Publisher", "FactorSeal".to_owned()),
        (
            "InstallLocation",
            install_dir.to_string_lossy().into_owned(),
        ),
        (
            "UninstallString",
            format!("\"{}\" --uninstall", setup.to_string_lossy()),
        ),
    ];
    for (name, value) in &strings {
        registry.set_string(UNINSTALL_KEY, name, value)?;
    }
    let desktop = release
        .files
        .iter()
        .any(|file| file.path.eq_ignore_ascii_case(DESKTOP_EXE));
    if desktop {
        let icon = install_dir.join(DESKTOP_EXE);
        registry.set_string(UNINSTALL_KEY, "DisplayIcon", &icon.to_string_lossy())?;
    }
    registry.set_dword(UNINSTALL_KEY, "NoModify", 1)?;
    registry.set_dword(UNINSTALL_KEY, "NoRepair", 1)?;
    registry.set_dword(
        UNINSTALL_KEY,
        "EstimatedSize",
        u32::try_from(size_kib).unwrap_or(u32::MAX),
    )
}

/// The command `start` runs for `launch`, if any.
#[must_use]
pub fn launch_command(release: &Release, launch: Launch) -> Option<&[String]> {
    let start = release.manifest.steps.iter().find_map(|step| match step {
        Step::Start(start) => Some(start),
        _ => None,
    })?;
    match launch {
        Launch::Open => Some(&start.command),
        Launch::Quiet => Some(start.quiet_command.as_deref().unwrap_or(&start.command)),
        Launch::None => None,
    }
}

/// Launch the new version once, from the install folder, without waiting
/// for it. Returns whether something was started.
pub fn start(
    release: &Release,
    install_dir: &Path,
    options: &StepOptions,
) -> std::io::Result<bool> {
    let Some((program, arguments)) =
        launch_command(release, options.launch).and_then(<[String]>::split_first)
    else {
        return Ok(false);
    };
    std::process::Command::new(installed(install_dir, program))
        .args(arguments)
        .current_dir(&options.working_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(true)
}

#[cfg(test)]
mod tests;
