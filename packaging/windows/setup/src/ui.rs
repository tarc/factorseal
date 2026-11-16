//! The installer's dialogs as data (step 10 of
//! `docs/plans/windows-installer.md`): each page is built here from the
//! release, what is installed and the run's log, and shown by
//! [`crate::dialog`] as a Win32 task dialog. Options are toggles, shown as
//! command links that flip when clicked, since a task dialog has only one
//! check box.
//!
//! The pages: install or update (with the optional shortcut places), the
//! WSL distros (before anything is probed), progress, and done; and for
//! uninstall, what goes (with the recorded distros and the folders the
//! release lists), progress, and done.

use std::path::Path;

use factorseal_setup::manifest::{Place, Release, Step};
use factorseal_setup::record::{Existing, InstallRecord};
use factorseal_setup::steps::Places;

/// The window title of every page.
pub const TITLE: &str = "FactorSeal Setup";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// FactorSeal's own.
    App,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Buttons {
    /// OK goes on, Cancel stops.
    OkCancel,
    /// Only Close.
    Close,
    /// Work in progress: nothing can be clicked.
    Working,
}

/// An option the user turns on or off.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toggle {
    pub label: String,
    /// A second, smaller line, such as a path.
    pub note: Option<String>,
    pub on: bool,
}

impl Toggle {
    fn new(label: impl Into<String>, on: bool) -> Self {
        Self {
            label: label.into(),
            note: None,
            on,
        }
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// The command link's text, with its state in front.
    #[must_use]
    pub fn text(&self) -> String {
        // U+FE0E asks for the text glyph, not the colour emoji Windows
        // draws for a bare U+2611. A command link shows what follows a
        // line break as its note.
        let mark = if self.on {
            "\u{2611}\u{FE0E}"
        } else {
            "\u{2610}"
        };
        match &self.note {
            Some(note) => format!("{mark} {}\n{note}", self.label),
            None => format!("{mark} {}", self.label),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub content: String,
    pub toggles: Vec<Toggle>,
    pub buttons: Buttons,
    /// Shown under "Show details".
    pub details: Option<String>,
    /// Details shown from the start.
    pub expanded: bool,
    pub icon: Icon,
    /// A moving progress bar, and the timer that polls the work.
    pub progress: bool,
}

impl Page {
    fn new(heading: impl Into<String>, content: impl Into<String>, buttons: Buttons) -> Self {
        Self {
            heading: heading.into(),
            content: content.into(),
            toggles: Vec::new(),
            buttons,
            details: None,
            expanded: false,
            icon: Icon::App,
            progress: false,
        }
    }
}

/// The items whose toggle is on.
#[must_use]
pub fn chosen<T: Clone>(items: &[T], states: &[bool]) -> Vec<T> {
    items
        .iter()
        .zip(states)
        .filter(|(_, on)| **on)
        .map(|(item, _)| item.clone())
        .collect()
}

fn place_label(place: Place) -> &'static str {
    match place {
        Place::Startup => "Start FactorSeal when you sign in",
        Place::Desktop => "Put a shortcut on the desktop",
        Place::StartMenu => "Put a shortcut in the Start menu",
    }
}

fn place_name(place: Place) -> &'static str {
    match place {
        Place::Startup => "start when you sign in",
        Place::Desktop => "desktop shortcut",
        Place::StartMenu => "Start menu shortcut",
    }
}

/// The release's optional shortcut places, split into those to offer and
/// those the previous install has, which the installer keeps anyway.
#[must_use]
pub fn optional_places(
    release: &Release,
    existing: &Existing,
    places: &Places,
) -> (Vec<Place>, Vec<Place>) {
    let had: &[std::path::PathBuf] = match existing {
        Existing::Recorded(record) => &record.shortcuts,
        _ => &[],
    };
    let (mut offered, mut kept) = (Vec::new(), Vec::new());
    for step in &release.manifest.steps {
        let Step::Shortcut(shortcut) = step else {
            continue;
        };
        for place in &shortcut.optional_places {
            let path = places.dir(*place).join(format!("{}.lnk", shortcut.name));
            let list = if had.contains(&path) {
                &mut kept
            } else {
                &mut offered
            };
            if !list.contains(place) {
                list.push(*place);
            }
        }
    }
    (offered, kept)
}

/// The first page of an install or update.
#[must_use]
pub fn install_page(
    version: &str,
    existing: &Existing,
    install_dir: &Path,
    offered: &[Place],
    kept: &[Place],
) -> Page {
    let dir = install_dir.display();
    let (heading, mut content) = match existing {
        Existing::Fresh => (
            format!("Install FactorSeal {version}"),
            format!("FactorSeal goes in {dir}."),
        ),
        Existing::Recorded(record) => (
            if record.version == version {
                format!("Reinstall FactorSeal {version}")
            } else {
                format!("Update FactorSeal {} to {version}", record.version)
            },
            format!(
                "FactorSeal in {dir} is replaced. If it runs, it is stopped first, and its \
                 vault stays sealed until you unlock it again."
            ),
        ),
        Existing::HandMade => (
            format!("Take over FactorSeal and update it to {version}"),
            format!(
                "FactorSeal in {dir} was extracted by hand. The installer takes it over: its \
                 UNINSTALL.txt goes, and its shortcuts are replaced by the installer's. If it \
                 runs, you are asked to quit it from its tray icon."
            ),
        ),
    };
    if !kept.is_empty() {
        let names: Vec<&str> = kept.iter().map(|place| place_name(*place)).collect();
        content.push_str(" Kept from the installed version: ");
        content.push_str(&names.join(", "));
        content.push('.');
    }
    let mut page = Page::new(heading, content, Buttons::OkCancel);
    page.toggles = offered
        .iter()
        .map(|place| Toggle::new(place_label(*place), false))
        .collect();
    page
}

/// The WSL page: the registered distros, those the install set up before
/// turned on.
#[must_use]
pub fn wsl_page(distros: &[String], recorded: &[String]) -> Page {
    let mut page = Page::new(
        "Set FactorSeal up in WSL?",
        "A WSL distro set up here uses this vault as its keyring. Setting up a distro starts \
         it; one without FactorSeal gets instructions instead. Leave them all off to skip.",
        Buttons::OkCancel,
    );
    page.toggles = distros
        .iter()
        .map(|distro| {
            let on = recorded
                .iter()
                .any(|known| known.eq_ignore_ascii_case(distro));
            Toggle::new(format!("Set up {distro}"), on)
        })
        .collect();
    page
}

/// The progress page.
#[must_use]
pub fn working_page(heading: impl Into<String>) -> Page {
    let mut page = Page::new(heading, "Starting…", Buttons::Working);
    page.progress = true;
    page
}

/// What the run's `result:` line says, without the prefix.
fn result_text(lines: &[String]) -> String {
    let Some(result) = lines
        .iter()
        .rev()
        .find_map(|line| line.strip_prefix("result: "))
    else {
        return "The installer stopped without saying why.".to_owned();
    };
    let text = result
        .strip_prefix("failed: ")
        .or_else(|| result.strip_prefix("refused: "))
        .unwrap_or(result);
    let mut text = text.replace("; see above", "");
    if let Some(first) = text.get(..1) {
        text.replace_range(..1, &first.to_uppercase());
    }
    text
}

fn with_details(mut page: Page, lines: &[String], expanded: bool) -> Page {
    page.details = Some(lines.join("\n"));
    page.expanded = expanded;
    page
}

/// The last page of an install, from its exit code and log lines.
#[must_use]
pub fn install_done(code: u8, version: &str, lines: &[String], can_open: bool) -> Page {
    match code {
        0 | 8 => {
            let mut page = if code == 0 {
                Page::new(
                    format!("FactorSeal {version} is installed"),
                    format!("{}.", result_text(lines)),
                    Buttons::Close,
                )
            } else {
                let mut page = Page::new(
                    format!("FactorSeal {version} is installed, but not in every WSL distro"),
                    "The details say what each distro needs.",
                    Buttons::Close,
                );
                page.icon = Icon::Warning;
                page
            };
            if can_open {
                page.toggles = vec![Toggle::new("Open FactorSeal now", true)];
            }
            with_details(page, lines, code != 0)
        }
        _ => {
            let mut page = Page::new(
                "FactorSeal was not installed",
                format!("{}.", result_text(lines).trim_end_matches('.')),
                Buttons::Close,
            );
            page.icon = Icon::Error;
            with_details(page, lines, true)
        }
    }
}

/// The first page of an uninstall: what goes, with the recorded distros
/// (on) and the release's listed folders that exist (off).
#[must_use]
pub fn uninstall_page(record: &InstallRecord, install_dir: &Path, folders: &[String]) -> Page {
    let mut content = format!(
        "This removes FactorSeal from {}, with its shortcuts and its entry in Installed apps. \
         If FactorSeal runs, it is stopped first.",
        install_dir.display()
    );
    content.push_str("\n\n");
    content.push_str(
        record
            .uninstall
            .keep_note
            .as_deref()
            .unwrap_or("Your vault is kept."),
    );
    let mut page = Page::new(
        format!("Uninstall FactorSeal {}?", record.version),
        content,
        Buttons::OkCancel,
    );
    page.toggles = record
        .distros
        .iter()
        .map(|distro| {
            Toggle::new(
                format!("Remove FactorSeal's setup from WSL distro {distro} (this starts it)"),
                true,
            )
        })
        .collect();
    if !folders.is_empty() {
        page.toggles.push(
            Toggle::new("Also delete FactorSeal's settings", false).with_note(folders.join("\n")),
        );
    }
    page
}

/// The last page of an uninstall.
#[must_use]
pub fn uninstall_done(code: u8, note: Option<&str>, lines: &[String]) -> Page {
    let page = match code {
        0 => Page::new(
            "FactorSeal is uninstalled",
            note.unwrap_or("Your vault is kept."),
            Buttons::Close,
        ),
        8 => {
            let mut page = Page::new(
                "FactorSeal is uninstalled, but its setup is left in a WSL distro",
                "The details say how to remove it there.",
                Buttons::Close,
            );
            page.icon = Icon::Warning;
            page
        }
        _ => {
            let text = result_text(lines);
            // Exit 5 after the files went: FactorSeal is gone, something
            // else is left.
            let partly = text.starts_with("Uninstalled");
            let mut page = Page::new(
                if partly {
                    "FactorSeal is uninstalled, but not everything could be removed"
                } else {
                    "FactorSeal was not uninstalled"
                },
                format!("{}.", text.trim_end_matches('.')),
                Buttons::Close,
            );
            page.icon = if partly { Icon::Warning } else { Icon::Error };
            page
        }
    };
    // The page shows the note already; the details are the rest of the log.
    let details: Vec<String> = lines
        .iter()
        .filter(|line| Some(line.as_str()) != note)
        .cloned()
        .collect();
    with_details(page, &details, code != 0)
}

/// A page that only says what went wrong.
#[must_use]
pub fn error_page(heading: impl Into<String>, text: impl Into<String>) -> Page {
    let mut page = Page::new(heading, text, Buttons::Close);
    page.icon = Icon::Error;
    page
}

#[cfg(test)]
mod tests;
