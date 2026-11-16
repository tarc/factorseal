//! `factorseal-setup.exe`: a per-user Windows installer that never changes
//! per FactorSeal release (`docs/plans/windows-installer.md`). It embeds no
//! payload: a release is a folder of artifacts plus a
//! `factorseal-release.json` that lists them with their hashes and the
//! install steps, from the installer's fixed vocabulary.
//!
//! - [`manifest`] reads and verifies a release;
//! - [`engine`] stages it beside the install folder and swaps it in;
//! - [`record`] is `install.json`, what updates and uninstall undo from;
//! - [`steps`] runs the `shortcut`, `registry` and `start` steps and
//!   registers the install in Installed apps, through [`shortcut`] (shell
//!   links written directly) and [`registry`];
//! - [`stop`] stops the installed version before its files change;
//! - [`wsl`] sets FactorSeal up in the WSL distros the user chose;
//! - [`uninstall`] undoes what the record says the installer did.

pub mod engine;
pub mod manifest;
pub mod record;
pub mod registry;
pub mod shortcut;
pub mod steps;
pub mod stop;
pub mod uninstall;
pub mod wsl;

/// Linux refuses to run a file some process has open for writing
/// (`ETXTBSY`), and a child forked by one test thread holds the file
/// another thread is writing until it runs its program. Tests that write
/// an executable or start a process hold this lock, so the two never
/// overlap.
#[cfg(test)]
pub(crate) fn exec_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub use manifest::{Manifest, ManifestError, Release, ReleaseFile, SCHEMA, SETUP_CAPABILITY, Step};
