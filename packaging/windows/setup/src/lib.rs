//! `factorseal-setup.exe`: a per-user Windows installer that never changes
//! per FactorSeal release (`docs/plans/windows-installer.md`). It embeds no
//! payload: a release is a folder of artifacts plus a
//! `factorseal-release.json` that lists them with their hashes and the
//! install steps, from the installer's fixed vocabulary.
//!
//! This crate so far reads and verifies that manifest ([`manifest`]),
//! which is plain Rust and tested on every platform.

pub mod manifest;

pub use manifest::{Manifest, ManifestError, Release, ReleaseFile, SCHEMA, SETUP_CAPABILITY, Step};
