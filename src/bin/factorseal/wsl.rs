//! The SecretSpec provider in WSL2, served by the vault on Windows.
//!
//! `factorseal wsl-setup` records where the Windows broker is and which pipe
//! the Windows vault listens on, in `wsl.json` under the user's
//! configuration directory, and publishes the SecretSpec claim. From then
//! on `factorseal provider` reaches the Windows vault through the broker
//! (see `factorseal::vault::wsl_relay`) instead of a Linux vault.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use factorseal::vault::wsl_relay::{BrokerVaultClient, validate_distro};
use serde::{Deserialize, Serialize};

use super::CliError;

/// Overrides the configuration file, for checks that use a test vault.
/// Listed in the SecretSpec claim so SecretSpec passes it to the provider.
pub(super) const CONFIG_ENVIRONMENT: &str = "FACTORSEAL_WSL_CONFIG";

const BROKER: &str = "factorseal-wsl-broker.exe";
const WINDOWS_CLI: &str = "factorseal.exe";
const PIPE_PREFIX: &str = r"\\.\pipe\factorseal-";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WslConfig {
    /// `factorseal-wsl-broker.exe`, as WSL sees it (`/mnt/c/...`).
    broker: PathBuf,
    /// The Windows vault's named pipe.
    pipe: String,
    /// The distro name the broker declares for each request.
    distro: String,
}

impl WslConfig {
    pub(super) fn client(self) -> Result<BrokerVaultClient, CliError> {
        Ok(BrokerVaultClient::new(self.broker, self.pipe, self.distro)?)
    }
}

fn config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(CONFIG_ENVIRONMENT) {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("factorseal/wsl.json"))
}

/// The configuration `wsl-setup` wrote, if any.
pub(super) fn load() -> Result<Option<WslConfig>, CliError> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            CliError::WslSetup(format!("{} is not valid: {error}", path.display()))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::WslSetup(format!(
            "could not read {}: {error}",
            path.display()
        ))),
    }
}

/// `factorseal wsl-setup`: point the SecretSpec provider in this distro at
/// the vault of the Windows installation in `windows_install`, or remove
/// that configuration.
pub(super) fn setup(windows_install: Option<&Path>, remove: bool) -> Result<(), CliError> {
    let path = config_path().ok_or_else(|| {
        CliError::WslSetup("the user configuration directory is unavailable".to_owned())
    })?;
    if remove {
        match fs::remove_file(&path) {
            Ok(()) => println!("Removed {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("Nothing to remove: {} does not exist", path.display());
            }
            Err(error) => {
                return Err(CliError::WslSetup(format!(
                    "could not remove {}: {error}",
                    path.display()
                )));
            }
        }
        return Ok(());
    }
    let distro = std::env::var("WSL_DISTRO_NAME").map_err(|_| {
        CliError::WslSetup("WSL_DISTRO_NAME is not set; run this inside WSL".to_owned())
    })?;
    validate_distro(&distro)?;
    let install = match windows_install {
        Some(install) => install.to_owned(),
        None => default_install()?,
    };
    let broker = install.join(BROKER);
    let cli = install.join(WINDOWS_CLI);
    for required in [&broker, &cli] {
        if !required.is_file() {
            return Err(CliError::WslSetup(format!(
                "{} is missing; pass --windows-install with the folder that holds FactorSeal on Windows",
                required.display()
            )));
        }
    }
    let pipe = format!("{PIPE_PREFIX}{}", installation_id(&cli)?);
    let config = WslConfig {
        broker,
        pipe,
        distro,
    };
    write_private(&path, &serde_json::to_vec_pretty(&config)?)?;
    super::secretspec_discovery::publish_for_wsl()?;
    println!("Wrote {}", path.display());
    println!(
        "SecretSpec in this distro now uses the Windows vault ({}) through {}",
        config.pipe,
        config.broker.display()
    );
    Ok(())
}

/// `%LOCALAPPDATA%\Programs\FactorSeal`, where the Windows installation
/// lives by default, as WSL sees it.
fn default_install() -> Result<PathBuf, CliError> {
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "echo %LOCALAPPDATA%"])
        .current_dir("/")
        .output()
        .map_err(|error| {
            CliError::WslSetup(format!(
                "could not ask Windows for %LOCALAPPDATA% (is WSL interop enabled?): {error}"
            ))
        })?;
    let local = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || local.is_empty() || local.contains('%') {
        return Err(CliError::WslSetup(
            "Windows did not report %LOCALAPPDATA%; pass --windows-install".to_owned(),
        ));
    }
    let output = Command::new("wslpath")
        .args(["-u", &format!(r"{local}\Programs\FactorSeal")])
        .output()
        .map_err(|error| CliError::WslSetup(format!("could not run wslpath: {error}")))?;
    if !output.status.success() {
        return Err(CliError::WslSetup(
            "wslpath could not translate the Windows install folder; pass --windows-install"
                .to_owned(),
        ));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}

/// The Windows vault's installation id, from `factorseal.exe status`, which
/// reads it from the vault's metadata whether or not the vault is unsealed.
fn installation_id(cli: &Path) -> Result<String, CliError> {
    #[derive(Deserialize)]
    struct Status {
        installation_id: String,
    }
    let output = Command::new(cli)
        .arg("status")
        .current_dir("/")
        .output()
        .map_err(|error| CliError::WslSetup(format!("could not run {}: {error}", cli.display())))?;
    if !output.status.success() {
        return Err(CliError::WslSetup(format!(
            "{} status failed: {}",
            cli.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let status: Status = serde_json::from_slice(&output.stdout).map_err(|error| {
        CliError::WslSetup(format!(
            "{} status printed no installation id: {error}",
            cli.display()
        ))
    })?;
    let valid = !status.installation_id.is_empty()
        && status
            .installation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        return Err(CliError::WslSetup(
            "the Windows vault reported an unexpected installation id".to_owned(),
        ));
    }
    Ok(status.installation_id)
}

/// Write `bytes` to `path`, readable by the user only, in a directory only
/// the user can open.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let failed = |error: std::io::Error| {
        CliError::WslSetup(format!("could not write {}: {error}", path.display()))
    };
    let directory = path
        .parent()
        .ok_or_else(|| CliError::WslSetup(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(directory).map_err(failed)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(failed)?;
    let temporary = directory.join(format!(".wsl.json.{}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(failed)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(failed(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_round_trips_and_rejects_unknown_fields() {
        let config = WslConfig {
            broker: "/mnt/c/FactorSeal/factorseal-wsl-broker.exe".into(),
            pipe: format!("{PIPE_PREFIX}abc"),
            distro: "NixOS".to_owned(),
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        let read: WslConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read.pipe, config.pipe);
        assert!(read.client().is_ok());
        assert!(
            serde_json::from_slice::<WslConfig>(br#"{"broker":"b","pipe":"p","distro":"d","x":1}"#)
                .is_err()
        );
    }
}
