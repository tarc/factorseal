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
    config_path().map_or(Ok(None), |path| load_from(&path))
}

/// The configuration at `path`, or `None` if there is no file.
pub(super) fn load_from(path: &Path) -> Result<Option<WslConfig>, CliError> {
    match fs::read(path) {
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
pub(super) fn setup(
    windows_install: Option<&Path>,
    windows_root: Option<&std::ffi::OsStr>,
    remove: bool,
) -> Result<(), CliError> {
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
    let config = windows_config(&install, windows_root, distro)?;
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

/// The configuration for the Windows installation in `install`: its broker,
/// and the pipe of the vault at `windows_root` (the default vault if
/// `None`), named after that vault's installation id.
fn windows_config(
    install: &Path,
    windows_root: Option<&std::ffi::OsStr>,
    distro: String,
) -> Result<WslConfig, CliError> {
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
    let pipe = format!("{PIPE_PREFIX}{}", installation_id(&cli, windows_root)?);
    Ok(WslConfig {
        broker,
        pipe,
        distro,
    })
}

/// `%LOCALAPPDATA%\Programs\FactorSeal`, where the Windows installation
/// lives by default, as WSL sees it.
fn default_install() -> Result<PathBuf, CliError> {
    // `/u` makes cmd.exe write UTF-16LE instead of the OEM code page, which
    // would mangle a profile folder named outside it.
    let output = Command::new("cmd.exe")
        .args(["/u", "/d", "/c", "echo %LOCALAPPDATA%"])
        .current_dir("/")
        .output()
        .map_err(|error| {
            CliError::WslSetup(format!(
                "could not ask Windows for %LOCALAPPDATA% (is WSL interop enabled?): {error}"
            ))
        })?;
    let local = windows_output(&output.stdout).unwrap_or_default();
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

/// Output of `cmd.exe /u`: UTF-16LE, trimmed. `None` if it isn't.
fn windows_output(bytes: &[u8]) -> Option<String> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let units: Vec<u16> = units.iter().map(|unit| u16::from_le_bytes(*unit)).collect();
    String::from_utf16(&units)
        .ok()
        .map(|text| text.trim().to_owned())
}

/// The Windows vault's installation id, from `factorseal.exe [--root R]
/// status`, which reads it from the vault's metadata whether or not the
/// vault is unsealed.
fn installation_id(cli: &Path, windows_root: Option<&std::ffi::OsStr>) -> Result<String, CliError> {
    #[derive(Deserialize)]
    struct Status {
        installation_id: String,
    }
    let mut command = Command::new(cli);
    if let Some(root) = windows_root {
        command.arg("--root").arg(root);
    }
    let output = command
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

/// Write `bytes` to `path`, readable by the user only. A directory this
/// creates is private; an existing one keeps its mode, since
/// `FACTORSEAL_WSL_CONFIG` can name any directory, but must not be writable
/// by others, who could replace the file.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let failed = |error: std::io::Error| {
        CliError::WslSetup(format!("could not write {}: {error}", path.display()))
    };
    let directory = path
        .parent()
        .ok_or_else(|| CliError::WslSetup(format!("{} has no parent directory", path.display())))?;
    match fs::metadata(directory) {
        Ok(metadata) if metadata.permissions().mode() & 0o022 != 0 => {
            return Err(CliError::WslSetup(format!(
                "{} is writable by other users; choose a private directory",
                directory.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(failed)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(failed)?;
        }
        Err(error) => return Err(failed(error)),
    }
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
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The configuration can live in a directory that isn't FactorSeal's
    /// (`FACTORSEAL_WSL_CONFIG`): leave its mode alone, refuse one others can
    /// write to, and make only a directory it creates private.
    #[test]
    fn wsl_config_writes_leave_an_existing_directory_alone() {
        let base = tempfile::tempdir().unwrap();
        let shared = base.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        write_private(&shared.join("wsl.json"), b"{}").unwrap();
        assert_eq!(mode(&shared), 0o755);
        assert_eq!(mode(&shared.join("wsl.json")), 0o600);

        let open = base.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_private(&open.join("wsl.json"), b"{}").is_err());
        assert_eq!(mode(&open), 0o777);
        assert!(!open.join("wsl.json").exists());

        let created = base.path().join("new/factorseal");
        write_private(&created.join("wsl.json"), b"{}").unwrap();
        assert_eq!(mode(&created), 0o700);
        assert_eq!(mode(&created.join("wsl.json")), 0o600);
    }

    /// `cmd.exe /u` writes UTF-16LE, so a profile folder outside the OEM
    /// code page survives.
    #[test]
    fn wsl_setup_reads_windows_output_as_utf16() {
        let local = r"C:\Users\João\AppData\Local";
        let mut bytes: Vec<u8> = format!("{local}\r\n")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(windows_output(&bytes).as_deref(), Some(local));
        bytes.push(0);
        assert_eq!(windows_output(&bytes), None);
        let unpaired: Vec<u8> = [0xD800_u16]
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(windows_output(&unpaired), None);
    }

    /// A Windows installation folder with a fake `factorseal.exe` that
    /// records its arguments and reports `installation_id`, and an empty
    /// broker.
    fn fake_install(directory: &Path, installation_id: &str) -> PathBuf {
        let install = directory.join("install");
        fs::create_dir(&install).unwrap();
        fs::write(install.join(BROKER), b"").unwrap();
        let cli = install.join(WINDOWS_CLI);
        fs::write(
            &cli,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '{{\"installation_id\":\"{installation_id}\",\"state\":\"sealed\"}}'\n",
                directory.join("args").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).unwrap();
        install
    }

    #[test]
    fn wsl_setup_reads_the_pipe_from_the_windows_vault() {
        let directory = tempfile::tempdir().unwrap();
        let install = fake_install(directory.path(), "abc-1");
        let args = || fs::read_to_string(directory.path().join("args")).unwrap();

        let config = windows_config(&install, None, "NixOS".to_owned()).unwrap();
        assert_eq!(config.pipe, r"\\.\pipe\factorseal-abc-1");
        assert_eq!(config.broker, install.join(BROKER));
        assert_eq!(config.distro, "NixOS");
        assert_eq!(args(), "status\n");

        // Another vault, such as the check vault, by its Windows root.
        let root = r"C:\Users\x\AppData\Local\FactorSeal-check\vault";
        let config = windows_config(
            &install,
            Some(std::ffi::OsStr::new(root)),
            "NixOS".to_owned(),
        )
        .unwrap();
        assert_eq!(config.pipe, r"\\.\pipe\factorseal-abc-1");
        assert_eq!(args(), format!("--root\n{root}\nstatus\n"));

        fs::remove_file(install.join(BROKER)).unwrap();
        assert!(windows_config(&install, None, "NixOS".to_owned()).is_err());
    }

    #[test]
    fn wsl_setup_refuses_an_installation_id_that_is_not_a_pipe_name() {
        let directory = tempfile::tempdir().unwrap();
        let install = fake_install(directory.path(), "../x");
        assert!(windows_config(&install, None, "NixOS".to_owned()).is_err());
    }

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
