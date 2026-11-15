//! The WSL distros registered for this Windows user, for Settings, WSL
//! keyrings. Read from the registry (`HKCU\...\Lxss`), so WSL is not started.

/// What Settings shows: the registered distros, and whether the WSL broker
/// is installed beside the CLI (without it no distro can use the vault).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WslDistros {
    pub(crate) registered: Result<Vec<String>, String>,
    pub(crate) broker_installed: bool,
}

impl WslDistros {
    #[cfg(windows)]
    pub(crate) fn load() -> Self {
        Self {
            registered: registered(),
            broker_installed: crate::runtime::wsl_broker_installed(),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn load() -> Self {
        Self {
            registered: Ok(Vec::new()),
            broker_installed: false,
        }
    }
}

/// The distro names in `reg.exe query ...\Lxss /s /v DistributionName`
/// output, sorted, without duplicates or names that are not valid distro
/// names.
#[cfg(any(windows, test))]
pub(crate) fn parse_registered(output: &str) -> Vec<String> {
    let mut distros: Vec<String> = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("DistributionName") && fields.next() == Some("REG_SZ"))
                .then(|| fields.collect::<Vec<_>>().join(" "))
        })
        .filter(|name| factorseal::vault::wsl_relay::validate_distro(name).is_ok())
        .collect();
    distros.sort_unstable();
    distros.dedup();
    distros
}

/// Windows' own `reg.exe`, by full path: a bare `reg.exe` is looked up in
/// the application's folder first.
#[cfg(any(windows, test))]
fn system_reg_exe(system_root: Option<std::ffi::OsString>) -> std::ffi::OsString {
    let mut path = system_root
        .filter(|root| !root.is_empty())
        .unwrap_or_else(|| r"C:\Windows".into());
    path.push(r"\System32\reg.exe");
    path
}

#[cfg(windows)]
fn registered() -> Result<Vec<String>, String> {
    use std::os::windows::process::CommandExt as _;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new(system_reg_exe(std::env::var_os("SystemRoot")))
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss",
            "/s",
            "/v",
            "DistributionName",
        ])
        .stdin(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| error.to_string())?;
    // No Lxss key: WSL has no distro for this user.
    Ok(parse_registered(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distro_names_come_from_the_registry_listing() {
        let output = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{2f1d}\r\n    DistributionName    REG_SZ    NixOS\r\n\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{9a3c}\r\n    DistributionName    REG_SZ    Ubuntu-24.04\r\n\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{bad}\r\n    DistributionName    REG_SZ    not/valid\r\n    DistributionName    REG_SZ    NixOS\r\n\r\nFim da pesquisa: 3 correspond\u{ea}ncias encontradas.\r\n";
        assert_eq!(parse_registered(output), ["NixOS", "Ubuntu-24.04"]);
        assert_eq!(parse_registered(""), Vec::<String>::new());
    }

    #[test]
    fn reg_exe_is_windows_own() {
        assert_eq!(
            system_reg_exe(Some(r"D:\Win".into())),
            std::ffi::OsString::from(r"D:\Win\System32\reg.exe")
        );
        for missing in [None, Some(std::ffi::OsString::new())] {
            assert_eq!(
                system_reg_exe(missing),
                std::ffi::OsString::from(r"C:\Windows\System32\reg.exe")
            );
        }
    }
}
