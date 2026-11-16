//! The `wsl` step: FactorSeal set up in the WSL distros the user chose
//! (Flows, step 5, of `docs/plans/windows-installer.md`).
//!
//! The manifest only says that WSL setup is part of the release. The shell
//! code is the installer's own: three fixed lines ([`Line`]), run through
//! `wsl.exe -d <distro> --exec sh -lc <line> sh <arguments>`, so a tampered
//! manifest can't run anything in a distro. The one value a line needs,
//! the install folder, reaches it as `$1`, never spliced into the code.
//!
//! Each chosen distro is probed first: whether `factorseal` is there, and
//! the `ID` from `/etc/os-release`. Probing starts the distro, which is why
//! the user chooses the distros before anything runs. A distro without
//! `factorseal` gets a hint, keyed by that `ID` (`nixos`), not by the
//! distro's name, which is the user's choice. One with it runs
//! `factorseal wsl-setup` pointed at the install folder.

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The longest distro name WSL commands accept here, as the vault's
/// protocol does.
const MAX_DISTRO_BYTES: usize = 64;

/// How long one line may run: the first command in a stopped distro waits
/// for it to start.
pub const LINE_TIMEOUT: Duration = Duration::from_secs(120);

/// The installer's fixed shell lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Line {
    /// Whether `factorseal` is installed, and the distro's os-release `ID`.
    Probe,
    /// Point the distro's FactorSeal at the Windows install folder (`$1`,
    /// a Windows path).
    Setup,
    /// Remove that configuration again (uninstall).
    Remove,
}

impl Line {
    /// The shell code, run by `sh -lc` so the login profile puts the
    /// distro's packages on `PATH` (NixOS keeps them out of a bare `sh`).
    #[must_use]
    pub fn script(self) -> &'static str {
        match self {
            Self::Probe => {
                "if command -v factorseal >/dev/null 2>&1; then echo factorseal=found; \
                 else echo factorseal=missing; fi; \
                 if [ -r /etc/os-release ]; then . /etc/os-release; fi; \
                 echo \"id=${ID:-}\""
            }
            Self::Setup => {
                "install=$(wslpath -u \"$1\") || exit 1; \
                 exec factorseal wsl-setup --windows-install \"$install\""
            }
            Self::Remove => "exec factorseal wsl-setup --remove",
        }
    }
}

/// What a line printed, and whether it succeeded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// WSL, behind a trait for tests.
pub trait Wsl {
    /// Run `line` in `distro` with `arguments` as `$1`…; an error when it
    /// couldn't be run at all.
    fn run(&mut self, distro: &str, line: Line, arguments: &[String]) -> Result<Output, String>;
}

/// A distro name as WSL and the vault accept it: letters, digits, `.`,
/// `-` and `_`.
pub fn check_distro(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_DISTRO_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(format!("{name:?} is not a WSL distro name"))
    }
}

/// What setting up WSL did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The distros set up, to record.
    pub set_up: Vec<String>,
    /// One line per distro that wasn't: why, or the hint for it.
    pub problems: Vec<String>,
}

/// Set up FactorSeal in each of `distros`, for the install in
/// `install_dir`, telling `say` what happens.
pub fn set_up(
    distros: &[String],
    install_dir: &Path,
    wsl: &mut dyn Wsl,
    say: &mut dyn FnMut(&str),
) -> Report {
    let mut report = Report::default();
    let install = install_dir.to_string_lossy().into_owned();
    for distro in distros {
        say(&format!("checking FactorSeal in WSL distro {distro}"));
        match set_up_one(distro, &install, wsl, say) {
            Ok(()) => report.set_up.push(distro.clone()),
            Err(problem) => {
                say(&problem);
                report.problems.push(problem);
            }
        }
    }
    report
}

fn set_up_one(
    distro: &str,
    install: &str,
    wsl: &mut dyn Wsl,
    say: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let probe = wsl
        .run(distro, Line::Probe, &[])
        .map_err(|error| format!("cannot reach WSL distro {distro}: {error}"))?;
    if !probe.success {
        return Err(format!(
            "cannot check WSL distro {distro}: {}",
            detail(&probe)
        ));
    }
    let Probe { found, id } = Probe::parse(&probe.stdout);
    if !found {
        return Err(hint(distro, id.as_deref()));
    }
    let setup = wsl
        .run(distro, Line::Setup, &[install.to_owned()])
        .map_err(|error| format!("cannot set up WSL distro {distro}: {error}"))?;
    if !setup.success {
        return Err(format!(
            "setting up WSL distro {distro} failed: {}",
            detail(&setup)
        ));
    }
    for line in setup.stdout.lines().filter(|line| !line.trim().is_empty()) {
        say(&format!("{distro}: {}", line.trim()));
    }
    say(&format!("set up WSL distro {distro}"));
    Ok(())
}

/// Remove FactorSeal's setup from each of `distros` (uninstall), telling
/// `say` what happens. Returns one line per distro where that failed.
pub fn remove(distros: &[String], wsl: &mut dyn Wsl, say: &mut dyn FnMut(&str)) -> Vec<String> {
    let mut problems = Vec::new();
    for distro in distros {
        say(&format!(
            "removing FactorSeal's setup from WSL distro {distro}"
        ));
        let why = match wsl.run(distro, Line::Remove, &[]) {
            Ok(output) if output.success => {
                for line in output.stdout.lines().filter(|line| !line.trim().is_empty()) {
                    say(&format!("{distro}: {}", line.trim()));
                }
                continue;
            }
            Ok(output) => detail(&output),
            Err(error) => error,
        };
        let problem = format!(
            "removing FactorSeal's setup from WSL distro {distro} failed: {why}; run \
             `factorseal wsl-setup --remove` in it"
        );
        say(&problem);
        problems.push(problem);
    }
    problems
}

/// What [`Line::Probe`] found.
#[derive(Debug, PartialEq, Eq)]
struct Probe {
    found: bool,
    /// The os-release `ID`, when it is a plain one.
    id: Option<String>,
}

impl Probe {
    fn parse(stdout: &str) -> Self {
        let mut probe = Self {
            found: false,
            id: None,
        };
        for line in stdout.lines().map(str::trim) {
            if line == "factorseal=found" {
                probe.found = true;
            } else if let Some(id) = line.strip_prefix("id=") {
                let plain = !id.is_empty()
                    && id.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'-' | b'_')
                    });
                probe.id = plain.then(|| id.to_owned());
            }
        }
        probe
    }
}

/// The installer's hint for a distro without `factorseal`, by os-release
/// `ID`.
#[must_use]
pub fn hint(distro: &str, id: Option<&str>) -> String {
    match id {
        Some("nixos") => format!(
            "FactorSeal isn't installed in WSL distro {distro}: add the factorseal package to \
             its NixOS configuration, rebuild, and run this installer again. Turn on \
             services.factorseal only after moving gnome-keyring's items into FactorSeal \
             (FactorSeal Desktop, WSL keyrings)"
        ),
        _ => format!(
            "FactorSeal isn't installed in WSL distro {distro}: install FactorSeal in it, then \
             run this installer again"
        ),
    }
}

/// The end of what a failed line printed, for the log.
fn detail(output: &Output) -> String {
    let text = if output.stderr.trim().is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let tail = lines[lines.len().saturating_sub(3)..].join(" / ");
    if tail.is_empty() {
        "it printed nothing".to_owned()
    } else if tail.chars().count() > 400 {
        let kept: String = tail.chars().take(400).collect();
        format!("{kept}…")
    } else {
        tail
    }
}

/// `wsl.exe` (or a stand-in for tests).
pub struct SystemWsl {
    pub program: std::path::PathBuf,
    /// Never the install folder, whose swap a working directory would stop.
    pub working_dir: std::path::PathBuf,
    pub timeout: Duration,
}

impl SystemWsl {
    /// The command for `script` in `distro`. `--exec` hands the arguments
    /// to `sh` one by one instead of joining them into a line for the
    /// user's shell.
    #[must_use]
    pub fn command(&self, distro: &str, script: &str, arguments: &[String]) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(["-d", distro, "--exec", "sh", "-lc", script, "sh"])
            .args(arguments)
            .current_dir(&self.working_dir)
            // wsl.exe's own messages in UTF-8 instead of UTF-16.
            .env("WSL_UTF8", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Run `command`, killing it after the timeout.
    pub fn output(&self, mut command: Command) -> Result<Output, String> {
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start {}: {error}", self.program.display()))?;
        let (sender, receiver) = mpsc::channel();
        for (index, pipe) in [
            child
                .stdout
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .enumerate()
        {
            let sender = sender.clone();
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = pipe {
                    let _ = pipe.read_to_end(&mut bytes);
                }
                let _ = sender.send((index, bytes));
            });
        }
        drop(sender);
        let deadline = std::time::Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("it didn't return in {} s", self.timeout.as_secs()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(error) => return Err(error.to_string()),
            }
        };
        let mut output = Output {
            success: status.success(),
            ..Output::default()
        };
        // A program the line started may still hold a pipe; don't wait
        // for it past the deadline.
        for _ in 0..2 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match receiver.recv_timeout(left.max(Duration::from_secs(1))) {
                Ok((0, bytes)) => output.stdout = decode(&bytes),
                Ok((_, bytes)) => output.stderr = decode(&bytes),
                Err(_) => break,
            }
        }
        Ok(output)
    }
}

impl Wsl for SystemWsl {
    fn run(&mut self, distro: &str, line: Line, arguments: &[String]) -> Result<Output, String> {
        check_distro(distro)?;
        self.output(self.command(distro, line.script(), arguments))
    }
}

/// Text from WSL: UTF-8 from the distro, or UTF-16LE from a `wsl.exe`
/// that ignores `WSL_UTF8`.
#[must_use]
pub fn decode(bytes: &[u8]) -> String {
    let (units, rest) = bytes.as_chunks::<2>();
    let utf16 = rest.is_empty() && units.iter().any(|unit| unit[1] == 0 && unit[0] != 0);
    if utf16
        && let Ok(text) = String::from_utf16(
            &units
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect::<Vec<_>>(),
        )
    {
        return text;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests;
