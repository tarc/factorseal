//! One Desktop per vault root. The first launch holds a lock file and
//! watches an activation file beside it; a later launch writes its request
//! there and exits. Requests are one line: `open`, `open <page>` or `quit`.
//! Desktops built before `open <page>` and `quit` treat any write as
//! `open`, so an older Desktop asked to quit only comes forward.

use std::collections::hash_map::DefaultHasher;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt as _;

/// How often the running Desktop looks for a request, and a quitting
/// launch for the lock.
const POLL: Duration = Duration::from_millis(200);

/// A page a launch can open Desktop on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Page {
    /// Settings, WSL keyrings.
    WslKeyrings,
}

impl Page {
    fn name(self) -> &'static str {
        match self {
            Self::WslKeyrings => "wsl-keyrings",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::WslKeyrings]
            .into_iter()
            .find(|page| page.name() == name)
    }
}

/// What a later launch asks the running Desktop to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    /// Come forward, on this page if one is named.
    Open(Option<Page>),
    /// Seal and quit, as the tray's Quit does.
    Quit,
}

impl Request {
    fn encode(self) -> String {
        match self {
            Self::Open(None) => "open\n".to_owned(),
            Self::Open(Some(page)) => format!("open {}\n", page.name()),
            Self::Quit => "quit\n".to_owned(),
        }
    }

    /// The request in `text`, or `None` while its line is incomplete. A
    /// line this build doesn't know (from a newer Desktop) opens Desktop,
    /// as older builds do with any request.
    fn decode(text: &str) -> Option<Self> {
        let (line, _) = text.split_once('\n')?;
        let line = line.trim_end_matches('\r');
        Some(match line.split_once(' ') {
            None if line == "quit" => Self::Quit,
            Some(("open", page)) => Self::Open(Page::from_name(page)),
            _ => Self::Open(None),
        })
    }
}

pub(crate) enum Instance {
    Primary {
        _lock: File,
        requests: smol::channel::Receiver<Request>,
    },
    Secondary,
}

/// Become the vault's Desktop, or hand `request` (when given) to the one
/// already running.
pub(crate) fn acquire(root: &Path, request: Option<Request>) -> Result<Instance, String> {
    let (lock_path, activation_path) = instance_paths(root)?;
    let file = open_private_file(&lock_path)?;
    if !try_lock(&file)? {
        if let Some(request) = request {
            signal(&activation_path, request)?;
        }
        return Ok(Instance::Secondary);
    }

    let watcher = open_private_file(&activation_path)?;
    watcher.set_len(0).map_err(|error| error.to_string())?;
    let (sender, requests) = smol::channel::bounded(4);
    std::thread::Builder::new()
        .name("factorseal-desktop-activation".to_owned())
        .spawn(move || watch(&watcher, &sender))
        .map_err(|error| error.to_string())?;
    Ok(Instance::Primary {
        _lock: file,
        requests,
    })
}

/// How a quit request ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Quit {
    /// No Desktop was running on the vault.
    NotRunning,
    /// The running Desktop sealed and exited.
    Quit,
}

/// Ask the Desktop running on `root` to seal and quit, and wait until it
/// has exited (its lock is free), at most `timeout`.
pub(crate) fn request_quit(root: &Path, timeout: Duration) -> Result<Quit, String> {
    let (lock_path, activation_path) = instance_paths(root)?;
    let file = open_private_file(&lock_path)?;
    if try_lock(&file)? {
        return Ok(Quit::NotRunning);
    }
    signal(&activation_path, Request::Quit)?;
    let deadline = Instant::now() + timeout;
    loop {
        std::thread::sleep(POLL);
        if try_lock(&file)? {
            return Ok(Quit::Quit);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the running Desktop did not quit within {} s",
                timeout.as_secs()
            ));
        }
    }
}

/// Take the instance lock: `false` when another process holds it.
fn try_lock(file: &File) -> Result<bool, String> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(true),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn signal(path: &Path, request: Request) -> Result<(), String> {
    let mut file = open_private_file(path)?;
    file.set_len(0).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    file.write_all(request.encode().as_bytes())
        .and_then(|()| file.sync_data())
        .map_err(|error| error.to_string())
}

fn watch(mut file: &File, sender: &smol::channel::Sender<Request>) {
    // A line still incomplete after this many polls (a writer that died
    // mid-line) counts as `open`, so it can't block later requests.
    const INCOMPLETE_POLLS: u32 = 5;
    let mut incomplete = 0;
    loop {
        std::thread::sleep(POLL);
        let mut text = String::new();
        let read = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.take(4096).read_to_string(&mut text));
        if read.is_err() || text.is_empty() {
            incomplete = 0;
            continue;
        }
        let request = match Request::decode(&text) {
            Some(request) => request,
            None if incomplete + 1 >= INCOMPLETE_POLLS => Request::Open(None),
            None => {
                incomplete += 1;
                continue;
            }
        };
        incomplete = 0;
        let _ = file.set_len(0);
        if sender.try_send(request).is_err() && sender.is_closed() {
            break;
        }
    }
}

fn instance_paths(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(root)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| "the vault path has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut hasher = DefaultHasher::new();
    absolute.hash(&mut hasher);
    let identifier = format!("{:016x}", hasher.finish());
    Ok((
        parent.join(format!(".factorseal-desktop-{identifier}.lock")),
        parent.join(format!(".factorseal-desktop-{identifier}.activate")),
    ))
}

fn open_private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primary(root: &Path) -> (File, smol::channel::Receiver<Request>) {
        let Instance::Primary {
            _lock: lock,
            requests,
        } = acquire(root, None).unwrap()
        else {
            panic!("first instance was not primary");
        };
        (lock, requests)
    }

    fn next_request(requests: &smol::channel::Receiver<Request>) -> Request {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(request) = requests.try_recv() {
                return request;
            }
            assert!(Instant::now() < deadline, "no request arrived");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn second_instance_requests_activation() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let (_lock, requests) = primary(&root);
        let request = Some(Request::Open(None));
        assert!(matches!(
            acquire(&root, request).unwrap(),
            Instance::Secondary
        ));
        assert_eq!(next_request(&requests), Request::Open(None));
    }

    #[test]
    fn second_instance_asks_for_a_page() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let (_lock, requests) = primary(&root);
        let request = Some(Request::Open(Some(Page::WslKeyrings)));
        assert!(matches!(
            acquire(&root, request).unwrap(),
            Instance::Secondary
        ));
        assert_eq!(
            next_request(&requests),
            Request::Open(Some(Page::WslKeyrings))
        );
    }

    #[test]
    fn requests_round_trip_and_unknown_lines_open() {
        for request in [
            Request::Open(None),
            Request::Open(Some(Page::WslKeyrings)),
            Request::Quit,
        ] {
            assert_eq!(Request::decode(&request.encode()), Some(request));
        }
        // What every Desktop so far writes, also with Windows line ends.
        assert_eq!(Request::decode("open\r\n"), Some(Request::Open(None)));
        // From a newer Desktop: still a request to come forward.
        assert_eq!(
            Request::decode("open passwords\n"),
            Some(Request::Open(None))
        );
        assert_eq!(Request::decode("lock\n"), Some(Request::Open(None)));
        assert_eq!(Request::decode("quit now\n"), Some(Request::Open(None)));
        // Not written to the end yet.
        assert_eq!(Request::decode("qui"), None);
        assert_eq!(Request::decode(""), None);
    }

    #[test]
    fn a_line_left_incomplete_still_opens() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let (_lock, requests) = primary(&root);
        let (_, activation) = instance_paths(&root).unwrap();
        std::fs::write(&activation, "qui").unwrap();
        assert_eq!(next_request(&requests), Request::Open(None));
        // The file was cleared, so the next request gets through.
        assert!(matches!(
            acquire(&root, Some(Request::Quit)).unwrap(),
            Instance::Secondary
        ));
        assert_eq!(next_request(&requests), Request::Quit);
    }

    #[test]
    fn quit_waits_until_the_running_desktop_exits() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let (lock, requests) = primary(&root);
        // The running Desktop: quits, releasing its lock, when asked to.
        let desktop = std::thread::spawn(move || {
            let request = next_request(&requests);
            drop(lock);
            request
        });
        assert_eq!(
            request_quit(&root, Duration::from_secs(10)).unwrap(),
            Quit::Quit
        );
        assert_eq!(desktop.join().unwrap(), Request::Quit);
        // Nothing runs now, and the quit left no instance behind.
        assert_eq!(
            request_quit(&root, Duration::from_secs(10)).unwrap(),
            Quit::NotRunning
        );
        assert!(matches!(
            acquire(&root, None).unwrap(),
            Instance::Primary { .. }
        ));
    }

    #[test]
    fn quit_fails_when_the_running_desktop_stays() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        // A Desktop that never quits: an older one only comes forward.
        let (_lock, requests) = primary(&root);
        let error = request_quit(&root, Duration::from_millis(500)).unwrap_err();
        assert!(error.contains("did not quit"), "{error}");
        assert_eq!(next_request(&requests), Request::Quit);
    }
}
