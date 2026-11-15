//! Relaying vault requests from WSL2 through `factorseal-wsl-broker.exe`.
//!
//! A Linux client in WSL (the SecretSpec provider, or the WSL keyring host
//! `factorseal wsl-keyring`) writes each encoded
//! [`VaultRequest`] to the broker's standard input and reads the encoded
//! [`VaultResponse`] from its standard output. Each message is a frame: a
//! four-byte little-endian length, then that many bytes.
//!
//! The broker decodes a request with [`VaultRequest::decode_relayed_from_wsl`],
//! which tags it with the distro and rewrites its folder into a Windows path,
//! forwards it only if [`relay_allows`] its action, and answers anything else
//! itself ([`serve`]), so the relay never carries other requests. That
//! narrows what honest WSL clients can trigger; it is not a boundary, since
//! a WSL process can run any Windows program of the user through interop.
//! Everything here is caller-declared context (the distro, the folder, the
//! launch chain): the vault still authenticates only the broker.

use std::io::{self, Read, Write};

use super::wire::{
    MAX_MESSAGE_BYTES, RequestId, VaultAction, VaultClient, VaultRequest, VaultResponse,
    VaultResponseError, VaultResponseErrorCode,
};
use crate::vault::{VaultError, VaultResult};

/// Largest frame either side accepts: the vault's own message bound.
pub const MAX_RELAY_FRAME_BYTES: usize = MAX_MESSAGE_BYTES;

/// Longest distro name accepted. WSL itself allows 64 characters or fewer.
const MAX_DISTRO_BYTES: usize = 64;

/// Read one frame. Returns `None` when the stream ends before a frame
/// starts, which is how the client says it is done.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    let mut filled = 0;
    while filled < length.len() {
        match reader.read(&mut length[filled..])? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            read => filled += read,
        }
    }
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is too large"))?;
    if length > MAX_RELAY_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame is too large",
        ));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// Write one frame and flush it.
pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_RELAY_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame is too large",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame is too large"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// Whether the broker for `distro` forwards a request with this action to
/// the vault: exactly what the WSL clients send. The SecretSpec provider's
/// cache actions and permission waits; and the WSL keyring host's access
/// checks, whose action may only read or write `distro`'s keyring, plus its
/// own read of that keyring's index (labels and attributes, no secrets).
/// Item values only travel inside an access check for a declared caller,
/// and nothing seals the vault. Everything else is answered by the broker,
/// so the relay never raises an approval prompt for it (see the module
/// documentation for what that does not prevent).
#[must_use]
pub fn relay_allows(action: &VaultAction, distro: &str) -> bool {
    let in_keyring = |namespace: &[u8]| wsl_keyring_distro(namespace) == Some(distro);
    match action {
        VaultAction::Status
        | VaultAction::WaitPermission { .. }
        | VaultAction::GetCache { .. }
        | VaultAction::PutCache { .. }
        | VaultAction::DeleteCache { .. } => true,
        VaultAction::WslKeyringAccess { action, .. } => match action.as_deref() {
            None => true,
            Some(VaultAction::Get { namespace, .. } | VaultAction::Mutate { namespace, .. }) => {
                in_keyring(namespace)
            }
            Some(_) => false,
        },
        VaultAction::Get { namespace, address } => {
            in_keyring(namespace)
                && address.item == SECRET_SERVICE_INDEX_ITEM
                && address.field.is_none()
        }
        _ => false,
    }
}

/// Serve one Linux client in the broker: answer each request frame read
/// from `input` with one response frame on `output`, until the input ends.
///
/// Each request is decoded with [`VaultRequest::decode_relayed_from_wsl`]
/// and sent to `client` only if [`relay_allows`] its action; anything else
/// is refused here with the request's own id. When the vault is sealed or
/// unreachable, the client gets `Sealed`, and `on_sealed` (which brings
/// Desktop forward) runs the first time only, unless `options` say
/// `--no-desktop`.
pub fn serve(
    client: &dyn VaultClient,
    distro: &str,
    options: &RelayOptions,
    input: &mut impl Read,
    output: &mut impl Write,
    on_sealed: impl FnOnce(),
) -> VaultResult<()> {
    validate_distro(distro)?;
    let mut on_sealed = (!options.no_desktop).then_some(on_sealed);
    while let Some(frame) = read_frame(input)
        .map_err(|error| VaultError::Protocol(format!("reading a request: {error}")))?
    {
        let (response, sealed) = relay_one(client, distro, &frame);
        if sealed && let Some(on_sealed) = on_sealed.take() {
            on_sealed();
        }
        let bytes = response.encode()?;
        write_frame(output, bytes.as_ref())
            .map_err(|error| VaultError::Protocol(format!("writing a response: {error}")))?;
    }
    Ok(())
}

/// The response to one relayed frame, and whether the vault was sealed or
/// unreachable.
fn relay_one(client: &dyn VaultClient, distro: &str, frame: &[u8]) -> (VaultResponse, bool) {
    let id =
        VaultRequest::encoded_request_id(frame).unwrap_or_else(|| RequestId::from_bytes([0; 16]));
    let request = match VaultRequest::decode_relayed_from_wsl(frame, distro) {
        Ok(request) => request,
        Err(error) => {
            return (
                refusal(
                    id,
                    VaultResponseErrorCode::InvalidRequest,
                    error.to_string(),
                ),
                false,
            );
        }
    };
    if !relay_allows(&request.action, distro) {
        return (
            refusal(
                id,
                VaultResponseErrorCode::AuthorizationRequired,
                "the WSL broker does not relay this request".to_owned(),
            ),
            false,
        );
    }
    match client.request(&request) {
        Ok(response) => {
            let sealed = matches!(
                &response.result,
                Err(VaultResponseError {
                    code: VaultResponseErrorCode::Sealed,
                    ..
                })
            );
            (response, sealed)
        }
        Err(VaultError::Sealed | VaultError::AgentUnreachable(_)) => (
            refusal(
                id,
                VaultResponseErrorCode::Sealed,
                "unlock FactorSeal Desktop on Windows, then try again".to_owned(),
            ),
            true,
        ),
        Err(error) => (
            refusal(id, VaultResponseErrorCode::Internal, error.to_string()),
            false,
        ),
    }
}

fn refusal(id: RequestId, code: VaultResponseErrorCode, message: String) -> VaultResponse {
    VaultResponse::failure(
        id,
        VaultResponseError {
            code,
            message,
            interaction: None,
        },
    )
}

/// Check a caller-declared distro name before it goes into a path and an
/// approval prompt: what WSL itself allows in a name, letters, digits, `.`,
/// `-` and `_`.
pub fn validate_distro(distro: &str) -> VaultResult<()> {
    let valid = !distro.is_empty()
        && distro.len() <= MAX_DISTRO_BYTES
        && distro != "."
        && distro != ".."
        && distro
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(VaultError::Protocol(
            "the WSL distro name is not valid".to_owned(),
        ))
    }
}

/// The item holding a Secret Service collection's index (labels and
/// attributes, no secrets), as the adapter names it.
const SECRET_SERVICE_INDEX_ITEM: &str = "secret-service-index";

/// Check a Windows vault root before it becomes an argument of Desktop.
fn validate_windows_root(root: &str) -> VaultResult<()> {
    if root.is_empty() || root.len() > 32 * 1024 || root.contains('\0') {
        return Err(VaultError::Protocol(
            "the Windows vault root is not valid".to_owned(),
        ));
    }
    Ok(())
}

/// The options after `relay` on the broker's command line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayOptions {
    /// `--root <WINDOWS_ROOT>`: the root of the vault the broker serves,
    /// which it passes to Desktop when it brings it forward.
    pub root: Option<String>,
    /// `--no-desktop`: never bring Desktop forward, for a client that checks
    /// the vault by itself (the WSL keyring host's monitor) rather than for
    /// a person waiting on an answer.
    pub no_desktop: bool,
}

/// Parse the options after `relay`: `--root <WINDOWS_ROOT>` and
/// `--no-desktop`, each at most once, in any order.
pub fn parse_relay_options(mut options: impl Iterator<Item = String>) -> VaultResult<RelayOptions> {
    let invalid =
        || VaultError::Protocol("usage: relay [--root <WINDOWS_ROOT>] [--no-desktop]".to_owned());
    let mut parsed = RelayOptions::default();
    while let Some(option) = options.next() {
        match option.as_str() {
            "--root" if parsed.root.is_none() => {
                let root = options.next().ok_or_else(invalid)?;
                validate_windows_root(&root)?;
                parsed.root = Some(root);
            }
            "--no-desktop" if !parsed.no_desktop => parsed.no_desktop = true,
            _ => return Err(invalid()),
        }
    }
    Ok(parsed)
}

/// Prefix of the keyring namespaces of WSL distros; the distro name follows.
const WSL_KEYRING_NAMESPACE_PREFIX: &[u8] = b"factorseal/wsl-secret-service/v1/";

/// The vault namespace holding the Secret Service items of one WSL distro,
/// `factorseal/wsl-secret-service/v1/<distro>`. A distro's name is declared
/// by the WSL side, so these namespaces keep distros' items apart; they do
/// not isolate one distro from another.
pub fn wsl_keyring_namespace(distro: &str) -> VaultResult<Vec<u8>> {
    validate_distro(distro)?;
    let mut namespace = WSL_KEYRING_NAMESPACE_PREFIX.to_vec();
    namespace.extend_from_slice(distro.as_bytes());
    Ok(namespace)
}

/// The distro whose keyring namespace this is, if it is one.
#[must_use]
pub fn wsl_keyring_distro(namespace: &[u8]) -> Option<&str> {
    let distro = std::str::from_utf8(namespace.strip_prefix(WSL_KEYRING_NAMESPACE_PREFIX)?).ok()?;
    validate_distro(distro).ok().map(|()| distro)
}

/// The Windows form of an absolute Linux folder inside `distro`, as Windows
/// programs reach it: a folder of a mounted drive (`/mnt/c/...`) is that
/// drive's folder (`C:\...`), and any other folder is under the distro's
/// network share (`\\wsl.localhost\<distro>\...`).
///
/// The vault requires an absolute folder, and Windows does not consider a
/// Linux path absolute, so a relayed request cannot keep the Linux form.
/// Refuses relative paths, `.` or `..` components, and backslashes or NULs,
/// which would make the Windows form ambiguous.
pub fn windows_folder(distro: &str, folder: &str) -> VaultResult<String> {
    validate_distro(distro)?;
    let invalid = || {
        VaultError::Protocol("a folder relayed from WSL must be an absolute Linux path".to_owned())
    };
    let rest = folder.strip_prefix('/').ok_or_else(invalid)?;
    if folder.contains(['\\', '\0']) {
        return Err(invalid());
    }
    let components: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    if components.iter().any(|part| matches!(*part, "." | "..")) {
        return Err(invalid());
    }
    if let ["mnt", drive, tail @ ..] = components.as_slice()
        && let [letter] = drive.as_bytes()
        && letter.is_ascii_alphabetic()
    {
        let mut path = format!("{}:\\", char::from(letter.to_ascii_uppercase()));
        path.push_str(&tail.join("\\"));
        return Ok(path);
    }
    let mut path = format!("\\\\wsl.localhost\\{distro}\\");
    path.push_str(&components.join("\\"));
    Ok(path)
}

/// A [`VaultClient`](super::wire::VaultClient) for Linux programs in WSL2
/// that reaches the Windows vault through `factorseal-wsl-broker.exe` in
/// relay mode. The broker starts on the first request and serves every later
/// one; if it exits, the next request starts a new one.
#[cfg(target_os = "linux")]
pub struct BrokerVaultClient {
    broker: std::path::PathBuf,
    pipe: String,
    distro: String,
    /// The vault's root on Windows, when it is not the default vault.
    windows_root: Option<String>,
    /// The broker never brings Desktop forward (`relay --no-desktop`).
    no_desktop: bool,
    relay: std::sync::Mutex<Option<Relay>>,
}

#[cfg(target_os = "linux")]
struct Relay {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::io::BufReader<std::process::ChildStdout>,
}

#[cfg(target_os = "linux")]
impl Relay {
    fn exchange(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        write_frame(&mut self.input, request)?;
        read_frame(&mut self.output)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the broker exited"))
    }
}

#[cfg(target_os = "linux")]
impl Drop for Relay {
    fn drop(&mut self) {
        // Stop the broker and reap it, so it does not linger as a zombie.
        // It is idle between frames, so nothing is cut short; its input
        // closes only afterwards, when the fields drop.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
impl BrokerVaultClient {
    /// `broker` is the Windows path of `factorseal-wsl-broker.exe` as seen
    /// from WSL (`/mnt/c/...`), `pipe` the vault's named pipe and `distro`
    /// the name this WSL distro declares.
    pub fn new(broker: std::path::PathBuf, pipe: String, distro: String) -> VaultResult<Self> {
        validate_distro(&distro)?;
        Ok(Self {
            broker,
            pipe,
            distro,
            windows_root: None,
            no_desktop: false,
            relay: std::sync::Mutex::new(None),
        })
    }

    /// Name the vault's root on Windows (`factorseal.exe --root`), for a
    /// vault other than the default one, so that the broker brings forward
    /// the Desktop of that vault when it is sealed.
    pub fn with_windows_root(mut self, windows_root: Option<String>) -> VaultResult<Self> {
        if let Some(root) = &windows_root {
            validate_windows_root(root)?;
        }
        self.windows_root = windows_root;
        Ok(self)
    }

    /// Never bring Desktop forward when the vault is sealed or not running:
    /// for a client that checks the vault by itself, not on someone's
    /// behalf.
    #[must_use]
    pub fn without_desktop(mut self) -> Self {
        self.no_desktop = true;
        self
    }

    fn start(&self) -> VaultResult<Relay> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(&self.broker)
            .args([self.pipe.as_str(), self.distro.as_str(), "relay"])
            .args(
                self.windows_root
                    .iter()
                    .flat_map(|root| ["--root", root.as_str()]),
            )
            .args(self.no_desktop.then_some("--no-desktop"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| {
                VaultError::Protocol(format!(
                    "could not start the WSL broker {}: {error}",
                    self.broker.display()
                ))
            })?;
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            return Err(VaultError::WorkerUnavailable);
        };
        Ok(Relay {
            child,
            input,
            output: std::io::BufReader::new(output),
        })
    }
}

#[cfg(target_os = "linux")]
impl super::wire::VaultClient for BrokerVaultClient {
    fn request(
        &self,
        request: &super::wire::VaultRequest,
    ) -> VaultResult<super::wire::VaultResponse> {
        let bytes = request.encode()?;
        let mut relay = self
            .relay
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        // A broker that exited since the last request gets one replacement.
        // Resending is safe: the vault refuses a request id it already saw.
        let mut last_error = None;
        for _ in 0..2 {
            let current = match relay.as_mut() {
                Some(current) => current,
                None => relay.insert(self.start()?),
            };
            match current.exchange(bytes.as_ref()) {
                Ok(reply) => {
                    let response = super::wire::VaultResponse::decode(&reply)?;
                    if response.request_id() != request.request_id() {
                        *relay = None;
                        return Err(VaultError::Protocol(
                            "the WSL broker answered another request".to_owned(),
                        ));
                    }
                    return Ok(response);
                }
                Err(error) => {
                    *relay = None;
                    last_error = Some(error);
                }
            }
        }
        Err(VaultError::Protocol(format!(
            "the WSL broker stopped: {}",
            last_error.map_or_else(String::new, |error| error.to_string())
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_distro_has_its_own_keyring_namespace() {
        let namespace = wsl_keyring_namespace("NixOS").unwrap();
        assert_eq!(namespace, b"factorseal/wsl-secret-service/v1/NixOS");
        assert_eq!(wsl_keyring_distro(&namespace), Some("NixOS"));
        assert!(wsl_keyring_namespace("../x").is_err());
        for other in [
            &b"factorseal/secret-service/v1"[..],
            b"factorseal/wsl-secret-service/v1/",
            b"factorseal/wsl-secret-service/v1/a/b",
            b"factorseal/wsl-secret-service/v1/..",
        ] {
            assert_eq!(wsl_keyring_distro(other), None, "{other:?}");
        }
    }

    #[test]
    fn folders_map_to_what_windows_programs_see() {
        for (folder, expected) in [
            (
                "/home/tarci/projects/carimbo",
                r"\\wsl.localhost\NixOS\home\tarci\projects\carimbo",
            ),
            ("/", r"\\wsl.localhost\NixOS\"),
            ("/mnt/c/Users/tarci/x", r"C:\Users\tarci\x"),
            ("/mnt/d", r"D:\"),
            ("/mnt/wsl/shared", r"\\wsl.localhost\NixOS\mnt\wsl\shared"),
            ("/home//tarci/", r"\\wsl.localhost\NixOS\home\tarci"),
        ] {
            assert_eq!(
                windows_folder("NixOS", folder).unwrap(),
                expected,
                "{folder}"
            );
        }
    }

    #[test]
    fn ambiguous_folders_are_refused() {
        for folder in [
            "relative/dir",
            "",
            "/home/../etc",
            "/home/./x",
            "/home/a\\b",
            "/home/a\0b",
        ] {
            assert!(windows_folder("NixOS", folder).is_err(), "{folder:?}");
        }
    }

    #[test]
    fn distro_names_must_be_plain() {
        for distro in ["NixOS", "Ubuntu-24.04", "my_distro"] {
            assert!(validate_distro(distro).is_ok(), "{distro}");
        }
        for distro in ["", ".", "..", "a\\b", "a/b", "a b", &"x".repeat(65)] {
            assert!(validate_distro(distro).is_err(), "{distro:?}");
        }
    }

    #[test]
    fn frames_round_trip_and_refuse_oversized_lengths() {
        let mut stream = Vec::new();
        write_frame(&mut stream, b"first").unwrap();
        write_frame(&mut stream, b"").unwrap();
        let mut reader = stream.as_slice();
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"first");
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), b"");
        assert!(read_frame(&mut reader).unwrap().is_none());

        let oversized = u32::try_from(MAX_RELAY_FRAME_BYTES + 1).unwrap();
        let mut reader: &[u8] = &oversized.to_le_bytes();
        assert!(read_frame(&mut reader).is_err());
        let mut truncated: &[u8] = &[5, 0];
        assert!(read_frame(&mut truncated).is_err());
    }

    /// An encoded `GetCache` request as the Linux provider sends it, with
    /// `fields` set in its application context. Built as JSON because a
    /// Linux folder is not a valid context on Windows.
    fn linux_request(fields: &[(&str, &str)]) -> Vec<u8> {
        use super::super::wire::{VaultApplicationContext, VaultRequest};
        let request = VaultRequest::new_with_application(
            VaultAction::GetCache {
                project: "carimbo".to_owned(),
                address: crate::SecretSpecAddress::convention("carimbo", "default", "KEY").unwrap(),
            },
            VaultApplicationContext::new(Some("carimbo".to_owned()), None, None, None).unwrap(),
        )
        .unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(request.encode().unwrap().as_ref()).unwrap();
        for (name, value) in fields {
            json["application"][*name] = serde_json::Value::from(*value);
        }
        serde_json::to_vec(&json).unwrap()
    }

    #[test]
    fn relayed_requests_keep_their_id_and_refuse_bad_context() {
        use super::super::wire::VaultRequest;
        let bytes = linux_request(&[("base_dir", "relative")]);
        assert!(VaultRequest::encoded_request_id(&bytes).is_some());
        assert!(VaultRequest::decode_relayed_from_wsl(&bytes, "NixOS").is_err());
        let bytes = linux_request(&[("base_dir", "/home/tarci")]);
        assert!(VaultRequest::decode_relayed_from_wsl(&bytes, "bad/name").is_err());
        assert!(VaultRequest::encoded_request_id(b"not json").is_none());
    }

    /// The broker's own view: the folder becomes the Windows form and the
    /// distro is the broker's, whatever the client declared.
    #[cfg(windows)]
    #[test]
    fn relayed_requests_carry_the_windows_folder_and_the_brokers_distro() {
        use super::super::wire::VaultRequest;
        let bytes = linux_request(&[
            ("base_dir", "/home/tarci/projects/carimbo"),
            ("declared_wsl_origin", "SomethingElse"),
        ]);
        let request = VaultRequest::decode_relayed_from_wsl(&bytes, "NixOS").unwrap();
        let application = request.application().unwrap();
        assert_eq!(
            application.base_dir.as_deref(),
            Some(r"\\wsl.localhost\NixOS\home\tarci\projects\carimbo")
        );
        assert_eq!(application.declared_wsl_origin.as_deref(), Some("NixOS"));
        assert_eq!(
            Some(request.request_id()),
            VaultRequest::encoded_request_id(&bytes)
        );
    }

    /// A stand-in for the Windows broker: answers one frame with `template`
    /// carrying the request's id, then exits, so the client must start a
    /// new broker for its next request.
    #[cfg(target_os = "linux")]
    fn fake_broker(directory: &std::path::Path, template: &[u8]) -> std::path::PathBuf {
        fake_broker_expecting(directory, template, &["pipe", "NixOS", "relay"])
    }

    #[cfg(target_os = "linux")]
    fn fake_broker_expecting(
        directory: &std::path::Path,
        template: &[u8],
        arguments: &[&str],
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let template_path = directory.join("template.json");
        std::fs::write(&template_path, template).unwrap();
        let arguments_path = directory.join("arguments.json");
        std::fs::write(&arguments_path, serde_json::to_vec(arguments).unwrap()).unwrap();
        let script = directory.join("broker");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env python3\nimport json, struct, sys\n\
                 assert sys.argv[1:] == json.load(open('{}')), sys.argv\n\
                 head = sys.stdin.buffer.read(4)\n\
                 request = json.loads(sys.stdin.buffer.read(struct.unpack('<I', head)[0]))\n\
                 response = json.load(open('{}'))\n\
                 response['request_id'] = request['request_id']\n\
                 body = json.dumps(response).encode()\n\
                 sys.stdout.buffer.write(struct.pack('<I', len(body)) + body)\n\
                 sys.stdout.buffer.flush()\n",
                arguments_path.display(),
                template_path.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    /// A stand-in broker that counts its runs in `runs`. On its first run it
    /// misbehaves: `exit` reads the frame and exits without answering;
    /// `other-id` answers with the all-zero id. Later runs answer properly.
    #[cfg(target_os = "linux")]
    fn misbehaving_broker(directory: &std::path::Path, mode: &str) -> std::path::PathBuf {
        use super::super::wire::{VaultResponse, VaultResponseBody};
        use std::os::unix::fs::PermissionsExt as _;
        let template =
            VaultResponse::success(RequestId::from_bytes([0; 16]), VaultResponseBody::Stored)
                .encode()
                .unwrap();
        std::fs::write(directory.join("template.json"), template.as_ref()).unwrap();
        let script = directory.join("broker");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env python3\nimport json, os, struct, sys\n\
                 runs = os.path.join('{dir}', 'runs')\n\
                 count = int(open(runs).read()) + 1 if os.path.exists(runs) else 1\n\
                 open(runs, 'w').write(str(count))\n\
                 head = sys.stdin.buffer.read(4)\n\
                 request = json.loads(sys.stdin.buffer.read(struct.unpack('<I', head)[0]))\n\
                 if count == 1 and '{mode}' == 'exit':\n    sys.exit(0)\n\
                 response = json.load(open(os.path.join('{dir}', 'template.json')))\n\
                 if count > 1 or '{mode}' != 'other-id':\n    response['request_id'] = request['request_id']\n\
                 body = json.dumps(response).encode()\n\
                 sys.stdout.buffer.write(struct.pack('<I', len(body)) + body)\n\
                 sys.stdout.buffer.flush()\n",
                dir = directory.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_broker_client_resends_once_and_refuses_another_requests_answer() {
        use super::super::wire::{VaultClient as _, VaultResponseBody};
        let runs =
            |directory: &std::path::Path| std::fs::read_to_string(directory.join("runs")).unwrap();
        // A broker that dies after reading the frame: the replacement gets
        // the same request.
        let directory = tempfile::tempdir().unwrap();
        let broker = misbehaving_broker(directory.path(), "exit");
        let client = BrokerVaultClient::new(broker, "pipe".to_owned(), "NixOS".to_owned()).unwrap();
        let request = VaultRequest::new(VaultAction::Status).unwrap();
        let response = client.request(&request).unwrap();
        assert_eq!(response.request_id(), request.request_id());
        assert!(matches!(response.result, Ok(VaultResponseBody::Stored)));
        assert_eq!(runs(directory.path()), "2");

        // An answer to another request is an error, and the broker that
        // gave it is not used again.
        let directory = tempfile::tempdir().unwrap();
        let broker = misbehaving_broker(directory.path(), "other-id");
        let client = BrokerVaultClient::new(broker, "pipe".to_owned(), "NixOS".to_owned()).unwrap();
        let error = client
            .request(&VaultRequest::new(VaultAction::Status).unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("another request"), "{error}");
        assert_eq!(runs(directory.path()), "1");
        assert!(client.relay.lock().unwrap().is_none());
        let request = VaultRequest::new(VaultAction::Status).unwrap();
        assert_eq!(
            client.request(&request).unwrap().request_id(),
            request.request_id()
        );
        assert_eq!(runs(directory.path()), "2");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_broker_client_round_trips_and_replaces_an_exited_broker() {
        use super::super::wire::{
            RequestId, VaultClient as _, VaultRequest, VaultResponse, VaultResponseBody,
        };
        let directory = tempfile::tempdir().unwrap();
        let template =
            VaultResponse::success(RequestId::from_bytes([0; 16]), VaultResponseBody::Stored)
                .encode()
                .unwrap();
        let broker = fake_broker(directory.path(), template.as_ref());
        let client = BrokerVaultClient::new(broker, "pipe".to_owned(), "NixOS".to_owned()).unwrap();
        for _ in 0..2 {
            let request = VaultRequest::new(VaultAction::Status).unwrap();
            let response = client.request(&request).unwrap();
            assert_eq!(response.request_id(), request.request_id());
            assert!(matches!(response.result, Ok(VaultResponseBody::Stored)));
        }
        assert!(
            BrokerVaultClient::new("x".into(), "pipe".to_owned(), "bad/name".to_owned()).is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_broker_is_told_which_vault_root_it_serves() {
        use super::super::wire::{
            RequestId, VaultClient as _, VaultRequest, VaultResponse, VaultResponseBody,
        };
        let directory = tempfile::tempdir().unwrap();
        let template =
            VaultResponse::success(RequestId::from_bytes([0; 16]), VaultResponseBody::Stored)
                .encode()
                .unwrap();
        let root = r"C:\Users\me\AppData\Local\FactorSeal-check\vault";
        let broker = fake_broker_expecting(
            directory.path(),
            template.as_ref(),
            &["pipe", "NixOS", "relay", "--root", root],
        );
        let client = BrokerVaultClient::new(broker, "pipe".to_owned(), "NixOS".to_owned())
            .unwrap()
            .with_windows_root(Some(root.to_owned()))
            .unwrap();
        let response = client
            .request(&VaultRequest::new(VaultAction::Status).unwrap())
            .unwrap();
        assert!(matches!(response.result, Ok(VaultResponseBody::Stored)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_client_without_desktop_starts_its_broker_with_no_desktop() {
        use super::super::wire::{
            RequestId, VaultClient as _, VaultRequest, VaultResponse, VaultResponseBody,
        };
        let directory = tempfile::tempdir().unwrap();
        let template =
            VaultResponse::success(RequestId::from_bytes([0; 16]), VaultResponseBody::Stored)
                .encode()
                .unwrap();
        let root = r"C:\vault";
        let broker = fake_broker_expecting(
            directory.path(),
            template.as_ref(),
            &["pipe", "NixOS", "relay", "--root", root, "--no-desktop"],
        );
        let client = BrokerVaultClient::new(broker, "pipe".to_owned(), "NixOS".to_owned())
            .unwrap()
            .with_windows_root(Some(root.to_owned()))
            .unwrap()
            .without_desktop();
        let response = client
            .request(&VaultRequest::new(VaultAction::Status).unwrap())
            .unwrap();
        assert!(matches!(response.result, Ok(VaultResponseBody::Stored)));
    }

    #[test]
    fn the_relay_takes_a_vault_root_and_no_desktop() {
        let parse = |options: &[&str]| {
            parse_relay_options(options.iter().map(|option| (*option).to_owned()))
        };
        assert_eq!(parse(&[]).unwrap(), RelayOptions::default());
        assert_eq!(
            parse(&["--root", r"C:\vault"]).unwrap(),
            RelayOptions {
                root: Some(r"C:\vault".to_owned()),
                no_desktop: false,
            }
        );
        for options in [
            &["--root", r"C:\vault", "--no-desktop"][..],
            &["--no-desktop", "--root", r"C:\vault"],
        ] {
            assert_eq!(
                parse(options).unwrap(),
                RelayOptions {
                    root: Some(r"C:\vault".to_owned()),
                    no_desktop: true,
                }
            );
        }
        assert!(parse(&["--no-desktop"]).unwrap().no_desktop);
        for invalid in [
            &["--root"][..],
            &["--root", ""],
            &["--root", "a\0b"],
            &["--root", "a", "b"],
            &["--root", "a", "--root", "b"],
            &["--no-desktop", "--no-desktop"],
            &["--other", "a"],
        ] {
            assert!(parse(invalid).is_err(), "{invalid:?}");
        }
    }

    /// A vault for [`serve`]: records what reaches it and answers each
    /// request with the next of `answers` (a sealed vault by default).
    struct RecordingVault {
        seen: std::sync::Mutex<Vec<(String, Option<String>)>>,
        answers: std::sync::Mutex<Vec<VaultResult<VaultResponseErrorCode>>>,
    }

    impl VaultClient for RecordingVault {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            self.seen.lock().unwrap().push((
                format!("{:?}", std::mem::discriminant(&request.action)),
                request
                    .application()
                    .and_then(|application| application.declared_wsl_origin.clone()),
            ));
            let answer = self
                .answers
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Ok(VaultResponseErrorCode::Sealed));
            Ok(refusal(request.request_id(), answer?, "test".to_owned()))
        }
    }

    /// Relay `requests` through [`serve`], returning the responses and how
    /// often `on_sealed` ran.
    fn served(vault: &RecordingVault, requests: &[Vec<u8>]) -> (Vec<VaultResponse>, usize) {
        served_with(vault, &RelayOptions::default(), requests)
    }

    fn served_with(
        vault: &RecordingVault,
        options: &RelayOptions,
        requests: &[Vec<u8>],
    ) -> (Vec<VaultResponse>, usize) {
        let mut input = Vec::new();
        for request in requests {
            write_frame(&mut input, request).unwrap();
        }
        let mut output = Vec::new();
        let mut opened = 0;
        serve(
            vault,
            "NixOS",
            options,
            &mut input.as_slice(),
            &mut output,
            || {
                opened += 1;
            },
        )
        .unwrap();
        let mut reader = output.as_slice();
        let mut responses = Vec::new();
        while let Some(frame) = read_frame(&mut reader).unwrap() {
            responses.push(VaultResponse::decode(&frame).unwrap());
        }
        (responses, opened)
    }

    fn encoded(action: VaultAction) -> (RequestId, Vec<u8>) {
        use super::super::wire::VaultApplicationContext;
        // No folder: a Linux path's Windows form is not absolute on Linux.
        let request = VaultRequest::new_with_application(
            action,
            VaultApplicationContext::new(Some("carimbo".to_owned()), None, None, None).unwrap(),
        )
        .unwrap();
        (
            request.request_id(),
            request.encode().unwrap().as_ref().to_vec(),
        )
    }

    fn get_cache() -> VaultAction {
        VaultAction::GetCache {
            project: "carimbo".to_owned(),
            address: crate::vault::SecretSpecAddress::convention("carimbo", "default", "KEY")
                .unwrap(),
        }
    }

    fn code(response: &VaultResponse) -> Option<VaultResponseErrorCode> {
        response.result.as_ref().err().map(|error| error.code)
    }

    #[test]
    fn the_relay_refuses_other_actions_before_they_reach_the_vault() {
        let vault = RecordingVault {
            seen: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(vec![Ok(VaultResponseErrorCode::Conflict)]),
        };
        let (list_id, list) = encoded(VaultAction::ListPermissions);
        let (get_id, get) = encoded(get_cache());
        let (responses, opened) = served(&vault, &[list, b"not json".to_vec(), get]);
        assert_eq!(opened, 0);
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].request_id(), list_id);
        assert_eq!(
            code(&responses[0]),
            Some(VaultResponseErrorCode::AuthorizationRequired)
        );
        assert_eq!(responses[1].request_id(), RequestId::from_bytes([0; 16]));
        assert_eq!(
            code(&responses[1]),
            Some(VaultResponseErrorCode::InvalidRequest)
        );
        // Only the cache read reaches the vault, tagged with the broker's distro.
        assert_eq!(responses[2].request_id(), get_id);
        assert_eq!(code(&responses[2]), Some(VaultResponseErrorCode::Conflict));
        let seen = vault.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].0,
            format!("{:?}", std::mem::discriminant(&get_cache()))
        );
        assert_eq!(seen[0].1.as_deref(), Some("NixOS"));
    }

    #[test]
    fn the_relay_brings_desktop_forward_once_when_the_vault_is_sealed() {
        // Answers pop from the end: sealed, unreachable, a client error, sealed.
        let vault = RecordingVault {
            seen: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(vec![
                Ok(VaultResponseErrorCode::Sealed),
                Err(VaultError::Crypto),
                Err(VaultError::AgentUnreachable("pipe".to_owned())),
                Ok(VaultResponseErrorCode::Sealed),
            ]),
        };
        let requests: Vec<_> = (0..4).map(|_| encoded(VaultAction::Status)).collect();
        let frames: Vec<_> = requests.iter().map(|(_, frame)| frame.clone()).collect();
        let (responses, opened) = served(&vault, &frames);
        assert_eq!(opened, 1);
        for ((id, _), response) in requests.iter().zip(&responses) {
            assert_eq!(response.request_id(), *id);
        }
        assert_eq!(
            responses.iter().map(code).collect::<Vec<_>>(),
            [
                Some(VaultResponseErrorCode::Sealed),
                Some(VaultResponseErrorCode::Sealed),
                Some(VaultResponseErrorCode::Internal),
                Some(VaultResponseErrorCode::Sealed),
            ]
        );
        assert!(
            serve(
                &vault,
                "bad/name",
                &RelayOptions::default(),
                &mut [].as_slice(),
                &mut Vec::new(),
                || {}
            )
            .is_err()
        );
    }

    #[test]
    fn a_relay_without_desktop_never_brings_it_forward() {
        let vault = RecordingVault {
            seen: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(vec![
                Ok(VaultResponseErrorCode::Sealed),
                Err(VaultError::AgentUnreachable("pipe".to_owned())),
                Ok(VaultResponseErrorCode::Sealed),
            ]),
        };
        let frames: Vec<_> = (0..3).map(|_| encoded(VaultAction::Status).1).collect();
        let options = RelayOptions {
            root: None,
            no_desktop: true,
        };
        let (responses, opened) = served_with(&vault, &options, &frames);
        assert_eq!(opened, 0);
        assert!(
            responses
                .iter()
                .all(|response| code(response) == Some(VaultResponseErrorCode::Sealed))
        );
    }

    #[test]
    fn only_the_providers_actions_are_relayed() {
        assert!(relay_allows(&VaultAction::Status, "NixOS"));
        assert!(relay_allows(
            &VaultAction::WaitPermission {
                id: "prm_x".to_owned(),
                timeout_ms: 1,
            },
            "NixOS"
        ));
        assert!(!relay_allows(&VaultAction::ListPermissions, "NixOS"));
        assert!(!relay_allows(
            &VaultAction::ListProjects {
                cursor: None,
                limit: 1,
            },
            "NixOS"
        ));
    }

    fn keyring_get(distro: &str, item: &str) -> VaultAction {
        VaultAction::Get {
            namespace: wsl_keyring_namespace(distro).unwrap(),
            address: super::super::wire::WireSecretAddress::new(item, None),
        }
    }

    fn keyring_access(action: Option<VaultAction>) -> VaultAction {
        VaultAction::WslKeyringAccess {
            caller: super::super::wire::DeclaredKeyringCaller {
                uid: 1000,
                executable: "/usr/bin/secret-tool".to_owned(),
                executable_digest: [3; 32],
            },
            entry: None,
            service: "demo".to_owned(),
            operation: super::super::wire::PermissionOperation::Get,
            action: action.map(Box::new),
            pending: None,
        }
    }

    #[test]
    fn the_relay_forwards_only_this_distros_keyring_and_never_seals() {
        const ITEM: &str = "item/0123456789abcdef0123456789abcdef";
        let mutate = |distro| VaultAction::Mutate {
            namespace: wsl_keyring_namespace(distro).unwrap(),
            mutations: vec![super::super::wire::VaultMutation::Delete {
                address: super::super::wire::WireSecretAddress::new(ITEM, None),
            }],
        };
        let forwarded = [
            keyring_access(None),
            keyring_access(Some(keyring_get("NixOS", ITEM))),
            keyring_access(Some(mutate("NixOS"))),
            // The host reads the index (labels and attributes) on its own.
            keyring_get("NixOS", SECRET_SERVICE_INDEX_ITEM),
        ];
        let refused = [
            keyring_access(Some(keyring_get("Debian", ITEM))),
            keyring_access(Some(mutate("Debian"))),
            // Item values only through an access check for a caller.
            keyring_get("NixOS", ITEM),
            keyring_get("Debian", SECRET_SERVICE_INDEX_ITEM),
            mutate("NixOS"),
            VaultAction::Seal {
                namespace: wsl_keyring_namespace("NixOS").unwrap(),
            },
            VaultAction::KeyringAccess {
                entry: None,
                sender: ":1.5".to_owned(),
                service: "demo".to_owned(),
                operation: super::super::wire::PermissionOperation::Get,
                action: None,
                pending: None,
            },
            VaultAction::SetWslKeyrings {
                distros: vec!["NixOS".to_owned()],
            },
        ];
        let forwarded_count = forwarded.len();
        let vault = RecordingVault {
            seen: std::sync::Mutex::new(Vec::new()),
            answers: std::sync::Mutex::new(
                (0..forwarded_count)
                    .map(|_| Ok(VaultResponseErrorCode::Conflict))
                    .collect(),
            ),
        };
        let frames: Vec<_> = forwarded
            .into_iter()
            .chain(refused)
            .map(|action| encoded(action).1)
            .collect();
        let (responses, _) = served(&vault, &frames);
        for (index, response) in responses.iter().enumerate() {
            let expected = if index < forwarded_count {
                VaultResponseErrorCode::Conflict
            } else {
                VaultResponseErrorCode::AuthorizationRequired
            };
            assert_eq!(code(response), Some(expected), "request {index}");
        }
        assert_eq!(vault.seen.lock().unwrap().len(), forwarded_count);
        // Decoding already refuses other inner actions; the allowlist does
        // not rely on it.
        let seal = VaultAction::Seal {
            namespace: wsl_keyring_namespace("NixOS").unwrap(),
        };
        assert!(!relay_allows(&keyring_access(Some(seal)), "NixOS"));
    }

    #[cfg(feature = "vault-store")]
    #[test]
    fn the_relay_names_the_adapters_index_item() {
        assert_eq!(
            SECRET_SERVICE_INDEX_ITEM,
            crate::vault::secret_service_data::INDEX_ITEM
        );
    }
}
