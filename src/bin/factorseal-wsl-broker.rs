//! Windows broker for WSL2-relayed vault requests, executed via WSL2
//! interop. Connects to the existing named-pipe transport exactly like any
//! other Windows client -- transport authentication is completely
//! unchanged, and the normal interactive-approval and grant-lookup flow
//! (`AuthorizationRequired` -> approve in Desktop -> retry) works exactly as
//! it does for any native caller. The broker tags each request with the
//! distro name that invoked it (`VaultApplicationContext::declared_wsl_origin`):
//! an unauthenticated, display-only hint that limits whatever grant approval
//! creates to the current unseal, since every WSL caller is this broker and
//! has no equivalent of the executable-identity hint a native caller gets.
//!
//! Usage:
//!   factorseal-wsl-broker.exe <pipe-name> <distro> status
//!   factorseal-wsl-broker.exe <pipe-name> <distro> get <project> <profile> <key>
//!   factorseal-wsl-broker.exe <pipe-name> <distro> relay
//!
//! `relay` serves a Linux client (the SecretSpec provider in WSL) over
//! standard input and output until the input ends; see
//! `factorseal::vault::wsl_relay` for the framing, the folder translation
//! and the requests it forwards.

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_impl::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("factorseal-wsl-broker only runs on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_impl {
    use std::sync::atomic::{AtomicBool, Ordering};

    use factorseal::vault::{
        MAX_PERMISSION_WAIT_MS, PermissionWaitStatus, RequestId, SecretSpecAddress, VaultAction,
        VaultApplicationContext, VaultClient, VaultError, VaultRequest, VaultResponse,
        VaultResponseBody, VaultResponseError, VaultResponseErrorCode, WindowsVaultClient,
        wsl_relay,
    };

    const USAGE: &str = "usage: factorseal-wsl-broker <pipe-name> <distro> status | get <project> <profile> <key> | relay";

    /// `VaultAction` deliberately doesn't derive `Clone` (some variants carry
    /// secret material), so the request this broker sends twice -- once
    /// before approval, once after -- is rebuilt from this small, plainly
    /// clonable description instead of cloning a constructed `VaultAction`.
    ///
    /// `get` targets the SecretSpec provider cache (`GetCache`), not the raw
    /// `Get` primitive: only cache actions with a declared project make
    /// `ApprovalCandidate::for_request` create a pending approval at all, so
    /// this is the only shape of request this broker can actually get a
    /// human to approve.
    #[derive(Clone)]
    enum RequestedAction {
        Status,
        GetCache {
            project: String,
            profile: String,
            key: String,
        },
    }

    impl RequestedAction {
        fn parse(
            name: &str,
            args: &mut impl Iterator<Item = String>,
        ) -> Result<Self, &'static str> {
            match name {
                "status" => Ok(Self::Status),
                "get" => Ok(Self::GetCache {
                    project: args.next().ok_or(USAGE)?,
                    profile: args.next().ok_or(USAGE)?,
                    key: args.next().ok_or(USAGE)?,
                }),
                _ => Err(USAGE),
            }
        }

        fn project(&self) -> Option<&str> {
            match self {
                Self::Status => None,
                Self::GetCache { project, .. } => Some(project),
            }
        }

        fn into_vault_action(self) -> Result<VaultAction, String> {
            match self {
                Self::Status => Ok(VaultAction::Status),
                Self::GetCache {
                    project,
                    profile,
                    key,
                } => Ok(VaultAction::GetCache {
                    project: project.clone(),
                    address: SecretSpecAddress::convention(project, profile, key)
                        .map_err(|error| error.to_string())?,
                }),
            }
        }
    }

    pub(super) fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let pipe_name = args.next().ok_or(USAGE)?;
        let distro = args.next().ok_or(USAGE)?;
        let action_name = args.next().ok_or(USAGE)?;
        if action_name == "relay" {
            if args.next().is_some() {
                return Err(USAGE.to_owned());
            }
            return relay(&WindowsVaultClient::new(pipe_name), &distro);
        }
        let requested = RequestedAction::parse(&action_name, &mut args)?;

        let application = VaultApplicationContext::new(
            requested.project().map(str::to_owned),
            None,
            None,
            Some(format!("Relayed from WSL distro {distro}")),
        )
        .and_then(|context| context.with_declared_wsl_origin(Some(distro)))
        .map_err(|error| error.to_string())?;

        let client = WindowsVaultClient::new(pipe_name);
        match send(
            &client,
            requested.clone().into_vault_action()?,
            application.clone(),
        )? {
            Ok(body) => print_result(&body),
            Err(error) => {
                let Some(interaction) = error.interaction else {
                    return Err(describe(&error));
                };
                println!(
                    "approval required (id {}); approve in Factorseal Desktop, then this will retry once...",
                    interaction.id
                );
                // One bounded wait, not a polling loop: a client that keeps
                // reacquiring the service's single state lock can starve a
                // concurrent caller (e.g. `factorseal permissions list`)
                // under Windows' unfair SRWLOCK. Exit and let the caller
                // re-run instead of monopolizing the lock indefinitely.
                let wait_request = VaultRequest::new(VaultAction::WaitPermission {
                    id: interaction.id,
                    timeout_ms: MAX_PERMISSION_WAIT_MS,
                })
                .map_err(|error| error.to_string())?;
                let wait_response = client
                    .request(&wait_request)
                    .map_err(|error| error.to_string())?;
                let status = match wait_response.result {
                    Ok(VaultResponseBody::PermissionWait { status }) => status,
                    Ok(_) => return Err("unexpected response waiting for approval".to_owned()),
                    Err(error) => return Err(describe(&error)),
                };
                match status {
                    PermissionWaitStatus::Granted => {
                        match send(&client, requested.into_vault_action()?, application)? {
                            Ok(body) => print_result(&body),
                            Err(error) => return Err(describe(&error)),
                        }
                    }
                    PermissionWaitStatus::Pending => {
                        println!("still pending; approve it, then run this command again");
                    }
                    other => return Err(format!("approval not granted: {other:?}")),
                }
            }
        }
        Ok(())
    }

    /// Serve one Linux client: each frame on standard input is a request,
    /// answered by one frame on standard output, until the input ends.
    fn relay(client: &WindowsVaultClient, distro: &str) -> Result<(), String> {
        wsl_relay::validate_distro(distro).map_err(|error| error.to_string())?;
        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout().lock();
        let opened_desktop = AtomicBool::new(false);
        while let Some(frame) = wsl_relay::read_frame(&mut input)
            .map_err(|error| format!("reading a request: {error}"))?
        {
            let response = relay_one(client, distro, &frame, &opened_desktop);
            let bytes = response.encode().map_err(|error| error.to_string())?;
            wsl_relay::write_frame(&mut output, bytes.as_ref())
                .map_err(|error| format!("writing a response: {error}"))?;
        }
        Ok(())
    }

    fn relay_one(
        client: &WindowsVaultClient,
        distro: &str,
        frame: &[u8],
        opened_desktop: &AtomicBool,
    ) -> VaultResponse {
        let id = VaultRequest::encoded_request_id(frame)
            .unwrap_or_else(|| RequestId::from_bytes([0; 16]));
        let request = match VaultRequest::decode_relayed_from_wsl(frame, distro) {
            Ok(request) => request,
            Err(error) => {
                return refusal(
                    id,
                    VaultResponseErrorCode::InvalidRequest,
                    error.to_string(),
                );
            }
        };
        if !wsl_relay::relay_allows(&request.action) {
            return refusal(
                id,
                VaultResponseErrorCode::AuthorizationRequired,
                "the WSL broker does not relay this request".to_owned(),
            );
        }
        let response = client.request(&request);
        let sealed = match &response {
            Ok(response) => matches!(
                &response.result,
                Err(VaultResponseError {
                    code: VaultResponseErrorCode::Sealed,
                    ..
                })
            ),
            Err(VaultError::Sealed | VaultError::AgentUnreachable(_)) => true,
            Err(_) => false,
        };
        if sealed && !opened_desktop.swap(true, Ordering::Relaxed) {
            open_desktop();
        }
        match response {
            Ok(response) => response,
            Err(VaultError::Sealed | VaultError::AgentUnreachable(_)) => refusal(
                id,
                VaultResponseErrorCode::Sealed,
                "unlock FactorSeal Desktop on Windows, then try again".to_owned(),
            ),
            Err(error) => refusal(id, VaultResponseErrorCode::Internal, error.to_string()),
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

    /// Bring FactorSeal Desktop forward so the person can unlock: starting
    /// the Desktop installed beside the broker shows the running instance's
    /// window, or starts it. Best effort; the request is refused either way.
    fn open_desktop() {
        use std::os::windows::process::CommandExt as _;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        let Some(desktop) = std::env::current_exe()
            .ok()
            .map(|broker| broker.with_file_name("factorseal-desktop.exe"))
            .filter(|desktop| desktop.is_file())
        else {
            return;
        };
        // No inherited handles: standard output is the relay's channel.
        let _ = std::process::Command::new(desktop)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn();
    }

    fn send(
        client: &WindowsVaultClient,
        action: VaultAction,
        application: VaultApplicationContext,
    ) -> Result<Result<VaultResponseBody, VaultResponseError>, String> {
        let request = VaultRequest::new_with_application(action, application)
            .map_err(|error| error.to_string())?;
        let response = client
            .request(&request)
            .map_err(|error| error.to_string())?;
        Ok(response.result)
    }

    fn print_result(body: &VaultResponseBody) {
        println!("{body:?}");
    }

    fn describe(error: &VaultResponseError) -> String {
        format!("{:?}: {}", error.code, error.message)
    }
}
