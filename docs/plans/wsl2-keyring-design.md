# Design: the WSL keyring (milestone 2)

Status, 2026-11-15: design note for milestone 2 of
[the WSL2 vault plan](wsl2-vault-from-windows.md), written before any code.
The decisions and trust model in the plan still apply; this note says how
each step is built and what it rests on. The decisions marked **Open** below
were put to the user before coding.

## Decisions (taken with the user, 2026-11-15)

1. **A Settings switch takes effect at once**: Desktop sends a manager-only
   `SetWslKeyrings` when it moves; off revokes the broker's grant on that
   distro immediately.
2. **`Lock` from WSL is refused**: the broker gets no `Seal` on a keyring
   namespace and the allowlist has no `Seal`; the WSL host answers `Lock`
   with nothing locked. The Windows vault is sealed from Desktop.
3. **Items already in a distro's gnome-keyring are left alone**: no import in
   milestone 2; the docs say so and how to switch back.

## Facts re-checked on 7cddb54

The plan's "Facts this rests on" list was checked again against the code on
`feature/wsl2-keyring` (7cddb54, on `stack/7-browser-windows` 8c95bdc, on
upstream main 214f27e; the stack has not moved). Every line number still
holds. Four facts were wrong or incomplete:

1. **The NetworkManager agent does not idle in this distro.** `run_frontend`
   always spawns `network_manager::run` (`src/vault/secret_service.rs:663`),
   which loops on `Connection::system()` every 2 s
   (`secret_service/network_manager.rs:555`). NixOS-WSL runs systemd and has a
   system bus (`/run/dbus/system_bus_socket` exists here; NetworkManager does
   not), so the agent connects and retries forever. The WSL host must not
   start it.
2. **The keyring needs no `List` permission.** The adapter's permissions are
   `Get`, `Put`, `Delete`, `Seal` (`SECRET_SERVICE_PERMISSIONS`,
   `secret_service.rs:67`); the item index is itself an item read with `Get`.
   Its actions are `Get`, `Mutate` and `Seal` (`secret_service/agent.rs`).
   The broker allowlist needs at most those three plus the access check (and,
   with decision 2, not `Seal`), not the plan's
   "Get/Put/Delete/List/Seal/Mutate".
3. **The adapter's namespace is a constant in the store.** `Store::get`,
   `mutate` and `seal` use `agent::NAMESPACE`, and the vault checks the host
   grant on the literal `factorseal/secret-service/v1` in two places
   (`AuthorizeSecretInput` and `KeyringAccess`, `service.rs:405`, `:435`). A
   per-distro namespace needs the store to carry its namespace.
4. **The NixOS module asserts TPM and polkit in every mode**
   (`nix/modules/factorseal.nix:106–116`). In WSL the vault lives on Windows,
   so `mode = "wsl"` must drop those two assertions (and the `tss` group), and
   keep only the gnome-keyring one.

Also checked, true as written: the vault resolves the D-Bus sender itself
(`keyring_peer`, `service.rs:846`, Linux only, `AuthorizationRequired`
elsewhere); exclusive grants are `cfg(linux, secret-service-host)`
(`authorization.rs:223`, `grant.rs:284`); the worker grants Desktop and the
CLI at every unlock (`authorize_hosts`, `desktop_worker.rs:219`);
`SecretServiceHost::start`/`install` take any `VaultClient`
(`secret_service.rs:125`, `:155`); `SECURITY.md:173–177` still says the
collection gives no per-application grants. Protocol: `PROTOCOL_VERSION = 19`
(`wire.rs:20`).

New facts this design uses:

- `VaultAction::Status` does not extend the idle lease (`actions.rs:60`
  returns `touch = false`) and answers with `idle_deadline` and
  `absolute_deadline`.
- Interop works from a systemd user service without `WSL_INTEROP`
  (`systemd-run --user --wait --pipe cmd.exe /c echo` printed its output), so
  a D-Bus-activated user service can start the broker.
- The vault's Linux peer resolution, `dbus_caller_identity`
  (`src/vault/linux.rs:601`), is ordinary Linux code: run inside WSL by the
  host, it gives the caller's uid, executable path and SHA-256, after the
  ptrace/loader-injection refusal (`reject_untrusted_peer_image`), plus the
  folder (`secretspec.toml` ancestor or working directory).
- The popup names the program from `principal.application_id` as a path
  (`factorseal-desktop/src/app/access.rs:1518`) and already shows "WSL
  distro" and "Access expires: When the vault seals" for any request with
  `declared_wsl_origin`.

## Overview

```
WSL distro "NixOS"                                     Windows
──────────────────                                     ───────
secret-tool ──D-Bus──▶ factorseal wsl-keyring
                         resolves the peer in WSL
                         (uid, exe, sha256, folder)
                         SecretServiceHost + Store{ns: wsl/NixOS}
                         BrokerVaultClient ──stdin/stdout──▶ factorseal-wsl-broker.exe <pipe> NixOS relay
                                                              tags distro, checks namespace
                                                              ──named pipe──▶ vault (Desktop's worker)
                                                                               host grant: broker on wsl/NixOS
                                                                               per-app grant: wsl:NixOS principal
                                                                               popup in Desktop
```

## Step 2: the vault (protocol v20)

### Namespace

`factorseal/wsl-secret-service/v1/<distro>`, scope
`DocumentKind::LinuxSecretService`, `<distro>` checked by
`wsl_relay::validate_distro`. A helper `wsl_keyring_namespace(distro)` in
`protocol/wsl.rs` builds it; nothing else spells it. Items, the index and the
grants live in it exactly as the Linux adapter's do in
`factorseal/secret-service/v1`.

### `WslKeyringAccess`, a new action

A new variant rather than a field on `KeyringAccess`, so the Linux path keeps
its strict `sender` validation and cannot be reached with a declared caller:

```rust
WslKeyringAccess {
    caller: DeclaredKeyringCaller,  // uid: u32, executable: String (absolute Linux path),
                                    // executable_digest: [u8; 32]
    entry: Option<SecretAddress>,   // same rule as KeyringAccess: item/<32 hex>
    service: String,
    operation: PermissionOperation,
    action: Option<Box<VaultAction>>,
    pending: Option<String>,
}
```

The distro and folder are not in the action: they come from the request's
`VaultApplicationContext`, which the broker rewrites
(`decode_relayed_from_wsl` sets `declared_wsl_origin` to its own distro
argument, whatever the client said, and turns the folder into
`\\wsl.localhost\<distro>\…`). The WSL host puts the peer's folder in
`application.base_dir`.

The vault handles it like `KeyringAccess`, with three differences:

1. **Host check**: the caller must hold `Get` on
   `wsl_keyring_namespace(declared_wsl_origin)`. A request without
   `declared_wsl_origin` is refused. Only the broker, granted by the worker
   (step 3), holds that.
2. **Principal**: instead of `keyring_peer`, a synthetic identity
   `CallerIdentity::new(Linux, "wsl:<distro>:uid:<uid>", <executable>,
   <digest>, None)`. `application_id` stays a plain Linux path so the popup's
   `application_name` works; the `wsl:` user id keeps its fingerprint apart
   from any native principal. It is never transport-authenticated, so
   `Permission::principal`'s doc comment gains "or, with
   `declared_wsl_origin`, declared by the WSL host".
3. **Lifetime**: `ApprovalCandidate::for_wsl_keyring` sets
   `declared_wsl_origin`, so `promote_permission` caps the grant at the
   lease's absolute deadline and `revoke_wsl_grants` sweeps it at the next
   unseal (decision 1), with no new code there.

The inner `action` runs as the broker (as `KeyringAccess` runs it as the
host), so its namespace must be the distro's: the broker's grant covers
nothing else. Per-app grants stay bound to the folder, as on Linux.

`PROTOCOL_VERSION` goes to 20. A v19 Linux CLI and a v20 Windows build refuse
each other (`wire.rs:579`), so the Linux CLI is rebuilt with every Windows
install of this branch; #36 (SSH agent, open) also bumps and whichever lands
second renumbers.

### Host grants without the exclusive-grant code

The broker's grant on a distro namespace is an ordinary grant (`Get`, `Put`,
`Delete`; no `Seal`, decision 2) **that expires at the lease's absolute
deadline**, not an exclusive one. That removes the reason for exclusivity (a superseded build
loses its grant when the vault next opens: `ServiceState::new` removes every
recorded host grant, and the worker grants the current broker right after;
added after the review, M1, before which it lasted to the absolute deadline
unless the worker ran), so `store_exclusive_grant` stays
Linux-only and nothing NetworkManager-related is ever compiled for, or
granted to, the broker.

To revoke a switched-off distro, or one removed from Windows, the vault keeps
one local `Authorization` record, `wsl-keyring-hosts`, listing the
(fingerprint, distro) pairs it granted. A new service method
`set_wsl_keyring_hosts(broker, distros, now)` diffs against it: grants the
new ones, deletes the grant records of the rest, rewrites the record, in one
generation. The worker calls it at every unlock (step 3).

**Open (1), decided: at once.** A manager-only action `SetWslKeyrings {
distros }`, sent by Desktop when a switch moves, applies the list with the
broker identity the worker registered at unlock (kept in memory in
`ServiceState`; refused when no broker was registered).

## Step 3: the host grant through the worker

- `Bootstrap` gains `#[serde(default)] wsl_keyrings: Vec<String>`, the
  distros switched on in Desktop's settings (validated with
  `validate_distro`).
- `identify_hosts` also identifies `factorseal-wsl-broker.exe` beside the CLI
  (`current_exe()`'s folder), with `caller_identity_for_executable`, on
  Windows only. No broker there: `wsl_keyrings` is ignored and Desktop's
  settings say so.
- `authorize_hosts` calls `set_wsl_keyring_hosts(broker, wsl_keyrings)` on
  every unlock, including an empty list (that revokes leftovers from a
  session sealed early).

## Step 4: the broker allowlist per namespace

`relay_allows(action, distro)` (no longer `const`, now takes the distro)
also lets through `WslKeyringAccess` when its inner action, if any, is `Get`
or `Mutate` on `wsl_keyring_namespace(distro)`. Plain `Get` is let through on
that namespace too, because the host reads the index without a delegated
caller (`Agent::load`); writes always go through a delegated `Mutate`.
Everything else, `KeyringAccess` and `AuthorizeSecretInput` included, is
still refused by the broker. One broker per host process, as the
`BrokerVaultClient` already keeps.

**Open (2), decided: refused.** On Linux, a client's `Lock` on the collection
seals the whole vault; from WSL it would seal the Windows vault under the
person's Windows apps. The broker holds no `Seal` and the allowlist has
none; the WSL host answers `Lock` with no object locked, which the Secret
Service API allows.

## Step 5: `factorseal wsl-keyring`

A Linux CLI command (`cfg(linux, secret-service-host)`), configured by the
same `wsl.json` that `wsl-setup` writes (`FACTORSEAL_WSL_CONFIG` overrides):

- `SecretServiceHost::start_with_options(prompter, HostOptions { network_manager: false })`;
  `start` keeps today's behaviour.
- `Store` gains `namespace: Vec<u8>` and an optional caller declarer. In
  WSL mode `check_access` resolves the sender with `dbus_caller_identity` in
  WSL, then sends `WslKeyringAccess` with the folder in
  `application.base_dir`; the delegated store keeps that declared caller, so
  the inner action is attributed to the same caller the check approved.
- `install(BrokerVaultClient)` while the vault answers. Sealed detection
  without idle polling: while installed, a `Status` at the reported
  `idle_deadline` (it does not extend the lease) and any `Sealed` answer
  uninstall; while sealed, nothing is polled until a client asks.
- Prompter: `request_unlock` sends one `Status`, which makes the broker
  bring Desktop forward on `Sealed` (milestone 1), then polls `Status` for up
  to two minutes and installs once unsealed. Access approvals are the vault's
  pending permissions, answered in the Windows popup. `supports_input` is
  false: no secure-entry dialog in WSL.
- It refuses to start without `wsl.json`, and says to run `wsl-setup`.

## Step 6: Desktop

- **Settings → WSL keyrings** (Windows only): one switch per distro, the
  names read from `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\*\DistributionName`
  (the registry, so WSL is not started). Off by default. Stored in
  `preferences.json` as `wsl_keyrings: Vec<String>`, sent in the bootstrap
  and, when a switch moves while unlocked, with `SetWslKeyrings`. When the broker is not
  installed, the section says so and the switches are disabled.
- **Popup**: for a keyring request with `declared_wsl_origin`, "Requested by"
  reads `<program> (from WSL, unverified)`; the existing "WSL distro" and
  "Access expires: When the vault seals" lines stay.
- Both are UI changes: left uncommitted until the user has seen them in the
  native build, with a script that shows them.

## Step 7: NixOS `mode = "wsl"`

- `mode` gains `"wsl"`: a user service `factorseal-wsl-keyring` running
  `factorseal wsl-keyring` (`Type=dbus`, `BusName=org.freedesktop.secrets`,
  `Restart=on-failure`), and a D-Bus service file for
  `org.freedesktop.secrets` with `SystemdService=factorseal-wsl-keyring.service`.
- The gnome-keyring assertion stays; the TPM, polkit and `tss`-group
  assertions apply only to `agent` and `desktop`.
- Built with `nixos-rebuild build` only, and a module eval check in
  `nix/tests`. The system-flakes change (poita: the module, `mode = "wsl"`,
  gnome-keyring off in `nixos-configurations/poita.nix:88` and
  `home-modules/keyring.nix`) is proposed as an edit, built, never switched.

**Open (3), decided: left alone.** Items in poita's gnome-keyring are not
imported; its files stay on disk, apps ask to sign in again, and the docs say
how to switch back.

## Step 8: packaging

`packaging/build-windows.ps1` builds `factorseal-wsl-broker.exe`
(`--features vault-client`) and puts it in the ZIP beside `factorseal.exe`;
the packaging README lists it.

## Step 9: `check.sh keyring`

On the test vault (`target\wsl-check`, never beside a Desktop):

1. `wsl-setup --windows-root` into a scratch config (as `secretspec-wsl`).
2. Enable the scratch distro name for the test vault's worker (the test
   Desktop's settings, or the live action), so the broker gets the host grant.
3. Inside `dbus-run-session`: `factorseal wsl-keyring` against
   `FACTORSEAL_WSL_CONFIG`, then nix libsecret's `secret-tool store`: popup
   (all-WSL choices only), approve, `secret-tool lookup` from the same program
   without a popup; a second program asks again; a deny fails the lookup.
4. Seal: `lookup` fails, the collection reports locked; unlock with
   `drive.ps1`, the grant is gone, a lookup asks again.
5. Cleanup trap as in `secretspec-wsl`: kill the process trees, deny the
   run's pending requests. Never the user's session bus or gnome-keyring.

## Step 10: docs

- `SECURITY.md:173–177`: the collection asks per application and item
  (native Linux: the vault resolves the D-Bus caller; WSL: the caller is
  declared by the WSL host and advisory, per the plan's trust model).
- `docs/architecture.md`: the WSL keyring (namespace per distro, host grant,
  declared caller, allowlist).
- `docs/usage.md`: enabling a distro in Settings, `wsl-keyring` / NixOS
  `mode = "wsl"`, the until-seal lifetime.
- `scripts/windows-desktop-check/README.md`: `check.sh keyring`.

## Commit plan

One commit per logical change, each with a test seen failing first:

1. Vault: namespace helper, `WslKeyringAccess`, synthetic principal, v20.
2. Vault: `set_wsl_keyring_hosts`, the hosts record, and `SetWslKeyrings`.
3. Worker: broker identity and `wsl_keyrings` in the bootstrap.
4. Broker allowlist per namespace.
5. `SecretServiceHost` options (no NetworkManager) and the namespaced store
   with a caller declarer.
6. `factorseal wsl-keyring`.
7. NixOS `mode = "wsl"`, plus the proposed system-flakes edit (not committed
   there).
8. Packaging.
9. `check.sh keyring`.
10. Docs.
11. Desktop Settings and popup wording: uncommitted until seen natively.
