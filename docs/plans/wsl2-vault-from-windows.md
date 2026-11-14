# Plan: the Windows vault for WSL2 (SecretSpec and the keyring)

Status, 2026-11-14: milestone 1 (SecretSpec in WSL) is done on
`feature/wsl2-keyring` (backed up on the fork as `wip/wsl2-keyring`, no PR).
Milestone 2 (the WSL keyring) is planned below and not started. This branch
sits on `stack/7-browser-windows`, the top of the WSL2 PR stack (#42 → #43 →
#44 → #46 → #47, index #40); rebase it with `git rebase --onto` when the stack
changes or merges.

## Goal

One vault: Linux programs inside a WSL2 distro use the FactorSeal vault that
FactorSeal Desktop hosts on Windows, with approvals in Desktop's popup.

1. **SecretSpec in WSL** (milestone 1): Linux `secretspec … --provider
   factorseal://default` in WSL reaches the Windows vault. Motivating case:
   `~/projects/carimbo`, key `CARIMBO_ANTHROPIC_API_KEY`, set from PowerShell.
2. **WSL keyring** (milestone 2): `org.freedesktop.secrets` in the distro is
   served by the Windows vault instead of gnome-keyring.

## Decisions (taken with the user, 2026-11-14)

1. **WSL approvals last until the vault seals** (at most the unseal lease's
   absolute deadline; swept at the next unseal), for keyring items and
   SecretSpec alike. "This write only" stays; no "until revoked" for WSL.
2. **The WSL keyring asks per app and per item**, like native Linux, with the
   WSL host declaring the calling program; the popup marks it as coming from
   WSL, unverified.
3. **SecretSpec first**, the keyring after.
4. **One keyring per distro**: a namespace per distro name; Desktop Settings
   lists distros (from the registry, without starting WSL) with a switch each.
5. **Relay allowlist in the broker**: only what the WSL clients use; anything
   else is refused before it reaches the vault.
6. **The broker ships in the Windows install**, next to `factorseal.exe`
   (ZIP and install folder); MSIX later.
7. **Backup**: push the work-in-progress branch to the fork as `wip/…`.
8. **Desktop's Projects/Provider-cache wording**: fix the copy only (separate
   from this plan, see the end).

Settled open questions of milestone 1: the broker brings Desktop forward when
the vault is sealed or not running; `/mnt/<drive>/…` folders translate to
`<DRIVE>:\…`; setup is an explicit `factorseal wsl-setup` (`--remove` undoes
it); the broker's interop start-up was measured at ~0.7 s for a whole
`secretspec get`, far inside SecretSpec's 30 s deadline.

## Trust model (what the docs must keep saying)

- The vault authenticates only the broker (SID + executable hash). The distro,
  project, folder, launch chain, and in milestone 2 the keyring caller, are
  declared by the WSL side and never identity.
- The trusted party is all of WSL (any distro, any Linux user, root included:
  interop runs as the Windows user) plus any Windows process of the user that
  can run the broker. That matches the documented boundary, the Windows SID
  (`SECURITY.md`, "same-user processes").
- Grants belong to the broker's identity, so one approval covers every WSL
  process asking for the same thing until the vault seals. Per-distro
  namespaces organise data; they do not isolate it (distro names are
  self-declared).
- Per-app keyring approval in WSL is advisory: it catches surprising access by
  honest tools and keeps an audit trail, but a malicious WSL process can run
  the broker and declare any caller.

## Milestone 1: SecretSpec in WSL (done)

Commits on `feature/wsl2-keyring` (on top of `stack/7-browser-windows`):

| Commit | What |
|---|---|
| d84559c | Vault: a grant approved for a WSL-tagged request (`declared_wsl_origin`) expires at the lease's absolute deadline (`promote_permission`, `src/vault/protocol/grant.rs`, fed from `state.lease_deadlines()`), and `revoke_wsl_grants` removes all WSL grants when the vault opens (`ServiceState::new`, `service/state.rs`). No wire or storage format change. |
| d1ebcda | Broker relay mode: `factorseal-wsl-broker.exe <pipe> <distro> relay`; library module `vault::wsl_relay` (`src/vault/protocol/wsl.rs`): length-prefixed frames, `windows_folder` (Linux path → `\\wsl.localhost\<distro>\…` or `C:\…`), `relay_allows` (Status, WaitPermission, Get/Put/DeleteCache), `validate_distro`, `BrokerVaultClient` (Linux client that spawns the broker). `VaultRequest::decode_relayed_from_wsl` decodes without validating, tags the distro, translates the folder, then validates (a Linux path is not absolute on Windows). The broker starts Desktop when the vault is sealed or unreachable. |
| 472d45f | `factorseal wsl-setup` (`src/bin/factorseal/wsl.rs`): finds the install, reads the pipe from `factorseal.exe status`, writes `~/.config/factorseal/wsl.json` (broker, pipe, distro; `FACTORSEAL_WSL_CONFIG` overrides), publishes a WSL claim that also forwards `WSL_INTEROP`, `WSL_DISTRO_NAME`, `FACTORSEAL_WSL_CONFIG`. The provider uses `BrokerVaultClient` when `wsl.json` exists and no socket is given, and skips the Linux Desktop `SupportsSecureInput` probe (writes take `PutCache`). |
| 08f80c2 | CLI `permissions approve`: WSL requests default to "until the vault seals". |
| 07315c0 | Docs: `docs/usage.md` (SecretSpec in WSL2), `docs/architecture.md` (WSL2 broker, relay mode). |
| 6040030 | Desktop popup: for all-WSL requests only "Until the vault seals" (default) and "This write only"; "Access expires: When the vault seals". `MAX_WSL_GRANT_SECONDS` removed. `check.sh secretspec-wsl`; `check.sh grant` checks the new expiry; `drive.ps1 press` finds radio buttons. Validated by the user in the native Windows build. |

How it was verified: Linux unit tests (`wsl_declared_origin_grant_ends_with_the_unseal`,
`wsl_grants_are_removed_when_the_vault_unseals_again`, `protocol::wsl::tests`,
`a_relayed_provider_writes_through_grants_not_the_linux_dialog`,
`a_wsl_request_defaults_to_lasting_until_the_vault_seals`, the popup's
`grant_choice` assertions), each checked to fail without its fix; workspace
clippy; Windows clippy and Desktop tests (169); broker and CLI cross-clippy
with `cargo xwin`; and live on the test vault, `check.sh secretspec-wsl`
PASS: write and read granted until seal, a second read without a popup in
696 ms, another folder asks again, the native provider reads the same value
under its own approval, a seal removes the WSL grant.

Using it: install this branch's Windows build (`build-windows.sh release
--broker`, copy the six exes incl. `factorseal-wsl-broker.exe` beside
`factorseal.exe`), build the Linux `factorseal` in WSL, run
`factorseal wsl-setup` once.

## Milestone 2: the WSL keyring (planned)

### Facts this rests on (checked 2026-11-14 on `stack/7-browser-windows`)

- Since 395b3c6 every Secret Service search/get/set/delete goes through
  `authorized_agent` → `VaultAction::KeyringAccess`
  (`src/vault/secret_service/interfaces.rs` ~85, 372, 460, 529–655;
  `secret_service.rs` ~396). The **vault** resolves the D-Bus sender itself
  (`dbus_caller_identity`, `src/vault/linux.rs` ~601). On a non-Linux vault
  `keyring_peer` returns `AuthorizationRequired`
  (`src/vault/protocol/service.rs` ~846–853), so a Windows vault refuses every
  keyring access as things stand. `SECURITY.md` ~172–177 ("session-wide
  trust") is stale against this code.
- `KeyringAccess` checks a grant on the hard-coded namespace
  `factorseal/secret-service/v1` (`service.rs` ~435).
- Exclusive host grants (`authorize_exclusive`,
  `service/authorization.rs` ~223; `store_exclusive_grant`, `grant.rs` ~284)
  and `authorize_secret_service_host` are `cfg(linux + secret-service-host)`.
- The desktop worker grants Desktop and the CLI at every unlock
  (`authorize_hosts`, `src/bin/factorseal/desktop_worker.rs` ~219, identities
  via `platform::caller_identity_for_executable`).
- `SecretServiceHost::start(prompter)` and `install(Box<dyn VaultClient>)`
  (`secret_service.rs` ~125, ~155) take any client, so `BrokerVaultClient`
  plugs in. The NetworkManager agent only acts when it reaches a system bus,
  so it idles in WSL; never grant the broker the NM namespace.
- The host already reads a peer's pid, executable and working directory from
  D-Bus + `/proc` (`interfaces.rs` ~130–150).
- NixOS module `nix/modules/factorseal.nix`: modes `agent`/`desktop`, asserts
  gnome-keyring off, D-Bus activation for `org.freedesktop.secrets`.
- Protocol: stack v19 (broker hint), main v18; #36 (SSH agent, open) also
  bumps. Milestone 2 needs v20.

### Steps

1. **Design note** with the user before code (as for milestone 1).
2. **Vault** (protocol v20):
   - Namespace per distro, kind `LinuxSecretService`, e.g.
     `factorseal/wsl-secret-service/v1/<distro>` (`validate_distro`).
   - `KeyringAccess` with a **declared caller** (new field or variant: program
     path, pid, working directory, executable hash computed in WSL), used
     where the vault cannot resolve the sender. Accepted only from the holder
     of that distro's WSL keyring grant; the per-app grant principal is a
     synthetic identity (e.g. platform Linux, application id
     `wsl:<distro>:<path>`), flagged unverified in the permission record.
   - Make the exclusive-grant code compile on Windows for the WSL namespaces;
     `KeyringAccess` accepts the WSL namespace for the broker.
   - Grants inherit the until-seal rule (the broker tags `declared_wsl_origin`).
3. **Host grant via the worker**: `authorize_hosts` identifies
   `factorseal-wsl-broker.exe` next to the CLI and issues the exclusive grant
   for each distro enabled in Desktop's settings, at every unlock (updates
   re-grant automatically, since grants pin the executable hash).
4. **Broker**: extend `relay_allows` with the declared-caller `KeyringAccess`
   and the keyring actions (Get/Put/Delete/List/Seal/Mutate) **only on that
   distro's namespace** (check the namespace per action); keep one broker
   running for the host.
5. **`factorseal wsl-keyring`** (Linux): runs `SecretServiceHost` with
   `BrokerVaultClient` (config from `wsl.json`); resolves the D-Bus peer in WSL
   and sends it as the declared caller instead of the sender name; prompter:
   unlock → the broker starts Desktop (already done on `Sealed`), access →
   pending permission → Windows popup, `supports_input` false (no secure-entry
   dialog in WSL); installs while the vault answers, reports locked when it
   seals.
6. **Desktop (Windows)**: Settings → WSL keyrings: distros from
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` (`DistributionName`)
   with a switch each, stored in preferences, read by the worker. Popup:
   keyring requests from WSL name the program "from WSL, unverified". UI is
   committed only after the user sees it in the native build.
7. **NixOS module**: `mode = "wsl"`: a D-Bus-activated user service running
   `factorseal wsl-keyring` (`Type=dbus`, `BusName=org.freedesktop.secrets`),
   keeping the gnome-keyring assertion. The user's home-manager keyring module
   lives in `~/projects/system-flakes` (propose the change there; build only,
   the user switches).
8. **Packaging**: add the broker to `packaging/build-windows.ps1`'s ZIP.
9. **Checks**: `check.sh keyring`: a private bus (`dbus-run-session`), the
   host against the test vault (`FACTORSEAL_WSL_CONFIG`), `secret-tool
   store/lookup` (nix libsecret's `secret-tool`), per-app popup approval, deny,
   seal → locked, unlock again. Never touch the user's session bus or
   gnome-keyring.
10. **Docs**: fix `SECURITY.md`'s session-wide-trust passage, add the WSL
    keyring to `docs/architecture.md` and `docs/usage.md`.

## Separate: Desktop's Projects/Provider-cache wording

Still on main 214f27e: the Projects page tells users to run `secretspec set …
--provider factorseal://default` (`factorseal-desktop/src/app.rs` ~1081), but
that stores under Provider cache, whose page calls its values "expiring local
copies" (~1142) though a plain set never expires. Fix: Projects points to
`factorseal set --project`; Provider cache says it also holds values stored by
`secretspec set`, which do not expire. UI change: validate natively first.

## Working notes for the next session

- Windows checks: `scripts/windows-desktop-check/` (README, `windows-desktop-check`
  skill). Release builds refuse while any FactorSeal process runs: ask the user,
  then seal their vault with the installed `factorseal.exe seal` and stop
  Desktop (the tray menu no longer takes `SendKeys` keystrokes). Restart it
  with the Startup shortcut afterwards.
- The test vault seals after ~5 idle minutes; a request left pending then keeps
  a popup with "Unlock to continue" open, which covers the main window's
  password field: unlock with `drive.ps1 -Action unlock-popup`, deny leftovers.
- Popup titles are "Secret access · FactorSeal" / "Browser access ·
  FactorSeal" (the scripts match the name before " · ").
- Linux test run: `libsecret_store_seal_lookup` needs
  `FACTORSEAL_TEST_SECRET_TOOL` set to nix libsecret's `secret-tool` (no
  `/usr/bin` here) and times out on most runs on main too; timing tests fail
  under parallel Windows builds, so rerun them alone.
- Cross-check Windows-only code from WSL with `cargo xwin clippy --target
  x86_64-pc-windows-msvc` inside `devenv shell`.
- C: fills fast (Linux `target` ~36 GB, Windows mirror ~19 GB): delete build
  output when done.
