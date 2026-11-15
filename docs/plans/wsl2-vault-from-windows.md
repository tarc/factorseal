# Plan: the Windows vault for WSL2 (SecretSpec and the keyring)

Status, 2026-11-15: milestone 1 (SecretSpec in WSL) is done on
`feature/wsl2-keyring` (backed up on the fork as `wip/wsl2-keyring` at
3ecbb9a, no PR), and the fixes from its independent review are committed
on top (see "Review fixes" below), the Desktop popup fix (finding 1)
included once the user saw it in the native build.
Milestone 2 (the WSL keyring) is done and committed, its Desktop UI
included after the user saw it in the native build (see "Milestone 2:
progress" below). Nothing is pushed. This branch
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
`factorseal wsl-setup` once (`--windows-root <Windows path>` targets a vault
other than the default one).

### Review fixes (2026-11-15)

An independent review of milestone 1 (`wsl2-milestone1-review.md`, kept in a
session scratchpad, not in the repo) found one blocking issue, eleven others
and six test gaps. Every fix below has a test that was seen failing without
it (or, for coverage-only tests and the relay move, failing under a
mutation of the code it guards), and each commit passed fmt, workspace
clippy, `test-with-dbus.sh cargo test --all-features --lib -- wsl
protocol::wsl` and `cargo test --all-features --bin factorseal -- relayed wsl
grant_lifetime`.

Decisions the user took:

- **Unreadable permission registry at unseal** (finding 3): the vault opens,
  records an `IntegrityFailure` security event, and leftover WSL grants run
  to their absolute deadline (option b). Not the per-unseal id in the grant
  (a storage format change).
- **Windows vault sealed** (deviation 2): `secretspec` in WSL waits for the
  unlock (polling `Status` through the broker) until shortly before its
  deadline, then retries once.
- **`wsl-setup` for another vault** (deviation 3): yes, named
  `--windows-root` because the global `--root` already names the Linux
  vault; `check.sh secretspec-wsl` now runs `wsl-setup` itself.

| Commit | Finding | What, and how it was verified |
|---|---|---|
| 42d8cbb | 1, blocking | Desktop popup: `approval_lifetime(grants, choice)` refuses a carried-over choice that no longer fits ("Until the vault seals" for mixed or native requests, a native duration for all-WSL ones, "This write only" for non-writes) with "The requests changed. Choose how long to allow access."; `grant()` uses it. Assertions in `secretspec_requests_name_…`; Linux and Windows Desktop tests (184, 169); live on the test vault (scratch `mixed-popup.sh`): a WSL read waiting with "Until the vault seals" selected, then a native `provider-probe.ps1` read joins, Allow is refused and both stay pending, "1 hour" then grants the native read for an hour and the WSL read for min(1 h, unseal deadline). The user watched the same run in the native build and approved it (2026-11-15). |
| 5834211 | 2 + deviation 2 | The relayed provider no longer calls the Linux `UnlockForIpc`/`FinishIpcAccess`; it waits for the Windows unseal and retries once. Test under the private bus with a fake Linux host counting calls (was 4, now 0) and a vault sealed for two requests, then left sealed. Live: started while the test vault was sealed, `secretspec get` waited, the unlock came at 10 s, the retried request was approved and the same command finished at 15 s; left sealed, a check gives up at ~29 s with "interaction required". |
| aa612c7 | 5 | `wsl_relay::serve` (the relay loop, with an `on_sealed` callback that runs once) replaces the broker's own loop; Linux tests with a recording client: other actions and bad frames never reach the vault and keep the frame's id, the distro tag, the error mapping, Desktop brought forward once. Mutations (allowlist skipped, callback never run) fail them. |
| f06b741 | 4 | `check.sh secretspec-wsl` cleanup trap: kills each background run's process tree (`timeout` gives secretspec its own process group) and denies the run's pending requests; step 6 asserts the denied read fails. Live: SIGINT to the check's process group during step 1 (2 secretspec and a broker running): the check exited within a second, no process and no pending request left, no popup open. |
| 2dede31 | 6 | `write_private` keeps an existing directory's mode, refuses one others can write to, makes only a directory it creates 0700. Unit test. |
| 0ca0e88 | 7 | The WSL claim forwards `XDG_CONFIG_HOME`. Unit test. |
| 48becfd | 8 | `cmd.exe /u` and UTF-16LE decoding for `%LOCALAPPDATA%`. Unit test with `C:\Users\João\…`; real `wsl-setup` run against the installed Desktop (output to a scratch config). |
| aac4805 | 11 | `Relay::drop` comment says it kills, then reaps. |
| e9c0ae5 | 3 | `ServiceState::new` records the sweep failure and opens. `wsl_sweep_does_not_block_unseal_on_an_unreadable_registry` (registry rewritten as version 2 between seal and unseal; the leftover WSL grant still works). |
| 0f7dd6f | deviation 3, test gap | `wsl-setup --windows-root`; `windows_config` tested against a fake `factorseal.exe` (pipe for the default and another root, refusal of `../x`). Live: run against the test vault's root. |
| 8353064 | 9, 10, deviation 6 | Docs: the allowlist narrows what honest clients trigger and is not a boundary; the stored expiry is the absolute deadline, a seal ends it earlier; `wsl.json` wins over `FACTORSEAL_ROOT`, not `FACTORSEAL_SOCKET`; WSL waits for the unlock. |
| 3c7c41a, 40b097e | test gap | Single-use WSL grant: expires at min(single-use window, absolute deadline) and is swept unspent. 40b097e removed a once-in-~180-runs flake (the request clock can stamp the approval a second late). |
| 1d15f4d | test gap | Provider client selection (`FactorsealProvider::select` with a loader): WSL setup without socket → relayed, socket wins and never reads `wsl.json`, damaged `wsl.json` → `WslSetup` error. |
| 332f468 | test gap | `BrokerVaultClient`: a broker that dies after reading gets the resend; a reply with another id is an error and that broker is dropped. |
| 9a806cb | test gap | `check.sh secretspec-wsl` step 3 asserts no new pending request. |
| e4bcffd | test gap | `build-windows.sh check` runs `cargo test --lib --features vault-client -- protocol::wsl` natively (9 passed, including the Windows-only relayed-decode test). |
| dee173a | new, from the live runs | `check.sh` puts the broker and CLI in `target\wsl-check`: beside `factorseal-desktop.exe` (as 0f7dd6f first had it), the broker answered the idle-sealed test vault by starting that Desktop **without `--root`**, on the user's own vault (it stayed sealed; the stray Desktop was stopped). |

Live on the test vault with the release build of this branch: `check.sh
secretspec-wsl` PASS twice (through `wsl-setup --windows-root`; second read
without a popup in 479 and 612 ms), plus the finding 1, finding 4 and
deviation 2 runs above.

Finding 12 (the broker client's lock held through each 5 s
`WaitPermission`), measured only: a three-key `secretspec check` in WSL with
no approvals had all three requests pending within ~0.7 s of each other
(vault `created` +1/+2/+1 s), so the popup lists every key at once. Approved,
the same check takes 1.1–1.4 s. Left unanswered, three keys end at 33.9 s
with "deadline exceeded", where one key ends at 30.0 s with "interaction
required": the keys' waits queue on the shared broker, so the provider
misses its answer-by time. A broker per in-flight request would fix that;
not built, pending the user's call.

Not changed: deviation 4 (`--remove` leaves the claim) and 5 (the CLI
accepts longer WSL durations, clamped) were acceptable in the review.
`single_use_write_permission_allows_exactly_one_write` (native, older)
asserts the same exact approval time that made 3c7c41a flaky.

## Milestone 2: progress (2026-11-15)

Design: [wsl2-keyring-design.md](wsl2-keyring-design.md). Decisions the user
took this session: a Settings switch takes effect at once; `Lock` from WSL is
refused; items in gnome-keyring are left alone; the broker learns the vault
root from `wsl.json` (so `check.sh keyring` can use the broker beside the test
Desktop's CLI); the Projects/Provider-cache copy splits the two flows (see
"Separate" below). Each commit passed the gate (fmt, workspace clippy, the
`wsl protocol::wsl` lib tests under a private bus, the `relayed wsl
grant_lifetime` CLI tests, plus the filters of what it touched), and its tests
were seen failing without the change, by a mutation of the code each guards
where the change added new types (every mutation listed in the session was
caught).

| Commit | What, and how it was verified |
|---|---|
| fc3fc0b | This design note and the decisions. |
| c6631da | Protocol v20 `WslKeyringAccess` (declared caller, distro and folder from the broker's context, host grant on `factorseal/wsl-secret-service/v1/<distro>`, action confined to it, `wsl:<distro>:uid:<n>` principal, until-seal lifetime); `KeyringAccess` and it share one path. Vault tests + 8 mutations. |
| 35574d2 | `set_wsl_keyring_hosts` (Get/Put/Delete until the absolute deadline, a `wsl-keyring-hosts` record to revoke) and manager-only `SetWslKeyrings`. Tests incl. a session sealed early (real clock: the store's open purge uses it) + 5 mutations. |
| fde20ca | New, found while building: export looked keyring items up in the native index only, so one WSL keyring item broke every backup; import, archive check and inventory labels fixed too. Test seen failing first + 4 mutations. |
| 2026ae6 | Worker: `wsl_keyrings` in the bootstrap, broker beside the CLI identified on Windows, applied at every unlock (non-fatal), no write when there is nothing to change. Shared `test_vault` fixture for CLI tests. Tests + 3 mutations; `cargo xwin clippy` of the CLI caught a Windows-only type error before commit. |
| 3181c6d | Broker allowlist per namespace: `WslKeyringAccess` only for its distro, plain `Get` only of that keyring's index, never Seal. Test seen failing against the old allowlist + 3 mutations; broker cross-clippy. |
| 4b2fdd9 | Host: store with namespace and caller declarer, `install_wsl`, `start_with_options` (no NetworkManager agent; not unit-testable, spawned under `cfg(not(test))`), `Lock` locks nothing for WSL, and new: a WSL `CreateItem` names its item first (the vault approves writes to named items only, so `secret-tool store` could never have been approved). End-to-end D-Bus test with a simulated broker + declarer test + planned-item test + 6 mutations. |
| 669e425 | `factorseal wsl-keyring` (state machine, sealed detection by idle deadline and by `Sealed` answers, unlock through a fresh broker). Unit tests + 4 mutations; smoke run without `wsl.json`. |
| db4ae0e | New, user's decision: `wsl.json` records `windows_root`, the client passes `relay --root`, the broker starts Desktop on that vault. Tests + 3 mutations; broker cross-clippy. |
| ed28f3b | NixOS `mode = "wsl"` (user service + activation file, TPM/polkit/tss only for agent/desktop). New flake check `nixos-module-wsl` (failed before the change); agent-mode VM test derivation unchanged. |
| 3fe57bd | Desktop non-UI: `wsl_keyrings` in preferences (validated), bootstrap, live `SetWslKeyrings`, hidden `--wsl-keyring`. Tests + 3 mutations. |
| f8a862d | `build-windows.sh` skips `.boostgraph/` (a Unix socket robocopy cannot copy, exit 9). Verified by the next mirror. |
| 7d40aeb | The `relay --root` test is Linux-only (it broke `build-windows.sh check`'s relay tests on Windows). |
| (packaging) | `build-windows.ps1` builds and ships the broker; the built unsigned ZIP lists `factorseal-wsl-broker.exe` (the old script built none). |

Verified natively and live: `build-windows.sh check` (clippy, Desktop 172
tests, relay 13 tests); `build-windows.sh release --broker`; **`check.sh
keyring` PASS** on the test vault: store and lookup each asked in the popup,
which names "secret-tool (from WSL, unverified)" and "When the vault seals";
the lookup's grant expires at the unseal deadline; a second lookup without a
popup (1.9 s: each Secret Service call resolves the caller and crosses the
broker); another program asked for itself (denied); the collection locked
after a seal; a lookup after the unlock asked again. Settings → WSL keyrings
seen through UI Automation in the test Desktop (switches for NixOS,
docker-desktop, podman-machine-default). Full suites: lib 506 passed (5
ignored), CLI 79, Desktop 187. poita built (`nix build --no-link`) with the
proposed system-flakes edit: the activation file runs `factorseal
wsl-keyring`, no gnome-keyring unit.

After the user's review in the native build (2026-11-15, "the UI changes look
good"), committed with the gate before each: 0838a7b Settings → WSL keyrings
and the popup's "(from WSL, unverified)"; be99435 the Projects/Provider-cache
copy; 69f362a `check.sh keyring`; f305112 the docs (SECURITY.md,
architecture, usage). The system-flakes edit (poita) is a proposal, built
but not committed there; the user switches.

Notes for later: libsecret clients give up after D-Bus's 25 s while an
approval waits (the request stays pending); the native headless agent has the
same unnamed-`CreateItem` limitation as WSL had (not changed: out of scope).

## Milestone 2: the WSL keyring (planned)

The design, its re-checked facts and the user's decisions of 2026-11-15
(switch at once, `Lock` from WSL refused, no gnome-keyring import) are in
[wsl2-keyring-design.md](wsl2-keyring-design.md); where it corrects the facts
and steps below, it wins.

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

2026-11-15: the provider reads only Provider cache (`GetCache`; a throwaway
test showed a `PutProject` value found by `GetProject` and not by
`GetCache`), so Projects must not keep the SecretSpec steps. The user chose to
split the flows: Projects = `factorseal set/get --project` for scripts, with a
line that SecretSpec does not read these; Provider cache = what SecretSpec
stores through factorseal://default (`secretspec set` values do not expire),
with the init/set/run steps and the cache alias; the links follow
(FactorSeal's usage docs, SecretSpec's Quick Start). Committed be99435 after
the user saw it.

## Working notes for the next session

- Windows checks: `scripts/windows-desktop-check/` (README, `windows-desktop-check`
  skill). Release builds refuse while any FactorSeal process runs: ask the user,
  then seal their vault with the installed `factorseal.exe seal` and stop
  Desktop (the tray menu no longer takes `SendKeys` keystrokes, and a plain
  `taskkill` only hides it: once sealed, `taskkill /F`). Stop the browser
  host too. Restart Desktop with the Startup shortcut afterwards.
- On `Sealed` the broker starts the `factorseal-desktop.exe` beside it
  without `--root`: never put a broker for the test vault next to a Desktop
  (`check.sh` uses `target\wsl-check`).
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
