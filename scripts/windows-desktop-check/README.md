# Windows Desktop checks from WSL2

Scripts for building FactorSeal natively on Windows and checking FactorSeal
Desktop's approval popup there, driven from a WSL2 shell. They exist because
Desktop cannot be cross-compiled from Linux (its renderer needs Windows'
shader compiler) and because what matters about the popup (focus, taskbar
flashing, what reaches the vault) only shows on a real Windows desktop.

Everything runs from the WSL2 checkout. The Windows side is a mirror of it,
by default `%USERPROFILE%\Projects\factorseal`; set `FACTORSEAL_WINDOWS_TREE`
(a WSL path such as `/mnt/c/Users/me/src/factorseal`) to use another.

## Scripts

| Script | Runs on | Does |
| --- | --- | --- |
| `build-windows.sh [release] [--broker]` | WSL | Mirrors the checkout and builds Desktop, the CLI (with the SecretSpec provider), and its parser, network and browser bridge helpers natively. Refuses to start while a Desktop, CLI or browser host built in the Windows copy runs (an installed FactorSeal elsewhere can stay open). `--broker` also cross-compiles the WSL broker. |
| `build-windows.sh --test-hooks` | WSL | Builds Desktop with the `wsl-test-hooks` feature, for `check.sh keyring-import` (with `check`, also runs Desktop's tests with it). Such a Desktop runs whatever program `FACTORSEAL_TEST_KEYRING_EXPORTER` names in WSL, in place of `factorseal`, and restores its output, so it is for the check only: never the ZIP, an installer release or a Desktop anyone uses. Its executable contains that variable's name; one built without the feature doesn't. |
| `build-windows.sh check` | WSL | Mirrors, then runs clippy, Desktop's tests and the WSL relay's library tests (`protocol::wsl`, including the Windows-only relayed-decode test) natively. Safe while Desktop runs. |
| `check.sh popup [--delay S] [--key K]` | WSL | Sends a request through the WSL broker and reports whether the popup opened, reached the foreground or flashed its taskbar button, with screenshots of the popup and the taskbar and a check that the vault holds the pending request. |
| `check.sh grant --key K` | WSL | After the popup was approved, resends the request and checks that it succeeds without a new popup and that the grant expires when the unseal ends, at the lease's absolute deadline. |
| `check.sh test-desktop` | WSL | Creates the throwaway test vault if needed, starts a Desktop on it (with `--wsl-keyring` for this distro, which only grants this distro's keyring in the test vault), and unlocks it through `drive.ps1`. |
| `check.sh popup --steal` | WSL | As soon as the popup takes the foreground, the observer hands it to a window of its own that stands in for another app. The popup must then flash. Needs the popup to take the foreground first, which happens when Desktop was just used, for example right after `test-desktop`. |
| `check.sh popup --test-vault --seal --then grant\|deny` | WSL | Seals the vault while the request waits and checks that the popup stays open. `grant` unlocks from the popup and grants; `deny` denies while sealed, unlocks from the main window, and checks that the request stays denied. |
| `check.sh popup --test-vault [--then grant\|deny]` | WSL | `popup` against the test vault and its Desktop; `--then` drives the popup afterwards, and `grant` also runs the grant check. `grant --test-vault` works the same way. |
| `check.sh write-once [--via popup\|cli]` | WSL | On the test vault, writes a new SecretSpec key through the provider, approves it with the default lifetime in the popup or with `factorseal permissions approve`, and checks that the default was "this write only": one write is stored, the grant is gone, and the next write asks again. |
| `check.sh secretspec-wsl` | WSL | On the test vault, runs the Linux `secretspec` against the Windows vault through the Linux provider and the broker's relay mode, configured with `factorseal wsl-setup --windows-root` in a scratch directory (the broker and the native CLI are copied to `target\wsl-check` in the Windows copy first, a folder without Desktop, since on `Sealed` the broker starts the Desktop beside it without `--root`): a write and a read granted "Until the vault seals" in the popup (which must offer only that and "This write only"), a second read without a popup and how long it took, another folder asking again, the native provider reading the same value from the translated `\\wsl.localhost` folder under its own approval, and a read after a seal and unlock asking again. Needs the Linux CLI (`FACTORSEAL_LINUX_CLI`, default `target/debug/factorseal`); builds SecretSpec from `nix/secretspec.nix` unless `FACTORSEAL_SECRETSPEC` names one. |
| `check.sh keyring` | WSL | On the test vault, serves this distro's keyring from the Windows vault with `factorseal wsl-keyring` on a private D-Bus session (`dbus-run-session`; never your own bus or gnome-keyring) and uses it with libsecret's `secret-tool`: a store and a lookup each asked in the popup, which must name the program as declared by WSL, unverified; a second lookup without a popup; another program asking again (denied); the collection locked after a seal; and a lookup after the unlock asking again. Copies the broker beside the test Desktop's CLI (the worker grants a distro's keyring only to the broker there; `wsl.json` holds the test vault's root, so the broker brings forward the test Desktop, never yours) and restarts the test Desktop with `--wsl-keyring <distro>` if it runs without it. Needs the Linux CLI (`FACTORSEAL_LINUX_CLI`, default `target/debug/factorseal`); builds libsecret from the flake's nixpkgs unless `FACTORSEAL_SECRET_TOOL` names a `secret-tool`. |
| `check.sh keyring-import` | WSL | Live check of Settings → WSL keyrings (`docs/plans/gnome-keyring-import.md`, step 8) on the test vault, never your own bus or gnome-keyring. Seeds a throwaway gnome-keyring in `/tmp/fsk-import` (a password-protected login collection: three items tagged with the run, so the test vault lacks them whatever earlier runs moved, and a Wi-Fi item a move skips), writes an exporter there that runs the Linux CLI on a private D-Bus session where only that gnome-keyring and gcr's prompter can start (D-Bus activation, as on a distro WSL has just started), runs its inventory once through `wsl.exe`, and restarts the test Desktop with `FACTORSEAL_TEST_KEYRING_EXPORTER` naming it. Then it prints what to expect and follows the exporter while you run **Check** and **Move** in the test Desktop; Move's gcr prompt (WSLg) asks for the throwaway password it prints. Needs a Desktop built with `build-windows.sh --test-hooks`, the broker and the Linux CLI. |
| `check.sh keyring --imported` | WSL | After `keyring-import`'s move: serves the distro's keyring from the test vault as `keyring` does, and `secret-tool` finds two of the moved items, each asked in the popup and granted. Removes `/tmp/fsk-import` when it passes. |
| `browser-check.sh [--browser=edge\|chrome\|both] [--restart-browser] [--only=STEP,...]` | WSL | Checks the browser extension end to end in a separate Edge or Chrome profile against the test vault's Desktop: pairing, saving through the page's **Save this login in FactorSeal?** question (and forgetting the login with **Not now**), resubmitting unchanged, saving from a registration form, updating a stored login's password (and failing when the login changes during review), filling from the button in a login field (and submitting the login just filled asks nothing), Deny, Escape, a site with no stored login, **Fill this page**, a fill started while sealed, and a fill held between the choice and its release while the login changes, the profile is disconnected in Settings, or Desktop's 5-second wait lapses; also a profile disconnected in Settings without the extension hearing of it, restarting the native host, the extension's service worker, Desktop, and the browser while a fill waits (the test browser and Desktop are started again), a save interrupted by navigation, denial, closing its tab, disconnecting the profile, or sealing; **Save login from this page**; resubmitting and correcting a login; forms that must not offer a save (mismatched confirmation, hidden password, another site's action); and that the extension's storage holds none of the submitted values. `both` pairs both and checks that consent never crosses from one browser to the other. See [Browser extension](#browser-extension). |
| `browser-check.mjs` | Windows (Node) | Used by `browser-check.sh`; drives the test browsers through the DevTools Protocol and Desktop's browser prompt through `drive.ps1`. |
| `foreground.ps1 -Action get\|raise [-ProcessId P]` | Windows | Used by `browser-check.mjs`; reports which window Windows has in front, or brings a process's window there. A browser's own focus state (`chrome.windows`) can say it is focused while another app is in front. |
| `observe.ps1` | Windows | Used by `check.sh`; hooks taskbar-flash notifications and captures the screenshots. |
| `uia-dump.ps1 [-Out FILE] [-DesktopPid P]` | Windows | Lists what UI Automation, and so a screen reader, sees in Desktop's windows: control types, names (the popup's text included), AutomationIds, whether a radio button is selected, and whether a value is exposed (never the value itself). An owned popup is listed twice, as UI Automation lists it: on its own and under the main window. |
| `test-vault.ps1 -Cli EXE` | Windows | Used by `check.sh`; creates a password-only vault in `%LOCALAPPDATA%\FactorSeal-check` with a random password in an owner-only file. Leaves an existing one alone. |
| `drive.ps1 -Action find\|unlock\|unlock-popup\|grant\|deny\|press\|show\|escape -DesktopPid P [-PasswordFile F] [-Title T] [-Name N] [-NoWait]` | Windows | Used by `check.sh` and `browser-check.mjs`; reports whether the popup is open (and where, and whether it is in front), unlocks Desktop's main window or a popup kept open by a seal, grants or denies the popup, or presses the button named `-Name` (`*` is a wildcard) or Escape in it; `show` only scrolls that button into view. `-Title` picks another popup by its name, the title before ` · FactorSeal`, such as `'Browser access'`, or the main window (`'FactorSeal'`). `-NoWait` returns without waiting for the popup to close. Finds controls through UI Automation, then clicks and types with real input, because the popup accepts approval only after a click inside it. |
| `screenshot.ps1 -DesktopPid P -Out FILE` | Windows | Saves a PNG of the approval popup, raised and kept topmost for the capture, to see how it looks. |
| `provider-probe.ps1 -Cli EXE [-Root DIR] [-Method get\|set] [-Key K] [-Directory D]` | Windows | Talks to `factorseal provider` directly as SecretSpec would (initialize, then one get or set) and prints the replies and the provider's standard error. Makes requests the `secretspec` CLI cannot, such as a write to an undeclared key. A get reply contains the value, so use `-Root` with the test vault. |
| `cli-approve.ps1 -Cli EXE -Root DIR -PasswordFile F -Id ID [-Answer A]` | Windows | Used by `check.sh write-once --via cli`. Runs `permissions approve` in its own console window, since its prompts need a terminal, and types the answer and Enter only while that window is in the foreground. |
| `proc-watch.ps1 -Out FILE [-Seconds N]` | Windows | Logs FactorSeal processes, their helpers and WerFault starting and exiting, and whether Desktop's window responds. For diagnosing hangs and crashes. |

PowerShell scripts are run from WSL as
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\...\script.ps1' ...`,
using their path in the Windows copy.

## Typical flow

1. `./scripts/windows-desktop-check/build-windows.sh --broker`
2. The user starts Desktop on Windows
   (`C:\...\factorseal\target\release\factorseal-desktop.exe`) and unlocks the
   vault. Only a person can do this step and step 4.
3. `./scripts/windows-desktop-check/check.sh popup`. Leave the popup alone
   until the result prints. For the "behind another app" case, use
   `--delay 10` and bring another app to the front during the delay.
4. The user approves the popup (or denies it).
5. `./scripts/windows-desktop-check/check.sh grant --key CHECK_...`, with the
   key printed by step 3.

Before changing Desktop's UI, run `build-windows.sh check`; afterwards,
`build-windows.sh` and the flow above.

## Automated flow on a test vault

Nobody has to type a password or click the popup when the checks run against
a throwaway vault. It runs in its own Desktop next to the user's, which keeps
its own vault and tray icon.

1. `./scripts/windows-desktop-check/check.sh test-desktop`
2. `./scripts/windows-desktop-check/check.sh popup --test-vault --then grant`
   (or `--then deny`)

The driver moves the pointer and types, so it takes over the Windows
desktop for a few seconds. It never clicks or types unless Desktop's window
is in front and under the pointer. While it acts, it keeps that window
topmost, because an always-on-top app (such as a pinned terminal) otherwise
covers it, and it releases it afterwards.

## Reading the results

- `check.sh popup` passes when the popup is **in the foreground or flashed its
  taskbar button**. Windows decides whether a background app may take focus
  (it depends on recent input and timing), so either outcome is correct; a
  popup that is behind and does not flash is a failure.
- `popup.png` shows what was on screen where the popup is. When the popup is
  behind another app, that is the other app; `taskbar.png` then shows the
  highlighted button.
- `FACTORSEAL_TIMINGS=1` in Desktop's environment makes Desktop and its
  worker print each startup, unlock, and parse stage with its duration to
  stderr.

## Pitfalls

- **The vault seals itself after a few idle minutes.** A pending request
  survives it: the popup stays open with "Unlock to continue", and the request
  is still pending after the unlock. A new request cannot reach a sealed vault,
  so `check.sh` checks before sending (and again after `--delay`); unlock and
  rerun when it says the vault is sealed.
- **Desktop locks its executables.** Quit the one built in the Windows copy
  (the test Desktop too) from the tray before `build-windows.sh release`; an
  installed Desktop elsewhere can stay open.
- **Windows blocks UI Automation from a normal process into an elevated
  one.** Desktop no longer needs elevation, but if it is started elevated,
  `uia-dump.ps1` and `drive.ps1` from WSL see only window frames.
- **A popup opened while the main window is active is owned by it.** GPUI
  makes such a dialog modal: the main window is disabled, the popup stays
  above it, and the popup has no taskbar button, so the main window's button
  flashes for it. UI Automation then lists the popup under the main window,
  so find it by its window title (as `observe.ps1` and `drive.ps1` do).
  `observe.ps1` counts the popup as in front when its owner is.
- **An always-on-top window covers the taskbar too**, so `taskbar.png` then
  shows that window; rely on the flash count instead.
- **The CLI needs `secretspec-provider`** for native SecretSpec on Windows.
  Packaging leaves it out until the SecretSpec IPC crate is published;
  `build-windows.sh` adds it (see `docs/development.md`).
- **Desktop needs its helpers beside the CLI.** Every request is parsed by
  `factorseal-parser.exe`; without it, unlocking can hang.
- Windows PowerShell 5.1 writes files with a UTF-8 byte-order mark and CRLF
  line endings; the scripts strip both when reading on the WSL side.

## Browser extension

`browser-check.sh` needs Node in WSL (the devenv shell has it) and on Windows.
It starts a separate Edge (or Chrome) with its own profile in
`%LOCALAPPDATA%\FactorSeal-check\edge-profile` (`chrome-profile`), remote
debugging on port 9333 (9334), and the extension loaded unpacked from
`%LOCALAPPDATA%\FactorSeal-check\extension-chromium`. Chrome ignores
`--load-extension` since version 137 and Edge since version 154, so the check
loads it with the DevTools Protocol's `Extensions.loadUnpacked`, which needs
`--enable-unsafe-extension-debugging`. Your own browsers and their profiles
are left alone: they refuse remote debugging on the default profile.
The extension keeps its ID in any profile (its manifest has a fixed `key`),
and browsers find native messaging hosts per Windows user, so the test Edge
reaches the same Desktop.

- Pages are served by the browser itself on made-up origins such as
  `https://login-<run>.factorseal.test`, from `extensions/browser/fixtures`.
  Nothing goes over the network, and each run uses new origins.
- Browsers reach the vault of the Desktop that started last. The check stops
  if that is not the test Desktop; stop the test Desktop and rerun.
- The test copy of the extension has site access granted at install, since
  Edge's permission dialog cannot be answered through the DevTools Protocol.
- The first run pairs the profile; later runs reuse the pairing. The check
  closes tabs left from earlier runs.
- A fill starts from the FactorSeal button the extension puts in a login
  field, and a save from the question it shows on the page after a
  submission. Both are extension pages framed into the site's page; the check
  presses their buttons in their own DevTools targets, and the extension
  accepts such a press only while the frame is visible and in front.
- `--browser=both` checks that consent stays with the browser that asked:
  while Edge's request waits, Chrome is told Desktop is busy; approving fills
  only Edge; Chrome, asked again, gets its own prompt. Then the same with the
  roles swapped and a denial.
- Windows decides whether the browser may take the foreground. If a step says
  Windows kept the test browser out of the foreground, click it once and
  rerun.
