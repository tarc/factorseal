# Plan: a small Windows installer (`factorseal-setup.exe`)

Status, 2026-11-16: all 12 steps done (Desktop `--quit` and `--open`, the
manifest crate, the install engine, shortcuts, registry and start,
stopping the installed version, the `wsl` step, uninstall, the release
build, the dialogs, the docs, and the rollout on the user's machine);
review folded in (see "Review record" at the end). Branch: `feature/wsl2-keyring`. It hands off to
Desktop's gnome-keyring check and move, planned in
[gnome-keyring-import.md](gnome-keyring-import.md).

## Goal

One per-user executable that installs, updates and uninstalls FactorSeal on
Windows, sets up the WSL distros that have FactorSeal installed, and ends in
Desktop's Settings → WSL keyrings. Today this is a ZIP extracted by hand,
plus manual steps:
- quitting Desktop through simulated tray clicks;
- stopping the browser host;
- creating shortcuts;
- running `factorseal wsl-setup` in the distro;
- an `UNINSTALL.txt` to remove it all.

**The installer does not change when FactorSeal does.** A new version of
FactorSeal is a folder of artifacts plus a release manifest that describes
them. The same `factorseal-setup.exe`, byte for byte, installs it: the
binary is built once and stored, not rebuilt per release (see step 8),
since MSVC builds aren't reproducible by default. The installer is closed
to modification and open to extension through the manifest and through
commands the product itself ships. An unchanged installer keeps its file
hash, so antivirus and SmartScreen reputation built up for it carries over,
and nothing about installing needs re-reviewing per release.

The installer sits beside the ZIP and the Store MSIX
(`packaging/README.md`); it does not replace either.

## Decisions (taken with the user, 2026-11-15)

1. **A Rust `factorseal-setup.exe`**, built by the existing native Windows
   pipeline: no new tools on the Windows machine, testable in our harness.
   The Installed apps entry and the uninstaller are ours.
2. **WSL: distros that already have `factorseal`** (NixOS through the
   package, later the module). For a distro without it, the installer shows
   what to add. No Linux binary in the Windows installer.
3. **The gnome-keyring check and move live in Desktop**; the installer only
   opens that page at the end.
4. **Release manifest, fixed installer.** The installer embeds no payload.
   It reads a `factorseal-release.json` that points at the release's
   artifacts (paths relative to the manifest, each with its SHA-256) and
   lists the install steps as data. Behavior that belongs to a version (how
   to quit Desktop, which page to open) is a command of that version's own
   executables, named in its manifest. WSL setup is the exception: its
   three command lines are fixed by the installer (see "The rules"), since
   they are the product CLI's stable interface. Releasing means building
   the artifacts and writing the manifest. The setup crate is rebuilt only
   when the installer itself gains a capability.

## Facts this rests on (checked 2026-11-15 on fdb0cb3, re-checked on 52e7f5b)

- **Package contents** (`build-windows.ps1`):
  - executables: `factorseal.exe`, `factorseal-desktop.exe`,
    `-parser`, `-network`, `-browser`, `-wsl-broker`;
  - the askpass helper and the Scheduled Task installer (both for the
    headless agent, not for Desktop);
  - licenses, README.
  - The user's install also needs a `factorseal.exe` built with
    `secretspec-provider` (the SecretSpec claim points at it); ZIP builds
    leave that feature out.
  - Desktop grants a distro's keyring to the WSL broker only when it runs
    from beside `factorseal.exe` (`build-windows.ps1:33`).
- **`build-windows.sh release` already exists**
  (`scripts/windows-desktop-check/build-windows.sh:74`). It builds Desktop
  and the CLI into the Windows mirror's `target`, and the
  `windows-desktop-check` skill and our notes use it.
- **The user's install today** (manual, since 2026-09-28):
  - Program files: `%LOCALAPPDATA%\Programs\FactorSeal`.
  - Shortcuts: Start menu, desktop (OneDrive-redirected), and Startup
    (`--background`, since Desktop has no autostart setting).
  - At each start, Desktop writes the four HKCU `NativeMessagingHosts` keys
    and `%APPDATA%\Factorseal\Factorseal\config`.
  - The vault is in `%LOCALAPPDATA%\Factorseal\Factorseal\data` with
    TPM-sealed keys. The installer never touches it.
- **`wsl-setup` already defaults its Windows install folder** to
  `%LOCALAPPDATA%\Programs\FactorSeal` (`cli.rs:337`, `WslSetup`), and has
  `--remove`. On Linux it exists only with `secretspec-provider`, which
  `nix/package.nix` enables.
- **Desktop is single-instance per vault root** (`instance.rs`): a second
  launch signals the first through an activation file it watches
  (`main.rs:256`, not with `--background` or `--keyring-activation`). There
  is no way to ask it to quit or to open a page. Desktops built before this
  plan:
  - reject an unknown `--quit` and exit, so the running Desktop stays;
  - treat any change of the activation file as "activate".
- **Replacing files needs every FactorSeal process stopped.**
  - The vault worker (`factorseal.exe`) runs only while unsealed and exits
    about 0.4 s after a seal.
  - The browser host keeps running after Desktop quits and locks its exe;
    the extension restarts it on demand.
  - `factorseal-wsl-broker.exe` is started from the install folder by WSL
    programs through interop (SecretSpec, the keyring relay), and they can
    relaunch it at any moment. So can native SecretSpec with the
    provider-enabled `factorseal.exe`, though only for a short time.
  - A plain `taskkill` only hides Desktop.
  - ~~Windows refuses to rename a folder while an executable inside it
    runs, the installer's own included.~~ Wrong, checked 2026-11-16 (step
    4): the folder renames while a program started from it runs, but that
    program's file can't be deleted. What stops the rename is a process
    whose working directory is in the folder (a Start menu shortcut sets
    it there) or a file open in it without delete sharing.
- **Desktop lists distros from `HKCU\…\Lxss`** without starting WSL
  (`wsl_distros.rs`). Probing a distro starts it, so the installer asks
  first. Distro names are the user's choice; `NixOS` is only a default.
- **There are no signing credentials**, so SmartScreen warns about an
  unknown publisher, as for the ZIP. With a fixed installer the warning
  concerns one unchanging file instead of a new one per release.

## The release manifest

A sketch; the schema is part of step 3 and versioned from the start.

```json
{
  "schema": 1,
  "product": "FactorSeal",
  "version": "0.1.0+fdb0cb3",
  "requires_setup": 1,
  "files": [
    { "path": "factorseal-desktop.exe", "sha256": "…" },
    { "path": "factorseal.exe", "sha256": "…" }
  ],
  "stop": { "command": ["factorseal-desktop.exe", "--quit"],
            "also_stop": ["factorseal-browser.exe", "factorseal-wsl-broker.exe"] },
  "steps": [
    { "install_files": {} },
    { "shortcut": { "name": "FactorSeal Desktop", "target": "factorseal-desktop.exe",
                    "places": ["start-menu"], "optional_places": ["startup", "desktop"],
                    "startup_args": ["--background"] } },
    { "wsl": {} },
    { "start": { "command": ["factorseal-desktop.exe", "--open", "wsl-keyrings"],
                 "quiet_command": ["factorseal-desktop.exe", "--background"] } }
  ],
  "uninstall": {
    "registry_cleanup": ["HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\dev.factorseal.browser", "…"],
    "ask_to_delete": ["%APPDATA%\\Factorseal"],
    "keep_note": "The vault stays in %LOCALAPPDATA%\\Factorseal; factorseal.exe destroy removes it."
  }
}
```

`stop` is not a step any more: it is how **this** version is stopped, and
the installer records it so the next update or the uninstall can stop this
version once it is the old one. `start` merges the former `start` and
`open` into one launch, so no two launches race for the instance lock.
`quiet_command` is used under `--no-open` or `--quiet`.

### The rules that keep the installer closed and safe

- **Step types are the installer's vocabulary**: `install_files`,
  `shortcut`, `wsl`, `start`, `registry` (values under an allowed prefix
  only), plus the `stop` and `uninstall` sections. A release combines and
  parameterises them freely. A new kind of step is the only reason to
  change the installer, and then `requires_setup` rises: an older installer
  refuses that manifest with "this release needs a newer installer"
  instead of guessing. `requires_setup` is one integer, which assumes every
  installer capability is cumulative. That holds for now; a capability
  ever removed would need a capability list instead.
- **Which version's files a command runs**, per phase:
  - **Stopping the running version** uses the stop command from
    `install.json`, which the old version's manifest recorded. Its
    executable must match the hash recorded for it, not the new manifest.
    Without a record, or without a stop command in it (the hand-made
    install, or anything built before `--quit`), the installer asks the
    user to quit FactorSeal from its tray icon, then waits for the install
    folder's processes. The tray-click simulation our scripts use is not
    taken into the installer: it relies on gpui-tray's private message
    number.
  - **After `install_files`** (`wsl`, `start`, `registry`), commands run
    the new files in the install folder, now verified copies. The
    confinement check uses the new manifest's file list.
- **Commands run only executables from verified files**, addressed relative
  to the install folder. The manifest cannot name a system program or a
  path.
- **WSL commands are the installer's own, not the manifest's.** The `wsl`
  step only says that WSL setup is part of this release. The installer runs
  fixed lines through `wsl.exe -d <distro> --exec sh -lc <line> sh <args>`
  (step 7: `--exec` hands the arguments over one by one):
  - probe: `command -v factorseal`, and `. /etc/os-release; echo $ID` for
    the hint;
  - setup: `exec factorseal wsl-setup --windows-install "$install"`, the
    install folder arriving as `$1` and translated by `wslpath -u`;
  - removal: `exec factorseal wsl-setup --remove`.

  So a tampered manifest can't run arbitrary shell code in a distro. The
  hint for a distro without `factorseal` is installer text, keyed by the
  `ID` from `/etc/os-release` (`nixos`), not by the user-chosen distro name.
  It says to add the `factorseal` package, and that `services.factorseal`
  comes after moving gnome-keyring's items (import plan, "Rollout on
  poita"). Other IDs get a generic "install FactorSeal in this distro".
- **Registry writes and deletions are confined to listed HKCU prefixes**, in
  the installer, for `registry` and `registry_cleanup` alike:
  - `Software\<vendor>\NativeMessagingHosts\dev.factorseal.browser` for
    the four vendors Desktop writes (`src/browser/registration.rs`):
    `Mozilla`, `Microsoft\Edge`, `Google\Chrome`, `Chromium`;
  - `Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal`.

  A `Run` value for autostart would join the list only when Desktop
  actually moves its autostart there.
- **`ask_to_delete` paths are confined.** They must lie under
  `%APPDATA%\Factorseal` or `%LOCALAPPDATA%\Factorseal`. Any path that
  equals or contains the vault root (`%LOCALAPPDATA%\Factorseal\Factorseal\data`)
  is refused, so "the vault is always kept" is enforced, not only promised.
- **Hashes are checked twice.** Every artifact is checked before anything
  stops or changes, so a mismatch aborts early with the old install
  untouched. Files are then hashed again **while** they are copied into
  staging, and the staged copies are verified before the swap. A file
  changed in the release folder between the two checks therefore aborts
  instead of being installed.
- **What the installer did is recorded in `install.json`** in the install
  folder:
  - the version, and the files with their hashes;
  - the shortcuts and registry values it created;
  - the distros it set up;
  - the resolved `stop` and `uninstall` sections of the manifest that
    installed it.

  Uninstall and the next update undo from that record, not from the new
  manifest, which may be newer or gone. So a release can change its steps
  without stranding what an older one created.
- **The manifest is local**: a path the user gives, or the default
  `dist\factorseal-<version>\factorseal-release.json` beside a setup run
  from the release folder. A remote source (a release page) would need a
  signed manifest and the public key in the installer; that is a later
  extension, not part of this plan.

## Flows

**Install or update.** Run `factorseal-setup.exe [--manifest PATH]`. The
installed copy in the program folder serves later updates and appears in
Start as "Update FactorSeal". Started from there, it doesn't know the new
version's location: without `--manifest` it opens a file picker for a
`factorseal-release.json`.
1. Read and verify the manifest and every artifact.
2. Read `install.json`. A folder without it but with
   `factorseal-desktop.exe` is the hand-made install, which gets adopted:
   - `UNINSTALL.txt` is dropped after the user agrees;
   - existing shortcuts in the Start menu, Startup and desktop folders
     (OneDrive-redirected included) whose target is the install folder's
     `factorseal-desktop.exe` are recorded as found. The `shortcut` step
     then replaces them, and uninstall removes them.
3. If the running setup exe lies inside the install folder, it copies
   itself to `%TEMP%` and relaunches from there with the same arguments,
   as uninstall does, with the copy's working directory outside the
   install folder. Otherwise its working directory could stop the swap,
   and its own file would keep the old folder from being removed.
4. Stop the running version (see "Which version's files a command runs"),
   then wait for every process whose image is in the install folder,
   `also_stop` included. The browser host is stopped only after the
   installer has said that a waiting browser fill will be cancelled.
5. Run the manifest's steps in order:
   - `install_files` stages into a new folder and swaps it in, renaming the
     old folder aside and restoring it on any failure. The setup exe copies
     itself into the **staging** folder when its version is newer than the
     installed copy, and carries the installed copy over otherwise, so it
     isn't lost with the old folder.
   - `wsl`: the distro page (below), then setup in the chosen distros.
   - `start`: one launch of the new Desktop, on the WSL keyrings page. With
     the vault sealed (it always is after a stop), Desktop shows the unlock
     first and then the page.
6. Register in Installed apps
   (`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal`,
   the version from the manifest, and `UninstallString` pointing at the
   installed setup with `--uninstall`).

A WSL program or SecretSpec can relaunch the broker or the CLI between the
stop and the swap. The swap then fails and rolls back, leaving the old
install intact, and the installer says which process held the folder.

**Uninstall.**
1. Relaunch from a temporary copy, so the setup exe can delete itself.
2. The first page lists what will be removed. That includes the recorded
   distros, with the warning that removal starts them; the user can untick
   them. Under `--quiet`, `--wsl` or `--no-wsl` is required.
3. The recorded stop command, or the ask-to-quit fallback.
4. The recorded `wsl` removals, in the distros the user kept.
5. Delete the recorded shortcuts and registry values, the recorded
   `registry_cleanup` keys (confined as above), the Installed apps key and
   the folder.
6. Ask before deleting the recorded `ask_to_delete` paths (confined as
   above).
7. Show the recorded `keep_note`. **The vault is always kept.**

**UI**: Win32 task dialogs (`TaskDialogIndirect`): native, accessible
through UI Automation, small. Four pages:
1. Install or update: current and new version, and the optional places;
2. Progress;
3. WSL distros (ask before probing; the hint for those without FactorSeal);
4. Done.

`--quiet` with explicit options (`--install-dir`, `--wsl`/`--no-wsl`,
`--no-start`, `--no-open`) is for our harness and scripts. Task dialogs
can't run headless, so `--quiet` reports through its exit code (0 success,
non-zero per failure class) and a log file (`--log PATH`, default
`%TEMP%\factorseal-setup.log`). The texts come from the installer, never
the manifest, apart from version strings.

## Steps

Each step is its own commit, with tests seen failing first or a mutation,
plus `build-windows.sh check` (Windows clippy and tests) and the Linux gate
where shared code changes. UI stays uncommitted until the user has seen it
in the native build.

1. **Desktop `--quit`**: a second launch with `--quit` asks the running
   Desktop of that root, through the instance channel, to seal and exit; it
   returns once it has, or fails after a timeout. The request is a new,
   distinct message, so an older Desktop that receives it only activates;
   the installer's timeout and fallback cover that case. Unit test on the
   instance channel. Live: the test Desktop unlocked, `--quit`, no
   FactorSeal process left. This also replaces the tray-click dance in our
   scripts (`drive.ps1`, the install notes) for Desktops that have it.
2. **Desktop `--open <page>`**: the same channel brings Desktop forward on a
   page (`wsl-keyrings` first). When the launch becomes the primary
   instance itself (nothing running), it starts on that page. A sealed
   vault shows the unlock first and then the page. It changes navigation,
   so the user sees it natively.

   As implemented (2026-11-16, steps 1 and 2 in one commit, since both
   are requests on the same channel):
   - **The channel** (`factorseal-desktop/src/instance.rs`): the
     activation file now carries one line, `open`, `open <page>` or
     `quit`; every Desktop so far writes `open`, and builds before this
     one treat any write as `open`. A line this build doesn't know opens
     Desktop (forward compatible), and a line left without its newline
     for five polls (a writer that died) counts as `open`, so it can't
     block later requests.
   - **`--quit`** sends `quit` and waits until the instance lock is free,
     which happens when the running Desktop's process exits, at most
     30 s; exit 0 then, and also when nothing ran ("no Desktop is
     running on this vault"), exit 1 on the timeout. The running Desktop
     runs the tray's Quit (seal, close the tray, quit). It conflicts with
     `--background`, `--no-tray`, `--keyring-activation` and `--open`,
     and starts nothing.
   - **`--open wsl-keyrings`** (a clap value enum, so an unknown page is
     a usage error) goes with the visible launch's request; a launch that
     becomes the primary opens the page itself. Sealed, Desktop leaves a
     sealed Settings page for the unlock and keeps the page pending until
     the vault is unsealed.
   - Tests: the request lines round-trip, unknown and incomplete lines
     open, a page request arrives, `--quit` waits for the lock and times
     out against a Desktop that stays (mutation: returning right after
     the request fails it), the argument conflicts. Desktop 219 passed,
     1 ignored on Linux, 205 natively; clippy on both.
   - Live (test vault, native build): `--quit` on an unlocked Desktop
     returned 0 after 268 ms with Desktop and its worker gone; `--open`
     from nothing running (unlock, then the page), on a running unlocked
     Desktop, on a sealed one on the vault page, and on one sealed while
     Settings was open, each checked through UI Automation; then the
     user watched unlock, `--open` and `--quit` (window and tray icon
     gone).
   - `check.sh` stops the test Desktop with `--quit`, falling back to a
     seal and `taskkill` for a Desktop built before it.
3. **Manifest schema and verification** (new crate
   `packaging/windows/setup`; the parsing and checks are plain Rust, tested
   on Linux too):
   - the schema with `requires_setup`, and refusal of unknown step types;
   - paths confined to the release folder (no `..`, no absolute paths,
     no links out);
   - commands confined to verified release files;
   - registry values and `registry_cleanup` keys confined to the listed
     HKCU prefixes;
   - `ask_to_delete` confined, and the vault root refused;
   - every hash checked before any change.

   Tests cover each refusal. One test pins that a manifest written for
   schema 1 with a new version and new files installs with an unchanged
   installer.

   As implemented (2026-11-16; `packaging/windows/setup`, crate
   `factorseal-setup`, a workspace member, so CI's clippy and tests run
   it on Linux, macOS and Windows):
   - `Manifest::parse` reads `requires_setup` (and `schema`) from the raw
     JSON first, so a release for a newer installer is refused as "needs
     a newer installer" even when it holds fields and steps this one
     doesn't know; then a strict parse (`deny_unknown_fields` everywhere,
     step types as an externally tagged enum, so an unknown step is
     "unknown variant").
   - The rules without a file system: product, a plain version (shown to
     the user), relative `/`-separated file paths (no `..`, `.`, empty or
     absolute parts, no `\`, no characters or device names Windows paths
     can't hold, no trailing dot or space, which Windows drops), no path
     listed twice ignoring case, lowercase hex hashes, `install_files`
     first and once, `start` at most once and last, `wsl` at most once,
     commands (`stop`, `start`, `quiet_command`), `also_stop` and shortcut
     targets only listed `.exe` files, shortcut names without path
     characters and places once, registry keys and `registry_cleanup`
     compared by `\` segments ignoring case against the five prefixes (so
     `dev.factorseal.browser.evil` and `..` are out), `ask_to_delete` under
     `%APPDATA%\Factorseal` or `%LOCALAPPDATA%\Factorseal` and not the
     vault root, an ancestor of it or a path inside it, no other `%`.
   - `Release::open` canonicalizes the release folder (a linked release
     folder is fine), then for each file refuses a link anywhere on its
     path (`symlink_metadata` per part), a missing file or a folder, a
     canonical path outside the folder, and a hash mismatch; every file is
     hashed before it returns. `sha256_hex` is shared for step 4's hashing
     while staging.
   - Tests: 16 on Linux (the two link tests are Unix-only); natively 15,
     with a Windows-only one where a junction (no privilege needed) for a
     release folder is refused. Mutations, each failing its own test:
     dropping the vault-ancestor check, matching registry keys as string
     prefixes, skipping the link check, checking `requires_setup` after the
     strict parse, skipping the hash comparison. The first native run
     found that Windows refuses to open a folder as a file ("access
     denied"), so the file type now comes from the walk's metadata before
     opening. `build-windows.sh check` now runs the crate's clippy and
     tests natively.
4. **Install engine**: `install_files` with hashing while staging, staged
   verification, swap and rollback. Also the relaunch from `%TEMP%`, the
   self-copy into staging, adopting a hand-made install (shortcuts
   included), and `install.json` as the full record undo works from. Native
   tests in temporary folders:
   - a failed copy rolls back;
   - a locked file stops the update cleanly;
   - an artifact changed between verify and copy aborts;
   - an update whose new manifest drops a shortcut still removes the old
     one;
   - an update run from inside the install folder succeeds through the
     relaunch.

   As implemented (2026-11-16; `packaging/windows/setup/src/engine.rs`,
   `record.rs`, and a `--quiet` front end in `main.rs` so the relaunch
   can be tested; the dialogs are step 10):
   - **Staging and swap**: files are copied into `<install folder>.new`,
     hashed while copied (an early abort) and read back (the check the
     tests pin: removing only the copy-time one leaves the test green,
     removing both fails it). The swap renames the install folder to
     `.old` and the staging folder into place; a failed rename puts the
     old folder back. [`Pending`] holds the swap for later steps:
     `commit` removes the old folder and the old record's shortcuts this
     install didn't make again, then writes `install.json`; `rollback`
     restores the old folder and touches no shortcut.
   - **What Windows allows** (probed with PowerShell before changing the
     code): see the corrected fact above. So a running FactorSeal doesn't
     stop the swap; it keeps the old folder, which `commit` then moves to
     `<install folder>.old-<pid>-<time>` for a later run to remove, so it
     never blocks the next update. Renames and removals retry for five
     seconds (a process that just exited, an antivirus scan). The
     installer moves its own working directory, and the relaunched
     copy's, to the temporary folder.
   - **Recovery**: a run first restores `.old` when the install folder is
     missing (stopped between the renames), removes it otherwise (or moves
     it aside if in use), removes `.new`, and removes moved-aside folders
     no longer in use.
   - **The record** (`install.json`, format 1): version, installer
     version, files with hashes, shortcuts, registry values, distros, and
     the manifest's `stop` and `uninstall`. Shortcuts stay recorded until
     the commit removes them, so a crash before it leaves them for the
     next run. An unreadable record is an error, never a fresh install.
     The manifest may not list `factorseal-setup.exe` or `install.json`.
   - **Self-copy**: the running installer goes into staging unless the
     record's installer version is the same or newer and its copy is
     there, which is then carried over.
   - **Adoption**: a folder with `factorseal-desktop.exe` and no record
     needs consent (`--adopt` under `--quiet`, exit 6 without). Its
     shortcuts under the Start menu (Startup included) and the Desktop
     (`directories`, so OneDrive's redirect too) are found by the target
     path inside the `.lnk` bytes (UTF-16LE at either alignment, or
     ASCII), recorded, and removed at the commit unless made again;
     `UNINSTALL.txt` goes with the old folder.
   - **`--quiet`**: `--manifest`, `--install-dir`, `--adopt`, `--log`;
     exit 0 installed, 2 usage, 3 refused, 4 needs a newer installer, 5
     failed (previous install kept), 6 needs `--adopt`. Run from inside
     the install folder (Windows), it copies itself to the temporary
     folder as `factorseal-setup-<pid>.exe`, starts it there with
     `--relaunched`, and exits 0; the log has the result. Later runs
     delete such copies no longer running.
   - Tests: 30 unit tests on each platform (the engine's 13 include two
     Windows-only and one Unix-only), 3 runs of the binary (one
     Windows-only, the relaunch).
     Natively: a working directory inside the folder stops the update
     with nothing changed; a program running from it lets the update
     through and the old folder is moved aside, then removed by the next
     run; the installed copy run with the install folder as its working
     directory finishes through the relaunch with nothing left beside the
     install folder. Mutations caught: keeping old shortcuts, not
     restoring after a failed swap, not restoring in recovery, always
     copying the running installer, adopting without consent, both hash
     checks removed (Linux); keeping the working directory, no relaunch
     (natively). Not in step 4: naming the process that holds the folder
     (step 6 waits for the folder's processes first).
5. **Steps `shortcut`, `registry`, `start`**: the registry root is
   configurable so tests write under a test key, never the real Uninstall
   key. Native tests.

   As implemented (2026-11-16; `steps.rs`, `shortcut.rs`, `registry.rs`):
   - **Shortcuts are written directly** in the `.lnk` format
     (MS-SHLLINK), so the installer needs no COM, no unsafe code and no
     PowerShell (which antivirus watches in installers). A link carries an
     item ID list in the simple form the shell makes ("This PC", the
     drive, then each folder and the file named in UTF-16), LinkInfo with
     the path in ANSI and UTF-16, and the description, working directory,
     arguments (quoted as the C runtime splits them) and icon. Checked
     natively with a probe link written from Linux: LinkInfo alone opens,
     but WScript.Shell and Shell.Application read an empty target (as
     Explorer's Properties would); with the ID list both read it, also
     for a folder with non-ASCII characters. An environment-variable block
     tried in between didn't help and was dropped. Targets longer than
     `MAX_PATH` are refused.
   - **Working directory**: shortcuts and the launch work in the user's
     profile, never the install folder, since a process working there
     stops the next update's swap (step 4).
   - **Places**: the manifest's `places` always; an optional place when
     chosen (`--optional-place` under `--quiet`) or when the previous
     install had the shortcut there. The Startup shortcut gets
     `startup_args`. Shortcuts are recorded in `Pending`, kept at the
     commit, and a rollback removes the ones it added.
   - **Registry** through `windows-registry` (already in the lock file,
     Microsoft's safe API) behind a `Registry` trait, with a `Root` that
     maps `HKCU\…` under a test key; an in-memory registry for tests
     elsewhere. Values the `registry` step writes are recorded; the
     commit removes old ones the release no longer writes, a rollback
     the ones it added.
   - **Installed apps** (Flows, step 6) after the commit: DisplayName,
     DisplayVersion, Publisher, InstallLocation, UninstallString (the
     installed setup with `--uninstall`, step 8), DisplayIcon, NoModify,
     NoRepair, EstimatedSize. From the commit on, a failure there or in
     the launch only warns.
   - **`start`** last, after the commit: `quiet_command` under `--quiet`
     (or `command` when there is none), nothing under `--no-start`; not
     waited for.
   - `--quiet` gains `--optional-place` and `--no-start`, and hidden test
     options `--registry-root`, `--shortcut-root` and `--working-dir`;
     the binary's tests pass all three, so they never touch the user's
     shortcuts or keys (removed afterwards).
   - Tests: 43 unit tests (6 for the steps, 5 for shortcuts); natively, a
     quiet install whose Desktop is `cmd.exe`: the quiet launch ran in
     the working folder, the registry values and Installed apps entry are
     under the test key only, WScript.Shell reads the shortcuts' target,
     arguments and working directory, and opening the Startup one through
     ShellExecute runs it with its arguments. Mutations caught: ignoring
     the previous install's places, Startup arguments on every shortcut,
     the commit keeping old values, a rollback keeping new values or
     shortcuts; natively, the missing ID list (the target assertion
     failed before it was added).
6. **Stopping**: the recorded command checked against its recorded hash,
   the process wait scoped to the install folder, `also_stop`, and the
   ask-to-quit fallback (no record, or no stop command). Live on a test
   install with the test vault: a stop through `--quit`, and one through
   the fallback with a Desktop built before step 1.

   As implemented (2026-11-16; `stop.rs`, wired into `--quiet` before
   `install_files`):
   - **The plan** (`StopPlan`): the record's stop command, used only when
     its executable is a recorded file (a plain release path, `.exe`)
     whose installed copy still matches the recorded hash; otherwise the
     reason is shown and the user is asked. A hand-made install and a
     record without `stop` take the fallback. `also_stop` joins the
     record's (checked like manifest paths, since the record sits in the
     user's folder) and the new release's, so a hand-made install still
     gets its browser host and broker stopped.
   - **Who holds the folder**: through `sysinfo` (already in the lock
     file; safe API, only its `system` feature), every process running an
     executable from the folder, or working in it (its current
     directory, which stops the swap), other than the installer itself and
     `factorseal-setup.exe` (the copy that relaunched this one, exiting).
     A process whose path can't be read (elevated) counts when its name is
     one of the folder's executables.
   - **The order**: `also_stop` processes are terminated whenever they
     show up, the browser host after the line that a waiting browser fill
     is cancelled; when only they run, nothing else happens. Otherwise
     the stop command runs (working in the profile, 45 s at most), then
     the folder's processes get 15 s to exit. Without a command, after a
     failed one, or when processes remain, the user is asked to quit
     FactorSeal from its tray icon (and to close programs working in the
     folder), naming each process, and the installer waits
     (`--wait-for-quit`, 300 s by default). What is left then is named,
     nothing changes, exit 7. Desktop and the vault worker are never
     terminated. Processes that refused termination alone are not a
     reason to ask.
   - A hand-made install without `--adopt` is refused before anything is
     stopped.
   - Tests: 11 unit tests (9 with fake processes and runner, one with real
     processes: a copy of a shell, or of ping on Windows, running from the
     folder and one working in it; one of the command runner's exit codes
     and timeout), and a binary test: an update waits in vain for the CLI
     running from the folder (exit 7, nothing changed, the process named)
     and then terminates the browser host and installs. 54 unit tests and
     4 binary tests on both platforms. Mutations caught: skipping the hash
     check, `also_stop` never matching a path, an unreadable process never
     terminated, ignoring working directories, never asking, ignoring the
     release's `also_stop`, `--quiet` not stopping at all.
   - Live, natively, on the test vault (every run `--no-start`, test
     registry root and shortcut folders; the test releases ship no browser
     host, so the test Desktop doesn't re-register the user's): a release
     whose stop command is `factorseal-desktop.exe --root <test vault>
     --quit` installed, its Desktop started and unlocked, then the update
     to a second release stopped it through the recorded command and
     installed, 2.8 s in all, nothing left running. Then a hand-made
     folder with the user's installed Desktop (14 Nov, before `--quit`)
     running on the test vault: `--adopt` said it can't stop a hand-made
     install and asked, naming the process; the tray's Quit was clicked
     (simulated) and the update finished 4.3 s later. The user's own
     Desktop and browser host ran on throughout. Not tried live: an
     elevated Desktop (the path-hidden case), covered by a unit test only.
   - Since the recorded command runs as written, it targets the default
     vault unless it names one; a release's `stop` stays
     `factorseal-desktop.exe --quit`.
7. **Step `wsl`** behind a command runner trait: the fixed probe, setup and
   removal lines, the `/etc/os-release` hint, consent. Tests with a fake
   runner. The real run is on the user's NixOS during rollout, with
   consent.

   As implemented (2026-11-16; `wsl.rs`, wired into `--quiet`):
   - **The lines** (`Line`): one probe run per distro prints whether
     `factorseal` is on the login `PATH` and the os-release `ID`; setup is
     `install=$(wslpath -u "$1") || exit 1; exec factorseal wsl-setup
     --windows-install "$install"`; removal (for step 8) `exec factorseal
     wsl-setup --remove`. The install folder is always passed: `wsl-setup`
     otherwise assumes `%LOCALAPPDATA%\Programs\FactorSeal`, wrong for
     `--install-dir` elsewhere. Each runs as `wsl.exe -d <distro> --exec
     sh -lc <line> sh <args>` from the profile folder, `WSL_UTF8=1`,
     120 s at most (killed after). The plan's `wsl.exe -- …` would join
     the arguments into one line for the user's own shell; `--exec` hands
     them over one by one, so the folder is never shell code. Distro
     names are checked as the vault's protocol checks them.
   - **Per distro**: the probe; without `factorseal`, the hint by `ID`
     (`nixos`: add the package, rebuild, run the installer again, and turn
     on `services.factorseal` only after moving gnome-keyring's items;
     others: install FactorSeal in it), nothing else runs there; with it,
     setup, whose output goes to the log. A failure in one distro is
     reported and the others still run.
   - **When**: after the commit and the Installed apps entry, before
     `start` (which opens the WSL keyrings page). The distros set up are
     added to `install.json` (once, ignoring case); the ones the record
     already lists stay, so an update with `--no-wsl` keeps them for
     uninstall. A distro not set up only warns: the install is kept, the
     result line says how many distros weren't set up, exit 8.
   - **Consent under `--quiet`**: `--wsl DISTRO` (repeatable) or
     `--no-wsl`; a release with the `wsl` step refuses `--quiet` without
     one, before anything is stopped (exit 2). Both are passed on to the
     relaunched copy, and so is the hidden `--wsl-program` (a stand-in
     for `wsl.exe`, for tests).
   - **Left for step 10**: listing the distros (Desktop reads
     `HKCU\…\Lxss`) belongs to the distro page; under `--quiet` the names
     come from the command line, and an unknown one fails at its probe
     with `wsl.exe`'s own message.
   - Tests: 10 unit tests (3 with a fake WSL: probe then setup with the
     folder as argument, the hint by `ID` and not by distro name, one
     failing distro among others; on Unix 4 with the lines run by a real
     `sh` through a stand-in `wsl.exe`, the folder with spaces, quotes and
     `$(…)` reaching `wslpath` untouched, a hang killed at the timeout;
     names, probe parsing, UTF-16 output), one for the record, and two
     binary tests: the `--wsl`/`--no-wsl` rule, and (Unix) an install with
     two distros through the stand-in, one without `factorseal`: exit 8,
     only the other recorded, then an update recording it once. The
     Windows relaunch test now carries a `wsl` step and `--no-wsl`, and
     stops waiting on a refusal. 65 unit tests and 5 binary tests on
     Linux; natively 61 (the Unix-only ones don't build there) and 6.
     Mutations caught (12 on Linux): the folder unquoted in the setup
     line, the probe's answer ignored, the hint ignoring `ID`, the folder
     not passed, stopping at the first failing distro, no timeout, names
     unchecked, distros not recorded or recorded twice, exit 8 never
     given, no choice required, the step never running; natively, the
     relaunch dropping `--no-wsl`.
   - **The tests' race**: a test thread writing an executable while
     another forks lets the child hold the file open for writing, and
     running it then fails with `ETXTBSY` ("Text file busy"); with the
     shell tests added, step 6's process test hit it about once in ten
     runs. Tests that write an executable or start a process now hold one
     lock (`exec_lock`); 20 runs in a row passed.
   - Live, natively, read-only (an ignored test,
     `FACTORSEAL_SETUP_WSL_DISTRO=NixOS`): the probe in the user's NixOS
     found `factorseal` and `id=nixos` through `sh -lc`; a folder
     `C:\Users\Jo Ann\O'Neil & Co\100%\$(x)\FactorSeal` reached `sh`
     as one `$1` and `wslpath` turned it into the `/mnt/c/…` path; an
     unknown distro made `wsl.exe` exit non-zero with its message, in
     UTF-8, on stdout (the log takes stdout when stderr is empty).
     `wsl-setup` itself was not run: NixOS has `factorseal`, so it would
     have rewritten the user's `wsl.json`; that run is the rollout's.
8. **Uninstall**: everything recorded is undone; self-deletion; the distro
   consent; the confinement of `registry_cleanup` and `ask_to_delete`; the
   vault untouched. Native tests under the test registry root and a
   temporary folder (with a fake WSL runner).

   As implemented (2026-11-16; `uninstall.rs`, `--quiet --uninstall`):
   - **Order**: the install is stopped the way its record says
     (`StopPlan::for_uninstall`: the recorded command, checked against its
     hash, and only the recorded `also_stop`; exit 7 and nothing changed
     when something keeps running); the setup is removed from the chosen
     recorded distros (`wsl::remove`, the fixed removal line); then the
     release's files. A file that can't be removed stops there, with the
     record, the shortcuts, the registry and the Installed apps entry
     untouched, so running the uninstall again finishes it (exit 5).
     Then the shortcuts, the recorded registry values, the
     `registry_cleanup` keys, the Installed apps key, the installed setup
     and `install.json`, the release's empty folders, and the install
     folder only when nothing the installer didn't put there is left in it
     (else it is kept and what it holds is named). Then the
     `ask_to_delete` folders, only with consent, and the `keep_note`.
   - **The record is checked as a manifest**: it sits in the user's
     folder, so each entry is checked before anything is deleted, and one
     outside the rules is left and named: release paths
     (`check_release_path`), shortcuts (`.lnk` files below the Start menu
     or desktop folder, no `..`, compared ignoring case), registry keys
     (the allowed prefixes, also for the recorded values), `ask_to_delete`
     (FactorSeal's folders, never the vault, expanded from `%APPDATA%` or
     `%LOCALAPPDATA%`), and `keep_note` (500 characters). The same
     shortcut check now applies to updates, which removed whatever path the
     record listed as a shortcut; a path outside the folders is neither
     removed nor kept in the record.
   - **Consent under `--quiet`**: `--wsl DISTRO` (each a recorded distro)
     or `--no-wsl`, required when the record lists distros; a distro not
     chosen is named with the command that undoes its setup.
     `--also-delete` deletes the `ask_to_delete` folders; without it they
     are named and kept. No record: exit 9 (a hand-made install is told to
     follow its `UNINSTALL.txt`). Exit 8 when only a distro's removal
     failed. The hidden `--appdata-root` maps the two folder variables for
     tests.
   - **Self-deletion**: run from the install folder (as Installed apps
     runs `--uninstall`), the installer continues from a copy in the
     temporary folder (step 4's relaunch, now passing `--uninstall`,
     `--also-delete` and the WSL choice), which removes the folder with
     the installed copy in it. The copy then hands its own deletion to
     `%SystemRoot%\System32\cmd.exe` (`ping -n 3 127.0.0.1 >nul & del
     /f /q "<copy>"`, no window), unless its path holds `"` or `%`, which
     `cmd.exe` would read as more than a path; that copy is left for the
     next run's cleanup of old copies. Until step 10, the Installed apps
     entry's `--uninstall` without `--quiet` only says that the dialogs
     aren't built yet.
   - Tests: 6 unit tests for the uninstall (with a fake WSL: everything
     recorded removed and the vault kept; folders and distros kept without
     consent; a tampered record's entries all left; a failed distro
     removal reported with the command to run; a file that can't be
     removed, through a read-only folder on Unix or a handle without
     delete sharing on Windows, stopping before anything else; the folder
     variables), the uninstall stop plan, 2 for the shortcut check (one an
     update with a tampered record). Binary: install then uninstall with a
     shortcut, a registry value, `registry_cleanup`, `ask_to_delete` and
     `keep_note`, first refused with exit 7 while the CLI runs from the
     folder, then done, the vault kept, the test registry values gone
     (checked on Windows), a second uninstall exit 9; (Unix) the distro
     choice through the WSL stand-in; (Windows) the uninstall run from the
     install folder, whose relaunched copy is gone afterwards. 74 unit and
     7 binary tests on Linux; natively 70 (+1 ignored) and 8. The steps
     tests' fixture listed no shortcut folders, unlike the installer; it
     now lists the Start menu and desktop. Mutations caught (17 on Linux):
     each of the five checks of the record skipped, the listed folders
     deleted without consent, a file that can't be removed ignored, a
     folder with unknown files removed, unchosen distros removed, the note
     unchecked, the removal running the wrong line, an update removing an
     unchecked shortcut, `..` accepted in a shortcut path, the distro
     choice not required, an unrecorded distro accepted, the uninstall
     not stopping, the uninstall plan ignoring the record; natively, the
     copy not deleting itself.
   - Live, natively, on the test vault (test registry, shortcut and
     AppData roots): a release whose stop command is
     `factorseal-desktop.exe --root <test vault> --quit` installed with a
     Start menu shortcut, its Desktop started; the installed
     `factorseal-setup.exe --uninstall --also-delete`, run from inside the
     install folder, continued from a copy in the test temporary folder,
     stopped Desktop through the recorded command, removed the folder, the
     shortcut, the registry values and the settings folder, kept the test
     vault, showed the note, and its copy was gone 5.4 s after the start.
     The user's own Desktop and browser host ran on throughout.
9. **The build writes the release**: a new mode, `build-windows.sh dist`,
   leaving `release` as it is for its current callers.
   - It puts the artifacts and `factorseal-release.json` in
     `dist\factorseal-<version>\`. Its `factorseal.exe` is built with
     `secretspec-provider`. The ZIP (`build-windows.ps1`) stays without the
     feature, as upstream ships it, so the two packages differ in that
     feature only, and `packaging/README.md` says so.
   - It checks that its Desktop was built without the import plan's
     `wsl-test-hooks` feature.
   - The installer binary is built by `build-windows.sh setup` only when the
     setup crate changes. It is stored in the Windows mirror as
     `dist\setup\factorseal-setup-<setup version>.exe`, with its SHA-256 in
     `dist\setup\SHA256SUMS`, and recorded in the footprint ledger. `dist`
     copies the stored binary into the release folder and never rebuilds
     it.
   - The check asserts that copying, not reproducibility: two `dist` runs
     give an installer equal to the stored file. Making MSVC builds
     reproducible (`/Brepro`, path remapping) is not attempted.

   As implemented (2026-11-16; `packaging/build-windows-release.ps1`, the
   `setup` and `dist` modes of `build-windows.sh`):
   - **`setup`** builds `factorseal-setup` natively and stores it in the
     Windows copy as `dist\setup\factorseal-setup-<version>.exe`, its
     SHA-256 appended to `dist\setup\SHA256SUMS` (`sha256sum` format). A
     stored version is refused unless `--replace` says otherwise: an
     installer changes only with its version. The mirror's robocopy
     `/MIR` would have deleted the copy's `dist\` on every run, since the
     repository has none; it is now excluded like `target`.
   - **`dist`** needs a stored installer for the setup crate's version. The
     release version is the workspace's plus `+g<10-digit commit>`, and
     `.dirty` (with a warning) when tracked files have uncommitted changes;
     the Windows copy has no `.git`, so the WSL side passes it in. The
     PowerShell script (a sibling of the ZIP's `build-windows.ps1`) checks
     the stored installer against `SHA256SUMS`, builds the CLI with the
     features of `build-windows.sh` (the SecretSpec provider included),
     Desktop without features and the WSL broker natively (as the ZIP
     does, not `--broker`'s cross-compile), refuses a Desktop whose
     executable holds `FACTORSEAL_TEST_KEYRING_EXPORTER` (the
     `wsl-test-hooks` feature's only trace), writes
     `dist\factorseal-<version>\` afresh with the six executables, the
     three licenses and `README.md`, copies the stored installer as
     `factorseal-setup.exe` and checks the copy, and writes the manifest:
     the sketch above, with `stop` `factorseal-desktop.exe --quit` and
     `also_stop` the browser host and broker; a Start menu shortcut,
     optional Startup (`--background`) and desktop ones; `wsl`; `start`
     on the WSL keyrings page, quietly in the tray; `registry_cleanup` the
     four browsers' native-messaging keys Desktop registers;
     `ask_to_delete` `%APPDATA%\Factorseal` (Desktop's preferences and
     native-messaging manifests; the vault is in `%LOCALAPPDATA%`); and a
     `keep_note` saying where the vault stays and how to destroy it. The
     JSON is written without a byte order mark, which PowerShell 5.1's
     `UTF8` encoding adds and serde refuses.
   - Then the WSL side checks that the release's installer is the stored
     file, and runs that installer on its release: installed into
     `target\dist-check` under a test registry key with test shortcut and
     AppData folders (`--no-start --no-wsl`), then uninstalled by the
     installed copy; both must succeed and the folder must be gone.
   - Under PowerShell 5.1 with `2>&1` (as `build-windows.sh` runs
     commands) and `$ErrorActionPreference = 'Stop'`, cargo's progress on
     standard error became a terminating error on the first build; the
     script runs cargo with errors continuing, its lines passed on as
     text, judged by the exit code.
   - `packaging/README.md` names the release builder and the provider
     difference from the ZIP; the check scripts' README the two modes.
   - Checked natively: `setup` stored `factorseal-setup-0.1.0.exe`
     (`b1cfad07…`) and refused a second run; `dist` from the uncommitted
     tree wrote `factorseal-0.1.0+gb0e7825b7f.dirty`, and after the commit
     `factorseal-0.1.0+ge1e565ca6a`; both installed (12 files) and
     uninstalled in the test folder, and both installers are the stored
     file byte for byte. The release's `factorseal.exe provider --help`
     works. The script's own test-hooks check, run on its own, refused
     Desktop's test build made with `--test-hooks` and accepted the
     release Desktop. `shellcheck` is clean.
10. **Task dialog UI**: the four pages and the uninstall page. Then the
    user tries it natively (install into a test folder, update to a second
    build with the same installer, uninstall) before it is committed.

    As implemented (2026-11-16; `src/dialog.rs`, `src/ui.rs`, `src/gui.rs`
    in the binary, `build.rs` and `windows/`):
    - **Pages as data** (`ui.rs`, tested on Linux): install or update
      (heading by what is installed: install, update from version X,
      reinstall, or taking over a hand-made install with what adoption
      does; the optional shortcut places as toggles, except places the
      installed version has, which are kept anyway and named), the WSL
      distros (from `HKCU\…\Lxss`, listed by the new
      `wsl::registered_distros`, step 7's leftover; those the record lists
      on), progress, and done (by exit code: installed, installed but not
      in every distro, not installed with the result line, and "Open
      FactorSeal now", on); uninstall (what goes, the release's
      `keep_note`, the recorded distros on, "Also delete FactorSeal's
      settings" off with the folders as a note line, from the new
      `uninstall::listed_folders`), progress, done (uninstalled with the
      note, left in a distro, partly, or not). The details under "Show
      details" are the run's log.
    - **Every choice comes first**, the WSL distros included, then one
      progress page: the plan's order (install, then the distro page) would
      have stopped the work midway for a question. The choices become the
      `--quiet` options (`optional_places`, `wsl`/`no_wsl`, `adopt` for a
      hand-made install, `also_delete`, `no_start`) and the same
      `install`/`uninstall` run on a worker thread; the log hands its lines
      to the progress page, which polls on the dialog's timer. The launch
      happens after the last page, when its toggle is on.
    - **The dialog** (`dialog.rs`, the binary's one module allowed unsafe
      code; `windows-sys` 0.61, already in the lock file): one window for
      all pages, moving with `TDM_NAVIGATE_PAGE`. A toggle is a command link
      without the arrow, `☐`/`☑` before its label, which flips and shows
      the page again with the focus on it (a task dialog has one check box
      only); the details' state survives that. Common buttons OK/Cancel
      and Close, in Windows' language; Cancel is disabled while working.
      300 dialog units wide, so install paths fit. `TaskDialogIndirect` is
      looked up at run time in Common Controls 6: imported, it would keep
      the test executables (no manifest) from starting.
    - **Manifest and icon** (`windows/factorseal-setup.rc`, embedded by
      `build.rs` with `embed-resource`, already in the lock file):
      Common Controls 6, `asInvoker` (a program named setup is otherwise
      guessed to want administrator rights), per-monitor DPI awareness, and
      FactorSeal's icon.
    - **A Windows program**: no console window opens beside the dialogs.
      `--quiet` still reports through its exit code and log; PowerShell
      waits for it only through `Start-Process -Wait -PassThru`, which the
      help now says. Command-line errors and `--help` show in a dialog
      unless `--quiet` was given.
    - Without `--manifest`, the dialogs install the
      `factorseal-release.json` beside the installer; none there gets a
      page saying where to run it from (exit 2). The relaunch from the
      install folder (Installed apps' `--uninstall`) passes `--quiet` only
      when given, so the copy shows the dialogs. A dialog closed before
      the work starts exits 10 (logged "result: cancelled").
    - The quiet binary tests now hold an exec lock too: a test copying an
      executable while another forked hit `ETXTBSY` (step 7's finding),
      seen once in the first run with the dialogs.
    - Tests: 5 for the pages (places kept or offered, the first page's
      headings, the WSL page's defaults, the done page by exit code, the
      uninstall pages), 1 for `listed_folders`; 75 unit, 5 bin and 7
      binary tests on Linux, 15 runs in a row; natively 71 (+1 ignored),
      5, 7 and 1. Mutations caught: kept places offered again, recorded
      distros off, the result prefix kept, exit 8 shown as plain success,
      the settings deleted by default, a partial uninstall called a
      failure.
    - Driven natively through UI Automation (`TDM_CLICK_BUTTON` for the
      common buttons, which .NET's client sees as panes without an invoke
      pattern) and screenshots, in a test folder with the test roots:
      install with the desktop shortcut, update to a second release with
      the same installer (the desktop shortcut kept, Startup added),
      uninstall with the settings deleted, and the installed copy's
      `--uninstall` run from its folder, whose relaunched copy showed the
      dialogs and deleted itself; Cancel, the missing release and a
      command-line error. Then the user did install, update and uninstall
      in a trial folder and approved; the uninstall's details no longer
      repeat the note shown above them.
11. **Docs**:
    - `packaging/README.md`: the installer beside the ZIP and MSIX, the
      manifest, the provider feature difference, SmartScreen.
    - `usage.md`: Windows install and update.
    - The WSL keyring section points at the installer.
    - A short "Releasing" note: `build-windows.sh dist`, the stored
      installer, run the installed setup.

    As implemented (2026-11-16):
    - `packaging/README.md`, "Windows installer": what the installer and a
      release are, that the folder is distributed whole, the SmartScreen
      steps for the unsigned files (one unchanging installer), "Building a
      release for the installer" (`setup` only when the installer changed,
      after raising its version; `dist` from a clean commit, what it
      writes and checks), and "Unattended use" (`--quiet`, the log, the WSL
      choice, `--uninstall`, and `Start-Process -Wait -PassThru` with
      quoted absolute paths). The provider difference from the ZIP was
      written in step 9.
    - `docs/usage.md`, "Installing on Windows": the pages in order, the
      stop or ask-to-quit, updates (run the new release's installer), and
      uninstall from Installed apps with the vault always kept. Both WSL
      sections say the installer's WSL page runs `wsl-setup`. The README's
      Desktop quick start links there.
    - Checking the unattended example natively (with test options, in a
      folder with spaces) found that `--log` in a folder that doesn't exist
      yet lost the log silently: the installer now creates the folder
      (a quiet test, seen failing first).
    - The installer stored in step 9 predated the dialogs, so releases
      would have carried the one without them. Version 0.1.0 never left
      the build machine, so it was stored again (`setup --replace`,
      `980e9679…`), and `dist` from the docs commit wrote
      `factorseal-0.1.0+g1156cd1b44`, installed and uninstalled in the test
      folder. The rollout's release is built from the commit it uses.
12. **Rollout on the user's machine**, with the user, as step 2 of "Rollout
    on poita" in the import plan:
    1. back up the vault first;
    2. the installer adopts the hand-made install and updates it from this
       build's manifest. The old Desktop predates `--quit`, so this run
       takes the ask-to-quit fallback;
    3. the WSL step runs in NixOS;
    4. Desktop opens on WSL keyrings, behind the unlock;
    5. a WSL keyring lookup still works through the broker from the new
       folder.

    Later versions then go through "Update FactorSeal" with a new manifest.
    Update the `project_windows_install` notes: the uninstaller replaces
    `UNINSTALL.txt`.

    As implemented (2026-11-16):
    - Backups: an encrypted vault backup before anything else, and a second
      one after the move (it holds the 15 moved items). The hand-made
      install's folder was copied aside as well.
    - The release was built with `dist` from 3541867
      (`factorseal-0.1.0+g35418677af`). 3a7c816 then changed only the Nix
      files: `nix/package.nix` and `nix/desktop-package.nix` list the
      workspace members in their filesets, and `packaging/windows/setup`
      was missing, so the NixOS build failed reading its `Cargo.toml`.
    - Its installer, with the dialogs, adopted the hand-made install in
      `%LOCALAPPDATA%\Programs\FactorSeal`. The old Desktop predates
      `--quit`, so the run took the ask-to-quit fallback. The list of
      processes holding the folder showed Desktop's vault worker (a child of
      Desktop, gone with it) and a short-lived `cmd.exe` that had already
      exited when the list was read. Quitting Desktop from the tray was
      enough, and the installer went on by itself. The record lists NixOS
      and the Start menu, Startup and desktop shortcuts.
    - The WSL page ran `wsl-setup` in NixOS, which wrote
      `~/.config/factorseal/wsl.json` with the installed folder's pipe.
      Desktop then opened on WSL keyrings behind the unlock.
    - Rollout on poita, the import plan's two switches: the first had installed
      this branch's CLI (the factorseal input bumped to 3a7c816); Check found
      the 15 gnome-keyring items, Move put them into the vault, and Check
      again said all were in FactorSeal. The NixOS toggle was switched on.
      The second switch set `services.factorseal = { enable = true; mode =
      "wsl"; }` and turned gnome-keyring off. The gnome-keyring daemon that
      D-Bus had activated earlier kept the name until it was stopped by hand
      (`systemctl --user stop` on its `dbus-…org.freedesktop.secrets@…`
      unit), after which `factorseal wsl-keyring` took
      `org.freedesktop.secrets` by D-Bus activation.
    - The first lookups found a bug: libsecret 0.21.8 sends its DH public
      key as 129 bytes with a leading zero byte whenever the top bit is set
      (about half of sessions), and `secret-service-protocol` refused keys
      longer than 128 bytes (`secret-tool: invalid Secret Service DH public
      key`). dc597ff drops leading zero bytes (a test, seen failing first),
      and one more switch, with the input bumped, deployed it.
    - Other lookups waited 30–60 s and failed with "FactorSeal unlock was
      cancelled". That was not a bug: the vault had sealed itself while
      idle, so the keyring reported it locked and waited for an unlock.
    - Final check: after an unlock, the first `secret-tool lookup` raised
      Desktop's popup, but libsecret gave up after its 25 s D-Bus timeout
      while the password was being typed. The grant still applied ("Until
      the vault seals"), and the next two lookups answered in about 0.25 s
      without a popup.

## Order with the import plan

1. Import core: steps 1–4 and 7 of the import plan (CLI usable by hand).
2. The vault action and the Desktop page: import steps 5, 6 and 8, then its
   docs (step 9).
3. This installer, steps 1–11.
4. Rollout: the import plan's "Rollout on poita", with this installer as its
   step 2.

## Notes and risks

- **Updates while a browser fill waits**: stopping the browser host cancels
  it. The installer says so before stopping it.
- **The update swaps folders**, so a running process the wait missed, or one
  relaunched after it (the broker, the SecretSpec CLI), makes the swap
  fail. The update then rolls back, leaving the old install intact.
- **A storage migration in a new version**: Desktop runs it at the next
  unlock, as today. The installer does not back up the vault itself, but
  the rollout step does, and the docs advise an export before major updates.
- **The manifest is code in disguise**: it decides what runs on Windows.
  The limits above (step vocabulary, verified release executables, fixed
  WSL lines, HKCU prefixes, confined paths) keep a tampered manifest from
  doing more than a tampered release folder could anyway: the release's
  unsigned executables run regardless. A remote source needs signing first.
- **Antivirus**: a fixed installer helps with the installer, not with the
  product's new executables, which are unsigned and new each release.
  Signing the release files is the real fix, outside this plan.
- **Upstream ships the ZIP and the Store MSIX**; this installer is
  additional packaging, kept separate in `packaging/windows/setup`.

## Review record

The review of 2026-11-15 (against 52e7f5b) is folded in above. Each finding
and what became of it:

1. **The first stop can't use `--quit`.** Accepted. "Which version's files a
   command runs" adds the ask-to-quit fallback, used without a record or a
   recorded stop command. The rollout names it, and step 6 tests it live.
   The tray-message candidate was rejected for the installer: it depends on
   gpui-tray's private message number, which a fixed installer can't track.
2. **Which version's commands run.** Accepted: the rule per phase, with stop
   checked against the record's hashes.
3. **`install.json` lacks what undo needs.** Accepted: it records the
   resolved `stop` and `uninstall` sections and file hashes.
4. **Update can't swap the folder it runs from.** Accepted:
   - the relaunch from `%TEMP%` (Flows, step 3);
   - the self-copy into staging;
   - the file picker or `--manifest` for "Update FactorSeal".
5. **Verify-then-copy window.** Accepted: hashing while staging and staged
   verification, with a test.
6. **The `wsl` step runs arbitrary shell code.** Accepted, with the
   recommended option: the installer owns the three lines, and the manifest
   only enables the step.
7. **`registry_cleanup` and `ask_to_delete` unconfined.** Accepted:
   - the prefixes are listed;
   - paths are confined, and the vault root is refused.

   `Run` is left off the list until an autostart uses it.
8. **Byte-identical means a stored binary.** Accepted in all parts:
   - the binary is stored in `dist\setup\` with its hash;
   - the check asserts copying, not reproducibility;
   - the new mode is named `dist`, since `release` exists
     (`build-windows.sh:74`, confirmed);
   - the ZIP keeps the CLI without the provider feature, and the release
     has it.
9. **The hint contradicts the two-switch rollout, and is keyed by name.**
   Accepted: the hint is installer text keyed by `/etc/os-release` `ID`,
   saying "add the package" first. It is consistent with the import plan's
   rollout step 1.
10. **Processes the stop must expect.** Accepted:
    - the broker in `also_stop`;
    - the relaunch window and rollback written down (Flows, Notes);
    - a live WSL lookup after the update (rollout step 5).
11. **`open` right after `start`.** Accepted:
    - `start` and `open` merged into one launch, which removes the race;
    - the sealed vault shows the unlock first (step 2).
12. **Uninstall starts distros.** Accepted: the uninstall page lists them
    with consent, and `--quiet` requires `--wsl`/`--no-wsl`.
13. **Smaller points.** All accepted:
    - uninstall moved to its own step 8, after stop and `wsl`;
    - adoption records the existing shortcuts by target;
    - `requires_setup` documented as cumulative;
    - `--quiet` uses exit codes and a log file.

The review's deliberate exclusions stay out of scope here as well:
- code signing, SmartScreen and antivirus beyond the notes;
- the remote manifest;
- the MSIX and the ZIP (apart from noting the provider-feature
  difference);
- the dialog wording, left to the native review;
- Rust versus WiX or Inno, already decided with the user.
