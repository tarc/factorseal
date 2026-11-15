# Plan: a small Windows installer (`factorseal-setup.exe`)

Status, 2026-11-15: planned, not started. Branch: `feature/wsl2-keyring`.
It hands off to Desktop's gnome-keyring check and move, planned in
[gnome-keyring-import.md](gnome-keyring-import.md).

## Goal

One per-user executable that installs, updates and uninstalls FactorSeal on
Windows, sets up the WSL distros that have FactorSeal installed, and ends in
Desktop's Settings → WSL keyrings, where the user switches distros on and
moves gnome-keyring items. Today this is a ZIP extracted by hand, plus manual
steps:
- quitting Desktop through simulated tray clicks;
- stopping the browser host;
- creating shortcuts;
- running `factorseal wsl-setup` in the distro;
- an `UNINSTALL.txt` to remove it all.

The installer sits beside the ZIP and the Store MSIX
(`packaging/README.md`); it does not replace either.

## Decisions (taken with the user, 2026-11-15)

1. **A Rust `factorseal-setup.exe`**, built by the existing native Windows
   pipeline: no new tools on the Windows machine, testable in our harness.
   The Installed apps entry and the uninstaller are ours (an HKCU key and a
   file manifest).
2. **WSL: distros that already have `factorseal`** (NixOS through the
   module). The installer runs `factorseal wsl-setup` there. For a distro
   without it, it shows what to add (the NixOS module, or "not supported
   yet"). No Linux binary in the Windows installer.
3. **The gnome-keyring check and move live in Desktop**; the installer only
   opens that page at the end.

## Facts this rests on (checked 2026-11-15 on fdb0cb3)

- **Package contents** (`build-windows.ps1`):
  - executables: `factorseal.exe`, `factorseal-desktop.exe`,
    `-parser`, `-network`, `-browser`, `-wsl-broker`;
  - the askpass helper and the Scheduled Task installer (both for the
    headless agent, not for Desktop);
  - licenses, README.
  - The user's install also needs a `factorseal.exe` built with
    `secretspec-provider` (the SecretSpec claim points at it); ZIP builds
    leave that feature out.
- **The user's install today** (manual, since 2026-09-28):
  - Program files: `%LOCALAPPDATA%\Programs\FactorSeal`.
  - Shortcuts: Start menu, desktop (OneDrive-redirected), and Startup
    (`--background`, since Desktop has no autostart setting).
  - At each start, Desktop writes the four HKCU `NativeMessagingHosts` keys
    and `%APPDATA%\Factorseal\Factorseal\config`.
  - The vault is in `%LOCALAPPDATA%\Factorseal\Factorseal\data` with
    TPM-sealed keys. The installer never touches it.
- **`wsl-setup` already defaults its Windows install folder** to
  `%LOCALAPPDATA%\Programs\FactorSeal` (`cli.rs`, `WslSetup`), and has
  `--remove`.
- **Desktop is single-instance per vault root** (`instance.rs`): a second
  launch signals the first through an activation file it watches. There is
  no way to ask it to quit or to open a page.
- **Replacing files needs every FactorSeal process stopped.**
  - The vault worker (`factorseal.exe`) runs only while unsealed and exits
    about 0.4 s after a seal.
  - The browser host keeps running after Desktop quits and locks its exe;
    the extension restarts it on demand.
  - A plain `taskkill` only hides Desktop.
- **Desktop lists distros from `HKCU\…\Lxss`** without starting WSL
  (`wsl_distros.rs`). Probing a distro for `factorseal` starts it, so the
  installer asks first.
- **There are no signing credentials**, so SmartScreen warns about an
  unknown publisher, as for the ZIP.

## Design

**Payload.** The setup exe embeds a zstd-compressed tar of the release files
and a manifest (version, commit, each file's path and SHA-256). The build
step runs after `build-windows.sh release --broker`, as `build-windows.sh
setup`. Extraction checks every hash.

**Install or update** (`%LOCALAPPDATA%\Programs\FactorSeal`, no admin):
1. Read `install.json` in the folder: version, files, distros set up. A
   folder without it but with `factorseal-desktop.exe` is the hand-made
   install: adopt it. Drop `UNINSTALL.txt` after the user agrees.
2. Stop FactorSeal:
   - run `factorseal-desktop.exe --quit` (new, step 1 below), which seals
     the vault and exits;
   - wait until no process runs from the folder;
   - stop the browser host after saying so.
   - On a timeout, name the processes and stop; never kill Desktop
     unsealed.
3. Write the new files to a staging folder, then swap folders (the old one
   is renamed aside and restored on any failure).
4. Shortcuts: Start menu always; Startup (`--background`) and desktop as
   checkboxes, defaulting to what exists.
5. Installed apps: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal`
   with display name, version, publisher, install location, size, icon, and
   `UninstallString` pointing at the setup copy kept in the folder
   (`--uninstall`).
6. Start Desktop.
7. **WSL**: list distros from the registry. For each one the user ticks:
   - probe it with `wsl.exe -d <distro> -- sh -lc 'command -v factorseal'`;
   - if found, run `factorseal wsl-setup` there and record the distro in
     `install.json`;
   - if not, show the NixOS module snippet (NixOS) or "not supported yet".
8. Open Desktop at Settings → WSL keyrings (`--open wsl-keyrings`, new,
   step 2 below).

**Uninstall** (`--uninstall`, or from Installed apps):
1. Stop FactorSeal as above.
2. Run `factorseal wsl-setup --remove` in the recorded distros.
3. Delete the shortcuts, the four `NativeMessagingHosts` keys, the
   Installed apps key and the program folder. The setup exe deletes itself
   by running from a temporary copy.
4. Ask before deleting `%APPDATA%\Factorseal` (settings).
5. **The vault is always kept**: the final page says where it is and that
   `factorseal.exe destroy` removes it.

**UI**: Win32 task dialogs (`TaskDialogIndirect`): native, accessible
through UI Automation, small. Four pages:
1. Install or update (with what is installed now and the checkboxes);
2. Progress;
3. WSL distros;
4. Done.

`--quiet` with explicit options (`--install-dir`, `--no-wsl`, `--no-start`)
is for our harness and scripts.

## Steps

Each step is its own commit, with tests seen failing first or a mutation,
plus `build-windows.sh check` (Windows clippy and tests) and the Linux gate
where shared code changes. UI stays uncommitted until the user has seen it
in the native build.

1. **Desktop `--quit`**: a second launch with `--quit` asks the running
   Desktop of that root, through the instance channel, to seal and exit; it
   returns once it has, or fails after a timeout. Unit test on the instance
   channel; live: the test Desktop unlocked, `--quit`, no FactorSeal process
   left. This also replaces the tray-click dance in our scripts
   (`drive.ps1`, the install notes).
2. **Desktop `--open <page>`**: the same channel brings Desktop forward on a
   page (`wsl-keyrings` first). It changes navigation, so the user sees it
   natively.
3. **Setup engine** (new crate `packaging/windows/setup`, Windows only):
   manifest, staging and swap with rollback, adopting a hand-made install,
   `install.json`. Native tests in temporary folders, including a failed
   copy that rolls back and a locked file that stops the update cleanly.
4. **Shortcuts, Installed apps, uninstall**: the registry root is
   configurable so tests write under a test key, never the real Uninstall
   key; uninstall self-deletion. Native tests.
5. **Stopping FactorSeal**: `--quit`, the process wait scoped to the install
   folder, the browser host. Live on a test install with the test vault.
6. **WSL step** behind a command runner trait: the probe, `wsl-setup`, its
   `--remove`, and the messages. Tests with a fake runner. The real run is
   on the user's NixOS during rollout, with consent.
7. **Payload and build**: `build-windows.sh setup` embeds the release files
   (provider-enabled `factorseal.exe` included) and checks their hashes at
   extraction. Record the output in the footprint ledger.
8. **Task dialog UI**: the four pages, then the user tries it natively
   (install over a test folder, update, uninstall) before it is committed.
9. **Docs**: `packaging/README.md` (the installer beside the ZIP and MSIX,
   SmartScreen), `usage.md` Windows install, the WSL keyring section
   pointing at the installer.
10. **Rollout on the user's machine**, with the user, as step 2 of "Rollout
    on poita" in the import plan:
    1. back up the vault first;
    2. the installer adopts the hand-made install and updates it;
    3. the WSL step runs in NixOS;
    4. Desktop opens on WSL keyrings.

    Update `project_windows_install` notes: the uninstaller replaces
    `UNINSTALL.txt`.

## Order with the import plan

1. Import core: steps 1–4 and 7 of the import plan (CLI usable by hand).
2. The vault action and the Desktop page: import steps 5, 6 and 8.
3. This installer, steps 1–9.
4. Rollout: the import plan's "Rollout on poita", with this installer as its
   step 2.

## Notes and risks

- **Updates while a browser fill waits**: stopping the browser host cancels
  it. The installer says so before stopping it.
- **The update swaps folders**, so a running process the wait missed (one
  started from elsewhere) makes the swap fail. The update then rolls back,
  leaving the old install intact.
- **A storage migration in a new version**: Desktop runs it at the next
  unlock, as today. The installer does not back up the vault itself, but
  the rollout step does, and the docs advise an export before major updates.
- **Upstream ships the ZIP and the Store MSIX**; this installer is
  additional packaging, kept separate in `packaging/windows/setup`.
