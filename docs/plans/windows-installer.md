# Plan: a small Windows installer (`factorseal-setup.exe`)

Status, 2026-11-15: planned, not started. Branch: `feature/wsl2-keyring`.
It hands off to Desktop's gnome-keyring check and move, planned in
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
them. The same `factorseal-setup.exe`, byte for byte, installs it. The
installer is closed to modification and open to extension through the
manifest and through hooks the product itself ships. An unchanged installer
keeps its file hash, so antivirus and SmartScreen reputation built up for it
carries over, and nothing about installing needs re-reviewing per release.

The installer sits beside the ZIP and the Store MSIX
(`packaging/README.md`); it does not replace either.

## Decisions (taken with the user, 2026-11-15)

1. **A Rust `factorseal-setup.exe`**, built by the existing native Windows
   pipeline: no new tools on the Windows machine, testable in our harness.
   The Installed apps entry and the uninstaller are ours.
2. **WSL: distros that already have `factorseal`** (NixOS through the
   module). For a distro without it, the installer shows what to add. No
   Linux binary in the Windows installer.
3. **The gnome-keyring check and move live in Desktop**; the installer only
   opens that page at the end.
4. **Release manifest, fixed installer.** The installer embeds no payload.
   It reads a `factorseal-release.json` that points at the release's
   artifacts (paths relative to the manifest, each with its SHA-256) and
   lists the install steps as data. Behavior that belongs to a version (how
   to quit Desktop, how to set up WSL, which page to open) is a command of
   that version's own executables, named in its manifest. Releasing means
   building the artifacts and writing the manifest; the setup crate is
   rebuilt only when the installer itself gains a capability.

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
  (`wsl_distros.rs`). Probing a distro starts it, so the installer asks
  first.
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
  "steps": [
    { "stop": { "command": ["factorseal-desktop.exe", "--quit"],
                "then_wait_for": "install-folder-processes",
                "also_stop": ["factorseal-browser.exe"] } },
    { "install_files": {} },
    { "shortcut": { "name": "FactorSeal Desktop", "target": "factorseal-desktop.exe",
                    "places": ["start-menu"], "optional_places": ["startup", "desktop"],
                    "startup_args": ["--background"] } },
    { "start": { "command": ["factorseal-desktop.exe", "--background"] } },
    { "wsl": { "probe": ["sh", "-lc", "command -v factorseal"],
               "setup": ["sh", "-lc", "exec factorseal wsl-setup"],
               "remove": ["sh", "-lc", "exec factorseal wsl-setup --remove"],
               "missing_hint": { "NixOS": "services.factorseal = { enable = true; mode = \"wsl\"; };" } } },
    { "open": { "command": ["factorseal-desktop.exe", "--open", "wsl-keyrings"] } }
  ],
  "uninstall": {
    "registry_cleanup": ["HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\dev.factorseal.browser", "…"],
    "ask_to_delete": ["%APPDATA%\\Factorseal"],
    "keep_note": "The vault stays in %LOCALAPPDATA%\\Factorseal; factorseal.exe destroy removes it."
  }
}
```

The rules that keep the installer closed and safe:

- **Step types are the installer's vocabulary**: `stop`, `install_files`,
  `shortcut`, `start`, `wsl`, `open`, `registry` (values under an allowed
  HKCU prefix only). A release combines and parameterises them freely. A
  new kind of step is the only reason to change the installer, and then
  `requires_setup` rises: an older installer refuses that manifest with
  "this release needs a newer installer" instead of guessing.
- **Commands run only executables from the release's own verified files**,
  addressed relative to the install folder, plus `wsl.exe` through the `wsl`
  step. The manifest cannot name an arbitrary system program or path.
- **Every artifact is checked against its SHA-256** before anything stops or
  changes; one mismatch aborts with the old install untouched.
- **What the installer did is recorded in `install.json`** in the install
  folder: version, files, shortcuts, registry values, distros set up.
  Uninstall and the next update undo from that record, not from the new
  manifest, so a release can change its steps without stranding what an
  older one created.
- **The manifest is local**: a path the user gives, or the default
  `dist\factorseal-<version>\factorseal-release.json` that the build
  writes. A remote source (a release page) would need a signed manifest and
  the public key in the installer; that is a later extension, not part of
  this plan.

## Flows

**Install or update.** Run `factorseal-setup.exe [--manifest PATH]`. The
installed copy in the program folder serves later updates and appears in
Start as "Update FactorSeal".
1. Read and verify the manifest and every artifact.
2. Read `install.json`. A folder without it but with
   `factorseal-desktop.exe` is the hand-made install: adopt it, and drop
   `UNINSTALL.txt` after the user agrees.
3. Run the manifest's steps in order:
   - `install_files` stages into a new folder and swaps it in, renaming the
     old folder aside and restoring it on any failure.
   - The setup exe copies itself into the folder only if its version is
     newer than the copy already there.
4. Register in Installed apps
   (`HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\FactorSeal`,
   the version from the manifest, and `UninstallString` pointing at the
   installed setup with `--uninstall`).

**Uninstall.**
1. The `stop` step of the recorded version.
2. The recorded `wsl` removals.
3. Delete the recorded shortcuts and registry values, the manifest's
   `registry_cleanup` keys, the Installed apps key and the folder, running
   from a temporary copy so the setup exe can delete itself.
4. Ask before deleting the `ask_to_delete` paths.
5. Show the `keep_note`. **The vault is always kept.**

**UI**: Win32 task dialogs (`TaskDialogIndirect`): native, accessible
through UI Automation, small. Four pages:
1. Install or update: current and new version, and the optional places;
2. Progress;
3. WSL distros;
4. Done.

`--quiet` with explicit options (`--install-dir`, `--no-wsl`, `--no-start`)
is for our harness and scripts. The texts come from the installer, never the
manifest, apart from version strings and the per-distro hint.

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
3. **Manifest schema and verification** (new crate
   `packaging/windows/setup`; the parsing and checks are plain Rust, tested
   on Linux too):
   - the schema with `requires_setup`, and refusal of unknown step types;
   - paths confined to the release folder (no `..`, no absolute paths,
     no links out);
   - commands confined to verified release files;
   - registry values confined to the allowed HKCU prefixes;
   - every hash checked before any change.

   Tests cover each refusal. One test pins that a manifest written for
   schema 1 with a new version and new files installs with an unchanged
   installer.
4. **Install engine**: `install_files` with staging, swap and rollback,
   adopting a hand-made install, and `install.json` as the record undo works
   from. Native tests in temporary folders: a failed copy rolls back, a
   locked file stops the update cleanly, and an update whose new manifest
   drops a shortcut still removes the old one.
5. **Steps `shortcut`, `registry`, `start`, `open`, and uninstall**: the
   registry root is configurable so tests write under a test key, never the
   real Uninstall key; uninstall self-deletion. Native tests.
6. **Step `stop`**: the command, the process wait scoped to the install
   folder, `also_stop`. Live on a test install with the test vault.
7. **Step `wsl`** behind a command runner trait: probe, setup, remove,
   hints. Tests with a fake runner; the real run is on the user's NixOS
   during rollout, with consent.
8. **The build writes the manifest**: `build-windows.sh release` puts the
   artifacts (provider-enabled `factorseal.exe` included) and
   `factorseal-release.json` in `dist\factorseal-<version>\`.
   `build-windows.sh setup` builds the installer on its own, only when its
   crate changes. A check builds two releases and asserts that the installer
   is the same file for both. Record the outputs in the footprint ledger.
9. **Task dialog UI**: the four pages, then the user tries it natively
   (install into a test folder, update to a second build with the same
   installer, uninstall) before it is committed.
10. **Docs**:
    - `packaging/README.md`: the installer beside the ZIP and MSIX, the
      manifest, SmartScreen.
    - `usage.md`: Windows install and update.
    - The WSL keyring section points at the installer.
    - A short "Releasing" note: build, manifest, run the installed setup.
11. **Rollout on the user's machine**, with the user, as step 2 of "Rollout
    on poita" in the import plan:
    1. back up the vault first;
    2. the installer adopts the hand-made install and updates it from this
       build's manifest;
    3. the WSL step runs in NixOS;
    4. Desktop opens on WSL keyrings.

    Later versions then go through "Update FactorSeal" with a new manifest.
    Update the `project_windows_install` notes: the uninstaller replaces
    `UNINSTALL.txt`.

## Order with the import plan

1. Import core: steps 1–4 and 7 of the import plan (CLI usable by hand).
2. The vault action and the Desktop page: import steps 5, 6 and 8.
3. This installer, steps 1–10.
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
- **The manifest is code in disguise**: it decides what runs. The limits
  above (step vocabulary, verified release executables, HKCU prefixes,
  confined paths) are what keep a tampered manifest from doing more than a
  tampered release folder could anyway. A remote source needs signing first.
- **Antivirus**: a fixed installer helps with the installer, not with the
  product's new executables, which are unsigned and new each release.
  Signing the release files is the real fix, outside this plan.
- **Upstream ships the ZIP and the Store MSIX**; this installer is
  additional packaging, kept separate in `packaging/windows/setup`.
