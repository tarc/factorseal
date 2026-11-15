# Review: windows-installer.md

Reviewed 2026-11-15 against `wip/wsl2-keyring` at 52e7f5b (same commit as
`feature/wsl2-keyring`). Written for the planning session to fold into the
plan. Findings are ordered by weight; each says what to change.

## Facts checked and confirmed

- **Package contents.** `packaging/build-windows.ps1` builds
  `factorseal.exe`, `-parser`, `-network`, `-browser`, `factorseal-desktop`
  and `factorseal-wsl-broker`. It builds the CLI without
  `secretspec-provider`, as the plan says.
- **The single-instance channel.** `instance.rs` uses a lock file and an
  activation file that it watches. `main.rs:256` sends an activation only
  when neither `--background` nor `--keyring-activation` is given. There is
  no quit or open request today.
- **`wsl-setup`.** It defaults to `%LOCALAPPDATA%\Programs\FactorSeal` and
  has `--remove` (`cli.rs:337`). It only exists with `secretspec-provider`
  on Linux, which `nix/package.nix` enables.
- **Distro listing.** Desktop lists distros through `reg.exe` without
  starting WSL (`wsl_distros.rs`).

Not re-checked: the facts about the user's current install (shortcuts,
OneDrive-redirected desktop) and the vault worker's 0.4 s exit. I took them
from the plan and memory notes.

## Findings

### 1. The first `stop` can't use `--quit`: the Desktop it must stop predates it (blocker for the adoption path)

The rollout's update is from the hand-made install, built before step 1.

- **The old executable.** If `stop` runs the installed (old)
  `factorseal-desktop.exe --quit`, clap rejects the unknown option and
  exits. The running Desktop stays.
- **The new executable.** If it runs the new release's executable, the new
  `--quit` writes a request the old Desktop doesn't understand. Its watcher
  treats any change of the activation file as "activate", so the old
  Desktop just comes forward and the installer times out.

The plan needs a fallback for a Desktop that predates `--quit`. Candidates:

- the tray-menu message the scripts already use
  (`reference_tray_click_simulation`);
- asking the user to quit from the tray, then waiting for the processes
  to exit.

It also needs a way to tell the two cases apart, e.g. "no `install.json`"
means adoption, which means the fallback. The same applies to any future
version whose `stop` command changes: the command that stops the
*running* version must come from that version.

### 2. Which version's commands run: the old one's, or the new release's? (internal consistency)

"Commands run only executables from the release's own verified files,
addressed relative to the install folder." Before `install_files`, the
install folder holds the **old** version, which the new manifest didn't
verify. After it, it holds the new one. The plan has to say, per step,
which one it means:

- **`stop` before `install_files`** should run the old version's stop
  command, which is the point of finding 1. That means the record has to
  carry the command (finding 3), and its executable is verified against
  the record's hashes, not the manifest's.
- **`start`, `open` and `wsl` after the swap** run the new files from the
  install folder, now verified.

Spell this out, and make the confinement check operate on the right file
list.

### 3. `install.json` doesn't record what uninstall and the next update need (internal consistency)

Uninstall says it runs "the `stop` step of the recorded version", "the
recorded `wsl` removals", and "the manifest's `registry_cleanup`". It also
says undo comes "from that record, not from the new manifest". But the
record holds only version, files, shortcuts, registry values and distros.

- Record the stop command, the wsl remove command, `registry_cleanup`,
  `ask_to_delete` and `keep_note` too: in effect, the resolved `stop` and
  `uninstall` sections of the manifest that installed it.
- Otherwise uninstall has to re-read a manifest that may be gone, or a
  newer one.

### 4. Updating from the installed copy: it runs inside the folder it swaps (blocker)

"The installed copy in the program folder serves later updates." But
`install_files` "renames the old folder aside". Windows won't rename a
directory while an executable inside it is running: its image section
holds the file open. So "Update FactorSeal" fails at the swap every time.

- Uninstall already plans to relaunch from a temporary copy. Updates need
  the same: relaunch from `%TEMP%` before step 3.
- Also: when "the setup exe copies itself into the folder only if newer",
  that copy has to go into the **staging** folder before the swap, or it
  is lost with the old folder.
- **The manifest location.** For the installed copy, the default
  `dist\factorseal-<version>\factorseal-release.json` is meaningless,
  because it doesn't know the new version or where the user put it. Say
  that the Start-menu "Update FactorSeal" opens a file picker for the
  manifest, or takes it from the command line.

### 5. Verify-then-copy leaves a TOCTOU window (security, cheap fix)

"Every artifact is checked against its SHA-256 before anything stops or
changes." The files are then copied later, after `stop`, from a folder the
user (or anything running as the user) can write to. Hash while copying
into staging, and verify the staged copies before the swap. Keep the
up-front check only for failing early. The install engine tests (step 4)
should include "an artifact changes between verify and copy".

### 6. The `wsl` step runs arbitrary shell code in every distro (the confinement rule overstates)

`probe`, `setup` and `remove` are arbitrary argument lists passed to
`sh -lc` inside each consented distro. "The manifest cannot name an
arbitrary system program or path" is true on Windows only. A tampered
manifest can run anything in WSL, as the user, without touching a single
release file.

The risk note's argument ("no more than a tampered release folder could")
still roughly holds, since the release's executables are unsigned and run
anyway. But the rule should say so honestly. The other option is to narrow
it: the installer owns the three command lines, which are fixed and
version-independent (`factorseal wsl-setup`, `--remove`,
`command -v factorseal`). Then the manifest only says whether to run the
`wsl` step at all. The second option fits "the installer never changes"
too, since the arguments live in the product's CLI. I recommend it.

### 7. `registry_cleanup` and `ask_to_delete` aren't covered by the confinement rules (security)

- **Registry.** The `registry` step is limited to allowed HKCU prefixes,
  but `registry_cleanup` (deleting keys) has no stated limit. It needs the
  same prefix allowlist, and the plan should list the prefixes:
  - the four browsers' `NativeMessagingHosts\dev.factorseal.*` keys;
  - `…\CurrentVersion\Uninstall\FactorSeal`;
  - possibly `…\Run` if an autostart ever moves there.
- **Paths.** `ask_to_delete` takes environment-expanded paths with no
  limit. Confine them to `%APPDATA%\Factorseal` and `%LOCALAPPDATA%`
  subfolders other than the vault's `data`. Refuse any path that contains
  or equals the vault root, so that "the vault is always kept" is enforced
  rather than only promised.

### 8. "The same installer, byte for byte" needs a stored binary, not a rebuild (feasibility)

- **Reproducibility.** MSVC Rust builds aren't reproducible by default:
  the PE timestamp, the PDB GUID and its path are embedded. Step 8's
  `build-windows.sh setup` "only when its crate changes" means the
  installer **binary** must be kept between releases: committed as a
  release asset, or cached under a versioned path recorded in the
  footprint ledger. Say where it lives.
- **The check.** "A check builds two releases and asserts that the
  installer is the same file" is then trivially true when it doesn't
  rebuild the installer. If it is meant to rebuild, it will fail unless
  the build is made reproducible (`/Brepro`, a remapped path prefix,
  `SOURCE_DATE_EPOCH`-like settings). Decide which of the two the check
  asserts.
- **`build-windows.sh release` already exists**
  (`scripts/windows-desktop-check/build-windows.sh`, mode `release`). It
  builds Desktop and the CLI into the Windows mirror's `target`. Step 8
  changes what it does. Either extend it explicitly, keeping its current
  callers (the `windows-desktop-check` skill, the memory notes) working,
  or name the new mode differently (`dist`).
- **The provider feature.** Step 8 says the release includes the
  provider-enabled `factorseal.exe`. Then the ZIP (`build-windows.ps1`) and
  the installer's release ship different CLIs. Say whether
  `build-windows.ps1` gains the feature too, or the release is built
  separately.

### 9. The `missing_hint` contradicts the two-switch rollout (cross-plan consistency)

The hint is `services.factorseal = { enable = true; mode = "wsl"; };`.
During the first phase of the import plan's rollout, a distro without
FactorSeal must add **only the package**. Every mode of the module installs
an `org.freedesktop.secrets` activation file (`nix/modules/factorseal.nix`),
which competes with home-manager's gnome-keyring. Following the hint skips
the move.

Make the hint "add the `factorseal` package", or show both stages and
point at the import plan. This is also a case for finding 6's narrower
design: hints that depend on rollout state don't belong in a fixed
vocabulary keyed by distro name.

Related: hints are keyed by distro **name** (`"NixOS"`). Registered names
are user-chosen; poita's distro may or may not be called `NixOS`. Key by
`/etc/os-release` `ID` from the probe, or drop the key.

### 10. Processes the stop wait must expect (robustness)

- **The WSL broker.** WSL programs (SecretSpec, the keyring relay) start
  `factorseal-wsl-broker.exe` from the install folder through interop. They
  can relaunch it during the update. The `stop` step should name it in
  `also_stop`. The plan should say the window between stop and swap is
  where a relaunch makes the swap fail, and the rollback covers it, as for
  the browser host.
- **`factorseal.exe` from the SecretSpec claim.** Native SecretSpec runs
  the provider-enabled `factorseal.exe` from the install folder. It's
  short-lived but has the same effect.
- **The broker's identity.** `build-windows.ps1` notes that Desktop grants
  a distro's keyring to the broker "only from beside `factorseal.exe`". The
  folder swap keeps the path, so this holds. Add a live check after the
  update that a WSL keyring lookup still works, in step 6 or step 11.

### 11. `open` right after `start` (ordering)

`start` launches `--background`, then `open` immediately runs
`--open wsl-keyrings`.

- **Startup race.** If the new Desktop hasn't taken the instance lock yet,
  the `--open` launch becomes the primary instance itself. That's probably
  harmless, but then `--background` is lost and two launches race. Either
  merge them (`start` with `--open`), or make `open` wait for the instance
  lock.
- **The sealed vault.** After `--quit` the vault is sealed. The page opens
  on a locked vault, and Check needs it unlocked. Say that Desktop shows
  unlock first and then the page; that also belongs to step 2's native
  review.

### 12. Uninstall starts WSL distros (consistency with "the installer asks first")

Uninstall's "recorded `wsl` removals" start each recorded distro. The plan
asks before probing on install. Uninstall should ask too, or at least list
the distros it will start on its first page. Under `--quiet`, require an
explicit `--wsl`/`--no-wsl`.

### 13. Smaller points

- **Step order.** Step 5 includes uninstall, but uninstall depends on
  `stop` (step 6) and `wsl` (step 7). Either move uninstall after step 7,
  or say that step 5's uninstall test covers files, shortcuts and registry
  only.
- **Adoption.** "Drop `UNINSTALL.txt` after the user agrees": also adopt
  the existing shortcuts. The user's Startup and OneDrive desktop
  shortcuts exist today and aren't in any record. Either record them as
  found (matching target path), or replace them, so uninstall removes them.
- **`requires_setup`** is a single integer. That works only if every
  installer capability is cumulative. Fine for now; say so.
- **`--quiet`** should report through its exit code and a log file. Task
  dialogs can't be used headless, and the harness needs failures to
  surface (see the global wrapper rule about returning exit codes).

## Aspects deliberately not considered

- **Code signing, SmartScreen and antivirus.** The plan places signing
  outside its scope, and its claims about hash-based reputation are
  plausible. I didn't evaluate them further.
- **A remote manifest source** (explicitly deferred by the plan).
- **The Store MSIX and the ZIP**, which the plan leaves unchanged.
- **The task dialog wording and page layout.** That's for the native review
  the plan already requires.
- **Whether a Rust installer beats an existing tool (WiX, Inno).** That was
  decided with the user (decision 1), so I didn't relitigate it.
