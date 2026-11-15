# Plan: move gnome-keyring items into FactorSeal

Status, 2026-11-15: planned, not started. Branch: `feature/wsl2-keyring`
(the WSL keyring this targets lives there). The Windows installer that hands
off to it is planned in [windows-installer.md](windows-installer.md).

## Goal

Items that programs stored in gnome-keyring (a `gh` token, git credentials,
VS Code's, anything written through libsecret) move into FactorSeal's
keyring, so that switching `org.freedesktop.secrets` to FactorSeal no longer
means signing in to everything again. Desktop on Windows can tell beforehand
how many items a move would bring. This replaces the WSL keyring design's
decision 3 ("left alone", `wsl2-keyring-design.md`) with an explicit move.
Two targets:

- **A WSL distro's keyring** in the Windows vault
  (`factorseal/wsl-secret-service/v1/<distro>`): the case that matters now,
  before poita switches to `mode = "wsl"`.
- **The native Linux keyring** (`factorseal/secret-service/v1`), for anyone
  replacing gnome-keyring with FactorSeal on plain Linux.

## Decisions (taken with the user, 2026-11-15)

1. **Archive handoff.** A new command reads the running Secret Service
   (gnome-keyring) and writes a passphrase-encrypted FactorSeal archive whose
   entries are keyring items for the chosen target, which is then restored
   like a backup. WSL gets no new write authority: only a permission manager
   restores, as today. No broker change, no new popup.
2. **Both targets, one command**: the target namespace is the only
   difference.
3. **gnome-keyring's items are left in place.** The command only reads; its
   files stay as the fallback for switching back, and the user can delete
   them in Seahorse later.
4. **Restore treats an item with identical attributes as existing**: kept,
   or replaced with `--replace-existing`, for backups as well as imports.
   This keeps two items from answering the same lookup.
5. **Desktop previews and moves.** Settings → WSL keyrings shows, per distro,
   how many gnome-keyring items are not in FactorSeal yet, and moves them on
   request. Desktop runs the WSL command through `wsl.exe` and receives the
   archive over a pipe, encrypted with a one-time random passphrase: no file,
   nothing to type. The installer ends by opening this page. The CLI path
   (file, then Desktop's restore or `factorseal import`) stays for manual
   use and for native Linux.

## Facts this rests on (checked 2026-11-15 on fdb0cb3)

- Archives carry keyring items already: `VaultArchive::validate` accepts
  `DocumentKind::LinuxSecretService` entries in any keyring partition, the
  WSL ones included (`archive.rs:73`, `is_keyring_partition`,
  `secret_service_data.rs:14`). Each value is a `PortableItem` (index entry
  and secret together, `secret_service_data.rs:87`). Encryption is
  passphrase-only (Argon2id), so an archive can be written without a vault
  (`encrypt_vault_archive`, `archive.rs:146`).
- Desktop and the CLI restore through the same `PreparedImport::archive`
  (`transfer/import_plan.rs:65`, Desktop `runtime.rs:515`, CLI
  `commands.rs:306`), which passes keyring entries unchanged to
  `ImportVaultEntry`. That action is for permission managers only
  (`require_live_manager`, `service.rs:308`) and writes keyring items in
  `import_secret_service_item` (`service.rs:967`), which today matches
  existing items **by id only** (`KeptExisting` unless `replace_existing`).
- Item ids are 32 hex digits (`IndexItem::validate`); the index is one flat
  collection (id, label, attributes, content type, created, modified).
  Nothing a manager can call today returns a keyring item's attributes
  without its secret (`ListVaultEntries` gives addresses; `ExportVaultEntry`
  gives the value too).
- **gnome-keyring shows metadata without unlocking** (checked on a throwaway
  gnome-keyring 2026-11-15, private bus, temporary data dir):
  - **Locked again after an unlock in the same daemon:** label, attributes
    and modified time stay readable.
  - **Never unlocked since the daemon started** (as after a WSL restart):
    the collection's `Items` lists every item, and `Attributes` gives each
    name with an MD5 of its value as `gkr:compat:hashed:<name>`
    (`md5("gh")` = `19b19ffc…`). `xdg:schema` stays plain, the label is
    empty and modified is 0.
  - `SearchItems` matches locked items.
- The Wi-Fi migration already reads the previous Secret Service on the
  session bus: owner of `org.freedesktop.secrets`, a `plain` session, never
  an implicit unlock (`network_manager/migration/legacy.rs`). It searches
  only NetworkManager's attributes.
- `wsl_keyring_namespace` and `validate_distro` (`protocol/wsl.rs:277`,
  `:207`) build and check the WSL target. Desktop lists distros from the
  registry without starting WSL (`wsl_distros.rs`).
- The Linux CLI that the NixOS package builds has `vault`, so it has the
  archive code (`key-protection` + `vault-client`, `vault/mod.rs:7`).
- poita today: gnome-keyring (home-manager, `home-modules/keyring.nix`, gcr's
  prompter) owns `org.freedesktop.secrets` on the session bus through D-Bus
  activation, and no `factorseal` is installed in the distro. Its `mode =
  "wsl"` edit (pending in system-flakes) installs factorseal **and** turns
  gnome-keyring off, so the move must come between two switches (see
  "Rollout on poita").

## The fingerprint

Both sides compute one fingerprint per item from its attributes: for each
attribute, its name and the MD5 of its value, in hex. A
`gkr:compat:hashed:<name>` attribute gives `<name>` and the hash it already
holds. The fingerprint is the SHA-256 of a versioned, canonical encoding of
those pairs, sorted. MD5 is here only to match gnome-keyring's own hashing,
not for security; the values it hides are attribute values (user names,
hosts), which Desktop, as permission manager, may read anyway.

An imported item's id is the first 16 bytes of its fingerprint, in hex, so a
re-run yields the same ids.

## How it is used

**From Desktop (WSL):** with the vault unlocked, Settings → WSL keyrings, a
distro's row, "Check gnome-keyring". Desktop starts the distro only on that
click (listing distros never starts WSL). It shows "14 items, 9 not in
FactorSeal" (labels when gnome-keyring is unlocked). "Move 9 items" may make
gnome-keyring ask for its password (gcr dialog in WSLg); Desktop restores what
arrives and reports added, kept, and skipped with reasons.

**By hand (WSL or native):**

```sh
factorseal export-secret-service --inventory      # counts, no secrets, no unlock
factorseal export-secret-service /mnt/c/Users/tarci/Downloads/keyring.fsarchive
```

In WSL the target defaults to this distro (`$WSL_DISTRO_NAME`);
`--wsl-distro NAME` or `--native` choose explicitly. Then, on Windows,
`factorseal.exe import <file> --dry-run`, then Desktop's restore (or the CLI
without `--dry-run`), and delete the archive. After gnome-keyring is turned
off, its files are still on disk: the docs give a recipe that runs
`gnome-keyring-daemon --components=secrets` on a private bus
(`dbus-run-session`) to export later.

## Steps

Each step is its own commit, with tests seen failing first or a mutation,
and the usual gate (fmt, workspace clippy `-D warnings`, the lib tests under
the private bus with the helpers built, the CLI tests). UI stays uncommitted
until the user has seen it in the native build.

1. **Restore: identical attributes count as existing**
   (`import_secret_service_item`). An incoming item whose attributes equal an
   existing item's is `KeptExisting`. With `replace_existing`, it replaces
   that item's label, content type, value and modified time **under the
   existing id** (so the item stays one entry). Tests in
   `service/tests.rs`: native and WSL partition, keep and replace, two
   incoming duplicates in one archive (second kept). Mutation: match by id
   only.
2. **Shared Secret Service reader.** Move the session-bus reader out of the
   Wi-Fi migration into `secret_service/legacy.rs`. The Wi-Fi code keeps its
   attribute-limited `find`. Two new calls:
   - `inventory` lists every collection's items (`Collections`, then
     `Items`) with attributes, label and modified time, never unlocking and
     never reading a secret.
   - `read_all` also reads secrets (`GetSecrets` in batches). It unlocks a
     locked collection only when the caller asks (`Unlock`, then `Prompt`
     and its `Completed` signal); a dismissed prompt reports the collection
     as skipped.

   Both skip the in-memory `session` collection. They refuse when
   `org.freedesktop.secrets` is owned by a FactorSeal host (owner pid's
   executable). Tests use a fake Secret Service on a private bus (zbus server
   in the test) that returns hashed attributes for a locked collection. The
   Wi-Fi migration tests must stay green.
3. **Fingerprints and mapping.** `fingerprint(attributes)` as above, shared
   by both sides (in the library, no D-Bus). A pure mapping from read items
   to `VaultArchiveEntry`s for a target partition, with these rules:
   - The id comes from the fingerprint.
   - Items with identical fingerprints across collections collapse to the
     most recently modified one; the others are reported.
   - The content type defaults to `text/plain`.
   - NetworkManager items (`connection-uuid` + `setting-name`) are skipped,
     with a pointer to "Move existing Wi-Fi passwords".
   - Values over the vault's secret limit are skipped and reported.

   The result passes `VaultArchive::validate`. Unit tests cover each rule,
   plus a hashed and a plain attribute set that give the same fingerprint.
4. **CLI `factorseal export-secret-service`** (Linux, `vault` feature):
   - The target is `--wsl-distro`, `--native`, or the WSL default.
   - `--inventory` prints JSON (fingerprint, label if known, modified if
     known, collection, locked), with no secrets and no unlock.
   - `FILE` writes the archive with `read_archive_passphrase(…, true)` and
     `write_private_file`.
   - `--stdout --passphrase-stdin` is for Desktop: the passphrase comes as
     the first line of stdin, and the archive goes to stdout.

   It prints a summary to stderr. CLI tests use the fake service.
5. **Vault: keyring fingerprints for managers** (protocol v21).
   `ListKeyringFingerprints { distro: Option<String> }`, for permission
   managers only, returns each item's fingerprint, id and modified time for
   that distro's keyring (or the native one); it returns no values and no
   attributes. It is not in the broker's allowlist. Tests: manager only, WSL
   and native partitions, values never in the response; mutation: no
   manager check.
6. **Desktop: check and move** (Settings → WSL keyrings, per distro row).
   - "Check gnome-keyring" runs `wsl.exe -d <distro> -- sh -lc 'exec
     factorseal export-secret-service --inventory'` and compares the result
     with `ListKeyringFingerprints`.
   - "Move N items" generates a random passphrase, runs the `--stdout
     --passphrase-stdin` form, decrypts in memory, and restores the
     not-yet-present items through the existing `commit_import`.
   - Errors are shown on the row: no factorseal in the distro (with the
     NixOS module hint), gnome-keyring not running, prompt dismissed.

   Tests cover the comparison and the command lines with a fake runner.
   UI: the user sees it natively before it is committed.
7. **Integration check** (Linux, private bus, never the user's bus or
   keyring):
   1. A throwaway `gnome-keyring-daemon --components=secrets --unlock` (nix
      `gnome-keyring`, temporary `XDG_DATA_HOME`) runs under
      `dbus-run-session`, seeded with `secret-tool store`.
   2. `--inventory` runs with the daemon restarted locked, then the export
      runs unlocked.
   3. The archive is restored into a test vault.
   4. FactorSeal's host is served on that private bus, and `secret-tool
      lookup` must return each value.

   Add it to `check.sh`, or a script beside `test-with-dbus.sh`.
8. **Live, Windows test vault**: Desktop's check and move against a
   throwaway gnome-keyring in WSL, run as above on a private bus. Desktop
   gets a test hook for the command prefix (`dbus-run-session` + daemon),
   used only by `check.sh`. Then `check.sh keyring`'s host finds an imported
   item after the popup approval.
9. **Docs**: `usage.md` (WSL keyring section and native Linux: check, move,
   the private-bus recipe, delete a hand-made archive), the restore rule from
   step 1 in the backup docs, and `wsl2-keyring-design.md` decision 3
   pointing here.

## Rollout on poita (with the user)

1. **system-flakes, first switch**: add the `factorseal` package (and
   `factorseal wsl-setup` via the installer), keeping gnome-keyring. This
   changes the pending `mode = "wsl"` edit into two edits; the user runs
   `just switch`.
2. **Windows**: the installer (or a manual install) puts this build in
   place; its WSL step runs `wsl-setup` in NixOS and opens Desktop's WSL
   keyrings page.
3. **Desktop**: check, then move; the gcr prompt and the move are the
   user's.
4. **system-flakes, second switch**: `mode = "wsl"`, gnome-keyring off. Then
   switch NixOS on in Desktop; programs find their items, each asking once
   in the popup.

## Notes and risks

- **Approvals**: imported items carry no per-app grants, so each program asks
  once per item at first use. That is decision 2 of the WSL keyring, and
  there may be a burst of popups on the first day.
- **Exposure**: secrets cross the local session bus in a `plain` session,
  as with the Wi-Fi migration and libsecret's default. They reach Desktop
  through the `wsl.exe` pipe inside an archive encrypted with a one-time
  passphrase that only Desktop and the WSL process see. A hand-made archive
  on `/mnt/c` is readable by the Windows user's processes (encrypted), and
  drvfs ignores the 0600 mode, so the docs say to delete it after the
  restore.
- **Starting WSL**: only on the user's click; listing distros stays
  registry-only.
- **Step 1 changes backup restore semantics**: a backup restored into a vault
  that already has an attribute-identical item keeps the vault's one. Say so
  in the docs; with `--replace-existing` the backup's value wins as before.
- **Environment of a `wsl.exe` command**: `factorseal` on `PATH`, the
  session bus (`XDG_RUNTIME_DIR/bus`) and WSLg's display for the gcr prompt
  must be there in a `sh -lc` started by `wsl.exe`. Check this on poita in
  step 6 before relying on it.
- **KWallet's Secret Service interface** should work the same way, but it is
  untested; the docs name only gnome-keyring.
