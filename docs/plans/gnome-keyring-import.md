# Plan: move gnome-keyring items into FactorSeal

Status, 2026-11-15: planned, not started. Branch: `feature/wsl2-keyring`
(the WSL keyring this targets lives there).

## Goal

Items that programs stored in gnome-keyring (a `gh` token, git credentials,
VS Code's, anything written through libsecret) move into FactorSeal's
keyring, so that switching `org.freedesktop.secrets` to FactorSeal no longer
means signing in to everything again. This replaces the WSL keyring design's
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
   entries are keyring items for the chosen target. The user restores it as
   a backup: Desktop's restore, or `factorseal import`. WSL gets no new write
   authority: only a permission manager restores, as today. No protocol
   change, no broker change, no new popup.
2. **Both targets, one command**: the target namespace is the only
   difference.
3. **gnome-keyring's items are left in place.** The command only reads; its
   files stay as the fallback for switching back, and the user can delete
   them in Seahorse later.
4. **Restore treats an item with identical attributes as existing**: kept,
   or replaced with `--replace-existing`, for backups as well as imports.
   This keeps two items from answering the same lookup.

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
- The Wi-Fi migration already reads the previous Secret Service on the
  session bus: owner of `org.freedesktop.secrets`, a `plain` session, never
  an implicit unlock (`network_manager/migration/legacy.rs`). It searches
  only NetworkManager's attributes.
- `wsl_keyring_namespace` and `validate_distro` (`protocol/wsl.rs:277`,
  `:207`) build and check the WSL target.
- The Linux CLI that the NixOS package builds has `vault`, so it has the
  archive code (`key-protection` + `vault-client`, `vault/mod.rs:7`).
- poita's gnome-keyring is home-manager's (`home-modules/keyring.nix`), with
  gcr's system prompter: a locked login keyring is unlocked through a gcr
  dialog (WSLg).

## How it is used (WSL)

1. Install the build with this change on Windows (it needs the new restore
   rule), with Desktop unlocked.
2. In WSL, while gnome-keyring still serves the session bus:

   ```sh
   factorseal export-secret-service /mnt/c/Users/tarci/Downloads/keyring.fsarchive
   ```

   In WSL the target defaults to this distro (`$WSL_DISTRO_NAME`);
   `--wsl-distro NAME` or `--native` choose explicitly. It asks for an
   archive passphrase twice (or `--passphrase-file`), unlocks locked
   collections through gnome-keyring's own prompt, and prints counts plus
   each skipped item's label and reason (never a value).
3. On Windows: `factorseal.exe import <file> --dry-run`, then Desktop's
   restore (or the CLI without `--dry-run`). Delete the archive.
4. Switch poita to `mode = "wsl"` and the distro on in Desktop. Each program
   asks once per item in the popup, as for any WSL keyring item.

After the switch, gnome-keyring's files are still on disk: the docs give a
recipe that runs `gnome-keyring-daemon --components=secrets` on a private bus
(`dbus-run-session`) to export later.

## Steps

Each step is its own commit, with tests seen failing first or a mutation,
and the usual gate (fmt, workspace clippy `-D warnings`, the lib tests under
the private bus with the helpers built, the CLI tests).

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
   attribute-limited `find`; the new `read_all` lists every collection
   (`Collections`, then each collection's `Items`) and reads labels,
   attributes, created/modified and secrets (`GetSecrets` in batches). It
   skips the in-memory `session` collection. A locked collection is unlocked
   only when the caller asks (`Unlock`, then `Prompt` and its `Completed`
   signal); a dismissed prompt reports the collection as skipped. It refuses
   when `org.freedesktop.secrets` is owned by a FactorSeal host (owner pid's
   executable), so it never "imports" FactorSeal into itself. Tests against a
   fake Secret Service on a private bus (zbus server in the test). The Wi-Fi
   migration tests must stay green.
3. **Mapping to archive entries.** A pure function from read items to
   `VaultArchiveEntry`s for a target partition. Its rules:
   - The id is the first 16 bytes of SHA-256 over a versioned, canonical
     encoding of the sorted attributes, in hex. A re-run therefore yields the
     same ids, and restore keeps what is there.
   - Items with identical attributes across collections collapse to the most
     recently modified one; the others are reported.
   - The content type defaults to `text/plain`.
   - NetworkManager items (`connection-uuid` + `setting-name`) are skipped,
     with a pointer to "Move existing Wi-Fi passwords".
   - Values over the vault's secret limit are skipped and reported.

   The result passes `VaultArchive::validate`. Unit tests cover each rule.
4. **CLI `factorseal export-secret-service FILE`** (Linux, `vault` feature):
   - The target is `--wsl-distro`, `--native`, or the WSL default.
   - It reuses `read_archive_passphrase(…, true)` and `write_private_file`.
   - It prints a summary; `--dry-run` reads and counts without writing.

   CLI tests use the fake service.
5. **Integration check** (Linux, private bus, never the user's bus or
   keyring):
   1. A throwaway `gnome-keyring-daemon --components=secrets --unlock` (nix
      `gnome-keyring`, temporary `XDG_DATA_HOME`) runs under
      `dbus-run-session`, seeded with `secret-tool store`.
   2. The export runs against it, and the archive is restored into a test
      vault.
   3. FactorSeal's host is served on that private bus, and `secret-tool
      lookup` must return each value. Add it to `check.sh` (or a script
      beside `test-with-dbus.sh`).
6. **Live, Windows test vault**: restore an archive exported from a
   throwaway gnome-keyring in WSL into the test Desktop. `check.sh
   keyring`'s host then finds an imported item after the popup approval.
   Restore's existing UI is unchanged, but the user sees its result in the
   native build before this is reported done.
7. **Docs**: `usage.md` (WSL keyring section and native Linux: how to move
   items, the private-bus recipe, delete the archive), the restore rule from
   step 1 in the backup docs, and `wsl2-keyring-design.md` decision 3
   pointing here.
8. **The real move on poita, with the user**: after the Windows install
   (item 1 of the WSL2 plan's next steps), before `just switch`. The user
   runs or approves each command; the gcr prompt and Desktop's restore are
   theirs.

## Notes and risks

- **Approvals**: imported items carry no per-app grants, so each program asks
  once per item at first use. That is decision 2 of the WSL keyring, and
  there may be a burst of popups on the first day.
- **Exposure**: secrets cross the local session bus in a `plain` session,
  as with the Wi-Fi migration and libsecret's default. The archive is
  encrypted. A copy on `/mnt/c` is readable by the Windows user's processes
  (encrypted), and drvfs ignores the 0600 mode, so the docs say to delete it
  after the restore.
- **Step 1 changes backup restore semantics**: a backup restored into a vault
  that already has an attribute-identical item keeps the vault's one. Say so
  in the docs; with `--replace-existing` the backup's value wins as before.
- **KWallet's Secret Service interface** should work the same way, but it is
  untested; the docs name only gnome-keyring.
