# Plan: move gnome-keyring items into FactorSeal

Status, 2026-11-15: planned, not started; review folded in (see "Review
record" at the end). Branch: `feature/wsl2-keyring` (the WSL keyring this
targets lives there). The Windows installer that hands off to it is planned
in [windows-installer.md](windows-installer.md).

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
   This stops restores from adding a second item that answers the same
   lookup. It is not a vault-wide invariant: `CreateItem` with
   `replace=false` already mints a new id beside an identical item
   (`create_or_replace_planned`, `agent.rs:336`), and existing duplicates
   are left alone. Matching rules are in step 1.
5. **Desktop previews and moves.** Settings → WSL keyrings shows, per distro,
   how many gnome-keyring items are not in FactorSeal yet, and moves them on
   request. Desktop runs the WSL command through `wsl.exe` and receives the
   archive over a pipe, encrypted with a one-time random passphrase: no file,
   nothing to type. The installer ends by opening this page. The CLI path
   (file, then Desktop's restore or `factorseal import`) stays for manual
   use and for native Linux.

## Facts this rests on (checked 2026-11-15 on fdb0cb3, re-checked on 52e7f5b)

- Archives carry keyring items already: `VaultArchive::validate` accepts
  `DocumentKind::LinuxSecretService` entries in any keyring partition, the
  WSL ones included (`archive.rs:73`, `is_keyring_partition`,
  `secret_service_data.rs:14`). Each value is a `PortableItem` (index entry
  and secret together, `secret_service_data.rs:87`), and
  `PortableItem::decode` (`:105`) requires the entry's address to be
  `item/<item.id>`. Encryption is passphrase-only (Argon2id), so an archive
  can be written without a vault (`encrypt_vault_archive`, `archive.rs:146`);
  it runs `validate_new_password` on the passphrase (`archive.rs:151`).
- Desktop and the CLI restore through the same `PreparedImport::archive`
  (`transfer/import_plan.rs:65`, Desktop `runtime.rs:515`, CLI
  `commands.rs:307`), which passes keyring entries unchanged to
  `ImportVaultEntry`. That action is for permission managers only
  (`require_live_manager`, `service.rs:307`) and writes keyring items in
  `import_secret_service_item` (`service.rs:967`), which today matches
  existing items **by id only** (`KeptExisting` unless `replace_existing`).
  `PreparedImport` has no per-entry filter, and the restore's
  `TransferSummary` reports only added and kept.
- Item ids are 32 hex digits (`IndexItem::validate`); the index is one flat
  collection (id, label, attributes, content type, created, modified).
  Nothing a manager can call today returns a keyring item's attributes
  without its secret (`ListVaultEntries` gives addresses; `ExportVaultEntry`
  gives the value too). The protocol is at 20 (`wire.rs:20`).
- **gnome-keyring shows metadata without unlocking.** Checked on a throwaway
  gnome-keyring 50.0 (private bus, temporary data dir), first 2026-11-15
  with a `gh`-style item, then again the same day with a libsecret schema
  that has an `INTEGER` attribute:
  - **Locked again after an unlock in the same daemon:** label, attributes
    and modified time stay readable.
  - **Never unlocked since the daemon started** (as after a WSL restart):
    - the collection's `Items` lists every item;
    - `Attributes` gives each name with an MD5 of its value as
      `gkr:compat:hashed:<name>` (`md5("gh")` = `19b19ffc…`);
    - the label is empty and modified is 0.
  - **The plain `xdg:schema` of a locked item is a placeholder.** It reads
    `org.freedesktop.Secret.Generic` for every item. The real schema is only
    in `gkr:compat:hashed:xdg:schema`: an item stored with schema `test.int`
    showed the placeholder plainly and `md5("test.int")` = `7675a45f…`
    hashed. (The first check used a generic item, where the two agree, which
    is how the earlier "`xdg:schema` stays plain" got in.)
  - **Integer attributes hash like text.** A libsecret `INTEGER` attribute
    `port=8080` reaches the daemon as the string `"8080"` (the Secret
    Service API only carries `a{ss}`) and is hashed as `md5("8080")` =
    `d4a973e3…`. gnome-keyring's uint32 compat hashing only applies to items
    from its legacy file format, which libsecret over D-Bus never creates.
  - **gnome-keyring reserves the `gkr:compat:` prefix.** An item stored with
    an attribute named `gkr:compat:hashed:fake` came back unlocked as
    `fake: ""`, so such names never survive a store. Ordinary unlocked items
    show no `gkr:compat:*` attributes.
  - `SearchItems` matches locked items.
- The Wi-Fi migration already reads the previous Secret Service on the
  session bus: owner of `org.freedesktop.secrets`, a `plain` session, never
  an implicit unlock (`network_manager/migration/legacy.rs`). It searches
  only NetworkManager's attributes.
- `wsl_keyring_namespace` and `validate_distro` (`protocol/wsl.rs:277`,
  `:207`) build and check the WSL target. Desktop lists distros from the
  registry without starting WSL (`wsl_distros.rs`).
- The Linux CLI that the NixOS package builds has `vault`, so it has the
  archive code (`key-protection` + `vault-client`, `vault/mod.rs:7`;
  `nix/package.nix` features).
- **The NixOS module claims `org.freedesktop.secrets` in every mode**
  (`nix/modules/factorseal.nix`: the WSL activation file, or the desktop
  package's service file). Its assertion against
  `services.gnome.gnome-keyring` doesn't see a home-manager gnome-keyring.
- poita today: gnome-keyring (home-manager, `home-modules/keyring.nix`, gcr's
  prompter) owns `org.freedesktop.secrets` on the session bus through D-Bus
  activation, and no `factorseal` is installed in the distro. Its `mode =
  "wsl"` edit (pending in system-flakes) installs factorseal **and** turns
  gnome-keyring off, so the move must come between two switches (see
  "Rollout on poita").

## The fingerprint

Both sides compute one fingerprint per item from its attributes, as a set
of pairs (name, MD5 of the value):

- **gnome-keyring, locked:** each `gkr:compat:hashed:<name>` gives
  `(<name>, its hash)`. Every other attribute is ignored: on a locked item
  the only plain one is the placeholder `xdg:schema`, whose real value is
  in the hashed set.
- **gnome-keyring, unlocked, and the vault:** each attribute gives
  `(name, md5(value))`. Names starting with `gkr:compat:` are left out
  (gnome-keyring reserves them; this is defensive).

The fingerprint is SHA-256 over this byte string:

- the ASCII tag `factorseal-keyring-fingerprint-v1` and a zero byte;
- then, for each pair sorted by the name's UTF-8 bytes:
  - the name's length as a 4-byte big-endian integer;
  - the name's UTF-8 bytes;
  - the 16 raw MD5 bytes.

Length prefixes leave nothing to escape. The tag's version changes if the
encoding ever does, and v21 of the protocol returns the fingerprint as
64-char lowercase hex.

MD5 is here only to match gnome-keyring's own hashing, not for security.
The values it hides are attribute values (user names, hosts), which Desktop,
as permission manager, may read anyway.

Items with no attributes (after leaving out `gkr:compat:*`) get no
fingerprint. They are skipped and reported ("no attributes"): every one of
them would share one fingerprint, and no program can look them up by
attributes anyway.

An imported item's id is the first 16 bytes of its fingerprint, in hex, so a
re-run yields the same ids. The imported item carries the plain attributes
only, never `gkr:compat:*`.

## How it is used

**From Desktop (WSL):** with the vault unlocked, Settings → WSL keyrings, a
distro's row, "Check gnome-keyring". Desktop starts the distro only on that
click (listing distros never starts WSL). If Desktop is sealed (as when the
installer opens this page), it asks for the unlock first. It shows "14
items, 9 not in FactorSeal", with labels when gnome-keyring is unlocked.
"Move 9 items" may make gnome-keyring ask for its password, once per locked
collection (gcr dialog in WSLg). Desktop restores what arrives and reports
added, kept, and skipped with reasons. The move can skip items the check
counted, for example "too large", which a locked check can't know (no
values).

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
(`dbus-run-session`) to export later. The recipe needs a short
`XDG_RUNTIME_DIR`: the daemon's control socket path is cut at the
108-byte socket limit, and a second daemon then fails with
`discover_other_daemon` (seen in the 2026-11-15 check from a deep
directory).

## Steps

Each step is its own commit, with tests seen failing first or a mutation,
and the usual gate (fmt, workspace clippy `-D warnings`, the lib tests under
the private bus with the helpers built, the CLI tests). UI stays uncommitted
until the user has seen it in the native build.

1. **Restore: identical attributes count as existing**
   (`import_secret_service_item`). Matching, in this order:
   1. **By attributes.** The first existing item, in index order, whose
      attributes equal the incoming item's (as `create_or_replace` picks).
      Without `replace_existing` it is `KeptExisting`. With it, the
      existing item keeps its id and `created`; label, content type, value
      and modified come from the incoming item. That means:
      - rewriting `portable.item.id` to the existing id;
      - writing the value at `item/<existing id>`, in the `VaultRequest`
        validation and in the `store.mutate` operations alike, since
        `PortableItem::decode` rejects a value whose address doesn't match
        its id.
   2. **By id only** (the id is taken by an item with other attributes, e.g.
      one a program changed through `SetAttributes` after an earlier
      import): the incoming item is added under a fresh random id and
      reported as added. Keeping or overwriting by id would make Move
      disagree with Check, which compares attributes.
   3. **No match:** added under its own id, as today.

   Other attribute-identical duplicates already in the vault are left
   alone. Tests in `service/tests.rs`, native and WSL partition:
   - keep, and replace;
   - after a replace, the value read back through the index (not only the
     import status), and `created` unchanged;
   - two incoming duplicates in one archive (second kept);
   - id collision with different attributes (new id, old item untouched);
   - two existing duplicates (the first in index order is the match).

   Mutation: match by id only.
2. **Shared Secret Service reader.** Move the session-bus reader out of the
   Wi-Fi migration into `secret_service/legacy.rs`. The Wi-Fi code keeps its
   attribute-limited `find`. Two new calls:
   - `inventory` lists every collection's items (`Collections`, then
     `Items`) with attributes, label and modified time, never unlocking and
     never reading a secret.
   - `read_all` also reads secrets (`GetSecrets` in batches). It unlocks
     locked collections only when the caller asks. It does this one
     collection at a time (`Unlock`, then `Prompt` and its `Completed`
     signal), so each password-protected collection gets its own gcr
     prompt. A dismissed prompt reports that collection as skipped and the
     others continue. Desktop's Move asks for the unlock (one prompt in the
     usual case of a single `login` collection).

   Both skip the in-memory `session` collection and visit each collection
   object path once, so the `aliases/default` alias doesn't read `login`
   twice. They refuse when `org.freedesktop.secrets` is owned by FactorSeal:
   `GetConnectionUnixProcessID`, then the file name of `/proc/<pid>/exe`
   starting with `factorseal`, never a full path, since NixOS store paths
   change per build. Tests use a fake Secret Service on a private bus (zbus
   server in the test) that returns hashed attributes and the placeholder
   `xdg:schema` for a locked collection, has a second locked collection, and
   exposes the default alias. The Wi-Fi migration tests must stay green.
3. **Fingerprints and mapping.** `fingerprint(attributes)` as above, shared
   by both sides (in the library, no D-Bus). A pure mapping from read items
   to a list of entries, each with a fingerprint, plus a list of skipped
   items with reasons. Rules:
   - The id comes from the fingerprint.
   - Items with identical fingerprints across collections collapse to the
     most recently modified one; the others are reported ("duplicate").
   - Items with no attributes are skipped ("no attributes").
   - The content type defaults to `text/plain`.
   - NetworkManager items (`connection-uuid` + `setting-name`) are skipped,
     with a pointer to "Move existing Wi-Fi passwords". On a locked item the
     rule tests the hashed names, which are visible.
   - Values over the vault's secret limit are skipped ("too large"). This
     rule only applies when values are present.

   The same mapping serves the inventory (without values) and the export
   (with values), so Check and Move apply the same rules. The export's
   entries become `VaultArchiveEntry`s that pass `VaultArchive::validate`.
   Unit tests cover:
   - each rule;
   - a hashed and a plain attribute set that give the same fingerprint,
     including an integer attribute (`port=8080`) and the placeholder
     `xdg:schema` (ignored when locked, real value hashed);
   - a pinned fingerprint for a fixed attribute set, so the encoding can't
     drift silently.
4. **CLI `factorseal export-secret-service`** (Linux, `vault` feature):
   - The target is `--wsl-distro`, `--native`, or the WSL default.
   - `--inventory` prints JSON with each mapped item (fingerprint, label if
     known, modified if known, collection, locked) and the skipped ones with
     reasons. It reads no secrets and never unlocks.
   - `FILE` writes the archive with `read_archive_passphrase(…, true)` and
     `write_private_file`.
   - `--framed --passphrase-stdin` is for Desktop. The passphrase comes as
     the first line of stdin. Stdout carries one framed record (also used
     with `--inventory --framed`):
     - a start line `FACTORSEAL-FRAME v1 <kind> <length>`;
     - `<length>` bytes of base64;
     - an end line `FACTORSEAL-FRAME end`.

     For the move, the record's content is JSON: the skipped items with
     reasons, and the encrypted archive as a nested base64 field. Desktop
     ignores everything outside the frame: login-shell output, direnv or
     nix warnings, and `wsl.exe`'s own UTF-16 messages. The skip reasons
     therefore reach Desktop in a form it can read, and no secret is in
     them.

   It prints a human summary to stderr. CLI tests use the fake service and
   check the frame.
5. **Vault: keyring fingerprints for managers** (protocol v21).
   `ListKeyringFingerprints { distro: Option<String> }`, for permission
   managers only, returns each item's fingerprint, id and modified time for
   that distro's keyring (or the native one). It returns no values and no
   attributes, and is not in the broker's allowlist. Tests: manager only,
   WSL and native partitions, values never in the response, the pinned
   fingerprint from step 3. Mutation: no manager check.
6. **Desktop: check and move** (Settings → WSL keyrings, per distro row).
   - "Check gnome-keyring" runs `wsl.exe -d <distro> -- sh -lc 'exec
     factorseal export-secret-service --inventory --framed'` and compares
     the result with `ListKeyringFingerprints`.
   - "Move N items" generates a one-time passphrase: 32 characters from the
     OS random source, from an alphabet that passes `validate_new_password`
     (a test asserts that). It runs the `--framed --passphrase-stdin` form,
     takes the record out of the frame, and decrypts in memory. Then it
     restores **the whole archive** through the existing `commit_import`
     with `replace_existing = false`. Step 1 makes the items already present
     `KeptExisting`, which also covers changes between Check and Move, so
     there is no filter.
   - The report merges the restore's added and kept with the export's
     skipped reasons.
   - Errors are shown on the row:
     - no `factorseal` in the distro, with the hint "add the `factorseal`
       package"; enabling the module comes only after the move (see
       "Rollout on poita");
     - no Secret Service on the session bus (no session bus in a `wsl.exe`
       shell). With D-Bus activation the call starts gnome-keyring locked,
       so "not running" rarely happens;
     - prompt dismissed;
     - no frame in the output: shows the first lines of stderr.

   Tests cover the comparison and the command lines with a fake runner,
   including garbage and UTF-16 text before the frame and a missing frame.
   UI: the user sees it natively before it is committed.
7. **Integration check** (Linux, private bus, never the user's bus or
   keyring):
   1. A throwaway `gnome-keyring-daemon --components=secrets --unlock` (nix
      `gnome-keyring`, temporary `XDG_DATA_HOME`, short `XDG_RUNTIME_DIR`)
      runs under `dbus-run-session`. It is seeded with `secret-tool store`
      and a libsecret schema with an integer attribute.
   2. `--inventory` runs with the daemon restarted locked, then the export
      runs unlocked. The fingerprints of both runs must match.
   3. The archive is restored into a test vault.
   4. FactorSeal's host is served on that private bus, and `secret-tool
      lookup` must return each value.

   Add it to `check.sh`, or a script beside `test-with-dbus.sh`.
8. **Live, Windows test vault**: Desktop's check and move against a
   throwaway gnome-keyring in WSL, run as above on a private bus. For this,
   Desktop gets a test hook for the command prefix (`dbus-run-session` +
   daemon). The hook exists only behind a cargo feature `wsl-test-hooks`:
   never in the default features, the ZIP, or the installer release. The
   release build (installer plan, step 8) checks that its Desktop was built
   without it. A release Desktop thus has no way to run another command in
   WSL and restore its output. Then `check.sh keyring`'s host finds an
   imported item after the popup approval.
9. **Docs**:
   - `usage.md`: WSL keyring section and native Linux (check, move, the
     private-bus recipe with its short runtime dir, delete a hand-made
     archive);
   - the restore rule from step 1 in the backup docs and in `CHANGELOG.md`,
     since it changes backup restores for everyone;
   - `wsl2-keyring-design.md` decision 3 pointing here.

   Done right after step 8, before the installer work starts (see the
   installer plan's "Order with the import plan").

## Rollout on poita (with the user)

1. **system-flakes, first switch**: add only the `factorseal` package
   (`home.packages` or `environment.systemPackages`), **not**
   `services.factorseal`. Every mode of the module installs an
   `org.freedesktop.secrets` activation file, which would compete with the
   home-manager gnome-keyring, and its assertion doesn't catch that.
   gnome-keyring stays. This turns the pending `mode = "wsl"` edit into two
   edits; the user runs `just switch`.
2. **Windows**: the installer (or a manual install) puts this build in
   place. Its WSL step runs `wsl-setup` in NixOS, then it opens Desktop's
   WSL keyrings page.
3. **Desktop**: unlock, check, then move. The gcr prompt and the move are
   the user's.
4. **system-flakes, second switch**: `services.factorseal` with `mode =
   "wsl"`, gnome-keyring off. Then switch NixOS on in Desktop; programs find
   their items, each asking once in the popup.

## Notes and risks

- **Approvals**: imported items carry no per-app grants, so each program asks
  once per item at first use. That is decision 2 of the WSL keyring, and
  there may be a burst of popups on the first day.
- **Exposure**: secrets cross the local session bus in a `plain` session,
  as with the Wi-Fi migration and libsecret's default. On the `wsl.exe`
  pipe, the archive's encryption is not an exposure control: a local
  process that could read that pipe could already read Desktop's or the WSL
  process's memory. It is there for format reuse and the ready-made restore
  path, at the price of the Argon2id cost twice per move, which is
  acceptable with the default parameters. A hand-made archive on `/mnt/c`
  is readable by the Windows user's processes (encrypted), and drvfs
  ignores the 0600 mode, so the docs say to delete it after the restore.
- **Starting WSL**: only on the user's click; listing distros stays
  registry-only.
- **Step 1 changes backup restore semantics**: a backup restored into a vault
  that already has an attribute-identical item keeps the vault's one. With
  `--replace-existing` the backup's value wins, under the vault item's id.
  Documented in the backup docs and `CHANGELOG.md`.
- **Environment of a `wsl.exe` command**: `factorseal` on `PATH`, the
  session bus (`XDG_RUNTIME_DIR/bus`) and WSLg's display for the gcr prompt
  must be there in a `sh -lc` started by `wsl.exe`. Check this on poita in
  step 6 before relying on it. The frame (step 4) covers what the login
  shell prints.
- **KWallet's Secret Service interface** should work the same way, but it is
  untested; the docs name only gnome-keyring.

## Review record

The review of 2026-11-15 (against 52e7f5b) is folded in above. Each finding
and what became of it:

1. **Replace under the existing id must move the value's address.**
   Accepted. Step 1 rewrites the id and the address and keeps `created`,
   with a read-back test. `PortableItem::decode` (`:105`) confirmed.
2. **Duplicates already exist; id and attribute matches can disagree.**
   Accepted. `create_or_replace_planned` only matches attributes when
   `replace` is true (`agent.rs:336`), confirmed. Decision 4 now says it
   isn't an invariant. Step 1 fixes the order: attributes first, the first
   in index order; an id-only collision gets a fresh id. Existing
   duplicates are left alone.
3. **Check count vs. Move.** Accepted in all four parts:
   - one mapping for inventory and export (step 3);
   - "too large" known only at Move ("How it is used");
   - items with no attributes skipped ("The fingerprint");
   - the whole archive restored without a filter (step 6).

   The skip reasons travel in the frame, not as a summary entry in the
   archive, which `VaultArchive::validate` would have to learn.
4. **`wsl.exe` output in front of the archive.** Accepted: the framed
   output (step 4), with garbage-before-frame tests (step 6). Moving the
   profile's output to stderr instead was not taken; the frame is more
   robust, as the review said.
5. **The Desktop test hook must not ship.** Accepted: the cargo feature
   `wsl-test-hooks`, checked absent by the release build (step 8). The
   feature was chosen over `debug_assertions` because the live test runs a
   release-profile Windows build.
6. **Fingerprint details.**
   - The `gkr:compat:*` strip is accepted ("The fingerprint").
   - The integer-attribute concern is disproved by running the throwaway
     daemon: `port=8080` from a libsecret `INTEGER` schema hashed as
     `md5("8080")`, because the D-Bus API only carries strings (see "Facts").
     The integer case stays in the unit and integration tests as a guard.
   - The canonical encoding is now specified.
   - The same run found something the review didn't: a locked item's plain
     `xdg:schema` is a placeholder, so the fingerprint takes only the hashed
     names when locked.
7. **Rollout's first switch must add only the package.** Accepted (Rollout
   step 1). The module's every-mode activation file is confirmed in
   `nix/modules/factorseal.nix`. The installer's hint is reconciled in that
   plan.
8. **Reader details.** Accepted:
   - per-collection unlock prompts;
   - visiting each collection once (alias);
   - matching the owner by `factorseal` file-name prefix, not path;
   - the error renamed "no Secret Service on the session bus".
9. **The archive encryption on the pipe is not an exposure control.**
   Accepted:
   - "Notes and risks" says so;
   - the passphrase is 32 random characters that must pass
     `validate_new_password` (confirmed at `archive.rs:151`), with a test;
   - the double Argon2id cost is noted as acceptable.
10. **Ordering and cross-references.** Accepted:
    - docs placed after step 8, in both plans' order;
    - `CHANGELOG.md` added;
    - the row hint says "add the package".

The review's deliberate exclusions stay out of scope here as well:
- KWallet;
- MD5's cryptographic strength, which isn't relied on;
- the Check/Move row's copy and layout, left to the native review;
- native Linux Desktop's restore UX for `--native`, which stays the manual
  path.
