# Plan: move gnome-keyring items into FactorSeal

Status, 2026-11-15: steps 1–5 and 7 implemented (de2780e..3b49775), then
the implementation review acted on (fc49f02..3555cbd), the review of
those fixes (cbada0a..d03d54a), a third review (bf0e7e6..b927d1b) and a
fourth (after b927d1b); step 6 implemented (b3429f9, 6539cb5) and its
review acted on (4cfeaa0..84ef1d7, see "Step 6 review"), then a review
of those fixes (1b1ab6d..8cfd413, "Step 6 fixes review"); steps 8 and 9
remain. All reviews
are folded in (see "Review record" and "Implementation
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
  - **The plain `xdg:schema` of a locked item is a placeholder, except for
    the generic schema.** It reads `org.freedesktop.Secret.Generic` for
    every item. An item stored with schema `test.int` showed that
    placeholder plainly and `md5("test.int")` = `7675a45f…` under
    `gkr:compat:hashed:xdg:schema`. An item stored with the generic schema
    (as `secret-tool store` does) has no hashed `xdg:schema` at all: its
    plain one is the real value. (Corrected 2026-11-15 by
    `scripts/test-keyring-import.sh`, step 7: the locked and unlocked
    fingerprints of a `secret-tool` item disagreed until the plain
    `xdg:schema` counted when no hashed one exists.)
  - **Integer attributes hash like text.** A libsecret `INTEGER` attribute
    `port=8080` reaches the daemon as the string `"8080"` (the Secret
    Service API only carries `a{ss}`) and is hashed as `md5("8080")` =
    `d4a973e3…`. gnome-keyring's uint32 compat hashing only applies to items
    from its legacy file format, which libsecret over D-Bus never creates.
  - **Items stored without a schema get the generic one.** An item stored
    with no `xdg:schema` (as go-keyring, which `gh` uses, and
    python-keyring do) comes back with `xdg:schema =
    org.freedesktop.Secret.Generic`, and its locked and unlocked
    fingerprints agree (implementation review, checked with Python
    `secretstorage`; step 7 now seeds such an item through libsecret).
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
  `(<name>, its hash)`. The plain `xdg:schema` gives `(xdg:schema,
  md5(value))` only when there is no `gkr:compat:hashed:xdg:schema` (the
  generic schema, which gnome-keyring leaves unhashed); otherwise it is the
  placeholder and is ignored. Every other attribute is ignored. A locked
  item is recognized by its hashed names, not by `Locked`: a collection
  locked again after an unlock shows plain attributes.
- **gnome-keyring, unlocked:** each attribute gives `(name,
  md5(value))`. Names starting with `gkr:compat:` are left out
  (gnome-keyring reserves them; this is defensive).
- **The vault:** the same plain rule (`vault_keyring_fingerprint`), never
  the locked one, over **every** attribute, `gkr:compat:*` included:
  FactorSeal's Secret Service doesn't reserve the prefix, so a vault item
  may carry such a name, and a restore compares the whole attributes
  (step 1). Leaving the names out made Check count an item as present
  that Move then added (step 6 review S6-4).

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
      import): the incoming item is added under an id derived from its own
      (`relocated_keyring_id`: SHA-256 under a tag, the next link in the
      chain while that is taken too) and reported as added. Derived, not
      random, so a restore of the same backup finds it there again; and
      not recorded in a new index field, since `Index` and `IndexItem`
      refuse unknown fields and older builds would reject the keyring. Keeping or overwriting by id would make Move
      disagree with Check, which compares attributes.
   3. **No match:** added under its own id, as today.

   An incoming item **without attributes** answers no lookup, so rule 1
   doesn't apply to it. It walks its id's whole relocation chain
   (`relocation_chain`, up to 64 links): the first attribute-less item on
   it is the match, past free ids too, since an item it moved past may
   have been deleted since; ids held by items with attributes are passed
   over; the first free id is where it is added when nothing matches. So
   its own copy is found on every restore, moved or not, and no unrelated
   item can stand in for it. (Matching by label, content type and
   creation time, tried in 94a0252 and cbada0a, let an unrelated
   look-alike from the same backup match: fixes review N1, third review
   R1.) An item with attributes computes its chain only when no item has
   its attributes, and stops at the first free id.

   **Known limitation** (fourth review F1, accepted): a backup holding an
   attribute-less item at an id and another at that id's relocated id
   (both from one item's history in the source keyring: a relocation, a
   deletion and another restore there), restored where an item with
   attributes holds the id, keeps only one of them (the other is kept
   existing, or with `replace_existing` overwrites it). Deriving the
   relocated id from the label and times as well would avoid it, but then
   a backup restored again after a label change adds a copy, a far more
   common case. A test pins the behaviour so a change to it is
   deliberate.

   Other attribute-identical duplicates already in the vault are left
   alone. Tests in `service/tests.rs`, native and WSL partition:
   - keep, and replace;
   - after a replace, the value read back through the index (not only the
     import status), and `created` unchanged;
   - two incoming duplicates in one archive (second kept);
   - id collision with different attributes (new id, old item untouched);
   - two existing duplicates (the first in index order is the match);
   - attribute-less items: matched by id only, a re-restore whose id is
     taken adds one copy, two different items with one label and time are
     both added (with and without `replace_existing`), the exact id wins
     over a look-alike earlier in the index, and an item whose id is taken
     is added beside a look-alike from the same backup and found again on
     a second restore; an item found past a freed link of its chain (the
     item at its id deleted, or a middle link); the known limitation,
     pinned.

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
   starting with `factorseal` once Nix's wrapper naming is undone (leading
   dots and repeated `-wrapped`: a NixOS Desktop runs as
   `.factorseal-desktop-wrapped`), never a full path, since NixOS store
   paths change per build. A non-dumpable owner hides `/proc/<pid>/exe`
   even from its own user: NixOS's gnome-keyring runs through a capability
   wrapper (`cap_ipc_lock`), and FactorSeal's own agent drops dumpability
   (`harden_key_owner`). Then `/proc/<pid>/comm` and the program in
   `/proc/<pid>/cmdline` decide, FactorSeal if either looks like it.

   Before looking up the owner, the export calls `StartServiceByName`
   (step 6 review S6-1): `GetNameOwner` never activates, and gnome-keyring
   is often only D-Bus-activatable (poita, right after WSL starts the
   distro). It starts locked, so nothing is asked. dbus-daemon answers
   `ServiceUnknown` without a service file even while the name has an
   owner (seen on the test bus), so that answer leaves the owner lookup to
   decide. In a distro already switched to FactorSeal's keyring the
   activation file is FactorSeal's, so this starts FactorSeal's own
   service and the export then refuses it ("is FactorSeal itself"):
   accepted, since any libsecret client there starts the same service and
   the export reads nothing from it; Desktop names the case (fixes review
   F6-2).

   An unlock prompt unanswered for five minutes is dismissed
   (`Prompt.Dismiss`) and its collection reported as "unlock timed out": a
   gcr prompt with no display never appears, and the wait would never end.
   The Dismiss itself is best effort and bounded to five seconds. Prompts
   run one collection after another, so the whole read can take five
   minutes and five seconds per locked collection.

   Tests use a fake Secret Service on a private bus (zbus
   server in the test) that returns hashed attributes and the placeholder
   `xdg:schema` for a locked collection, has a second locked collection, and
   exposes the default alias. The Wi-Fi migration tests must stay green.
3. **Fingerprints and mapping.** `fingerprint(attributes)` as above, shared
   by both sides (in the library, no D-Bus). A pure mapping from read items
   to a list of entries, each with a fingerprint, plus a list of skipped
   items with reasons. Rules:
   - The id comes from the fingerprint.
   - Items with identical fingerprints across collections collapse to one;
     the others are reported ("duplicate"). The inventory keeps the most
     recently modified (the first seen on a tie). The export keeps the most
     recent one that passes the value rules, so an unreadable or too large
     newest item doesn't lose an older readable one. Newer items passed
     over that way report their own reason ("unreadable", "too large"), so
     the report shows that an older value moved; older ones report
     "duplicate". When none passes, each reports its own reason.
   - Items with no attributes are skipped ("no attributes").
   - The content type defaults to `text/plain`.
   - NetworkManager items (`connection-uuid` + `setting-name`) are skipped,
     with a pointer to "Move existing Wi-Fi passwords". On a locked item the
     rule tests the hashed names, which are visible.
   - Values over 256 KiB (`MAX_IMPORTED_VALUE_BYTES`) are skipped ("too
     large"). The vault has no per-secret limit; 256 KiB is what still fits
     one restore request (the value is base64-encoded twice, ≈1.78×, in a
     1 MiB message). This rule only applies when values are present.

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

   It prints a human summary to stderr. CLI tests run the command with an
   injected reader (a closure standing in for the Secret Service) and check
   the frame; the D-Bus reader itself is tested against the fake service of
   step 2.
5. **Vault: keyring fingerprints for managers** (protocol v21).
   `ListKeyringFingerprints { distro: Option<String>, cursor:
   Option<String> }`, for permission managers only, returns each item's
   fingerprint, id and modified time for that distro's keyring (or the
   native one), sorted by id, as many as fit one response, with
   `next_cursor` (the last id) when more remain. The cursor must be a
   32-hex id in either case, as item ids are (`IndexItem::validate`);
   pages are cut and sorted by plain byte order, and the cursor is an id
   the vault returned, so it resumes exactly (step 6 review S6-5, which
   took back the lowercase-only rule of D2). It
   returns no values and no attributes, and is not in the broker's
   allowlist. Tests: manager only,
   WSL and native partitions, values never in the response, the pinned
   fingerprint from step 3. Mutation: no manager check.
6. **Desktop: check and move** (Settings → WSL keyrings, per distro row).
   - "Check gnome-keyring" runs `wsl.exe -d <distro> --exec sh -lc 'exec
     factorseal export-secret-service --inventory --framed'` and compares
     the result with `ListKeyringFingerprints`. `--exec`, not `--`: with
     `--`, WSL hands the command line to the user's login shell (zsh on
     poita), which parses and expands it before `sh` runs; `--exec` runs
     `sh` directly (seen on poita, 2026-11-15). Desktop starts `wsl.exe`
     from Rust with standard Windows argument quoting, to be checked
     natively (PowerShell 5.1's own quoting of native arguments mangles
     embedded quotes, so it is no guide).
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
       shell). With D-Bus activation the call starts gnome-keyring locked
       (since S6-1's fix), so "not running" rarely happens;
     - prompt dismissed;
     - no frame in the output: shows the first lines of stderr.

   Tests cover the comparison and the command lines with a fake runner,
   including garbage and UTF-16 text before the frame and a missing frame.
   UI: the user sees it natively before it is committed.

   From the implementation review:
   - the CLI dismisses a prompt after five minutes (step 2), so Desktop
     only needs a backstop on the `wsl.exe` child, killed on cancel too.
     It must exceed five minutes times the number of locked collections
     (prompts run one after another), plus Dismiss's five seconds each,
     with the count taken from the Check's inventory, not a constant;
   - a collection skipped as "unlock timed out" is shown apart from one
     whose prompt was dismissed;
   - the result shows a newer item skipped as "unreadable" or "too large"
     beside an older duplicate that moved (step 3), not as a duplicate;
   - the frame parser accepts `\r\n` and garbage before
     `FACTORSEAL-FRAME` on the same line, and checks `<length>` exactly;
   - read `ListKeyringFingerprints` page by page until `next_cursor` is
     absent;
   - the protocol is 21: Desktop and the CLI must come from the same build
     (the ZIP and installer ship both; a hand-updated CLI against an old
     Desktop fails);
   - Check compares fingerprints; the collection and label shown for a
     duplicate can differ between Check (first seen, no modified times
     while locked) and Move (newest usable), so the UI doesn't key on the
     collection.

   As implemented (b3429f9, 6539cb5; `factorseal-desktop/src/wsl_keyring_import.rs`):
   - The command also passes `--wsl-distro $1`, with the distro as
     `sh`'s positional argument (`sh -lc '<script>' sh <distro>`), so the
     archive is always for the keyring Desktop compared against. The
     distro is never pasted into the script, and no quote reaches
     `wsl.exe`'s command-line parsing; distro names (letters, digits,
     `.`, `-`, `_`) stay one word unquoted.
   - The backstop counts every collection the inventory visited (field
     `collections`, e851d9f), with the locked ones (`locked_collections`,
     b3429f9: empty ones prompt too) and the items' collections, at least
     one: any collection may be locked by the time of the Move (S6-3). A
     record from an older CLI gives the items' collections. The limit is
     three minutes (also the inventory's) plus five minutes five seconds
     per collection. `locked_collections` alone decides whether the row
     says that moving asks for gnome-keyring's password.
   - Desktop refuses a record whose `target` isn't `wsl:<distro>`, and an
     archive holding any entry outside that distro's keyring (another
     partition or document kind): otherwise a process in the distro could
     add any vault entry through a manager's restore.
   - The one-time passphrase is the personal generator's random style,
     32 letters and digits.
   - Errors: exit 127 (no `factorseal`), "no Secret Service" or "no
     session bus" ("none can be started there"), "is FactorSeal itself"
     ("already uses FactorSeal's keyring", F6-2), "unrecognized
     subcommand" (a CLI too old), else the CLI's own lines (`factorseal:`
     or `error:`), or the last three lines, of stderr, or of stdout when
     stderr is empty (where `wsl.exe` writes its UTF-16 messages). A login
     shell's output comes first and the CLI's error last (S6-6).
   - Cancel kills `wsl.exe`; a cancel that arrives after the archive was
     decrypted no longer stops the restore. A restore that fails, after
     a late cancel too, shows its error, and the vault is read again
     after any Move that reached the restore, since a failed one may have
     added items (S6-7).
   - The frame parser looks for a header's newline only within 64 bytes,
     and checks a body against the base64 alphabet before decoding it
     (the decoder first zeroes a buffer the size of the body), so its scan
     is linear (S6-2, F6-1). `wsl.exe`'s stderr is kept as its last 64
     KiB, where the CLI's error is (F6-3); its stdout up to
     `MAX_KEYRING_FRAME_BYTES` (512 MiB of frame body) plus a MiB, a limit
     the CLI shares and refuses to exceed with an error the row shows
     (F6-4). Output past a cap is read to the end and dropped, so the
     child isn't blocked on a full pipe (S6-8).
   - Sealed: the buttons are disabled and a note asks for the unlock;
     the page doesn't start one itself.
   - After a move Desktop reads the vault again, so the moved items show
     under System keyring.
   - Known gap: the text under a row is not exposed to UI Automation,
     like the page's other notes.
   - Seen natively (2026-11-15, test vault): the Check reached poita's
     installed CLI through `wsl.exe` with its arguments intact and showed
     "cannot identify the Secret Service: Permission denied", as expected
     from 5dffff3 (before 4d5dde5). A successful native Check needs the
     NixOS input past 4d5dde5; Move is left to step 8.
7. **Integration check** (Linux, private bus, never the user's bus or
   keyring):
   1. A throwaway `gnome-keyring-daemon --components=secrets --unlock` (nix
      `gnome-keyring`, temporary `XDG_DATA_HOME`, short `XDG_RUNTIME_DIR`)
      runs under `dbus-run-session`. It is seeded with `secret-tool store`
      and a libsecret schema with an integer attribute, and an item created
      through libsecret with no schema (which gnome-keyring then reports
      with the generic one).
   2. `--inventory` runs with the daemon restarted locked, again on a
      collection locked again after an unlock, then the export runs
      unlocked. The fingerprints of all three runs must match.
   3. The archive is restored into a test vault.
   4. FactorSeal's host is served on that private bus, and `secret-tool
      lookup` must return each value.

   Done as `scripts/test-keyring-import.sh`. The restore uses the
   library's test vault (mock key protector) through an ignored lib test,
   `restored_gnome_keyring_archive_is_found_by_secret_tool`, since a Linux
   `factorseal init` needs a TPM; it still goes through `ImportVaultEntry`.
   After the implementation review it also seeds a schema-less item,
   compares an inventory of a collection locked again after an unlock, and
   restores a second time (everything kept).
8. **Live, Windows test vault**: Desktop's check and move against a
   throwaway gnome-keyring in WSL, run as above on a private bus. For this,
   Desktop gets a test hook for the command prefix (`dbus-run-session` +
   daemon). The hook exists only behind a cargo feature `wsl-test-hooks`:
   never in the default features, the ZIP, or the installer release. The
   release build (installer plan, step 8) checks that its Desktop was built
   without it. A release Desktop thus has no way to run another command in
   WSL and restore its output. Then `check.sh keyring`'s host finds an
   imported item after the popup approval. If the hook relies on D-Bus
   activation inside `dbus-run-session`, the activated daemon gets the
   bus daemon's environment, not the script's: set `HOME`,
   `XDG_DATA_HOME` and a short `XDG_RUNTIME_DIR` before
   `dbus-run-session`, or in the service file's `Exec` as
   `scripts/test-keyring-import.sh` does, or it opens the real
   `~/.local/share/keyrings` (step 6 review S6-1).
9. **Docs**:
   - `usage.md`: WSL keyring section and native Linux (check, move, the
     private-bus recipe with its short runtime dir, delete a hand-made
     archive);
   - the restore rule from step 1 in the backup docs and in `CHANGELOG.md`,
     since it changes backup restores for everyone (no release from this
     branch before that); the attribute-less rule as it stands after the
     third review's R1 and the fourth review's F2 (the whole relocation
     chain), not 94a0252's or cbada0a's, with F1's known limitation;
   - the native recipe only now that a Nix-wrapped Desktop is recognized as
     FactorSeal (implementation review D1);
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
   edits; the user runs `just switch`. Done 2026-11-15 (factorseal input
   at 5dffff3; the full edit kept as a system-flakes stash). That build
   lacks 4d5dde5, so the installed CLI refuses NixOS's gnome-keyring
   ("Permission denied") until the input is bumped past it.
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
  must be there in a `sh -lc` started by `wsl.exe`. Checked on poita
  (2026-11-15, after the package-only switch), from PowerShell through
  `wsl.exe -d NixOS --exec sh -lc …`: `factorseal` at
  `/run/current-system/sw/bin`, `XDG_RUNTIME_DIR=/run/user/1000`,
  `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus` (socket present),
  `DISPLAY=:0`, `WAYLAND_DISPLAY=wayland-0`; `factorseal` is on `PATH`
  without `-l` too. The inventory came framed, with nothing before the
  frame. The gcr prompt itself is untested (the collection was
  unlocked); step 8 covers it. The frame (step 4) covers what the login
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

## Implementation record

Steps 1–5 and 7, 2026-11-15, each with tests seen failing first or a
mutation, and the gate:

| Commit | Step |
|---|---|
| de2780e | 1: restore matches keyring items by attributes |
| 314bdb4 | 2: shared Secret Service reader (`inventory`, `read_all`) |
| 29b8409 | 3: fingerprints and mapping (`md-5` added) |
| 2eb657e | 4: `factorseal export-secret-service` |
| 5f66822 | 5: `ListKeyringFingerprints`, protocol v21 |
| 1fdad6a | test fix: the id-collision test no longer assumes an id order |
| b0b7a9e | fix found by step 7: a locked generic item's plain `xdg:schema` counts |
| 3b49775 | 7: `scripts/test-keyring-import.sh` |
| b3429f9 | 6: the inventory names its locked collections; import types deserialize |
| 6539cb5 | 6: Desktop's Check and Move |
| 4cfeaa0 | step 6 review S6-1: start an activatable Secret Service |
| 0c3c6a2 | S6-2: linear frame scan |
| e851d9f | S6-3: Move's limit counts every collection |
| 44f2080 | S6-4: the vault's fingerprint keeps `gkr:compat:*` names |
| c36c048 | S6-5: the cursor follows the item-id rule |
| e45811d | S6-8: stderr cap, drain past the caps |
| 3750863 | S6-6: the CLI's own error line on the row |
| 84ef1d7 | S6-7: a failed restore is reported and the vault read again |
| 1b1ab6d | fixes review F6-1: base64 check before decoding a frame body |
| f73a05e | F6-3: keep the end of stderr |
| 8cfd413 | F6-4: one frame limit shared by the CLI and Desktop |
| (pending) | F6-2: Desktop names a distro on FactorSeal's keyring (uncommitted until the user's OK) |

`fuzz/Cargo.lock` gained only the `md-5` entry; it already failed
`cargo metadata --locked` at 4ed2d2d (missing `embed-resource`), which is
left for a separate fix.

Step 6's gate: fmt, workspace clippy, lib 557 passed, 0 failed, 6 ignored,
CLI 93 passed, Desktop 204 passed, 1 ignored;
`scripts/test-keyring-import.sh` passes; natively on Windows, clippy,
Desktop 189 passed, 1 ignored, and the WSL relay's 14. The library test
failed before its fix; the Desktop tests were written with the code and
checked by mutation instead (no exact frame length, no entry check, no
target check, every item missing, one fingerprint page): each fails a
test. The exact-length mutation first survived, since base64 and the end
line also reject most wrong lengths; cases off by a whole base64 group
and with the end marker glued to the body now catch it.

### Implementation review

An independent review of de2780e..3b49775 (2026-11-15) was acted on
point by point; this records every point, so the review file was
removed. Gate after the fixes: fmt, clippy, lib 546 passed, 1 failed
(`libsecret_store_seal_lookup` times out, as on main), CLI 93 passed;
`scripts/test-keyring-import.sh` passes.

**Defects**
- **D1, medium: a Nix-wrapped Desktop wasn't recognized as FactorSeal.**
  Fixed in fc49f02. Confirmed in nixpkgs'
  make-binary-wrapper-hook (`hidden="$(dirname "$prog")/.$(basename "$prog")"-wrapped`). The
  name is unwrapped before the prefix test; unit test of the names (the
  review's T3), and the old check fails it.
- **D2, low: an uppercase cursor paged wrongly.** Fixed in 1eae96c: lowercase only;
  test fails against the old check.
- **D3, low: a re-restored attribute-less item whose id is taken was
  copied again.** Fixed in 94a0252 with the review's first option (match by label,
  content type and created time); the second (always keep) was rejected,
  since it drops the backup's item and clients can still enumerate a
  collection's items. Test fails before the fix. The label match itself
  lost data and was replaced by the relocation chain (fixes review N1,
  third review R1).
- **D4, low: a readable older duplicate was lost to an unusable newest
  one.** Fixed in 711c208, in the export; the inventory still keeps the newest. Test
  fails before the fix.
- **D5, low: the vault guessed gnome-keyring's hashed mode.** Fixed in 0ca5554:
  `vault_keyring_fingerprint` always takes the plain rule. Test failed
  before the fix with an empty list.

**Conformance**
- **C1: the unlock prompt had no time limit.** Fixed in 4dddc4e, in the CLI (five
  minutes, then `Prompt.Dismiss`, "unlock timed out"); step 6 keeps a
  backstop. The fake gains a prompt that never completes; without the
  Dismiss call the test fails.
- **C2: CLI tests use an injected reader, not the fake service.** No
  change: together with step 2's fake-service tests they cover the same
  ground. Step 4 now says so.
- **C3: step 1 changes every backup restore; not yet in `CHANGELOG.md`.**
  Left to step 9, as planned; step 9 now says no release from this branch
  before it.

**Deviations** (all accepted by the review except 3 on the vault side)
1. Attribute-less items match by id, now with D3's rule: step 1.
2. `cursor` on `ListKeyringFingerprints`, lowercase only (D2): step 5.
3. Hashed mode chosen by hashed names: kept for gnome-keyring, removed on
   the vault side (D5): "The fingerprint".
4. A locked item's plain `xdg:schema` counts without a hashed one: kept;
   the review's run also showed that an item a client stores with no
   schema is reported by gnome-keyring with the generic one (in "Facts",
   and seeded in step 7, which stores it with none).
5. 256 KiB "too large": step 3.
6. Injected CLI reader: step 4 (C2).
7. Step 7 restores into the library's test vault: step 7.
8. `fuzz/Cargo.lock` with only `md-5`: above, separate fix.

**Test quality**
- **T1: reader tests pass vacuously outside the private bus.** That is the
  repo's convention (`private_bus()`, like the Wi-Fi tests). Every
  mutation of the reader, the original step 2 ones included, ran under
  `scripts/test-with-dbus.sh`; the C1 and T2 mutations failed there.
- **T2: no `GetSecrets` batch boundary.** Added in 1c48fe3: 33 items, two calls, all
  values; reading one batch fails it.
- **T3: the owner test couldn't catch D1.** Covered by D1's name test.
- **T4: step 7 lacked idempotence, the locked-again mode and a schema-less
  item.** Added all three in 3555cbd; with the restore never matching, the second
  pass fails.
- **T5: step 7 isolation holds.** No change.
- **T6: the pinned fingerprint ties the unit tests to the real daemon.**
  No change.

**Risks**
- **R1–R4 (step 6):** the backstop limit on `wsl.exe`, frame parsing,
  protocol 21 across builds, not keying the UI on the collection: in step
  6.
- **R5 (step 9):** the native recipe needed D1, now fixed: in step 9.
- **R6 (step 8):** nothing blocks `wsl-test-hooks`. No change.

### Fixes review

An independent review of fc49f02..7914db9 (2026-11-15) found that each
fix resolved its finding, and that D3's fix caused a new defect. Every
point and what became of it, so the review file was removed. Gate after
the fixes: fmt, clippy, lib 550 passed, 1 failed, 6 ignored
(`libsecret_store_seal_lookup` times out, as on main), CLI 93 passed; `scripts/test-keyring-import.sh` passes.

**New defects**
- **N1, medium: D3's label match dropped or overwrote a different
  attribute-less item** when its own id was free, and a look-alike earlier
  in the index beat the exact id. The reviewer showed it with a temporary
  test (`Added KeptExisting items=1`; with replace, the first item's value
  overwritten). Partly fixed in cbada0a (`attribute_less_match`, step 1),
  with the two tests of Q1, which failed before: the free-id case was
  fixed, the taken-id case was not (third review R1, fixed in bf0e7e6).
- **N2, low: newer duplicates passed over for the value rules were
  reported as "duplicate".** Fixed in 90e37b7: they report their own
  reason (step 3). The extended test failed before.
- **N3, low: the Dismiss after a timeout waited without a limit.** Fixed in
  b154670: five seconds. A fake whose Dismiss never replies held the read
  until the test's guard before the fix.

**Checked and fine:** D1 (unwrapping can't let a non-FactorSeal name
through; a process started through `ld-linux` is still missed, outside the
finding and unlikely for Desktop, so nothing changed), D2, D5, D4's order
on ties, C1's timer, T2, T4 (the script passes, run by the reviewer).

**Declined or answered points of the first review:** all judged justified
(D3's second option, C2, C3, T1, T3, T5, T6, R1–R6, deviation 8). For
deviation 8 the reviewer suggests a tracking issue for `fuzz/Cargo.lock`;
not opened, since filing on GitHub is the user's call.

**Plan accuracy**
- **P1:** step 1 described the flawed rule and missed the re-restore
  test. Rewritten with N1's rule and its tests.
- **P2:** step 6 now sizes the backstop (five minutes per locked collection
  plus Dismiss), shows "unlock timed out" apart from "dismissed", and shows
  N2's reasons in the result.
- **P3:** deviation 4 now says the client stores no schema and
  gnome-keyring reports the generic one; step 7's list names the
  schema-less seed and the relocked inventory.
- **P4:** the nixpkgs line in D1's record is now verbatim.
- The record lists every finding of the first review (checked by the
  reviewer).

**Test quality**
- **Q1:** exact id over a look-alike: added with N1.
- **Q2:** a prompt answered within the limit still unlocks: added in
  b154670.

**Risks:** step 6 gets P2 and N2's result note; step 8 nothing new; step 9
documents step 1's rule as fixed by N1 (in step 9).

### Third review

An independent review of cbada0a..d03d54a (2026-11-15) found that N2 and
N3 resolved their findings and N1 didn't fully. Every point and what
became of it, so the review file was removed. Gate after the fixes: fmt,
clippy, lib 551 passed, 1 failed, 6 ignored (`libsecret_store_seal_lookup`
times out, as on main), CLI 93 passed; `scripts/test-keyring-import.sh`
passes.

**Fix that didn't resolve its finding**
- **R1, medium: N1's look-alike rule still lost data when the incoming id
  was taken.** With an item with attributes at `11…1`, a backup's `b`
  (`22…2`) and `a` (`11…1`), both attribute-less, "Unnamed", one creation
  time, restored as `Added KeptExisting` (`a` lost), or with replace as
  `Added Replaced` (`b` overwritten); the reviewer ran it on both
  partitions. Fixed in bf0e7e6 with the relocation chain (step 1). The
  reviewer's suggested `restored_from` field was not taken: `Index` and
  `IndexItem` are `#[serde(deny_unknown_fields)]`
  (`secret_service_data.rs`), so an index written with it would make
  older builds reject the whole keyring; a derived id is as exact and
  changes no format. Its regression test (TQ2) failed before; relocating
  at random again fails it and the re-restore test.

**New defects:** none besides R1 (cbada0a, 90e37b7 and b154670 change only
what they say).

**Left alone: a FactorSeal started through `ld-linux` isn't recognized.**
Judged justified (the unwrapping can't let a non-FactorSeal name through;
no packaging launches it that way). The suggested note next to the
unwrapping is in 9a98b33.

**Checked and fine:** N2's choice of reasons (the `Duplicate` fallback is
unreachable for newer items; counts unchanged), N3 (bounded Dismiss,
separate from the unlock limit, 5 min + 5 s per locked collection), Q2,
the record's hashes and its completeness.

**Plan accuracy**
- **PA1:** step 1 and step 9 now describe the relocation chain, and the
  N1 and D3 entries say the label match was replaced.
- **PA2:** step 2 says five minutes and five seconds per locked
  collection.
- **PA3:** the reviewer counted 557 lib tests at d03d54a against the
  record's "550 passed, 1 failed": the record left out the 6 ignored
  (550 + 1 + 6 = 557). Gate lines now give all three counts.
- N1's entry now says partly fixed.

**Test quality**
- **TQ1:** the wedged-Dismiss test checks that the Dismiss was sent
  (dropping it fails the test) and closes the session: bf0e7e6.
- **TQ2:** R1's regression test: bf0e7e6.

**Risks:** step 6 takes the backstop's collection count from the
inventory (in step 6); step 8 nothing new; step 9 documents the rule after
R1 (in step 9).

### Fourth review

An independent review of bf0e7e6..b927d1b (2026-11-15), asked to report
behaviour only, found R1 fixed and two low-severity gaps, both shown with
temporary tests on both partitions. Every point and what became of it, so
the review file was removed. Gate after the fix: fmt, clippy, lib 553
passed, 1 failed, 6 ignored (`libsecret_store_seal_lookup` times out, as
on main), CLI 93 passed; `scripts/test-keyring-import.sh` passes.

- **F1, low: two attribute-less items of one backup, one at an id and one
  at its relocated id, can merge** when an item with attributes holds the
  id in the target (`Added, KeptExisting`, or `Added, Replaced` with
  replace, in either order). Accepted as a known limitation, as the
  reviewer recommended (step 1 gives the trade-off), and pinned by
  `known_limitation_one_lineage_items_of_one_backup_can_merge` in 8d3d08c,
  which reproduced the reviewer's result. Not a regression against a
  release: the random relocation it replaced was never released
  (installed build e226a2e).
- **F2, low: a freed link made the next restore add a duplicate** (a
  middle link deleted; or the item at the id itself, which predates
  bf0e7e6). Fixed in 8d3d08c: an attribute-less item walks the whole
  chain, ids looked up in a map. The new test failed before; stopping at
  the first free id again fails it.
- **Chain limit (checked, no finding):** the 64-link error could refuse an
  item with attributes that matched by attributes, with a hand-crafted
  backup only. 8d3d08c computes such an item's chain only after the
  attribute match fails, which also removes the unreachable "matched
  inconsistently" branch.
- **Checked, no finding:** `replace_existing` never overwrites items with
  attributes on a chain; restores in either order are stable after the
  first pass (run); derived ids are 32 lowercase hex and the index format
  is unchanged; gnome-keyring imports (always with attributes, ids under
  another tag) can't collide with relocated ids; 9a98b33 and b927d1b
  change no behaviour.

### Step 6 review

An independent review of 07b7fee..6539cb5 (2026-11-15, at e7c3020),
asked to report observed behaviour only, found eight points. Every point
and what became of it, so the review file was removed. Gate after the
fixes: fmt, workspace clippy, lib 557 passed, 1 failed, 6 ignored
(`libsecret_store_seal_lookup` times out, as on main), CLI 93 passed,
Desktop 209 passed, 1 ignored; `scripts/test-keyring-import.sh` passes;
natively on Windows, clippy, Desktop 194 passed, 1 ignored, and the WSL
relay's 14.

- **S6-1, high (ran): Check said there was no gnome-keyring when it was
  only D-Bus-activatable.** Fixed in 4cfeaa0 (step 2). The script's new
  phase, gnome-keyring only activatable through a service file, failed
  before with "no Secret Service on the session bus". The first fix took
  the reviewer's `ServiceUnknown` → "no Secret Service" and broke the
  plain locked phase: run on the test bus, dbus-daemon answers
  `ServiceUnknown` without a service file even while gnome-keyring owns
  the name, so that answer now falls through to the owner lookup.
  Desktop's message says none can be started (with S6-6). The reviewer
  reproduced it with an activated daemon that took the bus daemon's
  environment and listed the user's real keyring, locked (no unlock, no
  secrets, nothing written; mtimes checked unchanged afterwards): the
  script's service file sets the throwaway directories in its `Exec`,
  and step 8 carries the caution.
- **S6-2, medium (ran): quadratic frame parser.** Fixed in 0c3c6a2 (step
  6). The test (1.3 MB of markers; 16384 candidates whose lengths all end
  at one end line) took 64 s before. A base64 check before decoding,
  for the overlapping candidates, was tried and dropped because its
  mutation survived. That was wrong: the test was too small, and glibc
  hides the decoder's zeroed buffer; the fixes review (F6-1) measured it
  on Windows, and 1b1ab6d restores the check.
- **S6-3, medium (read): Move's limit fell to 3 minutes when a
  collection locked after Check.** Fixed in e851d9f (step 6, the inventory
  lists every collection).
- **S6-4, low (ran): Check and Move disagreed on a vault item with a
  `gkr:compat:*` name.** Fixed in 44f2080 with the reviewer's second
  option, which keeps step 1's matching ("The fingerprint"). The D5 test,
  which pinned the old rule, became the new one and failed before.
- **S6-5, low (ran): an uppercase id at a page end broke every later
  Check.** Fixed in c36c048 (step 5) by accepting either case in the
  cursor, rather than refusing or lowering such ids on import: they are
  valid ids today, and lowering one would move it under the matching
  chain of step 1. The test pages over 9100 mixed-case ids and failed
  before at the reviewer's cursor.
- **S6-6, low (read): the error shown was the first three stderr lines.**
  Fixed in 3750863: the CLI's own lines, else the last three. Tests
  with three warnings before the error failed before.
- **S6-7, low (read): a Move failing in the restore hid what it did.**
  Fixed in 84ef1d7: `move_items` reports whether the restore ran and
  whether the failure is the cancellation itself; the vault is read again
  after any Move that reached the restore, and an error after a late
  Cancel is shown. Mutations of either flag fail the new tests.
- **S6-8, low (read): output caps allowed ~2 GiB.** Fixed in e45811d.
  Reading the runner for it showed it stopped reading at the cap, leaving
  a child blocked on a full pipe until the time limit; output past a cap
  is now drained, with a test that fails without it. The fixes review
  found two side effects of the caps, F6-3 and F6-4.

**Checked and fine** (the reviewer's list, not repeated here in full): the
gate at e7c3020; the parser's functional rules; the record and archive
checks before restore; `replace_existing = false`; `wsl.exe` killing,
pipes, stdin EOF, argument passing, exit 127 and its UTF-16 messages
(run from PowerShell with the same Win32 calls); 20,000 passphrases;
`locked_collections`; the backstop arithmetic; paging; the UI's stale-run
guard.

### Step 6 fixes review

An independent review of the fixes 4cfeaa0..84ef1d7 (2026-11-15, at
ab9de61), behaviour only, on private buses (the user's `Default.keyring`
mtime equal before and after, checked again here). Its verdict: S6-1,
S6-3, S6-4, S6-5, S6-6 and S6-7 resolved, S6-2 partly, S6-8 resolved
with two side effects; four findings. Every point and what became of it,
so the review file was removed. Gate after the fixes: fmt, workspace
clippy, lib 557 passed, 1 failed, 6 ignored (`libsecret_store_seal_lookup`
times out, as on main), CLI 94 passed, Desktop 211 passed, 1 ignored;
`scripts/test-keyring-import.sh` passes; natively on Windows, clippy,
Desktop 196 passed, 1 ignored, and the WSL relay's 14.

- **F6-1, medium (ran): the frame scan was still quadratic.** Every
  candidate ending at an end line reached `STANDARD.decode`, which
  allocates and zeroes a buffer the size of the body before reading it;
  natively on Windows, 477 MB of output held the parser for 82–110 s.
  Fixed in 1b1ab6d with the reviewer's first option, the base64 check
  before decoding. The test repeats a 30,000-candidate window 20 times
  (22 MB): natively on Windows it took 4.9 s without the check and
  fails; on Linux it passes either way (glibc's fresh zero pages), so
  `build-windows.sh check` is where it guards the fix.
- **F6-2, low (ran): on a distro switched to FactorSeal's keyring, the
  export starts FactorSeal's own service and refuses it.** The start is
  kept (step 2 gives why); Desktop names the case instead of the generic
  row (pending commit). Its test failed before. Reading which service
  file D-Bus would start, the reviewer's other option, was not taken:
  the reviewer called it fragile, and the start does no harm there.
- **F6-3, low (ran): past 64 KiB of stderr the row lost the CLI's
  error.** Fixed in f73a05e: the last 64 KiB are kept. The test (3000
  warning lines, then the error) fails when the head is kept.
- **F6-4, low (read): a valid export could exceed 464 MiB.** Fixed in
  8cfd413 with a limit the CLI and Desktop share
  (`MAX_KEYRING_FRAME_BYTES`, 512 MiB of frame body), the CLI refusing a
  larger export with an error naming both sizes, rather than a bigger
  cap alone: item labels are unbounded, so no cap Desktop picks on its
  own holds every valid record. Dropping the CLI's check fails its test.

**Checked and fine** (the reviewer's list): the gate at ab9de61; each
fix's test fails with its fix removed; `StartServiceByName` when
gnome-keyring owns the name with no service file (`ServiceUnknown`
falls through), when activation never takes the name (fails after the
bus's timeout, 25 s on the test bus, 120 s in NixOS's session config,
within the 3-minute limit), when the service can't be spawned, and with
a broken service file for an owned name; the header bound (the longest
valid header is 20 bytes); the old-CLI fallback in `compare`; S6-5's
paging over mixed-case ids.

### Live check on poita

After the package-only switch (rollout step 1, factorseal input at
5dffff3), the step 6 environment check ran from Windows: PowerShell
running `wsl.exe -d NixOS --exec sh -lc …` (see "Notes and risks" for what
the shell had).

- **Defect found and fixed in 4d5dde5:** `export-secret-service` refused
  with "cannot identify the Secret Service: Permission denied". NixOS's
  gnome-keyring runs with `cap_ipc_lock` through
  `/run/wrappers/bin/gnome-keyring-daemon` (`CapEff 0x4000`), so it isn't
  dumpable and `/proc/<pid>/exe` can't be read; FactorSeal's agent isn't
  dumpable either. The check now falls back to `comm` and `cmdline`
  (step 2). The step 7 script couldn't catch it: nixpkgs' unwrapped
  daemon is dumpable. A test makes a non-dumpable child and identifies it
  (failed before with os error 13; ignoring the names fails it).
- **`wsl.exe --` goes through the user's shell:** zsh expanded `$0` and
  `$(…)` before `sh` ran. Step 6 now uses `--exec`.
- **Result with the fix** (debug build, same path): the frame arrived
  intact; target `wsl:NixOS`; 15 items in the collection `Default`,
  unlocked, none skipped. Gate: fmt, clippy, lib 555 passed, 1 failed,
  6 ignored (`libsecret_store_seal_lookup` times out, as on main), CLI 93
  passed; `scripts/test-keyring-import.sh` passes.
