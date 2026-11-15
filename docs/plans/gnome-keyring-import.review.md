# Review: gnome-keyring-import.md

Reviewed 2026-11-15 against `wip/wsl2-keyring` at 52e7f5b (same commit as
`feature/wsl2-keyring`). Written for the planning session to fold into the
plan. Findings are ordered by weight; each says what to change.

## Facts checked and confirmed

These references in "Facts this rests on" match the code:

- `VaultArchive::validate` at `archive.rs:73`.
- `is_keyring_partition` at `secret_service_data.rs:14`.
- `PortableItem` at `:87`.
- `encrypt_vault_archive` at `archive.rs:146`.
- `PreparedImport::archive` at `import_plan.rs:65`, called from Desktop
  `runtime.rs:515` and the CLI `commands.rs:307` (the plan says 306;
  trivial).
- `require_live_manager` in `ImportVaultEntry` (`service.rs:307`).
- `import_secret_service_item` at `service.rs:967`, which matches by id only.
- `validate_distro` at `wsl.rs:207` and `wsl_keyring_namespace` at
  `wsl.rs:277`.
- The protocol is at 20 (`wire.rs:20`), so v21 is the next.
- `nix/package.nix` builds with
  `vault,cli,hardware,secretspec-provider,…`, so the Linux CLI has the
  archive code and `wsl-setup`.

Not re-checked: the gnome-keyring locked-metadata observations (done in the
planning session on a throwaway daemon). I took them as given, except for
the uint32 caveat in finding 6.

## Findings

### 1. Step 1: "replace under the existing id" must also move the value's address (correctness)

`import_secret_service_item` writes the value at `entry.address`, which is
`item/<incoming id>`. `PortableItem::decode` (`secret_service_data.rs:105`)
requires that address to equal `item/<item.id>`. To keep the existing id
when the attributes match, the step must:

- rewrite `portable.item.id` to the existing id;
- write the value at `item/<existing id>`, in both the `VaultRequest`
  validation and the `store.mutate` operations;
- keep the existing item's `created`.

Otherwise the index points at one id while the value lands under another.
Add a test that reads the value back through the index after a replace,
not just the import status.

### 2. Step 1: the vault can already hold attribute-identical items, and id and attribute matches can disagree (spec gap)

- The native adapter's `create_or_replace_planned` (`agent.rs:336`) looks
  for an attribute match only when `replace` is true. `CreateItem` with
  `replace=false` mints a random id even when an identical item exists. So
  "keeps two items from answering the same lookup" is not an invariant the
  vault holds today; step 1 only stops imports from adding to it. The plan
  should say so, and pick the match deterministically: the first in index
  order, as `create_or_replace` does. Whether replace also removes the
  other duplicates is your call; I'd leave them alone and say so.
- **Precedence.** The plan doesn't say which match wins when an incoming
  item's id matches one existing item and its attributes match another, or
  match nothing. Example: an item imported earlier whose attributes a
  program later changed through `SetAttributes`. Its id is still the old
  fingerprint's prefix. Re-exporting the same gnome-keyring item gives the
  old fingerprint again, so the id matches a vault item with different
  attributes. Check (fingerprint comparison) counts the item as "not in
  FactorSeal". Move then returns `KeptExisting` by id, or with
  `--replace-existing` overwrites the changed item. Suggested rule:
  - match by attributes first;
  - if only the id collides, store the incoming item under a fresh random
    id (and report it).

  Add this case to step 1's tests.

### 3. Check count vs. Move result (consistency)

"14 items, 9 not in FactorSeal", then "Move 9 items", then a report.

- **Mapping rules.** The inventory has to apply the same rules as step 3:
  skip NetworkManager items, and collapse fingerprint duplicates across
  collections. Otherwise the numbers disagree. Make step 4's `--inventory`
  call the step 3 mapping, minus values.
- **Size.** The oversize rule can't be applied to a locked inventory (no
  values). Say that the move may skip items the check counted, and show
  them as "skipped: too large".
- **Items with no attributes** (allowed by the spec) all get the same
  fingerprint and the same id, so they collapse into one. Decide whether
  they get a fingerprint at all. I'd skip and report them: a program can't
  look them up by attributes anyway.
- **"Restores the not-yet-present items" (step 6).** `PreparedImport` has
  no filter, and with step 1 in place there's no need for one: restoring
  everything with `replace_existing = false` gives `KeptExisting` for the
  rest. It also covers changes between Check and Move. Say that Desktop
  restores the whole archive and relies on step 1, rather than filtering.
- **"Skipped with reasons".** Those reasons come from the export side
  (mapping), not from `commit_import`. With `--stdout`, the summary is on
  stderr in human form. Desktop needs it machine-readable: a JSON summary
  on stderr, or a summary entry inside the archive. The restore's
  `TransferSummary` gives only added and kept.

### 4. `wsl.exe` output as an archive stream (robustness)

`wsl.exe -d <distro> -- sh -lc '…'` runs a login shell. Anything the
profile writes to stdout lands in front of the archive, and decryption then
fails with an opaque error. That includes motd-like output, direnv or
devenv hooks, and `nix` warnings. `wsl.exe` can also print its own
warnings, in UTF-16, for example about networking or localhost.

- Have the command frame its output: a magic line followed by base64, or a
  length prefix. Desktop looks for the frame instead of treating all of
  stdout as the archive.
- Or redirect the profile's output to stderr, but the frame is more robust.
- Add this to step 6's fake-runner tests: garbage before the archive.

### 5. Step 8's Desktop test hook must not ship as a way to change the command (security)

"Desktop gets a test hook for the command prefix … used only by
`check.sh`". If that hook is an environment variable or setting in the
release build, anything that can set Desktop's environment can make the
manager-privileged Desktop run an arbitrary command in WSL and restore its
output into the vault.

- Gate it behind a cargo feature that release builds and the installer
  manifest never enable, or behind `debug_assertions`.
- Say which one, and add a check that the release build lacks it.
  `build-windows.sh release` and the installer's manifest step are where
  that check fits.

### 6. Fingerprint details to pin down before step 3

- **Strip gnome-keyring's own attributes.** On an unlocked item, any
  `gkr:compat:*` attributes still visible must be left out of both the
  fingerprint and the imported item's attributes. Otherwise the imported
  item carries gnome-keyring internals, and a vault item created natively
  with the same program attributes no longer matches. State the rule: on
  the gnome-keyring side the fingerprint is built from the plain
  attributes plus the `gkr:compat:hashed:` ones; the vault item gets the
  plain attributes only.
- **Integer attributes.** libsecret schema attributes of integer type
  (`SECRET_SCHEMA_ATTRIBUTE_INTEGER`) are stored as uint32 compat fields in
  gnome-keyring. I believe its hashed form for those is not the MD5 of the
  decimal string (gnome-keyring has a separate uint32 hash). I have not
  verified this. Check it on the throwaway daemon with an integer attribute
  (e.g. a schema with a port), and add a hashed-vs-plain unit test for it.
  If it differs, the locked check under-reports matches for such items.
- **The canonical encoding** should be specified in the plan, since it
  becomes a protocol value once v21 returns it. Spell out the version
  prefix, the separator and the escaping, or use length-prefixed fields.

### 7. Rollout step 1: "add the factorseal package" must not enable the module

`nix/modules/factorseal.nix` installs an `org.freedesktop.secrets` D-Bus
activation file in **every** mode (`wslActivation` for wsl, the desktop
package's service file for desktop). It asserts that NixOS's
`services.gnome.gnome-keyring` is off. That assertion doesn't fire for
poita's home-manager gnome-keyring, so enabling the module would quietly
put two activation files for the same name in place.

- The first switch must add only the `factorseal` package
  (`environment.systemPackages` or `home.packages`), not
  `services.factorseal`. Spell that out.
- The installer's `missing_hint` (installer plan) suggests enabling the
  module with `mode = "wsl"`, which is the second switch. Reconcile the two
  plans; that finding is repeated in the installer review.

### 8. Step 2: locked collections and the reader's refusal (minor spec gaps)

- **Unlock prompts.** `read_all` "unlocks a locked collection only when
  the caller asks". Say whether that's per collection or all at once, and
  what Desktop asks for. In poita there's normally one `login` collection,
  but a second password-protected collection would mean a second gcr
  prompt.
- **The default alias.** Skipping the `session` collection is right. Also
  resolve the `/org/freedesktop/secrets/aliases/default` alias so the same
  collection isn't read twice when it shows up as an alias.
- **The FactorSeal owner check.** The refusal checks the owner pid's
  executable. It works through `GetConnectionUnixProcessID` and
  `/proc/<pid>/exe`. On NixOS, that path is a store path whose name
  changes per build. Match on the file name (`factorseal`) or a marker
  property the host exposes, not on a full path.
- **"gnome-keyring not running" (step 6 errors).** With D-Bus activation,
  that error will rarely happen: the check starts the daemon locked.
  That's fine, but the error list should rather name "no Secret Service on
  the session bus" (no session bus in a `wsl.exe` shell). The real failure
  there is the environment risk already listed.

### 9. The archive encryption on the Desktop pipe (design note, no change required)

Over the `wsl.exe` pipe, the archive encryption protects against nothing a
local process couldn't already do to Desktop or the WSL process. Its value
is format reuse and the ready-made restore path, which is a fine reason.
The plan could say so instead of presenting it as an exposure control.
Also, `encrypt_vault_archive` runs `validate_new_password` on the
passphrase. The one-time passphrase must pass it, so generate at least 32
random characters. And the Argon2id cost is paid twice per move; with the
default parameters that's acceptable.

### 10. Ordering and cross-references

- The installer plan's "Order with the import plan" covers import steps
  1–8 but never places step 9 (docs). Put it after step 8, or split the
  docs per phase.
- Decision 4 changes backup restore semantics for everyone, not just
  imports. Note it in `CHANGELOG.md` too, not only in the backup docs.
- Step 6 says "with the NixOS module hint". With finding 7 in mind, the
  hint for a distro without `factorseal` during the first phase is "add the
  package", not "enable the module".

## Aspects deliberately not considered

- **KWallet** (the plan already marks it untested and out of the docs).
- **The cryptographic strength of MD5 in the fingerprint.** The plan's
  reasoning holds: it only mirrors gnome-keyring, and the values are
  readable by a manager anyway.
- **The UI copy and layout** of the Check/Move row. That's for the native
  review the plan already requires.
- **Native Linux Desktop's restore UX for the `--native` target.** The plan
  treats it as the manual path, and I found nothing inconsistent there.
