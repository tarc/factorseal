#!/usr/bin/env bash
# Integration check of the gnome-keyring import (docs/plans/gnome-keyring-import.md,
# step 7), on private session buses only: never the person's own bus,
# gnome-keyring or vault.
#
# 1. A throwaway gnome-keyring-daemon (temporary XDG_DATA_HOME, short
#    XDG_RUNTIME_DIR: its control socket path is cut at the 108-byte socket
#    limit) is seeded with secret-tool and with a libsecret schema that has
#    an INTEGER attribute.
# 2. `factorseal export-secret-service --inventory` runs with the daemon
#    restarted locked, again with gnome-keyring only D-Bus-activatable (not
#    running, as after WSL starts the distro), then the framed export runs
#    unlocked; all must give the same fingerprints.
# 3. The archive is restored into a test vault.
# 4. That vault serves the Secret Service on a private bus, and secret-tool
#    lookup must return each value; a second restore keeps every item.
#
# Usage: scripts/test-keyring-import.sh
# FACTORSEAL_CLI overrides the CLI (default target/debug/factorseal, built
# with `cargo build --all-features --bin factorseal`). gnome-keyring,
# libsecret and PyGObject come from the flake's nixpkgs, built with
# --no-link (no GC root).
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
die() {
    echo "FAIL: $*" >&2
    exit 1
}

cli=$(readlink -f "${FACTORSEAL_CLI:-$repo/target/debug/factorseal}")
[ -x "$cli" ] || die "no CLI at $cli; build it with: cargo build --all-features --bin factorseal"
rev=$(sed -n '/"nixpkgs": {/,/}/s/.*"rev": "\([0-9a-f]*\)".*/\1/p' "$repo/flake.lock" | head -1)
[ -n "$rev" ] || die "no nixpkgs revision in flake.lock"
nixpkgs() {
    nix build --no-link --print-out-paths --impure --expr \
        "let p = (builtins.getFlake \"github:NixOS/nixpkgs/$rev\").legacyPackages.x86_64-linux; in $1" |
        tail -1
}
gnome_keyring=$(nixpkgs p.gnome-keyring)/bin/gnome-keyring-daemon
libsecret=$(nixpkgs p.libsecret.out)
python=$(nixpkgs 'p.python3.withPackages (ps: [ ps.pygobject3 ])')/bin/python3
secret_tool=$libsecret/bin/secret-tool
dbus_config=$repo/tests/fixtures/dbus-session.conf

# Short paths: /tmp, not a deep TMPDIR.
base=$(mktemp -d /tmp/fsk.XXXXXX)
cleanup() {
    # Daemons die with their bus; remove what is left.
    rm -rf "$base"
}
trap cleanup EXIT
mkdir -m 700 "$base/run" "$base/data"
export XDG_RUNTIME_DIR=$base/run XDG_DATA_HOME=$base/data
export GI_TYPELIB_PATH=$libsecret/lib/girepository-1.0
export KEYRING_PASSWORD=keyring-check-password
export GNOME_KEYRING=$gnome_keyring SECRET_TOOL=$secret_tool PYTHON=$python CLI=$cli
export BASE=$base

# Each phase runs in its own private bus; the function names a phase.
phase() {
    dbus-run-session --config-file "$dbus_config" -- bash -c "set -euo pipefail; $(declare -f die start_keyring); $1"
}
start_keyring() {
    # With a password on stdin the login keyring is created or unlocked.
    if [ "${1:-}" = unlocked ]; then
        printf '%s' "$KEYRING_PASSWORD" |
            "$GNOME_KEYRING" --unlock --components=secrets --daemonize >/dev/null
    else
        "$GNOME_KEYRING" --components=secrets --daemonize >/dev/null
    fi
    for _ in $(seq 50); do
        dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
            org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets 2>/dev/null |
            grep -q 'boolean true' && return 0
        sleep 0.1
    done
    die "gnome-keyring did not take org.freedesktop.secrets"
}

# 1. Seed.
phase '
start_keyring unlocked
printf gho_check_value | "$SECRET_TOOL" store --label "GitHub CLI" service gh:github.com username octo
"$PYTHON" -I - <<PY
import gi
gi.require_version("Secret", "1")
from gi.repository import Secret
schema = Secret.Schema.new("test.int", Secret.SchemaFlags.NONE, {
    "port": Secret.SchemaAttributeType.INTEGER,
    "host": Secret.SchemaAttributeType.STRING,
})
assert Secret.password_store_sync(schema, {"port": "8080", "host": "example.org"},
    Secret.COLLECTION_DEFAULT, "Port check", "port_check_value", None)
# No schema at all, as go-keyring (gh) and python-keyring store items.
service = Secret.Service.get_sync(Secret.ServiceFlags.LOAD_COLLECTIONS, None)
collection = Secret.Collection.for_alias_sync(service, "default", Secret.CollectionFlags.NONE, None)
Secret.Item.create_sync(collection, None, {"service": "schemaless", "username": "octo"},
    "Schema-less check", Secret.Value.new("schemaless_check_value", -1, "text/plain"),
    Secret.ItemCreateFlags.NONE, None)
PY
'
echo "seeded:     3 items (an INTEGER attribute, a schema-less item)"

# 2. Inventory locked, export unlocked.
phase '
start_keyring
"$CLI" export-secret-service --inventory --native >"$BASE/inventory.json" 2>"$BASE/inventory.err"
'
# Not running, only activatable. An activated service gets the bus daemon's
# environment, not this script's, so its Exec sets the throwaway dirs:
# without them it would open the real ~/.local/share/keyrings.
mkdir "$base/services"
cat >"$base/services/org.freedesktop.secrets.service" <<SERVICE
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=$(command -v env) HOME=$base XDG_DATA_HOME=$base/data XDG_RUNTIME_DIR=$base/run $gnome_keyring --start --foreground --components=secrets
SERVICE
sed "s|</busconfig>|  <servicedir>$base/services</servicedir>\n</busconfig>|" "$dbus_config" >"$base/activation.conf"
dbus-run-session --config-file "$base/activation.conf" -- bash -c '
set -euo pipefail
dbus-send --session --print-reply --dest=org.freedesktop.DBus / \
    org.freedesktop.DBus.NameHasOwner string:org.freedesktop.secrets | grep -q "boolean false"
"$CLI" export-secret-service --inventory --native >"$BASE/activated.json" 2>"$BASE/activated.err"
' || die "inventory with gnome-keyring only activatable: $(cat "$base/activated.err")"
# Locked again after an unlock in the same daemon: attributes stay plain.
phase '
start_keyring unlocked
dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets \
    org.freedesktop.Secret.Service.Lock array:objpath:/org/freedesktop/secrets/collection/login >/dev/null
"$CLI" export-secret-service --inventory --native >"$BASE/relocked.json" 2>"$BASE/relocked.err"
'
phase '
start_keyring unlocked
printf "%s\n" "opal nebula lantern saffron velocity" |
    "$CLI" export-secret-service --native --framed --passphrase-stdin >"$BASE/export.out" 2>"$BASE/export.err"
'
"$python" -I - "$base" <<'PY' || die "inventory and export disagree"
import base64, json, sys
base = sys.argv[1]
inventory = json.load(open(f"{base}/inventory.json"))
relocked = json.load(open(f"{base}/relocked.json"))
activated = json.load(open(f"{base}/activated.json"))
text = open(f"{base}/export.out").read().splitlines()
start = next(i for i, line in enumerate(text) if line.startswith("FACTORSEAL-FRAME v1 export "))
assert text[start + 2] == "FACTORSEAL-FRAME end", "no frame end"
record = json.loads(base64.b64decode(text[start + 1]))
open(f"{base}/keyring.fsarchive", "wb").write(base64.b64decode(record["archive"]))
locked = sorted(item["fingerprint"] for item in inventory["items"])
unlocked = sorted(item["fingerprint"] for item in record["items"])
assert all(item["locked"] and "label" not in item for item in inventory["items"]), inventory
again = sorted(item["fingerprint"] for item in relocked["items"])
started = sorted(item["fingerprint"] for item in activated["items"])
assert len(locked) == 3 and locked == unlocked == again == started, (locked, unlocked, again, started)
assert all(item["locked"] and "label" in item for item in relocked["items"]), relocked
# The INTEGER item's fingerprint pinned in the unit tests (host, port, xdg:schema).
assert "786097a0da05fd756c858c9f65ec38f3fd9485f684d626d40504649cbdf8cbc7" in locked, locked
assert record["skipped"] == [] and inventory["skipped"] == [], (record, inventory)
PY
echo "fingerprints: locked, activated, locked-again and unlocked agree (3 items)"

# 3 and 4. Restore into a test vault (the library's, with a mock key
# protector: a Linux CLI vault needs a TPM), serve it, look the values up.
printf 'gho_check_value\tservice\tgh:github.com\tusername\tocto\n' >"$base/lookups"
printf 'port_check_value\tport\t8080\thost\texample.org\n' >>"$base/lookups"
printf 'schemaless_check_value\tservice\tschemaless\tusername\tocto\n' >>"$base/lookups"
(
    cd "$repo"
    FACTORSEAL_TEST_SECRET_TOOL=$secret_tool \
        FACTORSEAL_TEST_KEYRING_ARCHIVE=$base/keyring.fsarchive \
        FACTORSEAL_TEST_KEYRING_PASSPHRASE="opal nebula lantern saffron velocity" \
        FACTORSEAL_TEST_KEYRING_LOOKUPS=$base/lookups \
        bash scripts/test-with-dbus.sh cargo test --all-features --lib -- \
        --ignored --exact vault::secret_service::tests::restored_gnome_keyring_archive_is_found_by_secret_tool
) >"$base/restore.log" 2>&1 || die "restore and lookup: $(grep -E 'panicked|assert|lookup|error' "$base/restore.log" | head -10)"
echo "restored:   secret-tool finds all three values; a second restore keeps them all"
echo "PASS"
