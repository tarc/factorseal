#!/usr/bin/env bash
# Checks FactorSeal Desktop's approval popup on Windows from WSL2.
#
#   check.sh popup [--delay SECONDS] [--key KEY] [--observe SECONDS] [--steal]
#                  [--test-vault [--seal] [--then grant|deny]]
#       Send a WSL-relayed request and report whether the popup opened, whether
#       it reached the foreground or flashed its taskbar button, a screenshot,
#       and whether the vault holds the pending request with its WSL origin.
#       --delay waits before sending, so a focus scenario can be set up.
#       --steal hands the foreground back to the previous window as soon as
#       the popup takes it; the popup must then flash.
#       --then drives the popup afterwards (test vault only); grant also runs
#       the grant check.
#       --seal seals the vault while the request waits; the popup must stay
#       open. grant then unlocks from the popup, sends the request again (the
#       broker has stopped waiting by then, so Desktop shows it as expired)
#       and grants it; deny denies while sealed and unlocks from the main
#       window, and the request must stay denied.
#   check.sh grant --key KEY [--test-vault]
#       After approving in the popup, resend the request and check that it
#       succeeds without a new popup and that the grant ends with the unseal.
#   check.sh test-desktop
#       Create the throwaway test vault if needed, start a Desktop on it, and
#       unlock it, so --test-vault runs need no person.
#   check.sh write-once [--via popup|cli]
#       On the test vault, write a new SecretSpec key through the provider as
#       SecretSpec would, approve it with the default lifetime (in the popup,
#       or with `factorseal permissions approve` in a console), and check that
#       the default was "this write only" (the popup is read through UI
#       Automation): the grant covers one write, is gone after it, and the
#       next write asks again.
#   check.sh secretspec-wsl
#       On the test vault, run the Linux `secretspec` in WSL against the
#       Windows vault through the Linux provider and the broker's relay mode,
#       as `factorseal wsl-setup` configures it: set a key and read it back
#       (granted "Until the vault seals" in the popup), read it again without
#       a popup, ask again from another folder, read the same value from the
#       native provider in the translated folder, and ask again after the
#       vault seals and unlocks. Needs the Linux CLI
#       (FACTORSEAL_LINUX_CLI, default target/debug/factorseal) and builds
#       SecretSpec from nix/secretspec.nix unless FACTORSEAL_SECRETSPEC names
#       one.
#
# --test-vault targets the throwaway vault in %LOCALAPPDATA%\FactorSeal-check
# and the Desktop running on it instead of the default vault. Needs the native
# Windows build of the CLI and the cross-compiled broker. Paths can be
# overridden with FACTORSEAL_WINDOWS_TREE (Windows copy of this repository, as
# a WSL path) and FACTORSEAL_WSL_BROKER.
set -euo pipefail

case ${1:-} in
    popup | grant | test-desktop | write-once | secretspec-wsl) ;;
    *) sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

repo=$(cd "$(dirname "$0")/../.." && pwd)
here=$(cd "$(dirname "$0")" && pwd)

windows_env() { cmd.exe /c "echo %$1%" 2>/dev/null | tr -d '\r'; }
windows_profile=$(wslpath "$(windows_env USERPROFILE)")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
cli="$windows_tree/target/release/factorseal.exe"
desktop="$windows_tree/target/release/factorseal-desktop.exe"
broker=${FACTORSEAL_WSL_BROKER:-$repo/target/x86_64-pc-windows-msvc/release/factorseal-wsl-broker.exe}
distro=${WSL_DISTRO_NAME:?not running inside WSL}
test_dir="$(windows_env LOCALAPPDATA)\\FactorSeal-check"
test_root="$test_dir\\vault"
test_password="$test_dir\\password"
project=wsl-ui-check
profile=default

die() { echo "FAIL: $*" >&2; exit 1; }

powershell() {
    local script=$1
    shift
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w "$here/$script")" "$@" </dev/null |
        tr -d '\r'
}

[ -x "$cli" ] || die "no native CLI at $cli; build it with $here/build-windows.sh"

command=$1
shift
key="CHECK_$(date +%H%M%S)"
key_given=no
delay=0
observe=12
test_vault=no
steal=no
seal=no
then=
via=popup
while [ $# -gt 0 ]; do
    case $1 in
        --key) key=$2; key_given=yes; shift 2 ;;
        --delay) delay=$2; shift 2 ;;
        --observe) observe=$2; shift 2 ;;
        --test-vault) test_vault=yes; shift ;;
        --steal) steal=yes; shift ;;
        --seal) seal=yes; shift ;;
        --then) then=$2; shift 2 ;;
        --via) via=$2; shift 2 ;;
        *) die "unknown option $1" ;;
    esac
done
case $then in
    '' | grant | deny) ;;
    *) die "--then takes grant or deny" ;;
esac
[ -z "$then" ] || [ "$test_vault" = yes ] || die "--then drives only the test vault; add --test-vault"
[ "$seal" = no ] || [ -n "$then" ] || die "--seal needs --then grant or --then deny"
case $via in
    popup | cli) ;;
    *) die "--via takes popup or cli" ;;
esac
case $command in test-desktop | write-once | secretspec-wsl) test_vault=yes ;; esac

root_args=()
[ "$test_vault" = yes ] && root_args=(--root "$test_root")
factorseal() { "$cli" "${root_args[@]}" "$@" </dev/null 2>&1; }

# The Desktop serving the chosen vault; the test one runs with --root.
desktop_pid() {
    local test='$false'
    [ "$test_vault" = yes ] && test='$true'
    powershell.exe -NoProfile -Command "
        Get-CimInstance Win32_Process -Filter \"Name='factorseal-desktop.exe'\" |
            Where-Object { (\$_.CommandLine -like '*FactorSeal-check*') -eq $test } |
            Select-Object -First 1 -ExpandProperty ProcessId" </dev/null | tr -d '\r'
}

state() { factorseal status | sed -n 's/.*"state": "\([^"]*\)".*/\1/p'; }

# The vault seals itself after a few idle minutes, so check before sending.
require_unsealed() {
    status=$(factorseal status) || die "factorseal status failed: $status"
    installation=$(sed -n 's/.*"installation_id": "\([^"]*\)".*/\1/p' <<<"$status")
    [ -n "$installation" ] || die "no installation_id in factorseal status"
    if [ "$(sed -n 's/.*"state": "\([^"]*\)".*/\1/p' <<<"$status")" != unsealed ]; then
        [ "$test_vault" = yes ] && die "the test vault is sealed; run: $0 test-desktop"
        die "vault is sealed; unlock it in Desktop first"
    fi
}

if [ "$command" = test-desktop ]; then
    powershell test-vault.ps1 -Cli "$(wslpath -w "$cli")" | sed 's/^/test vault:    /'
    pid=$(desktop_pid)
    started=no
    if [ -z "$pid" ]; then
        started=yes
        # Detached, with no handle to this shell, so the launch returns.
        setsid "$desktop" --root "$test_root" </dev/null >/dev/null 2>&1 &
        for _ in $(seq 50); do
            pid=$(desktop_pid)
            [ -n "$pid" ] && break
            sleep 0.2
        done
        [ -n "$pid" ] || die "the test Desktop did not start"
        echo "desktop:       started, pid $pid"
        # Typing into a window that has only just appeared loses keystrokes.
        sleep 2
    else
        echo "desktop:       running, pid $pid"
    fi
    if [ "$(state)" = unsealed ]; then
        echo "vault:         unsealed"
        echo "PASS"
        exit 0
    fi
    if [ "$started" = no ]; then
        # The browser host starts Desktop in the tray, without a window;
        # starting it again shows the running one's window.
        setsid "$desktop" --root "$test_root" </dev/null >/dev/null 2>&1 &
        sleep 2
    fi
    result=$(powershell drive.ps1 -Action unlock -DesktopPid "$pid" -PasswordFile "$test_password" -Seconds 30 || true)
    sed 's/^/driver:        /' <<<"$result"
    grep -q '^unlocked=True' <<<"$result" || die "the driver could not unlock the test vault"
    # Status can trail the window by a moment.
    for _ in $(seq 25); do
        [ "$(state)" = unsealed ] && break
        sleep 0.2
    done
    [ "$(state)" = unsealed ] || die "the test vault is still sealed"
    echo "vault:         unsealed"
    echo "PASS"
    exit 0
fi

[ "$command" = write-once ] || [ -x "$broker" ] ||
    die "no broker at $broker; build it with: $here/build-windows.sh --broker"
require_unsealed
pipe="\\\\.\\pipe\\factorseal-$installation"
pid=$(desktop_pid)
[ -n "$pid" ] || die "no Desktop is running on this vault"

send() { timeout 60 "$broker" "$pipe" "$distro" get "$project" "$profile" "$1" 2>&1 || true; }

# Prints the permission block for one request ID, or nothing.
permission() {
    factorseal permissions list | awk -v id="\"$1\"" '
        $1 == id { found = 1; print; next }
        found && /^"prm_/ { exit }
        found { print }'
}

check_grant() {
    reply=$(send "$key")
    grep -q 'approval required' <<<"$reply" && die "the request needed approval again: $reply"
    echo "broker:        ${reply//$'\n'/ | }"
    # The target line, right after each ID line, holds the key JSON-escaped.
    id=$(factorseal permissions list | grep -F -B1 "\\\"key\\\":\\\"$key\\\"" |
        sed -n 's/^"\(prm_[^"]*\)".*/\1/p' | head -1)
    [ -n "$id" ] || die "no grant found for $key"
    record=$(permission "$id")
    check_ends_with_unseal "$record"
}

# The unseal lease's absolute deadline, from the broker's status reply.
absolute_deadline() {
    timeout 30 "$broker" "$pipe" "$distro" status 2>&1 |
        sed -n 's/.*absolute_deadline: \([0-9]*\).*/\1/p'
}

# A WSL grant expires when the unseal that created it ends.
check_ends_with_unseal() {
    local granted expires deadline
    granted=$(sed -n 's/.*granted: \([0-9]*\).*/\1/p' <<<"$1" | head -1)
    expires=$(sed -n 's/.*expires: \([0-9]*\).*/\1/p' <<<"$1" | head -1)
    deadline=$(absolute_deadline)
    [ -n "$granted" ] && [ -n "$expires" ] || die "the grant has no expiry: $1"
    [ -n "$deadline" ] || die "the broker did not report the unseal deadline"
    echo "grant:         expires at the unseal's deadline ($((expires - granted)) s from approval)"
    [ "$expires" = "$deadline" ] || die "the WSL grant expires at $expires, not at the unseal deadline $deadline"
}

case $command in
popup)
    out=$(mktemp -d "${TMPDIR:-/tmp}/factorseal-popup-check.XXXXXX")
    win_out=$(wslpath -w "$out")
    # The observer runs on Windows; copy it next to its output so the
    # Windows side reads a local path.
    cp "$here/observe.ps1" "$out/observe.ps1"
    if [ "$delay" -gt 0 ]; then
        echo "Sending in $delay s; set up the focus scenario now."
        sleep "$delay"
        require_unsealed
    fi
    steal_args=()
    [ "$steal" = yes ] && steal_args=(-Steal)
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$win_out\\observe.ps1" \
        -OutDir "$win_out" -Seconds "$observe" -DesktopPid "$pid" "${steal_args[@]}" \
        >"$out/powershell.txt" 2>&1 &
    observer=$!
    # Windows PowerShell writes UTF-8 with a byte-order mark and CRLF endings.
    report() { sed '1s/^\xEF\xBB\xBF//' "$out/observer.txt" 2>/dev/null | tr -d '\r'; }
    value() { report | sed -n "s/^$1=//p" | tail -1; }
    for _ in $(seq 150); do
        [ -e "$out/ready" ] && break
        kill -0 "$observer" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$(value error)" ] && die "$(value error)"
    [ -e "$out/ready" ] || die "observer did not start; see $out/powershell.txt"

    echo "Sending request for $project/$profile/$key at $(date -u +%T) UTC"
    [ -n "$then" ] || echo "Leave the popup alone until the result prints."
    reply=$(send "$key")
    wait "$observer" || true
    id=$(sed -n 's/.*approval required (id \(prm_[^)]*\)).*/\1/p' <<<"$reply")

    seen=$(value popup_seen)
    foreground=$(value popup_foreground)
    flashed=$(value popup_flashed)
    echo
    echo "broker:        ${reply//$'\n'/ | }"
    echo "popup seen:    $seen ($(value popup_title))"
    echo "foreground:    $foreground (foreground window: $(value foreground_process) '$(value foreground_title)')"
    echo "flashed:       $flashed ($(value flash_events) flash events in total; popup owned by the main window: $(value popup_owned))"
    if [ "$steal" = yes ]; then
        # Only a popup that had the foreground and lost it tests the steal case.
        if [ "$(value stolen)" = True ]; then
            echo "steal:         the popup took the foreground and lost it again"
        else
            echo "steal:         not reproduced (popup took foreground: $(value popup_took_foreground), stolen: $(value stolen))"
        fi
    fi
    echo "rect:          $(value popup_rect)"
    [ -n "$(value popup_screenshot)" ] && echo "screenshot:    $out/popup.png (what was on screen at the popup's position)"
    [ -n "$(value taskbar_screenshot)" ] && echo "taskbar:       $out/taskbar.png"

    failures=0
    if grep -q 'no vault agent is listening' <<<"$reply"; then
        die "the vault sealed before the request arrived; unlock it and run again"
    elif [ -z "$id" ]; then
        echo "vault:         no pending request (already granted, or the broker failed)"
        failures=$((failures + 1))
    elif grep -q 'approval not granted: Denied' <<<"$reply"; then
        echo "vault:         $id was denied in the popup during the run; not checked"
    else
        record=$(permission "$id")
        if grep -q 'pending' <<<"$record" && grep -q "relayed from WSL distro: \"$distro\"" <<<"$record"; then
            echo "vault:         $id pending, relayed from $distro"
        else
            echo "vault:         $id not pending with WSL origin:"; sed 's/^/  /' <<<"$record"
            failures=$((failures + 1))
        fi
    fi
    if [ "$seen" != True ]; then
        echo "FAIL: the popup never opened"; failures=$((failures + 1))
    elif [ "$foreground" != True ] && [ "$flashed" != True ]; then
        echo "FAIL: the popup is behind another app and did not flash"; failures=$((failures + 1))
    fi
    [ "$failures" -eq 0 ] || exit 1

    if [ -z "$then" ]; then
        echo "PASS"
        echo "Approve or deny it in the popup. After approving, run: $0 grant --key $key"
        exit 0
    fi
    drive() {
        result=$(powershell drive.ps1 -Action "$1" -DesktopPid "$pid" -PasswordFile "$test_password" || true)
        sed 's/^/driver:        /' <<<"$result"
    }
    wait_state() {
        for _ in $(seq 50); do
            [ "$(state)" = "$1" ] && return 0
            sleep 0.2
        done
        return 1
    }
    if [ "$seal" = yes ]; then
        factorseal seal >/dev/null
        wait_state sealed || die "the vault did not seal"
        drive find
        grep -q '^popup_open=True' <<<"$result" || die "sealing closed the popup"
        echo "sealed:        vault sealed, popup still open"
        if [ "$then" = grant ]; then
            drive unlock-popup
            grep -q '^unlocked=True' <<<"$result" || die "the popup did not unlock the vault"
            wait_state unsealed || die "the vault is still sealed after unlocking in the popup"
            # The broker stopped waiting long ago, so Desktop shows the request
            # as expired. Send it again, as a person would rerun the program,
            # and grant while the broker waits for the answer.
            send "$key" >"$out/resend.txt" &
            resend=$!
            sleep 1
        fi
    fi
    drive "$then"
    grep -q '^popup_closed=True' <<<"$result" || die "the driver could not $then the request"
    [ -z "${resend:-}" ] || wait "$resend" || true
    if [ "$seal" = yes ] && [ "$then" = deny ]; then
        # Denied while sealed: Desktop sends the denial after the next unlock.
        drive unlock
        grep -q '^unlocked=True' <<<"$result" || die "the driver could not unlock the main window"
        wait_state unsealed || die "the vault is still sealed"
        # Desktop sends it once its own view of the vault is unsealed again,
        # which can trail the vault's status by several seconds.
        for _ in $(seq 20); do
            grep -q 'pending' <<<"$(permission "$id")" || break
            sleep 1
        done
        drive find
        grep -q '^popup_open=False' <<<"$result" || die "the denied request came back after unlocking"
    fi
    record=$(permission "$id")
    if [ "$then" = deny ]; then
        grep -q 'pending' <<<"$record" && die "$id is still pending after Deny"
        grep -q 'granted: ' <<<"$record" && die "$id was granted after Deny: $record"
        echo "vault:         $id no longer pending, not granted"
    else
        check_grant
    fi
    echo "PASS"
    ;;
grant)
    [ "$key_given" = yes ] || die "grant needs --key KEY from the popup run"
    check_grant
    echo "PASS"
    ;;
write-once)
    key="ONCE_$(date +%H%M%S)"
    # One provider.set, as SecretSpec sends it. Five seconds is enough for
    # an answer: a write without a grant is answered interaction_required.
    write() {
        powershell provider-probe.ps1 -Cli "$(wslpath -w "$cli")" -Root "$test_root" \
            -Method set -Project write-once-check -Key "$key" -Value "$1" \
            -Directory "$test_dir" -Seconds 5 | sed -n 's/^set=//p'
    }
    asked() { sed -n 's/.*"interaction":{"kind":"authorization","id":"\(prm_[^"]*\)".*/\1/p' <<<"$1"; }

    reply=$(write first)
    id=$(asked "$reply")
    [ -n "$id" ] || die "the first write did not ask for approval: $reply"
    grep -q 'Put  pending' <<<"$(permission "$id")" || die "$id is not a pending write"
    echo "first write:   asked for approval ($id)"

    if [ "$via" = popup ]; then
        # The popup's text is exposed to UI Automation, so read what it asks
        # instead of trusting a screenshot. Desktop opens the popup once its
        # watcher sees the request, which can trail the write's answer.
        for _ in $(seq 10); do
            tree=$(powershell uia-dump.ps1 -DesktopPid "$pid" || true)
            grep -q "Text name='wants to write secrets" <<<"$tree" && break
            sleep 1
        done
        grep -q "Text name='SecretSpec'" <<<"$tree" &&
            grep -q "Text name='wants to write secrets" <<<"$tree" ||
            die "the popup does not say SecretSpec is asking to write"
        grep -q "RadioButton name='This write only' .* selected=True" <<<"$tree" ||
            die "the popup did not select This write only"
        echo "popup:         SecretSpec asks to write; This write only is selected"
        result=$(powershell drive.ps1 -Action grant -DesktopPid "$pid" -PasswordFile "$test_password" || true)
        sed 's/^/driver:        /' <<<"$result"
        grep -q '^popup_closed=True' <<<"$result" || die "the driver could not grant the request"
    else
        result=$(powershell cli-approve.ps1 -Cli "$(wslpath -w "$cli")" -Root "$test_root" \
            -PasswordFile "$test_password" -Id "$id" || true)
        sed 's/^/cli:           /' <<<"$result"
        grep -q '^exit=0$' <<<"$result" || die "permissions approve failed"
    fi
    record=$(permission "$id")
    grep -q 'next write only' <<<"$record" || die "the default was not this write only: $record"
    granted=$(sed -n 's/.*granted: \([0-9]*\).*/\1/p' <<<"$record" | head -1)
    expires=$(sed -n 's/.*expires: \([0-9]*\).*/\1/p' <<<"$record" | head -1)
    echo "grant:         next write only, within $((expires - granted)) s"

    reply=$(write first)
    grep -q '"stored":true' <<<"$reply" || die "the approved write was not stored: $reply"
    [ -z "$(permission "$id")" ] || die "the write did not spend $id"
    echo "retry:         stored, and the grant is gone"

    reply=$(write second)
    second=$(asked "$reply")
    [ -n "$second" ] || die "the next write did not ask again: $reply"
    factorseal permissions deny "$second" >/dev/null
    echo "second write:  asked again ($second, denied)"
    echo "PASS"
    ;;
secretspec-wsl)
    linux_cli=${FACTORSEAL_LINUX_CLI:-$repo/target/debug/factorseal}
    [ -x "$linux_cli" ] || die "no Linux CLI at $linux_cli; build it with: cargo build --bin factorseal"
    linux_cli=$(readlink -f "$linux_cli")
    secretspec=${FACTORSEAL_SECRETSPEC:-}
    if [ -z "$secretspec" ]; then
        # The release matching Factorseal's provider protocol, from the
        # flake's own nixpkgs; --no-link leaves no GC root.
        rev=$(sed -n '/"nixpkgs": {/,/}/s/.*"rev": "\([0-9a-f]*\)".*/\1/p' "$repo/flake.lock" | head -1)
        [ -n "$rev" ] || die "no nixpkgs revision in flake.lock"
        out=$(nix build --no-link --print-out-paths --impure --expr \
            "(builtins.getFlake \"github:NixOS/nixpkgs/$rev\").legacyPackages.x86_64-linux.callPackage $repo/nix/secretspec.nix {}") ||
            die "could not build SecretSpec from nix/secretspec.nix"
        secretspec="$out/bin/secretspec"
    fi
    echo "secretspec:    $secretspec"

    # Everything the provider in WSL needs, in a scratch directory, so the
    # person's own configuration stays untouched.
    base=$(mktemp -d "${TMPDIR:-/tmp}/factorseal-secretspec-wsl.XXXXXX")
    project="wsl-secretspec-$(date +%H%M%S)"
    key="WSL_$(date +%H%M%S)"
    # A process and everything it started: `timeout` puts secretspec in its
    # own process group, so stopping the background subshell alone would
    # leave secretspec, the provider and the broker waiting.
    kill_tree() {
        local child
        for child in $(ps -o pid= --ppid "$1" 2>/dev/null); do kill_tree "$child"; done
        kill "$1" 2>/dev/null || true
    }
    # On any exit, Ctrl-C included: stop the secretspec runs still waiting
    # and deny this run's pending requests, which would otherwise keep a
    # popup open with "Unlock to continue" once the test vault seals.
    cleanup() {
        set +e
        local job id
        for job in $(jobs -p); do kill_tree "$job"; done
        for id in $(factorseal permissions list | grep -F -B1 "\\\"key\\\":\\\"$key\\\"" |
            sed -n 's/^"\(prm_[^"]*\)".*/\1/p'); do
            permission "$id" | grep -q pending && factorseal permissions deny "$id" >/dev/null
        done
        rm -rf "$base"
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for folder in one two; do
        mkdir -p "$base/$folder"
        printf '[project]\nname = "%s"\nrevision = "1.0"\n\n[profiles.default]\n%s = { description = "WSL check", required = false }\n' \
            "$project" "$key" >"$base/$folder/secretspec.toml"
    done
    printf '{"broker":"%s","pipe":"%s","distro":"%s"}\n' "$broker" "${pipe//\\/\\\\}" "$distro" >"$base/wsl.json"
    install -d -m 700 "$base/xdg/secretspec/providers.d"
    printf '{"executable":"%s","environment":["FACTORSEAL_WSL_CONFIG","WSL_INTEROP","WSL_DISTRO_NAME"]}\n' \
        "$linux_cli" >"$base/xdg/secretspec/providers.d/factorseal.secretspec.json"
    chmod 600 "$base/xdg/secretspec/providers.d/factorseal.secretspec.json"
    secretspec_in() {
        local folder=$1
        shift
        (cd "$base/$folder" && XDG_CONFIG_HOME="$base/xdg" FACTORSEAL_WSL_CONFIG="$base/wsl.json" \
            timeout 90 "$secretspec" --file "$base/$folder/secretspec.toml" --reason wsl-check \
            "$@" --provider factorseal://default 2>&1)
    }
    # The pending request for this run's key, once the vault holds it.
    pending_request() {
        local id
        for _ in $(seq 60); do
            for id in $(factorseal permissions list | grep -F -B1 "\\\"key\\\":\\\"$key\\\"" |
                sed -n 's/^"\(prm_[^"]*\)".*/\1/p'); do
                if permission "$id" | grep -q pending; then
                    echo "$id"
                    return
                fi
            done
            sleep 0.5
        done
    }
    popup_tree() {
        local tree
        for _ in $(seq 10); do
            tree=$(powershell uia-dump.ps1 -DesktopPid "$pid" || true)
            grep -q "Text name='When the vault seals'" <<<"$tree" && break
            sleep 1
        done
        echo "$tree"
    }
    windows_folder="\\\\wsl.localhost\\$distro${base//\//\\}\\one"

    # 1. A write, granted until the vault seals.
    secretspec_in one set "$key" wsl-value >"$base/set.out" &
    setter=$!
    id=$(pending_request)
    [ -n "$id" ] || die "the write did not reach the vault: $(cat "$base/set.out")"
    record=$(permission "$id")
    grep -q "relayed from WSL distro: \"$distro\"" <<<"$record" || die "the write is not tagged with $distro: $record"
    # The listing prints the folder JSON-escaped, each backslash doubled.
    grep -qF "base directory: \"${windows_folder//\\/\\\\}\"" <<<"$record" ||
        die "the folder is not $windows_folder: $record"
    tree=$(popup_tree)
    grep -q "Text name='When the vault seals'" <<<"$tree" || die "the popup does not say access ends when the vault seals"
    grep -q "RadioButton name='Until the vault seals'" <<<"$tree" || die "the popup does not offer Until the vault seals"
    grep -q "RadioButton name='1 hour'" <<<"$tree" && die "the popup offers 1 hour for a WSL request"
    echo "write:         asked ($id); popup offers Until the vault seals, folder $windows_folder"
    result=$(powershell drive.ps1 -Action press -Name 'Until the vault seals' -NoWait -DesktopPid "$pid" -PasswordFile "$test_password" || true)
    grep -q '^clicked=' <<<"$result" || die "the driver could not pick Until the vault seals: $result"
    result=$(powershell drive.ps1 -Action grant -DesktopPid "$pid" -PasswordFile "$test_password" || true)
    grep -q '^popup_closed=True' <<<"$result" || die "the driver could not grant the write: $result"
    wait "$setter" || die "secretspec set failed: $(cat "$base/set.out")"
    check_ends_with_unseal "$(permission "$id")"
    echo "write:         stored"

    # 2. A read, granted with the popup's default.
    secretspec_in one get "$key" >"$base/get.out" &
    getter=$!
    id=$(pending_request)
    [ -n "$id" ] || die "the read did not reach the vault: $(cat "$base/get.out")"
    tree=$(popup_tree)
    grep -q "RadioButton name='Until the vault seals' .* selected=True" <<<"$tree" ||
        die "the popup did not select Until the vault seals for the read"
    result=$(powershell drive.ps1 -Action grant -DesktopPid "$pid" -PasswordFile "$test_password" || true)
    grep -q '^popup_closed=True' <<<"$result" || die "the driver could not grant the read: $result"
    wait "$getter" || die "secretspec get failed: $(cat "$base/get.out")"
    [ "$(tail -1 "$base/get.out")" = wsl-value ] || die "secretspec get returned: $(cat "$base/get.out")"
    check_ends_with_unseal "$(permission "$id")"
    echo "read:          granted until the vault seals; value matches"

    # 3. Again, without a popup.
    started=$(date +%s%N)
    reply=$(secretspec_in one get "$key") || die "the second read failed: $reply"
    elapsed=$((($(date +%s%N) - started) / 1000000))
    [ "$(tail -1 <<<"$reply")" = wsl-value ] || die "the second read returned: $reply"
    echo "read again:    no popup, $elapsed ms for the whole secretspec command"

    # 4. Another folder of the same project asks again.
    secretspec_in two get "$key" >"$base/other.out" &
    other=$!
    id=$(pending_request)
    [ -n "$id" ] || die "another folder did not ask again: $(cat "$base/other.out")"
    factorseal permissions deny "$id" >/dev/null
    wait "$other" && die "the denied read succeeded: $(cat "$base/other.out")"
    echo "other folder:  asked again ($id, denied)"

    # 5. The native provider in the translated folder reads the same value,
    # after its own approval: the caller is not the broker.
    probe() {
        powershell provider-probe.ps1 -Cli "$(wslpath -w "$cli")" -Root "$test_root" -Method get \
            -Project "$project" -Key "$key" -Directory "$windows_folder" -Seconds 5
    }
    reply=$(probe)
    asked=$(sed -n 's/.*"interaction":{"kind":"authorization","id":"\(prm_[^"]*\)".*/\1/p' <<<"$reply")
    [ -n "$asked" ] || die "the native provider did not ask for its own approval: $reply"
    result=$(powershell drive.ps1 -Action grant -DesktopPid "$pid" -PasswordFile "$test_password" || true)
    grep -q '^popup_closed=True' <<<"$result" || die "the driver could not grant the native read: $result"
    probe | grep -q 'wsl-value' || die "the native provider did not read the value"
    echo "native:        its own approval ($asked), same value"

    # 6. After a seal and unlock the WSL grants are gone.
    factorseal seal >/dev/null
    for _ in $(seq 50); do
        [ "$(state)" = sealed ] && break
        sleep 0.2
    done
    "$0" test-desktop >/dev/null || die "could not unlock the test vault again"
    pid=$(desktop_pid)
    secretspec_in one get "$key" >"$base/sealed.out" &
    after=$!
    id=$(pending_request)
    [ -n "$id" ] || die "the read after the seal did not ask again: $(cat "$base/sealed.out")"
    factorseal permissions deny "$id" >/dev/null
    wait "$after" && die "the denied read after the seal succeeded: $(cat "$base/sealed.out")"
    echo "after a seal:  asked again ($id, denied)"
    echo "PASS"
    ;;
esac
