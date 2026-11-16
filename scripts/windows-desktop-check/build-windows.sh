#!/usr/bin/env bash
# Builds and checks FactorSeal natively on Windows, driven from WSL2.
#
#   build-windows.sh [release] [--broker] [--test-hooks]
#       Mirror this checkout to the Windows copy, then build release binaries
#       there: Desktop, and the CLI with its helpers and SecretSpec provider.
#       Refuses to start while a Desktop or CLI built in the copy runs, since
#       Windows locks their executables; an installed one elsewhere can run.
#   build-windows.sh check [--broker] [--test-hooks]
#       Mirror, then run clippy, Desktop's tests, the installer's tests and
#       the WSL relay's tests natively. Leaves the release executables alone, so it can run while
#       Desktop is open.
#   build-windows.sh setup [--replace]
#       Mirror, build the installer (factorseal-setup.exe) and store it in the
#       copy as dist\setup\factorseal-setup-<setup version>.exe, its SHA-256
#       in dist\setup\SHA256SUMS. Only when the setup crate changed: a stored
#       version is never rebuilt unless --replace says so.
#   build-windows.sh dist
#       Mirror, then write a release for the installer in the copy's
#       dist\factorseal-<version>\ (packaging/build-windows-release.ps1): the
#       artifacts, the stored installer copied (never rebuilt), and
#       factorseal-release.json. Then install it with its own installer into
#       a test folder and uninstall it again, under a test registry key.
#   --broker also cross-compiles the WSL broker on the WSL side.
#   --test-hooks builds Desktop with the `wsl-test-hooks` feature (and, with
#       check, also runs its tests with it), for `check.sh keyring-import`.
#       Never for a Desktop anyone uses: such a Desktop runs any program
#       FACTORSEAL_TEST_KEYRING_EXPORTER names in WSL and restores its output.
#
# Desktop cannot be cross-compiled (its renderer needs Windows' shader
# compiler), so the Windows copy is built in place through interop. The copy
# defaults to %USERPROFILE%\Projects\factorseal; override it with
# FACTORSEAL_WINDOWS_TREE (a WSL path).
set -euo pipefail

mode=release
broker=no
desktop_features=
replace=no
for argument in "$@"; do
    case $argument in
        release | check | setup | dist) mode=$argument ;;
        --broker) broker=yes ;;
        --test-hooks) desktop_features=' --features wsl-test-hooks' ;;
        --replace) replace=yes ;;
        *) sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done
[ "$replace" = no ] || [ "$mode" = setup ] || { echo "--replace goes with setup" >&2; exit 2; }
[ -z "$desktop_features" ] || [ "$mode" != dist ] || { echo "a release never has --test-hooks" >&2; exit 2; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
windows_profile=$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
# Where `setup` stores installers and `dist` writes releases, in the copy.
setup_dir="$windows_tree/dist/setup"
setup_version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/packaging/windows/setup/Cargo.toml" | head -1)
# The features release packaging uses, plus the SecretSpec provider, which
# packaging leaves out until its IPC crate is published (docs/development.md).
cli_features=vault,cli,hardware,secretspec-provider,personal-sync-network,browser

die() { echo "FAIL: $*" >&2; exit 1; }

# Runs PowerShell commands in the Windows copy and returns cargo's exit code.
# Native stderr arrives as error records; print their text, not their type.
windows() {
    powershell.exe -NoProfile -Command "
        Set-Location '$(wslpath -w "$windows_tree")'
        $1 2>&1 | ForEach-Object {
            if (\$_ -is [System.Management.Automation.ErrorRecord]) { \$_.Exception.Message } else { \$_ }
        }
        exit \$LASTEXITCODE" | tr -d '\r'
}

if [ "$mode" = release ] || [ "$mode" = dist ]; then
    # Only executables in the copy's target\ are locked against the build;
    # an installed FactorSeal elsewhere can keep running. A process whose
    # path is hidden (elevated, seen from here) counts as in the way.
    running=$(powershell.exe -NoProfile -Command \
        "\$target = '$(wslpath -w "$windows_tree")\\target\\'
        Get-Process factorseal, factorseal-desktop, factorseal-browser -ErrorAction SilentlyContinue |
            Where-Object { -not \$_.Path -or \$_.Path.StartsWith(\$target, [StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { \"\$(\$_.Name) (pid \$(\$_.Id))\" }" |
        tr -d '\r' || true) # Get-Process exits 1 when nothing matches.
    [ -z "$running" ] || die "quit the FactorSeal built here first (tray icon, Quit); running: ${running//$'\n'/, }"
fi

mkdir -p "$windows_tree"
echo "Mirroring $repo to $windows_tree"
set +e
# devenv's generated .claude/ and .mcp.json link into /nix/store, which Windows
# cannot open, and a code index's .boostgraph/ holds a Unix socket, which it
# cannot copy. Robocopy retries an unreadable file a million times by default,
# so /R and /W make any such file fail within seconds instead of hanging.
# The copy's dist\ (stored installers, releases) exists only there: /XD keeps
# /MIR from deleting it.
/mnt/c/Windows/System32/robocopy.exe "$(wslpath -w "$repo")" "$(wslpath -w "$windows_tree")" \
    /MIR /XD .git target dist .claude .devenv .boostgraph /XF .mcp.json /R:1 /W:1 \
    /NJH /NJS /NDL /NP /NFL >/dev/null
copied=$?
set -e
# Robocopy exit codes below 8 mean success; 1 means files were copied.
[ "$copied" -lt 8 ] || die "robocopy failed with exit code $copied"

case $mode in
release)
    echo "Building Desktop"
    windows "cargo build --locked --release -p factorseal-desktop$desktop_features"
    echo "Building the CLI and its helpers"
    windows "cargo build --locked --release --no-default-features --features $cli_features --bin factorseal --bin factorseal-parser --bin factorseal-network --bin factorseal-browser"
    ;;
check)
    echo "Running clippy"
    windows "cargo clippy --locked -p factorseal-desktop --all-targets -- -D warnings"
    windows "cargo clippy --locked --no-default-features --features $cli_features --bins -- -D warnings"
    windows "cargo clippy --locked -p factorseal-setup --all-targets -- -D warnings"
    echo "Running Desktop's tests"
    windows "cargo test --locked -p factorseal-desktop"
    [ -z "$desktop_features" ] || windows "cargo test --locked -p factorseal-desktop$desktop_features"
    # The installer's manifest checks, where paths are Windows paths.
    echo "Running the installer's tests"
    windows "cargo test --locked -p factorseal-setup"
    # The broker's own view of a relayed request (Windows folder, the
    # broker's distro) is checked only where Windows paths are absolute.
    echo "Running the WSL relay's tests"
    windows "cargo test --locked --lib --features vault-client -- protocol::wsl"
    ;;
setup)
    stored="$setup_dir/factorseal-setup-$setup_version.exe"
    if [ -e "$stored" ] && [ "$replace" = no ]; then
        die "$(wslpath -w "$stored") is stored already; raise the version in packaging/windows/setup/Cargo.toml for a changed installer (--replace overwrites it)"
    fi
    echo "Building the installer $setup_version"
    windows "cargo build --locked --release -p factorseal-setup"
    mkdir -p "$setup_dir"
    cp "$windows_tree/target/release/factorseal-setup.exe" "$stored"
    sums="$setup_dir/SHA256SUMS"
    touch "$sums"
    { grep -v "  factorseal-setup-$setup_version.exe\$" "$sums" || true
      (cd "$setup_dir" && sha256sum "factorseal-setup-$setup_version.exe"); } > "$sums.new"
    mv "$sums.new" "$sums"
    echo "Stored $(wslpath -w "$stored")"
    grep "factorseal-setup-$setup_version.exe" "$sums"
    ;;
dist)
    stored="$setup_dir/factorseal-setup-$setup_version.exe"
    [ -e "$stored" ] || die "no stored installer $setup_version; run build-windows.sh setup first"
    version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)+g$(git -C "$repo" rev-parse --short=10 HEAD)
    if [ -n "$(git -C "$repo" status --porcelain --untracked-files=no)" ]; then
        version=$version.dirty
        echo "warning: uncommitted changes; the release is $version" >&2
    fi
    echo "Writing the release $version"
    output=$(windows "& .\\packaging\\build-windows-release.ps1 -Version '$version' \
        -Setup 'dist\\setup\\factorseal-setup-$setup_version.exe' \
        -SetupSums 'dist\\setup\\SHA256SUMS' -CliFeatures '$cli_features'") \
        || { printf '%s\n' "$output"; die "writing the release failed"; }
    printf '%s\n' "$output" | grep -v '^\s*$' | tail -n 3
    release="$windows_tree/dist/factorseal-$version"
    [ -f "$release/factorseal-release.json" ] || die "no manifest in $release"
    # The installer in the release is the stored file, byte for byte.
    copied=$(sha256sum "$release/factorseal-setup.exe" | cut -d' ' -f1)
    grep -q "^$copied  factorseal-setup-$setup_version.exe\$" "$setup_dir/SHA256SUMS" \
        || die "the release's installer is not the stored one"
    echo "Installer: the stored factorseal-setup-$setup_version.exe ($copied)"

    # The release installs with its own installer and uninstalls again, in a
    # test folder, under a test registry key, without WSL or a launch.
    check="$windows_tree/target/dist-check"
    rm -rf "$check"
    mkdir -p "$check"
    check_w=$(wslpath -w "$check")
    registry_root='HKCU\Software\FactorSeal-setup-test\dist'
    roots=(--registry-root "$registry_root" --shortcut-root "$check_w\shortcuts"
        --appdata-root "$check_w\appdata" --working-dir "$check_w" --log "$check_w\setup.log")
    set +e
    "$release/factorseal-setup.exe" --quiet --no-start --no-wsl \
        --manifest "$(wslpath -w "$release/factorseal-release.json")" \
        --install-dir "$check_w\FactorSeal" "${roots[@]}" </dev/null 2>/dev/null
    installed=$?
    files=$(find "$check/FactorSeal" -type f 2>/dev/null | wc -l)
    "$check/FactorSeal/factorseal-setup.exe" --quiet --uninstall --no-wsl \
        --install-dir "$check_w\FactorSeal" "${roots[@]}" </dev/null 2>/dev/null
    uninstalled=$?
    set -e
    # The relaunched copy that finishes the uninstall writes the result.
    for _ in $(seq 120); do
        grep -q 'result: \(uninstalled\|failed\|refused\)' "$check/setup.log" 2>/dev/null && break
        sleep 0.5
    done
    powershell.exe -NoProfile -Command "Remove-Item -Recurse -Force 'HKCU:\\Software\\FactorSeal-setup-test\\dist' -ErrorAction SilentlyContinue" </dev/null
    grep 'result:' "$check/setup.log" | cut -d' ' -f3- | sed 's/^/  /'
    [ "$installed" = 0 ] || die "installing the release failed (exit $installed)"
    if [ "$uninstalled" != 0 ] || ! grep -q 'result: uninstalled' "$check/setup.log"; then
        die "uninstalling the release failed (exit $uninstalled)"
    fi
    [ ! -e "$check/FactorSeal" ] || die "the uninstall left $check_w\FactorSeal"
    echo "Installed ($files files) and uninstalled in a test folder"
    rm -rf "$check"
    echo "Release: $(wslpath -w "$release")"
    ;;
esac

if [ "$broker" = yes ]; then
    echo "Cross-compiling the WSL broker"
    (cd "$repo" && devenv shell -- cargo xwin build --locked --release \
        --target x86_64-pc-windows-msvc --bin factorseal-wsl-broker --features vault-client)
fi

if [ "$mode" = release ]; then
    echo
    for binary in factorseal-desktop factorseal factorseal-parser factorseal-network factorseal-browser; do
        stat -c "%y  %n" "$windows_tree/target/release/$binary.exe" | cut -c1-19,36-
    done
fi
echo "OK"
