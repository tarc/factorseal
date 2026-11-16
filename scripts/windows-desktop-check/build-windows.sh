#!/usr/bin/env bash
# Builds and checks FactorSeal natively on Windows, driven from WSL2.
#
#   build-windows.sh [release] [--broker] [--test-hooks]
#       Mirror this checkout to the Windows copy, then build release binaries
#       there: Desktop, and the CLI with its helpers and SecretSpec provider.
#       Refuses to start while a Desktop or CLI built in the copy runs, since
#       Windows locks their executables; an installed one elsewhere can run.
#   build-windows.sh check [--broker] [--test-hooks]
#       Mirror, then run clippy, Desktop's tests and the WSL relay's tests
#       natively. Leaves the release executables alone, so it can run while
#       Desktop is open.
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
for argument in "$@"; do
    case $argument in
        release | check) mode=$argument ;;
        --broker) broker=yes ;;
        --test-hooks) desktop_features=' --features wsl-test-hooks' ;;
        *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done

repo=$(cd "$(dirname "$0")/../.." && pwd)
windows_profile=$(wslpath "$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')")
windows_tree=${FACTORSEAL_WINDOWS_TREE:-$windows_profile/Projects/factorseal}
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

if [ "$mode" = release ]; then
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
/mnt/c/Windows/System32/robocopy.exe "$(wslpath -w "$repo")" "$(wslpath -w "$windows_tree")" \
    /MIR /XD .git target .claude .devenv .boostgraph /XF .mcp.json /R:1 /W:1 \
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
    echo "Running Desktop's tests"
    windows "cargo test --locked -p factorseal-desktop"
    [ -z "$desktop_features" ] || windows "cargo test --locked -p factorseal-desktop$desktop_features"
    # The broker's own view of a relayed request (Windows folder, the
    # broker's distro) is checked only where Windows paths are absolute.
    echo "Running the WSL relay's tests"
    windows "cargo test --locked --lib --features vault-client -- protocol::wsl"
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
