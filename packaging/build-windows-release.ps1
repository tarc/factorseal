# Builds a FactorSeal release for factorseal-setup.exe: a folder
# dist\factorseal-<version>\ with the artifacts, the stored installer and a
# factorseal-release.json listing every artifact with its SHA-256
# (docs/plans/windows-installer.md, step 9). Run from the repository root;
# scripts/windows-desktop-check/build-windows.sh dist runs it in the Windows
# copy and then installs and uninstalls the release as a check.
#
# The installer is never built here: -Setup names the stored binary, which
# must match its line in -SetupSums, and is copied as factorseal-setup.exe.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$SetupSums,
    [Parameter(Mandatory = $true)][string]$CliFeatures,
    [string]$OutputDirectory = 'dist'
)

$ErrorActionPreference = 'Stop'

# Cargo reports progress on standard error, which PowerShell 5.1 turns into
# error records when the caller redirects it (build-windows.sh does): run it
# with errors continuing, pass its lines on as text, and judge it by its
# exit code.
function Invoke-Cargo {
    $ErrorActionPreference = 'Continue'
    & cargo @args 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { throw "cargo $($args -join ' ') failed" }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

if ($Version -notmatch '^[0-9A-Za-z.+_-]{1,64}$') { throw "not a version: $Version" }
$setupName = Split-Path -Leaf $Setup
$expected = Get-Content -LiteralPath $SetupSums |
    Where-Object { $_ -match "^([0-9a-f]{64})  $([regex]::Escape($setupName))$" } |
    ForEach-Object { $Matches[1] } | Select-Object -Last 1
if (-not $expected) { throw "$SetupSums has no line for $setupName" }
if ((Get-Sha256 $Setup) -ne $expected) { throw "$Setup doesn't match its line in $SetupSums" }

Invoke-Cargo build --locked --release --no-default-features --features $CliFeatures --bin factorseal --bin factorseal-parser --bin factorseal-network --bin factorseal-browser
# Never the import plan's wsl-test-hooks feature: such a Desktop runs any
# program FACTORSEAL_TEST_KEYRING_EXPORTER names in WSL.
Invoke-Cargo build --locked --release -p factorseal-desktop
Invoke-Cargo build --locked --release --no-default-features --features vault-client --bin factorseal-wsl-broker

$metadataJson = & { $ErrorActionPreference = 'Continue'; cargo metadata --locked --no-deps --format-version 1 2>$null }
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
$metadata = $metadataJson | ConvertFrom-Json
$built = Join-Path $metadata.target_directory 'release'
$desktop = Join-Path $built 'factorseal-desktop.exe'
# The feature's only trace in the binary is that variable's name.
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
if ($latin1.GetString([System.IO.File]::ReadAllBytes($desktop)).Contains('FACTORSEAL_TEST_KEYRING_EXPORTER')) {
    throw "$desktop was built with the wsl-test-hooks feature"
}

$release = Join-Path $OutputDirectory "factorseal-$Version"
if (Test-Path -LiteralPath $release) { Remove-Item -Recurse -Force -LiteralPath $release }
New-Item -ItemType Directory -Path $release | Out-Null
$artifacts = [ordered]@{}
foreach ($name in 'factorseal-desktop', 'factorseal', 'factorseal-parser', 'factorseal-network', 'factorseal-browser', 'factorseal-wsl-broker') {
    $artifacts["$name.exe"] = Join-Path $built "$name.exe"
}
$artifacts['LICENSE'] = 'LICENSE'
$artifacts['README.md'] = 'README.md'
$artifacts['LICENSE.IBM-Plex-Sans'] = 'assets/fonts/ibm-plex-sans/license.txt'
$artifacts['LICENSE.IBM-Plex-Mono'] = 'assets/fonts/ibm-plex-mono/license.txt'
$files = @()
foreach ($name in $artifacts.Keys) {
    $target = Join-Path $release $name
    Copy-Item -LiteralPath $artifacts[$name] -Destination $target
    $files += [ordered]@{ path = $name; sha256 = (Get-Sha256 $target) }
}
$installer = Join-Path $release 'factorseal-setup.exe'
Copy-Item -LiteralPath $Setup -Destination $installer
if ((Get-Sha256 $installer) -ne $expected) { throw "the copy of $Setup differs from it" }

$browserHosts = 'Mozilla', 'Microsoft\Edge', 'Google\Chrome', 'Chromium' |
    ForEach-Object { "HKCU\Software\$_\NativeMessagingHosts\dev.factorseal.browser" }
$manifest = [ordered]@{
    schema = 1
    product = 'FactorSeal'
    version = $Version
    requires_setup = 1
    files = $files
    stop = [ordered]@{
        command = @('factorseal-desktop.exe', '--quit')
        also_stop = @('factorseal-browser.exe', 'factorseal-wsl-broker.exe')
    }
    steps = @(
        [ordered]@{ install_files = @{} },
        [ordered]@{ shortcut = [ordered]@{
                name = 'FactorSeal Desktop'
                target = 'factorseal-desktop.exe'
                places = @('start-menu')
                optional_places = @('startup', 'desktop')
                startup_args = @('--background')
            } },
        [ordered]@{ wsl = @{} },
        [ordered]@{ start = [ordered]@{
                command = @('factorseal-desktop.exe', '--open', 'wsl-keyrings')
                quiet_command = @('factorseal-desktop.exe', '--background')
            } }
    )
    uninstall = [ordered]@{
        registry_cleanup = @($browserHosts)
        ask_to_delete = @('%APPDATA%\Factorseal')
        keep_note = 'Your vault stays in %LOCALAPPDATA%\Factorseal\Factorseal\data, with your secrets; installing FactorSeal again opens it. To remove it for good, install FactorSeal and run factorseal.exe destroy --yes-really-destroy.'
    }
}
# UTF-8 without a byte order mark, which the installer's JSON reader refuses.
$json = $manifest | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText((Join-Path (Resolve-Path $release) 'factorseal-release.json'), $json, (New-Object System.Text.UTF8Encoding $false))
Write-Output (Resolve-Path $release).Path
