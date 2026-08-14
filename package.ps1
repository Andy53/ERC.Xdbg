<#
.SYNOPSIS
    Produces the release archives, and the hashes the in-plugin updater requires.

.DESCRIPTION
    x64dbg loads a plugin from its plugins directory, and "ERC --update" installs a
    new one by extracting an archive straight into that directory. So the archive is
    not a convenience wrapper: its contents are exactly what ends up on disk, and
    anything missing from it is missing from the installation.

    That contract is stated once, in $Payload below, and asserted from the test suite
    (ReleasePackageTests) so a dependency added to the build without being added here
    fails a test rather than shipping a plugin that cannot load.

    Every archive is published with a "<name>.sha256" beside it. The updater refuses
    any download whose hash is not published, so a release without these cannot be
    installed at all.

.PARAMETER Platform
    x86, x64, or both (the default).

.PARAMETER Configuration
    Release by default. Debug is accepted for testing the packaging itself.

.PARAMETER OutputDirectory
    Where the archives are written. Defaults to "artifacts" at the repository root.

.PARAMETER SkipBuild
    Package whatever is already built, rather than building first.

.EXAMPLE
    .\package.ps1
    Builds both architectures and writes artifacts\Erc.Xdbg-x86.zip and -x64.zip.
#>

[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'both')]
    [string]$Platform = 'both',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDirectory,

    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts' }

# ---------------------------------------------------------------- the payload
#
# What a release archive contains, and why. Anything not listed is deliberately
# left out: shipping build by-products into a user's plugins directory is at best
# noise and at worst confusing when a stale copy is loaded.
$Payload = @(
    @{ Name = 'Erc.Xdbg.dp{arch}'; Required = $true
       Why  = 'The plugin. x64dbg selects it by extension, .dp32 or .dp64.' }

    @{ Name = 'FASM.DLL'; Required = $true
       Why  = 'Native assembler used by --assemble. Costura embeds managed dependencies into the plugin, but not this.' }

    @{ Name = 'FASMX64.DLL'; Required = $true
       Why  = 'The 64-bit half of the same assembler.' }

    @{ Name = 'FASM-LICENSE.TXT'; Required = $true
       Why  = "FASM's licence requires its notice to travel with the binaries." }
)

# Present in the build output and deliberately not shipped.
$Excluded = @(
    @{ Name = 'Erc.Xdbg.dll'
       Why  = 'The same assembly as the .dp file. x64dbg loads the .dp; a second copy only invites loading the wrong one.' }

    @{ Name = 'ERC.Net.xml'
       Why  = 'API documentation for consumers of the library, of no use inside a plugins directory.' }

    @{ Name = 'Erc.Xdbg.dll.config'
       Why  = 'Binding redirects are read from the host process configuration, x64dbg.exe.config, never from a plugin DLL. This file has no effect where it lands.' }

    @{ Name = 'Managed.x64dbg.dll.config'
       Why  = 'The same, for the SDK assembly.' }

    @{ Name = 'Reloaded.Assembler.targets'
       Why  = 'An MSBuild import that arrives through the package. Build-time only.' }
)

function Get-ArchSuffix([string]$platform) {
    if ($platform -eq 'x64') { return '64' } else { return '32' }
}

function New-Package([string]$platform) {
    $suffix = Get-ArchSuffix $platform
    $binDirectory = Join-Path $root "ErcXdbg\bin\$platform\$Configuration\net472"

    if (-not (Test-Path $binDirectory)) {
        throw "No build output at $binDirectory. Run build.ps1, or drop -SkipBuild."
    }

    $staging = Join-Path ([System.IO.Path]::GetTempPath()) ("erc-package-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $staging | Out-Null

    try {
        foreach ($item in $Payload) {
            $name = $item.Name.Replace('{arch}', $suffix)
            $source = Join-Path $binDirectory $name

            if (-not (Test-Path $source)) {
                if ($item.Required) {
                    throw "$name is missing from $binDirectory. The release would install a plugin that cannot work: $($item.Why)"
                }
                continue
            }

            Copy-Item $source -Destination (Join-Path $staging $name)
        }

        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
        }

        $archive = Join-Path $OutputDirectory "Erc.Xdbg-$platform.zip"
        if (Test-Path $archive) { Remove-Item $archive }

        Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $archive

        # The updater reads this from "<asset url>.sha256" and refuses the download
        # if it is absent or does not match. The "<hash>  <name>" form is what
        # sha256sum and CertUtil produce, and what ParsePublishedHash accepts.
        $hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLower()
        $hashFile = "$archive.sha256"
        [System.IO.File]::WriteAllText($hashFile, "$hash  $(Split-Path $archive -Leaf)", [System.Text.Encoding]::ASCII)

        Write-Host ""
        Write-Host "==> $platform" -ForegroundColor Cyan
        Write-Host "    $archive"
        foreach ($entry in (Get-ChildItem $staging | Sort-Object Name)) {
            Write-Host ("      {0,-22} {1,10:N0} bytes" -f $entry.Name, $entry.Length)
        }
        Write-Host "    sha256: $hash"
    }
    finally {
        Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$platforms = if ($Platform -eq 'both') { @('x86', 'x64') } else { @($Platform) }

if (-not $SkipBuild) {
    foreach ($p in $platforms) {
        & (Join-Path $root 'build.ps1') -Platform $p -Configuration $Configuration
        if ($LASTEXITCODE -ne 0) { throw "Build failed for $Configuration|$p." }
    }
}

foreach ($p in $platforms) {
    New-Package $p
}

Write-Host ""
Write-Host "Packaging complete." -ForegroundColor Green
Write-Host "Publish each .zip together with its .sha256; the updater refuses a release without one."
