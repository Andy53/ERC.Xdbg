<#
.SYNOPSIS
    Builds the ERC.Xdbg plugin for x86, x64, or both.

.DESCRIPTION
    Locates MSBuild, restores packages, builds, and verifies that the resulting
    plugin actually carries the native export table x64dbg needs.

    Full MSBuild is required rather than "dotnet build": the plugin's entry points
    are native exports produced by rewriting the compiled IL, and that step only
    runs under MSBuild from Visual Studio or the Build Tools.

.EXAMPLE
    .\build.ps1
    Builds Release for both architectures.

.EXAMPLE
    .\build.ps1 -Platform x64 -Configuration Debug

.EXAMPLE
    .\build.ps1 -CleanPackages
    Restores into a throwaway package folder, so the build cannot quietly depend on
    something already sitting in the machine's NuGet cache.
#>
[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'both')]
    [string] $Platform = 'both',

    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    # Skips the export-table check. Only useful when diagnosing the build itself.
    [switch] $SkipVerify,

    <#
      Restore into an empty package folder instead of the machine's own.

      This exists because the build spent a long time working on developer machines
      and failing everywhere else. The metalib project was named DllExport, the same
      identity as the DllExport package it sits beside, so NuGet treated the
      dependency as already satisfied by the project and never downloaded the real
      package. Anyone whose cache happened to contain it from an earlier restore saw
      a working build; a clean checkout got a plugin with no native exports.

      Slow - everything downloads again - so it is opt in, and CI runs it.
    #>
    [switch] $CleanPackages
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = $PSScriptRoot
$solution = Join-Path $repoRoot 'ErcXdbgPlugin.sln'

$cleanPackageFolder = $null
if ($CleanPackages) {
    $cleanPackageFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("erc-packages-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $cleanPackageFolder | Out-Null
    $env:NUGET_PACKAGES = $cleanPackageFolder

    Write-Host "Restoring into a clean package folder: $cleanPackageFolder" -ForegroundColor Yellow

    # Stale obj folders carry a resolved dependency graph from the previous restore,
    # which would hide exactly the problem this switch is meant to expose.
    Get-ChildItem -Path $repoRoot -Recurse -Directory -Filter 'obj' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*\.git\*' } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

function Find-MSBuild {
    # vswhere ships with every VS installer and is the supported way to locate MSBuild.
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.Component.MSBuild `
            -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
        if ($found) { return $found }
    }

    $onPath = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    throw @'
MSBuild was not found.

The plugin's native exports are produced by an IL-rewriting build step that needs
full MSBuild; "dotnet build" cannot produce a loadable plugin on its own.

Install "Visual Studio 2022 Build Tools" with the ".NET desktop build tools"
workload, then run this script again.
'@
}

function Assert-NativeExports {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string[]] $Expected
    )

    # Read the PE export directory directly so the check needs no extra SDK tools.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ([System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 2) -ne 'PE') {
        throw "$Path is not a valid PE image."
    }

    $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
    $optional     = $peOffset + 24
    $magic        = [BitConverter]::ToUInt16($bytes, $optional)
    $isPe32Plus   = $magic -eq 0x20b

    # The export directory is data directory 0, which sits after the optional header.
    $exportRva = [BitConverter]::ToUInt32($bytes, $optional + $(if ($isPe32Plus) { 112 } else { 96 }))
    if ($exportRva -eq 0) {
        throw "$([System.IO.Path]::GetFileName($Path)) has no native export table - x64dbg would not load it."
    }

    $sections = $peOffset + 24 + $optionalSize
    function Convert-RvaToOffset([uint32] $rva) {
        for ($i = 0; $i -lt $sectionCount; $i++) {
            $s = $sections + ($i * 40)
            $virtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
            $virtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
            $rawPointer     = [BitConverter]::ToUInt32($bytes, $s + 20)
            if ($rva -ge $virtualAddress -and $rva -lt ($virtualAddress + [Math]::Max($virtualSize, 1))) {
                return $rawPointer + ($rva - $virtualAddress)
            }
        }
        throw "RVA 0x$($rva.ToString('x')) is outside every section."
    }

    $dir       = Convert-RvaToOffset $exportRva
    $nameCount = [BitConverter]::ToUInt32($bytes, $dir + 24)
    $nameTable = Convert-RvaToOffset ([BitConverter]::ToUInt32($bytes, $dir + 32))

    $names = @()
    for ($i = 0; $i -lt $nameCount; $i++) {
        $offset = Convert-RvaToOffset ([BitConverter]::ToUInt32($bytes, $nameTable + ($i * 4)))
        $end = $offset
        while ($bytes[$end] -ne 0) { $end++ }
        $names += [System.Text.Encoding]::ASCII.GetString($bytes, $offset, $end - $offset)
    }

    $missing = $Expected | Where-Object { $names -notcontains $_ }
    if ($missing) {
        throw "$([System.IO.Path]::GetFileName($Path)) is missing exports: $($missing -join ', '). Found: $($names -join ', ')"
    }

    Write-Host "    exports verified: $($names -join ', ')" -ForegroundColor DarkGray
}

function Assert-DebuggerBinding {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Platform
    )

    # The plugin P/Invokes into the host debugger, and the DLL it binds to differs
    # per architecture. Getting this wrong used to be possible - and silent - because
    # the choice lived in hand-edited source. Assert it instead.
    $wanted   = if ($Platform -eq 'x64') { 'x64' } else { 'x32' }
    $unwanted = if ($Platform -eq 'x64') { 'x32' } else { 'x64' }

    # The lookbehind keeps this from matching the substring inside the assembly's
    # own name, "Managed.x64dbg.dll". Real module references are standalone strings
    # in the metadata heap, so they are never preceded by a name character.
    #
    # Note: the metadata string heap folds a string that is a suffix of another
    # into it, so "x64dbg.dll" can be stored inside "Managed.x64dbg.dll" and go
    # unseen here. The bridge DLLs are never suffixes of anything, so they are the
    # load-bearing part of this check; the *bridge.dll assertions below are what
    # actually prove the architecture switch applied.
    $text  = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Path))
    $found = [regex]::Matches($text, '(?<![A-Za-z0-9._])x(?:32|64)(?:bridge|dbg)\.dll') |
             ForEach-Object { $_.Value } | Sort-Object -Unique

    $wrong = $found | Where-Object { $_ -like "$unwanted*" }
    if ($wrong) {
        throw "$([System.IO.Path]::GetFileName($Path)) binds the wrong debugger DLLs for $Platform : $($wrong -join ', ')"
    }
    if ($found -notcontains "${wanted}bridge.dll") {
        throw "$([System.IO.Path]::GetFileName($Path)) does not import ${wanted}bridge.dll - the architecture switch did not apply."
    }

    Write-Host "    debugger binding verified: $($found -join ', ')" -ForegroundColor DarkGray
}

$msbuild = Find-MSBuild
Write-Host "MSBuild: $msbuild" -ForegroundColor DarkGray

$platforms = if ($Platform -eq 'both') { @('x86', 'x64') } else { @($Platform) }

# x64dbg identifies a plugin's architecture by extension, not by inspecting it.
$expectedExports = @('pluginit', 'plugstop', 'plugsetup', 'CBMENUENTRY')

foreach ($p in $platforms) {
    Write-Host ""
    Write-Host "==> Building $Configuration|$p" -ForegroundColor Cyan

    & $msbuild $solution `
        -restore `
        -p:Configuration=$Configuration `
        -p:Platform=$p `
        -nologo `
        -verbosity:minimal `
        -maxcpucount

    if ($LASTEXITCODE -ne 0) { throw "Build failed for $Configuration|$p." }

    $suffix = if ($p -eq 'x64') { '64' } else { '32' }
    $plugin = Join-Path $repoRoot "ErcXdbg\bin\$p\$Configuration\net472\Erc.Xdbg.dp$suffix"

    if (-not (Test-Path $plugin)) { throw "Expected plugin was not produced: $plugin" }

    Write-Host "    $plugin" -ForegroundColor Green

    if (-not $SkipVerify) {
        Assert-NativeExports -Path $plugin -Expected $expectedExports

        $sdk = Join-Path $repoRoot "Managed.x64dbg\bin\$p\$Configuration\net472\Managed.x64dbg.dll"
        Assert-DebuggerBinding -Path $sdk -Platform $p
    }
}

if ($cleanPackageFolder) {
    Remove-Item Env:\NUGET_PACKAGES -ErrorAction SilentlyContinue
    Remove-Item $cleanPackageFolder -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Build succeeded." -ForegroundColor Green
