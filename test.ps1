<#
.SYNOPSIS
    Runs the ERC.Net test suite.

.DESCRIPTION
    Runs for x86, x64, or both. The library is built per architecture and reads
    pointer width at run time, so both legs are worth running: some behaviour
    (notably pointer filtering) differs between them.

.EXAMPLE
    .\test.ps1
    Runs the full suite for both architectures.

.EXAMPLE
    .\test.ps1 -Platform x64 -Coverage
    Runs the x64 leg and reports per-class coverage.

.EXAMPLE
    .\test.ps1 -PinnedDefectsOnly
    Runs only the tests that pin known-wrong behaviour.
#>
[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'both')]
    [string] $Platform = 'both',

    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug',

    # Collect coverage and print a per-class summary.
    [switch] $Coverage,

    # Run only tests tagged as pinning a known defect.
    [switch] $PinnedDefectsOnly,

    # Force every target framework on every platform. Requires an x86 .NET runtime
    # for the x86 net8.0 leg.
    [switch] $AllFrameworks,

    # Skip the live-process tests, which launch a target and take a few seconds.
    [switch] $SkipIntegration
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = $PSScriptRoot
$project  = Join-Path $repoRoot 'tests\ERC.Net.Tests\ERC.Net.Tests.csproj'

$platforms = if ($Platform -eq 'both') { @('x86', 'x64') } else { @($Platform) }

# The fixture the live-process tests launch. It is deliberately not a
# ProjectReference - that would tie its target framework and runtime identifier to
# the test project's - so it is built here instead. Without this the integration
# tests skip rather than run.
if (-not $PinnedDefectsOnly -and -not $SkipIntegration) {
    $fixture = Join-Path $repoRoot 'tests\Fixtures\ErcTestTarget\ErcTestTarget.csproj'

    foreach ($p in $platforms) {
        Write-Host "==> Building fixture target ($p)" -ForegroundColor DarkGray
        & dotnet build $fixture -c $Configuration "-p:Platform=$p" --nologo -v quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "The fixture target failed to build for $p." }
    }
}

foreach ($p in $platforms) {
    Write-Host ""
    Write-Host "==> Testing $Configuration|$p" -ForegroundColor Cyan

    $args = @(
        'test', $project,
        '-c', $Configuration,
        "-p:Platform=$p",
        '--nologo'
    )

    # Running the net8.0 leg as x86 needs an x86 .NET runtime installed alongside
    # the x64 one, which most machines do not have. net472 always works because the
    # .NET Framework ships both. So x86 covers net472 only; x64 covers both, which
    # is enough to prove the library works on a modern runtime.
    if ($p -eq 'x86' -and -not $AllFrameworks) {
        $args += @('-f', 'net472')
    }

    if ($PinnedDefectsOnly) {
        $args += @('--filter', 'Category=PinnedDefect')
    }
    elseif ($SkipIntegration) {
        $args += @('--filter', 'Category!=Integration')
    }

    if ($Coverage) {
        # coverlet's MSBuild integration is used rather than its VSTest collector:
        # the collector produces no output for this net472 xUnit v3 host.
        $args += @(
            '-p:CollectCoverage=true',
            '-p:CoverletOutputFormat=cobertura',
            '-p:CoverletOutput=coverage/',
            '-p:Include="[ERC.Net]*"'
        )
    }

    & dotnet @args
    if ($LASTEXITCODE -ne 0) { throw "Tests failed for $Configuration|$p." }
}

if ($Coverage) {
    $report = Get-ChildItem -Recurse -Filter 'coverage.cobertura.xml' `
                            (Join-Path $repoRoot 'tests\ERC.Net.Tests') |
              Select-Object -First 1

    if ($report) {
        [xml] $xml = Get-Content $report.FullName
        Write-Host ""
        Write-Host "Coverage by class (ERC.Net):" -ForegroundColor Cyan

        $xml.coverage.packages.package.classes.class |
            Where-Object { [double] $_.'line-rate' -gt 0 } |
            Sort-Object { [double] $_.'line-rate' } -Descending |
            Select-Object @{ n = 'Class';  e = { $_.name -replace '^ERC\.', '' } },
                          @{ n = 'Lines';  e = { '{0,6:P1}' -f [double] $_.'line-rate' } },
                          @{ n = 'Branch'; e = { '{0,6:P1}' -f [double] $_.'branch-rate' } } |
            Format-Table -AutoSize

        Write-Host "Total: $('{0:P2}' -f [double] $xml.coverage.'line-rate') of lines" -ForegroundColor DarkGray
        Write-Host "Untested classes are the live-process and ROP code - see phases 04 and 06." -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Tests passed." -ForegroundColor Green
