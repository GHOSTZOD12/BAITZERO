<#
.SYNOPSIS
    Registers the BaitZero candidate package identity (link-protection-candidate)
    side-by-side with production registration.
.DESCRIPTION
    Safely registers .winapp\candidate\appxmanifest.xml with ExternalLocation
    src-tauri\target-candidate-v2\release.
    Enforces strict pre- and post-validation to guarantee that production registration
    (link-protection-system) is completely untouched.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection"
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BaitZero Candidate Package Registration (Side-by-Side) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$manifestDir = Join-Path $ProjectRoot ".winapp\candidate"
$manifestPath = Join-Path $manifestDir "appxmanifest.xml"
$externalLocation = Join-Path $ProjectRoot "src-tauri\target-candidate-v2\release"
$candidateExe = Join-Path $externalLocation "link-protection-system.exe"
$assetsSource = Join-Path $ProjectRoot "msix-staging\Assets"
$candidateAssets = Join-Path $manifestDir "Assets"
$expectedProdDir = (Join-Path $ProjectRoot "src-tauri\target\release").TrimEnd('\')

[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()

# ---------------------------------------------------------------------------
# Phase 1: Fail-Closed Production Baseline Verification
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 1] Verifying production package baseline registration..." -ForegroundColor Cyan

$prodPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($prodPkgs.Count -ne 1) {
    throw "FAIL-CLOSED: Production package 'link-protection-system' not found or ambiguous (count: $($prodPkgs.Count)). Cannot proceed."
}
$prodPkg = $prodPkgs[0]
$prodExternal = $prodPkg.EffectiveExternalLocation.Path.TrimEnd('\')
if ($prodExternal -ne $expectedProdDir) {
    throw "FAIL-CLOSED: Production package is registered to unexpected path '$prodExternal' (expected: '$expectedProdDir')."
}
Write-Host "  [OK] Production registration verified intact:" -ForegroundColor Green
Write-Host "       Name:             $($prodPkg.Id.Name)"
Write-Host "       FullName:         $($prodPkg.Id.FullName)"
Write-Host "       ExternalLocation: $prodExternal"

# ---------------------------------------------------------------------------
# Phase 2: Active Process & Target File Verification
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 2] Verifying no running processes and validating candidate binary..." -ForegroundColor Cyan

$running = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
if ($running) {
    $pids = ($running | Select-Object -ExpandProperty Id) -join ", "
    throw "FAIL-CLOSED: Existing link-protection-system process(es) running (PIDs: $pids). Cannot proceed."
}
Write-Host "  [OK] No running BaitZero processes detected." -ForegroundColor Green

if (-not (Test-Path $manifestPath)) {
    throw "FAIL-CLOSED: Candidate manifest missing at '$manifestPath'."
}
if (-not (Test-Path $candidateExe)) {
    throw "FAIL-CLOSED: Candidate executable missing at '$candidateExe'. Please run build-candidate-v2.ps1 first."
}

# Verify candidate binary embedded manifest
$bytes = [System.IO.File]::ReadAllBytes($candidateExe)
$str = [System.Text.Encoding]::UTF8.GetString($bytes)
if ($str -notmatch 'packageName="link-protection-candidate"') {
    throw "FAIL-CLOSED: Candidate executable does NOT have embedded packageName='link-protection-candidate'!"
}
if ($str -notmatch 'applicationId="linkprotectioncandidate"') {
    throw "FAIL-CLOSED: Candidate executable does NOT have embedded applicationId='linkprotectioncandidate'!"
}
Write-Host "  [OK] Candidate executable embedded manifest verified." -ForegroundColor Green

# Ensure visual assets exist
if (-not (Test-Path $candidateAssets)) {
    New-Item -ItemType Directory -Path $candidateAssets -Force | Out-Null
    Copy-Item "$assetsSource\*" -Destination $candidateAssets -Force
    Write-Host "  [OK] Copied assets to $candidateAssets" -ForegroundColor Green
}

# Ensure visual assets exist at externalLocation for AppX runtime icon resolution
$externalAssets = Join-Path $externalLocation "Assets"
if (-not (Test-Path $externalAssets)) {
    New-Item -ItemType Directory -Path $externalAssets -Force | Out-Null
}
Copy-Item "$candidateAssets\*" -Destination $externalAssets -Force
Write-Host "  [OK] Synchronized package visual assets to $externalAssets" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Phase 3: Candidate Package Registration
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 3] Checking candidate package registration..." -ForegroundColor Cyan

[xml]$targetXml = Get-Content $manifestPath
$targetVersion = $targetXml.Package.Identity.Version

$existingCand = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })

$needsRegistration = $true
if ($existingCand.Count -gt 0) {
    $candInstalled = $existingCand[0]
    $installedVer = "$($candInstalled.Id.Version.Major).$($candInstalled.Id.Version.Minor).$($candInstalled.Id.Version.Build).$($candInstalled.Id.Version.Revision)"
    $installedExt = $candInstalled.EffectiveExternalLocation.Path.TrimEnd('\')

    if ($installedVer -eq $targetVersion -and $installedExt -eq $externalLocation.TrimEnd('\')) {
        Write-Host "  [OK] Candidate package 'link-protection-candidate' is already registered at target version $installedVer with correct external location." -ForegroundColor Green
        Write-Host "       Skipping redundant registration to prevent Windows 0x80073CFB (package already installed)." -ForegroundColor Green
        $needsRegistration = $false
    } elseif ($installedVer -ne $targetVersion) {
        Write-Host "  [INFO] Candidate package version change detected (installed: $installedVer, target: $targetVersion). Applying in-place update..." -ForegroundColor Cyan
    } else {
        Write-Host "  [INFO] Candidate package external location change detected. Re-registering..." -ForegroundColor Yellow
    }
}

if ($needsRegistration) {
    Write-Host "  Registering/updating candidate sparse package from $manifestPath..." -ForegroundColor Cyan
    try {
        Add-AppxPackage -Register $manifestPath -ExternalLocation $externalLocation -ForceApplicationShutdown -ErrorAction Stop
        Write-Host "  [OK] Add-AppxPackage succeeded." -ForegroundColor Green
    } catch {
        $exMsg = $_.Exception.Message
        if ($exMsg -like "*0x80073CFB*" -or $exMsg -like "*already installed*") {
            Write-Host "`n[WARNING] Windows AppX Deployment blocked registration: package is already installed (0x80073CFB)." -ForegroundColor Yellow
            Write-Host "  To apply updated manifest properties to an installed development package:" -ForegroundColor Yellow
            Write-Host "  1. (Recommended) Increment Version in .winapp\candidate\appxmanifest.xml (e.g. 1.0.0.1) for an in-place update." -ForegroundColor Yellow
            Write-Host "  2. Or unregister the existing candidate package first (powershell -File scripts\rollback-candidate-package.ps1)." -ForegroundColor Yellow
            throw
        } else {
            throw
        }
    }
}

# ---------------------------------------------------------------------------
# Phase 4: Side-by-Side Coexistence Verification
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 4] Verifying side-by-side coexistence..." -ForegroundColor Cyan

$allCand = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })
if ($allCand.Count -ne 1) {
    throw "FAIL-CLOSED: Candidate package verification failed after registration (found $($allCand.Count) packages)."
}
$candPkg = $allCand[0]

# RE-VERIFY PRODUCTION REGISTRATION HAS NOT CHANGED
$allProd = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($allProd.Count -ne 1) {
    Write-Host "`n[CRITICAL ALERT] Production package 'link-protection-system' was modified or removed during candidate registration!" -ForegroundColor Red
    Write-Host "Manual Recovery Instruction:" -ForegroundColor Yellow
    Write-Host "  Add-AppxPackage -Register `"$ProjectRoot\.winapp\debug\appxmanifest.xml`" -ExternalLocation `"$expectedProdDir`"" -ForegroundColor Yellow
    throw "FAIL-CLOSED: Production registration compromised!"
}
$reverifiedProd = $allProd[0]
if ($reverifiedProd.EffectiveExternalLocation.Path.TrimEnd('\') -ne $expectedProdDir) {
    Write-Host "`n[CRITICAL ALERT] Production package external location was modified!" -ForegroundColor Red
    Write-Host "Manual Recovery Instruction:" -ForegroundColor Yellow
    Write-Host "  Add-AppxPackage -Register `"$ProjectRoot\.winapp\debug\appxmanifest.xml`" -ExternalLocation `"$expectedProdDir`"" -ForegroundColor Yellow
    throw "FAIL-CLOSED: Production external location altered!"
}

Write-Host "  [SUCCESS] Both packages are registered side-by-side:" -ForegroundColor Green
Write-Host "  1. Production Package:"
Write-Host "     Name:             $($reverifiedProd.Id.Name)"
Write-Host "     FullName:         $($reverifiedProd.Id.FullName)"
Write-Host "     ExternalLocation: $($reverifiedProd.EffectiveExternalLocation.Path)"
Write-Host "  2. Candidate Package:"
Write-Host "     Name:             $($candPkg.Id.Name)"
Write-Host "     FullName:         $($candPkg.Id.FullName)"
Write-Host "     ExternalLocation: $($candPkg.EffectiveExternalLocation.Path)"
