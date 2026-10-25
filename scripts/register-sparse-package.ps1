<#
.SYNOPSIS
    Registers or updates the Windows Sparse Package registration for Link Protection System.
.DESCRIPTION
    Validates manifest, assets, and external location layout, then registers the sparse package
    with external location pointing to src-tauri\target\release.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection"
)

$ErrorActionPreference = "Stop"

Set-Location $ProjectRoot

$manifestDir = Join-Path $ProjectRoot ".winapp\debug"
$manifestPath = Join-Path $manifestDir "appxmanifest.xml"
$externalLocation = Join-Path $ProjectRoot "src-tauri\target\release"
$assetsSource = Join-Path $ProjectRoot "msix-staging\Assets"
$debugAssets = Join-Path $manifestDir "Assets"
$rootAssets = Join-Path $ProjectRoot "Assets"

Write-Host "=== Link Protection Sparse Package Registration ===" -ForegroundColor Cyan
Write-Host "Project Root:      $ProjectRoot"
Write-Host "Manifest Directory: $manifestDir"
Write-Host "External Location:  $externalLocation"

# 1. Ensure assets exist
if (Test-Path $assetsSource) {
    if (-not (Test-Path $debugAssets)) {
        New-Item -ItemType Directory -Path $debugAssets -Force | Out-Null
        Copy-Item -Path "$assetsSource\*" -Destination $debugAssets -Force
        Write-Host "[Assets] Copied assets to $debugAssets" -ForegroundColor Green
    }
    if (-not (Test-Path $rootAssets)) {
        New-Item -ItemType Directory -Path $rootAssets -Force | Out-Null
        Copy-Item -Path "$assetsSource\*" -Destination $rootAssets -Force
        Write-Host "[Assets] Copied assets to $rootAssets" -ForegroundColor Green
    }
}

# 2. Ensure manifest exists
if (-not (Test-Path $manifestPath)) {
    Write-Host "[Manifest] Missing $manifestPath. Generating via winapp..." -ForegroundColor Yellow
    $exePath = Join-Path $externalLocation "link-protection-system.exe"
    winapp create-debug-identity $exePath --keep-identity
}

# 3. Check current package registration
$existingPkg = Get-AppxPackage -Name "link-protection-system" -ErrorAction SilentlyContinue

[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()
$registeredPkg = $pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" }

$needsRegistration = $false
if (-not $registeredPkg) {
    $needsRegistration = $true
    Write-Host "[Registration] Package not currently registered." -ForegroundColor Yellow
} else {
    $currentExt = $registeredPkg.EffectiveExternalLocation.Path.TrimEnd('\')
    $targetExt = $externalLocation.TrimEnd('\')
    if ($currentExt -ne $targetExt) {
        Write-Host "[Registration] Package registered with external location: $currentExt" -ForegroundColor Yellow
        Write-Host "[Registration] Target external location is: $targetExt. Updating registration..." -ForegroundColor Yellow
        $needsRegistration = $true
    } else {
        Write-Host "[Registration] Package is already registered with correct external location: $targetExt" -ForegroundColor Green
    }
}

if ($needsRegistration) {
    Write-Host "[Registration] Registering sparse package from $manifestPath..." -ForegroundColor Cyan
    try {
        Add-AppxPackage -Register $manifestPath -ExternalLocation $externalLocation -ErrorAction Stop
        Write-Host "[Registration] Add-AppxPackage completed successfully." -ForegroundColor Green
    } catch {
        Write-Host "[Registration] Add-AppxPackage failed: $_. Retrying via winapp create-debug-identity..." -ForegroundColor Yellow
        $exePath = Join-Path $externalLocation "link-protection-system.exe"
        winapp create-debug-identity $exePath --keep-identity
    }
}

# 4. Verify registration
$verifiedPkg = $pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" }
if ($verifiedPkg) {
    Write-Host "`nRegistration Verified:" -ForegroundColor Green
    Write-Host "  Name:                      $($verifiedPkg.Id.Name)"
    Write-Host "  FullName:                  $($verifiedPkg.Id.FullName)"
    Write-Host "  InstalledPath:             $($verifiedPkg.InstalledPath)"
    Write-Host "  EffectiveExternalLocation: $($verifiedPkg.EffectiveExternalLocation.Path)"
} else {
    throw "Failed to verify package registration."
}
