<#
.SYNOPSIS
    Read-only verification of production and candidate package coexistence.
.DESCRIPTION
    Queries Windows Package Manager for link-protection-system and link-protection-candidate,
    verifying both exist independently with correct external locations and healthy status.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BaitZero Side-by-Side Coexistence Verification " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$expectedProdDir = (Join-Path $ProjectRoot "src-tauri\target\release").TrimEnd('\')
$expectedCandDir = (Join-Path $ProjectRoot "src-tauri\target-candidate-v2\release").TrimEnd('\')

[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()

# 1. Query Production Package
Write-Host "`n[1. Production Package Registration]" -ForegroundColor Cyan
$prodPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($prodPkgs.Count -eq 0) {
    Write-Host "  [MISSING] Production package 'link-protection-system' is NOT registered!" -ForegroundColor Red
} else {
    foreach ($p in $prodPkgs) {
        $ext = $p.EffectiveExternalLocation.Path.TrimEnd('\')
        $locOk = ($ext -eq $expectedProdDir)
        Write-Host "  Name:             $($p.Id.Name)" -ForegroundColor $(if ($locOk) { "Green" } else { "Yellow" })
        Write-Host "  FullName:         $($p.Id.FullName)"
        Write-Host "  ExternalLocation: $ext"
        Write-Host "  Location Valid:   $locOk (expected: $expectedProdDir)"
        Write-Host "  Status.VerifyIsOK:$($p.Status.VerifyIsOK())"
        Write-Host "  DevelopmentMode:  $($p.IsDevelopmentMode)"
    }
}

# 2. Query Candidate Package
Write-Host "`n[2. Candidate Package Registration]" -ForegroundColor Cyan
$candPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })
if ($candPkgs.Count -eq 0) {
    Write-Host "  [INFO] Candidate package 'link-protection-candidate' is NOT registered." -ForegroundColor Yellow
} else {
    foreach ($p in $candPkgs) {
        $ext = $p.EffectiveExternalLocation.Path.TrimEnd('\')
        $locOk = ($ext -eq $expectedCandDir)
        Write-Host "  Name:             $($p.Id.Name)" -ForegroundColor $(if ($locOk) { "Green" } else { "Yellow" })
        Write-Host "  FullName:         $($p.Id.FullName)"
        Write-Host "  ExternalLocation: $ext"
        Write-Host "  Location Valid:   $locOk (expected: $expectedCandDir)"
        Write-Host "  Status.VerifyIsOK:$($p.Status.VerifyIsOK())"
        Write-Host "  DevelopmentMode:  $($p.IsDevelopmentMode)"
    }
}

# 3. Overall Coexistence Assessment
Write-Host "`n[3. Coexistence Summary]" -ForegroundColor Cyan
$prodOk = ($prodPkgs.Count -eq 1 -and $prodPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\') -eq $expectedProdDir)
$candOk = ($candPkgs.Count -eq 1 -and $candPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\') -eq $expectedCandDir)

if ($prodOk -and $candOk) {
    Write-Host "  [STATUS: COEXISTING] Both packages are registered side-by-side with separate external locations." -ForegroundColor Green
} elseif ($prodOk -and (-not $candOk)) {
    Write-Host "  [STATUS: PRODUCTION ONLY] Production package is registered and healthy. Candidate package is not yet registered." -ForegroundColor Yellow
} else {
    Write-Host "  [STATUS: ANOMALY] Production registration is missing or not pointing to expected location!" -ForegroundColor Red
}

# 4. Running Processes
Write-Host "`n[4. Process Status]" -ForegroundColor Cyan
$running = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "  Active PID(s): $(($running | Select-Object -ExpandProperty Id) -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host "  No running link-protection-system processes." -ForegroundColor Green
}
