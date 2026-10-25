<#
.SYNOPSIS
    Safely unregisters ONLY the candidate package identity (link-protection-candidate).
.DESCRIPTION
    Terminates running candidate processes, removes the link-protection-candidate package,
    and strictly verifies that production registration (link-protection-system) remains
    completely intact and untouched.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection"
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BaitZero Candidate Package Rollback / Unregister " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$expectedProdDir = (Join-Path $ProjectRoot "src-tauri\target\release").TrimEnd('\')
$candidateDir = (Join-Path $ProjectRoot "src-tauri\target-candidate-v2\release").TrimEnd('\')

[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()

# ---------------------------------------------------------------------------
# Phase 1: Fail-Closed Production Baseline Pre-Verification
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 1] Pre-verifying production package baseline registration..." -ForegroundColor Cyan

$preProdPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($preProdPkgs.Count -ne 1) {
    throw "FAIL-CLOSED: Production package 'link-protection-system' not found or ambiguous before rollback (count: $($preProdPkgs.Count)). Aborting without changes."
}
$preProdPkg = $preProdPkgs[0]
$preProdExternal = $preProdPkg.EffectiveExternalLocation.Path.TrimEnd('\')
if ($preProdExternal -ne $expectedProdDir) {
    throw "FAIL-CLOSED: Production package is registered to unexpected path '$preProdExternal' (expected: '$expectedProdDir'). Aborting without changes."
}
Write-Host "  [OK] Production baseline pre-verified intact:" -ForegroundColor Green
Write-Host "       Name:             $($preProdPkg.Id.Name)"
Write-Host "       FullName:         $($preProdPkg.Id.FullName)"
Write-Host "       ExternalLocation: $preProdExternal"

# ---------------------------------------------------------------------------
# Phase 2: Terminate candidate process if running
# ---------------------------------------------------------------------------
$procs = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
    try {
        $exePath = $p.MainModule.FileName
        if ($exePath -like "$candidateDir*") {
            Write-Host "Terminating running candidate process (PID $($p.Id))..." -ForegroundColor Yellow
            Stop-Process -Id $p.Id -Force
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Write-Host "Note: Could not inspect MainModule for PID $($p.Id): $_" -ForegroundColor Yellow
    }
}

# 2. Query Candidate Package
$candPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })

if ($candPkgs.Count -eq 0) {
    Write-Host "[Rollback] Candidate package 'link-protection-candidate' is not registered. Nothing to remove." -ForegroundColor Green
} else {
    foreach ($cand in $candPkgs) {
        Write-Host "Removing candidate package '$($cand.Id.FullName)'..." -ForegroundColor Yellow
        Remove-AppxPackage -Package $cand.Id.FullName -ErrorAction Stop
        Write-Host "  [OK] Remove-AppxPackage completed for candidate." -ForegroundColor Green
    }
}

# 3. Verify Candidate Package is gone
$recheckCand = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })
if ($recheckCand.Count -ne 0) {
    throw "FAIL-CLOSED: Candidate package is still registered after removal attempt!"
}
Write-Host "[Verification] Candidate package successfully unregistered." -ForegroundColor Green

# 4. Strict Production Baseline Verification
Write-Host "`n[Production Baseline Check]" -ForegroundColor Cyan
$prodPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($prodPkgs.Count -ne 1) {
    Write-Host "[CRITICAL ALERT] Production package 'link-protection-system' is missing or ambiguous!" -ForegroundColor Red
    Write-Host "Manual Recovery Instruction:" -ForegroundColor Yellow
    Write-Host "  Add-AppxPackage -Register `"$ProjectRoot\.winapp\debug\appxmanifest.xml`" -ExternalLocation `"$expectedProdDir`"" -ForegroundColor Yellow
    throw "FAIL-CLOSED: Production baseline compromised!"
}
$prodPkg = $prodPkgs[0]
if ($prodPkg.EffectiveExternalLocation.Path.TrimEnd('\') -ne $expectedProdDir) {
    Write-Host "[CRITICAL ALERT] Production package points to unexpected location!" -ForegroundColor Red
    Write-Host "Manual Recovery Instruction:" -ForegroundColor Yellow
    Write-Host "  Add-AppxPackage -Register `"$ProjectRoot\.winapp\debug\appxmanifest.xml`" -ExternalLocation `"$expectedProdDir`"" -ForegroundColor Yellow
    throw "FAIL-CLOSED: Production external location altered!"
}

Write-Host "  [VERIFIED] Production registration remains 100% intact:" -ForegroundColor Green
Write-Host "    Name:             $($prodPkg.Id.Name)"
Write-Host "    FullName:         $($prodPkg.Id.FullName)"
Write-Host "    ExternalLocation: $($prodPkg.EffectiveExternalLocation.Path)"
Write-Host "    Status.VerifyIsOK:$($prodPkg.Status.VerifyIsOK())"
Write-Host "`nCandidate rollback complete. System is clean." -ForegroundColor Green
