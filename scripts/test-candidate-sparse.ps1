<#
.SYNOPSIS
    Guarded test harness for launching the isolated candidate with Windows Package Identity.
.DESCRIPTION
    Stage 3C-6 Guarded Test Harness.
    Validates environment, SHA-256 binary hashes, process isolation, and port availability.
    Safely and reversibly updates Windows Sparse Package registration to point to the isolated
    candidate directory, launches the isolated candidate with Package Identity verification,
    and unconditionally restores package registration back to production in a finally block.

    STRICT SAFETY NOTICE:
    This script requires the explicit opt-in parameter -AllowRegistrationSwitch.
    Without this switch, the script aborts immediately with zero modifications.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$AllowRegistrationSwitch,

    [Parameter(Mandatory = $false)]
    [string]$ProjectRoot = "C:\Dev\LinkProtection",

    [Parameter(Mandatory = $false)]
    [int]$WaitSeconds = 4
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " BaitZero Stage 3C-6: Guarded Isolated Candidate Sparse Harness " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Phase 0: Explicit Opt-in Parameter Check (Fail-Closed)
# ---------------------------------------------------------------------------
if (-not $AllowRegistrationSwitch) {
    Write-Host "`n[OPT-IN REQUIRED] -AllowRegistrationSwitch was NOT specified." -ForegroundColor Yellow
    Write-Host "No system package registration changes or process launches will be performed." -ForegroundColor Yellow
    Write-Host "To execute in an authorized future test run, re-run with: -AllowRegistrationSwitch" -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------------------
# Phase 1: Environment & File Path Definitions
# ---------------------------------------------------------------------------
$manifestDir = Join-Path $ProjectRoot ".winapp\debug"
$manifestPath = Join-Path $manifestDir "appxmanifest.xml"

$prodExe = Join-Path $ProjectRoot "src-tauri\target\release\link-protection-system.exe"
$candExe = Join-Path $ProjectRoot "src-tauri\target-candidate\release\link-protection-system.exe"
$isolatedCandExe = Join-Path $ProjectRoot "src-tauri\target-stage3-candidate\release\link-protection-system.exe"
$isolatedCandDir = Split-Path -Parent $isolatedCandExe

$testDataDir = Join-Path $ProjectRoot "scratch\test-data"
$testWv2Dir = Join-Path $ProjectRoot "scratch\test-wv2"

$expectedProdHash = "AAF8C161FFA2E9D9504D55C00590C8DACFB14562265612E22DF4ADD76DCE7A0E"
$expectedCandHash = "FE6E8F533BCD48BD1CC2F0D8FB44CFCF00D93212A030F523E57E6530BE27D95E"
$expectedIsolatedCandHash = "7921263D462B0E90AAD8A63A27C6C2D0CE79BB5475067574B3E8AE7E2BDFA203"

Write-Host "`n[Phase 1] Validating file existence and SHA-256 hashes..." -ForegroundColor Cyan

if (-not (Test-Path $manifestPath)) {
    throw "FAIL-CLOSED: Manifest not found at '$manifestPath'."
}

$filesToCheck = @(
    @{ Name = "Production Executable"; Path = $prodExe; Expected = $expectedProdHash },
    @{ Name = "Existing Candidate";    Path = $candExe; Expected = $expectedCandHash },
    @{ Name = "Isolated Candidate";    Path = $isolatedCandExe; Expected = $expectedIsolatedCandHash }
)

foreach ($f in $filesToCheck) {
    if (-not (Test-Path $f.Path)) {
        throw "FAIL-CLOSED: $($f.Name) missing at '$($f.Path)'."
    }
    $actualHash = (Get-FileHash -Path $f.Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actualHash -ne $f.Expected) {
        throw "FAIL-CLOSED: $($f.Name) hash mismatch! Expected: $($f.Expected), Actual: $actualHash"
    }
    Write-Host "  [OK] $($f.Name): Verified ($actualHash)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Phase 2: Process & Port Availability Checks (Fail-Closed)
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 2] Verifying no running BaitZero instances and ports..." -ForegroundColor Cyan

$runningProcs = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
if ($runningProcs) {
    $pids = ($runningProcs | Select-Object -ExpandProperty Id) -join ", "
    throw "FAIL-CLOSED: Existing link-protection-system process(es) running (PIDs: $pids). Cannot proceed with test."
}

function Test-TcpPortInUse([int]$Port) {
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return ($listeners | Where-Object { $_.Port -eq $Port }) -ne $null
}

if (Test-TcpPortInUse 27433) {
    throw "FAIL-CLOSED: Test port 27433 is already in use by another service."
}
if (Test-TcpPortInUse 27432) {
    throw "FAIL-CLOSED: Production port 27432 is active. Must ensure isolated test environment."
}
Write-Host "  [OK] No running BaitZero processes detected." -ForegroundColor Green
Write-Host "  [OK] Ports 27433 (test) and 27432 (prod) verified clean." -ForegroundColor Green

# ---------------------------------------------------------------------------
# Phase 3: Inspect & Record Original Package Registration
# ---------------------------------------------------------------------------
Write-Host "`n[Phase 3] Inspecting current sparse package registration..." -ForegroundColor Cyan

[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()
$registeredPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })

if ($registeredPkgs.Count -eq 0) {
    throw "FAIL-CLOSED: Package 'link-protection-system' is not registered. Cannot record baseline registration."
}
if ($registeredPkgs.Count -gt 1) {
    throw "FAIL-CLOSED: Ambiguous package registration: found $($registeredPkgs.Count) packages matching 'link-protection-system'."
}

$origPkg = $registeredPkgs[0]
$origFullName = $origPkg.Id.FullName
$origExternalLocation = $origPkg.EffectiveExternalLocation.Path.TrimEnd('\')
$expectedProdDir = (Split-Path -Parent $prodExe).TrimEnd('\')

if (-not $origExternalLocation) {
    throw "FAIL-CLOSED: Registered package has empty or missing EffectiveExternalLocation."
}
if ($origExternalLocation -ne $expectedProdDir) {
    throw "FAIL-CLOSED: Registered package external location ('$origExternalLocation') does not match expected production location ('$expectedProdDir')."
}

Write-Host "  [OK] Baseline registration verified:" -ForegroundColor Green
Write-Host "       Package FullName:  $origFullName"
Write-Host "       External Location: $origExternalLocation"

# Manual recovery advisory
Write-Host "`n-----------------------------------------------------------------" -ForegroundColor Magenta
Write-Host " IMPORTANT ADVISORY ON SYSTEM REGISTRATION RECOVERY:" -ForegroundColor Magenta
Write-Host " While this harness uses try/finally to restore registration," -ForegroundColor Magenta
Write-Host " PowerShell finally blocks DO NOT execute on unexpected power loss," -ForegroundColor Magenta
Write-Host " hard process termination (taskkill /F), or system kernel crashes." -ForegroundColor Magenta
Write-Host " If any unhandled interruption occurs, restore manually by running:" -ForegroundColor Magenta
Write-Host "   Add-AppxPackage -Register `"$manifestPath`" -ExternalLocation `"$origExternalLocation`"" -ForegroundColor Yellow
Write-Host "-----------------------------------------------------------------`n" -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# Phase 4: Setup P/Invoke for Package Identity Inspection
# ---------------------------------------------------------------------------
$pInvokeCode = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace BaitZeroTestHarness {
    public static class AppModelVerifier {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetPackageFullName(
            IntPtr hProcess,
            ref int packageFullNameLength,
            StringBuilder packageFullName
        );
    }
}
'@
if (-not ([System.Management.Automation.PSTypeName]'BaitZeroTestHarness.AppModelVerifier').Type) {
    Add-Type -TypeDefinition $pInvokeCode -ErrorAction Stop
}

# ---------------------------------------------------------------------------
# Phase 5: Reversible Registration Switch & Guarded Execution
# ---------------------------------------------------------------------------
$registrationSwitched = $false
$launchedProc = $null

try {
    Write-Host "[Phase 5.1] Updating registration to isolated candidate folder..." -ForegroundColor Cyan
    Write-Host "            Target Location: $isolatedCandDir"
    
    Add-AppxPackage -Register $manifestPath -ExternalLocation $isolatedCandDir -ErrorAction Stop
    $registrationSwitched = $true

    # Verify switch
    $switchedPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
    if ($switchedPkgs.Count -ne 1) {
        throw "FAIL-CLOSED: Switched package verification failed (found $($switchedPkgs.Count) packages)."
    }
    $currentExt = $switchedPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\')
    if ($currentExt -ne $isolatedCandDir.TrimEnd('\')) {
        throw "FAIL-CLOSED: Package external location did not update to candidate directory! Current: '$currentExt'"
    }
    Write-Host "  [OK] Registration successfully switched to isolated candidate." -ForegroundColor Green

    # Setup isolated directories
    if (-not (Test-Path $testDataDir)) { New-Item -ItemType Directory -Path $testDataDir -Force | Out-Null }
    if (-not (Test-Path $testWv2Dir)) { New-Item -ItemType Directory -Path $testWv2Dir -Force | Out-Null }

    # Setup isolated test environment variables
    $env:BAITZERO_ISOLATED_TEST_MODE = "1"
    $env:BAITZERO_TEST_MUTEX = "Global\BaitZeroTestSingleInstance"
    $env:BAITZERO_TEST_ACTIVATE_EVENT = "Global\BaitZeroTestActivate"
    $env:BAITZERO_TEST_PORT = "27433"
    $env:BAITZERO_TEST_DATA_DIR = $testDataDir
    $env:WEBVIEW2_USER_DATA_FOLDER = $testWv2Dir

    Write-Host "`n[Phase 5.2] Launching isolated candidate process..." -ForegroundColor Cyan
    Write-Host "            Executable: $isolatedCandExe"
    
    # Launch ONLY isolated candidate (never production or existing candidate)
    $launchedProc = Start-Process -FilePath $isolatedCandExe -WorkingDirectory $isolatedCandDir -PassThru
    Write-Host "  Candidate launched with PID: $($launchedProc.Id)" -ForegroundColor Green

    Write-Host "  Observing process startup for $WaitSeconds seconds..."
    Start-Sleep -Seconds $WaitSeconds

    $procCheck = Get-Process -Id $launchedProc.Id -ErrorAction SilentlyContinue
    if (-not $procCheck) {
        $exitCode = $launchedProc.ExitCode
        Write-Host "  [FAILURE] Isolated candidate exited prematurely with exit code: $exitCode" -ForegroundColor Red
        if ($exitCode -eq -1073741502 -or $exitCode -eq 3221225794) {
            Write-Host "  [DIAGNOSTIC] Exit code is 0xC0000142 (STATUS_DLL_INIT_FAILED)." -ForegroundColor Red
        }
    } else {
        Write-Host "  [SUCCESS] Isolated candidate process is running! PID: $($procCheck.Id)" -ForegroundColor Green

        # Check Package Identity
        $length = 256
        $sb = New-Object System.Text.StringBuilder $length
        $rc = [BaitZeroTestHarness.AppModelVerifier]::GetPackageFullName($launchedProc.Handle, [ref]$length, $sb)

        if ($rc -eq 0) {
            Write-Host "  [SUCCESS] Package Identity verified: $($sb.ToString())" -ForegroundColor Green
        } else {
            Write-Host "  [WARNING] Package Identity query returned code $rc (15700 = APPMODEL_ERROR_NO_PACKAGE)" -ForegroundColor Yellow
        }
    }
}
finally {
    # -----------------------------------------------------------------------
    # Phase 6: Process Teardown & Guaranteed Baseline Restoration
    # -----------------------------------------------------------------------
    Write-Host "`n[Phase 6] Teardown & Restoring baseline production registration..." -ForegroundColor Cyan

    # Terminate test process if still running
    if ($launchedProc -and (-not $launchedProc.HasExited)) {
        Write-Host "  Terminating isolated candidate test process (PID $($launchedProc.Id))..."
        $launchedProc | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }

    # Clean isolated environment variables from current session
    Remove-Item env:BAITZERO_ISOLATED_TEST_MODE -ErrorAction SilentlyContinue
    Remove-Item env:BAITZERO_TEST_MUTEX -ErrorAction SilentlyContinue
    Remove-Item env:BAITZERO_TEST_ACTIVATE_EVENT -ErrorAction SilentlyContinue
    Remove-Item env:BAITZERO_TEST_PORT -ErrorAction SilentlyContinue
    Remove-Item env:BAITZERO_TEST_DATA_DIR -ErrorAction SilentlyContinue
    Remove-Item env:WEBVIEW2_USER_DATA_FOLDER -ErrorAction SilentlyContinue

    if ($registrationSwitched) {
        Write-Host "  Restoring package registration to original location: '$origExternalLocation'..."
        try {
            Add-AppxPackage -Register $manifestPath -ExternalLocation $origExternalLocation -ErrorAction Stop
            Write-Host "  Add-AppxPackage registration call completed." -ForegroundColor Green
        } catch {
            Write-Host "  [CRITICAL ERROR] Failed to execute Add-AppxPackage restoration: $_" -ForegroundColor Red
            Write-Host "  MANUAL RECOVERY REQUIRED IMMEDIATELY:" -ForegroundColor Red
            Write-Host "    Add-AppxPackage -Register `"$manifestPath`" -ExternalLocation `"$origExternalLocation`"" -ForegroundColor Red
            if ($host -and $host.SetShouldExit) { $host.SetShouldExit(1) }
            throw "CRITICAL RESTORATION FAILURE: Add-AppxPackage restoration failed: $_"
        }

        # Verify restoration explicitly (Do NOT assume it succeeded)
        try {
            $restoredPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
            if ($restoredPkgs.Count -ne 1) {
                throw "Expected exactly 1 restored package matching 'link-protection-system', found $($restoredPkgs.Count)."
            }

            if (-not $restoredPkgs[0].EffectiveExternalLocation -or -not $restoredPkgs[0].EffectiveExternalLocation.Path) {
                throw "Restored package has null or unreadable EffectiveExternalLocation.Path."
            }

            $restoredExt = $restoredPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\')
            if ($restoredExt -ne $origExternalLocation) {
                throw "EffectiveExternalLocation mismatch after restore. Current: '$restoredExt', Expected: '$origExternalLocation'."
            }

            Write-Host "  [RESTORED] Baseline production registration verified successfully!" -ForegroundColor Green
            Write-Host "             EffectiveExternalLocation: $restoredExt" -ForegroundColor Green
        } catch {
            Write-Host "  [CRITICAL ERROR] Restoration verification failed: $_" -ForegroundColor Red
            Write-Host "  MANUAL RECOVERY REQUIRED IMMEDIATELY:" -ForegroundColor Red
            Write-Host "    Add-AppxPackage -Register `"$manifestPath`" -ExternalLocation `"$origExternalLocation`"" -ForegroundColor Red
            if ($host -and $host.SetShouldExit) { $host.SetShouldExit(1) }
            throw "CRITICAL RESTORATION FAILURE: Restoration verification failed: $_"
        }
    } else {
        Write-Host "  Registration was not altered; no restoration required." -ForegroundColor DarkGray
    }
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " BaitZero Stage 3C-6 Test Harness Completed                     " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
