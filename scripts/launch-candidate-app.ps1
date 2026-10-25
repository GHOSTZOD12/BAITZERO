<#
.SYNOPSIS
    Launches BaitZero Candidate with Windows Sparse Package identity and test isolation.
.DESCRIPTION
    Validates registration and executable layout, initializes fail-closed test mode
    environment variables (mutex, activation event, port 27433, data dirs), launches
    the candidate process, and verifies that Windows assigns candidate package identity.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection",
    [switch]$NoWait,
    [int]$WaitSeconds = 4
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " BaitZero Candidate Launch with Package Identity " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$candidateDir = Join-Path $ProjectRoot "src-tauri\target-candidate-v2\release"
$candidateExe = Join-Path $candidateDir "link-protection-system.exe"
$testDataDir = Join-Path $ProjectRoot "scratch\candidate-test-data"
$testWv2Dir = Join-Path $ProjectRoot "scratch\candidate-test-wv2"
$expectedProdDir = (Join-Path $ProjectRoot "src-tauri\target\release").TrimEnd('\')

if (-not (Test-Path $candidateExe)) {
    throw "FAIL-CLOSED: Candidate executable not found at '$candidateExe'."
}

# 1. Verify registrations & production hash
[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()

$prodPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($prodPkgs.Count -ne 1 -or $prodPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\') -ne $expectedProdDir) {
    throw "FAIL-CLOSED: Production package 'link-protection-system' is missing or not registered at '$expectedProdDir'!"
}

$candPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })
if ($candPkgs.Count -ne 1) {
    throw "FAIL-CLOSED: Candidate package 'link-protection-candidate' is not registered. Please run register-candidate-package.ps1 first."
}
$candPkg = $candPkgs[0]
if ($candPkg.EffectiveExternalLocation.Path.TrimEnd('\') -ne $candidateDir.TrimEnd('\')) {
    throw "FAIL-CLOSED: Candidate package external location is '$($candPkg.EffectiveExternalLocation.Path)' (expected '$candidateDir')."
}

# Verify production executable hash
$expectedProdHash = "AAF8C161FFA2E9D9504D55C00590C8DACFB14562265612E22DF4ADD76DCE7A0E"
$prodExe = Join-Path $expectedProdDir "link-protection-system.exe"
if (-not (Test-Path $prodExe)) {
    throw "FAIL-CLOSED: Production executable missing at '$prodExe'."
}
$prodHash = (Get-FileHash -Path $prodExe -Algorithm SHA256).Hash.ToUpperInvariant()
if ($prodHash -ne $expectedProdHash) {
    throw "FAIL-CLOSED: Production executable hash mismatch! Expected: $expectedProdHash, Actual: $prodHash"
}

Write-Host "[Preflight Verification]" -ForegroundColor Green
Write-Host "  Production: $($prodPkgs[0].Id.FullName) -> $($prodPkgs[0].EffectiveExternalLocation.Path)"
Write-Host "  Candidate:  $($candPkg.Id.FullName) -> $($candPkg.EffectiveExternalLocation.Path)"
Write-Host "  Production Hash: Verified ($prodHash)"

# 2. Verify ports
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
Write-Host "  [OK] Ports 27433 (test) and 27432 (prod) verified clean." -ForegroundColor Green

# 3. Setup test isolation directories
if (-not (Test-Path $testDataDir)) { New-Item -ItemType Directory -Path $testDataDir -Force | Out-Null }
if (-not (Test-Path $testWv2Dir)) { New-Item -ItemType Directory -Path $testWv2Dir -Force | Out-Null }

# 4. Snapshot pre-existing environment variables for safe restoration
$isoVarNames = @(
    "BAITZERO_ISOLATED_TEST_MODE",
    "BAITZERO_TEST_MUTEX",
    "BAITZERO_TEST_ACTIVATE_EVENT",
    "BAITZERO_TEST_PORT",
    "BAITZERO_TEST_DATA_DIR",
    "WEBVIEW2_USER_DATA_FOLDER"
)
$origEnv = @{}
foreach ($var in $isoVarNames) {
    if (Test-Path "env:$var") {
        $origEnv[$var] = (Get-Item "env:$var").Value
    } else {
        $origEnv[$var] = $null
    }
}

try {
    # Set candidate isolation environment variables for child process launch
    $env:BAITZERO_ISOLATED_TEST_MODE = "1"
    $env:BAITZERO_TEST_MUTEX = "Global\BaitZeroCandidateSingleInstance"
    $env:BAITZERO_TEST_ACTIVATE_EVENT = "Global\BaitZeroCandidateActivate"
    $env:BAITZERO_TEST_PORT = "27433"
    $env:BAITZERO_TEST_DATA_DIR = $testDataDir
    $env:WEBVIEW2_USER_DATA_FOLDER = $testWv2Dir

    # 5. P/Invoke for Package Identity Verification
    $signature = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int GetPackageFullName(IntPtr hProcess, ref int packageFullNameLength, System.Text.StringBuilder packageFullName);
'@
    Add-Type -MemberDefinition $signature -Name "CandidateAppModelLauncher" -Namespace "Win32CandidateLauncher" -ErrorAction SilentlyContinue

    # 6. Launch Candidate Process with Log Redirection
    $stdoutLog = Join-Path $ProjectRoot "scratch\candidate-stdout.log"
    $stderrLog = Join-Path $ProjectRoot "scratch\candidate-stderr.log"
    if (Test-Path $stdoutLog) { Remove-Item $stdoutLog -Force }
    if (Test-Path $stderrLog) { Remove-Item $stderrLog -Force }

    Write-Host "`nLaunching candidate process..." -ForegroundColor Cyan
    Write-Host "  Executable:       $candidateExe"
    Write-Host "  WorkingDir:       $candidateDir"
    Write-Host "  Package FullName: $($candPkg.Id.FullName)"

    $proc = Start-Process -FilePath $candidateExe -WorkingDirectory $candidateDir -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
    Write-Host "  Candidate launched with PID: $($proc.Id)" -ForegroundColor Green

    Write-Host "  Observing process startup for $WaitSeconds seconds..."
    Start-Sleep -Seconds $WaitSeconds

    $procCheck = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $procCheck) {
        $exitCode = $proc.ExitCode
        Write-Host "  [FAILURE] Candidate process exited prematurely with exit code: $exitCode" -ForegroundColor Red
        if (Test-Path $stderrLog) {
            Write-Host "`n[Captured stderr]:" -ForegroundColor Red
            Get-Content $stderrLog | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
        throw "FAIL-CLOSED: Candidate process exited prematurely with exit code: $exitCode"
    }

    # 7. Verify Process Package Identity
    $length = 256
    $sb = New-Object System.Text.StringBuilder $length
    $rc = [Win32CandidateLauncher.CandidateAppModelLauncher]::GetPackageFullName($proc.Handle, [ref]$length, $sb)

    if ($rc -eq 0) {
        $fullName = $sb.ToString()
        Write-Host "`n[SUCCESS] Candidate launched WITH Package Identity!" -ForegroundColor Green
        Write-Host "  PID:              $($proc.Id)" -ForegroundColor Green
        Write-Host "  Package FullName: $fullName" -ForegroundColor Green
        Write-Host "  Package Identity: True" -ForegroundColor Green
        if ($fullName -notlike "link-protection-candidate*") {
            Write-Host "  [WARNING] Package FullName does not start with 'link-protection-candidate': $fullName" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n[ERROR] Candidate launched WITHOUT package identity!" -ForegroundColor Red
        Write-Host "  PID:        $($proc.Id)" -ForegroundColor Red
        Write-Host "  Error Code: $rc (15700 = APPMODEL_ERROR_NO_PACKAGE)" -ForegroundColor Red
    }

    # 8. Check Windows and Bridge Port
    Write-Host "`n[Windows & Bridge Check]" -ForegroundColor Cyan
    Write-Host "  Main Window Title:  $($procCheck.MainWindowTitle)"
    Write-Host "  Main Window Handle: $($procCheck.MainWindowHandle)"
    
    $bridgeListening = Test-TcpPortInUse 27433
    Write-Host "  Bridge Listening on Port 27433: $bridgeListening" -ForegroundColor $(if ($bridgeListening) { "Green" } else { "Yellow" })

    # 9. Startup Logs
    Write-Host "`n[Captured Startup Logs (stderr)]" -ForegroundColor Cyan
    if (Test-Path $stderrLog) {
        Get-Content $stderrLog | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  No stderr log file found."
    }

    if (-not $NoWait) {
        Write-Host "`nProcess is running. (PID $($proc.Id))"
    }
}
finally {
    # Clean up / restore caller's pre-existing environment variables fail-safe
    foreach ($var in $isoVarNames) {
        if ($null -ne $origEnv[$var]) {
            [System.Environment]::SetEnvironmentVariable($var, $origEnv[$var], [System.EnvironmentVariableTarget]::Process)
        } else {
            if (Test-Path "env:$var") {
                Remove-Item "env:$var" -ErrorAction SilentlyContinue
            }
        }
    }
}

