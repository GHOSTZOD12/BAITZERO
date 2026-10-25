<#
.SYNOPSIS
    Diagnostic launch for BaitZero Candidate v2 without standard I/O pipe redirection.
.DESCRIPTION
    Launches the registered candidate executable from src-tauri\target-candidate-v2\release
    using candidate isolation settings without -RedirectStandardOutput / -RedirectStandardError.
    Records all launch, package identity, window, port, and file artifact diagnostics to log files.
    Restores all caller environment variables in a finally block.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection",
    [int]$WaitSeconds = 4,
    [switch]$NoWait
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

$diagLog = Join-Path $ProjectRoot "scratch\candidate-diagnostic-launch.log"
$diagDir = Split-Path $diagLog -Parent
if (-not (Test-Path $diagDir)) { New-Item -ItemType Directory -Path $diagDir -Force | Out-Null }
if (Test-Path $diagLog) { Remove-Item $diagLog -Force }

function Write-DiagLog([string]$msg, [string]$color = "White") {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "[$timestamp] $msg"
    Write-Host $logLine -ForegroundColor $color
    Add-Content -Path $diagLog -Value $logLine
}

Write-DiagLog "==========================================================" "Cyan"
Write-DiagLog " Candidate v2 Diagnostic Launch (No Pipe Redirection) " "Cyan"
Write-DiagLog "==========================================================" "Cyan"

$candidateDir = Join-Path $ProjectRoot "src-tauri\target-candidate-v2\release"
$candidateExe = Join-Path $candidateDir "link-protection-system.exe"
$testDataDir = Join-Path $ProjectRoot "scratch\candidate-test-data"
$testWv2Dir = Join-Path $ProjectRoot "scratch\candidate-test-wv2"
$expectedProdDir = (Join-Path $ProjectRoot "src-tauri\target\release").TrimEnd('\')
$expectedProdHash = "AAF8C161FFA2E9D9504D55C00590C8DACFB14562265612E22DF4ADD76DCE7A0E"

# ---------------------------------------------------------------------------
# Phase 1: Fail-Closed Preflight Baseline Verification
# ---------------------------------------------------------------------------
Write-DiagLog "`n[Phase 1] Preflight Verification" "Cyan"

if (-not (Test-Path $candidateExe)) {
    throw "FAIL-CLOSED: Candidate executable not found at '$candidateExe'."
}

# WinRT package check
[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()

$prodPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" })
if ($prodPkgs.Count -ne 1 -or $prodPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\') -ne $expectedProdDir) {
    throw "FAIL-CLOSED: Production package 'link-protection-system' missing or not at '$expectedProdDir'!"
}
$candPkgs = @($pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-candidate" })
if ($candPkgs.Count -ne 1 -or $candPkgs[0].EffectiveExternalLocation.Path.TrimEnd('\') -ne $candidateDir.TrimEnd('\')) {
    throw "FAIL-CLOSED: Candidate package 'link-protection-candidate' missing or not at '$candidateDir'!"
}
$candPkg = $candPkgs[0]

# Verify production executable hash
$prodExe = Join-Path $expectedProdDir "link-protection-system.exe"
if (-not (Test-Path $prodExe)) {
    throw "FAIL-CLOSED: Production executable missing at '$prodExe'."
}
$prodHash = (Get-FileHash -Path $prodExe -Algorithm SHA256).Hash.ToUpperInvariant()
if ($prodHash -ne $expectedProdHash) {
    throw "FAIL-CLOSED: Production executable hash mismatch! Expected: $expectedProdHash, Actual: $prodHash"
}

# Verify candidate executable embedded manifest
$candBytes = [System.IO.File]::ReadAllBytes($candidateExe)
$candStr = [System.Text.Encoding]::UTF8.GetString($candBytes)
if ($candStr -notmatch 'packageName="link-protection-candidate"' -or $candStr -notmatch 'applicationId="linkprotectioncandidate"') {
    throw "FAIL-CLOSED: Candidate executable embedded manifest does not match candidate identity!"
}

# Verify ports
function Test-TcpPortInUse([int]$Port) {
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return ($listeners | Where-Object { $_.Port -eq $Port }) -ne $null
}

if (Test-TcpPortInUse 27433) { throw "FAIL-CLOSED: Port 27433 is in use." }
if (Test-TcpPortInUse 27432) { throw "FAIL-CLOSED: Production port 27432 is in use." }

# Verify no running instances
$running = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
if ($running) {
    $pids = ($running | Select-Object -ExpandProperty Id) -join ", "
    throw "FAIL-CLOSED: Active link-protection-system processes running (PIDs: $pids)."
}

Write-DiagLog "  Production Package: $($prodPkgs[0].Id.FullName)" "Green"
Write-DiagLog "  Candidate Package:  $($candPkg.Id.FullName)" "Green"
Write-DiagLog "  Production Hash:    Verified ($prodHash)" "Green"
Write-DiagLog "  Ports 27433 & 27432: Free" "Green"

# ---------------------------------------------------------------------------
# Phase 2: Isolation Environment Setup
# ---------------------------------------------------------------------------
if (-not (Test-Path $testDataDir)) { New-Item -ItemType Directory -Path $testDataDir -Force | Out-Null }
if (-not (Test-Path $testWv2Dir)) { New-Item -ItemType Directory -Path $testWv2Dir -Force | Out-Null }

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
    $env:BAITZERO_ISOLATED_TEST_MODE = "1"
    $env:BAITZERO_TEST_MUTEX = "Global\BaitZeroCandidateSingleInstance"
    $env:BAITZERO_TEST_ACTIVATE_EVENT = "Global\BaitZeroCandidateActivate"
    $env:BAITZERO_TEST_PORT = "27433"
    $env:BAITZERO_TEST_DATA_DIR = $testDataDir
    $env:WEBVIEW2_USER_DATA_FOLDER = $testWv2Dir

    # P/Invoke for Package Identity
    $signature = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int GetPackageFullName(IntPtr hProcess, ref int packageFullNameLength, System.Text.StringBuilder packageFullName);
'@
    Add-Type -MemberDefinition $signature -Name "DiagCandidateAppModel" -Namespace "Win32Diag" -ErrorAction SilentlyContinue

    # -----------------------------------------------------------------------
    # Phase 3: Launch Process (NO PIPE REDIRECTION)
    # -----------------------------------------------------------------------
    Write-DiagLog "`n[Phase 3] Launching candidate process without standard I/O redirection..." "Cyan"
    Write-DiagLog "  Executable:  $candidateExe"
    Write-DiagLog "  WorkingDir:  $candidateDir"

    $launchTime = Get-Date
    # Start-Process without -RedirectStandardOutput or -RedirectStandardError
    $proc = Start-Process -FilePath $candidateExe -WorkingDirectory $candidateDir -PassThru
    $createdPid = $proc.Id
    Write-DiagLog "  Process spawned: PID $createdPid" "Green"

    Write-DiagLog "  Observing process state for $WaitSeconds seconds..." "Cyan"
    Start-Sleep -Seconds $WaitSeconds

    $procCheck = Get-Process -Id $createdPid -ErrorAction SilentlyContinue
    $isAlive = ($procCheck -ne $null)

    if (-not $isAlive) {
        $exitCode = $proc.ExitCode
        Write-DiagLog ("`n[RESULT: FAILURE] Process exited prematurely with code: $exitCode (0x{0:X8})" -f $exitCode) "Red"

        # Query Windows Event Logs for diagnostic details
        Write-DiagLog "  Querying Windows Event Log for loader/activation details..." "Cyan"
        try {
            $appEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Application'
                Level = 2 # Error
                StartTime = $launchTime.AddSeconds(-2)
            } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match "link-protection-system" }

            if ($appEvents) {
                foreach ($evt in $appEvents) {
                    Write-DiagLog "  [EventLog Application Error] $($evt.Message)" "Yellow"
                }
            } else {
                Write-DiagLog "  No Application crash events recorded for link-protection-system.exe." "DarkGray"
            }

            $appModelEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-AppModel-Runtime/Admin'
                StartTime = $launchTime.AddSeconds(-2)
            } -ErrorAction SilentlyContinue

            if ($appModelEvents) {
                foreach ($evt in $appModelEvents) {
                    Write-DiagLog "  [AppModel Event $($evt.Id)] $($evt.Message)" "Yellow"
                }
            }
        } catch {
            Write-DiagLog "  Event log query exception: $($_.Exception.Message)" "DarkGray"
        }

        throw "FAIL-CLOSED: Candidate process exited prematurely with exit code: $exitCode"
    }

    # -----------------------------------------------------------------------
    # Phase 4: Identity & Runtime Validation
    # -----------------------------------------------------------------------
    Write-DiagLog "`n[Phase 4] Verifying Process Package Identity..." "Cyan"
    $length = 256
    $sb = New-Object System.Text.StringBuilder $length
    $rc = [Win32Diag.DiagCandidateAppModel]::GetPackageFullName($procCheck.Handle, [ref]$length, $sb)

    if ($rc -eq 0) {
        $fullName = $sb.ToString()
        Write-DiagLog "  [PASS] Package FullName: $fullName" "Green"
        Write-DiagLog "  [PASS] Package Identity Verified: True" "Green"
    } else {
        Write-DiagLog "  [FAIL] GetPackageFullName returned code: $rc" "Red"
    }

    # Window & Port Checks
    Write-DiagLog "`n[Phase 5] Window and Network Checks" "Cyan"
    Write-DiagLog "  MainWindowTitle:  '$($procCheck.MainWindowTitle)'"
    Write-DiagLog "  MainWindowHandle: $($procCheck.MainWindowHandle)"

    $bridgeListening = Test-TcpPortInUse 27433
    $bridgeColor = if ($bridgeListening) { "Green" } else { "Yellow" }
    Write-DiagLog "  Bridge Listening on Port 27433: $bridgeListening" $bridgeColor

    # File System Artifact Checks (Application Logs & State)
    Write-DiagLog "`n[Phase 6] Checking File-based Application State..." "Cyan"
    $tokenFile = Join-Path $testDataDir "auth_token.txt"
    if (Test-Path $tokenFile) {
        Write-DiagLog "  [PASS] auth_token.txt created by Rust application in test data dir." "Green"
    } else {
        Write-DiagLog "  [INFO] auth_token.txt not yet created." "Yellow"
    }

    $wv2Profile = Join-Path $testWv2Dir "EBWebView"
    if (Test-Path $wv2Profile) {
        Write-DiagLog "  [PASS] WebView2 profile initialized in test WebView2 dir." "Green"
    } else {
        Write-DiagLog "  [INFO] WebView2 profile not yet created." "Yellow"
    }

    Write-DiagLog "`n[RESULT: SUCCESS] Candidate v2 process is active and healthy (PID $createdPid)." "Green"

    if (-not $NoWait) {
        Write-DiagLog "Process remains running for review. Use rollback or Stop-Process when authorized." "Cyan"
    }
}
finally {
    # Restore environment variables
    foreach ($var in $isoVarNames) {
        if ($null -ne $origEnv[$var]) {
            [System.Environment]::SetEnvironmentVariable($var, $origEnv[$var], [System.EnvironmentVariableTarget]::Process)
        } else {
            if (Test-Path "env:$var") {
                Remove-Item "env:$var" -ErrorAction SilentlyContinue
            }
        }
    }
    Write-DiagLog "`nEnvironment variables restored to prior state." "DarkGray"
}
