param(
    [string]$ProjectRoot = (Resolve-Path "$PSScriptRoot\..").Path
)

$ErrorActionPreference = "Stop"

# 1. Environment configuration
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    $fnmNode = "$env:APPDATA\fnm\aliases\default\node.exe"
    if (Test-Path $fnmNode) {
        $fnmDir = Split-Path $fnmNode
        $env:PATH = "$fnmDir;$env:PATH"
    }
}
$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}
$env:LINK_PROTECTION_TEST_CONFIG = "1"

# 2. MSVC linker setup
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Get-Command link -ErrorAction SilentlyContinue) -and (Test-Path $vcvars)) {
    cmd.exe /c "call `"$vcvars`" && set" | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

# 3. Prevent overlapping executions of our application binary
Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

Set-Location $ProjectRoot
$testTargetDir = Join-Path $ProjectRoot "src-tauri\target\test_run"

# 4. Exactly one retry loop (up to 3 attempts) with immediate exit code check
$success = $false
$lastCode = 0

for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Host "`n[Test Run] Starting attempt $attempt of 3..." -ForegroundColor Cyan

    # Ensure no lingering application process before this attempt
    Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    cargo test --manifest-path (Join-Path $ProjectRoot "src-tauri\Cargo.toml") --target-dir $testTargetDir -j 2 -- --nocapture
    $lastCode = $LASTEXITCODE

    if ($lastCode -eq 0) {
        $success = $true
        Write-Host "`n[Test Run] Attempt $attempt succeeded! (Exit Code: $lastCode)" -ForegroundColor Green
        break
    }

    Write-Host "`n[Test Run] Attempt $attempt finished with exit code $lastCode." -ForegroundColor Yellow
    if ($lastCode -eq -1073741502 -or $lastCode -eq 3221225794) {
        Write-Host "[Diagnostic] Exit code 0xc0000142 (STATUS_DLL_INIT_FAILED) detected." -ForegroundColor DarkYellow
        Write-Host "[Diagnostic] Compilation succeeded, but execution failed because the binary links Win32/WinRT UserNotificationListener APIs requiring an interactive Window Station and Windows Package Identity." -ForegroundColor DarkYellow
    }

    if ($attempt -lt 3) {
        Write-Host "[Test Run] Waiting 2 seconds before retry attempt $($attempt + 1)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

if (-not $success) {
    throw "Cargo test suite failed with exit code $lastCode."
}
