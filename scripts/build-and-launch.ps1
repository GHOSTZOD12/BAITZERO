<#
.SYNOPSIS
    Builds the frontend and Rust binary, registers the sparse package, and launches the app.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection",
    [switch]$SkipUiBuild
)

$ErrorActionPreference = "Stop"

Set-Location $ProjectRoot

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Link Protection System: Complete Sparse Build & Run  " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 0. Environment Setup & Process Cleanup
$nodeExe = "C:\Users\risha\AppData\Roaming\fnm\aliases\default\node.exe"
if (Test-Path $nodeExe) {
    $fnmDir = Split-Path $nodeExe
    $env:PATH = "$fnmDir;$env:PATH"
}
$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

$runningProcs = Get-Process -Name "link-protection-system" -ErrorAction SilentlyContinue
if ($runningProcs) {
    Write-Host "`nStopping running instance of link-protection-system to release file locks..." -ForegroundColor Yellow
    $runningProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
}

# 1. Build Frontend
if (-not $SkipUiBuild) {
    Write-Host "`n[1/4] Building Vite Frontend (dist)..." -ForegroundColor Yellow
    cmd.exe /c "npm run build"
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE"
    }
    $distIndex = Join-Path $ProjectRoot "dist\index.html"
    if (-not (Test-Path $distIndex)) {
        throw "Frontend build succeeded, but dist/index.html was not found at '$distIndex'."
    }
    Write-Host "[1/4] Frontend built successfully (verified dist/index.html)." -ForegroundColor Green
} else {
    Write-Host "`n[1/4] Skipping frontend build as requested." -ForegroundColor DarkGray
    $distIndex = Join-Path $ProjectRoot "dist\index.html"
    if (-not (Test-Path $distIndex)) {
        throw "dist/index.html not found. Please run without -SkipUiBuild first."
    }
}

# 2. Build Rust Backend with embedded sparse manifest and custom-protocol
Write-Host "`n[2/4] Building Rust Release Binary (custom-protocol)..." -ForegroundColor Yellow
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Get-Command link -ErrorAction SilentlyContinue) -and (Test-Path $vcvars)) {
    cmd.exe /c "call `"$vcvars`" && set" | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}
cargo build --release --manifest-path (Join-Path $ProjectRoot "src-tauri\Cargo.toml") --features custom-protocol
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed with exit code $LASTEXITCODE"
}
Write-Host "[2/4] Rust release binary built successfully." -ForegroundColor Green

# 3. Ensure Sparse Package Registration
Write-Host "`n[3/4] Ensuring Sparse Package Registration..." -ForegroundColor Yellow
& (Join-Path $ProjectRoot "scripts\register-sparse-package.ps1") -ProjectRoot $ProjectRoot

# 4. Launch Application with Package Identity
Write-Host "`n[4/4] Launching Packaged Application..." -ForegroundColor Yellow
& (Join-Path $ProjectRoot "scripts\launch-sparse-app.ps1") -ProjectRoot $ProjectRoot
