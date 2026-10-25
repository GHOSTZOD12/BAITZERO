<#
.SYNOPSIS
    Builds the BaitZero candidate executable with dedicated candidate package identity.
.DESCRIPTION
    Builds link-protection-system.exe into src-tauri\target-candidate-v2\release
    with embedded <msix> identity:
      - PackageName:   link-protection-candidate
      - ApplicationId: linkprotectioncandidate
      - Publisher:     CN=Link Protection Team
    Verifies the embedded manifest fail-closed after compilation.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection"
)

$ErrorActionPreference = "Stop"
Set-Location $ProjectRoot

Write-Host "=== BaitZero Candidate v2 Build ===" -ForegroundColor Cyan
Write-Host "Project Root:      $ProjectRoot"

# 1. Environment and tooling setup
$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

$nodeBin = "$env:APPDATA\fnm\aliases\default"
if (Test-Path $nodeBin) {
    $env:PATH = "$nodeBin;$env:PATH"
}

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Get-Command link -ErrorAction SilentlyContinue) -and (Test-Path $vcvars)) {
    cmd.exe /c "call `"$vcvars`" && set" | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

# 1b. Build Frontend (dist) fail-closed
Write-Host "Building frontend assets (npm run build)..." -ForegroundColor Cyan
cmd.exe /c "npm run build"
if ($LASTEXITCODE -ne 0) {
    throw "FAIL-CLOSED: Frontend build (npm run build) failed with exit code $LASTEXITCODE."
}
$distIndex = Join-Path $ProjectRoot "dist\index.html"
if (-not (Test-Path $distIndex)) {
    throw "FAIL-CLOSED: dist/index.html was not generated."
}
Write-Host "  [OK] Frontend assets successfully built to dist." -ForegroundColor Green


# 2. Configure candidate identity explicitly
$env:LINK_PROTECTION_IDENTITY = "candidate"
# Remove any unpackaged test override so <msix> is embedded
if (Test-Path env:LINK_PROTECTION_TEST_CONFIG) {
    Remove-Item env:LINK_PROTECTION_TEST_CONFIG
}

$targetDir = Join-Path $ProjectRoot "src-tauri\target-candidate-v2"
$manifestPath = Join-Path $ProjectRoot "src-tauri\Cargo.toml"
$candidateExe = Join-Path $targetDir "release\link-protection-system.exe"

Write-Host "Target Directory:  $targetDir"
Write-Host "Identity Mode:     $env:LINK_PROTECTION_IDENTITY"
Write-Host "Building isolated candidate release binary..." -ForegroundColor Cyan

cargo build --release --manifest-path $manifestPath --target-dir $targetDir --features custom-protocol
if ($LASTEXITCODE -ne 0) {
    throw "FAIL-CLOSED: Cargo candidate build failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path $candidateExe)) {
    throw "FAIL-CLOSED: Candidate binary not found at '$candidateExe'."
}

# 3. Validate embedded manifest fail-closed
Write-Host "`n[Validation] Checking embedded PE manifest..." -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes($candidateExe)
$str = [System.Text.Encoding]::UTF8.GetString($bytes)

if ($str -notmatch '<msix\s+xmlns="urn:schemas-microsoft-com:msix\.v1"\s+publisher="CN=Link Protection Team"\s+packageName="link-protection-candidate"\s+applicationId="linkprotectioncandidate"/>') {
    throw "FAIL-CLOSED: Candidate binary at '$candidateExe' does NOT contain the expected candidate <msix> manifest attributes!"
}
Write-Host "  [OK] Embedded manifest verified: packageName='link-protection-candidate', applicationId='linkprotectioncandidate'." -ForegroundColor Green

# 3b. Ensure candidate package Assets folder is staged alongside executable for AppX icon resolution
$destAssets = Join-Path $targetDir "release\Assets"
if (-not (Test-Path $destAssets)) {
    New-Item -ItemType Directory -Path $destAssets -Force | Out-Null
}
$srcAssets = Join-Path $ProjectRoot ".winapp\candidate\Assets"
if (Test-Path $srcAssets) {
    Copy-Item "$srcAssets\*" -Destination $destAssets -Force
    Write-Host "  [OK] Staged candidate visual assets to $destAssets" -ForegroundColor Green
}

# 4. Compute SHA-256
$hash = (Get-FileHash -Path $candidateExe -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Host "  [OK] Candidate v2 Binary SHA-256: $hash" -ForegroundColor Green
Write-Host "`nBuild complete. Candidate is ready for registration and isolated testing." -ForegroundColor Green
