$ErrorActionPreference = "Stop"
$ProjectRoot = "C:\Dev\LinkProtection"
Set-Location $ProjectRoot

$cargoBin = "$env:USERPROFILE\.cargo\bin"
if (Test-Path $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Get-Command link -ErrorAction SilentlyContinue) -and (Test-Path $vcvars)) {
    cmd.exe /c "call `"$vcvars`" && set" | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

Write-Host "Building isolated release candidate in target-candidate..." -ForegroundColor Cyan
cargo build --release --manifest-path "$ProjectRoot\src-tauri\Cargo.toml" --target-dir "$ProjectRoot\src-tauri\target-candidate" --features custom-protocol
if ($LASTEXITCODE -ne 0) {
    throw "Cargo candidate build failed with exit code $LASTEXITCODE"
}

$candidatePath = "$ProjectRoot\src-tauri\target-candidate\release\link-protection-system.exe"
if (-not (Test-Path $candidatePath)) {
    throw "Candidate binary not found at $candidatePath"
}

$candHash = (Get-FileHash -Path $candidatePath -Algorithm SHA256).Hash.ToUpperInvariant()
Write-Host "Candidate built successfully!" -ForegroundColor Green
Write-Host "Candidate Path:   $candidatePath"
Write-Host "Candidate SHA256: $candHash"
