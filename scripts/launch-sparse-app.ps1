<#
.SYNOPSIS
    Launches Link Protection System with Windows Sparse Package identity.
.DESCRIPTION
    Validates the executable layout and registration, launches the process, and verifies
    that Windows assigns package identity to the process.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = "C:\Dev\LinkProtection",
    [switch]$NoWait
)

$ErrorActionPreference = "Stop"

Set-Location $ProjectRoot

$exePath = Join-Path $ProjectRoot "src-tauri\target\release\link-protection-system.exe"
if (-not (Test-Path $exePath)) {
    throw "Executable not found at '$exePath'. Please build the project first."
}

# 1. Verify package registration
[Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType = WindowsRuntime] | Out-Null
$pm = [Windows.Management.Deployment.PackageManager]::new()
$registeredPkg = $pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" }

if (-not $registeredPkg) {
    Write-Host "[Launch] Package not registered. Registering now..." -ForegroundColor Yellow
    & (Join-Path $ProjectRoot "scripts\register-sparse-package.ps1") -ProjectRoot $ProjectRoot
    $registeredPkg = $pm.FindPackagesForUser("") | Where-Object { $_.Id.Name -eq "link-protection-system" }
}

Write-Host "=== Launching Link Protection with Sparse Package Identity ===" -ForegroundColor Cyan
Write-Host "Executable:       $exePath"
Write-Host "Package FullName: $($registeredPkg.Id.FullName)"

# 2. Setup P/Invoke for identity verification
$signature = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int GetPackageFullName(IntPtr hProcess, ref int packageFullNameLength, System.Text.StringBuilder packageFullName);
'@
Add-Type -MemberDefinition $signature -Name "AppModelLauncher" -Namespace "Win32Launcher" -ErrorAction SilentlyContinue

# 3. Launch process
$proc = Start-Process -FilePath $exePath -WorkingDirectory (Split-Path $exePath) -PassThru
Start-Sleep -Milliseconds 1200

# 4. Verify process package identity
$length = 256
$sb = New-Object System.Text.StringBuilder $length
$rc = [Win32Launcher.AppModelLauncher]::GetPackageFullName($proc.Handle, [ref]$length, $sb)

if ($rc -eq 0) {
    $fullName = $sb.ToString()
    Write-Host "`n[SUCCESS] Application launched with Package Identity!" -ForegroundColor Green
    Write-Host "  PID:              $($proc.Id)" -ForegroundColor Green
    Write-Host "  Package FullName: $fullName" -ForegroundColor Green
    Write-Host "  Package Identity: True" -ForegroundColor Green
    Write-Host "  Error Code:       0 (ERROR_SUCCESS)" -ForegroundColor Green
} else {
    Write-Host "`n[ERROR] Application launched WITHOUT package identity!" -ForegroundColor Red
    Write-Host "  PID:        $($proc.Id)" -ForegroundColor Red
    Write-Host "  Error Code: $rc (APPMODEL_ERROR_NO_PACKAGE = 15700)" -ForegroundColor Red
}

if (-not $NoWait) {
    Write-Host "`nProcess is running. (PID $($proc.Id))"
}
