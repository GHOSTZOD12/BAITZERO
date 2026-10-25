function Get-Sha256([string]$filePath) {
    if (-not (Test-Path $filePath)) { return "NOT FOUND: $filePath" }
    return (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToUpperInvariant()
}

$cand = "src-tauri\target-candidate\release\link-protection-system.exe"
$active = "src-tauri\target\release\link-protection-system.exe"
$prev2 = "src-tauri\target\release\link-protection-system.active-prev-2.exe"
$prev1 = "src-tauri\target\release\link-protection-system.active-prev.exe"
$kg = "src-tauri\target\release\link-protection-system.known-good.exe"

Write-Host "Candidate:       " (Get-Sha256 $cand)
Write-Host "Active (current):" (Get-Sha256 $active)
Write-Host "Active Prev 2:   " (Get-Sha256 $prev2)
Write-Host "Active Prev 1:   " (Get-Sha256 $prev1)
Write-Host "Known Good:      " (Get-Sha256 $kg)
