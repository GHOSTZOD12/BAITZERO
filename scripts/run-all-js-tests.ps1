$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if ($nodeCmd) {
    $node = $nodeCmd.Source
} else {
    $fnmNode = "$env:APPDATA\fnm\aliases\default\node.exe"
    if (Test-Path $fnmNode) {
        $node = $fnmNode
    } else {
        $node = "node"
    }
}

Write-Host "Running test-context-aware-alerts.js..."
& $node test-context-aware-alerts.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-batch-a.js..."
& $node test-batch-a.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-clipboard.js..."
& $node test-clipboard.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-notification.js..."
& $node test-notification.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-extension.js..."
& $node test-extension.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-history-privacy.js..."
& $node test-history-privacy.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running test-packaging-safeguards.js..."
& $node test-packaging-safeguards.js
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nAll 7 JS test suites passed!" -ForegroundColor Green
