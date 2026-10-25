/**
 * test-packaging-safeguards.js
 * Stage 3B-4C: Packaging Safeguards Test Suite
 *
 * Verifies public asset validation, browser extension packaging allowlist,
 * failure modes, and artifact exclusion using isolated temporary fixtures.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { validatePublicAssets, scanForSuspiciousArtifacts, isSuspiciousArtifact } from './scripts/validate-public-assets.js';
import { validateExtensionSource, packageExtension, EXTENSION_ALLOWLIST } from './scripts/package-extension.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  [PASS] ${message}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${message}`);
    failed++;
  }
}

console.log('\n=== Stage 3B-4C: Packaging Safeguards Test Suite ===\n');

// Create isolated temporary root for test fixtures
const testTmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bzero-pkg-test-'));

try {
  // ---------------------------------------------------------------------------
  // 1. Asset Validation Safeguard Tests
  // ---------------------------------------------------------------------------
  console.log('--- 1. Desktop Public Asset Safeguard Tests ---');

  // Test 1: Clean asset directory passes
  const cleanDir = path.join(testTmpRoot, 'clean-public');
  fs.mkdirSync(cleanDir, { recursive: true });
  fs.writeFileSync(path.join(cleanDir, 'favicon.svg'), '<svg>clean</svg>');
  fs.writeFileSync(path.join(cleanDir, 'icons.svg'), '<svg>icons</svg>');
  fs.writeFileSync(path.join(cleanDir, 'logo.png'), 'png-data');

  const cleanResult = validatePublicAssets(cleanDir);
  assert(cleanResult.ok === true, 'Test 1: Clean asset directory passes validation');
  assert(cleanResult.suspicious.length === 0, 'Test 1b: Zero suspicious artifacts found in clean directory');

  // Test 2: .bak file detected
  const bakDir = path.join(testTmpRoot, 'bak-public');
  fs.mkdirSync(bakDir, { recursive: true });
  fs.writeFileSync(path.join(bakDir, 'favicon.svg'), '<svg>clean</svg>');
  fs.writeFileSync(path.join(bakDir, 'favicon.svg.bak-redesign'), '<svg>backup</svg>');

  const bakResult = validatePublicAssets(bakDir);
  assert(bakResult.ok === false, 'Test 2: Asset directory with .bak file fails validation');
  assert(bakResult.suspicious.some(f => f.includes('favicon.svg.bak-redesign')), 'Test 2b: Offending .bak-redesign file path reported');

  // Test 3: .tmp and .temp files detected
  const tmpDir = path.join(testTmpRoot, 'tmp-public');
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'cache.tmp'), 'temp data');
  fs.writeFileSync(path.join(tmpDir, 'asset.temp'), 'temp data');

  const tmpResult = validatePublicAssets(tmpDir);
  assert(tmpResult.ok === false, 'Test 3: Asset directory with .tmp and .temp files fails validation');
  assert(tmpResult.suspicious.length === 2, 'Test 3b: Both .tmp and .temp files identified');

  // Test 4: Trailing ~ editor backup detected
  const tildeDir = path.join(testTmpRoot, 'tilde-public');
  fs.mkdirSync(tildeDir, { recursive: true });
  fs.writeFileSync(path.join(tildeDir, 'style.css~'), 'backup');

  const tildeResult = validatePublicAssets(tildeDir);
  assert(tildeResult.ok === false, 'Test 4: Asset directory with trailing ~ backup fails validation');
  assert(tildeResult.suspicious.some(f => f === 'style.css~'), 'Test 4b: Trailing ~ file path reported');

  // Test 5: .corrupted.backup detected
  const corruptDir = path.join(testTmpRoot, 'corrupt-public');
  fs.mkdirSync(corruptDir, { recursive: true });
  fs.writeFileSync(path.join(corruptDir, 'state.corrupted.backup'), 'corrupt');

  const corruptResult = validatePublicAssets(corruptDir);
  assert(corruptResult.ok === false, 'Test 5: .corrupted.backup file is detected');

  // Test 6: Pattern unit checks
  assert(isSuspiciousArtifact('favicon.svg') === false, 'Test 6a: Authoritative favicon.svg is NOT suspicious');
  assert(isSuspiciousArtifact('logo.png') === false, 'Test 6b: Authoritative logo.png is NOT suspicious');
  assert(isSuspiciousArtifact('index.html') === false, 'Test 6c: Authoritative index.html is NOT suspicious');

  // ---------------------------------------------------------------------------
  // 2. Browser Extension Packaging Safeguard Tests
  // ---------------------------------------------------------------------------
  console.log('\n--- 2. Browser Extension Packaging Safeguard Tests ---');

  // Test 7: Missing manifest.json rejected
  const noManifestDir = path.join(testTmpRoot, 'no-manifest-ext');
  fs.mkdirSync(noManifestDir, { recursive: true });
  const noManifestResult = validateExtensionSource(noManifestDir);
  assert(noManifestResult.ok === false, 'Test 7: Missing manifest.json is rejected');
  assert(noManifestResult.error.includes('manifest.json missing'), 'Test 7b: Error message specifies missing manifest');

  // Test 8: Malformed JSON manifest rejected
  const badJsonDir = path.join(testTmpRoot, 'bad-json-ext');
  fs.mkdirSync(badJsonDir, { recursive: true });
  fs.writeFileSync(path.join(badJsonDir, 'manifest.json'), '{ invalid: json ]');
  const badJsonResult = validateExtensionSource(badJsonDir);
  assert(badJsonResult.ok === false, 'Test 8: Malformed JSON manifest is rejected');
  assert(badJsonResult.error.includes('Failed to parse manifest.json'), 'Test 8b: Error identifies JSON parse failure');

  // Test 9: Incomplete manifest rejected
  const incompleteDir = path.join(testTmpRoot, 'incomplete-ext');
  fs.mkdirSync(incompleteDir, { recursive: true });
  fs.writeFileSync(path.join(incompleteDir, 'manifest.json'), JSON.stringify({ name: "Test" }));
  const incompleteResult = validateExtensionSource(incompleteDir);
  assert(incompleteResult.ok === false, 'Test 9: Incomplete manifest missing version and manifest_version is rejected');

  // Test 10: Missing required allowlisted file rejected
  const missingFileDir = path.join(testTmpRoot, 'missing-file-ext');
  fs.mkdirSync(missingFileDir, { recursive: true });
  fs.writeFileSync(path.join(missingFileDir, 'manifest.json'), JSON.stringify({
    manifest_version: 3,
    name: "Test Ext",
    version: "1.0.0"
  }));
  // Missing background.js and icons
  const missingResult = validateExtensionSource(missingFileDir);
  assert(missingResult.ok === false, 'Test 10: Extension missing required allowlisted files is rejected');
  assert(missingResult.missingFiles.includes('background.js'), 'Test 10b: Specific missing file identified in error');

  // Test 11: Valid extension with contaminant files packages ONLY allowlist
  const fixtureExtDir = path.join(testTmpRoot, 'fixture-ext');
  fs.mkdirSync(fixtureExtDir, { recursive: true });

  // Copy real extension files to fixture
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const realExtDir = path.resolve(__dirname, 'browser-extension');
  for (const f of EXTENSION_ALLOWLIST) {
    const dest = path.join(fixtureExtDir, f);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(realExtDir, f), dest);
  }

  // Plant packaging contaminants in the fixture
  fs.writeFileSync(path.join(fixtureExtDir, 'background.js.bak-20261022-phase2b'), '// old code');
  fs.writeFileSync(path.join(fixtureExtDir, 'manifest.json.tmp'), '{}');
  fs.writeFileSync(path.join(fixtureExtDir, 'notes.md~'), 'notes');
  fs.writeFileSync(path.join(fixtureExtDir, 'dev_script.sh'), '#!/bin/bash');

  const testZipOut = path.join(testTmpRoot, 'fixture-extension.zip');
  const pkgResult = packageExtension(fixtureExtDir, testZipOut);
  assert(pkgResult.success === true, 'Test 11: Extension with contaminants packages successfully');
  assert(pkgResult.filesIncluded.length === EXTENSION_ALLOWLIST.length, 'Test 11b: Exactly allowlisted file count included');

  // Read zip file header bytes to confirm valid zip
  const zipBytes = fs.readFileSync(testZipOut);
  assert(zipBytes.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04])), 'Test 11c: Output is a valid PKZIP binary archive');

  // Test 12: Production browser-extension directory packaging
  const prodZipOut = path.join(testTmpRoot, 'prod-extension.zip');
  const prodPkgResult = packageExtension(realExtDir, prodZipOut);
  assert(prodPkgResult.success === true, 'Test 12: Production browser-extension directory packages cleanly');
  assert(fs.existsSync(prodZipOut) && fs.statSync(prodZipOut).size > 0, 'Test 12b: Production package zip created with non-zero size');

} finally {
  // Clean up all temporary fixtures created during the test
  try {
    fs.rmSync(testTmpRoot, { recursive: true, force: true });
  } catch {
    // Ignore cleanup error in tmpdir
  }
}

console.log('\n====================================================');
console.log(` PACKAGING SAFEGUARDS TEST SUMMARY: ${passed} Passed, ${failed} Failed`);
console.log('====================================================\n');

if (failed > 0) {
  process.exit(1);
}
