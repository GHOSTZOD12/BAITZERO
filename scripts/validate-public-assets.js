/**
 * scripts/validate-public-assets.js
 * Stage 3B-4C: Packaging Safeguard for Desktop Build Assets
 *
 * Scans the public directory before Vite/Tauri build to detect and block
 * backup, temporary, and development artifacts from entering release packages.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Returns true if a filename matches backup, temporary, or editor artifact patterns.
 *
 * @param {string} fileName
 * @returns {boolean}
 */
export function isSuspiciousArtifact(fileName) {
  const lower = fileName.toLowerCase();
  if (lower.includes('.bak')) return true;
  if (lower.includes('.backup')) return true;
  if (lower.includes('.tmp')) return true;
  if (lower.includes('.temp')) return true;
  if (lower.endsWith('~')) return true;
  if (lower.startsWith('.~') || lower.startsWith('.#')) return true;
  return false;
}

/**
 * Recursively scans a directory for suspicious artifacts.
 *
 * @param {string} dir
 * @returns {string[]} Array of relative file paths matching suspicious patterns
 */
export function scanForSuspiciousArtifacts(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }

  const suspicious = [];

  function walk(currentDir, relativePrefix = '') {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const relPath = relativePrefix ? path.join(relativePrefix, entry.name) : entry.name;
      if (entry.isDirectory()) {
        walk(path.join(currentDir, entry.name), relPath);
      } else if (entry.isFile()) {
        if (isSuspiciousArtifact(entry.name)) {
          suspicious.push(relPath);
        }
      }
    }
  }

  walk(dir);
  return suspicious;
}

/**
 * Validates the public assets directory.
 *
 * @param {string} [targetDir] - Directory to scan (defaults to project's public/)
 * @returns {{ ok: boolean, suspicious: string[], targetDir: string }}
 */
export function validatePublicAssets(targetDir) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const dirToScan = targetDir || path.resolve(__dirname, '..', 'public');

  const suspicious = scanForSuspiciousArtifacts(dirToScan);
  return {
    ok: suspicious.length === 0,
    suspicious,
    targetDir: dirToScan
  };
}

// CLI Execution entry point
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectRun) {
  const targetDir = process.argv[2];
  const result = validatePublicAssets(targetDir);

  if (!result.ok) {
    console.error(`\n[Packaging Safeguard] ERROR: ${result.suspicious.length} suspicious artifact(s) detected in '${result.targetDir}':`);
    for (const file of result.suspicious) {
      console.error(`  - ${file}`);
    }
    console.error('\nTo protect release bundles from unintended artifact leakage, packaging is aborted.');
    console.error('Please remove or relocate these files before proceeding.\n');
    process.exit(1);
  } else {
    console.log(`[Packaging Safeguard] Asset validation passed: '${result.targetDir}' contains no backup/temporary artifacts.`);
  }
}
