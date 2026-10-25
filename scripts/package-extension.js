/**
 * scripts/package-extension.js
 * Stage 3B-4C: Packaging Safeguard for Browser Extension
 *
 * Packages an explicit allowlist of verified browser-extension files into a distribution ZIP.
 * Strictly excludes backup, temporary, test, and development artifacts.
 * Uses pure Node.js (zlib) to construct standard PKZIP archives without external dependencies
 * or subprocess invocation.
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

/**
 * Authoritative allowlist of files required for the browser extension.
 * Any file NOT in this list is strictly excluded from the release package.
 */
export const EXTENSION_ALLOWLIST = [
  'manifest.json',
  'background.js',
  'popup.html',
  'popup.js',
  'pages/warning.html',
  'pages/warning.js',
  'icons/icon16.png',
  'icons/icon32.png',
  'icons/icon48.png',
  'icons/icon128.png'
];

/**
 * Validates the extension manifest and required files.
 *
 * @param {string} sourceDir - Extension source directory
 * @returns {{ ok: boolean, error?: string, manifest?: object, missingFiles?: string[] }}
 */
export function validateExtensionSource(sourceDir) {
  if (!fs.existsSync(sourceDir)) {
    return { ok: false, error: `Extension directory does not exist: '${sourceDir}'` };
  }

  const manifestPath = path.join(sourceDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    return { ok: false, error: `manifest.json missing in '${sourceDir}'` };
  }

  let manifest;
  try {
    const raw = fs.readFileSync(manifestPath, 'utf8');
    manifest = JSON.parse(raw);
  } catch (err) {
    return { ok: false, error: `Failed to parse manifest.json: ${err.message}` };
  }

  if (!manifest.name || !manifest.version || manifest.manifest_version !== 3) {
    return { ok: false, error: `Invalid manifest.json: missing required fields or manifest_version is not 3` };
  }

  // Verify all allowlisted files exist in the source directory
  const missingFiles = [];
  for (const relFile of EXTENSION_ALLOWLIST) {
    const fullPath = path.join(sourceDir, relFile);
    if (!fs.existsSync(fullPath)) {
      missingFiles.push(relFile);
    }
  }

  if (missingFiles.length > 0) {
    return {
      ok: false,
      error: `Missing required extension file(s): ${missingFiles.join(', ')}`,
      missingFiles
    };
  }

  return { ok: true, manifest };
}

/**
 * Creates a standard PKZIP archive in pure Node.js from an array of file entries.
 *
 * @param {{ path: string, data: Buffer }[]} entries - Relative file paths and contents
 * @param {string} outputPath - Output .zip destination file
 */
export function createZipArchive(entries, outputPath) {
  const localHeaders = [];
  const centralHeaders = [];
  let currentOffset = 0;

  for (const entry of entries) {
    const rawPath = entry.path.replace(/\\/g, '/');
    const pathBuffer = Buffer.from(rawPath, 'utf8');
    const uncompressed = entry.data;
    const crc = zlib.crc32(uncompressed);
    const compressed = zlib.deflateRawSync(uncompressed);

    // Local file header: 30 bytes + filename + data
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // Signature
    localHeader.writeUInt16LE(20, 4);         // Version needed: 2.0
    localHeader.writeUInt16LE(0, 6);          // Flags
    localHeader.writeUInt16LE(8, 8);          // Compression: Deflate
    localHeader.writeUInt16LE(0, 10);         // Mod time
    localHeader.writeUInt16LE(0, 12);         // Mod date
    localHeader.writeUInt32LE(crc, 14);       // CRC-32
    localHeader.writeUInt32LE(compressed.length, 18);   // Compressed size
    localHeader.writeUInt32LE(uncompressed.length, 22); // Uncompressed size
    localHeader.writeUInt16LE(pathBuffer.length, 26);   // Filename length
    localHeader.writeUInt16LE(0, 28);         // Extra field length

    const localChunk = Buffer.concat([localHeader, pathBuffer, compressed]);
    localHeaders.push(localChunk);

    // Central directory header: 46 bytes + filename
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // Signature
    centralHeader.writeUInt16LE(20, 4);         // Version made by: 2.0
    centralHeader.writeUInt16LE(20, 6);         // Version needed: 2.0
    centralHeader.writeUInt16LE(0, 8);          // Flags
    centralHeader.writeUInt16LE(8, 10);         // Compression: Deflate
    centralHeader.writeUInt16LE(0, 12);         // Mod time
    centralHeader.writeUInt16LE(0, 14);         // Mod date
    centralHeader.writeUInt32LE(crc, 16);       // CRC-32
    centralHeader.writeUInt32LE(compressed.length, 20);   // Compressed size
    centralHeader.writeUInt32LE(uncompressed.length, 24); // Uncompressed size
    centralHeader.writeUInt16LE(pathBuffer.length, 28);   // Filename length
    centralHeader.writeUInt16LE(0, 30);         // Extra field length
    centralHeader.writeUInt16LE(0, 32);         // Comment length
    centralHeader.writeUInt16LE(0, 34);         // Disk number start
    centralHeader.writeUInt16LE(0, 36);         // Internal file attributes
    centralHeader.writeUInt32LE(0, 38);         // External file attributes
    centralHeader.writeUInt32LE(currentOffset, 42); // Relative offset of local header

    const centralChunk = Buffer.concat([centralHeader, pathBuffer]);
    centralHeaders.push(centralChunk);

    currentOffset += localChunk.length;
  }

  const cdBuffer = Buffer.concat(centralHeaders);
  const cdOffset = currentOffset;
  const cdSize = cdBuffer.length;

  // End of central directory record: 22 bytes
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);       // Signature
  eocd.writeUInt16LE(0, 4);                // Disk number
  eocd.writeUInt16LE(0, 6);                // Disk with CD start
  eocd.writeUInt16LE(entries.length, 8);   // Total entries on disk
  eocd.writeUInt16LE(entries.length, 10);  // Total entries in CD
  eocd.writeUInt32LE(cdSize, 12);          // Size of CD
  eocd.writeUInt32LE(cdOffset, 16);        // Offset of CD
  eocd.writeUInt16LE(0, 20);               // Comment length

  const fullZip = Buffer.concat([...localHeaders, cdBuffer, eocd]);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, fullZip);
}

/**
 * Packages the browser extension into a zip archive using strictly allowlisted files.
 *
 * @param {string} [sourceDir] - Extension directory (defaults to browser-extension/)
 * @param {string} [outputZip] - Output zip path (defaults to dist/browser-extension.zip)
 * @returns {{ success: boolean, outputPath?: string, filesIncluded: string[], error?: string }}
 */
export function packageExtension(sourceDir, outputZip) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const src = (sourceDir && sourceDir.trim()) ? path.resolve(sourceDir) : path.resolve(__dirname, '..', 'browser-extension');
  const out = (outputZip && outputZip.trim()) ? path.resolve(outputZip) : path.resolve(__dirname, '..', 'dist', 'browser-extension.zip');

  const validation = validateExtensionSource(src);
  if (!validation.ok) {
    return { success: false, error: validation.error, filesIncluded: [] };
  }

  try {
    const entries = [];
    for (const relFile of EXTENSION_ALLOWLIST) {
      const filePath = path.join(src, relFile);
      const data = fs.readFileSync(filePath);
      entries.push({ path: relFile, data });
    }

    createZipArchive(entries, out);

    if (!fs.existsSync(out) || fs.statSync(out).size === 0) {
      return { success: false, error: 'Failed to create extension zip archive', filesIncluded: [] };
    }

    return {
      success: true,
      outputPath: out,
      filesIncluded: [...EXTENSION_ALLOWLIST]
    };
  } catch (err) {
    return { success: false, error: err.message, filesIncluded: [] };
  }
}

// CLI Execution entry point
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isDirectRun) {
  const srcDir = process.argv[2];
  const outZip = process.argv[3];

  console.log('[Extension Packager] Packaging browser extension with explicit allowlist...');
  const result = packageExtension(srcDir, outZip);

  if (!result.success) {
    console.error(`\n[Extension Packager] ERROR: Packaging failed: ${result.error}\n`);
    process.exit(1);
  } else {
    console.log(`\n[Extension Packager] SUCCESS: Created extension package:`);
    console.log(`  Path: ${result.outputPath}`);
    console.log(`  Files included (${result.filesIncluded.length}):`);
    for (const f of result.filesIncluded) {
      console.log(`    ✓ ${f}`);
    }
    console.log('');
  }
}
