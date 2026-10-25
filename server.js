/**
 * server.js — Companion Local Analysis Server
 * Phase 3B-2: Localhost HTTP Endpoint for Browser Extension
 *
 * Implements the exact same HTTP protocol and security boundary as the
 * Tauri native Rust backend:
 * - Bound exclusively to 127.0.0.1:27432 (local loopback)
 * - Validates Origin (chrome-extension://, moz-extension://)
 * - Requires X-Extension-Token authentication
 * - Imports the authoritative JavaScript analysis engines:
 *     ./src/engines/urlAnalyzer.js
 *     ./src/engines/evidenceEngine.js
 *     ./src/engines/riskEngine.js
 *     ./src/engines/explanationEngine.js
 * - Token is persisted in %APPDATA%\LinkProtection\extension_token.txt
 *
 * This provides the local analysis interface for the browser extension,
 * allowing full functionality whether running via Node.js or native Tauri.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// Import the single source of truth: the existing engines
import { parseUrl } from './src/engines/urlAnalyzer.js';
import { collectEvidence } from './src/engines/evidenceEngine.js';
import { calculateRisk } from './src/engines/riskEngine.js';
import { generateExplanation } from './src/engines/explanationEngine.js';

const PORT = 27432;
const HOST = '127.0.0.1';

// Protection state (true by default)
let protectionActive = true;

// ---------------------------------------------------------------------------
// Token Management
// ---------------------------------------------------------------------------

function getAppDataDir() {
  const appData = process.env.APPDATA || (process.platform === 'darwin'
    ? path.join(process.env.HOME || '', 'Library', 'Application Support')
    : path.join(process.env.HOME || '', '.config'));
  return path.join(appData, 'LinkProtection');
}

function getOrGenerateToken() {
  const dir = getAppDataDir();
  const tokenFile = path.join(dir, 'extension_token.txt');

  try {
    if (fs.existsSync(tokenFile)) {
      const existing = fs.readFileSync(tokenFile, 'utf8').trim();
      if (existing.length >= 32) {
        return existing;
      }
    }
  } catch (_) {}

  // Generate new 64-char hex token
  const newToken = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tokenFile, newToken, 'utf8');
  } catch (err) {
    console.warn('[Server] Could not write token to AppData:', err.message);
  }
  return newToken;
}

const SERVER_TOKEN = getOrGenerateToken();

// ---------------------------------------------------------------------------
// Security & Origin Validation
// ---------------------------------------------------------------------------

function isAllowedOrigin(origin) {
  if (!origin || origin === 'null') return true; // Direct local curls / dev tools
  if (origin.startsWith('chrome-extension://')) return true;
  if (origin.startsWith('moz-extension://')) return true;
  if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) return true;
  return false;
}

function sendJson(res, statusCode, data, origin = '*') {
  const body = JSON.stringify(data);
  const allowOrigin = (origin && origin.startsWith('chrome-extension://')) ? origin : '*';
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'Content-Type, X-Extension-Token',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Connection': 'close',
  });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Analysis Pipeline
// ---------------------------------------------------------------------------

function runAnalysis(url) {
  const parseResult = parseUrl(url);
  if (!parseResult.success) {
    return {
      riskLevel: 'LOW',
      riskScore: 0,
      evidenceCount: 0,
      explanation: 'URL could not be parsed.',
      recommendation: 'Verify the URL is correct.',
      evidenceTitles: [],
    };
  }

  const urlData = parseResult.data;
  const evidenceList = collectEvidence(urlData, { deepInvestigation: false });
  const riskResult = calculateRisk(evidenceList);
  const { explanation, recommendation } = generateExplanation(evidenceList, riskResult);

  return {
    status: 'ok',
    protectionActive: true,
    riskLevel: riskResult.level,
    riskScore: riskResult.score,
    evidenceCount: evidenceList.length,
    explanation,
    recommendation,
    evidenceTitles: evidenceList.map(e => e.title),
  };
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

export const server = http.createServer((req, res) => {
  const origin = req.headers['origin'] || '';

  // 1. CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': origin || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Extension-Token',
      'Access-Control-Max-Age': '86400',
      'Connection': 'close',
    });
    return res.end();
  }

  // 2. Origin Verification
  if (!isAllowedOrigin(origin)) {
    return sendJson(res, 403, { error: 'Forbidden: Untrusted Origin' }, origin);
  }

  // 3. Token Authentication
  const clientToken = req.headers['x-extension-token'] || '';
  if (clientToken !== SERVER_TOKEN) {
    return sendJson(res, 401, { error: 'Unauthorized: Invalid or missing X-Extension-Token' }, origin);
  }

  // 4. Routes
  const urlObj = new URL(req.url, `http://${HOST}:${PORT}`);

  if (req.method === 'GET' && urlObj.pathname === '/status') {
    return sendJson(res, 200, {
      status: 'ok',
      protectionActive,
      version: '3B-2',
      token: SERVER_TOKEN,
    }, origin);
  }

  if (req.method === 'POST' && urlObj.pathname === '/set-protection') {
    // Allows testing protection state toggle
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        if (typeof payload.active === 'boolean') {
          protectionActive = payload.active;
        }
        return sendJson(res, 200, { status: 'ok', protectionActive }, origin);
      } catch (err) {
        return sendJson(res, 400, { error: 'Invalid JSON' }, origin);
      }
    });
    return;
  }

  if (req.method === 'POST' && urlObj.pathname === '/analyze') {
    // If protection is paused, return immediately without analyzing
    if (!protectionActive) {
      return sendJson(res, 200, {
        status: 'paused',
        protectionActive: false,
      }, origin);
    }

    let body = '';
    req.on('data', chunk => {
      body += chunk;
      // Protect against overly large payloads
      if (body.length > 65536) {
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const urlToAnalyze = payload.url;

        if (!urlToAnalyze || (!urlToAnalyze.startsWith('http://') && !urlToAnalyze.startsWith('https://'))) {
          return sendJson(res, 422, {
            error: 'Invalid URL. Only http:// and https:// schemes are supported.',
          }, origin);
        }

        const result = runAnalysis(urlToAnalyze);
        return sendJson(res, 200, result, origin);
      } catch (err) {
        return sendJson(res, 400, { error: 'Malformed JSON payload' }, origin);
      }
    });
    return;
  }

  return sendJson(res, 404, { error: 'Not found' }, origin);
});

// Start listening if executed directly
if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  server.listen(PORT, HOST, () => {
    console.log(`[LinkProtection] Local analysis server listening on http://${HOST}:${PORT}`);
    console.log(`[LinkProtection] Extension Auth Token: ${SERVER_TOKEN}`);
    console.log(`[LinkProtection] AppData directory: ${getAppDataDir()}`);
  });
}
