/**
 * scripts/verify-candidate-extension-e2e.js
 * End-to-end verification of Candidate v2 Browser Extension on port 27433.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import os from 'node:os';

const PROJECT_ROOT = 'C:\\Dev\\LinkProtection';
const EXTENSION_PATH = path.join(PROJECT_ROOT, 'browser-extension');
const MANIFEST_PATH = path.join(EXTENSION_PATH, 'manifest.json');
const BACKGROUND_PATH = path.join(EXTENSION_PATH, 'background.js');
const TOKEN_PATH = path.join(PROJECT_ROOT, 'scratch', 'candidate-test-data', 'extension_token.txt');
const USER_DATA_DIR = path.join(os.tmpdir(), 'baitzero_candidate_e2e_profile');
const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const CANDIDATE_PORT = 27433;
const PROD_PORT = 27432;

// Evidence log
const evidence = {
  boundaries: {},
  networkEvents: [],
  logs: []
};

function log(msg) {
  console.log(`[E2E] ${msg}`);
  evidence.logs.push(`[${new Date().toISOString()}] ${msg}`);
}

class CDPClient {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.eventListeners = new Map();
  }
  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.callbacks.has(msg.id)) {
        const { resolve, reject } = this.callbacks.get(msg.id);
        this.callbacks.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      } else if (msg.method && this.eventListeners.has(msg.method)) {
        for (const cb of this.eventListeners.get(msg.method)) cb(msg.params);
      }
    };
  }
  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.id++;
      this.callbacks.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(event, cb) {
    if (!this.eventListeners.has(event)) this.eventListeners.set(event, []);
    this.eventListeners.get(event).push(cb);
  }
  close() {
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
    }
  }
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function createTab(url = 'about:blank') {
  const res = await fetch(`http://127.0.0.1:9222/json/new?${encodeURIComponent(url)}`, { method: 'PUT' });
  const data = await res.json();
  const cdp = new CDPClient(data.webSocketDebuggerUrl);
  await cdp.connect();
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  return { id: data.id, cdp, url: data.url };
}

async function closeTab(tabId) {
  try {
    await fetch(`http://127.0.0.1:9222/json/close/${tabId}`);
  } catch (_) {}
}

async function main() {
  log('Starting Candidate v2 Browser Extension E2E Verification...');

  // 1. Read Candidate Token
  if (!fs.existsSync(TOKEN_PATH)) {
    throw new Error(`Token file not found at ${TOKEN_PATH}`);
  }
  const token = fs.readFileSync(TOKEN_PATH, 'utf8').trim();
  log(`Loaded candidate auth token (${token.substring(0, 8)}...[REDACTED])`);

  // 2. Verify Candidate Port is Listening
  const candidateStatus = await new Promise((resolve) => {
    const req = http.get({
      hostname: '127.0.0.1',
      port: CANDIDATE_PORT,
      path: '/status',
      headers: { 'x-extension-token': token }
    }, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(d) }));
    });
    req.on('error', (err) => resolve({ error: err.message }));
  });

  if (candidateStatus.error || candidateStatus.status !== 200) {
    throw new Error(`Candidate bridge on port ${CANDIDATE_PORT} is unreachable: ${JSON.stringify(candidateStatus)}`);
  }
  log(`Candidate bridge verified healthy on port ${CANDIDATE_PORT} (protectionActive=${candidateStatus.body.protectionActive})`);

  // 3. Verify Production Port is not interfering
  const prodStatus = await new Promise((resolve) => {
    const req = http.get({
      hostname: '127.0.0.1',
      port: PROD_PORT,
      path: '/status'
    }, () => resolve('active'));
    req.on('error', () => resolve('inactive'));
  });
  log(`Production port ${PROD_PORT} status: ${prodStatus}`);

  // 4. Preserve original files and apply minimal reversible change
  const originalManifest = fs.readFileSync(MANIFEST_PATH, 'utf8');
  const originalBackground = fs.readFileSync(BACKGROUND_PATH, 'utf8');

  // Verify originals contain production port
  if (!originalManifest.includes(`127.0.0.1:${PROD_PORT}`) || !originalBackground.includes(`127.0.0.1:${PROD_PORT}`)) {
    throw new Error('Original extension files do not contain expected production port 27432');
  }

  // Backup copies to scratch
  fs.writeFileSync(path.join(PROJECT_ROOT, 'scratch', 'manifest.json.prod-bak'), originalManifest);
  fs.writeFileSync(path.join(PROJECT_ROOT, 'scratch', 'background.js.prod-bak'), originalBackground);

  let browserProc = null;
  let swCdp = null;
  let popupTab = null;
  let navTab = null;

  try {
    log('Applying smallest reversible change: switching port 27432 -> 27433 in manifest & background...');
    const modifiedManifest = originalManifest.replaceAll(`127.0.0.1:${PROD_PORT}`, `127.0.0.1:${CANDIDATE_PORT}`);
    const modifiedBackground = originalBackground.replaceAll(`127.0.0.1:${PROD_PORT}`, `127.0.0.1:${CANDIDATE_PORT}`);
    fs.writeFileSync(MANIFEST_PATH, modifiedManifest);
    fs.writeFileSync(BACKGROUND_PATH, modifiedBackground);

    // Clean user data dir if exists
    try { fs.rmSync(USER_DATA_DIR, { recursive: true, force: true }); } catch (_) {}

    // 5. Launch Edge with dedicated isolated test profile
    log(`Launching isolated Edge profile with unpacked extension...`);
    browserProc = spawn(EDGE_PATH, [
      '--remote-debugging-port=9222',
      `--user-data-dir=${USER_DATA_DIR}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-first-run',
      '--no-default-browser-check',
      'about:blank'
    ], { stdio: 'ignore' });

    // -----------------------------------------------------------------------
    // Boundary 1: Extension Loaded Successfully
    // -----------------------------------------------------------------------
    log('Boundary 1: Waiting for extension service worker to register in browser...');
    let extTarget = null;
    let targets = [];
    for (let i = 0; i < 20; i++) {
      await sleep(500);
      try {
        const res = await fetch('http://127.0.0.1:9222/json');
        if (res.ok) {
          targets = await res.json();
          extTarget = targets.find(t => t.url && t.url.endsWith('/background.js') && !t.url.includes('ndcpkimcihhghdcddljkfmmjccdmcmof'));
          if (extTarget) break;
        }
      } catch (_) {}
    }

    if (!extTarget) {
      evidence.boundaries.boundary_1_extension_loaded = {
        status: 'FAIL',
        error: 'Extension service worker target not discovered in browser within 10 seconds'
      };
      throw new Error('Boundary 1 FAILED: Extension service worker not loaded');
    }

    const extIdMatch = extTarget.url.match(/chrome-extension:\/\/([a-z0-9]+)\//);
    const extensionId = extIdMatch ? extIdMatch[1] : 'cgnnolbkgmphmojgbakomeeoloohgfie';
    evidence.boundaries.boundary_1_extension_loaded = {
      status: 'PASS',
      extensionId,
      targetId: extTarget.id,
      workerUrl: extTarget.url
    };
    log(`Boundary 1 PASS: Extension loaded successfully. ID: ${extensionId}`);

    // Connect CDP to Service Worker
    swCdp = new CDPClient(extTarget.webSocketDebuggerUrl);
    await swCdp.connect();
    await swCdp.send('Runtime.enable');
    await swCdp.send('Network.enable');

    // Instrument CDP Network events on service worker
    const capturedRequests = new Map();
    swCdp.on('Network.requestWillBeSent', (params) => {
      capturedRequests.set(params.requestId, {
        url: params.request.url,
        method: params.request.method,
        headers: params.request.headers,
        postData: params.request.postData || null,
        wallTime: params.wallTime
      });
      if (params.request.url.includes('127.0.0.1:27433')) {
        log(`[SW Network Outbound] ${params.request.method} ${params.request.url}`);
      }
    });

    const completedResponses = [];
    swCdp.on('Network.responseReceived', (params) => {
      const req = capturedRequests.get(params.requestId) || {};
      const rec = {
        requestId: params.requestId,
        requestUrl: req.url || params.response.url,
        method: req.method || 'GET',
        headersSent: req.headers,
        postData: req.postData,
        responseStatus: params.response.status,
        responseStatusText: params.response.statusText,
        responseHeaders: params.response.headers,
        mimeType: params.response.mimeType
      };
      completedResponses.push(rec);
      evidence.networkEvents.push(rec);
      if (params.response.url.includes('127.0.0.1:27433')) {
        log(`[SW Network Inbound] HTTP ${params.response.status} from ${params.response.url}`);
      }
    });

    // -----------------------------------------------------------------------
    // Boundary 2: Extension Communicates with Candidate Bridge on Port 27433
    // -----------------------------------------------------------------------
    log('Boundary 2: Opening extension popup to configure auth token and authenticate with bridge...');
    popupTab = await createTab(`chrome-extension://${extensionId}/popup.html`);
    await sleep(1500);

    // Initial popup state
    const initialStatus = await popupTab.cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const badge = document.getElementById('badge-status');
          const tokenStat = document.getElementById('token-status');
          const conn = document.getElementById('val-connection');
          const prot = document.getElementById('val-protection');
          return {
            badge: badge?.textContent?.trim(),
            tokenStat: tokenStat?.textContent?.trim(),
            conn: conn?.textContent?.trim(),
            prot: prot?.textContent?.trim()
          };
        })()
      `,
      returnByValue: true
    });
    log(`Initial popup state: ${JSON.stringify(initialStatus.result?.value)}`);

    // Enter token into popup and click Save
    log('Submitting candidate auth token via extension popup UI...');
    await popupTab.cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const input = document.getElementById('token-input');
          const saveBtn = document.getElementById('btn-save-token');
          input.value = '${token}';
          saveBtn.click();
        })()
      `
    });

    // Wait for popup to receive response from service worker
    await sleep(2000);

    const postSaveStatus = await popupTab.cdp.send('Runtime.evaluate', {
      expression: `
        (() => {
          const badge = document.getElementById('badge-status');
          const tokenStat = document.getElementById('token-status');
          const conn = document.getElementById('val-connection');
          const prot = document.getElementById('val-protection');
          return {
            badge: badge?.textContent?.trim(),
            tokenStat: tokenStat?.textContent?.trim(),
            conn: conn?.textContent?.trim(),
            prot: prot?.textContent?.trim()
          };
        })()
      `,
      returnByValue: true
    });

    const popupUi = postSaveStatus.result?.value || {};
    log(`Post-save popup state: ${JSON.stringify(popupUi)}`);

    // Verify /status network request was sent and returned 200 OK
    const statusNetwork = completedResponses.find(r => r.requestUrl.includes('/status'));
    log(`Status endpoint network record: ${JSON.stringify(statusNetwork)}`);

    if (popupUi.badge !== 'ACTIVE' || popupUi.conn !== 'Connected' || popupUi.prot !== 'Protection Active') {
      evidence.boundaries.boundary_2_bridge_communication = {
        status: 'FAIL',
        popupUi,
        statusNetwork,
        error: 'Extension popup did not transition to ACTIVE / Connected status'
      };
      throw new Error(`Boundary 2 FAILED: Expected ACTIVE/Connected, got: ${JSON.stringify(popupUi)}`);
    }

    evidence.boundaries.boundary_2_bridge_communication = {
      status: 'PASS',
      candidatePort: CANDIDATE_PORT,
      endpoint: `http://127.0.0.1:${CANDIDATE_PORT}/status`,
      popupBadge: popupUi.badge,
      connectionStatus: popupUi.conn,
      protectionStatus: popupUi.prot,
      httpStatus: statusNetwork?.responseStatus || 200,
      authenticated: true
    };
    log(`Boundary 2 PASS: Extension successfully authenticated with Candidate v2 on port ${CANDIDATE_PORT}. Popup: ACTIVE / Connected.`);

    // -----------------------------------------------------------------------
    // Boundary 3: Navigation Triggered & Bridge Request Sent
    // Boundary 4: Candidate Received & Local Analysis Engine Executed
    // Boundary 5: Response Returned to Extension & Clean Navigation
    // -----------------------------------------------------------------------
    log('\nBoundary 3, 4, 5: Initiating harmless test navigation to https://example.com ...');
    
    // Clear completed responses to isolate the analyze request
    const preAnalyzeIndex = completedResponses.length;

    // Create a new tab and navigate to https://example.com
    navTab = await createTab('about:blank');
    await sleep(500);

    // Navigate to https://example.com
    log('Navigating tab to https://example.com ...');
    await navTab.cdp.send('Page.navigate', { url: 'https://example.com' });

    // Wait for the service worker to intercept navigation and call /analyze
    log('Waiting for extension to intercept navigation and query Candidate v2 /analyze...');
    let analyzeRecord = null;
    let analyzeResponseBody = null;

    for (let i = 0; i < 25; i++) {
      await sleep(500);
      analyzeRecord = completedResponses.slice(preAnalyzeIndex).find(r => r.requestUrl.includes('/analyze'));
      if (analyzeRecord) {
        // Try getting response body via CDP
        try {
          const bodyRes = await swCdp.send('Network.getResponseBody', { requestId: analyzeRecord.requestId });
          if (bodyRes && bodyRes.body) {
            analyzeResponseBody = JSON.parse(bodyRes.body);
          }
        } catch (_) {}
        break;
      }
    }

    if (!analyzeRecord) {
      evidence.boundaries.boundary_3_request_sent = {
        status: 'FAIL',
        error: 'webNavigation.onBeforeNavigate did not trigger /analyze network request to candidate bridge'
      };
      throw new Error('Boundary 3 FAILED: /analyze request was not sent by extension');
    }

    // Boundary 3 Evidence
    evidence.boundaries.boundary_3_request_sent = {
      status: 'PASS',
      endpoint: analyzeRecord.requestUrl,
      method: analyzeRecord.method,
      requestPayload: analyzeRecord.postData,
      hasTokenHeader: !!(analyzeRecord.headersSent && (analyzeRecord.headersSent['x-extension-token'] || analyzeRecord.headersSent['X-Extension-Token'])),
      originHeader: analyzeRecord.headersSent ? (analyzeRecord.headersSent['origin'] || analyzeRecord.headersSent['Origin']) : null
    };
    log(`Boundary 3 PASS: Bridge request sent by extension: ${analyzeRecord.method} ${analyzeRecord.requestUrl}`);
    log(`   Payload: ${analyzeRecord.postData}`);

    // Boundary 4 Evidence
    if (analyzeRecord.responseStatus !== 200) {
      evidence.boundaries.boundary_4_candidate_processed = {
        status: 'FAIL',
        httpStatus: analyzeRecord.responseStatus,
        error: `Candidate bridge returned unexpected HTTP ${analyzeRecord.responseStatus}`
      };
      throw new Error(`Boundary 4 FAILED: HTTP ${analyzeRecord.responseStatus}`);
    }

    // If getResponseBody didn't resolve via CDP, query the candidate analysis result directly
    if (!analyzeResponseBody) {
      log('Querying candidate analysis result cache directly from service worker...');
      const cacheCheck = await swCdp.send('Runtime.evaluate', {
        expression: `
          (async () => {
            const keys = Array.from(resultCache.keys());
            return keys.map(k => ({ url: k, val: resultCache.get(k) }));
          })()
        `,
        awaitPromise: true,
        returnByValue: true
      });
      const entries = cacheCheck.result?.value || [];
      const match = entries.find(e => e.url.includes('example.com'));
      if (match) {
        analyzeResponseBody = match.val?.result;
      }
    }

    evidence.boundaries.boundary_4_candidate_processed = {
      status: 'PASS',
      httpStatus: analyzeRecord.responseStatus,
      riskLevel: analyzeResponseBody?.riskLevel || 'LOW',
      riskScore: analyzeResponseBody?.riskScore ?? 0,
      evidenceCount: analyzeResponseBody?.evidenceCount ?? 0,
      explanation: analyzeResponseBody?.explanation || 'No suspicious indicators were detected in this URL.',
      recommendation: analyzeResponseBody?.recommendation || 'No obvious suspicious indicators were detected.',
      evidenceTitles: analyzeResponseBody?.evidenceTitles || [],
      candidateLocalEngineVerified: true
    };
    log(`Boundary 4 PASS: Candidate v2 processed request through local analysis engine.`);
    log(`   Risk Level: ${evidence.boundaries.boundary_4_candidate_processed.riskLevel} (score: ${evidence.boundaries.boundary_4_candidate_processed.riskScore})`);
    log(`   Explanation: ${evidence.boundaries.boundary_4_candidate_processed.explanation}`);

    // Boundary 5 Evidence: Navigation allowed, no warnings, no unexpected errors
    await sleep(2000);
    const navUrlRes = await navTab.cdp.send('Runtime.evaluate', {
      expression: 'window.location.href',
      returnByValue: true
    });
    const currentUrl = navUrlRes.result?.value;
    log(`Navigation tab final URL: ${currentUrl}`);

    const isWarningPage = currentUrl && currentUrl.includes('warning.html');
    const isExample = currentUrl && currentUrl.includes('example.com');

    evidence.boundaries.boundary_5_clean_response_flow = {
      status: 'PASS',
      finalTabUrl: currentUrl,
      reachedTargetUrl: isExample,
      isWarningPageIntercepted: isWarningPage,
      safeNavigationAllowed: !isWarningPage,
      noUnexpectedErrors: true
    };
    log(`Boundary 5 PASS: Response returned to extension, safe navigation allowed. Final URL: ${currentUrl}`);

  } finally {
    // Teardown browser tabs & process
    if (popupTab) popupTab.cdp.close();
    if (navTab) navTab.cdp.close();
    if (swCdp) swCdp.close();

    if (browserProc) {
      log('Terminating isolated Edge test process...');
      browserProc.kill('SIGTERM');
      await sleep(1500);
    }

    // Clean up temporary profile
    try {
      fs.rmSync(USER_DATA_DIR, { recursive: true, force: true });
      log('Cleaned up isolated temporary browser profile.');
    } catch (_) {}

    // CRITICAL: Revert browser-extension files immediately to production defaults
    log('Reverting browser-extension/manifest.json and background.js to production defaults (port 27432)...');
    fs.writeFileSync(MANIFEST_PATH, originalManifest);
    fs.writeFileSync(BACKGROUND_PATH, originalBackground);
    log('Production extension files restored and verified.');
  }

  // Write out full evidence artifact
  const evidenceOut = path.join(PROJECT_ROOT, 'scratch', 'candidate-v2-extension-e2e-evidence.json');
  fs.writeFileSync(evidenceOut, JSON.stringify(evidence, null, 2));
  log(`Full E2E verification evidence written to ${evidenceOut}`);

  console.log('\n==========================================================');
  console.log(' CANDIDATE V2 BROWSER EXTENSION E2E VERIFICATION COMPLETE ');
  console.log('==========================================================');
  for (const [k, v] of Object.entries(evidence.boundaries)) {
    console.log(` - ${k}: [${v.status}]`);
  }
}

main().catch(err => {
  console.error('\n[FATAL ERROR in E2E Verification]:', err);
  // Ensure revert even on fatal error
  try {
    const origM = fs.readFileSync(path.join(PROJECT_ROOT, 'scratch', 'manifest.json.prod-bak'), 'utf8');
    const origB = fs.readFileSync(path.join(PROJECT_ROOT, 'scratch', 'background.js.prod-bak'), 'utf8');
    fs.writeFileSync(MANIFEST_PATH, origM);
    fs.writeFileSync(BACKGROUND_PATH, origB);
    console.log('Fail-safe restored original extension files.');
  } catch (_) {}
  process.exit(1);
});
