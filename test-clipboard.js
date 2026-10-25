/**
 * test-clipboard.js
 * Automated verification test suite for Clipboard URL detection and event dispatch.
 */

// Setup browser/DOM mocks for Node environment if running outside browser
if (typeof globalThis.localStorage === 'undefined') {
  const store = new Map();
  globalThis.localStorage = {
    getItem: (key) => store.get(key) || null,
    setItem: (key, value) => store.set(key, String(value)),
    removeItem: (key) => store.delete(key),
    clear: () => store.clear(),
  };
}

if (typeof globalThis.window === 'undefined') {
  globalThis.window = {
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  };
}

if (typeof globalThis.CustomEvent === 'undefined') {
  globalThis.CustomEvent = class CustomEvent {
    constructor(type, eventInitDict) {
      this.type = type;
      this.detail = eventInitDict?.detail;
    }
  };
}

if (typeof globalThis.document === 'undefined') {
  globalThis.document = {
    getElementById: () => null,
    createElement: () => ({
      style: {},
      innerHTML: '',
      appendChild: () => {},
      remove: () => {},
      children: [],
    }),
    body: {
      appendChild: () => {},
    },
  };
}

import {
  extractValidUrl,
  handleClipboardUpdate,
  resetClipboardDetectorState,
  getClipboardDetectorState,
} from './src/clipboardDetector.js';
import { parseUrl } from './src/engines/urlAnalyzer.js';
import { collectEvidence } from './src/engines/evidenceEngine.js';
import { calculateRisk } from './src/engines/riskEngine.js';
import { generateExplanation } from './src/engines/explanationEngine.js';
import { getHistory, clearHistory } from './src/storage.js';

let passed = 0;
let failed = 0;

function assert(condition, name, details = '') {
  if (condition) {
    console.log(`  [PASS] ${name}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${name} - ${details}`);
    failed++;
  }
}

console.log('====================================================');
console.log(' CLIPBOARD URL DETECTION & EXTRACTION VERIFICATION');
console.log('====================================================\n');

// 1. Valid URLs
assert(
  extractValidUrl('https://paypal.account-verify-login.secure-portal.example/update') ===
    'https://paypal.account-verify-login.secure-portal.example/update',
  'Test 1: Suspicious HTTPS URL extracted'
);

assert(
  extractValidUrl('http://192.168.1.1:8080/login') ===
    'http://192.168.1.1:8080/login',
  'Test 2: HTTP bare IP URL extracted'
);

assert(
  extractValidUrl('  https://google.com/search?q=test  ') ===
    'https://google.com/search?q=test',
  'Test 3: URL with surrounding whitespace extracted and trimmed'
);

// 2. Non-URLs and Private Data Ignored
assert(
  extractValidUrl('P@ssw0rd123!') === null,
  'Test 4: Password ignored completely'
);

assert(
  extractValidUrl('Hello this is a normal message.') === null,
  'Test 5: Natural language text ignored'
);

assert(
  extractValidUrl('user@domain.com') === null,
  'Test 6: Email address ignored'
);

assert(
  extractValidUrl('C:\\Windows\\System32\\cmd.exe') === null,
  'Test 7: Local file path ignored'
);

assert(
  extractValidUrl('https://site1.com\nhttps://site2.com') === null,
  'Test 8: Multiline clipboard text ignored'
);

assert(
  extractValidUrl('') === null,
  'Test 9: Empty string returns null'
);

assert(
  extractValidUrl(null) === null,
  'Test 10: Null returns null'
);

// IPv6 and Development Hosts
assert(
  extractValidUrl('http://[::1]:8080/test') === 'http://[::1]:8080/test',
  'Test 10a: IPv6 localhost literal [::1] extracted'
);

assert(
  extractValidUrl('https://[2001:db8::1]/') === 'https://[2001:db8::1]/',
  'Test 10b: IPv6 global unicast literal [2001:db8::1] extracted'
);

assert(
  extractValidUrl('http://localhost:3000/dashboard') === 'http://localhost:3000/dashboard',
  'Test 10c: Localhost with development port extracted'
);

assert(
  extractValidUrl('https://localhost/') === 'https://localhost/',
  'Test 10d: Localhost without port extracted'
);

// Credential and Scheme Security Rejections
assert(
  extractValidUrl('https://user:password@example.com/') === null,
  'Test 10e: URL with embedded credentials rejected'
);

assert(
  extractValidUrl('http://admin:@example.com/') === null,
  'Test 10f: URL with username and empty password rejected'
);

assert(
  extractValidUrl('https://user@example.com/') === null,
  'Test 10g: URL with username only rejected'
);

assert(
  extractValidUrl('javascript:alert(1)') === null,
  'Test 10h: javascript: scheme rejected'
);

assert(
  extractValidUrl('file:///C:/Windows/System32') === null,
  'Test 10i: file: scheme rejected'
);

assert(
  extractValidUrl('data:text/html,<script>alert(1)</script>') === null,
  'Test 10j: data: scheme rejected'
);

// Single-label non-localhost hostnames
assert(
  extractValidUrl('http://intranet/') === null,
  'Test 10k: Single-label hostname intranet rejected'
);

assert(
  extractValidUrl('https://router/setup') === null,
  'Test 10l: Single-label hostname router rejected'
);

// Internal whitespace and prose
assert(
  extractValidUrl('https://exa mple.com') === null,
  'Test 10m: Internal whitespace rejected'
);

assert(
  extractValidUrl('Check out https://example.com today!') === null,
  'Test 10n: Prose containing URL rejected'
);

// 3. Heuristic Engine Pipeline verification
const sampleUrl = 'https://paypal.account-verify-login.secure-portal.example/update';
const parseRes = parseUrl(sampleUrl);
assert(parseRes.success, 'Test 11: Sample URL parses successfully');

const evidence = collectEvidence(parseRes.data, { deepInvestigation: false });
assert(evidence.length >= 2, 'Test 12: Evidence collected (>= 2 flags)');

const risk = calculateRisk(evidence);
assert(risk.level === 'HIGH', 'Test 13: Risk level calculated as HIGH');

const { explanation, recommendation } = generateExplanation(evidence, risk);
assert(typeof explanation === 'string' && explanation.length > 0, 'Test 14: Explanation generated');
assert(typeof recommendation === 'string' && recommendation.length > 0, 'Test 15: Recommendation generated');

// 4. Repeated URL & Clipboard Detection Regression Suite
console.log('\n--- Repeated Clipboard Copy & Polling Regression Suite ---');

clearHistory();
resetClipboardDetectorState();

// Regression Test 16: First clipboard copy
const targetUrl = 'https://paypal.account-verify-login.secure-portal.example/update';
handleClipboardUpdate(targetUrl, { sequence: 1, isNewEvent: true });

const historyAfterFirst = getHistory();
assert(
  historyAfterFirst.length === 1 && historyAfterFirst[0].url === targetUrl,
  'Test 16: First copy generates 1 history entry with matching URL'
);
assert(
  historyAfterFirst[0].source === 'Clipboard',
  'Test 17: First copy record correctly attributes source as "Clipboard"'
);
assert(
  historyAfterFirst[0].riskLevel === 'HIGH',
  'Test 18: First copy record correctly classified as HIGH risk'
);

const stateAfterFirst = getClipboardDetectorState();
assert(
  stateAfterFirst.lastProcessedUrl === targetUrl && stateAfterFirst.lastSequence === 1,
  'Test 19: Detector tracks last processed URL and sequence'
);

// Regression Test 20: Unchanged clipboard polling produces NO duplicate entries or spam
handleClipboardUpdate(targetUrl, { sequence: 1, isNewEvent: false });
handleClipboardUpdate(targetUrl, { sequence: 1, isNewEvent: false });
handleClipboardUpdate(targetUrl, { sequence: 1, isNewEvent: false });

const historyAfterIdlePolling = getHistory();
assert(
  historyAfterIdlePolling.length === 1,
  'Test 20: Polling unchanged clipboard produces NO duplicate history entries or notification spam'
);

// Regression Test 21: Same URL copied again as a distinct event
handleClipboardUpdate(targetUrl, { sequence: 2, isNewEvent: true });

const historyAfterSecondCopy = getHistory();
assert(
  historyAfterSecondCopy.length === 2,
  'Test 21: Same URL copied again as a distinct event produces a second history entry'
);
assert(
  historyAfterSecondCopy[0].url === targetUrl && historyAfterSecondCopy[1].url === targetUrl,
  'Test 22: Both history entries match the copied URL'
);
assert(
  historyAfterSecondCopy[0].id !== historyAfterSecondCopy[1].id,
  'Test 23: Both entries have distinct unique IDs (no overwrite)'
);
assert(
  historyAfterSecondCopy[0].timestamp >= historyAfterSecondCopy[1].timestamp,
  'Test 24: History records maintain accurate chronological ordering'
);

// Regression Test 25: Persistence after refresh
// Simulating refresh by re-reading history from storage
const refreshedHistory = getHistory();
assert(
  refreshedHistory.length === 2,
  'Test 25: Refreshing preserves both entries in persistent history'
);
assert(
  refreshedHistory[0].id === historyAfterSecondCopy[0].id &&
  refreshedHistory[1].id === historyAfterSecondCopy[1].id,
  'Test 26: Preserved entries retain identical data across refresh'
);

// Regression Test 27: Repeated unchanged polling after second copy
handleClipboardUpdate(targetUrl, { sequence: 2, isNewEvent: false });
handleClipboardUpdate(targetUrl, { sequence: 2, isNewEvent: false });

const historyAfterMorePolling = getHistory();
assert(
  historyAfterMorePolling.length === 2,
  'Test 27: Continued polling on unchanged clipboard remains deduplicated at 2 entries'
);

// Regression Test 28: Third distinct copy event of same URL
handleClipboardUpdate(targetUrl, { sequence: 3, isNewEvent: true });
const historyAfterThirdCopy = getHistory();
assert(
  historyAfterThirdCopy.length === 3,
  'Test 28: Third intentional copy of same URL produces a third distinct history entry'
);

// ---------------------------------------------------------------------------
// Stage 1 Clipboard Privacy & Progression Verification
// ---------------------------------------------------------------------------
console.log('\n--- Stage 1 Privacy & Sequence Progression Verification ---');

// Test 29: Raw password copied -> state must NOT retain raw text
const secretPassword = 'SuperSecretMasterPassword123!#$';
handleClipboardUpdate(secretPassword, { sequence: 4, isNewEvent: true });
const stateAfterPassword = getClipboardDetectorState();
assert(
  stateAfterPassword.lastRawClipboard === '',
  'Test 29: Raw password is NEVER stored in detector state (lastRawClipboard is empty)'
);

// Test 30: Raw password copy produces no history entries
const historyAfterPassword = getHistory();
assert(
  historyAfterPassword.length === 3,
  'Test 30: Non-URL password creates zero history entries'
);

// Test 31: Sequence advances on rejected content to prevent looping
assert(
  stateAfterPassword.lastSequence === 4,
  'Test 31: Sequence number advances on rejected content (preventing idle loop)'
);

// Test 32: Valid URL copied AFTER rejected password is processed correctly
const validAfterPassword = 'https://clean-site.example/page';
handleClipboardUpdate(validAfterPassword, { sequence: 5, isNewEvent: true });
const historyAfterClean = getHistory();
assert(
  historyAfterClean.length === 4 && historyAfterClean[0].url === validAfterPassword,
  'Test 32: Valid URL copied after rejected password processes correctly into history'
);

// Test 33: IPv6 literal URL processing
const ipv6Url = 'http://[::1]:8080/test';
handleClipboardUpdate(ipv6Url, { sequence: 6, isNewEvent: true });
const historyAfterIPv6 = getHistory();
assert(
  historyAfterIPv6.length === 5 && historyAfterIPv6[0].url === ipv6Url,
  'Test 33: Valid IPv6 literal URL processes correctly into history'
);

// Test 34: Polling unchanged IPv6 URL does not create duplicate
handleClipboardUpdate(ipv6Url, { sequence: 6, isNewEvent: false });
handleClipboardUpdate(ipv6Url, { sequence: 6, isNewEvent: false });
const historyAfterIPv6Polling = getHistory();
assert(
  historyAfterIPv6Polling.length === 5,
  'Test 34: Unchanged IPv6 URL during idle polling is deduplicated'
);

// Test 35: Re-copying same IPv6 URL with new sequence creates distinct history entry
handleClipboardUpdate(ipv6Url, { sequence: 7, isNewEvent: true });
const historyAfterIPv6Recopy = getHistory();
assert(
  historyAfterIPv6Recopy.length === 6,
  'Test 35: Intentional re-copy of same IPv6 URL with new sequence creates distinct entry'
);

// Test 36: State privacy check after multiple operations
const finalState = getClipboardDetectorState();
assert(
  finalState.lastRawClipboard === '',
  'Test 36: Detector state lastRawClipboard remains permanently empty across all operations'
);
assert(
  !JSON.stringify(finalState).includes(secretPassword),
  'Test 37: Serialized detector state contains zero trace of sensitive clipboard text'
);

console.log('\n====================================================');
console.log(` TEST SUMMARY: ${passed} Passed, ${failed} Failed`);
console.log('====================================================\n');

if (failed > 0) {
  process.exit(1);
}
