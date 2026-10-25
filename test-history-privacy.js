/**
 * test-history-privacy.js
 * Comprehensive automated regression suite for Stage 3B-1 URL history redaction
 * and diagnostic log privacy (BZ-PRIV-01 & BZ-PRIV-02).
 */

// Setup browser/DOM mocks for Node environment
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

import {
  sanitizeUrlForHistory,
  saveHistoryItem,
  getHistory,
  clearHistory,
  deleteHistoryItem,
} from './src/storage.js';
import { parseUrl } from './src/engines/urlAnalyzer.js';
import { collectEvidence } from './src/engines/evidenceEngine.js';
import { calculateRisk } from './src/engines/riskEngine.js';
import { generateExplanation } from './src/engines/explanationEngine.js';

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
console.log(' STAGE 3B-1: URL HISTORY REDACTION & PRIVACY TESTS');
console.log('====================================================\n');

// 1. Core Redaction Function Tests
console.log('--- 1. Dedicated URL Sanitizer Function Tests ---');

// Test 1: URL with ?token=secret123
const urlWithToken = 'https://portal.example.com/reset?token=secret123';
const sanitized1 = sanitizeUrlForHistory(urlWithToken);
assert(
  sanitized1 === 'https://portal.example.com/reset' && !sanitized1.includes('secret123') && !sanitized1.includes('?'),
  'Test 1: Query parameter ?token=secret123 is completely stripped'
);

// Test 2: URL with OAuth ?code=...
const urlOAuth = 'https://auth.provider.example/oauth/callback?code=AUTH_CODE_98765&state=xyz';
const sanitized2 = sanitizeUrlForHistory(urlOAuth);
assert(
  sanitized2 === 'https://auth.provider.example/oauth/callback' && !sanitized2.includes('AUTH_CODE'),
  'Test 2: OAuth ?code=... and state parameters are completely stripped'
);

// Test 3: URL containing email and sensitive query parameter
const urlWithEmail = 'https://service.example/verify?email=user%40victim.com&key=K837492817';
const sanitized3 = sanitizeUrlForHistory(urlWithEmail);
assert(
  sanitized3 === 'https://service.example/verify' && !sanitized3.includes('victim.com') && !sanitized3.includes('K837492817'),
  'Test 3: Email and verification key query parameters are stripped'
);

// Test 4: URL with sensitive fragment
const urlWithFragment = 'https://docs.example.com/app/index.html#access_token=TOP_SECRET_HASH_TOKEN';
const sanitized4 = sanitizeUrlForHistory(urlWithFragment);
assert(
  sanitized4 === 'https://docs.example.com/app/index.html' && !sanitized4.includes('TOP_SECRET') && !sanitized4.includes('#'),
  'Test 4: Sensitive URL hash/fragment is completely stripped'
);

// Test 5: URL with embedded username/password credentials
const urlWithCreds = 'https://admin:super_secret_password@internal.example.org/dashboard?session=999';
const sanitized5 = sanitizeUrlForHistory(urlWithCreds);
assert(
  sanitized5 === 'https://internal.example.org/dashboard' &&
  !sanitized5.includes('admin') &&
  !sanitized5.includes('super_secret_password') &&
  !sanitized5.includes('@'),
  'Test 5: Embedded credentials (user:pass@) and query parameters are stripped'
);

// Test 6: URL without query parameters or fragments
const cleanUrl = 'https://safe-domain.example/public/about-us';
const sanitized6 = sanitizeUrlForHistory(cleanUrl);
assert(
  sanitized6 === 'https://safe-domain.example/public/about-us',
  'Test 6: Clean URL without query or fragment is preserved intact'
);

// Test 7: URL with port and nested path
const urlWithPortAndPath = 'https://staging.internal.example:8443/api/v2/services/health?debug=true#tab1';
const sanitized7 = sanitizeUrlForHistory(urlWithPortAndPath);
assert(
  sanitized7 === 'https://staging.internal.example:8443/api/v2/services/health' &&
  !sanitized7.includes('debug') &&
  !sanitized7.includes('tab1'),
  'Test 7: URL with port and nested path is preserved while query/fragment are stripped'
);

// Test 8: Malformed or unsupported input safely handled without persisting raw secret
const malformedInput = 'not a valid url but has ?secret=myPassword123';
const sanitized8 = sanitizeUrlForHistory(malformedInput);
assert(
  !sanitized8.includes('myPassword123') && (sanitized8 === '[Invalid URL]' || !sanitized8.includes('?')),
  'Test 8: Malformed input never persists raw sensitive data'
);

// Test 9: Null or empty input
assert(sanitizeUrlForHistory(null) === '', 'Test 9a: Null input returns empty string');
assert(sanitizeUrlForHistory('') === '', 'Test 9b: Empty string input returns empty string');


// 2. Integration with Storage Pipeline & Callers
console.log('\n--- 2. Storage Persistence & Pipeline Preservation Tests ---');

clearHistory();

// Test 10: Original URL is evaluated by analysis pipeline BEFORE history save
const attackUrl = 'https://paypal.account-verify-login.secure-portal.example/update?token=EXFILTRATE_ME_NOW#step2';
const parseRes = parseUrl(attackUrl);
assert(parseRes.success, 'Test 10a: Original URL with token successfully parsed by URL analyzer');

// Phase 2 engine evaluates the raw URL
const evidence = collectEvidence(parseRes.data, { deepInvestigation: false });
const risk = calculateRisk(evidence);
const { explanation, recommendation } = generateExplanation(evidence, risk);

// Save to history
const savedRecord = saveHistoryItem({
  url: attackUrl, // Passing the raw URL
  urlData: parseRes.data,
  riskResult: risk,
  evidenceList: evidence,
  explanation,
  recommendation,
  source: 'Manual',
});

assert(savedRecord !== null, 'Test 10b: Record saved successfully');
assert(
  savedRecord.url === 'https://paypal.account-verify-login.secure-portal.example/update',
  'Test 10c: Saved record URL is sanitized (token and fragment stripped)'
);
assert(!savedRecord.url.includes('EXFILTRATE_ME_NOW'), 'Test 10d: Token is absent from saved record');
assert(!savedRecord.url.includes('#step2'), 'Test 10e: Fragment is absent from saved record');
assert(savedRecord.hostname === 'paypal.account-verify-login.secure-portal.example', 'Test 10f: Hostname is preserved');
assert(savedRecord.riskLevel === 'HIGH', 'Test 10g: Risk level is preserved');
assert(savedRecord.riskScore > 0, 'Test 10h: Risk score is preserved');
assert(savedRecord.evidenceCount >= 2, 'Test 10i: Evidence count is preserved');
assert(typeof savedRecord.timestamp === 'number', 'Test 10j: Timestamp is preserved');

// Verify actual persisted localStorage value
const rawStoredJson = globalThis.localStorage.getItem('linkguard_scan_history');
assert(
  !rawStoredJson.includes('EXFILTRATE_ME_NOW'),
  'Test 11: Raw localStorage does NOT contain the secret token'
);
assert(
  !rawStoredJson.includes('#step2'),
  'Test 12: Raw localStorage does NOT contain the secret fragment'
);


// 3. Legacy Record Migration Test
console.log('\n--- 3. Legacy History Cleansing / Migration Tests ---');

// Manually seed unredacted legacy records into localStorage
const legacyRecords = [
  {
    id: 'legacy_1',
    timestamp: Date.now() - 5000,
    url: 'https://legacy.example.com/oauth?token=LEGACY_SECRET_TOKEN_ABC',
    hostname: 'legacy.example.com',
    riskLevel: 'LOW',
  },
  {
    id: 'legacy_2',
    timestamp: Date.now() - 4000,
    url: 'https://user:password123@legacy.example.com/admin#private',
    hostname: 'legacy.example.com',
    riskLevel: 'HIGH',
  },
];
globalThis.localStorage.setItem('linkguard_scan_history', JSON.stringify(legacyRecords));

// Trigger getHistory() which cleanses legacy records
const loadedHistory = getHistory();
assert(loadedHistory.length === 2, 'Test 13a: Both legacy records retrieved');
assert(
  loadedHistory[0].url === 'https://legacy.example.com/oauth',
  'Test 13b: Legacy record 1 sanitized in memory'
);
assert(
  !loadedHistory[0].url.includes('LEGACY_SECRET_TOKEN_ABC'),
  'Test 13c: Secret token purged from legacy record 1'
);
assert(
  loadedHistory[1].url === 'https://legacy.example.com/admin',
  'Test 13d: Legacy record 2 credentials and fragment purged'
);

// Check that localStorage was also updated on disk
const migratedStorageRaw = globalThis.localStorage.getItem('linkguard_scan_history');
assert(
  !migratedStorageRaw.includes('LEGACY_SECRET_TOKEN_ABC'),
  'Test 14a: localStorage cleansed of legacy token'
);
assert(
  !migratedStorageRaw.includes('password123'),
  'Test 14b: localStorage cleansed of legacy password'
);


// 4. Storage Limits and Deletion Operations
console.log('\n--- 4. History Limits & Deletion Tests ---');

// Test 15: Single item deletion
const idToDelete = loadedHistory[0].id;
const deleteRes = deleteHistoryItem(idToDelete);
assert(deleteRes === true, 'Test 15a: deleteHistoryItem returned true');
const historyAfterDel = getHistory();
assert(historyAfterDel.length === 1 && historyAfterDel[0].id === 'legacy_2', 'Test 15b: Correct item removed');

// Test 16: Clear history
const clearRes = clearHistory();
assert(clearRes === true, 'Test 16a: clearHistory returned true');
assert(getHistory().length === 0, 'Test 16b: getHistory returns empty array after clear');
assert(globalThis.localStorage.getItem('linkguard_scan_history') === null, 'Test 16c: Storage key removed');

// Test 17: History entry limit (MAX_HISTORY_ITEMS = 100)
for (let i = 0; i < 110; i++) {
  saveHistoryItem({
    url: `https://test-entry-${i}.example/path?token=SECRET_${i}`,
    urlData: { hostname: `test-entry-${i}.example` },
    riskResult: { level: 'LOW', score: 0 },
    evidenceList: [],
  });
}
const cappedHistory = getHistory();
assert(cappedHistory.length === 100, 'Test 17a: History length capped strictly at 100');
assert(
  cappedHistory[0].url === 'https://test-entry-109.example/path',
  'Test 17b: Most recent item is at index 0'
);
assert(
  !globalThis.localStorage.getItem('linkguard_scan_history').includes('SECRET_'),
  'Test 17c: None of the 110 secret tokens were persisted'
);


// 5. Diagnostic Log Privacy Test
console.log('\n--- 5. Diagnostic Logging Privacy Tests ---');

let capturedWarnings = [];
const originalWarn = console.warn;
console.warn = (...args) => {
  capturedWarnings.push(args.join(' '));
  originalWarn(...args);
};

// Trigger saveHistoryItem with sensitive URL
saveHistoryItem({
  url: 'https://bank.example/account?auth_token=LOG_SENSITIVE_SECRET#fragment123',
  urlData: { hostname: 'bank.example' },
  riskResult: { level: 'MEDIUM', score: 50 },
  evidenceList: [],
});

console.warn = originalWarn;

const logOutput = capturedWarnings.join('\n');
assert(
  !logOutput.includes('LOG_SENSITIVE_SECRET'),
  'Test 18: Diagnostic logs do NOT contain the sensitive query token'
);
assert(
  !logOutput.includes('fragment123'),
  'Test 19: Diagnostic logs do NOT contain the URL fragment'
);
assert(
  logOutput.includes('[UI-DIAG] History write completed | host=bank.example'),
  'Test 20: Diagnostic logs contain safe host metadata and record count'
);


console.log('\n====================================================');
console.log(` TEST SUMMARY: ${passed} Passed, ${failed} Failed`);
console.log('====================================================\n');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
