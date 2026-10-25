/**
 * test-notification.js
 * Automated test suite for Phase 3B-3: Windows Notification URL Detection.
 *
 * Verifies all 12 required URL extraction test cases and notification processing behaviors:
 * 1. Single HTTPS URL
 * 2. Single HTTP URL
 * 3. Multiple URLs
 * 4. URL surrounded by punctuation
 * 5. No URL
 * 6. Duplicate URL
 * 7. Invalid URL
 * 8. URL with query parameters
 * 9. URL with fragments
 * 10. URL with port
 * 11. Very long URL
 * 12. Non-URL text
 *
 * Plus system coordination, failure handling, and privacy tests:
 * 13. Suspicious test URL evaluation (PayPal lookalike)
 * 14. Loop Prevention: Own application notifications ignored
 * 15. Bounded Deduplication Cache
 * 16. Privacy Verification: URL extraction drops message text & OTPs
 * 17. Startup failure handling: state resets to false and allows retry
 * 18. Successful startup and stop monitoring lifecycle
 * 19. Discord notification processing & History persistence
 * 20. WhatsApp notification processing & History persistence
 * 21. Privacy verification: notification body and title are NEVER persisted in history
 * 22. In-place updated notification detection (same ID, new link)
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

globalThis.window.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
  unregisterListener: () => {},
};

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
  extractNotificationUrls,
  normalizeNotificationUrl,
} from './src/notification/notificationUrlExtractor.js';

import {
  isOwnNotification,
  isDuplicateNotification,
  processNotificationEvent,
  startNotificationMonitoring,
  stopNotificationMonitoring,
  getIsMonitoring,
} from './src/notification/notificationDetector.js';

import { getHistory, clearHistory } from './src/storage.js';

// Import existing authoritative engines
import { parseUrl } from './src/engines/urlAnalyzer.js';
import { collectEvidence } from './src/engines/evidenceEngine.js';
import { calculateRisk } from './src/engines/riskEngine.js';
import { generateExplanation } from './src/engines/explanationEngine.js';

let passed = 0;
let failed = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName} - ${details}`);
    failed++;
  }
}

async function runTests() {
  console.log('====================================================');
  console.log(' PHASE 3B-3: NOTIFICATION URL EXTRACTION & DETECTION');
  console.log('====================================================\n');

  // -----------------------------------------------------------------
  // 1. Single HTTPS URL
  // -----------------------------------------------------------------
  console.log('--- URL Extractor Tests (1 to 12) ---');
  const t1 = extractNotificationUrls('Discord notification: check out https://example.com/chat/general for updates');
  assert(t1.length === 1 && t1[0] === 'https://example.com/chat/general', 'Test 1: Single HTTPS URL extracted');

  // -----------------------------------------------------------------
  // 2. Single HTTP URL
  // -----------------------------------------------------------------
  const t2 = extractNotificationUrls('Insecure link received: http://insecure-portal.org/login');
  assert(t2.length === 1 && t2[0] === 'http://insecure-portal.org/login', 'Test 2: Single HTTP URL extracted');

  // -----------------------------------------------------------------
  // 3. Multiple URLs
  // -----------------------------------------------------------------
  const t3 = extractNotificationUrls('Links:\nhttps://example.com\nhttps://example.org/path');
  assert(
    t3.length === 2 &&
    t3.some(u => u.startsWith('https://example.com')) &&
    t3.some(u => u.startsWith('https://example.org')),
    'Test 3: Multiple distinct URLs extracted',
    `Got: ${JSON.stringify(t3)}`
  );

  // -----------------------------------------------------------------
  // 4. URL surrounded by punctuation
  // -----------------------------------------------------------------
  const t4a = extractNotificationUrls('Visit (https://example.com/login).');
  assert(t4a.length === 1 && t4a[0] === 'https://example.com/login', 'Test 4a: URL enclosed in parentheses with trailing period');

  const t4b = extractNotificationUrls('Check [https://example.com/docs] now!');
  assert(t4b.length === 1 && t4b[0] === 'https://example.com/docs', 'Test 4b: URL enclosed in brackets with trailing exclamation');

  const t4c = extractNotificationUrls('He said: "https://example.com/quote", right?');
  assert(t4c.length === 1 && t4c[0] === 'https://example.com/quote', 'Test 4c: URL enclosed in quotes with trailing comma');

  // -----------------------------------------------------------------
  // 5. No URL
  // -----------------------------------------------------------------
  const t5 = extractNotificationUrls('Hello world! How are you doing today? No links here.');
  assert(t5.length === 0, 'Test 5: No URL returns empty array');

  // -----------------------------------------------------------------
  // 6. Duplicate URL
  // -----------------------------------------------------------------
  const t6 = extractNotificationUrls('Repeated link: https://example.com/home and again https://example.com/home');
  assert(t6.length === 1 && t6[0] === 'https://example.com/home', 'Test 6: Duplicate URLs within notification deduplicated to 1');

  // -----------------------------------------------------------------
  // 7. Invalid URL
  // -----------------------------------------------------------------
  const t7a = extractNotificationUrls('Broken: https:// or https://... or http://');
  assert(t7a.length === 0, 'Test 7a: Incomplete scheme discarded');

  const t7b = extractNotificationUrls('Malformed: https://.com or http://bad domain/path');
  assert(t7b.length === 0, 'Test 7b: Malformed domain discarded');

  // -----------------------------------------------------------------
  // 8. URL with query parameters
  // -----------------------------------------------------------------
  const t8 = extractNotificationUrls('Search here: https://example.com/search?q=test%20query&filter=active&sort=desc');
  assert(
    t8.length === 1 && t8[0].includes('q=test%20query') && t8[0].includes('filter=active'),
    'Test 8: Query parameters preserved intact'
  );

  // -----------------------------------------------------------------
  // 9. URL with fragments
  // -----------------------------------------------------------------
  const t9 = extractNotificationUrls('Anchor link: https://example.com/guide#section-4.2');
  assert(t9.length === 1 && t9[0].endsWith('#section-4.2'), 'Test 9: URL fragments preserved');

  // -----------------------------------------------------------------
  // 10. URL with port
  // -----------------------------------------------------------------
  const t10 = extractNotificationUrls('Dev service at http://127.0.0.1:8080/dashboard');
  assert(t10.length === 1 && t10[0] === 'http://127.0.0.1:8080/dashboard', 'Test 10: URL port preserved');

  // -----------------------------------------------------------------
  // 11. Very long URL
  // -----------------------------------------------------------------
  const longPath = 'a'.repeat(300);
  const longUrlInput = `Long link https://example.com/path/${longPath}?token=${'b'.repeat(100)}`;
  const t11 = extractNotificationUrls(longUrlInput);
  assert(t11.length === 1 && t11[0].length > 400, 'Test 11: Very long URL extracted without truncation');

  // -----------------------------------------------------------------
  // 12. Non-URL text
  // -----------------------------------------------------------------
  const t12 = extractNotificationUrls('Email user@example.com, file C:\\Users\\docs, package.json, or word.with.dots');
  assert(t12.length === 0, 'Test 12: Non-URL text (emails, file paths, words with dots) ignored');

  // -----------------------------------------------------------------
  // 13. Suspicious test URL evaluation through existing engines
  // -----------------------------------------------------------------
  console.log('\n--- Authoritative Analysis Pipeline Integration ---');
  const suspUrl = 'https://paypal.account-verify-login.secure-portal.example/update';
  const parseResult = parseUrl(suspUrl);
  assert(parseResult.success, 'Test 13a: Suspicious URL parsed successfully');

  const evidence = collectEvidence(parseResult.data, { deepInvestigation: false });
  const risk = calculateRisk(evidence);
  const exp = generateExplanation(evidence, risk);

  assert(risk.level === 'HIGH', `Test 13b: Risk level is HIGH (got: ${risk.level})`);
  assert(evidence.length >= 2, `Test 13c: Evidence collected (count: ${evidence.length})`);
  assert(exp.explanation.length > 20, 'Test 13d: Explanation generated by existing explanationEngine');
  assert(exp.recommendation.length > 20, 'Test 13e: Recommendation generated by existing explanationEngine');

  // -----------------------------------------------------------------
  // 14. Loop Prevention: Own application notifications ignored
  // -----------------------------------------------------------------
  console.log('\n--- Loop Prevention & Deduplication ---');
  const ownNotif1 = {
    sourceApp: 'com.security.linkprotection',
    title: '⚠️ Suspicious Link Detected',
    text: 'HIGH RISK — Suspicious indicators detected at https://evil.example/login',
  };
  assert(isOwnNotification(ownNotif1) === true, 'Test 14a: Own application notification identified');

  const ownNotif2 = {
    sourceApp: 'Discord',
    title: '⚠️ Suspicious Link Detected', // Title matches our warning pattern
    text: 'Notice',
  };
  assert(isOwnNotification(ownNotif2) === true, 'Test 14b: Warning title matches own notification pattern');

  const thirdPartyNotif = {
    sourceApp: 'Discord',
    title: 'New Message from Alice',
    text: 'Check this link: https://example.com',
  };
  assert(isOwnNotification(thirdPartyNotif) === false, 'Test 14c: Third-party notification correctly permitted');

  // -----------------------------------------------------------------
  // 15. Bounded Deduplication Cache
  // -----------------------------------------------------------------
  const app = 'Discord';
  const notifId = 'notif_9981';
  const url = 'https://example.com/unique-test';

  const firstCheck = isDuplicateNotification(app, notifId, url);
  assert(firstCheck === false, 'Test 15a: First occurrence is not a duplicate');

  const secondCheck = isDuplicateNotification(app, notifId, url);
  assert(secondCheck === true, 'Test 15b: Immediate re-occurrence is identified as duplicate');

  // Different notification ID or URL should not be marked duplicate
  const differentUrlCheck = isDuplicateNotification(app, notifId, 'https://example.com/another-url');
  assert(differentUrlCheck === false, 'Test 15c: Different URL in same notification is not duplicate');

  // -----------------------------------------------------------------
  // 16. Privacy Verification
  // -----------------------------------------------------------------
  console.log('\n--- Privacy & Data Sanitization ---');
  const sensitiveMessage = 'Private chat: Hey, your OTP is 492019 and here is https://portal.example/auth to login';
  const extractedFromSensitive = extractNotificationUrls(sensitiveMessage);

  assert(extractedFromSensitive.length === 1, 'Test 16a: Only URL was extracted from sensitive message');
  assert(
    !extractedFromSensitive[0].includes('OTP') &&
    !extractedFromSensitive[0].includes('Private') &&
    !extractedFromSensitive[0].includes('492019'),
    'Test 16b: Surrounding message text, OTP, and conversation content discarded'
  );

  // -----------------------------------------------------------------
  // 17. Startup failure handling and state reset
  // -----------------------------------------------------------------
  console.log('\n--- Startup Failure Handling & State Reset ---');
  // In non-Tauri or unavailable environment:
  delete globalThis.window.__TAURI__;
  delete globalThis.window.__TAURI_INTERNALS__;
  globalThis.isTauri = false;
  if (globalThis.window) globalThis.window.isTauri = false;

  const startFailRes = await startNotificationMonitoring();
  assert(startFailRes.success === false, 'Test 17a: Startup returns failure when Tauri listener is unavailable');
  assert(getIsMonitoring() === false, 'Test 17b: isMonitoring state resets to false on startup failure');

  // Verify backend command failure preserves actionable error
  globalThis.isTauri = true;
  globalThis.window.isTauri = true;
  globalThis.window.__TAURI__ = {
    core: {
      invoke: async (cmd) => {
        if (cmd === 'start_notification_listener') {
          throw new Error('Windows notification access is not granted (status: Denied). Enable access in Windows Settings.');
        }
        if (cmd === 'plugin:event|listen') {
          return 1;
        }
        return null;
      },
    },
    event: {
      listen: async () => () => {},
    },
  };
  globalThis.window.__TAURI_INTERNALS__ = {
    invoke: globalThis.window.__TAURI__.core.invoke,
    transformCallback: () => 1,
  };

  const commandFailRes = await startNotificationMonitoring();
  assert(commandFailRes.success === false, 'Test 17d: Startup returns false when start_notification_listener command fails');
  assert(commandFailRes.error.includes('Windows notification access is not granted'), 'Test 17e: Actionable backend error message is preserved and returned');
  assert(getIsMonitoring() === false, 'Test 17f: isMonitoring remains false after backend command failure');

  // -----------------------------------------------------------------
  // 18. Successful startup, repeated click prevention, and stop monitoring lifecycle
  // -----------------------------------------------------------------
  console.log('\n--- Monitoring Lifecycle & Toggle State Synchronization ---');
  let mockUnlistenCalled = false;
  let mockStartInvokeCount = 0;
  let mockStopInvokeCount = 0;

  globalThis.isTauri = true;
  globalThis.window.isTauri = true;
  globalThis.window.__TAURI__ = {
    core: {
      invoke: async (cmd) => {
        if (cmd === 'start_notification_listener') {
          mockStartInvokeCount++;
          return { success: true };
        }
        if (cmd === 'stop_notification_listener') {
          mockStopInvokeCount++;
          return { success: true };
        }
        if (cmd === 'plugin:event|listen') {
          return 1;
        }
        if (cmd === 'plugin:event|unlisten') {
          mockUnlistenCalled = true;
          return null;
        }
        return null;
      },
    },
    event: {
      listen: async (evt, cb) => {
        return () => { mockUnlistenCalled = true; };
      },
    },
  };
  globalThis.window.__TAURI_INTERNALS__ = {
    invoke: globalThis.window.__TAURI__.core.invoke,
    transformCallback: () => 1,
  };
  globalThis.window.__TAURI_EVENT_PLUGIN_INTERNALS__ = {
    unregisterListener: () => {},
  };

  const startOkRes = await startNotificationMonitoring();
  assert(startOkRes.success === true, 'Test 18a: startNotificationMonitoring succeeds with valid Tauri interface');
  assert(getIsMonitoring() === true, 'Test 18b: isMonitoring becomes true after successful startup');
  assert(mockStartInvokeCount === 1, 'Test 18c: start_notification_listener invoked once');

  // Verify repeated click while already running does not spawn duplicate thread
  const alreadyRunningRes = await startNotificationMonitoring();
  assert(alreadyRunningRes.alreadyRunning === true, 'Test 18d: Subsequent start call acknowledges already running');
  assert(mockStartInvokeCount === 1, 'Test 18e: start_notification_listener is not invoked again when already running');

  await stopNotificationMonitoring();
  assert(getIsMonitoring() === false, 'Test 18f: isMonitoring resets to false after stopNotificationMonitoring');
  assert(mockUnlistenCalled === true, 'Test 18g: Event unlisten callback executed on stop');
  assert(mockStopInvokeCount === 1, 'Test 18h: stop_notification_listener invoked once on stop');

  // -----------------------------------------------------------------
  // 19. Discord notification processing & History persistence
  // -----------------------------------------------------------------
  console.log('\n--- Discord & WhatsApp Notification Pipeline Verification ---');
  globalThis.localStorage.setItem('app_settings', JSON.stringify({ notificationProtection: true }));
  clearHistory();

  // Discord sends body and title
  const discordPayload = {
    sourceApp: 'Discord',
    notificationId: 'discord_msg_4412',
    title: 'Project Channel',
    body: 'Please review documentation at https://discord-safe.example/docs before the standup.',
  };

  await processNotificationEvent(discordPayload);

  const historyAfterDiscord = getHistory();
  assert(historyAfterDiscord.length === 1, 'Test 19a: Discord notification link saved to History');
  assert(historyAfterDiscord[0].url === 'https://discord-safe.example/docs', 'Test 19b: Correct URL extracted and stored');
  assert(historyAfterDiscord[0].source === 'Notification', 'Test 19c: History record source is "Notification"');
  assert(historyAfterDiscord[0].riskLevel !== undefined, 'Test 19d: History record has riskLevel assigned');

  // -----------------------------------------------------------------
  // 20. WhatsApp notification processing & History persistence
  // -----------------------------------------------------------------
  const waPayload = {
    sourceApp: 'WhatsApp',
    notificationId: 'wa_msg_8819',
    title: '+1 555-0199',
    text: 'Urgent action required: https://paypal.account-verify-login.secure-portal.example/update',
  };

  await processNotificationEvent(waPayload);

  const historyAfterWa = getHistory();
  assert(historyAfterWa.length === 2, 'Test 20a: WhatsApp notification link saved to History (total 2 records)');
  assert(historyAfterWa[0].riskLevel === 'HIGH', 'Test 20b: Malicious WhatsApp link evaluated as HIGH risk');
  assert(historyAfterWa[0].source === 'Notification', 'Test 20c: History record source is "Notification"');

  // -----------------------------------------------------------------
  // 21. Privacy Verification on Persisted History
  // -----------------------------------------------------------------
  console.log('\n--- Privacy Verification in Persistent Storage ---');
  const rawHistoryStorage = globalThis.localStorage.getItem('linkguard_scan_history') || '';

  // Confirm NO message text, phone numbers, or channel names leaked into history records
  const leaksText =
    rawHistoryStorage.includes('Please review documentation') ||
    rawHistoryStorage.includes('before the standup') ||
    rawHistoryStorage.includes('Project Channel') ||
    rawHistoryStorage.includes('+1 555-0199') ||
    rawHistoryStorage.includes('Urgent action required');

  assert(leaksText === false, 'Test 21a: No message bodies, titles, or sender info persisted in localStorage history');

  for (const item of historyAfterWa) {
    assert(item.body === undefined && item.text === undefined && item.title === undefined,
      `Test 21b: Record ${item.id} has no body/text/title property`);
  }

  // -----------------------------------------------------------------
  // 22. In-place Updated Notification Handling
  // -----------------------------------------------------------------
  console.log('\n--- In-place Notification Update Detection ---');
  const updatePayload = {
    sourceApp: 'WhatsApp',
    notificationId: 'wa_msg_8819', // Same notification ID updated in place
    text: 'Follow-up link: https://whatsapp-call.example/room-alpha',
    title: '+1 555-0199',
  };

  await processNotificationEvent(updatePayload);
  const historyAfterUpdate = getHistory();
  assert(
    historyAfterUpdate.length === 3,
    'Test 22: Updated notification with new URL produces a distinct new history record',
    `Expected 3 records, got ${historyAfterUpdate.length}`
  );

  console.log('\n====================================================');
  console.log(` TEST SUMMARY: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

await runTests();
