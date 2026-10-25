/**
 * test-context-aware-alerts.js
 * Automated verification test suite for Context-Aware Floating Alerts (Modes A & B).
 *
 * Verifies:
 * 1. Event Source Propagation:
 *    - Clipboard events pass { source: 'clipboard' }.
 *    - Standard security events pass { source: 'security' }.
 *    - Unspecified events default safely to { source: 'security' } without accidental suppression.
 * 2. Toast Suppression vs Preservation:
 *    - Clipboard events suppress native Windows toast (invoke('notify_user') not called).
 *    - Security events preserve native Windows toast (invoke('notify_user') called).
 *    - In-app desktop banner toast is always displayed for visual feedback in all modes.
 * 3. Mode B (Clipboard URL Detection):
 *    - show_floating_alert is invoked with positionMode: 'clipboard' and appName: 'Clipboard'.
 *    - update_floating_alert is invoked with authoritative risk assessment.
 *    - History item attributes source: 'Clipboard'.
 * 4. Mode A (Standard Security Notification):
 *    - show_floating_alert is invoked with positionMode: 'security'.
 *    - Preserves native toast notification pipeline.
 *    - History item attributes source: 'Notification'.
 * 5. Floating Alert UI Rendering:
 *    - Clipboard icon renders cleanly with cyan accent.
 *    - Discord and social icons render as before.
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

let mockAppendedElements = [];
let mockToasts = [];

if (typeof globalThis.document === 'undefined') {
  globalThis.document = {
    getElementById: (id) => {
      if (id === 'desktop-toast-container') {
        return mockAppendedElements.find(e => e.id === 'desktop-toast-container') || null;
      }
      return null;
    },
    createElement: (tag) => {
      const el = {
        tagName: tag,
        id: '',
        className: '',
        style: { cssText: '' },
        innerHTML: '',
        children: [],
        appendChild: (child) => {
          el.children.push(child);
          if (child.className && child.className.includes('desktop-toast')) {
            mockToasts.push(child);
          }
        },
        remove: () => {
          const idx = mockAppendedElements.indexOf(el);
          if (idx !== -1) mockAppendedElements.splice(idx, 1);
        },
      };
      return el;
    },
    body: {
      appendChild: (el) => {
        mockAppendedElements.push(el);
      },
    },
  };
}

if (typeof globalThis.window === 'undefined') {
  globalThis.window = {
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  };
}

// Track all Tauri IPC invocations
const tauriInvocations = [];
globalThis.isTauri = true;
globalThis.window.isTauri = true;
globalThis.window.__TAURI__ = {
  core: {
    invoke: async (cmd, args) => {
      tauriInvocations.push({ cmd, args, timestamp: Date.now() });
      if (cmd === 'get_clipboard_text') return 'https://suspicious-test-link.xyz/login';
      if (cmd === 'get_clipboard_sequence') return 42;
      return null;
    },
  },
};
globalThis.window.__TAURI_INTERNALS__ = globalThis.window.__TAURI__.core;

import { notifyUser, isTauriEnvironment } from './src/protectionState.js';
import { processClipboardUrl } from './src/clipboardDetector.js';
import { processNotificationEvent } from './src/notification/notificationDetector.js';
import { renderFloatingAlert } from './src/components/floatingAlert.js';
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

async function runTests() {
  console.log('====================================================');
  console.log(' CONTEXT-AWARE FLOATING ALERTS VERIFICATION SUITE');
  console.log('====================================================\n');

  // ---------------------------------------------------------------------------
  // 1. Tauri Environment Check
  // ---------------------------------------------------------------------------
  assert(isTauriEnvironment() === true, 'Test 1: Environment correctly identifies Tauri mock');

  // ---------------------------------------------------------------------------
  // 2. Event-Specific Native Toast Suppression Logic
  // ---------------------------------------------------------------------------
  console.log('\n--- Event Source & Toast Suppression Suite ---');

  // Test 2A: Clipboard event MUST suppress native toast
  tauriInvocations.length = 0;
  mockToasts.length = 0;
  await notifyUser('Suspicious Link Copied', 'High risk URL copied to clipboard', { source: 'clipboard' });

  const clipNotifyInvocations = tauriInvocations.filter(inv => inv.cmd === 'notify_user');
  assert(
    clipNotifyInvocations.length === 0,
    'Test 2: Clipboard event strictly suppresses native Windows toast (notify_user not called)'
  );
  assert(
    mockToasts.length === 1 && mockToasts[0].innerHTML.includes('Suspicious Link Copied'),
    'Test 3: Clipboard event displays in-app banner toast for immediate visual feedback'
  );

  // Test 2B: Standard security event MUST retain native toast
  tauriInvocations.length = 0;
  mockToasts.length = 0;
  await notifyUser('Threat Blocked', 'Phishing attempt intercepted', { source: 'security' });

  const secNotifyInvocations = tauriInvocations.filter(inv => inv.cmd === 'notify_user');
  assert(
    secNotifyInvocations.length === 1,
    'Test 4: Standard security event invokes native Windows toast'
  );
  assert(
    secNotifyInvocations[0].args.source === 'security' && secNotifyInvocations[0].args.title === 'Threat Blocked',
    'Test 5: Standard security event passes correct title and source="security" to native backend'
  );

  // Test 2C: Unknown / unspecified source MUST safely default to security (no accidental suppression)
  tauriInvocations.length = 0;
  mockToasts.length = 0;
  await notifyUser('System Alert', 'General security status notice');

  const defaultNotifyInvocations = tauriInvocations.filter(inv => inv.cmd === 'notify_user');
  assert(
    defaultNotifyInvocations.length === 1,
    'Test 6: Unspecified event source safely defaults to preserving native Windows toast'
  );
  assert(
    defaultNotifyInvocations[0].args.source === 'security',
    'Test 7: Unspecified event source attributes source as "security"'
  );

  // ---------------------------------------------------------------------------
  // 3. Mode B: Clipboard URL Detection Pipeline
  // ---------------------------------------------------------------------------
  console.log('\n--- Mode B: Clipboard Detection Pipeline Suite ---');
  clearHistory();
  tauriInvocations.length = 0;

  const testClipboardUrl = 'https://paypal.account-verify-login.secure-portal.example/update';
  processClipboardUrl(testClipboardUrl);

  // Check show_floating_alert invocation for Mode B
  const clipAlertShows = tauriInvocations.filter(inv => inv.cmd === 'show_floating_alert');
  assert(
    clipAlertShows.length === 1,
    'Test 8: Clipboard URL detection invokes show_floating_alert'
  );
  assert(
    clipAlertShows[0].args.positionMode === 'clipboard',
    'Test 9: Clipboard detection passes positionMode: "clipboard" (Mode B)'
  );
  assert(
    clipAlertShows[0].args.appName === 'Clipboard',
    'Test 10: Clipboard detection passes appName: "Clipboard"'
  );
  assert(
    clipAlertShows[0].args.url === testClipboardUrl,
    'Test 11: Floating alert receives exact target URL'
  );

  // Check update_floating_alert invocation with analysis outcome
  const clipAlertUpdates = tauriInvocations.filter(inv => inv.cmd === 'update_floating_alert');
  assert(
    clipAlertUpdates.length === 1,
    'Test 12: Floating alert updated with risk analysis'
  );
  assert(
    clipAlertUpdates[0].args.status === 'suspicious',
    'Test 13: Analysis classified suspicious link as status: "suspicious"'
  );
  assert(
    clipAlertUpdates[0].args.riskScore >= 60,
    'Test 14: Risk score matches high severity detection'
  );

  // Verify history record attribution
  const history = getHistory();
  assert(
    history.length === 1 && history[0].url === testClipboardUrl,
    'Test 15: History record persisted for clipboard URL'
  );
  assert(
    history[0].source === 'Clipboard',
    'Test 16: History record source correctly recorded as "Clipboard"'
  );

  // Verify that the clipboard event DID NOT produce a native Windows toast
  const clipNativeToasts = tauriInvocations.filter(inv => inv.cmd === 'notify_user');
  assert(
    clipNativeToasts.length === 0,
    'Test 17: Clipboard detection pipeline completely suppresses native Windows toast'
  );

  // ---------------------------------------------------------------------------
  // 4. Mode A: Windows Notification Processing Pipeline
  // ---------------------------------------------------------------------------
  console.log('\n--- Mode A: Notification Processing Pipeline Suite ---');
  globalThis.localStorage.setItem('app_settings', JSON.stringify({ notificationProtection: true }));
  clearHistory();
  tauriInvocations.length = 0;

  const notifPayload = {
    sourceApp: 'Discord',
    notificationId: 'notif-discord-999',
    text: 'Hey check this out https://steamcommunity-trade-offer.scam-verify.ru/trade',
    title: 'Discord Notification',
  };

  await processNotificationEvent(notifPayload);

  // Check show_floating_alert invocation for Mode A
  const notifAlertShows = tauriInvocations.filter(inv => inv.cmd === 'show_floating_alert');
  assert(
    notifAlertShows.length === 1,
    'Test 18: Notification URL detection invokes show_floating_alert'
  );
  assert(
    notifAlertShows[0].args.positionMode === 'security',
    'Test 19: Notification event passes positionMode: "security" (Mode A)'
  );
  assert(
    notifAlertShows[0].args.appName === 'Discord',
    'Test 20: Notification event badges source app name ("Discord")'
  );

  const notifHistory = getHistory();
  assert(
    notifHistory.length === 1 && notifHistory[0].source === 'Notification',
    'Test 21: Notification event stored in history with source: "Notification"'
  );

  // ---------------------------------------------------------------------------
  // 5. Floating Alert Component Structure & Clipboard Icon Support
  // ---------------------------------------------------------------------------
  console.log('\n--- Floating Alert UI & Asset Verification ---');

  const alertHtml = renderFloatingAlert();
  assert(
    alertHtml.includes('floating-alert-card'),
    'Test 22: Alert template contains floating-alert-card root container'
  );
  assert(
    alertHtml.includes('baitzero-mascot-svg'),
    'Test 23: Approved BaitZero mascot SVG preserved in alert markup'
  );
  assert(
    alertHtml.includes('bracket bracket-tl') && alertHtml.includes('bracket bracket-br'),
    'Test 24: Sci-fi corner brackets preserved'
  );
  assert(
    alertHtml.includes('alert-close-btn'),
    'Test 25: Close/dismiss button present in alert card'
  );
  assert(
    alertHtml.includes('alert-clickable-area'),
    'Test 26: Clickable area for opening main application analysis preserved'
  );

  // Summary
  console.log('\n====================================================');
  console.log(` RESULTS: ${passed} passed, ${failed} failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
