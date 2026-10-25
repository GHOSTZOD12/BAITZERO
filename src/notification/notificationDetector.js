/**
 * notificationDetector.js
 * Phase 3B-3: Windows Notification Link Detection & Analysis Coordinator
 *
 * Responsibilities:
 * 1. Coordinates with the Windows notification listener layer (via Tauri IPC).
 * 2. Extracts URLs from raw notification text using notificationUrlExtractor.
 * 3. Enforces strict privacy guarantees:
 *    - Never stores, logs, or persists notification message bodies or titles.
 *    - Discards raw notification text immediately after URL extraction.
 *    - Passes ONLY extracted URLs into the analysis pipeline.
 * 4. Loop Prevention & Deduplication:
 *    - Ignores our own application notifications to prevent infinite warning loops.
 *    - Bounded in-memory TTL cache prevents duplicate scans for repeat notifications.
 * 5. Respects Authoritative Protection State:
 *    - Only processes notifications when protection state is ACTIVE.
 *    - Paused protection short-circuits evaluation without analysis.
 * 6. Invokes the single authoritative analysis pipeline:
 *    - urlAnalyzer -> evidenceEngine -> riskEngine -> explanationEngine
 * 7. Dispatches safe Windows notifications for MEDIUM and HIGH risks only.
 * 8. Records scans in local history with source: 'Notification'.
 */

import { extractNotificationUrls } from './notificationUrlExtractor.js';
import { parseUrl } from '../engines/urlAnalyzer.js';
import { collectEvidence } from '../engines/evidenceEngine.js';
import { calculateRisk } from '../engines/riskEngine.js';
import { generateExplanation } from '../engines/explanationEngine.js';
import { saveHistoryItem } from '../storage.js';
import { loadSettings } from '../pages/settings.js';
import {
  isProtectionActive,
  onProtectionStateChange,
  notifyUser,
  isTauriEnvironment,
} from '../protectionState.js';
import { isTauri, invokeCommand, listenEvent } from '../tauriBridge.js';

// ---------------------------------------------------------------------------
// Configuration & Constants
// ---------------------------------------------------------------------------

const DEDUPE_CACHE_TTL_MS = 60000; // 60-second cooldown per (source, id, url)
const MAX_CACHE_ENTRIES = 100;     // Strictly bounded memory limit

// Application identifiers to detect our own notifications and prevent loops
const OWN_APP_IDS = [
  'com.security.linkprotection',
  'link-protection-system',
  'link protection system',
];

const OWN_NOTIFICATION_TITLES = [
  'suspicious link detected',
  'protection active',
  'protection paused',
  'link protection',
];

// ---------------------------------------------------------------------------
// In-Memory State
// ---------------------------------------------------------------------------

/**
 * Bounded deduplication cache: Map<cacheKey, timestamp>
 */
const dedupeCache = new Map();

/**
 * Timestamps of our own recently generated warnings to prevent self-triggering
 */
const recentOwnNotificationTimestamps = new Set();

let isMonitoring = false;
let isStarting = false;
let unlistenTauriEvent = null;


// ---------------------------------------------------------------------------
// Tauri IPC Helpers
// ---------------------------------------------------------------------------

async function invokeTauri(cmd, args = {}, _diagContext = null, throwOnError = false) {
  if (!isTauri()) {
    if (throwOnError) throw new Error('Not running inside Tauri desktop shell.');
    return null;
  }
  const ipcStart = performance.now();
  try {
    const result = await invokeCommand(cmd, args);
    const ipcElapsed = performance.now() - ipcStart;
    // [DIAG] Measure Tauri IPC round-trip for every command
    if (_diagContext) {
      console.warn(`[TIMING][NotifDetector] Tauri IPC '${cmd}' round-trip: ${ipcElapsed.toFixed(2)} ms (pipeline elapsed: ${(performance.now() - _diagContext.t0).toFixed(2)} ms)`);
    } else {
      console.warn(`[TIMING][NotifDetector] Tauri IPC '${cmd}' round-trip: ${ipcElapsed.toFixed(2)} ms`);
    }
    return result;
  } catch (err) {
    const ipcElapsed = performance.now() - ipcStart;
    console.warn(`[TIMING][NotifDetector] Tauri IPC '${cmd}' FAILED after ${ipcElapsed.toFixed(2)} ms:`, err?.message || err);
    console.debug('[NotificationDetector] IPC error:', cmd, err?.message || err);
    if (throwOnError) {
      throw err;
    }
  }
  return null;
}

/**
 * Returns current in-memory monitoring active status.
 * @returns {boolean}
 */
export function getIsMonitoring() {
  return isMonitoring;
}

// ---------------------------------------------------------------------------
// Loop & Deduplication Guards
// ---------------------------------------------------------------------------

/**
 * Format raw source application identifier into a clean UI badge label.
 *
 * @param {string} appStr
 * @returns {string}
 */
export function formatAppBadgeName(appStr) {
  if (!appStr) return 'Social';
  const norm = appStr.toLowerCase();
  if (norm.includes('discord')) return 'Discord';
  if (norm.includes('slack')) return 'Slack';
  if (norm.includes('telegram')) return 'Telegram';
  if (norm.includes('whatsapp')) return 'WhatsApp';
  if (norm.includes('teams')) return 'Teams';
  if (norm.includes('chrome')) return 'Chrome';
  if (norm.includes('edge')) return 'Edge';
  if (norm.includes('twitter') || norm.includes(' x ')) return 'X';
  const cleaned = appStr.replace(/^(com|org|net)\.[^.]+\./i, '').replace(/\.exe$/i, '').trim();
  return cleaned ? cleaned.charAt(0).toUpperCase() + cleaned.slice(1) : 'Social';
}

/**
 * Checks if a notification originated from our own application.
 *
 * @param {object} notification
 * @returns {boolean}
 */
export function isOwnNotification(notification) {
  if (!notification) return false;

  const sourceApp = (notification.sourceApp || notification.appId || '').toLowerCase();
  for (const ownId of OWN_APP_IDS) {
    if (sourceApp.includes(ownId)) return true;
  }

  const title = (notification.title || '').toLowerCase();
  for (const ownTitle of OWN_NOTIFICATION_TITLES) {
    if (title.includes(ownTitle)) return true;
  }

  return false;
}

/**
 * Bounded cache check to prevent repeated analysis of the same notification URL.
 *
 * @param {string} sourceApp
 * @param {string} notificationId
 * @param {string} url
 * @returns {boolean} true if recently processed (duplicate)
 */
export function isDuplicateNotification(sourceApp, notificationId, url) {
  const now = Date.now();
  const key = `${sourceApp || 'unknown'}:${notificationId || ''}:${url}`;

  // Purge expired entries
  if (dedupeCache.size > MAX_CACHE_ENTRIES / 2) {
    for (const [k, ts] of dedupeCache.entries()) {
      if (now - ts > DEDUPE_CACHE_TTL_MS) {
        dedupeCache.delete(k);
      }
    }
  }

  if (dedupeCache.has(key)) {
    const timestamp = dedupeCache.get(key);
    if (now - timestamp < DEDUPE_CACHE_TTL_MS) {
      return true;
    }
  }

  // Cache new entry
  dedupeCache.set(key, now);

  // Evict oldest if exceeding max entries
  if (dedupeCache.size > MAX_CACHE_ENTRIES) {
    const oldestKey = dedupeCache.keys().next().value;
    dedupeCache.delete(oldestKey);
  }

  return false;
}

// ---------------------------------------------------------------------------
// Core Notification Processing Pipeline
// ---------------------------------------------------------------------------

/**
 * Formats URL metadata safely for diagnostic logs, strictly omitting
 * query strings, tokens, credentials, and fragments (BZ-PRIV-02).
 *
 * @param {string} rawUrl
 * @returns {string} Safe log identifier
 */
function formatUrlForDiagLog(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (_) {
      if (!rawUrl.includes('://')) {
        parsed = new URL('https://' + rawUrl);
      } else {
        return `url_len=${rawUrl.length}`;
      }
    }
    const host = parsed.hostname || 'unknown-host';
    const path = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname : '';
    return `host=${host}${path ? ` path=${path}` : ''} len=${rawUrl.length}`;
  } catch (_) {
    return `url_len=${rawUrl.length}`;
  }
}

/**
 * Helper to produce uniform, clearly identifiable timing diagnostic logs.
 * Measures timestamps, per-stage elapsed time, and total elapsed time.
 * Strictly adheres to privacy: NEVER logs raw message contents, passwords,
 * personal text, query parameters, or credentials (BZ-PRIV-02).
 */
function logTiming(stageNum, stageName, tNow, tPrev, t0, { sourceApp, notificationId, url = null, extra = null } = {}) {
  const timestamp = new Date().toISOString();
  const elapsedPrev = (tNow - tPrev).toFixed(2);
  const totalElapsed = (tNow - t0).toFixed(2);
  const app = sourceApp || 'unknown';
  const notifId = notificationId || 'none';
  let line = `[TIMING] Stage ${stageNum}: ${stageName} | timestamp=${timestamp} | elapsed_prev=+${elapsedPrev}ms | total=+${totalElapsed}ms | app=${app} | notif_id=${notifId}`;
  if (url) {
    const meta = formatUrlForDiagLog(url);
    if (meta) {
      line += ` | ${meta}`;
    }
  }
  if (extra) {
    line += ` | ${extra}`;
  }
  console.warn(line);
}

/**
 * Processes a raw incoming Windows notification event.
 *
 * PRIVACY GUARANTEE:
 * - Only URLs are extracted.
 * - Raw notification text and message body are NOT persisted or logged.
 * - Surrounding text is discarded from memory immediately after URL extraction.
 *
 * @param {object} notification - { sourceApp, notificationId, text, title }
 * @param {number|null} [initialTimestamp=null] - Optional performance.now() captured at event reception
 * @returns {Promise<Array<object>>} Analysis results for extracted URLs
 */
export async function processNotificationEvent(notification, initialTimestamp = null) {
  if (!notification) return [];

  // ─── STAGE 1: Windows notification received ────────────────────────────────
  const t0 = initialTimestamp || performance.now();
  let tPrev = t0;
  const sourceApp = notification.sourceApp || notification.appId || 'unknown';
  const notificationId = notification.notificationId || notification.id || 'none';

  logTiming(1, 'Windows notification received', t0, tPrev, t0, {
    sourceApp,
    notificationId,
    extra: `fields=[${Object.keys(notification).join(',')}] has_text=${Boolean(notification.text)} has_body=${Boolean(notification.body)} has_title=${Boolean(notification.title)}`,
  });

  // 1. Authoritative protection state check
  if (!isProtectionActive()) {
    console.debug('[NotificationDetector] Ignored: Protection is PAUSED.');
    const tEnd = performance.now();
    logTiming(10, 'Notification pipeline completely finished (Protection PAUSED)', tEnd, tPrev, t0, {
      sourceApp,
      notificationId,
      extra: 'early_exit=protection_paused',
    });
    return [];
  }

  // 2. Setting toggle check
  const settings = loadSettings();
  if (!settings.notificationProtection) {
    const tEnd = performance.now();
    logTiming(10, 'Notification pipeline completely finished (Setting disabled)', tEnd, tPrev, t0, {
      sourceApp,
      notificationId,
      extra: 'early_exit=setting_disabled',
    });
    return [];
  }

  // 3. Self-notification loop prevention
  if (isOwnNotification(notification)) {
    console.debug('[NotificationDetector] Ignored: Own application notification.');
    const tEnd = performance.now();
    logTiming(10, 'Notification pipeline completely finished (Own app ignored)', tEnd, tPrev, t0, {
      sourceApp,
      notificationId,
      extra: 'early_exit=own_app_notification',
    });
    return [];
  }

  // Combine all candidate text fields (text, body, title) to ensure no message field is missed
  const textCandidates = [notification.text, notification.body, notification.title].filter(
    t => typeof t === 'string' && t.trim().length > 0
  );
  const rawText = textCandidates.join('\n');

  if (!rawText) {
    const tEnd = performance.now();
    logTiming(10, 'Notification pipeline completely finished (Empty text)', tEnd, tPrev, t0, {
      sourceApp,
      notificationId,
      extra: 'early_exit=no_text_in_notification',
    });
    return [];
  }

  // ─── STAGE 2: URL extraction started ───────────────────────────────────────
  const t2_start = performance.now();
  logTiming(2, 'URL extraction started', t2_start, tPrev, t0, { sourceApp, notificationId });
  tPrev = t2_start;

  // 4. Extract URLs (Surrounding text is discarded immediately)
  const extractedUrls = extractNotificationUrls(rawText);

  // ─── STAGE 3: URL extraction finished ──────────────────────────────────────
  const t2_end = performance.now();
  logTiming(3, 'URL extraction finished', t2_end, tPrev, t0, {
    sourceApp,
    notificationId,
    extra: `urls_found=${extractedUrls.length}`,
  });
  tPrev = t2_end;

  if (extractedUrls.length === 0) {
    const tEnd = performance.now();
    logTiming(10, 'Notification pipeline completely finished (0 URLs)', tEnd, tPrev, t0, {
      sourceApp,
      notificationId,
      extra: 'urls_found=0',
    });
    return [];
  }

  const results = [];

  for (const url of extractedUrls) {
    // Deduplication check
    const tDedup_start = performance.now();
    const isDupe = isDuplicateNotification(sourceApp, notificationId, url);
    const tDedup_end = performance.now();

    if (isDupe) {
      console.warn(
        `[TIMING] Stage 3b: Duplicate URL skipped | timestamp=${new Date().toISOString()} | elapsed_prev=+${(tDedup_end - tPrev).toFixed(2)}ms | total=+${(tDedup_end - t0).toFixed(2)}ms | app=${sourceApp} | notif_id=${notificationId} | ${formatUrlForDiagLog(url)} | dedupe_check_took=+${(tDedup_end - tDedup_start).toFixed(2)}ms`
      );
      tPrev = tDedup_end;
      continue;
    }
    tPrev = tDedup_end;

    // Trigger compact gaming floating alert promptly on detection (Mode A: Security)
    const formattedApp = formatAppBadgeName(sourceApp);
    await invokeTauri('show_floating_alert', {
      appName: formattedApp,
      url,
      positionMode: 'security',
    });

    // ─── STAGE 4: URL analysis started ───────────────────────────────────────
    const t4_start = performance.now();
    logTiming(4, 'URL analysis started', t4_start, tPrev, t0, { sourceApp, notificationId, url });
    tPrev = t4_start;

    // 6. Existing authoritative URL analysis pipeline
    const parseResult = parseUrl(url);
    if (!parseResult.success) {
      await invokeTauri('update_floating_alert', {
        url,
        status: 'inconclusive',
        title: 'Inconclusive analysis',
        message: 'Could not reach a reliable conclusion.',
        riskScore: null,
        evidence: [],
      });
      continue;
    }

    const urlData = parseResult.data;
    const evidenceList = collectEvidence(urlData, {
      deepInvestigation: settings.deepInvestigation,
    });
    const riskResult = calculateRisk(evidenceList);
    const { explanation, recommendation } = generateExplanation(evidenceList, riskResult);

    // ─── STAGE 5: URL analysis finished ──────────────────────────────────────
    const t4_end = performance.now();
    logTiming(5, 'URL analysis finished', t4_end, tPrev, t0, {
      sourceApp,
      notificationId,
      url,
      extra: `analysis_duration=+${(t4_end - t4_start).toFixed(2)}ms indicators=${evidenceList.length}`,
    });
    tPrev = t4_end;

    // ─── STAGE 6: Risk result produced ───────────────────────────────────────
    const t6 = performance.now();
    logTiming(6, 'Risk result produced', t6, tPrev, t0, {
      sourceApp,
      notificationId,
      url,
      extra: `risk_level=${riskResult.level} risk_score=${riskResult.score} evidence_count=${evidenceList.length}`,
    });
    tPrev = t6;

    // Update the same floating alert window with authoritative analysis outcome
    let alertStatus = 'safe';
    let alertTitle = 'No known threats';
    let alertMessage = 'No risk indicators found by standard checks.';
    if (riskResult.level === 'HIGH' || riskResult.level === 'MEDIUM') {
      alertStatus = 'suspicious';
      alertTitle = 'Suspicious link detected';
      const topEvidence = evidenceList[0]?.title || 'Multiple risk indicators detected';
      alertMessage = `${riskResult.level} RISK — ${topEvidence}`;
    }

    await invokeTauri('update_floating_alert', {
      url,
      status: alertStatus,
      title: alertTitle,
      message: alertMessage,
      riskScore: riskResult.score,
      evidence: evidenceList.map(e => e.title),
    });

    // ─── STAGE 7: History save started ───────────────────────────────────────
    const t7_start = performance.now();
    logTiming(7, 'History save started', t7_start, tPrev, t0, { sourceApp, notificationId, url });
    tPrev = t7_start;

    // 7. Store in history with source 'Notification' (NO message body is stored)
    saveHistoryItem({
      url: urlData.href,
      urlData,
      riskResult,
      evidenceList,
      explanation,
      recommendation,
      source: 'Notification',
    });

    // ─── STAGE 8: History save finished ──────────────────────────────────────
    const t7_end = performance.now();
    logTiming(8, 'History save finished', t7_end, tPrev, t0, {
      sourceApp,
      notificationId,
      url,
      extra: `save_duration=+${(t7_end - t7_start).toFixed(2)}ms`,
    });
    tPrev = t7_end;

    // ─── STAGE 9: In-app notification triggered ──────────────────────────────
    const t9_start = performance.now();

    // 8. The floating alert serves as the single dedicated visual notification for
    // incoming notification links, eliminating the redundant Windows native toast.
    logTiming(9, 'Notification handled by floating alert (native toast omitted to prevent duplication)', t9_start, tPrev, t0, {
      sourceApp,
      notificationId,
      url,
      extra: `level=${riskResult.level} action=floating_alert_active`,
    });

    const t9_end = performance.now();
    tPrev = t9_end;

    results.push({
      url,
      riskLevel: riskResult.level,
      riskScore: riskResult.score,
      evidenceCount: evidenceList.length,
      explanation,
    });
  }

  // ─── STAGE 10: Notification pipeline completely finished ───────────────────
  const t10 = performance.now();
  logTiming(10, 'Notification pipeline completely finished', t10, tPrev, t0, {
    sourceApp,
    notificationId,
    extra: `urls_processed=${results.length} pipeline_total=+${(t10 - t0).toFixed(2)}ms`,
  });

  return results;
}

// ---------------------------------------------------------------------------
// Listener Status & Permission Management
// ---------------------------------------------------------------------------

/**
 * Query current Windows notification listener status.
 *
 * Status values:
 * - 'not_available': OS does not support UserNotificationListener or running in web browser
 * - 'permission_required': UserNotificationListener requires explicit permission / package identity
 * - 'permission_denied': User explicitly denied access in Windows Settings
 * - 'enabled': UserNotificationListener active and authorized
 * - 'error': Native initialization error
 *
 * @returns {Promise<{ status: string, message: string }>}
 */
export async function getListenerStatus() {
  if (!isTauriEnvironment()) {
    return {
      status: 'not_available',
      message: 'Windows notification listener is only available in the native desktop application.',
    };
  }

  try {
    const res = await invokeTauri('get_notification_listener_status');
    if (res && res.status) {
      return res;
    }
  } catch (err) {
    return {
      status: 'error',
      message: err?.message || 'Error checking notification listener status.',
    };
  }

  return {
    status: 'permission_required',
    message: 'Windows notification access has not been granted.',
  };
}

/**
 * Request Windows notification listener permission.
 *
 * @returns {Promise<{ status: string, message: string }>}
 */
export async function requestListenerPermission() {
  if (!isTauriEnvironment()) {
    return {
      status: 'not_available',
      message: 'Windows notification listener is only available in the native desktop application.',
    };
  }

  try {
    const res = await invokeTauri('request_notification_listener_permission');
    if (res && res.status) {
      return res;
    }
  } catch (err) {
    return {
      status: 'error',
      message: err?.message || 'Failed to request notification permission.',
    };
  }

  return {
    status: 'permission_denied',
    message: 'Permission was not granted.',
  };
}

// ---------------------------------------------------------------------------
// Lifecycle Management
// ---------------------------------------------------------------------------

/**
 * Start listening for notification events.
 * Handles startup failures properly by resetting monitoring state so the user can retry.
 *
 * @returns {Promise<{ success: boolean, error?: string, alreadyRunning?: boolean }>}
 */
export async function startNotificationMonitoring() {
  if (isMonitoring) {
    console.warn('[NotificationDetector] Monitoring already active.');
    return { success: true, alreadyRunning: true };
  }

  if (isStarting) {
    console.warn('[NotificationDetector] Monitoring startup already in progress.');
    return { success: false, error: 'Monitoring startup already in progress.' };
  }

  if (!isTauri()) {
    console.warn('[NotificationDetector] Native notification monitoring skipped: not in Tauri desktop environment.');
    return { success: false, error: 'Not running inside Tauri desktop shell.' };
  }

  isStarting = true;
  try {
    if (typeof unlistenTauriEvent === 'function') {
      try { unlistenTauriEvent(); } catch (_) {}
      unlistenTauriEvent = null;
    }

    unlistenTauriEvent = await listenEvent(
      'notification-link-detected',
      event => {
        let payload = event?.payload;
        if (typeof payload === 'string') {
          try { payload = JSON.parse(payload); } catch (_) {}
        }
        if (payload) {
          const tEventReceived = performance.now();
          console.warn(
            `[TIMING][NotifDetector] Tauri 'notification-link-detected' event received | frontend callback entry: ${tEventReceived.toFixed(2)} ms` +
            ` | app=${payload.sourceApp || 'unknown'} | notif_id=${payload.notificationId || payload.id || 'none'} | text_len=${(payload.text || '').length}`
          );
          processNotificationEvent(payload, tEventReceived);
        }
      },
    );

    const diagCtx = { t0: performance.now() };
    await invokeTauri('start_notification_listener', {}, diagCtx, true);

    isMonitoring = true;
    console.warn('[NotificationDetector] Native notification monitoring started successfully.');
    return { success: true };
  } catch (err) {
    // Startup failed: clean up and reset state so the user can retry!
    isMonitoring = false;
    if (typeof unlistenTauriEvent === 'function') {
      try { unlistenTauriEvent(); } catch (_) {}
      unlistenTauriEvent = null;
    }
    const errMsg = err?.message || String(err);
    console.warn('[NotificationDetector] Failed to start native notification listener:', errMsg);
    return { success: false, error: errMsg };
  } finally {
    isStarting = false;
  }
}

/**
 * Stop listening for notification events.
 */
export async function stopNotificationMonitoring() {
  isMonitoring = false;

  if (typeof unlistenTauriEvent === 'function') {
    try { unlistenTauriEvent(); } catch (_) {}
    unlistenTauriEvent = null;
  }

  if (isTauriEnvironment()) {
    try {
      await invokeTauri('stop_notification_listener');
    } catch (err) {
      console.warn('[NotificationDetector] Failed to stop native notification listener:', err?.message || err);
    }
  }
  console.warn('[NotificationDetector] Native notification monitoring stopped.');
}

/**
 * Initialize notification detector.
 * Called once during application startup.
 */
export function initNotificationDetector() {
  const settings = loadSettings();

  // Listen to authoritative protection state changes
  onProtectionStateChange((state, active) => {
    if (!active) {
      // Protection paused: stop processing
      stopNotificationMonitoring();
    } else {
      // Protection resumed: if setting is enabled, start
      const currentSettings = loadSettings();
      if (currentSettings.notificationProtection) {
        startNotificationMonitoring();
      }
    }
  });

  // Start if protection is ACTIVE and setting is ON
  if (isProtectionActive() && settings.notificationProtection) {
    startNotificationMonitoring();
  }
}
