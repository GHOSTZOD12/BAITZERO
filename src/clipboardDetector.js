/**
 * clipboardDetector.js
 * Lightweight, privacy-focused Windows clipboard URL detection (Phase 3B-1).
 *
 * Responsibilities:
 * 1. Monitors clipboard changes while authoritative protection state is ACTIVE.
 * 2. Strictly filters for single valid URLs; completely ignores passwords, normal text,
 *    messages, images, and non-text data.
 * 3. Never retains or logs arbitrary clipboard text.
 * 4. Deduplicates scans to avoid repeated analysis and notification spam.
 * 5. Passes recognized URLs through the existing heuristic analysis pipeline:
 *      urlAnalyzer -> evidenceEngine -> riskEngine -> explanationEngine
 * 6. Stores scan results in local investigation history with source: 'Clipboard'.
 * 7. Dispatches desktop notifications for MEDIUM and HIGH risk levels only.
 * 8. Never automatically opens, fetches, or visits the detected URL.
 */

import { parseUrl } from './engines/urlAnalyzer.js';
import { collectEvidence } from './engines/evidenceEngine.js';
import { calculateRisk } from './engines/riskEngine.js';
import { generateExplanation } from './engines/explanationEngine.js';
import { saveHistoryItem } from './storage.js';
import { loadSettings } from './pages/settings.js';
import {
  isProtectionActive,
  onProtectionStateChange,
  notifyUser,
  isTauriEnvironment,
} from './protectionState.js';
import { isTauri, safeInvoke, listenEvent } from './tauriBridge.js';

const CHECK_INTERVAL_MS = 400; // Fast, lightweight 400ms polling interval

let timerId = null;
let lastProcessedUrl = '';
let lastProcessedTimestamp = 0;
let lastSequence = null;
let browserCopyEventSeq = 0;
let isChecking = false;
let unlistenNativeClipboard = null;

function handleBrowserCopyEvent() {
  browserCopyEventSeq++;
}

/**
 * Strictly filters clipboard text for a single valid HTTP/HTTPS URL.
 * Privacy guarantee: completely ignores passwords, normal text, messages,
 * images, file paths, and non-URL data.
 *
 * @param {string} text
 * @returns {string|null} Canonical URL or null if invalid/non-URL
 */
export function extractValidUrl(text) {
  if (!text || typeof text !== 'string') return null;
  const trimmed = text.trim();

  // Must not be empty, must not contain newlines (discards messages/multiline lists/passwords)
  if (!trimmed || trimmed.includes('\n') || trimmed.includes('\r')) {
    return null;
  }

  // Strictly filter out normal sentences or text with spaces
  if (/\s/.test(trimmed)) {
    return null;
  }

  // Must start with http:// or https:// (strict scheme check for clipboard detection)
  if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }

  const parseResult = parseUrl(trimmed);
  if (!parseResult.success) {
    return null;
  }

  // Security check: reject URLs with embedded credentials (e.g. https://user:pass@example.com)
  try {
    const urlObj = new URL(trimmed);
    if (urlObj.username || urlObj.password) {
      return null;
    }
  } catch (_) {
    return null;
  }

  const { protocol, hostname } = parseResult.data;
  if (!['http:', 'https:'].includes(protocol)) {
    return null;
  }

  // Must have a valid destination hostname (not blank or single word unless localhost)
  // Supports localhost, domain names with dots, IPv4 literals, and IPv6 bracketed literals
  const isIPv4Like = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIPv6Like = hostname.startsWith('[');
  if (!hostname || (hostname !== 'localhost' && !hostname.includes('.') && !isIPv4Like && !isIPv6Like)) {
    return null;
  }

  return parseResult.data.href;
}

/**
 * Read text and sequence number from system clipboard via Tauri IPC or browser clipboard API.
 * @returns {Promise<{ text: string|null, sequence: number|null }>}
 */
export async function readClipboardData() {
  let text = null;
  let sequence = null;

  if (isTauri()) {
    try {
      const [rawText, rawSeq] = await Promise.all([
        safeInvoke('get_clipboard_text'),
        safeInvoke('get_clipboard_sequence'),
      ]);
      if (typeof rawText === 'string') text = rawText;
      if (typeof rawSeq === 'number') sequence = rawSeq;
      return { text, sequence };
    } catch (_) {}
  }

  if (typeof navigator !== 'undefined' && navigator.clipboard?.readText) {
    try {
      text = await navigator.clipboard.readText();
      sequence = browserCopyEventSeq;
      return { text, sequence };
    } catch (_) {}
  }

  return { text: null, sequence: null };
}

/**
 * Read text from system clipboard via Tauri IPC or browser clipboard API.
 * @returns {Promise<string|null>}
 */
export async function readClipboardText() {
  const data = await readClipboardData();
  return data.text;
}

/**
 * Process a validated clipboard URL through the authoritative heuristic analysis pipeline.
 *
 * @param {string} url
 * @param {number} [tDetected=null]
 */
export function processClipboardUrl(url, tDetected = null) {
  console.warn(`[UI-DIAG] Trace: URL extraction & validation successful`);
  const parseResult = parseUrl(url);
  if (!parseResult.success) {
    console.warn(`[UI-DIAG] Trace: URL parsing failed`);
    return;
  }

  const urlData = parseResult.data;
  const settings = loadSettings();

  // Mode B: Trigger compact floating alert at bottom-right of active display, just above taskbar
  if (isTauri()) {
    safeInvoke('show_floating_alert', {
      appName: 'Clipboard',
      url: urlData.href,
      positionMode: 'clipboard',
    }).catch((err) => console.warn('[ClipboardDetector] show_floating_alert warning:', err));
  }

  console.warn(`[UI-DIAG] Trace: Running heuristic analysis pipeline`);
  // Run through existing authoritative engines
  const evidenceList = collectEvidence(urlData, {
    deepInvestigation: settings.deepInvestigation,
  });
  const riskResult = calculateRisk(evidenceList);
  const { explanation, recommendation } = generateExplanation(evidenceList, riskResult);

  console.warn(`[UI-DIAG] Trace: Analysis complete | riskLevel=${riskResult.level} | score=${riskResult.score} | flags=${evidenceList.length}`);

  // Mode B: Update floating alert with authoritative risk analysis result
  if (isTauri()) {
    let alertStatus = 'safe';
    let alertTitle = 'No known threats';
    let alertMessage = 'No risk indicators found by standard checks.';
    if (riskResult.level === 'HIGH' || riskResult.level === 'MEDIUM') {
      alertStatus = 'suspicious';
      alertTitle = 'Suspicious link detected';
      const topEvidence = evidenceList[0]?.title || 'Multiple risk indicators detected';
      alertMessage = `${riskResult.level} RISK — ${topEvidence}`;
    }
    safeInvoke('update_floating_alert', {
      url: urlData.href,
      status: alertStatus,
      title: alertTitle,
      message: alertMessage,
      riskScore: riskResult.score,
      evidence: evidenceList.map(e => e.title),
    }).catch((err) => console.warn('[ClipboardDetector] update_floating_alert warning:', err));
  }

  // Save to history with source: 'Clipboard'
  console.warn(`[UI-DIAG] Trace: Persisting scan to history`);
  saveHistoryItem({
    url: urlData.href,
    urlData,
    riskResult,
    evidenceList,
    explanation,
    recommendation,
    source: 'Clipboard',
  });

  // Mode B: Explicitly attribute event to 'clipboard'.
  // Suppresses native Windows toast while maintaining in-app notifications and assertions.
  console.warn(`[UI-DIAG] Trace: Dispatching desktop notification (clipboard source) | riskLevel=${riskResult.level}`);
  if (riskResult.level === 'HIGH') {
    notifyUser(
      'Suspicious Link Detected',
      'HIGH RISK — Suspicious indicators detected in copied link.',
      { source: 'clipboard' }
    );
  } else if (riskResult.level === 'MEDIUM') {
    notifyUser(
      'Suspicious Link Detected',
      'MEDIUM RISK — Some suspicious indicators detected in copied link.',
      { source: 'clipboard' }
    );
  }
}

/**
 * Handle a detected clipboard text string.
 * Distinguishes between preventing duplicate processing of the same clipboard event
 * during idle polling and allowing intentional copy events of identical URLs.
 *
 * @param {string} raw
 * @param {object} [options={}]
 * @param {number} [options.sequence]
 * @param {boolean} [options.isNewEvent=false]
 */
export function handleClipboardUpdate(raw, options = {}) {
  if (!raw || typeof raw !== 'string') return;

  // Strict URL validation & privacy filter
  const validUrl = extractValidUrl(raw);
  if (!validUrl) {
    // Rejected content: advance sequence tracking if provided to prevent reprocessing cycles,
    // but never retain raw text in module state.
    if (options.sequence !== undefined && options.sequence !== null) {
      lastSequence = options.sequence;
    }
    return;
  }

  const { sequence, isNewEvent = false } = options;
  const hasSeq = sequence !== undefined && sequence !== null && sequence !== 0;
  const isDistinctEvent = isNewEvent || (hasSeq && sequence !== lastSequence);

  // Deduplication: If this is NOT a distinct new copy event and the validated URL
  // is unchanged from our last processed URL, skip idle polling tick.
  if (!isDistinctEvent && validUrl === lastProcessedUrl) {
    return;
  }

  // Update tracking state (storing only validated URL and sequence)
  if (hasSeq) {
    lastSequence = sequence;
  }
  lastProcessedUrl = validUrl;
  lastProcessedTimestamp = Date.now();

  console.warn(`[UI-DIAG] Clipboard URL detected | distinctEvent=${Boolean(isDistinctEvent)} | hasSeq=${hasSeq}`);

  // Process through the existing local analysis pipeline
  const tDetected = performance.now();
  processClipboardUrl(validUrl, tDetected);
}

/**
 * Setup Tauri native background clipboard event listener.
 * Wakes up and processes clipboard changes even when window is minimized.
 */
async function setupNativeClipboardListener() {
  if (unlistenNativeClipboard) return;
  if (isTauri()) {
    try {
      unlistenNativeClipboard = await listenEvent('clipboard-updated', (event) => {
        if (!isProtectionActive()) return;
        const settings = loadSettings();
        if (settings.clipboardProtection === false) return;

        const payload = event.payload;
        const raw = (typeof payload === 'object' && payload !== null) ? payload.text : payload;
        const seq = (typeof payload === 'object' && payload !== null) ? payload.sequence : undefined;
        if (typeof raw === 'string') {
          // Defense in depth: validate before processing
          const valid = extractValidUrl(raw);
          if (valid) {
            handleClipboardUpdate(valid, { sequence: seq, isNewEvent: true });
          }
        }
      });
    } catch (err) {
      console.warn('[ClipboardDetector] Native clipboard listener error:', err);
    }
  }
}

/**
 * Single periodic tick of the clipboard detector.
 */
export async function checkClipboard() {
  if (isChecking) return;
  if (!isProtectionActive()) return;

  const settings = loadSettings();
  if (settings.clipboardProtection === false) return;

  isChecking = true;

  try {
    const { text: raw, sequence: seq } = await readClipboardData();

    // If no text or empty, nothing to do
    if (!raw || typeof raw !== 'string') {
      return;
    }

    const validUrl = extractValidUrl(raw);
    const hasSeq = seq !== null && seq !== undefined && seq !== 0;

    if (!validUrl) {
      // Discard rejected content completely; advance sequence tracking if present to prevent looping
      if (hasSeq) {
        lastSequence = seq;
      }
      return;
    }

    const isSameSeq = hasSeq && (seq === lastSequence);
    const isSameUrl = (validUrl === lastProcessedUrl);

    // If sequence is available and unchanged, and URL is unchanged: skip idle polling tick
    if (hasSeq && isSameSeq && isSameUrl) {
      return;
    }

    // If sequence is not available and URL is unchanged: skip idle polling tick
    if (!hasSeq && isSameUrl) {
      return;
    }

    const isNewEvent = hasSeq ? (seq !== lastSequence) : false;
    handleClipboardUpdate(validUrl, { sequence: seq, isNewEvent });
  } catch (_) {
    // Fail safely without throwing
  } finally {
    isChecking = false;
  }
}

/**
 * Start clipboard monitoring if protection is ACTIVE.
 */
export async function startClipboardMonitoring() {
  if (timerId !== null) return;

  // Listen to native Windows background events from Tauri
  setupNativeClipboardListener();

  // Listen to browser copy events
  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('copy', handleBrowserCopyEvent);
  }

  // Seed current clipboard state so pre-existing content is not re-analyzed immediately
  try {
    const { text: initialRaw, sequence: initialSeq } = await readClipboardData();
    if (initialSeq !== undefined && initialSeq !== null) {
      lastSequence = initialSeq;
    }
    if (initialRaw && typeof initialRaw === 'string') {
      const initialUrl = extractValidUrl(initialRaw);
      if (initialUrl) {
        lastProcessedUrl = initialUrl;
        lastProcessedTimestamp = Date.now();
      }
    }
  } catch (_) {}

  timerId = setInterval(() => {
    if (isProtectionActive()) {
      checkClipboard();
    }
  }, CHECK_INTERVAL_MS);
}

/**
 * Stop clipboard monitoring (e.g. when protection is PAUSED).
 */
export function stopClipboardMonitoring() {
  if (timerId !== null) {
    clearInterval(timerId);
    timerId = null;
  }
  if (typeof unlistenNativeClipboard === 'function') {
    unlistenNativeClipboard();
    unlistenNativeClipboard = null;
  }
  if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
    window.removeEventListener('copy', handleBrowserCopyEvent);
  }
  isChecking = false;
}

/**
 * Reset detector in-memory deduplication state (useful for tests).
 */
export function resetClipboardDetectorState() {
  lastProcessedUrl = '';
  lastProcessedTimestamp = 0;
  lastSequence = null;
  browserCopyEventSeq = 0;
  isChecking = false;
}

/**
 * Inspect detector internal state (useful for tests and diagnostics).
 */
export function getClipboardDetectorState() {
  return {
    lastRawClipboard: '',
    lastProcessedUrl,
    lastProcessedTimestamp,
    lastSequence,
    browserCopyEventSeq,
    isChecking,
  };
}

/**
 * Initialize clipboard monitoring and bind to authoritative protection state.
 */
export function initClipboardDetector() {
  // Listen to single authoritative protection state changes
  onProtectionStateChange((state, active) => {
    if (active) {
      startClipboardMonitoring();
    } else {
      stopClipboardMonitoring();
    }
  });

  // Start immediately if protection is already active
  if (isProtectionActive()) {
    startClipboardMonitoring();
  }
}
