/**
 * extensionBridge.js
 * Phase 3B-2: Desktop ↔ Browser Extension IPC Bridge
 *
 * Responsibilities:
 * 1. Poll the Tauri backend for pending URL analysis requests from the browser extension.
 * 2. Process each URL through the EXISTING analysis pipeline
 *    (urlAnalyzer → evidenceEngine → riskEngine → explanationEngine).
 * 3. Deliver results back to the Tauri backend so the waiting HTTP thread
 *    can respond to the browser extension.
 * 4. Respect the authoritative protection state — only process when ACTIVE.
 * 5. Handle Tauri IPC gracefully; fail silently if Tauri is unavailable.
 *
 * This module does NOT contain any analysis logic. All analysis is performed
 * by the existing engine pipeline, keeping the desktop application the
 * single authoritative security engine.
 */

import { parseUrl }            from './engines/urlAnalyzer.js';
import { collectEvidence }     from './engines/evidenceEngine.js';
import { calculateRisk }       from './engines/riskEngine.js';
import { generateExplanation } from './engines/explanationEngine.js';
import { saveHistoryItem }     from './storage.js';
import { loadSettings }        from './pages/settings.js';
import {
  isProtectionActive,
  onProtectionStateChange,
  notifyUser,
  isTauriEnvironment,
} from './protectionState.js';
import { safeInvoke } from './tauriBridge.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** How often to poll the Tauri backend for pending extension requests (ms). */
const POLL_INTERVAL_MS = 250;

/** Deduplication: don't re-analyze the same URL within this window (ms). */
const DEDUPE_COOLDOWN_MS = 10000;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let pollTimer = null;
let isPolling = false;
const recentUrls = new Map(); // url → timestamp

// ---------------------------------------------------------------------------
// Tauri IPC Helpers
// ---------------------------------------------------------------------------

/**
 * Invoke a Tauri command safely, returning null on any failure.
 */
async function invokeTauri(cmd, args = {}) {
  try {
    return await safeInvoke(cmd, args);
  } catch (err) {
    // Fail silently — the bridge is a background service
    console.debug('[ExtBridge] IPC error:', cmd, err?.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Analysis Pipeline
// ---------------------------------------------------------------------------

/**
 * Process a URL through the FULL existing analysis pipeline.
 * This is the ONLY place where analysis is performed — all engines are reused.
 *
 * @param {string} url - A validated http/https URL
 * @returns {{ riskLevel, riskScore, evidenceCount, explanation, recommendation, evidenceTitles }}
 */
function analyzeUrl(url) {
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
  const settings = loadSettings();

  // Run through existing evidence, risk, and explanation engines
  const evidenceList = collectEvidence(urlData, {
    deepInvestigation: settings.deepInvestigation,
  });
  const riskResult = calculateRisk(evidenceList);
  const { explanation, recommendation } = generateExplanation(evidenceList, riskResult);

  // Save to history with source 'Browser Extension'
  saveHistoryItem({
    url: urlData.href,
    urlData,
    riskResult,
    evidenceList,
    explanation,
    recommendation,
    source: 'Browser Extension',
  });

  // Notify user for MEDIUM/HIGH risk (same threshold as clipboard detector)
  if (riskResult.level === 'HIGH') {
    notifyUser(
      'Suspicious Link Detected',
      'HIGH RISK — Suspicious indicators detected.',
    );
  } else if (riskResult.level === 'MEDIUM') {
    notifyUser(
      'Suspicious Link Detected',
      'MEDIUM RISK — Some suspicious indicators detected.',
    );
  }

  return {
    riskLevel:      riskResult.level,
    riskScore:      riskResult.score,
    evidenceCount:  evidenceList.length,
    explanation,
    recommendation,
    evidenceTitles: evidenceList.map(e => e.title),
  };
}

// ---------------------------------------------------------------------------
// Queue Polling
// ---------------------------------------------------------------------------

/**
 * Single poll cycle: ask the Tauri backend for one pending extension request,
 * run the analysis, and deliver the result.
 */
async function pollOnce() {
  if (isPolling) return;
  if (!isProtectionActive()) return;
  if (!isTauriEnvironment()) return;

  isPolling = true;
  try {
    // Ask the Rust backend for the next pending URL from the extension
    const pending = await invokeTauri('poll_extension_queue');
    if (!pending || !pending.id || !pending.url) {
      return;
    }

    const { id, url } = pending;

    // Deduplication: skip if we analyzed this URL very recently
    const now = Date.now();
    const lastSeen = recentUrls.get(url);
    if (lastSeen && now - lastSeen < DEDUPE_COOLDOWN_MS) {
      // Deliver a cached-equivalent response (re-run is harmless but avoids spam)
      // We still need to deliver SOMETHING so the HTTP thread isn't left hanging.
      // Re-run the analysis (it's cheap and deterministic).
    }
    recentUrls.set(url, now);

    // Clean up old entries from the deduplication map
    if (recentUrls.size > 100) {
      const cutoff = now - DEDUPE_COOLDOWN_MS * 2;
      for (const [k, v] of recentUrls) {
        if (v < cutoff) recentUrls.delete(k);
      }
    }

    // Run the full analysis pipeline
    const result = analyzeUrl(url);

    // Deliver result to Rust backend so the HTTP thread can respond
    await invokeTauri('deliver_extension_result', {
      id,
      riskLevel:     result.riskLevel,
      riskScore:     result.riskScore,
      evidenceCount: result.evidenceCount,
      explanation:   result.explanation,
      recommendation: result.recommendation,
      evidenceTitles: result.evidenceTitles,
    });
  } catch (err) {
    console.debug('[ExtBridge] Poll error:', err?.message);
  } finally {
    isPolling = false;
  }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/**
 * Start the extension bridge polling loop.
 */
export function startExtensionBridge() {
  if (pollTimer !== null) return;
  pollTimer = setInterval(pollOnce, POLL_INTERVAL_MS);
}

/**
 * Stop the extension bridge polling loop.
 */
export function stopExtensionBridge() {
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  isPolling = false;
}

/**
 * Initialize the extension bridge, binding to the authoritative protection state.
 * Called once from main.js during app bootstrap.
 */
export function initExtensionBridge() {
  // Only active inside the Tauri shell — silently no-op in plain browser
  if (!isTauriEnvironment()) {
    return;
  }

  // Bind to authoritative protection state changes
  onProtectionStateChange((state, active) => {
    if (active) {
      startExtensionBridge();
    } else {
      stopExtensionBridge();
    }
  });

  // Start immediately if protection is already active
  if (isProtectionActive()) {
    startExtensionBridge();
  }
}
