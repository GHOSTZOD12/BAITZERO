/**
 * background.js — Browser Extension Service Worker
 * Phase 3B-2: Link Protection Browser Guard
 *
 * Responsibilities:
 * 1. Intercept browser navigation events via webNavigation API.
 * 2. For http/https URLs: send URL to local desktop application for analysis.
 * 3. If desktop app returns MEDIUM or HIGH risk: redirect tab to warning page.
 * 4. If desktop app is unreachable: fail safely, allow navigation.
 * 5. If protection is PAUSED on desktop: allow navigation without analysis.
 * 6. Deduplicate repeat requests to avoid unnecessary analysis.
 *
 * Security Design:
 * - Auth token is stored in chrome.storage.local (not accessible to web pages).
 * - Only http/https URLs are analyzed (chrome://, file://, etc. are ignored).
 * - Only sends URLs to 127.0.0.1:27432 (localhost loopback — no external servers).
 * - Only chrome-extension:// origin is sent in requests.
 * - Arbitrary web page content is NEVER read.
 * - Browsing history is NOT retained by the extension.
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DESKTOP_API_URL = 'http://127.0.0.1:27432';
const STATUS_ENDPOINT  = `${DESKTOP_API_URL}/status`;
const ANALYZE_ENDPOINT = `${DESKTOP_API_URL}/analyze`;

/** Time in ms to wait for desktop app response before failing safely. */
const REQUEST_TIMEOUT_MS = 12000;

/** How long to cache analysis results for the same URL (ms). */
const RESULT_CACHE_TTL_MS = 30000;

/** How often to re-check desktop app status (ms). */
const STATUS_CHECK_INTERVAL_MS = 15000;

// ---------------------------------------------------------------------------
// In-Memory State
// ---------------------------------------------------------------------------

/**
 * Cache of recent analysis results to avoid redundant requests.
 * Map<url, { result, timestamp }>
 */
const resultCache = new Map();

/**
 * Set of tab IDs currently being analyzed (prevents re-entrancy).
 */
const pendingTabs = new Set();

/**
 * Set of URLs explicitly approved by the user to continue after seeing a warning.
 * Stored with a timestamp to auto-expire.
 * Map<string, number>
 */
const allowedUrls = new Map();
const BYPASS_TTL_MS = 60000;

/**
 * Last known status of the desktop application.
 */
let desktopStatus = {
  reachable: false,
  protectionActive: false,
  lastChecked: 0,
};

/**
 * In-memory token cache to avoid repeated asynchronous storage queries
 * during rapid navigation while maintaining chrome.storage.local as single source of truth.
 */
let cachedToken = null;

/**
 * Single-flight promise coalescing concurrent checkDesktopStatus invocations.
 */
let pendingStatusCheck = null;

// ---------------------------------------------------------------------------
// Token & State Rehydration Management
// ---------------------------------------------------------------------------

/**
 * Retrieve the auth token from in-memory cache or chrome.storage.local.
 * Returns null if not configured.
 *
 * @returns {Promise<string|null>}
 */
async function getToken() {
  if (cachedToken) {
    return cachedToken;
  }
  try {
    const data = await chrome.storage.local.get('extension_token');
    if (data && data.extension_token) {
      cachedToken = data.extension_token;
      return cachedToken;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Store a token in chrome.storage.local and update cache.
 *
 * @param {string} token
 */
async function setToken(token) {
  cachedToken = token || null;
  await chrome.storage.local.set({ extension_token: token });
}

/**
 * Persist an approved navigation bypass so it survives service-worker suspension.
 *
 * @param {string} url
 */
async function allowUrlBypass(url) {
  if (!url) return;
  const now = Date.now();
  allowedUrls.set(url, now);
  try {
    const data = await chrome.storage.local.get('allowed_bypasses');
    const bypasses = (data && typeof data.allowed_bypasses === 'object' && data.allowed_bypasses) ? data.allowed_bypasses : {};
    bypasses[url] = now;
    // Clean up expired bypasses
    for (const [k, v] of Object.entries(bypasses)) {
      if (now - v >= BYPASS_TTL_MS) {
        delete bypasses[k];
      }
    }
    await chrome.storage.local.set({ allowed_bypasses: bypasses });
  } catch {
    // Fail silently on storage errors
  }
}

/**
 * Check whether a URL has an active bypass and consume it if valid.
 *
 * @param {string} url
 * @returns {Promise<boolean>}
 */
async function isUrlBypassed(url) {
  if (!url) return false;
  const now = Date.now();

  // Check in-memory state
  const memTime = allowedUrls.get(url);
  if (memTime && (now - memTime) < BYPASS_TTL_MS) {
    allowedUrls.delete(url);
    // Asynchronously cleanup storage
    chrome.storage.local.get('allowed_bypasses').then(data => {
      if (data?.allowed_bypasses && data.allowed_bypasses[url]) {
        delete data.allowed_bypasses[url];
        chrome.storage.local.set({ allowed_bypasses: data.allowed_bypasses }).catch(() => {});
      }
    }).catch(() => {});
    return true;
  }

  // Check storage state (in case service worker suspended after user clicked Continue Anyway)
  try {
    const data = await chrome.storage.local.get('allowed_bypasses');
    if (data?.allowed_bypasses && data.allowed_bypasses[url]) {
      const storedTime = data.allowed_bypasses[url];
      delete data.allowed_bypasses[url];
      await chrome.storage.local.set({ allowed_bypasses: data.allowed_bypasses });
      if ((now - storedTime) < BYPASS_TTL_MS) {
        return true;
      }
    }
  } catch {
    // Fail safely
  }
  return false;
}

// ---------------------------------------------------------------------------
// Desktop Application Communication
// ---------------------------------------------------------------------------

/**
 * Build headers for a request to the local desktop API.
 *
 * @param {string|null} token
 * @returns {Record<string, string>}
 */
function buildHeaders(token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['X-Extension-Token'] = token;
  }
  return headers;
}

/**
 * Fetch with a timeout. Returns null on timeout or network error.
 *
 * @param {string} url
 * @param {RequestInit} options
 * @param {number} timeoutMs
 * @returns {Promise<Response|null>}
 */
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Check whether the desktop application is reachable and protection is active.
 * Coalesces concurrent in-flight requests and updates desktopStatus in place.
 *
 * @returns {Promise<boolean>} true if reachable AND protection is active
 */
async function checkDesktopStatus() {
  const now = Date.now();

  // Use cached status if checked recently
  if (now - desktopStatus.lastChecked < STATUS_CHECK_INTERVAL_MS && desktopStatus.lastChecked > 0) {
    return desktopStatus.reachable && desktopStatus.protectionActive;
  }

  // Single-flight deduplication: return existing promise if check is already running
  if (pendingStatusCheck) {
    return pendingStatusCheck;
  }

  pendingStatusCheck = (async () => {
    try {
      const token = await getToken();
      if (!token) {
        desktopStatus = { reachable: false, protectionActive: false, lastChecked: now };
        await updateBadge(false, false);
        return false;
      }

      const response = await fetchWithTimeout(
        STATUS_ENDPOINT,
        { method: 'GET', headers: buildHeaders(token) },
        3000,
      );

      if (!response || !response.ok) {
        desktopStatus = { reachable: false, protectionActive: false, lastChecked: now };
        await updateBadge(false, false);
        return false;
      }

      const data = await response.json();
      desktopStatus = {
        reachable: true,
        protectionActive: !!data.protectionActive,
        lastChecked: now,
      };
      await updateBadge(true, desktopStatus.protectionActive);
      return desktopStatus.protectionActive;
    } catch {
      desktopStatus = { reachable: false, protectionActive: false, lastChecked: now };
      await updateBadge(false, false);
      return false;
    } finally {
      pendingStatusCheck = null;
    }
  })();

  return pendingStatusCheck;
}

/**
 * Send a URL to the desktop application for analysis.
 * Returns the analysis result, or null if the desktop app is unreachable.
 *
 * @param {string} url
 * @returns {Promise<AnalysisResponse|null>}
 */
async function analyzeUrl(url) {
  const token = await getToken();
  if (!token) {
    return null;
  }

  try {
    const response = await fetchWithTimeout(
      ANALYZE_ENDPOINT,
      {
        method: 'POST',
        headers: buildHeaders(token),
        body: JSON.stringify({ url }),
      },
      REQUEST_TIMEOUT_MS,
    );

    if (!response) {
      // Network error / timeout — fail safely
      return null;
    }

    if (!response.ok) {
      console.warn('[Extension] Analyze error:', response.status);
      return null;
    }

    const data = await response.json();
    return data;
  } catch (err) {
    console.warn('[Extension] analyzeUrl error:', err.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Result Cache
// ---------------------------------------------------------------------------

/**
 * Check the in-memory cache for a recent result for this URL.
 *
 * @param {string} url
 * @returns {object|null}
 */
function getCachedResult(url) {
  const entry = resultCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > RESULT_CACHE_TTL_MS) {
    resultCache.delete(url);
    return null;
  }
  return entry.result;
}

/**
 * Store a result in the in-memory cache.
 *
 * @param {string} url
 * @param {object} result
 */
function cacheResult(url, result) {
  resultCache.set(url, { result, timestamp: Date.now() });
  // Limit cache size to 50 entries
  if (resultCache.size > 50) {
    const oldestKey = resultCache.keys().next().value;
    resultCache.delete(oldestKey);
  }
}

// ---------------------------------------------------------------------------
// Badge Display
// ---------------------------------------------------------------------------

/**
 * Update the extension badge to reflect current status.
 *
 * @param {boolean} reachable
 * @param {boolean} active
 */
async function updateBadge(reachable, active) {
  try {
    if (!reachable) {
      await chrome.action.setBadgeText({ text: 'OFF' });
      await chrome.action.setBadgeBackgroundColor({ color: '#6b7280' });
    } else if (!active) {
      await chrome.action.setBadgeText({ text: '⏸' });
      await chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch {
    // Badge API may not be available in all contexts
  }
}

/**
 * Briefly show a risk badge on the action icon.
 *
 * @param {number} tabId
 * @param {'LOW'|'MEDIUM'|'HIGH'} level
 */
async function showRiskBadge(tabId, level) {
  try {
    const color = level === 'HIGH' ? '#dc2626' : level === 'MEDIUM' ? '#d97706' : '#16a34a';
    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setBadgeText({ text: level === 'LOW' ? '✓' : '!', tabId });

    // Clear badge after 4 seconds
    setTimeout(async () => {
      try {
        await chrome.action.setBadgeText({ text: '', tabId });
      } catch { /* Tab may be closed */ }
    }, 4000);
  } catch { /* Tab may be closed */ }
}

// ---------------------------------------------------------------------------
// Warning Page Redirect
// ---------------------------------------------------------------------------

/**
 * Redirect a tab to the warning page, passing analysis data as URL parameters.
 *
 * @param {number} tabId
 * @param {string} originalUrl
 * @param {object} analysisResult
 */
async function redirectToWarning(tabId, originalUrl, analysisResult) {
  const warningPageUrl = chrome.runtime.getURL('pages/warning.html');

  const params = new URLSearchParams({
    url: originalUrl,
    level: analysisResult.riskLevel || 'MEDIUM',
    score: String(analysisResult.riskScore || 0),
    explanation: analysisResult.explanation || '',
    recommendation: analysisResult.recommendation || '',
    titles: JSON.stringify(analysisResult.evidenceTitles || []),
  });

  try {
    await chrome.tabs.update(tabId, {
      url: `${warningPageUrl}?${params.toString()}`,
    });
  } catch (err) {
    console.warn('[Extension] Failed to redirect tab:', err.message);
  }
}

// ---------------------------------------------------------------------------
// Navigation Interception
// ---------------------------------------------------------------------------

/**
 * Handle a browser navigation event.
 * This is called when the user navigates to a URL in the main frame.
 *
 * @param {chrome.webNavigation.WebNavigationTransitionCallbackDetails} details
 */
async function handleNavigation(details) {
  const { tabId, url, frameId } = details;

  // Only intercept top-level frame navigation (frameId 0 = main frame)
  if (frameId !== 0) return;

  // Only analyze http/https URLs — ignore chrome://, file://, etc.
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return;
  }

  // Don't re-analyze our own warning page
  if (url.includes(chrome.runtime.id)) {
    return;
  }

  // If user explicitly chose to continue anyway on warning page, bypass check once
  if (await isUrlBypassed(url)) {
    return;
  }

  // Deduplication: if this tab is already being analyzed, skip
  if (pendingTabs.has(tabId)) {
    return;
  }

  // Check cache first
  const cached = getCachedResult(url);
  if (cached) {
    await showRiskBadge(tabId, cached.riskLevel || 'LOW');
    if (cached.riskLevel === 'MEDIUM' || cached.riskLevel === 'HIGH') {
      await redirectToWarning(tabId, url, cached);
    }
    return;
  }

  // Check if desktop app is active (uses cached status if recent)
  const shouldAnalyze = await checkDesktopStatus();
  if (!shouldAnalyze) {
    // Desktop app not available or protection paused — fail safely, allow navigation
    return;
  }

  pendingTabs.add(tabId);

  try {
    const result = await analyzeUrl(url);

    if (!result) {
      // Desktop app unreachable or returned error — fail safely
      return;
    }

    // If protection was paused on the desktop, don't intercept
    if (result.status === 'paused' || result.protectionActive === false) {
      // Update our status cache
      desktopStatus.protectionActive = false;
      desktopStatus.lastChecked = Date.now();
      await updateBadge(true, false);
      return;
    }

    const riskLevel = result.riskLevel || 'LOW';

    // Cache the result
    cacheResult(url, result);

    // Update badge
    await showRiskBadge(tabId, riskLevel);

    // LOW: allow navigation, no interruption
    if (riskLevel === 'LOW') {
      return;
    }

    // MEDIUM or HIGH: redirect to warning page
    await redirectToWarning(tabId, url, result);
  } catch (err) {
    console.warn('[Extension] handleNavigation error:', err.message);
    // Fail safely — allow navigation
  } finally {
    pendingTabs.delete(tabId);
  }
}

// ---------------------------------------------------------------------------
// Message Handler (for popup communication)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATUS') {
    // Force a fresh status check
    desktopStatus.lastChecked = 0;
    Promise.all([checkDesktopStatus(), getToken()]).then(([active, token]) => {
      sendResponse({
        reachable: desktopStatus.reachable,
        protectionActive: desktopStatus.protectionActive,
        hasToken: !!token,
        token: token,
      });
    }).catch(() => {
      sendResponse({
        reachable: false,
        protectionActive: false,
        hasToken: false,
        token: null,
      });
    });
    return true; // Keep message channel open for async response
  }

  if (message.type === 'SET_TOKEN') {
    setToken(message.token).then(() => {
      desktopStatus.lastChecked = 0; // Force re-check
      checkDesktopStatus().then(() => {
        sendResponse({ success: true, reachable: desktopStatus.reachable, protectionActive: desktopStatus.protectionActive });
      });
    });
    return true;
  }

  if (message.type === 'ALLOW_NAVIGATION') {
    if (message.url) {
      allowUrlBypass(message.url);
    }
    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'CLEAR_CACHE') {
    resultCache.clear();
    sendResponse({ success: true });
    return false;
  }
});

// ---------------------------------------------------------------------------
// Event Registration
// ---------------------------------------------------------------------------

/**
 * webNavigation.onBeforeNavigate fires when the browser is about to navigate.
 * This is the earliest point where we can intercept and redirect.
 *
 * Transition types filtered to user-initiated navigations:
 * - typed: user typed in address bar
 * - link: user clicked a link
 * - generated: most JavaScript-initiated navigations
 * - auto_bookmark, form_submit, keyword, keyword_generated
 *
 * We intentionally exclude:
 * - reload: reloading a page we already checked is unnecessary
 */
chrome.webNavigation.onBeforeNavigate.addListener(
  handleNavigation,
  {
    url: [
      { schemes: ['http'] },
      { schemes: ['https'] },
    ],
  },
);

// Lifecycle event listeners: refresh bridge status upon startup or installation
if (typeof chrome !== 'undefined' && chrome.runtime?.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    desktopStatus.lastChecked = 0;
    checkDesktopStatus();
  });
}

if (typeof chrome !== 'undefined' && chrome.runtime?.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    desktopStatus.lastChecked = 0;
    checkDesktopStatus();
  });
}

// Initial status check on service worker startup
checkDesktopStatus();

