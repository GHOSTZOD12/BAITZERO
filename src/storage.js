/**
 * storage.js
 * Persistent storage layer for desktop security application using localStorage.
 *
 * Responsibilities:
 * - Persist and retrieve URL analysis scan history
 * - Compute real-time dashboard statistics
 * - Manage sample demonstration URLs for viva/evaluation
 * - Provide JSON/CSV export capabilities
 * - Clear and prune investigation records
 */

const HISTORY_STORAGE_KEY = 'linkguard_scan_history';
const MAX_HISTORY_ITEMS   = 100;

/**
 * Pre-defined test cases for evaluation and demonstration.
 * Covers safe, suspicious, and high-risk attack vectors.
 */
export const SAMPLE_URLS = [
  {
    label: 'Safe — Official Wikipedia',
    url: 'https://en.wikipedia.org/wiki/Phishing',
    category: 'safe',
    expectedRisk: 'LOW',
  },
  {
    label: 'Safe — Verified Google Service',
    url: 'https://accounts.google.com/signin/v2/identifier',
    category: 'safe',
    expectedRisk: 'LOW',
  },
  {
    label: 'Impersonation — Fake PayPal Domain',
    url: 'https://paypal.account-verify-login.secure-portal.com/update',
    category: 'impersonation',
    expectedRisk: 'HIGH',
  },
  {
    label: 'Credential Theft — Bare IP + HTTP',
    url: 'http://192.168.1.105:8080/bank/login-verify-account',
    category: 'credential-theft',
    expectedRisk: 'HIGH',
  },
  {
    label: 'Deceptive — Punycode Apple Lookalike',
    url: 'https://xn--pple-43d.com/recovery/password-reset',
    category: 'punycode',
    expectedRisk: 'HIGH',
  },
  {
    label: 'Obfuscated — URL Shortener with Credential Path',
    url: 'https://bit.ly/secure-banking-update-confirm',
    category: 'shortener',
    expectedRisk: 'MEDIUM',
  },
  {
    label: 'Suspicious — Suspicious TLD & Deep Subdomains',
    url: 'https://secure.auth.member.portal.billing-update.xyz/login.php',
    category: 'tld-subdomain',
    expectedRisk: 'HIGH',
  },
];

/**
 * Sanitizes a URL for persistent storage in scan history (BZ-PRIV-01).
 * Completely strips query strings, fragments, and credentials (username/password)
 * while preserving protocol, hostname, port, and pathname.
 *
 * Guarantees:
 * - If parsing fails, returns a safe fallback placeholder ('[Invalid URL]').
 * - Never returns raw unparsed input or sensitive query/fragment/credential data.
 *
 * @param {string} rawUrl
 * @returns {string} Sanitized URL
 */
export function sanitizeUrlForHistory(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return '';
  }
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return '';
  }

  try {
    let urlObj;
    try {
      urlObj = new URL(trimmed);
    } catch (_) {
      // Handle schemes like http/https omitted
      if (!trimmed.includes('://')) {
        urlObj = new URL('https://' + trimmed);
      } else {
        return '[Invalid URL]';
      }
    }

    // Strip credentials
    urlObj.username = '';
    urlObj.password = '';
    // Strip query strings and fragments entirely
    urlObj.search = '';
    urlObj.hash = '';

    return urlObj.href;
  } catch (_) {
    return '[Invalid URL]';
  }
}

/**
 * Retrieve all stored history records, newest first.
 * Safely sanitizes legacy records in memory and cleanses localStorage if unredacted records are found.
 * @returns {Array<object>}
 */
export function getHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return [];

    let hasUnsanitized = false;
    const sanitizedList = list.map(item => {
      if (!item || typeof item !== 'object') return item;
      if (item.url && (item.url.includes('?') || item.url.includes('#') || item.url.includes('@'))) {
        hasUnsanitized = true;
        return {
          ...item,
          url: sanitizeUrlForHistory(item.url),
        };
      }
      return item;
    });

    if (hasUnsanitized) {
      try {
        localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(sanitizedList));
      } catch (_) {}
    }

    return sanitizedList;
  } catch (err) {
    console.warn('Failed to parse history from localStorage:', err);
    return [];
  }
}

/**
 * Save an analysis result into history.
 * Prepends the new record and maintains MAX_HISTORY_ITEMS limit.
 * Sanitizes the persisted URL to eliminate sensitive tokens, query params, and credentials (BZ-PRIV-01).
 *
 * @param {object} record
 * @returns {object} The saved record with generated ID and timestamp
 */
export function saveHistoryItem({ url, urlData, riskResult, evidenceList, explanation, recommendation, isDemo = false, timestamp, source = 'Manual' }) {
  try {
    const history = getHistory();
    const sanitizedUrl = sanitizeUrlForHistory(url);

    const recordTimestamp = timestamp || Date.now();
    const newRecord = {
      id:                 'rec_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      timestamp:          recordTimestamp,
      isoDate:            new Date(recordTimestamp).toISOString(),
      url:                sanitizedUrl,
      hostname:           urlData?.hostname || '',
      protocol:           urlData?.protocol || '',
      riskLevel:          riskResult?.level || 'LOW',
      riskScore:          riskResult?.score || 0,
      evidenceCount:      evidenceList?.length || 0,
      highSeverityCount:  riskResult?.highSeverityCount || 0,
      isDemo:             !!isDemo,
      source:             source || 'Manual',
      evidenceSummary:    (evidenceList || []).map(e => ({
        id:       e.id,
        title:    e.title,
        severity: e.severity,
        category: e.category,
      })),
      explanation:        explanation || '',
      recommendation:     recommendation || '',
    };

    history.unshift(newRecord);

    if (history.length > MAX_HISTORY_ITEMS) {
      history.length = MAX_HISTORY_ITEMS;
    }

    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
    console.warn(`[UI-DIAG] History write completed | host=${newRecord.hostname || 'unknown'} | total_records=${history.length}`);

    // Dispatch event so other components (e.g. Dashboard) can react if desired
    console.warn(`[UI-DIAG] History refresh requested (dispatching 'linkguard:history-updated')`);
    window.dispatchEvent(new CustomEvent('linkguard:history-updated'));

    return newRecord;
  } catch (err) {
    console.warn('Failed to save history item to localStorage:', err);
    return null;
  }
}

/**
 * Delete a single history record by ID.
 * @param {string} id
 * @returns {boolean}
 */
export function deleteHistoryItem(id) {
  try {
    const history = getHistory();
    const filtered = history.filter(item => item.id !== id);
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(filtered));
    window.dispatchEvent(new CustomEvent('linkguard:history-updated'));
    return true;
  } catch (err) {
    console.warn('Failed to delete history item:', err);
    return false;
  }
}

/**
 * Clear all stored history.
 * @returns {boolean}
 */
export function clearHistory() {
  try {
    localStorage.removeItem(HISTORY_STORAGE_KEY);
    window.dispatchEvent(new CustomEvent('linkguard:history-updated'));
    return true;
  } catch (err) {
    console.warn('Failed to clear history:', err);
    return false;
  }
}

/**
 * Compute aggregate statistics for the dashboard.
 * @returns {{
 *   totalChecked: number,
 *   checkedToday: number,
 *   suspiciousCount: number,
 *   highRiskCount: number,
 *   lowRiskCount: number,
 *   avgScore: number
 * }}
 */
export function getStats() {
  const history = getHistory();
  const now = new Date();
  const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();

  let checkedToday    = 0;
  let suspiciousCount = 0;
  let highRiskCount   = 0;
  let lowRiskCount    = 0;
  let totalScore      = 0;

  history.forEach(item => {
    if (item.timestamp >= startOfDay) {
      checkedToday++;
    }
    if (item.riskLevel === 'HIGH') {
      highRiskCount++;
      suspiciousCount++;
    } else if (item.riskLevel === 'MEDIUM') {
      suspiciousCount++;
    } else {
      lowRiskCount++;
    }
    totalScore += item.riskScore || 0;
  });

  return {
    totalChecked: history.length,
    checkedToday,
    suspiciousCount,
    highRiskCount,
    lowRiskCount,
    avgScore: history.length > 0 ? Math.round(totalScore / history.length) : 0,
  };
}

/**
 * Export history as a formatted JSON file download.
 */
export function exportHistoryJSON() {
  const history = getHistory();
  const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
  triggerDownload(blob, `security_history_${formatDateForFilename(new Date())}.json`);
}

/**
 * Export history as a CSV file download.
 */
export function exportHistoryCSV() {
  const history = getHistory();
  const headers = ['ID', 'Date/Time', 'URL', 'Hostname', 'Risk Level', 'Risk Score', 'Indicators Count', 'High Severity Indicators'];

  const rows = history.map(item => [
    `"${item.id}"`,
    `"${new Date(item.timestamp).toLocaleString()}"`,
    `"${(item.url || '').replace(/"/g, '""')}"`,
    `"${(item.hostname || '').replace(/"/g, '""')}"`,
    `"${item.riskLevel}"`,
    item.riskScore,
    item.evidenceCount,
    item.highSeverityCount,
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  triggerDownload(blob, `security_history_${formatDateForFilename(new Date())}.csv`);
}

/**
 * Helper to trigger browser download for a blob.
 */
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function formatDateForFilename(date) {
  return date.toISOString().replace(/[:.]/g, '-').slice(0, 19);
}

export { loadSettings as getSettings } from './pages/settings.js';

// Cross-window storage synchronization
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key === HISTORY_STORAGE_KEY) {
      window.dispatchEvent(new CustomEvent('linkguard:history-updated'));
    }
  });
}
