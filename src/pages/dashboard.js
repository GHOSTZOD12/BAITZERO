/**
 * pages/dashboard.js
 * BaitZero reference-matched Dashboard page.
 * Hero with greeting, particle/wave branding, integrated URL input,
 * middle Protection Active card + 4 compact stat cards,
 * and full-width Recent Scans table matching media_1792397520873.jpg.
 */

import { icon } from '../icons.js';
import { navigate } from '../router.js';
import { getStats, getHistory } from '../storage.js';
import { isProtectionActive, onProtectionStateChange } from '../protectionState.js';
import { parseUrl } from '../engines/urlAnalyzer.js';

function formatTimestamp(timestamp) {
  if (!timestamp) return 'Oct 13, 2026 10:24 PM';
  const d = new Date(timestamp);
  const month = d.toLocaleDateString('en-US', { month: 'short' });
  const day = d.getDate();
  const year = d.getFullYear();
  let hours = d.getHours();
  const minutes = String(d.getMinutes()).padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12 || 12;
  return `${month} ${day}, ${year} ${String(hours).padStart(2, '0')}:${minutes} ${ampm}`;
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderDashboard() {
  const stats       = getStats();
  const history     = getHistory().slice(0, 5);
  const isProtected = isProtectionActive();

  // If history is empty, show nice mock/sample rows or empty message
  const totalScans = stats.totalChecked || 0;
  const highRisk   = stats.highRiskCount || 0;
  const medRisk    = stats.suspiciousCount || 0;
  const lowRisk    = stats.lowRiskCount || 0;

  return `
    <main class="page-content" id="page-dashboard">

      <!-- Hero Greeting & URL input card -->
      <div class="dash-hero-banner">
        <div class="dash-hero-header">
          <div class="dash-hero-title-group">
            <h1 class="dash-hero-title">Good evening</h1>
            <p class="dash-hero-sub">Stay one step ahead. Analyze links, detect risks, and get clear explanations.</p>
          </div>
          <div class="dash-hero-ambient-wave">
            <svg class="hero-wave-svg" viewBox="0 0 400 100" fill="none" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                <linearGradient id="waveGrad1" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stop-color="#7C3CFF" stop-opacity="0" />
                  <stop offset="40%" stop-color="#A970FF" stop-opacity="0.32" />
                  <stop offset="70%" stop-color="#7C3CFF" stop-opacity="0.18" />
                  <stop offset="100%" stop-color="#A970FF" stop-opacity="0" />
                </linearGradient>
                <linearGradient id="waveGrad2" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stop-color="#A970FF" stop-opacity="0" />
                  <stop offset="35%" stop-color="#C084FC" stop-opacity="0.28" />
                  <stop offset="65%" stop-color="#7C3CFF" stop-opacity="0.22" />
                  <stop offset="100%" stop-color="#A970FF" stop-opacity="0" />
                </linearGradient>
                <linearGradient id="waveGrad3" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stop-color="#7C3CFF" stop-opacity="0" />
                  <stop offset="50%" stop-color="#8B5CF6" stop-opacity="0.15" />
                  <stop offset="100%" stop-color="#7C3CFF" stop-opacity="0" />
                </linearGradient>
                <filter id="waveGlow" x="-10%" y="-20%" width="120%" height="140%">
                  <feGaussianBlur stdDeviation="1.5" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <path class="wave-line wave-line-1" d="M0,50 C50,25 100,70 160,40 C220,10 280,65 340,35 C370,22 390,38 400,30" stroke="url(#waveGrad1)" stroke-width="1.4" fill="none" filter="url(#waveGlow)" />
              <path class="wave-line wave-line-2" d="M0,60 C60,35 120,80 180,48 C240,16 300,72 350,42 C380,28 395,48 400,40" stroke="url(#waveGrad2)" stroke-width="1.1" fill="none" filter="url(#waveGlow)" />
              <path class="wave-line wave-line-3" d="M0,40 C70,68 140,22 210,58 C270,82 320,30 370,55 C390,62 400,50 400,50" stroke="url(#waveGrad3)" stroke-width="0.8" fill="none" opacity="0.5" />
              <path class="wave-line wave-line-4" d="M0,70 C80,45 150,85 230,55 C290,32 350,68 400,45" stroke="url(#waveGrad1)" stroke-width="0.6" fill="none" opacity="0.3" />
              <circle class="wave-particle particle-1" cx="130" cy="42" r="1.3" fill="#A970FF" />
              <circle class="wave-particle particle-2" cx="240" cy="32" r="1.0" fill="#C084FC" />
              <circle class="wave-particle particle-3" cx="310" cy="55" r="1.5" fill="#A970FF" />
            </svg>
            <span class="dash-hero-tagline">Spot the bait.<br/>Stop the risk.</span>
          </div>
        </div>

        <!-- Integrated search input -->
        <div class="dash-search-container">
          <div class="dash-search-bar">
            <span class="dash-search-icon">${icon.link}</span>
            <input
              type="url"
              id="dashboard-url-input"
              class="dash-search-input"
              placeholder="Paste a suspicious link to inspect (e.g. https://example.com or domain)"
              aria-label="URL to inspect"
              autocomplete="off"
              spellcheck="false"
            />
            <button class="btn-analyze-cyan" id="dashboard-analyze-btn" aria-label="Analyze URL">
              <span>Analyze URL</span>
              ${icon.arrowRight}
            </button>
          </div>

          <div class="dash-search-helper-row">
            <span class="dash-helper-text">Paste any link, domain, or short URL to inspect for phishing and spoofing. Press Enter to analyze.</span>
            <button type="button" class="dash-paste-btn" id="dashboard-paste-btn" title="Paste link from clipboard">
              ${icon.clipboardPaste}
              <span>Paste</span>
            </button>
          </div>
          <div id="dashboard-url-error" class="error-msg"></div>
        </div>
      </div>

      <!-- Middle row: Security Pulse + 4 stat cards -->
      <div class="dash-middle-grid">

        <!-- Compact Security Pulse Panel -->
        <div class="dash-pulse-card" id="security-pulse-card" role="button" tabindex="0" title="View Scan History">
          <div class="dash-pulse-top">
            <div class="dash-pulse-icon-box" aria-hidden="true">
              ${icon.activity}
            </div>
            <div class="dash-pulse-meta">
              <div class="dash-pulse-label-row">
                <span class="dash-pulse-heading">Security Pulse</span>
                <span class="dash-pulse-beacon" aria-hidden="true">
                  <span class="dash-pulse-glow"></span>
                  <span class="dash-pulse-core"></span>
                </span>
              </div>
              <span class="dash-pulse-sub" id="pulse-activity-status">
                ${totalScans > 0 ? `${totalScans} scans recorded` : 'Heuristic engine ready'}
              </span>
            </div>
          </div>
          <div class="dash-pulse-metrics">
            <div class="dash-pulse-stat">
              <span class="dash-pulse-stat-val" id="stat-scans-today">${stats.checkedToday || 0}</span>
              <span class="dash-pulse-stat-label">Checked Today</span>
            </div>
            <div class="dash-pulse-divider"></div>
            <div class="dash-pulse-stat">
              <span class="dash-pulse-stat-val ${highRisk > 0 ? 'text-high' : 'text-low'}" id="stat-pulse-threats">
                ${highRisk > 0 ? `${highRisk} Flagged` : '0 Threats'}
              </span>
              <span class="dash-pulse-stat-label">Threat Profile</span>
            </div>
          </div>
        </div>

        <!-- 4 Stats cards matching reference -->
        <div class="dash-stats-quad">
          <div class="dash-stat-tile">
            <div class="dash-stat-tile-badge badge-total">${icon.fileText}</div>
            <div class="dash-stat-tile-num" id="stat-total-checked">${totalScans}</div>
            <div class="dash-stat-tile-label">Total Scans</div>
          </div>
          <div class="dash-stat-tile">
            <div class="dash-stat-tile-badge badge-high">${icon.alertCircle}</div>
            <div class="dash-stat-tile-num text-high" id="stat-high-risk-count">${highRisk}</div>
            <div class="dash-stat-tile-label">High Risk</div>
          </div>
          <div class="dash-stat-tile">
            <div class="dash-stat-tile-badge badge-med">${icon.alertCircle}</div>
            <div class="dash-stat-tile-num text-med" id="stat-suspicious-count">${medRisk}</div>
            <div class="dash-stat-tile-label">Medium Risk</div>
          </div>
          <div class="dash-stat-tile">
            <div class="dash-stat-tile-badge badge-low">${icon.shieldCheck}</div>
            <div class="dash-stat-tile-num text-low" id="stat-low-risk-count">${lowRisk}</div>
            <div class="dash-stat-tile-label">Low Risk</div>
          </div>
        </div>

      </div>

      <!-- Recent Scans table (Full width card matching reference) -->
      <div class="dash-recent-section">
        <div class="dash-recent-header">
          <h2 class="dash-recent-title">Recent Scans</h2>
          <button class="dash-view-all-btn" id="view-all-history-btn">
            <span>View all</span>
            ${icon.arrowRight}
          </button>
        </div>

        <div class="dash-table-wrapper" id="recent-scans-list">
          ${renderRecentScansTableHtml(history)}
        </div>
      </div>

    </main>
  `;
}

function renderRecentScansTableHtml(history) {
  if (history.length === 0) {
    return `
      <div class="dash-empty-scans">
        <div class="dash-empty-icon">${icon.shieldCheck}</div>
        <div class="dash-empty-title">No scans yet</div>
        <div class="dash-empty-sub">Analyze a URL above to see results here.</div>
      </div>
    `;
  }

  return `
    <table class="reference-table">
      <thead>
        <tr>
          <th style="width: 38px;"><input type="checkbox" class="ref-checkbox" aria-label="Select all" /></th>
          <th>URL</th>
          <th style="width: 120px;">Risk</th>
          <th style="width: 120px;">Source</th>
          <th style="width: 190px;">Date</th>
        </tr>
      </thead>
      <tbody>
        ${history.map(item => {
          const levelLower = (item.riskLevel || 'Low').toLowerCase();
          const riskDisplay = item.riskLevel ? item.riskLevel.charAt(0).toUpperCase() + item.riskLevel.slice(1).toLowerCase() : 'Low';
          const sourceDisplay = item.source ? item.source.charAt(0).toUpperCase() + item.source.slice(1).toLowerCase() : 'Manual';
          return `
            <tr class="recent-table-row" data-url="${escapeHtml(item.url)}">
              <td><input type="checkbox" class="ref-checkbox" aria-label="Select row" /></td>
              <td class="col-url"><span class="table-url-text" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span></td>
              <td><span class="pill-badge pill-risk-${levelLower}">${riskDisplay}</span></td>
              <td><span class="pill-badge pill-source">${sourceDisplay}</span></td>
              <td class="col-date">${formatTimestamp(item.timestamp)}</td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function wireRecentItemEvents() {
  const rows = document.querySelectorAll('.recent-table-row');
  rows.forEach(row => {
    row.addEventListener('click', e => {
      // Don't navigate if clicking checkbox directly
      if (e.target.tagName === 'INPUT') return;
      const url = row.dataset.url;
      if (url) {
        sessionStorage.setItem('pendingAnalysisUrl', url);
        navigate('#/analyze');
      }
    });
  });
}

function refreshDashboardData() {
  if (!document.getElementById('page-dashboard')) return;

  const stats   = getStats();
  const history = getHistory().slice(0, 5);

  const elTotal = document.getElementById('stat-total-checked');
  const elSusp  = document.getElementById('stat-suspicious-count');
  const elHigh  = document.getElementById('stat-high-risk-count');
  const elLow   = document.getElementById('stat-low-risk-count');

  if (elTotal) elTotal.textContent = stats.totalChecked || 0;
  if (elSusp)  elSusp.textContent  = stats.suspiciousCount || 0;
  if (elHigh)  elHigh.textContent  = stats.highRiskCount || 0;
  if (elLow)   elLow.textContent   = stats.lowRiskCount || 0;

  const elToday   = document.getElementById('stat-scans-today');
  const elThreats = document.getElementById('stat-pulse-threats');
  const elStatus  = document.getElementById('pulse-activity-status');

  if (elToday)   elToday.textContent = stats.checkedToday || 0;
  if (elThreats) {
    elThreats.textContent = (stats.highRiskCount || 0) > 0 ? `${stats.highRiskCount} Flagged` : '0 Threats';
    elThreats.className   = `dash-pulse-stat-val ${(stats.highRiskCount || 0) > 0 ? 'text-high' : 'text-low'}`;
  }
  if (elStatus) {
    elStatus.textContent = (stats.totalChecked || 0) > 0
      ? `${stats.totalChecked} scans recorded`
      : 'Heuristic engine ready';
  }

  const recentListEl = document.getElementById('recent-scans-list');
  if (recentListEl) {
    recentListEl.innerHTML = renderRecentScansTableHtml(history);
    wireRecentItemEvents();
  }
}

function onDashboardHistoryUpdated() {
  if (document.getElementById('page-dashboard')) {
    refreshDashboardData();
  }
}

let unsubProtection = null;

export function initDashboard() {
  const analyzeBtn = document.getElementById('dashboard-analyze-btn');
  const urlInput   = document.getElementById('dashboard-url-input');
  const pasteBtn   = document.getElementById('dashboard-paste-btn');
  const historyBtn = document.getElementById('view-all-history-btn');
  const pulseCard  = document.getElementById('security-pulse-card');

  if (pulseCard) {
    pulseCard.addEventListener('click', () => navigate('#/history'));
  }

  // Protection state subscription
  if (unsubProtection) unsubProtection();
  unsubProtection = onProtectionStateChange((state, active) => {
    const pulseCard = document.getElementById('security-pulse-card');
    if (pulseCard) {
      if (active) pulseCard.classList.remove('paused');
      else pulseCard.classList.add('paused');
    }
  });

  if (analyzeBtn && urlInput) {
    const dashErrorMsg = document.getElementById('dashboard-url-error');

    analyzeBtn.addEventListener('click', () => {
      const url = urlInput.value.trim();
      if (!url) {
        urlInput.focus();
        urlInput.classList.add('input-error');
        if (dashErrorMsg) {
          dashErrorMsg.textContent = 'Please enter a valid URL.';
          dashErrorMsg.classList.add('visible');
        }
        return;
      }
      const parseResult = parseUrl(url);
      if (!parseResult.success) {
        urlInput.focus();
        urlInput.classList.add('input-error');
        if (dashErrorMsg) {
          dashErrorMsg.textContent = 'Please enter a valid URL.';
          dashErrorMsg.classList.add('visible');
        }
        return;
      }
      if (dashErrorMsg) dashErrorMsg.classList.remove('visible');
      urlInput.classList.remove('input-error');
      sessionStorage.setItem('pendingAnalysisUrl', parseResult.data.href);
      navigate('#/analyze');
    });

    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') analyzeBtn.click();
    });

    urlInput.addEventListener('input', () => {
      if (dashErrorMsg) dashErrorMsg.classList.remove('visible');
      urlInput.classList.remove('input-error');
    });
  }

  if (pasteBtn && urlInput) {
    pasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          urlInput.value = text.trim();
          urlInput.focus();
        }
      } catch (e) {
        console.warn('Clipboard read error:', e);
      }
    });
  }

  // No preset sample chips rendered in production build

  wireRecentItemEvents();

  if (historyBtn) {
    historyBtn.addEventListener('click', () => navigate('#/history'));
  }

  window.removeEventListener('linkguard:history-updated', onDashboardHistoryUpdated);
  window.addEventListener('linkguard:history-updated', onDashboardHistoryUpdated);
}
