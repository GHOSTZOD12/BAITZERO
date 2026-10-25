/**
 * pages/analyze.js
 * BaitZero reference-matched URL Analysis page.
 * Matches media_1792397520873.jpg (top-right screen):
 * - Header with "URL Analysis", subtitle, and "Illustrative result" badge.
 * - Integrated URL input bar with "Analyze ->".
 * - Amber/Orange glowing risk banner with circular score gauge on the right (score / 100).
 * - "Why this was flagged" accordion rows with lettered icon badges and chevrons.
 * - Bottom action buttons: "View details" and "Deep Research".
 */

import { icon }                from '../icons.js';
import { parseUrl }            from '../engines/urlAnalyzer.js';
import { collectEvidence }     from '../engines/evidenceEngine.js';
import { calculateRisk, getScoreDisclaimer } from '../engines/riskEngine.js';
import { generateExplanation } from '../engines/explanationEngine.js';
import { saveHistoryItem, SAMPLE_URLS } from '../storage.js';
import { loadSettings }        from './settings.js';
import { navigate }            from '../router.js';

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderAnalyze() {
  let pendingUrl = sessionStorage.getItem('pendingAnalysisUrl') || '';
  if (!pendingUrl && window.location.hash.includes('?url=')) {
    try {
      const q = window.location.hash.split('?url=')[1];
      if (q) pendingUrl = decodeURIComponent(q);
    } catch (_) {}
  }
  if (pendingUrl) sessionStorage.removeItem('pendingAnalysisUrl');

  return `
    <main class="page-content" id="page-analyze">

      <!-- Header with status badge -->
      <div class="analyze-header-row">
        <div>
          <h1 class="page-title">URL Analysis</h1>
          <p class="page-subtitle">Get a detailed risk analysis and explanation.</p>
        </div>
        <div class="analyze-badge-illustrative">
          <span class="badge-dot"></span>
          <span>Deterministic heuristic engine</span>
        </div>
      </div>

      <!-- Integrated Scanner Input Bar -->
      <div class="analyze-search-wrap">
        <div class="dash-search-bar analyze-bar">
          <span class="dash-search-icon">${icon.link}</span>
          <input
            type="text"
            id="analyze-url-input"
            class="dash-search-input"
            placeholder="Paste URL to inspect (e.g. https://example.com/login)"
            value="${escapeHtml(pendingUrl || '')}"
            aria-label="URL to inspect"
            autocomplete="off"
            spellcheck="false"
          />
          <button class="btn-analyze-cyan" id="analyze-submit-btn" aria-label="Analyze URL">
            <span>Analyze</span>
            ${icon.arrowRight}
          </button>
        </div>
        <div id="analyze-error-msg" class="error-msg"></div>
      </div>

      <!-- Result Container -->
      <div id="analyze-result-area">
        ${renderEmptyState()}
      </div>

    </main>
  `;
}

function renderEmptyState() {
  return `
    <div class="empty-state">
      ${icon.search}
      <div class="empty-state-title">Ready to Inspect</div>
      <div class="empty-state-text">
        Paste any URL above or choose a test sample to analyze structural indicators, domain properties, and risk signals.
      </div>
    </div>
  `;
}

export function initAnalyze() {
  const input     = document.getElementById('analyze-url-input');
  const submitBtn = document.getElementById('analyze-submit-btn');
  const errorMsg  = document.getElementById('analyze-error-msg');

  if (submitBtn && input) {
    submitBtn.addEventListener('click', () => {
      runAnalysis(input.value.trim(), { input, errorMsg });
    });

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') submitBtn.click();
    });

    input.addEventListener('input', () => {
      if (errorMsg) errorMsg.classList.remove('visible');
      input.classList.remove('input-error');
    });
  }

  // Presets
  const presetChips = document.querySelectorAll('.preset-chip');
  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const url = chip.dataset.url;
      if (url && input && submitBtn) {
        input.value = url;
        if (errorMsg) errorMsg.classList.remove('visible');
        input.classList.remove('input-error');
        submitBtn.click();
      }
    });
  });

  // Result area delegated events
  const resultArea = document.getElementById('analyze-result-area');
  if (resultArea) {
    resultArea.addEventListener('click', e => {
      const drBtn = e.target.closest('#deep-research-btn');
      if (drBtn) {
        const url = drBtn.dataset.url;
        if (url) {
          sessionStorage.setItem('deepResearchUrl', url);
          navigate('#/deep-research');
        }
        return;
      }

      const vdBtn = e.target.closest('#view-details-btn');
      if (vdBtn) {
        const detailsModal = document.getElementById('bz-tech-details-modal');
        if (detailsModal) detailsModal.style.display = 'flex';
        return;
      }

      const closeVdBtn = e.target.closest('#bz-close-tech-modal') || e.target.closest('#bz-close-tech-modal-btn') || e.target.closest('.bz-modal-backdrop');
      if (closeVdBtn && (!e.target.closest('.bz-tech-drawer') || e.target.closest('#bz-close-tech-modal') || e.target.closest('#bz-close-tech-modal-btn'))) {
        const detailsModal = document.getElementById('bz-tech-details-modal');
        if (detailsModal) detailsModal.style.display = 'none';
        return;
      }

      // Accordion toggle
      const accRow = e.target.closest('.why-flagged-row');
      if (accRow) {
        accRow.classList.toggle('open');
      }
    });
  }

  // Auto-run if URL present
  if (input && input.value) {
    runAnalysis(input.value.trim(), { input, errorMsg });
  }
}

let lastAnalysisContext = null;

function runAnalysis(rawUrl, { input, errorMsg }) {
  if (!rawUrl) {
    showError(input, errorMsg, 'Please enter a valid URL.');
    return;
  }

  const parseResult = parseUrl(rawUrl);
  if (!parseResult.success) {
    showError(input, errorMsg, parseResult.error);
    return;
  }

  if (errorMsg) errorMsg.classList.remove('visible');
  if (input) input.classList.remove('input-error');

  const urlData = parseResult.data;
  const settings = loadSettings();
  const evidenceList = collectEvidence(urlData, {
    deepInvestigation: settings.deepInvestigation,
  });
  const riskResult = calculateRisk(evidenceList);
  const { explanation, recommendation } = generateExplanation(evidenceList, riskResult);

  lastAnalysisContext = {
    urlData,
    evidenceList,
    riskResult,
    explanation,
    recommendation,
  };

  saveHistoryItem({
    url: rawUrl,
    urlData,
    riskResult,
    evidenceList,
    explanation,
    recommendation,
  });

  renderResult(urlData, evidenceList, riskResult, explanation, recommendation);
}

function showError(input, errorMsg, text) {
  if (input) {
    input.focus();
    input.classList.add('input-error');
  }
  if (errorMsg) {
    errorMsg.textContent = text;
    errorMsg.classList.add('visible');
  }
}

function renderResult(urlData, evidenceList, riskResult, explanation, recommendation) {
  const area = document.getElementById('analyze-result-area');
  if (!area) return;

  const level = (riskResult?.level || 'LOW').toUpperCase();
  const score = Math.min(100, Math.max(0, Math.round(riskResult?.score || 0)));
  const levelDisplay = level;
  const levelClass = level.toLowerCase();

  // Color mappings
  const strokeColor = level === 'HIGH' ? '#ef4444' : level === 'MEDIUM' ? '#f59e0b' : '#22c55e';
  // Arc calculation for 0-100 radial gauge
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const scoreExplanation = level === 'HIGH'
    ? 'Score 71–100 indicates high confidence of deceptive, spoofed, or credential-harvesting mechanisms.'
    : level === 'MEDIUM'
    ? 'Score 31–70 indicates structural anomalies, misleading authority tokens, or nonstandard redirection patterns.'
    : 'Score 0–30 indicates standard URL syntax with no deceptive impersonation indicators found.';

  const bannerDesc = explanation || (
    level === 'HIGH'
      ? 'This URL shows high-confidence phishing or deceptive indicators. Proceed with extreme caution.'
      : level === 'MEDIUM'
      ? 'This URL shows suspicious characteristics or structural anomalies that warrant caution.'
      : 'No obvious suspicious indicators detected in structural heuristics.'
  );

  // Scannable evidence order: highest severity/weight first
  const severityRank = { high: 3, medium: 2, low: 1 };
  const sortedEvidence = [...(evidenceList || [])].sort((a, b) => {
    const diff = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
    if (diff !== 0) return diff;
    return (b.weight || 0) - (a.weight || 0);
  });

  // Build accordion items from sorted real evidence
  let accordionItems = [];
  if (sortedEvidence.length === 0) {
    accordionItems = [
      {
        letter: '✓',
        badgeClass: 'badge-teal',
        typeLabel: 'Verified Baseline',
        title: 'Clean baseline indicators',
        desc: 'No known phishing patterns, deceptive authority, or structural anomalies detected.',
        detail: 'Analyzed domain syntax, protocol scheme, path structure, and known security baselines.'
      }
    ];
  } else {
    accordionItems = sortedEvidence.map(item => {
      let badgeLetter = '!';
      let badgeClass = 'badge-orange';
      let typeLabel = 'Suspicious Indicator';

      if (item.severity === 'high') {
        badgeLetter = '▲';
        badgeClass = 'badge-red';
        typeLabel = 'High Severity Risk';
      } else if (item.category === 'Structure' || item.category === 'Syntax') {
        badgeLetter = 'S';
        badgeClass = 'badge-teal';
        typeLabel = 'Structural Finding';
      } else if (item.category === 'Domain' || item.category === 'DNS') {
        badgeLetter = 'i';
        badgeClass = 'badge-blue';
        typeLabel = 'Domain Signal';
      }

      return {
        letter: badgeLetter,
        badgeClass,
        typeLabel,
        title: item.title,
        desc: item.description,
        detail: item.evidence
          ? `Evidence observed: ${item.evidence}`
          : `Category: ${item.category || 'Heuristics'} | Severity: ${(item.severity || 'medium').toUpperCase()} | Rule weight: ${item.weight || 0} pts.`
      };
    });
  }

  area.innerHTML = `
    <div class="analyze-results-container">

      <!-- Risk Banner -->
      <div class="risk-banner banner-${levelClass}">
        <div class="risk-banner-left">
          <div class="risk-banner-icon-box">
            ${level === 'HIGH' ? icon.alertCircle : level === 'MEDIUM' ? icon.alertTriangle : icon.shieldCheck}
          </div>
          <div class="risk-banner-text-box">
            <h2 class="risk-banner-title">${levelDisplay} RISK (${score}/100)</h2>
            <p class="risk-banner-desc">${escapeHtml(bannerDesc)}</p>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
              ${scoreExplanation}
            </div>
          </div>
        </div>

        <!-- Radial Score Gauge on the Right -->
        <div class="risk-gauge-container">
          <div class="radial-gauge-wrap">
            <svg class="radial-svg" width="90" height="90" viewBox="0 0 90 90">
              <circle class="radial-bg" cx="45" cy="45" r="${radius}" stroke-width="7" />
              <circle
                class="radial-progress"
                cx="45"
                cy="45"
                r="${radius}"
                stroke="${strokeColor}"
                stroke-width="7"
                stroke-dasharray="${circumference}"
                stroke-dashoffset="${strokeDashoffset}"
                stroke-linecap="round"
                transform="rotate(-90 45 45)"
              />
            </svg>
            <div class="radial-score-box">
              <span class="radial-score-val">${score}</span>
              <span class="radial-score-denom">/100</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Why this was flagged section -->
      <div class="why-flagged-section">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 class="why-flagged-heading" style="margin-bottom: 0;">
            ${evidenceList && evidenceList.length > 0 ? 'Why this was flagged (Ranked by Relevance)' : 'Heuristic Findings'}
          </h3>
          <span style="font-size: 11.5px; color: var(--text-2);">
            ${sortedEvidence.length} indicator${sortedEvidence.length === 1 ? '' : 's'} identified
          </span>
        </div>

        <div class="why-flagged-list">
          ${accordionItems.map((item, idx) => `
            <div class="why-flagged-row" id="flagged-row-${idx}">
              <div class="why-flagged-summary">
                <div class="why-badge ${item.badgeClass}">${item.letter}</div>
                <div class="why-texts">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="why-title">${escapeHtml(item.title)}</div>
                    <span style="font-size: 10px; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.04em;">${item.typeLabel}</span>
                  </div>
                  <div class="why-desc">${escapeHtml(item.desc)}</div>
                </div>
                <span class="why-chevron">${icon.chevronDown}</span>
              </div>
              <div class="why-detail-panel">
                <p>${escapeHtml(item.detail)}</p>
              </div>
            </div>
          `).join('')}
        </div>

        <div style="font-size: 11px; color: var(--text-3); margin-top: 10px; padding: 0 4px; line-height: 1.4;">
          <strong>Information availability:</strong> Live DNS records, WHOIS registration, and external reputation feeds are offline during deterministic heuristic scans. For remote infrastructure verification, choose Deep Research.
        </div>
      </div>

      <!-- Action Buttons Row -->
      <div class="analyze-actions-row">
        <button class="btn-view-details" id="view-details-btn" title="Inspect technical structure and raw heuristics">
          ${icon.shield}
          <span>View Details (Technical Inspector)</span>
        </button>
        <button class="btn-deep-research-action" id="deep-research-btn" data-url="${escapeHtml(urlData.href)}" title="Investigate DNS, WHOIS, and TLS in Deep Research">
          ${icon.sparkles}
          <span>Deep Research</span>
        </button>
      </div>

      <!-- Technical Details Modal Backdrop & Drawer -->
      <div id="bz-tech-details-modal" class="bz-modal-backdrop" style="display: none;">
        <div class="bz-tech-drawer" role="dialog" aria-modal="true" aria-labelledby="tech-drawer-title">
          <div class="bz-tech-drawer-header">
            <div class="bz-tech-drawer-title" id="tech-drawer-title">
              ${icon.shield}
              <span>Technical Analysis Inspector</span>
            </div>
            <button class="alert-close-btn" id="bz-close-tech-modal" aria-label="Close modal">✕</button>
          </div>
          <table class="bz-tech-table">
            <tbody>
              <tr>
                <td>Target URL</td>
                <td>${escapeHtml(urlData.href)}</td>
              </tr>
              <tr>
                <td>Protocol / Scheme</td>
                <td>${escapeHtml(urlData.protocol || 'http:')}</td>
              </tr>
              <tr>
                <td>Hostname</td>
                <td>${escapeHtml(urlData.hostname || '—')}</td>
              </tr>
              <tr>
                <td>Domain / TLD</td>
                <td>${escapeHtml(urlData.domain || urlData.hostname || '—')}</td>
              </tr>
              <tr>
                <td>Pathname</td>
                <td>${escapeHtml(urlData.pathname || '/')}</td>
              </tr>
              <tr>
                <td>Query Parameters</td>
                <td>${escapeHtml(urlData.search || 'None')}</td>
              </tr>
              <tr>
                <td>Risk Classification</td>
                <td><span class="pill-badge pill-risk-${levelClass}">${levelDisplay} (${score}/100)</span></td>
              </tr>
              <tr>
                <td>Rules Evaluated</td>
                <td>${sortedEvidence.length} triggered / 14 baseline checks</td>
              </tr>
            </tbody>
          </table>
          <div class="bz-modal-actions">
            <button class="bz-btn-cancel" id="bz-close-tech-modal-btn">
              Close
            </button>
          </div>
        </div>
      </div>

    </div>
  `;
}
