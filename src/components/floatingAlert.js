/**
 * components/floatingAlert.js
 * BaitZero — Compact Gaming-Style Floating Alert (Final Design)
 *
 * Implements the approved compact floating notification for incoming links
 * detected from Discord and other supported social-media applications.
 *
 * Visual & Design Requirements:
 * - Target approx 320–340 px wide and 85–100 px high at 100% display scaling.
 * - Positioned at bottom-right of the active display, above Windows toast area.
 * - Dark translucent background with thin cyan border and sci-fi corner brackets.
 * - Real BaitZero mascot logo with glowing cyan accent.
 * - Source application badge (e.g. Discord pill).
 * - Multi-state transition:
 *     * Initial: "Link received" | "Checking for potential risks…" | cyan accent | spinning ring.
 *     * Suspicious: "Suspicious link" | evidence summary | restrained red accent | manual dismiss.
 *     * No known threats: "No known threats" | standard checks note | neutral teal accent | auto-dismiss.
 *     * Inconclusive: "Inconclusive" | unreliable conclusion note | restrained amber accent | auto-dismiss.
 */

import { icon } from '../icons.js';
import { safeInvoke, listenEvent } from '../tauriBridge.js';

let currentUrl = '';
let autoDismissTimer = null;
let dismissRemainingMs = 0;
let dismissDeadline = 0;

export function renderFloatingAlert() {
  return `
    <div id="floating-alert-card" class="floating-alert-card state-checking" role="alert" aria-live="assertive" tabindex="0" aria-label="BaitZero Security Alert — Press Enter or click to inspect link">
      <!-- Sci-fi Corner Brackets -->
      <div class="bracket bracket-tl"></div>
      <div class="bracket bracket-tr"></div>
      <div class="bracket bracket-bl"></div>
      <div class="bracket bracket-br"></div>

      <!-- Left Mascot Icon -->
      <div class="alert-mascot-box" aria-hidden="true">
        <svg viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" class="baitzero-mascot-svg">
          <image href="/logo.png" x="2" y="2" width="32" height="32" preserveAspectRatio="xMidYMid meet" />
        </svg>
      </div>

      <!-- Center Info Column -->
      <div class="alert-info-col" id="alert-clickable-area" title="Click to inspect this link in BaitZero">
        <!-- Brand + App Badge Row -->
        <div class="alert-top-row">
          <span class="alert-brand-name">BaitZero</span>
          <div class="alert-app-badge" id="alert-source-badge">
            <span class="alert-app-icon" id="alert-source-icon">${getAppIconSvg('Discord')}</span>
            <span class="alert-app-label" id="alert-source-label">Discord</span>
          </div>
        </div>

        <!-- Main Title -->
        <div class="alert-title" id="alert-title-text">Link received</div>

        <!-- Status Message / Evidence -->
        <div class="alert-message" id="alert-message-text">Checking for potential risks…</div>
      </div>

      <!-- Right Action / Spinner Column -->
      <div class="alert-right-col">
        <!-- Close Button -->
        <button class="alert-close-btn" id="alert-close-btn" aria-label="Close notification" title="Dismiss" type="button">
          ✕
        </button>

        <!-- Dynamic Indicator (Spinner or Result Icon) -->
        <div class="alert-status-indicator" id="alert-indicator-box">
          <svg class="alert-spinner-ring" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="9" fill="none" stroke="rgba(169, 112, 255, 0.2)" stroke-width="2.5"/>
            <circle cx="12" cy="12" r="9" fill="none" stroke="#A970FF" stroke-width="2.5" stroke-dasharray="22 36" stroke-linecap="round"/>
          </svg>
        </div>
      </div>
    </div>
  `;
}

function getAppIconSvg(sourceApp) {
  const norm = (sourceApp || '').toLowerCase();
  if (norm.includes('discord')) {
    return `<svg viewBox="0 0 20 19" fill="#5865F2" style="width: 13px; height: 13px;"><path d="M16.224 3.768a14.5 14.5 0 0 0-3.67-1.153c-.158.286-.343.67-.47.976a13.5 13.5 0 0 0-4.067 0c-.128-.306-.317-.69-.476-.976A14.4 14.4 0 0 0 3.868 3.77C1.546 7.28.916 10.703 1.231 14.077a14.7 14.7 0 0 0 4.5 2.306q.545-.748.965-1.587a9.5 9.5 0 0 1-1.518-.74q.191-.14.372-.293c2.927 1.369 6.107 1.369 8.999 0q.183.152.372.294-.723.437-1.52.74.418.838.963 1.588a14.6 14.6 0 0 0 4.504-2.308c.37-3.911-.63-7.302-2.644-10.309m-9.13 8.234c-.878 0-1.599-.82-1.599-1.82 0-.998.705-1.82 1.6-1.82.894 0 1.614.82 1.599 1.82.001 1-.705 1.82-1.6 1.82m5.91 0c-.878 0-1.599-.82-1.599-1.82 0-.998.705-1.82 1.6-1.82.893 0 1.614.82 1.599 1.82 0 1-.706 1.82-1.6 1.82"/></svg>`;
  }
  if (norm.includes('slack')) {
    return `<svg viewBox="0 0 24 24" fill="#E01E5A" style="width: 13px; height: 13px;"><circle cx="12" cy="12" r="9"/></svg>`;
  }
  if (norm.includes('telegram')) {
    return `<svg viewBox="0 0 24 24" fill="#229ED9" style="width: 13px; height: 13px;"><circle cx="12" cy="12" r="9"/></svg>`;
  }
  if (norm.includes('whatsapp')) {
    return `<svg viewBox="0 0 24 24" fill="#25D366" style="width: 13px; height: 13px;"><circle cx="12" cy="12" r="9"/></svg>`;
  }
  if (norm.includes('clipboard')) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="#A970FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width: 13px; height: 13px;"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M9 14l2 2 4-4"/></svg>`;
  }
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 12px; height: 12px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;
}

async function invokeTauri(cmd, args = {}) {
  return await safeInvoke(cmd, args);
}

export function initFloatingAlert() {
  const card = document.getElementById('floating-alert-card');
  const closeBtn = document.getElementById('alert-close-btn');

  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dismissAlert();
    });
    closeBtn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        e.stopPropagation();
        dismissAlert();
      }
    });
  }

  if (card) {
    let lastNavigateMs = 0;
    card.addEventListener('click', (e) => {
      // Never trigger body navigation when the close button (or its children) was clicked
      if (e.target.closest('#alert-close-btn')) {
        return;
      }
      const now = Date.now();
      if (now - lastNavigateMs < 800) return; // debounce repeated rapid clicks
      lastNavigateMs = now;
      if (currentUrl) {
        invokeTauri('open_alert_in_main', { url: currentUrl });
      }
    });

    card.addEventListener('keydown', (e) => {
      if (e.target.closest('#alert-close-btn')) {
        return;
      }
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const now = Date.now();
        if (now - lastNavigateMs < 800) return;
        lastNavigateMs = now;
        if (currentUrl) {
          invokeTauri('open_alert_in_main', { url: currentUrl });
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        dismissAlert();
      }
    });

    // Hover pause / resume for auto-dismiss timer
    card.addEventListener('mouseenter', () => {
      if (autoDismissTimer) {
        clearTimeout(autoDismissTimer);
        autoDismissTimer = null;
        dismissRemainingMs = Math.max(0, dismissDeadline - Date.now());
      }
    });

    card.addEventListener('mouseleave', () => {
      if (dismissRemainingMs > 0) {
        dismissDeadline = Date.now() + dismissRemainingMs;
        autoDismissTimer = setTimeout(dismissAlert, dismissRemainingMs);
      }
    });
  }

  // Listen for Tauri events from the backend via centralized bridge.
  listenEvent('floating-alert-show', (event) => {
    const payload = event?.payload;
    if (payload) {
      showInitialAlert(payload);
    }
  });

  listenEvent('floating-alert-update', (event) => {
    const payload = event?.payload;
    if (payload) {
      updateAlertResult(payload);
    }
  });

  // Reliable pull model: fetch init data on startup to eliminate event race condition
  invokeTauri('get_alert_init_data').then((data) => {
    if (data) {
      if (data.status === 'checking') {
        showInitialAlert(data);
      } else {
        updateAlertResult(data);
      }
    }
  });
}

function showInitialAlert(data) {
  currentUrl = data.url || '';
  if (autoDismissTimer) {
    clearTimeout(autoDismissTimer);
    autoDismissTimer = null;
  }
  dismissRemainingMs = 0;

  const card = document.getElementById('floating-alert-card');
  const titleEl = document.getElementById('alert-title-text');
  const messageEl = document.getElementById('alert-message-text');
  const sourceLabel = document.getElementById('alert-source-label');
  const sourceIcon = document.getElementById('alert-source-icon');
  const indicatorBox = document.getElementById('alert-indicator-box');

  const appName = data.sourceApp || data.appName || 'Discord';

  if (card) {
    card.className = 'floating-alert-card state-checking';
  }
  if (titleEl) {
    titleEl.textContent = data.title || 'Link received';
  }
  if (messageEl) {
    messageEl.textContent = data.message || 'Checking for potential risks…';
  }
  if (sourceLabel) {
    sourceLabel.textContent = appName;
  }
  if (sourceIcon) {
    sourceIcon.innerHTML = getAppIconSvg(appName);
  }
  if (indicatorBox) {
    indicatorBox.innerHTML = `
      <svg class="alert-spinner-ring" viewBox="0 0 24 24">
        <circle cx="12" cy="12" r="9" fill="none" stroke="rgba(169, 112, 255, 0.2)" stroke-width="2.5"/>
        <circle cx="12" cy="12" r="9" fill="none" stroke="#A970FF" stroke-width="2.5" stroke-dasharray="22 36" stroke-linecap="round"/>
      </svg>
    `;
  }
}

function updateAlertResult(data) {
  if (data.url) {
    currentUrl = data.url;
  }

  const card = document.getElementById('floating-alert-card');
  const titleEl = document.getElementById('alert-title-text');
  const messageEl = document.getElementById('alert-message-text');
  const indicatorBox = document.getElementById('alert-indicator-box');

  const riskLevel = (data.riskLevel || 'LOW').toUpperCase();

  if (riskLevel === 'HIGH' || riskLevel === 'MEDIUM') {
    // Suspicious result
    if (card) {
      card.className = 'floating-alert-card state-suspicious';
    }
    if (titleEl) {
      titleEl.textContent = data.title || 'Suspicious link';
    }
    if (messageEl) {
      messageEl.textContent = data.message || 'Suspicious indicators detected in link';
    }
    if (indicatorBox) {
      indicatorBox.innerHTML = `
        <div style="color: #EF4444; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 4px rgba(239, 68, 68, 0.6));">
          ${icon.shieldAlert}
        </div>
      `;
    }
    // Stays visible until manually dismissed!
    if (autoDismissTimer) {
      clearTimeout(autoDismissTimer);
      autoDismissTimer = null;
    }
    dismissRemainingMs = 0;
  } else if (riskLevel === 'LOW') {
    // No known threats
    if (card) {
      card.className = 'floating-alert-card state-safe';
    }
    if (titleEl) {
      titleEl.textContent = data.title || 'No known threats';
    }
    if (messageEl) {
      messageEl.textContent = data.message || 'No risk indicators found by standard checks.';
    }
    if (indicatorBox) {
      indicatorBox.innerHTML = `
        <div style="color: #22C55E; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 4px rgba(34, 197, 94, 0.6));">
          ${icon.shieldCheck}
        </div>
      `;
    }
    scheduleDismiss(data.autoDismiss || 6000);
  } else {
    // Inconclusive
    if (card) {
      card.className = 'floating-alert-card state-inconclusive';
    }
    if (titleEl) {
      titleEl.textContent = data.title || 'Inconclusive';
    }
    if (messageEl) {
      messageEl.textContent = data.message || 'Could not reach a reliable conclusion.';
    }
    if (indicatorBox) {
      indicatorBox.innerHTML = `
        <div style="color: #F59E0B; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 4px rgba(245, 158, 11, 0.6));">
          ${icon.alertTriangle}
        </div>
      `;
    }
    scheduleDismiss(data.autoDismiss || 8000);
  }
}

function scheduleDismiss(durationMs) {
  if (autoDismissTimer) {
    clearTimeout(autoDismissTimer);
    autoDismissTimer = null;
  }
  if (durationMs > 0) {
    dismissRemainingMs = durationMs;
    dismissDeadline = Date.now() + durationMs;
    autoDismissTimer = setTimeout(dismissAlert, durationMs);
  }
}

function dismissAlert() {
  if (autoDismissTimer) {
    clearTimeout(autoDismissTimer);
    autoDismissTimer = null;
  }
  dismissRemainingMs = 0;
  invokeTauri('dismiss_floating_alert');
}
