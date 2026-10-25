/**
 * warning.js — Browser Extension Warning Page Script
 * Phase 3B-2: BaitZero Security Warning Page
 *
 * Manifest V3 CSP Compliant: Extracted from inline script block in warning.html.
 */

(function() {
  'use strict';

  /**
   * Validates that the destination URL is a well-formed http: or https: URL.
   * Strictly rejects javascript:, data:, file:, chrome-extension:, relative paths, or malformed inputs.
   *
   * @param {string} urlStr
   * @returns {string|null} Normalized URL string if valid, null otherwise.
   */
  function validateDestinationUrl(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return null;
    const trimmed = urlStr.trim();
    if (!trimmed) return null;

    try {
      const parsed = new URL(trimmed);
      // Strictly permit only standard web protocols
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }
      // Must have a non-empty hostname
      if (!parsed.hostname || parsed.hostname.trim() === '') {
        return null;
      }
      return parsed.href;
    } catch {
      return null;
    }
  }

  const params = new URLSearchParams(window.location.search);
  const rawTargetUrl = params.get('url') || '';
  const validatedTargetUrl = validateDestinationUrl(rawTargetUrl);

  const level = (params.get('level') || 'HIGH').toUpperCase();
  const explanation = params.get('explanation') || '';
  const recommendation = params.get('recommendation') || '';
  let titles = [];

  try {
    const parsedTitles = JSON.parse(params.get('titles') || '[]');
    if (Array.isArray(parsedTitles)) {
      titles = parsedTitles.filter(t => typeof t === 'string' && t.trim().length > 0);
    }
  } catch {
    titles = [];
  }

  const container = document.getElementById('container');
  const badge = document.getElementById('risk-badge');
  const titleText = document.getElementById('title-text');
  const targetUrlEl = document.getElementById('target-url');
  const explanationText = document.getElementById('explanation-text');
  const indicatorsContainer = document.getElementById('indicators-container');
  const indicatorsList = document.getElementById('indicators-list');
  const recommendationText = document.getElementById('recommendation-text');
  const backBtn = document.getElementById('back-btn');
  const continueBtn = document.getElementById('continue-btn');

  // Theme according to level
  if (level === 'MEDIUM') {
    container.classList.add('risk-medium');
    badge.textContent = 'MEDIUM RISK — Some suspicious indicators detected';
    titleText.textContent = 'Caution: Potential Risk Detected';
  } else {
    container.classList.add('risk-high');
    badge.textContent = 'HIGH RISK — Suspicious indicators detected';
    titleText.textContent = 'Warning: Suspicious Link Detected';
  }

  // Populate data using safe textContent to prevent markup interpretation
  if (validatedTargetUrl) {
    targetUrlEl.textContent = validatedTargetUrl;
  } else {
    targetUrlEl.textContent = rawTargetUrl
      ? 'Invalid or unsupported destination (blocked)'
      : 'Unknown destination';
    targetUrlEl.style.color = 'var(--risk-high)';

    // Disable bypass button if destination is invalid or forbidden scheme
    if (continueBtn) {
      continueBtn.disabled = true;
      continueBtn.style.opacity = '0.35';
      continueBtn.style.cursor = 'not-allowed';
      continueBtn.title = 'Bypass is disabled because the destination URL is invalid or unsafe.';
    }
  }

  if (explanation) {
    explanationText.textContent = explanation;
  } else {
    explanationText.textContent = level === 'HIGH'
      ? 'Multiple suspicious patterns were identified by the local heuristic analysis pipeline.'
      : 'Suspicious indicators were detected in this link structure.';
  }

  if (recommendation) {
    recommendationText.textContent = recommendation;
  }

  if (titles && titles.length > 0) {
    indicatorsContainer.style.display = 'block';
    indicatorsList.innerHTML = '';
    titles.forEach(title => {
      const li = document.createElement('li');
      li.textContent = title;
      indicatorsList.appendChild(li);
    });
  }

  // Actions
  backBtn.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  continueBtn.addEventListener('click', async () => {
    // Validate AGAIN immediately before navigation
    const currentValidated = validateDestinationUrl(validatedTargetUrl || rawTargetUrl);
    if (!currentValidated) {
      alert('Navigation blocked: destination URL is invalid, malformed, or uses an unsupported protocol.');
      return;
    }

    // Inform the background worker to allow this one navigation through without intercepting
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      try {
        await new Promise(resolve => {
          chrome.runtime.sendMessage({ type: 'ALLOW_NAVIGATION', url: currentValidated }, () => resolve());
        });
      } catch {
        // Ignore messaging errors
      }
    }

    // Navigate to the validated target URL only
    window.location.replace(currentValidated);
  });
})();
