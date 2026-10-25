/**
 * popup.js — Browser Extension Popup Interface
 * Phase 3B-2: Link Protection Browser Guard
 */

'use strict';

document.addEventListener('DOMContentLoaded', async () => {
  const badgeStatus = document.getElementById('badge-status');
  const valConnection = document.getElementById('val-connection');
  const valProtection = document.getElementById('val-protection');
  const tokenStatus = document.getElementById('token-status');
  const tokenInput = document.getElementById('token-input');
  const btnSaveToken = document.getElementById('btn-save-token');
  const btnClearCache = document.getElementById('btn-clear-cache');
  const msgFeedback = document.getElementById('msg-feedback');

  function showFeedback(text, isError = false) {
    msgFeedback.textContent = text;
    msgFeedback.className = `msg-feedback ${isError ? 'error' : 'success'}`;
    setTimeout(() => {
      msgFeedback.className = 'msg-feedback';
    }, 4000);
  }

  function updateUi(status) {
    if (!status.hasToken) {
      tokenStatus.textContent = 'Not configured';
      tokenStatus.style.color = 'var(--risk-med)';
    } else {
      tokenStatus.textContent = 'Configured';
      tokenStatus.style.color = 'var(--risk-low)';
      if (status.token && !tokenInput.value) {
        tokenInput.value = status.token;
      }
    }

    if (!status.reachable) {
      badgeStatus.textContent = 'OFFLINE';
      badgeStatus.className = 'badge-status offline';
      valConnection.textContent = 'Disconnected';
      valConnection.style.color = 'var(--text-3)';
      valProtection.textContent = 'Unavailable';
      valProtection.style.color = 'var(--text-3)';
    } else if (!status.protectionActive) {
      badgeStatus.textContent = 'PAUSED';
      badgeStatus.className = 'badge-status paused';
      valConnection.textContent = 'Connected';
      valConnection.style.color = 'var(--risk-low)';
      valProtection.textContent = 'Protection Paused';
      valProtection.style.color = 'var(--risk-med)';
    } else {
      badgeStatus.textContent = 'ACTIVE';
      badgeStatus.className = 'badge-status active';
      valConnection.textContent = 'Connected';
      valConnection.style.color = 'var(--risk-low)';
      valProtection.textContent = 'Protection Active';
      valProtection.style.color = 'var(--risk-low)';
    }
  }

  // Request status from service worker
  try {
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        updateUi({ reachable: false, protectionActive: false, hasToken: false });
      } else {
        updateUi(response);
      }
    });
  } catch (err) {
    updateUi({ reachable: false, protectionActive: false, hasToken: false });
  }

  // Save Token
  btnSaveToken.addEventListener('click', () => {
    const token = tokenInput.value.trim();
    if (!token) {
      showFeedback('Please enter a valid token.', true);
      return;
    }

    chrome.runtime.sendMessage({ type: 'SET_TOKEN', token }, (response) => {
      if (chrome.runtime.lastError) {
        showFeedback('Failed to save token.', true);
      } else {
        showFeedback('Token saved! Rechecking status...');
        setTimeout(() => {
          chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (resp) => {
            if (resp) updateUi(resp);
          });
        }, 500);
      }
    });
  });

  // Clear Cache
  btnClearCache.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }, (response) => {
      if (chrome.runtime.lastError) {
        showFeedback('Failed to clear cache.', true);
      } else {
        showFeedback('Analysis cache cleared.');
      }
    });
  });
});
