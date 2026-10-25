/**
 * pages/history.js
 * BaitZero reference-matched Scan History page.
 * Matches media_1792397520873.jpg (bottom-left screen):
 * - Header: "Scan History", "View and manage your past scans."
 * - Compact toolbar: Search input, All Risk dropdown, All Source dropdown, Clear button.
 * - Full-width table: Checkbox, URL, Risk, Source, Date, and Actions (Inspect & Delete).
 * - All filtering, search, individual item deletion, and clear operations fully preserved.
 */

import { icon } from '../icons.js';
import { navigate } from '../router.js';
import {
  getHistory,
  deleteHistoryItem,
  clearHistory,
  exportHistoryJSON,
  exportHistoryCSV,
  saveHistoryItem,
  SAMPLE_URLS,
} from '../storage.js';

let currentRiskFilter   = 'all';
let currentSourceFilter = 'all';
let searchQuery         = '';

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

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

export function renderHistory() {
  const history  = getHistory();
  const filtered = getFilteredHistory(history);

  return `
    <main class="page-content" id="page-history">

      <!-- Header -->
      <div class="page-header">
        <h1 class="page-title">Scan History</h1>
        <p class="page-subtitle">View, search, and inspect past URL scans from this device.</p>
      </div>

      <!-- Reference-matched toolbar -->
      <div class="history-ref-toolbar">
        <div class="history-search-box">
          <span class="history-search-icon">${icon.search}</span>
          <input
            type="text"
            id="history-search-input"
            class="history-ref-input"
            placeholder="Search URLs or hostnames..."
            aria-label="Search URLs"
            value="${escapeHtml(searchQuery)}"
          />
          <button
            class="history-search-clear-btn"
            id="history-search-clear-btn"
            title="Clear search"
            style="${searchQuery ? '' : 'display: none;'}"
            aria-label="Clear search input"
          >✕</button>
        </div>

        <div class="history-dropdowns-group">
          <!-- Risk dropdown -->
          <div class="ref-select-wrap">
            <select id="history-risk-select" class="ref-select" aria-label="Filter by risk">
              <option value="all" ${currentRiskFilter === 'all' ? 'selected' : ''}>All Risk Levels</option>
              <option value="high" ${currentRiskFilter === 'high' ? 'selected' : ''}>High Risk</option>
              <option value="medium" ${currentRiskFilter === 'medium' ? 'selected' : ''}>Medium Risk</option>
              <option value="low" ${currentRiskFilter === 'low' ? 'selected' : ''}>Low Risk</option>
            </select>
            <span class="ref-select-chevron">${icon.chevronDown}</span>
          </div>

          <!-- Source dropdown -->
          <div class="ref-select-wrap">
            <select id="history-source-select" class="ref-select" aria-label="Filter by source">
              <option value="all" ${currentSourceFilter === 'all' ? 'selected' : ''}>All Sources</option>
              <option value="manual" ${currentSourceFilter === 'manual' ? 'selected' : ''}>Manual Input</option>
              <option value="clipboard" ${currentSourceFilter === 'clipboard' ? 'selected' : ''}>Clipboard Guard</option>
              <option value="notification" ${currentSourceFilter === 'notification' ? 'selected' : ''}>Notification</option>
            </select>
            <span class="ref-select-chevron">${icon.chevronDown}</span>
          </div>

          <span class="history-count-badge" id="history-count-badge">
            Showing ${filtered.length} of ${history.length}
          </span>

          <!-- Clear button -->
          <button class="btn-ref-clear" id="history-clear-btn" title="Clear all history">
            Clear All
          </button>
        </div>
      </div>

      <!-- Reference-matched Table -->
      <div class="dash-recent-section" style="margin-top: 18px;" id="history-list-container">
        ${renderHistoryTable(filtered, history.length)}
      </div>

      <!-- Confirmation Modal for Clear History -->
      <div id="bz-clear-confirm-modal" class="bz-modal-backdrop" style="display: none;">
        <div class="bz-modal-card" role="alertdialog" aria-modal="true" aria-labelledby="clear-modal-title">
          <div class="bz-modal-header">
            <div class="bz-modal-icon-warning">${icon.trash}</div>
            <div class="bz-modal-title" id="clear-modal-title">Clear Scan History?</div>
          </div>
          <div class="bz-modal-body">
            This will permanently remove all recorded URL scans and cached results from your local device. This action cannot be undone.
          </div>
          <div class="bz-modal-actions">
            <button class="bz-btn-cancel" id="bz-cancel-clear-btn">Keep History</button>
            <button class="bz-btn-destructive" id="bz-confirm-clear-btn">Clear History</button>
          </div>
        </div>
      </div>

    </main>
  `;
}

function getFilteredHistory(history) {
  if (!Array.isArray(history)) return [];

  return history.filter(item => {
    // Risk filter
    if (currentRiskFilter !== 'all') {
      const level = (item.riskLevel || '').toLowerCase();
      if (level !== currentRiskFilter) return false;
    }

    // Source filter
    if (currentSourceFilter !== 'all') {
      const src = (item.source || '').toLowerCase();
      if (src !== currentSourceFilter) return false;
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const urlMatch = (item.url || '').toLowerCase().includes(q);
      const domainMatch = (item.hostname || '').toLowerCase().includes(q);
      return urlMatch || domainMatch;
    }

    return true;
  });
}

function renderHistoryTable(records, totalUnfilteredCount = 0) {
  if (records.length === 0) {
    if (totalUnfilteredCount > 0) {
      return `
        <div class="empty-state">
          ${icon.search}
          <div class="empty-state-title">No Matching Scans Found</div>
          <div class="empty-state-text">
            No past scans match your current filter or search criteria.
          </div>
          <button class="btn-ref-clear" id="history-reset-filters-btn" style="margin-top: 12px;">
            Reset Filters
          </button>
        </div>
      `;
    }
    return `
      <div class="empty-state">
        ${icon.history}
        <div class="empty-state-title">No Scans Recorded Yet</div>
        <div class="empty-state-text">
          URLs scanned through manual analysis, clipboard detection, or browser navigation will appear here.
        </div>
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
          <th style="width: 100px; text-align: right;">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${records.map(item => {
          const levelLower = (item.riskLevel || 'Low').toLowerCase();
          const riskDisplay = item.riskLevel ? item.riskLevel.charAt(0).toUpperCase() + item.riskLevel.slice(1).toLowerCase() : 'Low';
          const sourceDisplay = item.source ? item.source.charAt(0).toUpperCase() + item.source.slice(1).toLowerCase() : 'Manual';
          return `
            <tr class="history-table-row" data-url="${escapeHtml(item.url)}" title="Click to inspect this URL in Analysis">
              <td><input type="checkbox" class="ref-checkbox" aria-label="Select row" /></td>
              <td class="col-url"><span class="table-url-text" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span></td>
              <td><span class="pill-badge pill-risk-${levelLower}">${riskDisplay}</span></td>
              <td><span class="pill-badge pill-source">${sourceDisplay}</span></td>
              <td class="col-date">${formatTimestamp(item.timestamp)}</td>
              <td class="col-actions">
                <button class="row-act-btn btn-inspect" data-url="${escapeHtml(item.url)}" title="Open in URL Analysis">
                  ${icon.search}
                </button>
                <button class="row-act-btn btn-delete" data-id="${item.id}" title="Delete scan record">
                  ${icon.trash}
                </button>
              </td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function reRenderTable() {
  const container = document.getElementById('history-list-container');
  if (!container) return;
  const history = getHistory();
  const filtered = getFilteredHistory(history);
  container.innerHTML = renderHistoryTable(filtered, history.length);

  const countBadge = document.getElementById('history-count-badge');
  if (countBadge) {
    countBadge.textContent = `Showing ${filtered.length} of ${history.length}`;
  }

  const clearInputBtn = document.getElementById('history-search-clear-btn');
  if (clearInputBtn) {
    clearInputBtn.style.display = searchQuery ? '' : 'none';
  }

  const clearBtn = document.getElementById('history-clear-btn');
  if (clearBtn) {
    const hasItems = history.length > 0;
    clearBtn.disabled = !hasItems;
    clearBtn.style.opacity = hasItems ? '1' : '0.45';
    clearBtn.style.cursor = hasItems ? 'pointer' : 'not-allowed';
    clearBtn.title = hasItems ? 'Clear all history' : 'No scan history to clear';
  }

  wireTableActions();
}

function wireTableActions() {
  // Reset filters button in empty state
  const resetBtn = document.getElementById('history-reset-filters-btn');
  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      searchQuery = '';
      currentRiskFilter = 'all';
      currentSourceFilter = 'all';

      const searchInput = document.getElementById('history-search-input');
      const riskSelect = document.getElementById('history-risk-select');
      const sourceSelect = document.getElementById('history-source-select');

      if (searchInput) searchInput.value = '';
      if (riskSelect) riskSelect.value = 'all';
      if (sourceSelect) sourceSelect.value = 'all';

      reRenderTable();
    });
  }

  // Row inspect buttons
  const inspectBtns = document.querySelectorAll('.row-act-btn.btn-inspect');
  inspectBtns.forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const url = btn.dataset.url;
      if (url) {
        sessionStorage.setItem('pendingAnalysisUrl', url);
        navigate('#/analyze');
      }
    });
  });

  // Row delete buttons
  const deleteBtns = document.querySelectorAll('.row-act-btn.btn-delete');
  deleteBtns.forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const id = btn.dataset.id;
      if (id) {
        deleteHistoryItem(id);
        reRenderTable();
      }
    });
  });

  // Clicking row navigates to analyze
  const rows = document.querySelectorAll('.history-table-row');
  rows.forEach(row => {
    row.addEventListener('click', e => {
      if (e.target.tagName === 'INPUT' || e.target.closest('button')) return;
      const url = row.dataset.url;
      if (url) {
        sessionStorage.setItem('pendingAnalysisUrl', url);
        navigate('#/analyze');
      }
    });
  });
}

export function initHistory() {
  const searchInput    = document.getElementById('history-search-input');
  const searchClearBtn = document.getElementById('history-search-clear-btn');
  const riskSelect     = document.getElementById('history-risk-select');
  const sourceSelect   = document.getElementById('history-source-select');
  const clearBtn       = document.getElementById('history-clear-btn');
  const modal          = document.getElementById('bz-clear-confirm-modal');
  const cancelClearBtn = document.getElementById('bz-cancel-clear-btn');
  const confirmClearBtn= document.getElementById('bz-confirm-clear-btn');

  // Ensure modal is closed on page init/navigation
  if (modal) {
    modal.style.display = 'none';
    modal.classList.remove('is-open');
  }

  // Sync Clear All button initial disabled state
  if (clearBtn) {
    const hasItems = getHistory().length > 0;
    clearBtn.disabled = !hasItems;
    clearBtn.style.opacity = hasItems ? '1' : '0.45';
    clearBtn.style.cursor = hasItems ? 'pointer' : 'not-allowed';
    clearBtn.title = hasItems ? 'Clear all history' : 'No scan history to clear';
  }

  const closeModal = () => {
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('is-open');
    }
    if (clearBtn && !clearBtn.disabled) {
      clearBtn.focus();
    }
    document.removeEventListener('keydown', handleKeyDown);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      closeModal();
    }
  };

  const openModal = () => {
    if (!modal) return;
    const history = getHistory();
    if (history.length === 0) return;

    modal.style.display = 'flex';
    modal.classList.add('is-open');
    if (cancelClearBtn) {
      cancelClearBtn.focus();
    }
    document.addEventListener('keydown', handleKeyDown);
  };

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value;
      reRenderTable();
    });
  }

  if (searchClearBtn && searchInput) {
    searchClearBtn.addEventListener('click', () => {
      searchInput.value = '';
      searchQuery = '';
      searchInput.focus();
      reRenderTable();
    });
  }

  if (riskSelect) {
    riskSelect.addEventListener('change', () => {
      currentRiskFilter = riskSelect.value;
      reRenderTable();
    });
  }

  if (sourceSelect) {
    sourceSelect.addEventListener('change', () => {
      currentSourceFilter = sourceSelect.value;
      reRenderTable();
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      openModal();
    });
  }

  if (cancelClearBtn) {
    cancelClearBtn.addEventListener('click', () => {
      closeModal();
    });
  }

  if (modal) {
    // Backdrop click dismisses the dialog
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeModal();
      }
    });
  }

  if (confirmClearBtn && modal) {
    confirmClearBtn.addEventListener('click', () => {
      try {
        const success = clearHistory();
        closeModal();
        if (success) {
          reRenderTable();
        } else {
          alert('Failed to clear scan history from storage. Please check permissions.');
        }
      } catch (err) {
        console.error('[History] Error clearing history:', err);
        closeModal();
        alert('An unexpected error occurred while clearing scan history.');
      }
    });
  }

  wireTableActions();

  // Listen for history updates
  window.removeEventListener('linkguard:history-updated', reRenderTable);
  window.addEventListener('linkguard:history-updated', reRenderTable);
}
