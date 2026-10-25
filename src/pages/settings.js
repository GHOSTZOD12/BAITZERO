/**
 * pages/settings.js
 * Settings page for desktop security application (Phase 3A).
 * Synchronizes authoritative protection state, desktop notifications, and system specifications.
 */

import { icon } from '../icons.js';
import { clearHistory } from '../storage.js';
import {
  isProtectionActive,
  setProtectionState,
  onProtectionStateChange,
  notifyUser,
  isTauriEnvironment,
} from '../protectionState.js';
import { safeInvoke } from '../tauriBridge.js';
import {
  getListenerStatus,
  requestListenerPermission,
  startNotificationMonitoring,
  stopNotificationMonitoring,
  getIsMonitoring,
} from '../notification/notificationDetector.js';

const DEFAULTS = {
  browserProtection: true,
  clipboardProtection: true,
  notificationProtection: false,
  gmailProtection: false,
  outlookProtection: false,
  notifications: true,
  deepInvestigation: false,
};

const STORAGE_KEY = 'app_settings';

export function loadSettings() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      return { ...DEFAULTS, ...JSON.parse(raw) };
    }
  } catch (_) {
    // Reset silently on corrupt storage
  }
  return { ...DEFAULTS };
}

function saveSettings(settings) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch (_) {
    // Storage quota fallback
  }
}

export function renderSettings() {
  const s = loadSettings();
  const active = isProtectionActive();
  const isTauri = isTauriEnvironment();

  return `
    <main class="page-content" id="page-settings">

      <!-- Page heading -->
      <div class="settings-page-header">
        <div class="settings-page-title">Settings</div>
        <div class="settings-page-sub">Configure protection modules, notifications, and browser integration.</div>
      </div>

      <!-- Two-column balanced settings grid on desktop -->
      <div class="settings-grid-container">

        <!-- Column 1: Core Protection Modules -->
        <div class="settings-col">
          <div class="settings-group">
            <div class="settings-group-header">Protection Modules</div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Real-Time Link Protection</div>
                <div class="settings-row-desc">
                  Master switch: Keeps background protection active and enables automated link safety checks across your system
                </div>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="setting-browser-protection" ${active ? 'checked' : ''} />
                <span class="toggle-track"></span>
                <span class="toggle-thumb"></span>
              </label>
            </div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Clipboard Link Inspection</div>
                <div class="settings-row-desc">
                  Automatically inspects copied links for phishing and spoofing indicators before you paste them into a browser
                </div>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="setting-clipboard-protection" ${s.clipboardProtection !== false ? 'checked' : ''} />
                <span class="toggle-track"></span>
                <span class="toggle-thumb"></span>
              </label>
            </div>

            <div class="settings-row" style="flex-direction: column; align-items: stretch; gap: 10px;">
              <div style="display: flex; align-items: center; justify-content: space-between;">
                <div class="settings-row-info">
                  <div class="settings-row-label">Notification Link Protection</div>
                  <div class="settings-row-desc">
                    Scans links appearing in Windows notifications to detect deceptive destinations before you click them
                  </div>
                </div>
                <label class="toggle-switch">
                  <input type="checkbox" id="setting-notification-protection" ${s.notificationProtection ? 'checked' : ''} />
                  <span class="toggle-track"></span>
                  <span class="toggle-thumb"></span>
                </label>
              </div>
              <div id="notification-perm-box" class="settings-status-panel">
                <div class="settings-status-row">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="settings-status-label">Status</span>
                    <span id="notification-status-text" class="settings-status-value">Checking&hellip;</span>
                  </div>
                  <button class="btn btn-secondary btn-sm" id="btn-request-notification-perm" style="display: none;">
                    Enable Notification Access
                  </button>
                </div>
                <pre id="debug-output" style="display: none; margin: 0; font-size: 10px; color: var(--text-3); white-space: pre-wrap; word-break: break-all; background: var(--bg); border-radius: var(--r-sm); padding: 6px 8px; border: 1px solid var(--border-dim);"></pre>
              </div>
              <div id="notification-explainer" class="notif-explainer-box" style="display: none;">
                Windows notification access allows this app to inspect notification content from other applications so it can detect suspicious links before you open them. Only URLs will be analyzed. Notification text will not be stored.
              </div>
            </div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Deep Investigation Pipeline</div>
                <div class="settings-row-desc">Executes extended multi-layered heuristic analysis for subtle homograph and brand-spoofing signals</div>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="setting-deep-investigation" ${s.deepInvestigation ? 'checked' : ''} />
                <span class="toggle-track"></span>
                <span class="toggle-thumb"></span>
              </label>
            </div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Webmail Link Inspection</div>
                <div class="settings-row-desc">Evaluates incoming webmail hyperlink structures before client-side dispatch</div>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="setting-gmail-protection" ${s.gmailProtection ? 'checked' : ''} />
                <span class="toggle-track"></span>
                <span class="toggle-thumb"></span>
              </label>
            </div>
          </div>
        </div>

        <!-- Column 2: Extension, Notifications & Privacy -->
        <div class="settings-col">

          <!-- Browser Extension Integration — prominent section -->
          <div class="settings-group" id="ext-integration-group">
            <div class="settings-group-header">Browser Extension Integration</div>

            <!-- Live connection status card -->
            <div class="ext-status-card">
              <div class="ext-status-left">
                <div class="ext-status-dot" id="ext-conn-dot"></div>
                <div class="ext-status-texts">
                  <div class="ext-status-head" id="ext-conn-label">Checking&hellip;</div>
                  <div class="ext-status-sub" id="ext-conn-sub">Connecting to local bridge on port 27432</div>
                </div>
              </div>
              <div class="ext-status-right">
                <span class="ext-port-badge">PORT&nbsp;27432</span>
                <button class="btn btn-secondary btn-sm" id="ext-refresh-btn" title="Refresh connection status">
                  ${icon.refresh}
                </button>
              </div>
            </div>

            <!-- Setup guidance steps -->
            <div class="ext-setup-section">
              <div class="ext-setup-heading">Setup</div>
              <ol class="ext-setup-steps">
                <li class="ext-setup-step">
                  <div class="ext-step-num">1</div>
                  <div class="ext-step-body">
                    <div class="ext-step-title">Load the extension in Chrome</div>
                    <div class="ext-step-desc">Open <code>chrome://extensions</code>, enable Developer mode, click <strong>Load unpacked</strong>, and select the <code>browser-extension/</code> folder from this project.</div>
                  </div>
                </li>
                <li class="ext-setup-step">
                  <div class="ext-step-num">2</div>
                  <div class="ext-step-body">
                    <div class="ext-step-title">Copy the security token</div>
                    <div class="ext-step-desc">Click <strong>Copy Token</strong> below. This copies the one-time shared secret that the extension uses to authenticate with the desktop application. The token is never transmitted outside your device.</div>
                  </div>
                </li>
                <li class="ext-setup-step">
                  <div class="ext-step-num">3</div>
                  <div class="ext-step-body">
                    <div class="ext-step-title">Paste the token into the extension popup</div>
                    <div class="ext-step-desc">Click the BaitZero icon in the Chrome toolbar, paste the token in the <em>Extension Auth Token</em> field, and click <strong>Save Token</strong>.</div>
                  </div>
                </li>
                <li class="ext-setup-step">
                  <div class="ext-step-num">4</div>
                  <div class="ext-step-body">
                    <div class="ext-step-title">Verify connection</div>
                    <div class="ext-step-desc">The extension popup should show <strong>Connected — Protection Active</strong>. Navigation events will now be analyzed by the local engine.</div>
                  </div>
                </li>
              </ol>
            </div>

            <!-- Token copy action -->
            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Extension Security Token</div>
                <div class="settings-row-desc" id="settings-token-desc">
                  Copy the shared secret to configure the browser extension. The token is stored locally and is never sent to any external server.
                </div>
              </div>
              <button class="btn btn-secondary btn-sm" id="settings-copy-token-btn">
                ${icon.clipboardPaste}
                <span id="settings-copy-token-label">Copy Token</span>
              </button>
            </div>
          </div>

          <!-- Desktop Notifications & Alerts -->
          <div class="settings-group">
            <div class="settings-group-header">Desktop Notifications &amp; Alerts</div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">System Notifications</div>
                <div class="settings-row-desc">Show desktop notifications when protection state changes or links are flagged</div>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" id="setting-notifications" ${s.notifications ? 'checked' : ''} />
                <span class="toggle-track"></span>
                <span class="toggle-thumb"></span>
              </label>
            </div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Test Notification</div>
                <div class="settings-row-desc">Trigger a test desktop notification to verify native notification delivery</div>
              </div>
              <button class="btn btn-secondary btn-sm" id="settings-test-notification-btn">
                ${icon.sparkles}
                <span>Send Test</span>
              </button>
            </div>
          </div>

          <!-- Data & Privacy -->
          <div class="settings-group">
            <div class="settings-group-header">Data &amp; Privacy</div>

            <div class="settings-row">
              <div class="settings-row-info">
                <div class="settings-row-label">Local Investigation History</div>
                <div class="settings-row-desc">All scan results and evidence logs are stored strictly on this device</div>
              </div>
              <button class="btn btn-danger btn-sm" id="settings-clear-history-btn">
                ${icon.trash}
                <span>Clear History</span>
              </button>
            </div>
          </div>

        </div>
      </div>


      <!-- Advanced Diagnostics (collapsible) -->
      <div class="settings-group">
        <button class="settings-advanced-toggle" id="settings-advanced-toggle" aria-expanded="false">
          <span>Advanced Diagnostics</span>
          <span class="settings-advanced-chevron">${icon.chevronDown}</span>
        </button>
        <div class="settings-advanced-body" id="settings-advanced-body">
          <div class="about-grid">
            <div class="about-cell">
              <div class="about-cell-key">Protection State</div>
              <div class="about-cell-val" id="settings-spec-state" style="color: ${active ? 'var(--risk-low)' : 'var(--text-3)'}; font-weight: 600;">
                ${active ? 'PROTECTION ACTIVE' : 'PROTECTION PAUSED'}
              </div>
            </div>
            <div class="about-cell">
              <div class="about-cell-key">Desktop Shell</div>
              <div class="about-cell-val">${isTauri ? 'Tauri v2 Native Shell' : 'Browser Preview Mode'}</div>
            </div>
            <div class="about-cell">
              <div class="about-cell-key">System Tray</div>
              <div class="about-cell-val">${isTauri ? 'Tauri Native Tray &amp; Minimize-to-Tray' : 'N/A — Desktop only'}</div>
            </div>
            <div class="about-cell">
              <div class="about-cell-key">Clipboard Detection</div>
              <div class="about-cell-val" id="settings-spec-clipboard" style="color: ${active && s.clipboardProtection !== false ? 'var(--risk-low)' : 'var(--text-3)'}; font-weight: 500;">
                ${active && s.clipboardProtection !== false ? 'ACTIVE' : 'PAUSED'}
              </div>
            </div>
            <div class="about-cell">
              <div class="about-cell-key">Analysis Engine</div>
              <div class="about-cell-val">Deterministic Heuristics (14 Rules)</div>
            </div>
            <div class="about-cell">
              <div class="about-cell-key">Extension Bridge</div>
              <div class="about-cell-val" id="settings-spec-bridge">${isTauri ? 'Polling 127.0.0.1:27432' : 'Desktop only'}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Confirmation Modal for Pausing Real-Time Protection -->
      <div id="bz-pause-confirm-modal" class="bz-modal-backdrop" style="display: none;">
        <div class="bz-modal-card" role="alertdialog" aria-modal="true" aria-labelledby="pause-modal-title">
          <div class="bz-modal-header">
            <div class="bz-modal-icon-warning">${icon.alertTriangle}</div>
            <div class="bz-modal-title" id="pause-modal-title">Pause Real-Time Protection?</div>
          </div>
          <div class="bz-modal-body">
            Pausing protection temporarily disables background clipboard inspection and automated link safety alerts. You will still be able to scan links manually in the Analyze URL screen.
          </div>
          <div class="bz-modal-actions">
            <button class="bz-btn-cancel" id="bz-cancel-pause-btn">Keep Protected</button>
            <button class="bz-btn-destructive" id="bz-confirm-pause-btn">Pause Protection</button>
          </div>
        </div>
      </div>

    </main>
  `;
}

export function initSettings() {
  const browserToggle = document.getElementById('setting-browser-protection');
  const clipToggle = document.getElementById('setting-clipboard-protection');
  const deepToggle = document.getElementById('setting-deep-investigation');
  const gmailToggle = document.getElementById('setting-gmail-protection');
  const notifyToggle = document.getElementById('setting-notifications');
  const clearBtn = document.getElementById('settings-clear-history-btn');
  const testNotifyBtn = document.getElementById('settings-test-notification-btn');

  function updateSetting(key, value) {
    const s = loadSettings();
    s[key] = value;
    saveSettings(s);
  }

  function syncClipboardSpec(active) {
    const s = loadSettings();
    const clipSpec = document.getElementById('settings-spec-clipboard');
    if (clipSpec) {
      const isClipActive = active && s.clipboardProtection !== false;
      clipSpec.textContent = isClipActive ? 'ACTIVE' : 'PAUSED';
      clipSpec.style.color = isClipActive ? 'var(--risk-low)' : 'var(--text-3)';
    }
  }

  // Authoritative protection state toggle with confirmation on pause
  if (browserToggle) {
    const pauseModal = document.getElementById('bz-pause-confirm-modal');
    const cancelPauseBtn = document.getElementById('bz-cancel-pause-btn');
    const confirmPauseBtn = document.getElementById('bz-confirm-pause-btn');

    browserToggle.addEventListener('change', e => {
      if (!e.target.checked) {
        // Prevent immediate deactivation; prompt user
        e.target.checked = true;
        if (pauseModal) pauseModal.style.display = 'flex';
      } else {
        setProtectionState(true);
      }
    });

    if (cancelPauseBtn && pauseModal) {
      cancelPauseBtn.addEventListener('click', () => {
        pauseModal.style.display = 'none';
        browserToggle.checked = true;
      });
    }

    if (confirmPauseBtn && pauseModal) {
      confirmPauseBtn.addEventListener('click', () => {
        pauseModal.style.display = 'none';
        browserToggle.checked = false;
        setProtectionState(false);
      });
    }
  }

  if (clipToggle) {
    clipToggle.addEventListener('change', e => {
      updateSetting('clipboardProtection', e.target.checked);
      syncClipboardSpec(isProtectionActive());
    });
  }

  // Notification Link Protection (Phase 3B-3)
  const notifToggle = document.getElementById('setting-notification-protection');
  const notifStatusText = document.getElementById('notification-status-text');
  const notifPermBtn = document.getElementById('btn-request-notification-perm');
  const notifExplainer = document.getElementById('notification-explainer');

  async function refreshNotificationStatus(preserveDebug = false, errorMsg = null) {
    if (!notifStatusText) return;
    const statusObj = await getListenerStatus();
    const status = statusObj.status;

    // Log every status poll so the exact returned values are visible in DevTools
    console.warn(
      '[NotifStatus] getListenerStatus() returned:',
      'status=' + status,
      '| granted=' + statusObj.granted,
      '| package_identity=' + statusObj.package_identity,
      '| raw_status=' + statusObj.raw_status,
      '| message=' + statusObj.message
    );

    // Show raw diagnostic in debug panel only for error conditions, not normal statuses
    const debugDiv = document.getElementById('debug-output');
    const isErrorStatus = status === 'error' || status === 'permission_denied';
    if (debugDiv && !preserveDebug && isErrorStatus) {
      debugDiv.textContent = JSON.stringify(statusObj, null, 2);
      debugDiv.style.display = 'block';
    } else if (debugDiv && !preserveDebug) {
      debugDiv.textContent = '';
      debugDiv.style.display = 'none';
    }

    if (errorMsg) {
      notifStatusText.textContent = errorMsg;
      notifStatusText.style.color = 'var(--risk-high)';
      if (notifToggle) notifToggle.checked = false;
      return;
    }

    if (status === 'enabled') {
      const monitoringActive = getIsMonitoring();
      console.warn('[NotifStatus] Permission is enabled. getIsMonitoring()=' + monitoringActive);
      notifStatusText.textContent = monitoringActive
        ? 'Protected — Monitoring Active'
        : 'Allowed — Monitoring Inactive';
      notifStatusText.style.color = monitoringActive ? 'var(--risk-low)' : 'var(--risk-med)';
      if (notifToggle) notifToggle.checked = monitoringActive;
      if (notifPermBtn) notifPermBtn.style.display = 'none';
      if (notifExplainer) notifExplainer.style.display = 'none';

    } else if (status === 'permission_denied') {
      notifStatusText.textContent =
        'Denied (raw_status: ' + (statusObj.raw_status ?? '?') + ') — enable in Windows Settings \u2192 Notifications';
      notifStatusText.style.color = 'var(--risk-high)';
      if (notifToggle) notifToggle.checked = false;
      if (notifPermBtn) {
        notifPermBtn.style.display = 'inline-block';
        notifPermBtn.textContent = 'Retry Access';
      }

    } else if (status === 'not_available') {
      notifStatusText.textContent = 'Not available — Windows only';
      notifStatusText.style.color = 'var(--text-3)';
      if (notifToggle) notifToggle.checked = false;
      if (notifPermBtn) notifPermBtn.style.display = 'none';

    } else if (status === 'error') {
      const hresult = statusObj.hresult ? ' HRESULT: ' + statusObj.hresult : '';
      notifStatusText.textContent = 'Error' + hresult;
      notifStatusText.style.color = 'var(--risk-high)';
      if (notifToggle) notifToggle.checked = false;
      if (notifPermBtn) notifPermBtn.style.display = 'none';

    } else {
      // permission_required — two distinct sub-cases:
      // (a) package_identity: false  →  running unpackaged; MSIX install is required; button cannot help
      // (b) package_identity: true   →  packaged but not yet granted; show Enable button
      const hasIdentity = statusObj.package_identity === true;
      if (notifToggle) notifToggle.checked = false;
      if (!hasIdentity) {
        // Unpackaged mode: the Windows permission switch in Settings cannot be seen by this exe.
        // Clicking "Enable" would call RequestAccessAsync which immediately returns Unspecified
        // because there is no package identity for the OS to associate the permission with.
        console.warn('[NotifStatus] package_identity=false → running unpackaged. MSIX install required.');
        notifStatusText.textContent =
          'Requires MSIX package — run the installed app for notification access';
        notifStatusText.style.color = 'var(--risk-med)';
        if (notifPermBtn) notifPermBtn.style.display = 'none';
      } else {
        // Packaged but not yet granted
        const raw = statusObj.raw_status !== undefined && statusObj.raw_status !== null
          ? ' (raw_status: ' + statusObj.raw_status + ')' : '';
        notifStatusText.textContent = 'Permission required' + raw;
        notifStatusText.style.color = 'var(--risk-med)';
        if (notifPermBtn) {
          notifPermBtn.style.display = 'inline-block';
          notifPermBtn.textContent = 'Enable Notification Access';
        }
      }
    }
  }

  if (notifToggle) {
    notifToggle.addEventListener('change', async e => {
      const wantEnabled = e.target.checked;
      notifToggle.disabled = true;

      try {
        if (wantEnabled) {
          if (notifExplainer) notifExplainer.style.display = 'block';
          const statusObj = await getListenerStatus();
          console.warn(
            '[NotifToggle] Toggle turned ON. getListenerStatus():',
            'status=' + statusObj.status,
            '| granted=' + statusObj.granted,
            '| package_identity=' + statusObj.package_identity
          );

          if (statusObj.status !== 'enabled') {
            notifToggle.checked = false;
            updateSetting('notificationProtection', false);
            const reason = statusObj.package_identity === false
              ? 'Requires MSIX package — run the installed app for notification access'
              : (statusObj.message || 'Notification access not granted in Windows Settings.');
            console.warn(
              '[NotifToggle] Blocked: status is not enabled.',
              'package_identity=' + statusObj.package_identity,
              'message=' + statusObj.message
            );
            await refreshNotificationStatus(false, reason);
            return;
          }

          if (notifStatusText) {
            notifStatusText.textContent = 'Starting monitoring…';
            notifStatusText.style.color = 'var(--text-2)';
          }

          console.warn('[NotifToggle] Permission confirmed enabled. Calling startNotificationMonitoring().');
          const res = await startNotificationMonitoring();
          console.warn(
            '[NotifToggle] startNotificationMonitoring() returned:',
            'success=' + res?.success,
            '| alreadyRunning=' + res?.alreadyRunning,
            '| error=' + res?.error
          );

          if (!res?.success) {
            notifToggle.checked = false;
            updateSetting('notificationProtection', false);
            const errMsg = res?.error || 'Failed to start listener.';
            console.warn('[NotifToggle] Startup failed, displaying error:', errMsg);
            const debugDiv = document.getElementById('debug-output');
            if (debugDiv) {
              debugDiv.textContent = JSON.stringify({
                stage: 'startNotificationMonitoring failed',
                error: errMsg,
                statusObj,
              }, null, 2);
              debugDiv.style.display = 'block';
            }
            await refreshNotificationStatus(true, errMsg);
            return;
          }

          // Startup succeeded: commit setting and update UI
          updateSetting('notificationProtection', true);
          await refreshNotificationStatus();
        } else {
          console.warn('[NotifToggle] Toggle turned OFF. Stopping monitoring.');
          updateSetting('notificationProtection', false);
          await stopNotificationMonitoring();
          if (notifExplainer) notifExplainer.style.display = 'none';
          await refreshNotificationStatus();
        }
      } catch (err) {
        console.error('[NotifToggle] Unexpected error in toggle handler:', err);
        notifToggle.checked = false;
        updateSetting('notificationProtection', false);
        await refreshNotificationStatus(false, err?.message || String(err));
      } finally {
        notifToggle.disabled = false;
      }
    });
  }


  if (notifPermBtn) {
    notifPermBtn.addEventListener('click', async () => {
      const debugDiv = document.getElementById('debug-output');

      const showDebug = (data) => {
        if (debugDiv) {
          debugDiv.style.display = 'block';
          debugDiv.textContent = JSON.stringify(data, null, 2);
        }
      };

      notifPermBtn.disabled = true;
      notifPermBtn.textContent = 'Requesting…';

      // Show progress immediately, not only after the Windows call finishes.
      showDebug({ stage: 'Starting permission request…' });

      if (notifExplainer) notifExplainer.style.display = 'block';

      try {
        showDebug({ stage: 'Checking current Windows permission…' });
        const before = await getListenerStatus();

        showDebug({
          stage: 'Calling Windows permission request…',
          before
        });

        const result = await requestListenerPermission();

        showDebug({
          stage: 'Permission request returned',
          before,
          result
        });

        const after = await getListenerStatus();

        showDebug({
          stage: 'Permission status refreshed',
          before,
          result,
          after
        });

        const granted = result?.status === 'enabled' ||
          result?.granted === true ||
          after?.status === 'enabled';

        if (notifToggle) notifToggle.checked = granted;
        updateSetting('notificationProtection', granted);

        if (granted) {
          const res = await startNotificationMonitoring();
          if (!res?.success) {
            if (notifToggle) notifToggle.checked = false;
            updateSetting('notificationProtection', false);
            const errMsg = res?.error || 'Permission granted, but listener failed to start.';
            await refreshNotificationStatus(true, errMsg);
          } else {
            if (notifToggle) notifToggle.checked = true;
            updateSetting('notificationProtection', true);
            await refreshNotificationStatus(true);
          }
        } else {
          if (notifToggle) notifToggle.checked = false;
          updateSetting('notificationProtection', false);
          await stopNotificationMonitoring();
          await refreshNotificationStatus(true);
        }
      } catch (error) {
        showDebug({
          stage: 'Permission request failed',
          error: String(error),
          stack: error?.stack ?? null
        });

        if (notifToggle) notifToggle.checked = false;
        updateSetting('notificationProtection', false);
        stopNotificationMonitoring();

        if (notifStatusText) {
          notifStatusText.textContent = 'Permission request failed — see diagnostics below.';
          notifStatusText.style.color = 'var(--risk-high)';
        }
      } finally {
        notifPermBtn.disabled = false;
        notifPermBtn.textContent = 'Enable Notification Access';
      }
    });
  }


  refreshNotificationStatus();

  // Subscribe to changes from any source (tray, sidebar, or other components)
  onProtectionStateChange((state, active) => {
    if (browserToggle) {
      browserToggle.checked = active;
    }
    const specState = document.getElementById('settings-spec-state');
    if (specState) {
      specState.textContent = active ? 'PROTECTION ACTIVE' : 'PROTECTION PAUSED';
      specState.style.color = active ? 'var(--risk-low)' : 'var(--text-3)';
    }
    syncClipboardSpec(active);
  });

  if (deepToggle) {
    deepToggle.addEventListener('change', e => {
      updateSetting('deepInvestigation', e.target.checked);
    });
  }

  if (gmailToggle) {
    gmailToggle.addEventListener('change', e => {
      updateSetting('gmailProtection', e.target.checked);
    });
  }

  if (notifyToggle) {
    notifyToggle.addEventListener('change', e => {
      updateSetting('notifications', e.target.checked);
    });
  }

  // Test Notification Foundation (Phase 3A)
  if (testNotifyBtn) {
    testNotifyBtn.addEventListener('click', async () => {
      testNotifyBtn.disabled = true;
      testNotifyBtn.classList.add('loading');
      await notifyUser('Protection Active', 'Desktop protection is running.');
      testNotifyBtn.disabled = false;
      testNotifyBtn.classList.remove('loading');
    });
  }

  // Extension Token Copy Handler (Phase 3B-2 & Phase 2B Hardening)
  const copyTokenBtn = document.getElementById('settings-copy-token-btn');
  const copyTokenLabel = document.getElementById('settings-copy-token-label');

  if (copyTokenBtn) {
    copyTokenBtn.addEventListener('click', async () => {
      let token = '';
      if (isTauriEnvironment()) {
        try {
          const info = await safeInvoke('get_extension_server_info');
          if (info?.token && typeof info.token === 'string' && info.token.trim().length === 64) {
            token = info.token.trim();
          }
        } catch (_) { }
      }

      if (token) {
        try {
          await navigator.clipboard.writeText(token);
          if (copyTokenLabel) copyTokenLabel.textContent = 'Copied!';
          setTimeout(() => {
            if (copyTokenLabel) copyTokenLabel.textContent = 'Copy Token';
          }, 2000);
        } catch (_) {
          if (copyTokenLabel) copyTokenLabel.textContent = 'Copy Failed';
          setTimeout(() => {
            if (copyTokenLabel) copyTokenLabel.textContent = 'Copy Token';
          }, 2000);
        }
      } else {
        if (copyTokenLabel) copyTokenLabel.textContent = isTauriEnvironment() ? 'Unavailable' : 'Desktop only';
        setTimeout(() => {
          if (copyTokenLabel) copyTokenLabel.textContent = 'Copy Token';
        }, 2000);
      }
    });
  }

  // Live Extension Bridge Status Checker (Phase 2B Authenticated Verification)
  const extConnDot = document.getElementById('ext-conn-dot');
  const extConnLabel = document.getElementById('ext-conn-label');
  const extConnSub = document.getElementById('ext-conn-sub');
  const extRefreshBtn = document.getElementById('ext-refresh-btn');

  async function checkExtensionStatus() {
    if (extConnLabel) extConnLabel.textContent = 'Checking bridge…';
    if (extConnSub) extConnSub.textContent = 'Connecting to 127.0.0.1:27432…';
    if (extConnDot) {
      extConnDot.className = 'ext-status-dot';
    }

    try {
      // 1. In Tauri environment: verify through authenticated native command and socket probe
      if (isTauriEnvironment()) {
        let serverInfo = null;
        try {
          serverInfo = await safeInvoke('get_extension_server_info');
        } catch (_) { }

        if (serverInfo && serverInfo.token) {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);
          try {
            const res = await fetch(`http://127.0.0.1:${serverInfo.port || 27432}/status`, {
              method: 'GET',
              headers: {
                'X-Extension-Token': serverInfo.token,
              },
              credentials: 'omit',
              signal: controller.signal,
            });
            clearTimeout(timeoutId);

            if (res.ok) {
              const data = await res.json();
              if (extConnDot) {
                extConnDot.className = 'ext-status-dot active';
              }
              if (extConnLabel) extConnLabel.textContent = 'Bridge Connected — Port 27432';
              if (extConnSub) {
                extConnSub.textContent = data.protectionActive !== false
                  ? 'Local bridge listening • Real-time link inspection active'
                  : 'Local bridge listening • Desktop protection paused';
              }
              return;
            }
          } catch (_) {
            clearTimeout(timeoutId);
          }
        }
      } else {
        // 2. In Browser Preview Mode: check if local bridge is reachable on 127.0.0.1:27432
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        try {
          const res = await fetch('http://127.0.0.1:27432/status', { credentials: 'omit', signal: controller.signal });
          clearTimeout(timeoutId);

          if (res.status === 401) {
            // Bridge is listening and properly enforcing authentication
            if (extConnDot) {
              extConnDot.className = 'ext-status-dot standby';
            }
            if (extConnLabel) extConnLabel.textContent = 'Authentication Required — Port 27432';
            if (extConnSub) {
              extConnSub.textContent = 'Bridge listening • Access restricted to authenticated clients';
            }
            return;
          } else if (res.ok) {
            const data = await res.json();
            if (extConnDot) {
              extConnDot.className = 'ext-status-dot active';
            }
            if (extConnLabel) extConnLabel.textContent = 'Bridge Connected — Port 27432';
            if (extConnSub) {
              extConnSub.textContent = data.protectionActive !== false
                ? 'Local bridge listening • Real-time link inspection active'
                : 'Local bridge listening • Desktop protection paused';
            }
            return;
          }
        } catch (_) {
          clearTimeout(timeoutId);
        }
      }
    } catch (_) {
      // Bridge is not running or unreachable
    }

    if (extConnDot) {
      extConnDot.className = 'ext-status-dot standby';
    }
    if (extConnLabel) extConnLabel.textContent = 'Bridge Disconnected';
    if (extConnSub) {
      extConnSub.textContent = 'Desktop background bridge not detected on port 27432';
    }
  }

  if (extRefreshBtn) {
    extRefreshBtn.addEventListener('click', () => {
      checkExtensionStatus();
    });
  }

  checkExtensionStatus();

  // Collapsible Advanced Diagnostics Handler
  const advToggle = document.getElementById('settings-advanced-toggle');
  const advBody = document.getElementById('settings-advanced-body');
  if (advToggle && advBody) {
    advToggle.addEventListener('click', () => {
      const isExpanded = advToggle.getAttribute('aria-expanded') === 'true';
      advToggle.setAttribute('aria-expanded', String(!isExpanded));
      advBody.classList.toggle('open', !isExpanded);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (window.confirm('Clear all local investigation records?')) {
        clearHistory();
        clearBtn.textContent = 'Cleared';
        clearBtn.disabled = true;
        setTimeout(() => {
          clearBtn.innerHTML = `${icon.trash} <span>Clear History</span>`;
          clearBtn.disabled = false;
        }, 1500);
      }
    });
  }
}


