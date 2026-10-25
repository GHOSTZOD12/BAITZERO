/**
 * protectionState.js
 * Authoritative Protection State & Desktop Bridge (Phase 3A).
 *
 * Responsibilities:
 * 1. Single authoritative state: 'ACTIVE' or 'PAUSED'
 * 2. Synchronizes Settings, Sidebar, Topbar, Overview, and Tauri System Tray
 * 3. Persists state locally via storage
 * 4. Provides native/desktop notification foundation (notifyUser)
 * 5. Handles Tauri IPC events gracefully with browser fallback
 */

import { navigate } from './router.js';

export const ProtectionStatus = {
  ACTIVE: 'ACTIVE',
  PAUSED: 'PAUSED',
};

const STORAGE_KEY = 'app_settings';
let currentState = ProtectionStatus.ACTIVE;
const listeners = new Set();

import { isTauri, safeInvoke, listenEvent } from './tauriBridge.js';

/**
 * Check if the application is running inside a Tauri shell.
 */
export function isTauriEnvironment() {
  return isTauri();
}

/**
 * Invoke a Tauri IPC command safely.
 */
async function invokeTauri(cmd, args = {}) {
  return await safeInvoke(cmd, args);
}

/**
 * Get current authoritative protection state string.
 * @returns {'ACTIVE' | 'PAUSED'}
 */
export function getProtectionState() {
  return currentState;
}

/**
 * Check if protection is currently active.
 * @returns {boolean}
 */
export function isProtectionActive() {
  return currentState === ProtectionStatus.ACTIVE;
}

/**
 * Subscribe to protection state changes.
 * @param {function(state: 'ACTIVE' | 'PAUSED', active: boolean): void} callback
 * @returns {function(): void} unsubscribe function
 */
export function onProtectionStateChange(callback) {
  listeners.add(callback);
  return () => listeners.delete(callback);
}

/**
 * Set the authoritative protection state.
 * Syncs local storage, all UI subscribers, and the Tauri system tray.
 *
 * @param {'ACTIVE' | 'PAUSED' | boolean} newStateOrBool
 * @param {boolean} [syncToBackend=true]
 */
export function setProtectionState(newStateOrBool, syncToBackend = true) {
  let newState;
  if (typeof newStateOrBool === 'boolean') {
    newState = newStateOrBool ? ProtectionStatus.ACTIVE : ProtectionStatus.PAUSED;
  } else {
    newState = newStateOrBool === ProtectionStatus.ACTIVE ? ProtectionStatus.ACTIVE : ProtectionStatus.PAUSED;
  }

  const previousState = currentState;
  currentState = newState;
  const active = currentState === ProtectionStatus.ACTIVE;

  // Persist to local storage
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const settings = raw ? JSON.parse(raw) : {};
    settings.browserProtection = active;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch (err) {
    console.warn('[Storage] Failed to save protection state:', err);
  }

  // Sync to Tauri native tray / backend
  if (syncToBackend && isTauriEnvironment()) {
    invokeTauri('set_protection_state', { active });
  }

  // Notify all UI listeners
  listeners.forEach(fn => {
    try {
      fn(currentState, active);
    } catch (e) {
      console.error('[ProtectionState] Listener error:', e);
    }
  });

  return currentState;
}

/**
 * Toggle the protection state between ACTIVE and PAUSED.
 */
export function toggleProtectionState() {
  return setProtectionState(currentState !== ProtectionStatus.ACTIVE);
}

/**
 * Desktop Notification Foundation (Phase 3A).
 * Native OS notification via Tauri, with HTML5 Notification & in-app fallback.
 *
 * @param {string} title
 * @param {string} body
 * @param {object|string} [options={}] - Options object or source string ('security' | 'clipboard')
 */
export async function notifyUser(title, body, options = {}) {
  const source = typeof options === 'string'
    ? options
    : (options?.source || options?.eventType || 'security');

  const isClipboardEvent = source.trim().toLowerCase() === 'clipboard';
  const tStart = performance.now();
  console.warn(`[UI-DIAG] notifyUser invocation started | title="${title}" | source="${source}" | isTauri=${isTauriEnvironment()} | notifPerm=${typeof Notification !== 'undefined' ? Notification.permission : 'n/a'}`);

  // 1. Display in-app desktop banner toast immediately (so user always gets instant visual feedback)
  showInAppToast(title, body);

  // 2. Mode B: Clipboard events strictly suppress native Windows toasts
  if (isClipboardEvent) {
    console.warn(`[UI-DIAG] Native Windows toast suppressed for clipboard event: title="${title}"`);
    return;
  }

  // 3. If running under Tauri native shell, dispatch to native notification system
  if (isTauriEnvironment()) {
    console.warn(`[UI-DIAG] Native toast API call start (invoking 'notify_user') | source=${source}`);
    try {
      await safeInvoke('notify_user', { title, body, source });
      const elapsed = performance.now() - tStart;
      console.warn(`[UI-DIAG] Native toast API call end (invoking 'notify_user' completed in +${elapsed.toFixed(2)}ms)`);
    } catch (err) {
      console.error(`[UI-DIAG] Native toast API error:`, err);
    }
  }

  // 4. Browser standard notification API fallback only when NOT running under Tauri and permission already granted
  // Never prompt for permission automatically during background clipboard/notification events
  else if (typeof window !== 'undefined' && 'Notification' in window) {
    if (Notification.permission === 'granted') {
      try {
        console.warn(`[UI-DIAG] HTML5 Notification dispatched (permission already granted)`);
        new Notification(title, { body, icon: '/favicon.svg' });
      } catch (_) {
        // Ignored if notifications blocked in browser frame
      }
    }
  }
}

/**
 * Non-intrusive desktop toast alert.
 */
function showInAppToast(title, body) {
  console.warn(`[UI-DIAG] Notification UI render started | title="${title}"`);
  let container = document.getElementById('desktop-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'desktop-toast-container';
    container.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 99999;
      display: flex;
      flex-direction: column;
      gap: 8px;
      pointer-events: none;
    `;
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'desktop-toast';
  toast.style.cssText = `
    background: #151a21;
    border: 1px solid #252c35;
    border-left: 3px solid #3b82f6;
    border-radius: 6px;
    padding: 10px 14px;
    color: #f1f4f7;
    font-size: 13px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.5);
    max-width: 320px;
    animation: toastIn 180ms ease;
    pointer-events: auto;
  `;
  toast.innerHTML = `
    <div style="font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #3b82f6; margin-bottom: 2px;">
      ${escapeHtml(title)}
    </div>
    <div style="color: #929ba8; font-size: 12px; line-height: 1.4;">
      ${escapeHtml(body)}
    </div>
  `;

  container.appendChild(toast);
  console.warn(`[UI-DIAG] Notification UI render completed | toast appended to container (childCount=${container.children.length})`);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(4px)';
    toast.style.transition = 'opacity 200ms ease, transform 200ms ease';
    setTimeout(() => toast.remove(), 220);
  }, 4000);
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

/**
 * Initialize protection state on app startup.
 */
export function initProtectionState() {
  // Read local storage initial state
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const settings = JSON.parse(raw);
      if (settings.browserProtection === false) {
        currentState = ProtectionStatus.PAUSED;
      } else {
        currentState = ProtectionStatus.ACTIVE;
      }
    }
  } catch (_) {
    currentState = ProtectionStatus.ACTIVE;
  }

  // Setup Tauri event listeners if inside Tauri
  if (isTauriEnvironment()) {
    // Sync initial state to native backend / tray
    invokeTauri('set_protection_state', { active: currentState === ProtectionStatus.ACTIVE });

    try {
      listenEvent('protection-state-changed', (event) => {
        const active = !!event.payload;
        setProtectionState(active ? ProtectionStatus.ACTIVE : ProtectionStatus.PAUSED, false);
      });

      listenEvent('navigate-to', (event) => {
        if (event.payload) {
          navigate(event.payload);
        }
      });

      listenEvent('desktop-notification', (event) => {
        console.warn(`[UI-DIAG] Notification listener received (Tauri desktop-notification) | title="${event?.payload?.title}"`);
      });
    } catch (e) {
      console.warn('[Tauri Listeners] setup warning:', e);
    }
  }

  return currentState;
}
