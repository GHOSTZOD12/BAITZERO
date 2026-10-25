/**
 * tauriBridge.js
 * Centralized, secure abstraction for Tauri v2 IPC commands and events.
 *
 * Replaces direct global window.__TAURI__ access with official @tauri-apps/api
 * module imports, allowing withGlobalTauri to be disabled.
 */

import { invoke, isTauri as coreIsTauri } from '@tauri-apps/api/core';
import { listen as coreListen, emit as coreEmit } from '@tauri-apps/api/event';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';

/**
 * Returns true if running inside a Tauri application context.
 * Uses official core isTauri check with safe fallback for non-browser/test environments.
 * @returns {boolean}
 */
export function isTauri() {
  try {
    if (typeof window === 'undefined') return false;
    return Boolean(coreIsTauri());
  } catch (_) {
    return false;
  }
}

/**
 * Safely invokes a native Tauri command.
 * Rejects with the backend error if inside Tauri and the command fails.
 * Returns null if outside Tauri.
 *
 * @param {string} cmd
 * @param {Record<string, any>} [args={}]
 * @returns {Promise<any>}
 */
export async function invokeCommand(cmd, args = {}) {
  if (!isTauri()) {
    return null;
  }
  try {
    return await invoke(cmd, args);
  } catch (err) {
    console.warn(`[TauriBridge] Command '${cmd}' error:`, err);
    throw err;
  }
}

/**
 * Safely invokes a native Tauri command, catching and returning fallback rather than throwing.
 *
 * @param {string} cmd
 * @param {Record<string, any>} [args={}]
 * @param {any} [fallback=null]
 * @returns {Promise<any>}
 */
export async function safeInvoke(cmd, args = {}, fallback = null) {
  if (!isTauri()) {
    return fallback;
  }
  try {
    return await invoke(cmd, args);
  } catch (err) {
    console.warn(`[TauriBridge] safeInvoke '${cmd}' warning:`, err);
    return fallback;
  }
}

/**
 * Registers an event listener on the Tauri event system.
 * Returns an unlisten function for proper lifecycle cleanup, or a no-op if outside Tauri.
 *
 * @param {string} event
 * @param {(event: { payload: any }) => void} handler
 * @returns {Promise<() => void>} Unlisten function
 */
export async function listenEvent(event, handler) {
  if (!isTauri()) {
    return () => {};
  }
  try {
    return await coreListen(event, handler);
  } catch (err) {
    console.warn(`[TauriBridge] listen '${event}' error:`, err);
    return () => {};
  }
}

/**
 * Emits an event to the Tauri event system.
 *
 * @param {string} event
 * @param {any} [payload]
 * @returns {Promise<void>}
 */
export async function emitEvent(event, payload) {
  if (!isTauri()) {
    return;
  }
  try {
    await coreEmit(event, payload);
  } catch (err) {
    console.warn(`[TauriBridge] emit '${event}' error:`, err);
  }
}

/**
 * Determines whether the current window context is the 'alert' floating window.
 * Checks URL route hash ('#/alert') first, with fallback to official WebviewWindow label.
 *
 * @returns {boolean}
 */
export function isAlertWindow() {
  if (typeof window !== 'undefined' && window.location?.hash?.startsWith('#/alert')) {
    return true;
  }
  if (isTauri()) {
    try {
      const current = getCurrentWebviewWindow();
      return current?.label === 'alert';
    } catch (_) {}
  }
  return false;
}
