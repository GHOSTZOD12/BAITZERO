/**
 * main.js
 * Application entry point.
 *
 * Responsibilities:
 * 1. Import global styles
 * 2. Build the app shell (sidebar + topbar + content area)
 * 3. Register routes
 * 4. Initialize the router (renders first page)
 * 5. Signal Tauri that the frontend is ready (shows the window)
 * 6. Start background protection services (deferred off critical path)
 *
 * The page-specific init functions (initDashboard, initAnalyze, etc.)
 * are called after each navigation via the router's onNavigate hook,
 * because the DOM for a page only exists after it has been rendered.
 */

import './style.css';

import { addRoute, initRouter, onNavigate } from './router.js';
import { renderSidebar, initNavbar }        from './components/navbar.js';
import { renderTopbar, initTopbar }         from './components/topbar.js';
import { initProtectionState }              from './protectionState.js';
import { initClipboardDetector }            from './clipboardDetector.js';
import { initExtensionBridge }              from './extensionBridge.js';
import { initNotificationDetector }         from './notification/notificationDetector.js';

import { renderDashboard, initDashboard }   from './pages/dashboard.js';
import { renderAnalyze, initAnalyze }       from './pages/analyze.js';
import { renderHistory, initHistory }       from './pages/history.js';
import { renderSettings, initSettings }     from './pages/settings.js';
import { renderDeepResearch, initDeepResearch } from './pages/deepResearch.js';
import { renderFloatingAlert, initFloatingAlert } from './components/floatingAlert.js';

/** Map of route paths to their (render, init) pairs */
const pageModules = {
  '#/dashboard':      { render: renderDashboard,    init: initDashboard    },
  '#/analyze':        { render: renderAnalyze,       init: initAnalyze      },
  '#/history':        { render: renderHistory,       init: initHistory      },
  '#/settings':       { render: renderSettings,      init: initSettings     },
  '#/deep-research':  { render: renderDeepResearch,  init: initDeepResearch },
};

import { safeInvoke, listenEvent, isTauri, isAlertWindow } from './tauriBridge.js';

function bootstrap() {
  const t0 = performance.now();
  console.warn(`[STARTUP][TIMING] bootstrap() entry | t=${t0.toFixed(2)}ms`);

  const appEl = document.getElementById('app');
  if (!appEl) return;

  // Dedicated branch for the compact floating alert window
  if (isAlertWindow()) {
    document.body.classList.add('floating-alert-mode');
    appEl.innerHTML = renderFloatingAlert();
    initFloatingAlert();
    console.warn('[FloatingAlert] Alert window bootstrapped.');
    return;
  }

  // ── CRITICAL PATH: render shell ───────────────────────────────────────────
  // Build the app shell (sidebar + topbar + content area) synchronously so
  // the first frame can paint as quickly as possible.
  appEl.innerHTML = `
    ${renderSidebar()}

    <div class="main-wrapper">
      ${renderTopbar()}
      <div id="page-root" style="overflow-y: auto; flex: 1;"></div>
    </div>
  `;

  const pageRoot = document.getElementById('page-root');

  // Register routes
  Object.entries(pageModules).forEach(([path, { render }]) => {
    addRoute(path, render);
  });

  // Call page init after each navigation
  onNavigate(path => {
    const module = pageModules[path];
    if (module?.init) {
      module.init();
    }
  });

  // Initialize nav components
  initNavbar();
  initTopbar();

  // Start router: renders first page and attaches navigation listeners
  initRouter(pageRoot);

  // Initialize protection state early so tray/sidebar show correct status
  initProtectionState();

  const tShellReady = performance.now();
  console.warn(`[STARTUP][TIMING] shell + first page rendered | elapsed=+${(tShellReady - t0).toFixed(2)}ms`);

  // ── SIGNAL TAURI: window can now be shown ─────────────────────────────────
  // Tell Rust that the frontend is ready and flush any queued navigation.
  // Uses a retry loop to ensure IPC bridge is ready.
  if (isTauri()) {
    const emitFrontendReady = async (maxAttempts = 15) => {
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const res = await safeInvoke('frontend_ready');
          if (res !== null) {
            console.warn(`[STARTUP][TIMING] frontend_ready acknowledged by Rust (attempt ${attempt}) | elapsed=+${(performance.now() - t0).toFixed(2)}ms`);
            return;
          }
        } catch (e) {
          console.warn(`[Startup] frontend_ready attempt ${attempt} warning:`, e);
        }
        await new Promise(r => setTimeout(r, 40));
      }
    };
    emitFrontendReady();

    // Listen for direct navigation when user clicks floating alert
    listenEvent('open-url-in-analyze', (event) => {
      const url = event?.payload?.url;
      if (url) {
        sessionStorage.setItem('pendingAnalysisUrl', url);
        if (window.location.hash === '#/analyze') {
          const input = document.getElementById('analyze-url-input');
          const submitBtn = document.getElementById('analyze-submit-btn');
          if (input && submitBtn) {
            input.value = url;
            submitBtn.click();
          }
        } else {
          window.location.hash = '#/analyze';
        }
      }
    });
  }

  // ── DEFERRED: start background protection services ────────────────────────
  // These do not need to complete before the window is usable.
  // Using setTimeout(0) yields to the browser so the first paint completes
  // before any background IPC/event-listener work begins.
  setTimeout(() => {
    const tDeferred = performance.now();
    console.warn(`[STARTUP][TIMING] deferred background init started | elapsed=+${(tDeferred - t0).toFixed(2)}ms`);

    // Real-time clipboard link detector (Phase 3B-1)
    initClipboardDetector();

    // Browser extension IPC bridge (Phase 3B-2)
    initExtensionBridge();

    // Windows notification link detector (Phase 3B-3)
    initNotificationDetector();

    console.warn(`[STARTUP][TIMING] deferred background init complete | elapsed=+${(performance.now() - t0).toFixed(2)}ms`);
  }, 0);
}

// Run once the DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
