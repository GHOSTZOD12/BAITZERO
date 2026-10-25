/**
 * router.js
 * Lightweight hash-based client-side router.
 * Routes are registered with a path and a render function.
 * On hash change, the matching render function is called and its
 * returned HTML is injected into the content container.
 *
 * Design decision: Hash-based routing requires no server configuration,
 * works with file:// if needed, and is trivial to explain in a BCA presentation.
 *
 * Supports multiple onNavigate listeners (upgraded from single callback).
 */

const routes = new Map();
let contentEl = null;
const onNavigateCallbacks = [];

/**
 * Register a route.
 * @param {string} path - Hash path, e.g. '#/dashboard'
 * @param {function(): string} renderFn - Returns HTML string for the page
 */
export function addRoute(path, renderFn) {
  routes.set(path, renderFn);
}

/**
 * Register a callback that fires on every navigation.
 * Multiple calls are additive — all registered callbacks will fire.
 * @param {function(path: string): void} cb
 */
export function onNavigate(cb) {
  if (typeof cb === 'function') {
    onNavigateCallbacks.push(cb);
  }
}

/**
 * Navigate to a given hash path programmatically.
 * @param {string} path
 */
export function navigate(path) {
  window.location.hash = path;
}

/**
 * Return current active route path.
 * @returns {string}
 */
export function currentRoute() {
  return window.location.hash || '#/dashboard';
}

/**
 * Initialize the router. Must be called once on app start.
 * @param {HTMLElement} el - The element into which page content is rendered
 */
export function initRouter(el) {
  contentEl = el;

  window.addEventListener('hashchange', resolve);
  resolve(); // Render the initial route
}

function resolve() {
  if (!contentEl) return;

  const path = window.location.hash || '#/dashboard';
  const renderFn = routes.get(path);

  if (!renderFn) {
    // Fallback: redirect to dashboard if route not found
    navigate('#/dashboard');
    return;
  }

  // Render page content
  contentEl.innerHTML = renderFn();

  // Add entrance animation
  const pageEl = contentEl.querySelector('.page-content');
  if (pageEl) {
    pageEl.classList.add('page-enter');
  }

  // Notify all registered listeners about the new route
  onNavigateCallbacks.forEach(cb => cb(path));

  // Scroll content area to top
  contentEl.scrollTop = 0;
}
