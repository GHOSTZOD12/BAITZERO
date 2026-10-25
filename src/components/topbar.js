/**
 * components/topbar.js
 * No-op module — the BaitZero reference design uses a sidebar-only layout.
 * renderTopbar() returns an empty string; initTopbar() is a no-op.
 * The module is retained so main.js imports do not break.
 */

export function renderTopbar() {
  return '';
}

export function initTopbar() {
  // No-op: topbar removed in BaitZero reference design
}
