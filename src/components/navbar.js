/**
 * components/navbar.js
 * BaitZero reference-matched sidebar navigation.
 * Squircle glowing logo, exact tagline, reference-accurate nav items & active states,
 * and bottom Protection Active card with chevron.
 */

import { icon } from '../icons.js';
import { navigate, onNavigate, currentRoute } from '../router.js';
import { isProtectionActive, onProtectionStateChange } from '../protectionState.js';

const navItems = [
  { id: 'nav-overview',       path: '#/dashboard',     label: 'Dashboard',      icon: icon.home },
  { id: 'nav-analyze',        path: '#/analyze',        label: 'Analyze URL',    icon: icon.search },
  { id: 'nav-history',        path: '#/history',        label: 'History',        icon: icon.history },
  { id: 'nav-deep-research',  path: '#/deep-research',  label: 'Deep Research',  icon: icon.radar },
  { id: 'nav-settings',       path: '#/settings',       label: 'Settings',       icon: icon.settings },
];

export function renderSidebar() {
  return `
    <aside class="sidebar" id="main-sidebar" role="navigation" aria-label="Application navigation">

      <!-- Logo + brand -->
      <div class="sidebar-brand-card">
        <div class="sidebar-logo-card" aria-hidden="true">
          ${icon.baitzeroLogo}
        </div>
        <div class="sidebar-brand-text">
          <span class="sidebar-brand-name">BaitZero</span>
          <span class="sidebar-tagline">Spot the bait. Stop the risk.</span>
        </div>
      </div>

      <!-- Primary nav (no artificial category headers matching reference) -->
      <nav class="sidebar-nav" aria-label="Main navigation">
        ${navItems.map(item => `
          <button
            class="nav-item"
            id="${item.id}"
            data-path="${item.path}"
            aria-label="${item.label}"
            title="${item.label}"
          >
            <span class="nav-item-icon">${item.icon}</span>
            <span class="nav-item-label">${item.label}</span>
          </button>
        `).join('')}
      </nav>

      <!-- Reference-matched Protection Active card at bottom -->
      <div class="sidebar-footer-wrap">
        <div class="sidebar-footer-card" id="sidebar-footer-status" role="button" tabindex="0" title="Open Protection Settings">
          <div class="sidebar-footer-shield">
            ${icon.shieldCheck}
          </div>
          <div class="sidebar-footer-content">
            <div class="sidebar-footer-title" id="sidebar-status-title">Protection Active</div>
            <div class="sidebar-footer-sub" id="sidebar-status-sub">Clipboard monitoring ON</div>
          </div>
          <div class="sidebar-footer-arrow">
            ${icon.chevronRight}
          </div>
        </div>
      </div>

    </aside>
  `;
}

export function initNavbar() {
  navItems.forEach(item => {
    const el = document.getElementById(item.id);
    if (!el) return;
    el.addEventListener('click', () => navigate(item.path));
  });

  const footerStatus = document.getElementById('sidebar-footer-status');
  if (footerStatus) {
    footerStatus.addEventListener('click', () => navigate('#/settings'));
  }

  onNavigate(path => {
    updateActiveState(path);
    syncProtectionStatus();
  });

  // Subscribe to authoritative state changes
  onProtectionStateChange(() => {
    syncProtectionStatus();
  });

  updateActiveState(currentRoute());
  syncProtectionStatus();
}

function updateActiveState(path) {
  navItems.forEach(item => {
    const el = document.getElementById(item.id);
    if (!el) return;
    if (item.path === path) {
      el.classList.add('active');
      el.setAttribute('aria-current', 'page');
    } else {
      el.classList.remove('active');
      el.removeAttribute('aria-current');
    }
  });
}

function syncProtectionStatus() {
  const active = isProtectionActive();

  const title = document.getElementById('sidebar-status-title');
  const sub   = document.getElementById('sidebar-status-sub');
  const card  = document.getElementById('sidebar-footer-status');
  if (!title || !sub) return;

  if (active) {
    title.textContent = 'Protection Active';
    sub.textContent   = 'Clipboard monitoring ON';
    if (card) card.classList.remove('paused');
  } else {
    title.textContent = 'Protection Paused';
    sub.textContent   = 'Monitoring is disabled';
    if (card) card.classList.add('paused');
  }
}
