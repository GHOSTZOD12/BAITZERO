/**
 * pages/deepResearch.js
 * BaitZero Deep Research & Infrastructure Probes page.
 *
 * Implements expandable detailed reviews for all five investigation modules:
 * 1. Domain Registration (RDAP)
 * 2. DNS Records (Cloudflare DoH)
 * 3. TLS Certificate (Schannel In-Band Handshake)
 * 4. Reputation & Threat Intelligence (Abuse.ch URLhaus)
 * 5. Redirect Chain & SSRF Defense (Hop-by-hop Tracer)
 *
 * Guarantees:
 * - Keyboard-accessible interactive cards (Enter/Space toggle, aria-expanded, clear focus outline).
 * - Smooth chevron animation and collapsible drawers.
 * - Displays authentic evidence strictly returned by the native probe pipeline.
 * - Clear plain-language explanations distinguishing verified, suspicious, and unavailable outcomes.
 * - Non-negotiable security principle: An unavailable reputation source or HTTP 401 is NEVER treated as clean.
 * - Methodological limitations, authoritative source citations, and timestamps included.
 * - Full idempotency: cards remain interactive and update correctly across probe reruns and URL changes.
 */

import { icon } from '../icons.js';
import { navigate } from '../router.js';
import { invokeCommand } from '../tauriBridge.js';

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatIsoDate(isoStr) {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return String(isoStr);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return String(isoStr);
  }
}

function formatEpochDate(sec) {
  if (!sec) return 'N/A';
  try {
    const d = new Date(sec * 1000);
    if (isNaN(d.getTime())) return String(sec);
    return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return String(sec);
  }
}

const FEATURE_MODULES = [
  {
    id: 'whois',
    title: 'Domain registration',
    icon: icon.fileText,
    category: 'Registry',
    desc: 'Check domain age, registrar and other details.',
    capability: 'Authoritative ICANN RDAP bootstrap lookup via rdap.org.',
    badge: 'Ready',
  },
  {
    id: 'dns',
    title: 'DNS records',
    icon: icon.database,
    category: 'Network Protocol',
    desc: 'View DNS configuration and related information.',
    capability: 'Resolves IPv4 (A) and IPv6 (AAAA) records via Cloudflare DoH (RFC 8484).',
    badge: 'Ready',
  },
  {
    id: 'tls',
    title: 'TLS certificate',
    icon: icon.lock,
    category: 'Cryptographic Identity',
    desc: 'Analyse SSL/TLS certificate details.',
    capability: 'In-band TLS handshake and leaf X.509 certificate cryptographic parsing.',
    badge: 'Ready',
  },
  {
    id: 'reputation',
    title: 'Reputation',
    icon: icon.shieldCheck,
    category: 'Threat Intelligence',
    desc: 'Check against multiple reputation sources.',
    capability: 'Threat intelligence cross-reference against Abuse.ch URLhaus malware feeds.',
    badge: 'Ready',
  },
  {
    id: 'redirect',
    title: 'Redirect chain',
    icon: icon.link,
    category: 'Routing Analysis',
    desc: 'Analyse redirections and final destination.',
    capability: 'Hop-by-hop HTTP redirect tracer with strict SSRF and DNS rebinding defenses.',
    badge: 'Ready',
    fullWidth: true,
  },
];

function renderInitialDrawer(mod) {
  return `
    <div class="dr-analysis-banner dr-analysis-skipped">
      <strong>Ready to probe</strong>: External infrastructure queries are executed strictly on-demand. Enter a target URL above and click <strong>Execute Live Probes</strong> to collect detailed evidence.
    </div>
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Module Category</div>
        <div class="dr-evidence-value">${escapeHtml(mod.category)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Capability &amp; Protocol</div>
        <div class="dr-evidence-value">${escapeHtml(mod.capability)}</div>
      </div>
      <div class="dr-evidence-item" style="grid-column: 1 / -1;">
        <div class="dr-evidence-label">Privacy Guarantee</div>
        <div class="dr-evidence-value">Strict hostname isolation: URL paths, query parameters, fragments, and credentials are never transmitted to third-party services.</div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Status: <strong style="color: var(--risk-med);">Awaiting User Probe Request</strong></span>
      </div>
    </div>
  `;
}

function renderWhoisDetails(check, res) {
  const status = (check?.status || 'unavailable').toLowerCase();
  const d = check?.details || {};
  const source = check?.source || 'RDAP (rdap.org)';
  const domain = d.domain || res?.canonical_domain || 'N/A';
  const registrar = d.registrar || (status === 'skipped' ? 'N/A (IP Target)' : 'Not available from provider');
  const created = d.created ? formatIsoDate(d.created) : (status === 'skipped' ? 'N/A (IP Target)' : 'Not recorded in registry');
  const expires = d.expires ? formatIsoDate(d.expires) : (status === 'skipped' ? 'N/A (IP Target)' : 'Not recorded in registry');
  const statusCodes = Array.isArray(d.status) && d.status.length > 0 ? d.status.join(', ') : (status === 'verified' ? 'Active / Standard Delegation' : 'Unavailable');

  let analysisText = '';
  let bannerClass = 'dr-analysis-unavailable';

  if (status === 'verified') {
    bannerClass = 'dr-analysis-verified';
    analysisText = 'Verified: Domain registration record was located in the authoritative RDAP bootstrap. Established domain age and active registrar delegation provide positive baseline trust indicators.';
  } else if (status === 'suspicious') {
    bannerClass = 'dr-analysis-suspicious';
    analysisText = 'Suspicious: No registration record found in public RDAP bootstrap (HTTP 404) or anomaly detected. Unregistered domains or newly registered lookalikes are frequently deployed in disposable phishing campaigns.';
  } else if (status === 'skipped') {
    bannerClass = 'dr-analysis-skipped';
    analysisText = 'Skipped: The target host is an IP address literal; domain registration queries are not applicable to raw IP targets.';
  } else {
    bannerClass = 'dr-analysis-unavailable';
    analysisText = 'Unavailable: The public RDAP registry service timed out, was unreachable, or does not support this specific top-level domain. Domain registration details could not be independently confirmed.';
  }

  return `
    <div class="dr-analysis-banner ${bannerClass}">
      ${escapeHtml(analysisText)}
    </div>
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Registrable Domain</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(domain)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Registrar</div>
        <div class="dr-evidence-value">${escapeHtml(registrar)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Registration Date</div>
        <div class="dr-evidence-value">${escapeHtml(created)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Expiration Date</div>
        <div class="dr-evidence-value">${escapeHtml(expires)}</div>
      </div>
      <div class="dr-evidence-item" style="grid-column: 1 / -1;">
        <div class="dr-evidence-label">Registry EPP Status</div>
        <div class="dr-evidence-value">${escapeHtml(statusCodes)}</div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Authoritative Source: <strong class="dr-meta-source">${escapeHtml(source)}</strong></span>
        ${res?.timestamp_ms ? `<span>Probed: ${new Date(res.timestamp_ms).toLocaleTimeString()}</span>` : ''}
      </div>
      <div class="dr-meta-limitation">
        Limitations: RDAP coverage depends on registrar participation and ccTLD registry support. Registrant identity may be redacted per ICANN privacy specifications.
      </div>
    </div>
  `;
}

function renderDnsDetails(check, res) {
  const status = (check?.status || 'unavailable').toLowerCase();
  const d = check?.details || {};
  const source = check?.source || 'DNS-over-HTTPS (Cloudflare)';
  const aRecords = Array.isArray(d.a) && d.a.length > 0 ? d.a.join(', ') : (status === 'verified' ? 'None returned' : 'Unavailable');
  const aaaaRecords = Array.isArray(d.aaaa) && d.aaaa.length > 0 ? d.aaaa.join(', ') : (status === 'verified' ? 'None configured' : 'Unavailable');
  const prohibited = Array.isArray(d.prohibited) && d.prohibited.length > 0 ? d.prohibited.join(', ') : null;

  let analysisText = '';
  let bannerClass = 'dr-analysis-unavailable';

  if (status === 'verified') {
    bannerClass = 'dr-analysis-verified';
    analysisText = 'Verified: Domain name resolved cleanly to public routable IP addresses via encrypted DNS-over-HTTPS (RFC 8484). All resolved IP addresses successfully cleared SSRF boundary checks.';
  } else if (status === 'suspicious') {
    bannerClass = 'dr-analysis-suspicious';
    if (prohibited) {
      analysisText = `Suspicious: DNS resolves to prohibited private, loopback, or internal address space (${prohibited}). Outbound traffic blocked by SSRF defense filters.`;
    } else {
      analysisText = 'Suspicious: Domain does not exist (NXDOMAIN) or returned anomalous DNS response from authoritative resolvers.';
    }
  } else if (status === 'skipped') {
    bannerClass = 'dr-analysis-skipped';
    analysisText = 'Skipped: The target host is an IP literal; DNS hostname resolution was bypassed.';
  } else {
    bannerClass = 'dr-analysis-unavailable';
    analysisText = 'Unavailable: Cloudflare DoH resolver timed out or was unreachable from the current network environment. DNS records could not be resolved.';
  }

  return `
    <div class="dr-analysis-banner ${bannerClass}">
      ${escapeHtml(analysisText)}
    </div>
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">IPv4 Addresses (A)</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(aRecords)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">IPv6 Addresses (AAAA)</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(aaaaRecords)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">DNS Protocol</div>
        <div class="dr-evidence-value">DNS-over-HTTPS (DoH, RFC 8484)</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">SSRF Perimeter Defense</div>
        <div class="dr-evidence-value" style="color: ${prohibited ? 'var(--risk-high)' : 'var(--risk-low)'};">
          ${prohibited ? `BLOCKED (${escapeHtml(prohibited)})` : 'Passed (No private/loopback IPs)'}
        </div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Authoritative Source: <strong class="dr-meta-source">${escapeHtml(source)}</strong></span>
        ${res?.timestamp_ms ? `<span>Probed: ${new Date(res.timestamp_ms).toLocaleTimeString()}</span>` : ''}
      </div>
      <div class="dr-meta-limitation">
        Limitations: DNS responses reflect recursive DoH resolver perspective. Geographically distributed CDN nodes may resolve to different local POPs.
      </div>
    </div>
  `;
}

function renderTlsDetails(check, res) {
  const status = (check?.status || 'unavailable').toLowerCase();
  const d = check?.details || {};
  const source = check?.source || 'Direct In-Band TLS Handshake (Schannel)';
  const subject = d.subject || (status === 'skipped' ? 'N/A (HTTP Target)' : 'Not presented');
  const issuer = d.issuer || (status === 'skipped' ? 'N/A (HTTP Target)' : 'Not presented');
  const days = d.days_remaining !== undefined ? `${d.days_remaining} days` : 'N/A';
  const validityPeriod = d.not_before && d.not_after
    ? `${formatEpochDate(d.not_before)} — ${formatEpochDate(d.not_after)}`
    : 'N/A';
  const sans = Array.isArray(d.sans) && d.sans.length > 0
    ? d.sans.slice(0, 8).join(', ') + (d.sans.length > 8 ? ` (+${d.sans.length - 8} more)` : '')
    : 'None specified';
  const isTrusted = d.trusted === true;

  let analysisText = '';
  let bannerClass = 'dr-analysis-unavailable';

  if (status === 'verified') {
    bannerClass = 'dr-analysis-verified';
    analysisText = 'Verified: Cryptographically valid X.509 leaf certificate presented. The certificate is trusted by the Windows certificate store, matches the target hostname, and has active remaining validity.';
  } else if (status === 'suspicious') {
    bannerClass = 'dr-analysis-suspicious';
    if (d.expired) {
      analysisText = 'Suspicious: The presented TLS certificate has expired. Expired certificates expose traffic to interception and are common indicators of abandoned or compromised infrastructure.';
    } else if (d.trusted === false) {
      analysisText = `Suspicious: TLS certificate is NOT trusted by the Windows system trust store (${escapeHtml(d.trust_error || 'Untrusted Authority / Self-signed')}).`;
    } else {
      analysisText = 'Suspicious: Certificate subject or Subject Alternative Names (SANs) do not match the target host. Potential hostname mismatch or domain spoofing risk.';
    }
  } else if (status === 'skipped') {
    bannerClass = 'dr-analysis-skipped';
    analysisText = 'Skipped: The destination uses unencrypted plain HTTP (port 80). No TLS socket negotiation was performed.';
  } else {
    bannerClass = 'dr-analysis-unavailable';
    analysisText = 'Unavailable: Direct TLS handshake timed out or TCP connection on port 443 could not be established.';
  }

  return `
    <div class="dr-analysis-banner ${bannerClass}">
      ${escapeHtml(analysisText)}
    </div>
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Certificate Subject (CN)</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(subject)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Issuing Authority (CA)</div>
        <div class="dr-evidence-value">${escapeHtml(issuer)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Windows Trust Store</div>
        <div class="dr-evidence-value" style="color: ${isTrusted ? 'var(--risk-low)' : (status === 'skipped' ? 'var(--text-3)' : 'var(--risk-high)')};">
          ${isTrusted ? 'Trusted (Windows Root CA)' : (status === 'skipped' ? 'N/A (HTTP)' : (d.trust_error ? `Untrusted: ${escapeHtml(d.trust_error)}` : 'Untrusted Authority'))}
        </div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Validity Remaining</div>
        <div class="dr-evidence-value">${escapeHtml(days)} (${escapeHtml(validityPeriod)})</div>
      </div>
      <div class="dr-evidence-item" style="grid-column: 1 / -1;">
        <div class="dr-evidence-label">Subject Alternative Names (SANs)</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(sans)}</div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Authoritative Source: <strong class="dr-meta-source">${escapeHtml(source)}</strong></span>
        ${res?.timestamp_ms ? `<span>Probed: ${new Date(res.timestamp_ms).toLocaleTimeString()}</span>` : ''}
      </div>
      <div class="dr-meta-limitation">
        Limitations: Leaf certificate inspected directly over TLS socket using Windows Schannel. Revocation is evaluated through standard system trust mechanisms.
      </div>
    </div>
  `;
}

function renderReputationDetails(check, res) {
  const status = (check?.status || 'unavailable').toLowerCase();
  const d = check?.details || {};
  const source = check?.source || 'Abuse.ch URLhaus Community API';
  const queryStatus = d.query_status || (status === 'verified' ? 'ok' : 'unavailable');
  const urlCount = d.url_count !== undefined ? d.url_count : (status === 'verified' ? 0 : 'N/A');
  const threat = d.threat || (status === 'suspicious' ? 'Malware / Botnet' : 'None detected');

  let analysisText = '';
  let bannerClass = 'dr-analysis-unavailable';
  let caveatAlert = '';

  if (status === 'verified') {
    bannerClass = 'dr-analysis-verified';
    analysisText = 'Verified: Domain was cross-referenced with Abuse.ch URLhaus threat feeds. 0 active malware or botnet distribution URLs are cataloged for this host. Note: Absence from community threat feeds does not guarantee complete safety.';
  } else if (status === 'suspicious') {
    bannerClass = 'dr-analysis-suspicious';
    analysisText = `Suspicious: Host is actively listed on Abuse.ch URLhaus with ${urlCount} identified malicious URL(s) (Threat Category: ${escapeHtml(threat)}).`;
  } else if (status === 'skipped') {
    bannerClass = 'dr-analysis-skipped';
    analysisText = 'Skipped: Reputation check was bypassed for this target.';
  } else {
    bannerClass = 'dr-analysis-unavailable';
    analysisText = 'Unavailable: The threat intelligence service was unreachable, timed out, or returned an HTTP status error (e.g. HTTP 401 Unauthorized or rate limit).';
    caveatAlert = `
      <div class="dr-reputation-alert">
        <strong>SECURITY REQUIREMENT:</strong> The reputation check could not be completed.
        An unavailable reputation source, timeout, or HTTP 401 response must <u>never</u> be interpreted as a clean reputation result.
      </div>
    `;
  }

  return `
    <div class="dr-analysis-banner ${bannerClass}">
      ${escapeHtml(analysisText)}
    </div>
    ${caveatAlert}
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Intelligence Database</div>
        <div class="dr-evidence-value">Abuse.ch URLhaus Community API</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Feed Query Status</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(queryStatus)}</div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Active Malicious URLs</div>
        <div class="dr-evidence-value" style="color: ${urlCount > 0 ? 'var(--risk-high)' : (urlCount === 0 ? 'var(--risk-low)' : 'var(--text-3)')};">
          ${urlCount > 0 ? `${urlCount} Malicious URLs Detected` : (urlCount === 0 ? '0 Active Threats' : 'Not Available')}
        </div>
      </div>
      <div class="dr-evidence-item">
        <div class="dr-evidence-label">Threat Classification</div>
        <div class="dr-evidence-value">${escapeHtml(threat)}</div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Authoritative Source: <strong class="dr-meta-source">${escapeHtml(source)}</strong></span>
        ${res?.timestamp_ms ? `<span>Probed: ${new Date(res.timestamp_ms).toLocaleTimeString()}</span>` : ''}
      </div>
      <div class="dr-meta-limitation">
        Privacy &amp; Scope: Only the domain/hostname is submitted to reputation endpoints; paths, query parameters, and fragments are never shared. Community databases track known malware; zero-day threats may not yet be cataloged.
      </div>
    </div>
  `;
}

function renderRedirectDetails(check, res) {
  const status = (check?.status || 'unavailable').toLowerCase();
  const d = check?.details || {};
  const source = check?.source || 'Out-of-Band Hop Tracer';
  const hops = Array.isArray(d.hops) ? d.hops : [];
  const finalUrl = d.final_url || (hops.length ? hops[hops.length - 1].url : res?.target_url || 'N/A');

  let analysisText = '';
  let bannerClass = 'dr-analysis-unavailable';

  if (status === 'verified') {
    bannerClass = 'dr-analysis-verified';
    if (hops.length <= 1) {
      analysisText = 'Verified: Direct HTTP connection established without redirects. No protocol downgrades or unauthorized SSRF hops occurred.';
    } else {
      analysisText = `Verified: Safely followed ${hops.length - 1} HTTP redirect(s) to destination. All hops maintained protocol integrity and cleared SSRF validation.`;
    }
  } else if (status === 'suspicious') {
    bannerClass = 'dr-analysis-suspicious';
    if (d.cycle_url) {
      analysisText = `Suspicious: Redirect loop or cycle detected returning repeatedly to '${escapeHtml(d.cycle_url)}'.`;
    } else if (d.prohibited_ip) {
      analysisText = `Suspicious: Redirect chain attempted connection to prohibited private/internal IP address (${escapeHtml(d.prohibited_ip)}). Blocked by SSRF defenses.`;
    } else {
      analysisText = 'Suspicious: Redirect tracer detected insecure protocol downgrade (HTTPS to HTTP) or excessive redirect hops (>5).';
    }
  } else if (status === 'skipped') {
    bannerClass = 'dr-analysis-skipped';
    analysisText = 'Skipped: Initial target URL is prohibited; redirect tracing halted.';
  } else {
    bannerClass = 'dr-analysis-unavailable';
    analysisText = 'Unavailable: HTTP request failed or timed out during redirect tracing.';
  }

  const hopsHtml = hops.length > 0
    ? `
      <div class="dr-hop-sequence">
        ${hops.map(h => {
          const isRedirect = [301, 302, 303, 307, 308].includes(h.status);
          const badgeClass = isRedirect ? 'status-redirect' : (h.status === 200 ? 'status-200' : '');
          return `
            <div class="dr-hop-step">
              <span class="dr-hop-badge ${badgeClass}">Hop ${h.hop}: HTTP ${h.status}</span>
              <span class="dr-hop-url">${escapeHtml(h.url)}</span>
              <div class="dr-hop-meta">
                <span>IP: <code>${escapeHtml(h.ip)}</code></span>
                ${h.location ? `<span>&rarr; Next: <code>${escapeHtml(h.location)}</code></span>` : ''}
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `
    : `<div style="font-size: 12px; color: var(--text-3); margin: 8px 0;">No redirect hops recorded.</div>`;

  return `
    <div class="dr-analysis-banner ${bannerClass}">
      ${escapeHtml(analysisText)}
    </div>
    <div style="font-size: 11.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-3); margin-top: 10px; margin-bottom: 6px;">
      Hop Trace Execution &amp; SSRF Validation (${hops.length} Total Hops)
    </div>
    ${hopsHtml}
    <div class="dr-evidence-grid">
      <div class="dr-evidence-item" style="grid-column: 1 / -1;">
        <div class="dr-evidence-label">Final Destination URL</div>
        <div class="dr-evidence-value dr-evidence-code">${escapeHtml(finalUrl)}</div>
      </div>
    </div>
    <div class="dr-drawer-footer">
      <div class="dr-meta-line">
        <span>Authoritative Source: <strong class="dr-meta-source">${escapeHtml(source)}</strong></span>
        ${res?.timestamp_ms ? `<span>Probed: ${new Date(res.timestamp_ms).toLocaleTimeString()}</span>` : ''}
      </div>
      <div class="dr-meta-limitation">
        Limitations: Hops are evaluated independently with IP address pinning and DNS rebinding protections. JavaScript-driven redirects (window.location) cannot be captured over HTTP HEAD/GET.
      </div>
    </div>
  `;
}

export function renderDeepResearch() {
  const url = sessionStorage.getItem('deepResearchUrl') || '';

  return `
    <main class="page-content" id="page-deep-research">

      <!-- Header with Preview and Status badges -->
      <div class="dr-ref-header">
        <div class="dr-ref-title-group">
          <div class="dr-title-row">
            <h1 class="page-title" style="margin-bottom: 0;">Deep Research</h1>
            <span class="pill-badge pill-preview">Preview</span>
          </div>
          <p class="page-subtitle" style="margin-top: 4px;">In-depth investigation for a more complete picture.</p>
        </div>
        <div class="dr-ref-status-badge">
          <span class="badge-dot-amber"></span>
          <span id="dr-header-status-text">Ready to probe</span>
        </div>
      </div>

      <!-- Hero Banner with bounded radar icon -->
      <div class="dr-coming-soon-hero">
        <div class="dr-hero-icon-box" aria-hidden="true">
          ${icon.radar}
        </div>
        <div class="dr-hero-texts">
          <h2 class="dr-hero-title">Deep Research &amp; Infrastructure Probes</h2>
          <p class="dr-hero-desc">
            In-depth multi-protocol investigation querying authoritative registry data, DNS-over-HTTPS (DoH), TLS certificate chains, and threat intelligence feeds. Live external network calls are executed directly through the native runtime.
          </p>
        </div>
      </div>

      <!-- Investigation Controls: URL field, Re-run Probes and Back to Instant Scan buttons -->
      <div class="dr-active-target-bar">
        <div class="dr-active-target-left">
          <span class="dr-target-icon">${icon.link}</span>
          <input
            type="text"
            id="dr-url-input"
            class="dr-url-input"
            placeholder="Enter or paste a URL to investigate (e.g. https://example.com)..."
            value="${escapeHtml(url)}"
          />
        </div>
        <div class="dr-active-actions">
          <button class="btn-analyze-cyan" id="dr-run-scan-btn">
            <span>Execute Live Probes</span>
            ${icon.sparkles}
          </button>
          <button class="btn-ref-clear" id="dr-back-to-scan-btn">
            Back to Instant Scan
          </button>
        </div>
      </div>

      <div id="dr-progress-strip-container"></div>
      <div id="dr-assessment-container"></div>

      <!-- 5 Investigation Modules Grid with Keyboard-Accessible Collapsible Drawers -->
      <div class="dr-feature-grid" style="margin-top: 18px;">
        ${FEATURE_MODULES.map(mod => `
          <div class="dr-feature-card ${mod.fullWidth ? 'card-full-width' : ''}" id="dr-card-${mod.id}">
            <div
              class="dr-card-header"
              id="dr-header-${mod.id}"
              role="button"
              tabindex="0"
              aria-expanded="false"
              aria-controls="dr-drawer-${mod.id}"
            >
              <div class="dr-card-icon-box" aria-hidden="true">
                ${mod.icon}
              </div>
              <div class="dr-card-header-main">
                <div class="dr-card-top-row">
                  <div class="dr-card-title-group">
                    <span class="dr-card-title">${mod.title}</span>
                    <span class="dr-card-category">${mod.category}</span>
                  </div>
                  <div class="dr-card-header-actions">
                    <span class="pill-badge pill-not-avail" id="dr-badge-${mod.id}">
                      ${mod.badge}
                    </span>
                    <span class="dr-card-chevron" id="dr-chevron-${mod.id}" aria-hidden="true">
                      ${icon.chevronDown}
                    </span>
                  </div>
                </div>
                <p class="dr-card-desc" id="dr-desc-${mod.id}">${mod.desc}</p>
              </div>
            </div>
            <div
              class="dr-card-drawer"
              id="dr-drawer-${mod.id}"
              role="region"
              aria-labelledby="dr-header-${mod.id}"
            >
              <div class="dr-drawer-inner" id="dr-details-${mod.id}">
                ${renderInitialDrawer(mod)}
              </div>
            </div>
          </div>
        `).join('')}
      </div>

    </main>
  `;
}

async function invokeTauriCmd(cmd, args = {}) {
  return await invokeCommand(cmd, args);
}

let isScanning = false;

export function initDeepResearch() {
  const urlInput = document.getElementById('dr-url-input');
  const runBtn = document.getElementById('dr-run-scan-btn');
  const backBtn = document.getElementById('dr-back-to-scan-btn');

  // Wire up keyboard accessibility and click expand/collapse on all 5 card headers
  FEATURE_MODULES.forEach(mod => {
    const header = document.getElementById(`dr-header-${mod.id}`);
    const card = document.getElementById(`dr-card-${mod.id}`);
    if (header && card) {
      const toggleExpand = () => {
        const isExpanded = card.classList.toggle('is-expanded');
        header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
      };

      header.addEventListener('click', toggleExpand);
      header.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
          e.preventDefault();
          toggleExpand();
        }
      });
    }
  });

  if (backBtn) {
    backBtn.addEventListener('click', () => {
      const url = urlInput ? urlInput.value.trim() : (sessionStorage.getItem('deepResearchUrl') || '');
      if (url) sessionStorage.setItem('pendingAnalysisUrl', url);
      navigate('#/analyze');
    });
  }

  if (runBtn) {
    runBtn.addEventListener('click', async () => {
      if (isScanning) return;
      const targetUrl = urlInput ? urlInput.value.trim() : (sessionStorage.getItem('deepResearchUrl') || '');
      if (!targetUrl) {
        if (urlInput) {
          urlInput.focus();
          urlInput.classList.add('input-error');
          setTimeout(() => urlInput.classList.remove('input-error'), 2000);
        }
        return;
      }

      sessionStorage.setItem('deepResearchUrl', targetUrl);
      isScanning = true;
      runBtn.disabled = true;
      runBtn.innerHTML = `<span>Probing Infrastructure...</span>`;

      const progressStrip = document.getElementById('dr-progress-strip-container');
      const assessmentContainer = document.getElementById('dr-assessment-container');

      if (progressStrip) {
        progressStrip.innerHTML = `
          <div class="dr-progress-strip">
            <div class="dr-progress-bar-inner"></div>
          </div>
          <div style="font-size: 11.5px; color: var(--accent); margin-top: 6px;">
            Connecting to authoritative endpoints (DNS-over-HTTPS, RDAP, TLS handshake)...
          </div>
        `;
      }

      // Set all badges to Probing
      FEATURE_MODULES.forEach(m => {
        const b = document.getElementById(`dr-badge-${m.id}`);
        if (b) {
          b.className = 'pill-badge pill-preview dr-pulse';
          b.textContent = 'Probing...';
        }
      });

      try {
        const rawRes = await invokeTauriCmd('run_deep_scan', { url: targetUrl });
        if (progressStrip) progressStrip.innerHTML = '';

        if (rawRes) {
          const res = typeof rawRes === 'string' ? JSON.parse(rawRes) : rawRes;
          renderAssessmentCard(res, assessmentContainer);
          renderModuleOutcomes(res);
          const statusText = document.getElementById('dr-header-status-text');
          if (statusText) statusText.textContent = 'Probes Complete';
        } else {
          reportRuntimeNotice(assessmentContainer, 'Tauri Native Runtime Required for Live Network Probes');
        }
      } catch (e) {
        if (progressStrip) progressStrip.innerHTML = '';
        reportRuntimeNotice(assessmentContainer, e?.message || 'Probes could not be dispatched in this environment');
      } finally {
        isScanning = false;
        runBtn.disabled = false;
        runBtn.innerHTML = `<span>Re-run Probes</span> ${icon.sparkles}`;
      }
    });
  }
}

function reportRuntimeNotice(container, msg) {
  if (!container) return;
  container.innerHTML = `
    <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 8px; padding: 14px 18px; margin-bottom: 18px;">
      <div style="font-size: 13px; font-weight: 600; color: var(--risk-med); margin-bottom: 4px;">
        Environment Notice: ${escapeHtml(msg)}
      </div>
      <p style="font-size: 12px; color: var(--text-2); line-height: 1.5;">
        Direct TCP TLS handshakes and UDP/DoH queries require the compiled Windows Tauri desktop process.
        When running in standard browser dev-server mode, cross-origin security prevents arbitrary raw socket creation.
      </p>
    </div>
  `;

  FEATURE_MODULES.forEach(m => {
    const b = document.getElementById(`dr-badge-${m.id}`);
    if (b && b.textContent === 'Probing...') {
      b.className = 'pill-badge pill-not-avail';
      b.textContent = 'Native Only';
    }
  });
}

function renderAssessmentCard(res, container) {
  if (!container || !res) return;
  const assessment = res.assessment || {};
  const verdict = assessment.verdict || 'inconclusive';

  let badgeColor = 'var(--risk-med)';
  let verdictTitle = assessment.title || 'Investigation Complete';
  let cardBorder = 'rgba(245, 158, 11, 0.3)';

  if (verdict === 'no_known_threats') {
    badgeColor = 'var(--risk-low)';
    cardBorder = 'rgba(34, 211, 160, 0.3)';
  } else if (verdict === 'suspicious_findings') {
    badgeColor = 'var(--risk-high)';
    cardBorder = 'rgba(239, 68, 68, 0.3)';
  }

  container.innerHTML = `
    <div style="background: var(--bg-card); border: 1px solid ${cardBorder}; border-radius: 10px; padding: 16px 20px; margin-bottom: 18px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="font-size: 14px; font-weight: 700; color: ${badgeColor};">${escapeHtml(verdictTitle)}</span>
        <span class="pill-badge" style="background: rgba(255,255,255,0.06); color: ${badgeColor};">${escapeHtml(verdict.replace(/_/g, ' ').toUpperCase())}</span>
      </div>
      <p style="font-size: 12.5px; color: var(--text-2); line-height: 1.45;">${escapeHtml(assessment.description || '')}</p>
    </div>
  `;
}

function renderModuleOutcomes(res) {
  const checks = res.checks || {};
  FEATURE_MODULES.forEach(m => {
    const check = checks[m.id];
    const badge = document.getElementById(`dr-badge-${m.id}`);
    const desc = document.getElementById(`dr-desc-${m.id}`);
    const details = document.getElementById(`dr-details-${m.id}`);

    if (check && badge) {
      const status = (check.status || 'unavailable').toLowerCase();
      if (status === 'verified') {
        badge.className = 'pill-badge pill-risk-low';
        badge.textContent = 'Verified';
      } else if (status === 'suspicious') {
        badge.className = 'pill-badge pill-risk-high';
        badge.textContent = 'Suspicious';

        // Auto-expand suspicious findings so user immediately sees why it was flagged
        const card = document.getElementById(`dr-card-${m.id}`);
        const header = document.getElementById(`dr-header-${m.id}`);
        if (card && header && !card.classList.contains('is-expanded')) {
          card.classList.add('is-expanded');
          header.setAttribute('aria-expanded', 'true');
        }
      } else if (status === 'skipped') {
        badge.className = 'pill-badge pill-not-avail';
        badge.textContent = 'Skipped';
      } else {
        badge.className = 'pill-badge pill-not-avail';
        badge.textContent = 'Unavailable';
      }

      if (desc && check.summary) {
        desc.textContent = check.summary;
      }

      if (details) {
        switch (m.id) {
          case 'whois':
            details.innerHTML = renderWhoisDetails(check, res);
            break;
          case 'dns':
            details.innerHTML = renderDnsDetails(check, res);
            break;
          case 'tls':
            details.innerHTML = renderTlsDetails(check, res);
            break;
          case 'reputation':
            details.innerHTML = renderReputationDetails(check, res);
            break;
          case 'redirect':
            details.innerHTML = renderRedirectDetails(check, res);
            break;
          default:
            details.innerHTML = `<div class="dr-analysis-banner dr-analysis-skipped">${escapeHtml(check.summary || '')}</div>`;
        }
      }
    }
  });
}
