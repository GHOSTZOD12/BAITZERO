/**
 * urlAnalyzer.js
 *
 * Safely parses a submitted URL string into a structured data object
 * for use by the evidence and risk engines.
 *
 * Design decisions:
 * - Uses the native URL constructor for parsing (not regex). This is safe,
 *   well-tested, and handles edge cases like IPv6, punycode, and encoded chars.
 * - Never eval()s or fetches the URL.
 * - Returns a { success, data } or { success: false, error } shape so callers
 *   can handle parse failures without try/catch at the call site.
 * - Domain and subdomain splitting recognizes common multi-part ccTLDs (.co.uk,
 *   .com.au, .co.jp, etc.) matching deep_scan.rs, with fallback to the last two
 *   labels for standard single-part TLDs.
 */

// ---------------------------------------------------------------------------
// Constants used during analysis
// ---------------------------------------------------------------------------

/**
 * Terms that appear in many phishing URLs.
 * Presence alone is NOT sufficient to flag a URL — see evidenceEngine.js.
 */
const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'logon',
  'verify',
  'verification',
  'account',
  'secure',
  'update',
  'payment',
  'billing',
  'password',
  'passwd',
  'confirm',
  'credential',
  'bank',
  'banking',
  'authenticate',
  'auth',
  'recovery',
  'reset',
  'validate',
  'webscr',
];

/**
 * Known URL-shortening service domains.
 * This list covers common services — it is not exhaustive.
 */
const SHORTENER_DOMAINS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'ow.ly',
  'goo.gl',
  'is.gd',
  'buff.ly',
  'short.link',
  'tiny.cc',
  'bc.vc',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
  'tiny.one',
  'tr.im',
  's.id',
  'u.to',
  'v.gd',
  'x.co',
  'trib.al',
  'ift.tt',
]);

/**
 * Ports that are non-standard for public HTTP/HTTPS traffic.
 * Presence of these ports in a URL is a minor indicator only — many legitimate
 * development and internal services use these ports.
 */
const SUSPICIOUS_PORTS = new Set([
  8080, 8443, 3000, 8000, 4443, 9090, 1080, 4000, 9000, 8888, 6666,
]);

/** Matches a standard IPv4 address. */
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

/**
 * Known multi-part ccTLD suffixes (matching deep_scan.rs extract_canonical_domain).
 */
const KNOWN_TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.in', 'net.in', 'org.in', 'gen.in', 'gov.in', 'nic.in', 'ac.in', 'edu.in',
  'co.jp', 'ne.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br',
  'com.mx', 'org.mx',
  'com.sg', 'edu.sg',
  'com.tr', 'org.tr',
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a raw URL string and return structured analysis data.
 *
 * @param {string} raw - Raw URL string from user input
 * @returns {{ success: true, data: object } | { success: false, error: string }}
 */
export function parseUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return { success: false, error: 'Input is empty.' };
  }

  const trimmed = raw.trim();

  // --- Primary parse attempt ---
  let parsed = tryParse(trimmed);

  // --- Fallback: prepend https:// if the URL appears to be missing a scheme ---
  if (!parsed && !trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    parsed = tryParse('https://' + trimmed);
  }

  if (!parsed) {
    return {
      success: false,
      error: 'The value entered does not appear to be a valid URL. Example: https://example.com/path',
    };
  }

  // Only allow http and https schemes
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return {
      success: false,
      error: `URL scheme "${parsed.protocol}" is not supported. Only http:// and https:// URLs can be analyzed.`,
    };
  }

  // Reject bare single-label hostnames (e.g. "agshshs", "localhost" is OK, IPs are OK)
  const hn = parsed.hostname.toLowerCase();
  const isIPv4Like = IPV4_REGEX.test(hn);
  const isIPv6Like = hn.startsWith('[');
  const hasValidHostname = isIPv4Like || isIPv6Like || hn === 'localhost' || hn.includes('.');
  if (!hasValidHostname || hn === '') {
    return {
      success: false,
      error: 'Please enter a valid URL. (e.g. https://example.com/path)',
    };
  }

  return { success: true, data: extractData(parsed, trimmed) };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Try to construct a URL object. Returns null on failure instead of throwing.
 * @param {string} str
 * @returns {URL|null}
 */
function tryParse(str) {
  try {
    return new URL(str);
  } catch (_) {
    return null;
  }
}

/**
 * Extract all analysis-relevant fields from a parsed URL object.
 * @param {URL} parsed
 * @param {string} raw - Original user input string
 * @returns {object}
 */
function extractData(parsed, raw) {
  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = parsed.href.toLowerCase();

  // --- IP address detection ---
  const isIPv4 = IPV4_REGEX.test(hostname);
  // IPv6 hostnames are bracketed by the URL spec: [::1]
  const isIPv6 = hostname.startsWith('[');

  // --- Domain and subdomain breakdown ---
  let domain     = hostname;
  let subdomains = [];

  if (!isIPv4 && !isIPv6) {
    const parts = hostname.split('.').filter(Boolean);
    const lastTwo = parts.length >= 2 ? `${parts[parts.length - 2]}.${parts[parts.length - 1]}` : '';
    if (KNOWN_TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
      domain     = parts.slice(-3).join('.');
      subdomains = parts.slice(0, -3);
    } else if (parts.length > 2) {
      domain     = parts.slice(-2).join('.');
      subdomains = parts.slice(0, -2);
    } else {
      domain     = parts.join('.');
      subdomains = [];
    }
  }

  // --- Port ---
  const portStr        = parsed.port; // '' if not explicitly set
  const portNumber     = portStr ? parseInt(portStr, 10) : null;
  const hasExplicitPort = portStr !== '';

  // --- Keyword detection (against the full lowercased URL) ---
  const keywordsFound = SUSPICIOUS_KEYWORDS.filter(kw => fullUrl.includes(kw));

  // --- Encoded character detection ---
  // Match all %XX sequences in the original href
  const encodedMatches  = parsed.href.match(/%[0-9a-fA-F]{2}/g) || [];
  const encodedCharCount = encodedMatches.length;

  // --- Punycode detection ---
  // xn-- prefix indicates an ACE-encoded internationalized label
  const hasPunycode = hostname.includes('xn--');

  // --- URL shortener detection ---
  const isKnownShortener = SHORTENER_DOMAINS.has(domain) || SHORTENER_DOMAINS.has(hostname);

  // --- Suspicious port ---
  const isSuspiciousPort = hasExplicitPort && portNumber !== null && SUSPICIOUS_PORTS.has(portNumber);

  // --- High-risk TLD & Structural patterns ---
  const hostParts = hostname.split('.').filter(Boolean);
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';

  // At-symbol detection in authority (deceptive authority e.g. https://google.com@attacker.com)
  // Strips scheme and tests authority portion before path, query, or fragment.
  const authorityPart = raw.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
  const hasAtSymbol = Boolean(parsed.username || parsed.password || authorityPart.includes('@'));

  // Dangerous file extension in pathname (e.g. .exe, .scr, .iso)
  const dangerousExtRegex = /\.(exe|scr|bat|vbs|iso|hta|apk|cmd|msi|ps1)($|\?|#)/i;
  const hasDangerousExtension = dangerousExtRegex.test(parsed.pathname);

  // Double slash in pathname (normalization evasion)
  const hasDoubleSlashPath = parsed.pathname.includes('//');

  return {
    // Raw input
    raw,

    // Parsed URL fields
    href:        parsed.href,
    protocol:    parsed.protocol,   // 'https:' or 'http:'
    hostname,                        // full hostname including subdomains
    domain,                          // registerable domain (last two labels)
    tld,                             // top-level domain e.g. com, xyz, top
    subdomains,                      // array of subdomain label strings
    subdomainCount: subdomains.length,
    pathname:    parsed.pathname,
    search:      parsed.search,      // query string including '?'
    hash:        parsed.hash,
    port:        portStr,
    portNumber,
    hasExplicitPort,

    // Flags
    isIPv4,
    isIPv6,
    urlLength:       parsed.href.length,
    keywordsFound,
    encodedCharCount,
    hasPunycode,
    isKnownShortener,
    isSuspiciousPort,
    hasAtSymbol,
    hasDangerousExtension,
    hasDoubleSlashPath,
  };
}
