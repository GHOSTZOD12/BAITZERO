/**
 * evidenceEngine.js
 *
 * Runs deterministic checks on parsed URL data and returns an array of
 * structured evidence objects. Each check is a separate function so that
 * rules are individually readable, testable, and explainable.
 *
 * Evidence object structure:
 * {
 *   id:          string  — unique check identifier
 *   category:    string  — display category ('Protocol', 'Domain', etc.)
 *   severity:    'low' | 'medium' | 'high'
 *   title:       string  — short human-readable indicator name
 *   description: string  — plain-language explanation of what was found and why it matters
 *   weight:      number  — contribution to the risk score (see riskEngine.js)
 * }
 *
 * IMPORTANT — Avoiding over-flagging:
 * Individual indicators are assigned conservative weights. A single keyword
 * or an HTTP protocol alone should not push a URL into HIGH risk. Multiple
 * meaningful indicators must accumulate before reaching HIGH.
 *
 * These weights are internal project thresholds, NOT validated probabilities.
 */

// ---------------------------------------------------------------------------
// Lookalike brand patterns
// Only a small, well-known set is included. This is NOT a comprehensive
// impersonation detection system and should not be claimed as one.
// ---------------------------------------------------------------------------
const BRAND_PATTERNS = [
  {
    name: 'PayPal',
    keyword: 'paypal',
    legitimateDomains: ['paypal.com', 'paypal.me', 'paypal.co.uk'],
  },
  {
    name: 'Amazon',
    keyword: 'amazon',
    legitimateDomains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
  },
  {
    name: 'Google',
    keyword: 'google',
    legitimateDomains: [
      'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr',
      'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    ],
  },
  {
    name: 'Microsoft',
    keyword: 'microsoft',
    legitimateDomains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
  },
  {
    name: 'Apple',
    keyword: 'apple',
    legitimateDomains: ['apple.com', 'icloud.com'],
  },
  {
    name: 'Facebook',
    keyword: 'facebook',
    legitimateDomains: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com'],
  },
  {
    name: 'Netflix',
    keyword: 'netflix',
    legitimateDomains: ['netflix.com'],
  },
  {
    name: 'eBay',
    keyword: 'ebay',
    legitimateDomains: ['ebay.com', 'ebay.in', 'ebay.co.uk'],
  },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Run all evidence checks against parsed URL data.
 *
 * @param {object} urlData - The .data field from urlAnalyzer.parseUrl()
 * @returns {Array<object>} Sorted array of evidence objects (by weight, descending)
 */
export function collectEvidence(urlData, options = {}) {
  const evidence = [];

  checkHTTP(urlData, evidence);
  checkIPAddress(urlData, evidence);
  checkURLLength(urlData, evidence);
  checkExcessiveSubdomains(urlData, evidence);
  checkSuspiciousKeywords(urlData, evidence);
  checkURLShortener(urlData, evidence);
  checkPunycode(urlData, evidence);
  checkEncodedCharacters(urlData, evidence);
  checkSuspiciousPort(urlData, evidence);
  checkLookalikePattern(urlData, evidence);

  // Extended heuristic checks
  checkSuspiciousTLD(urlData, evidence);
  checkAtSymbol(urlData, evidence);
  checkDangerousExtension(urlData, evidence);
  checkDoubleSlash(urlData, evidence);

  // Sort by weight descending so the most significant findings appear first
  return evidence.sort((a, b) => b.weight - a.weight);
}

// ---------------------------------------------------------------------------
// Individual check functions
// Each function pushes at most one evidence item to the array.
// ---------------------------------------------------------------------------

/**
 * CHECK 1: HTTP instead of HTTPS
 * HTTP is a minor flag on its own. It becomes more meaningful combined
 * with other indicators (e.g. IP address + HTTP + credentials keyword).
 */
function checkHTTP(urlData, evidence) {
  if (urlData.protocol === 'http:') {
    evidence.push({
      id:       'http-protocol',
      category: 'Protocol',
      severity: 'low',
      title:    'Unencrypted Connection (HTTP)',
      description:
        'The URL uses HTTP rather than HTTPS. Data sent over an HTTP connection ' +
        'is transmitted without encryption. Legitimate websites handling personal ' +
        'or financial information should use HTTPS. This is a low-confidence ' +
        'indicator on its own.',
      weight: 15,
    });
  }
}

/**
 * CHECK 2: IP address used as hostname
 * Legitimate public-facing websites almost never use bare IP addresses.
 * This is a strong indicator when combined with other factors.
 */
function checkIPAddress(urlData, evidence) {
  if (urlData.isIPv4) {
    evidence.push({
      id:       'ip-hostname',
      category: 'Domain',
      severity: 'high',
      title:    'IP Address Used Instead of Domain Name',
      description:
        'The URL uses a raw IP address as the destination instead of a registered ' +
        'domain name. Legitimate websites almost always use domain names. Raw IP ' +
        'addresses make it impossible to verify which organisation operates the server, ' +
        'and this pattern is commonly seen in phishing infrastructure.',
      weight: 40,
    });
  } else if (urlData.isIPv6) {
    evidence.push({
      id:       'ip-hostname-v6',
      category: 'Domain',
      severity: 'high',
      title:    'IPv6 Address Used Instead of Domain Name',
      description:
        'The URL uses an IPv6 address as the hostname. This is uncommon for ' +
        'publicly accessible websites and may be used to obscure the actual destination.',
      weight: 35,
    });
  }
}

/**
 * CHECK 3: Excessive URL length
 * Very long URLs are sometimes used to embed hidden parameters or to push
 * the visible domain out of the browser address bar.
 * Note: Many legitimate URLs (e.g. OAuth flows, search results) are also long.
 */
function checkURLLength(urlData, evidence) {
  const len = urlData.urlLength;

  if (len > 200) {
    evidence.push({
      id:       'url-length-high',
      category: 'URL Structure',
      severity: 'medium',
      title:    `Unusually Long URL (${len} characters)`,
      description:
        `The URL is ${len} characters long. Very long URLs are sometimes used to ` +
        'push the actual domain name out of view in browser address bars, or to embed ' +
        'large numbers of parameters that obscure the destination. This alone does ' +
        'not confirm a threat.',
      weight: 20,
    });
  } else if (len > 100) {
    evidence.push({
      id:       'url-length-moderate',
      category: 'URL Structure',
      severity: 'low',
      title:    `Long URL (${len} characters)`,
      description:
        `The URL is ${len} characters long, which is longer than a typical direct ` +
        'web address. This is a minor structural observation.',
      weight: 10,
    });
  }
}

/**
 * CHECK 4: Excessive subdomain depth
 * Deep subdomain structures can be used to make a malicious domain look
 * more legitimate by placing a trusted-looking name at the front.
 * Example: paypal.com.secure.login.evil.com
 */
function checkExcessiveSubdomains(urlData, evidence) {
  const count = urlData.subdomainCount;

  if (count >= 4) {
    evidence.push({
      id:       'excessive-subdomains',
      category: 'Domain',
      severity: 'medium',
      title:    `Excessive Subdomain Depth (${count} levels)`,
      description:
        `The URL contains ${count} subdomain levels. While subdomains are a normal ` +
        'part of web infrastructure, an unusually deep structure can be used to make ' +
        'a deceptive domain appear more familiar or to hide the actual registerable domain.',
      weight: 25,
    });
  } else if (count === 3) {
    evidence.push({
      id:       'deep-subdomains',
      category: 'Domain',
      severity: 'low',
      title:    `Multiple Subdomain Levels (${count} levels)`,
      description:
        `The URL has ${count} subdomain levels. This is a minor structural observation — ` +
        'some legitimate services (e.g. regional or product subdomains) use deep structures.',
      weight: 12,
    });
  }
}

/**
 * CHECK 5: Suspicious keywords
 * Terms associated with credential or payment collection are detected in the
 * full URL (path, query, subdomain). Weight scales with the number of matches.
 *
 * Deliberate choice: 1–2 keywords receive a LOW weight because many legitimate
 * URLs contain "login" or "account". Only 4+ keywords accumulate enough weight
 * on their own to reach MEDIUM risk.
 */
function checkSuspiciousKeywords(urlData, evidence) {
  const keywords = urlData.keywordsFound;
  if (keywords.length === 0) return;

  const count = keywords.length;
  let severity, weight, description;

  if (count >= 4) {
    severity    = 'medium';
    weight      = 28;
    description =
      `The URL contains ${count} terms commonly found in credential-harvesting or ` +
      `account-related phishing pages: ${formatList(keywords)}. The accumulation of ` +
      'multiple such terms together is a stronger indicator than any single term alone.';
  } else if (count >= 2) {
    severity    = 'low';
    weight      = 18;
    description =
      `The URL contains terms that appear in some phishing scenarios: ${formatList(keywords)}. ` +
      'Note that these words also appear regularly in legitimate URLs — this is a ' +
      'low-confidence indicator that gains significance only when combined with other findings.';
  } else {
    severity    = 'low';
    weight      = 10;
    description =
      `The URL contains the term "${keywords[0]}", which appears in some phishing URLs. ` +
      'This is a weak indicator on its own and does not imply the link is malicious.';
  }

  evidence.push({
    id:       'suspicious-keywords',
    category: 'Keywords',
    severity,
    title:    `Sensitive Keyword${count > 1 ? 's' : ''} Detected`,
    description,
    weight,
  });
}

/**
 * CHECK 6: URL shortening service
 * Shortened URLs hide the actual destination. This is often legitimate,
 * but prevents assessment of the real URL without following the redirect.
 * Redirect-following is a Phase 6 feature (Deep Investigation).
 */
function checkURLShortener(urlData, evidence) {
  if (urlData.isKnownShortener) {
    evidence.push({
      id:       'url-shortener',
      category: 'URL Structure',
      severity: 'medium',
      title:    'URL Shortening Service Detected',
      description:
        `The URL uses a known link-shortening service (${urlData.domain}). Shortened ` +
        'URLs conceal the actual destination. While shorteners have many legitimate uses, ' +
        'this means the final destination cannot be assessed without following the redirect.',
      weight: 20,
    });
  }
}

/**
 * CHECK 7: Punycode / Internationalized Domain Name
 * The xn-- prefix indicates ACE-encoded internationalized labels.
 * This encoding has been used in IDN homograph attacks where visually
 * similar characters (e.g. Cyrillic 'а' vs Latin 'a') are used to
 * impersonate known domains.
 */
function checkPunycode(urlData, evidence) {
  if (urlData.hasPunycode) {
    evidence.push({
      id:       'punycode-hostname',
      category: 'Domain',
      severity: 'high',
      title:    'Punycode / Internationalized Domain Name Detected',
      description:
        'The domain name contains Punycode encoding (indicated by the "xn--" prefix). ' +
        'Punycode is used for internationalized domain names and has been exploited in ' +
        'IDN homograph attacks — where characters from other scripts are substituted to ' +
        'create domain names that visually resemble well-known brands (e.g. using ' +
        'Cyrillic characters to impersonate Latin ones).',
      weight: 30,
    });
  }
}

/**
 * CHECK 8: Encoded characters
 * Percent-encoding is a standard part of URLs (e.g. spaces as %20).
 * An unusually high count may indicate an attempt to obscure content.
 * Threshold is set at 3+ to avoid false positives on normal encoded paths.
 */
function checkEncodedCharacters(urlData, evidence) {
  if (urlData.encodedCharCount >= 3) {
    evidence.push({
      id:       'encoded-characters',
      category: 'Encoding',
      severity: 'medium',
      title:    `Multiple Encoded Characters Detected (${urlData.encodedCharCount})`,
      description:
        `The URL contains ${urlData.encodedCharCount} percent-encoded sequences (%XX). ` +
        'A small number of encoded characters is normal. A higher count may indicate ' +
        'an attempt to obfuscate the URL content or bypass simple text-based filters.',
      weight: 15,
    });
  }
}

/**
 * CHECK 9: Non-standard port
 * Standard web traffic uses port 443 (HTTPS) or port 80 (HTTP).
 * Non-standard ports are common in development environments and some
 * legitimate services, but their presence in an unexpected link is worth noting.
 */
function checkSuspiciousPort(urlData, evidence) {
  if (urlData.isSuspiciousPort) {
    evidence.push({
      id:       'suspicious-port',
      category: 'Port',
      severity: 'medium',
      title:    `Non-Standard Port in Use (${urlData.portNumber})`,
      description:
        `The URL specifies port ${urlData.portNumber}, which is not the standard HTTP (80) ` +
        `or HTTPS (443) port. Non-standard ports are commonly used by development servers ` +
        'or internal proxies. Their presence in a link from an unexpected source warrants ' +
        'additional scrutiny. This is not malicious on its own.',
      weight: 22,
    });
  }
}

/**
 * CHECK 10: Lookalike / Brand impersonation pattern
 * Detects when a well-known brand name appears in the hostname but the
 * registerable domain is not an official domain of that brand.
 *
 * Example: paypal.login.attacker.com
 * — "paypal" appears in hostname
 * — registerable domain is "attacker.com" (not paypal.com)
 * → flagged
 *
 * Limitation: Only a small set of brands is included. This check will miss
 * impersonation of brands not in the list. This limitation is documented and
 * should be stated clearly in the BCA project.
 */
function checkLookalikePattern(urlData, evidence) {
  // Skip check for IP-based URLs — no domain to impersonate
  if (urlData.isIPv4 || urlData.isIPv6) return;

  const hostname = urlData.hostname;
  const domain   = urlData.domain;

  for (const brand of BRAND_PATTERNS) {
    const brandRegex = new RegExp(`(^|[.-])${brand.keyword}([.-]|$)`, 'i');
    const brandInHostname = brandRegex.test(hostname);
    if (!brandInHostname) continue;

    // Check if the domain is one of the brand's known legitimate domains
    const isLegitimate =
      brand.legitimateDomains.includes(domain) ||
      brand.legitimateDomains.some(d => hostname === d || hostname.endsWith('.' + d));

    if (!isLegitimate) {
      evidence.push({
        id:       `lookalike-${brand.keyword}`,
        category: 'Impersonation',
        severity: 'high',
        title:    `Possible Brand Reference — ${brand.name}`,
        description:
          `The URL contains the name "${brand.name}" within the hostname, but the ` +
          `actual registerable domain (${domain}) is not an official ${brand.name} domain. ` +
          `This pattern — placing a trusted brand name in a subdomain — is frequently ` +
          'used to make deceptive links appear associated with a well-known service. ' +
          'This check covers a limited set of brands and does not guarantee detection ' +
          'of all impersonation attempts.',
        weight: 35,
      });
      // Only report the first matching brand to avoid stacking multiple impersonation flags
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Extended Heuristic Checks
// ---------------------------------------------------------------------------

const HIGH_ABUSE_TLDS = new Set([
  'xyz', 'top', 'click', 'work', 'loan', 'fit', 'gq', 'cf', 'ml', 'ga', 'buzz', 'tokyo', 'surf', 'support', 'link', 'country'
]);

/**
 * CHECK 11: High-Abuse TLD
 * Many phishing campaigns use cheap or unmoderated top-level domains.
 */
function checkSuspiciousTLD(urlData, evidence) {
  if (urlData.tld && HIGH_ABUSE_TLDS.has(urlData.tld.toLowerCase())) {
    evidence.push({
      id:       'suspicious-tld',
      category: 'Domain',
      severity: 'medium',
      title:    `High-Abuse Top-Level Domain (.${urlData.tld})`,
      description:
        `The domain uses the .${urlData.tld} top-level domain. Security research reports ` +
        'indicate that certain low-cost or unmoderated TLDs frequently host temporary phishing ' +
        'infrastructure. While legitimate websites also use this TLD, it is a recognized risk contributor.',
      weight: 20,
    });
  }
}

/**
 * CHECK 12: @ Symbol in Authority
 * Trick: https://legitimate.com@attacker.com - the browser ignores legitimate.com
 */
function checkAtSymbol(urlData, evidence) {
  if (urlData.hasAtSymbol) {
    evidence.push({
      id:       'at-symbol-obfuscation',
      category: 'URL Structure',
      severity: 'high',
      title:    '@ Symbol Detected in Authority (Host Confusion Trick)',
      description:
        'The URL contains an "@" symbol. Under standard URL specifications, characters ' +
        'preceding the "@" are interpreted as user credentials, and the browser connects ' +
        'exclusively to the hostname that follows. Attackers use this to display a trusted ' +
        'domain in front of the "@" to deceive users into thinking they are visiting a safe site.',
      weight: 35,
    });
  }
}

/**
 * CHECK 13: Dangerous Executable File Extension
 * Points directly to .exe, .scr, .iso, .bat, etc.
 */
function checkDangerousExtension(urlData, evidence) {
  if (urlData.hasDangerousExtension) {
    evidence.push({
      id:       'dangerous-extension',
      category: 'Payload',
      severity: 'high',
      title:    'Dangerous Executable File Download Target',
      description:
        'The URL path points directly to a high-risk executable or script file extension ' +
        '(such as .exe, .scr, .iso, or .bat). Deceptive links pointing to executable files ' +
        'are a primary delivery mechanism for malware and ransomware payloads.',
      weight: 35,
    });
  }
}

/**
 * CHECK 14: Multiple Consecutive Slashes in Path
 * Often used to bypass web application firewalls or trick URL parsers.
 */
function checkDoubleSlash(urlData, evidence) {
  if (urlData.hasDoubleSlashPath) {
    evidence.push({
      id:       'double-slash-path',
      category: 'URL Structure',
      severity: 'low',
      title:    'Consecutive Slashes in Path (Path Normalization Anomaly)',
      description:
        'The URL path contains multiple consecutive slashes ("//"). This structural anomaly ' +
        'can be exploited to bypass filtering rules, confuse logging systems, or ' +
        'trigger open redirect vulnerabilities on unhardened web servers.',
      weight: 12,
    });
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/**
 * Format a keyword array as a readable quoted list.
 * @param {string[]} keywords
 * @returns {string}
 */
function formatList(keywords) {
  return keywords.map(k => `"${k}"`).join(', ');
}

