/**
 * explanationEngine.js
 *
 * Generates a plain-language explanation and a user-facing recommendation
 * from detected evidence and the calculated risk level.
 *
 * Rules:
 * - Explanations are built deterministically from actual evidence items only.
 * - Nothing is invented or assumed beyond what the evidence shows.
 * - If no evidence exists, the explanation says so clearly.
 * - No AI is used.
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate an explanation and recommendation based on evidence and risk.
 *
 * @param {Array<object>} evidenceList - From evidenceEngine.collectEvidence()
 * @param {{ level: string, score: number }} riskResult - From riskEngine.calculateRisk()
 * @returns {{ explanation: string, recommendation: string }}
 */
export function generateExplanation(evidenceList, riskResult) {
  return {
    explanation:    buildExplanation(evidenceList, riskResult.level),
    recommendation: buildRecommendation(riskResult.level),
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Build the explanation paragraph from evidence items.
 * Only mentions findings that are actually present.
 *
 * @param {Array<object>} evidenceList
 * @param {string} level
 * @returns {string}
 */
function buildExplanation(evidenceList, level) {
  if (evidenceList.length === 0) {
    return (
      'No suspicious indicators were detected in this URL. The structure, protocol, ' +
      'and domain appear consistent with a normal web address. Continue to apply ' +
      'general caution when visiting any unfamiliar website.'
    );
  }

  // Collect the IDs present in this evidence list
  const ids = new Set(evidenceList.map(e => e.id));

  // Build individual finding sentences based on what is actually detected
  const findings = [];

  if (ids.has('ip-hostname') || ids.has('ip-hostname-v6')) {
    findings.push(
      'The URL uses a raw IP address instead of a registered domain name, ' +
      'which is unusual for legitimate public-facing websites.'
    );
  }

  // Check for any lookalike/impersonation evidence
  const lookalike = evidenceList.find(e => e.category === 'Impersonation');
  if (lookalike) {
    findings.push(
      'The URL appears to reference a well-known service name within the domain, ' +
      'while the actual registered domain is different — a common pattern in deceptive links.'
    );
  }

  if (ids.has('punycode-hostname')) {
    findings.push(
      'The domain uses internationalized character encoding (Punycode), ' +
      'which has been used to create domains that visually resemble legitimate brands.'
    );
  }

  if (ids.has('http-protocol')) {
    findings.push(
      'The connection is unencrypted (HTTP), meaning any data transmitted could be ' +
      'intercepted by a third party on the same network.'
    );
  }

  if (ids.has('url-shortener')) {
    findings.push(
      'The link uses a URL shortening service, which prevents the actual ' +
      'destination from being assessed without following the redirect.'
    );
  }

  if (ids.has('suspicious-keywords')) {
    const kwEvidence = evidenceList.find(e => e.id === 'suspicious-keywords');
    if (kwEvidence) {
      const count = evidenceList.find(e => e.id === 'suspicious-keywords');
      findings.push(
        'The URL contains terms commonly associated with credential collection or ' +
        'account verification pages.'
      );
    }
  }

  if (ids.has('excessive-subdomains') || ids.has('deep-subdomains')) {
    findings.push('The URL has an unusually deep subdomain structure.');
  }

  if (ids.has('url-length-high') || ids.has('url-length-moderate')) {
    findings.push('The URL is notably longer than a typical web address.');
  }

  if (ids.has('encoded-characters')) {
    findings.push(
      'The URL contains a high number of encoded characters, which may ' +
      'be used to obscure the actual content.'
    );
  }

  if (ids.has('suspicious-port')) {
    findings.push('A non-standard network port is specified in the URL.');
  }

  if (ids.has('at-symbol-obfuscation')) {
    findings.push(
      'An "@" character was detected in the authority portion of the URL, a known ' +
      'trick used to deceive users regarding the actual destination server.'
    );
  }

  if (ids.has('suspicious-tld')) {
    findings.push(
      'The domain uses a top-level domain frequently associated with high rates of malicious registration.'
    );
  }

  if (ids.has('dangerous-extension')) {
    findings.push(
      'The URL targets a direct executable or script download, which carries immediate security risk.'
    );
  }

  if (ids.has('double-slash-path')) {
    findings.push('The path contains consecutive slashes that may indicate normalization evasion.');
  }

  // Compose the final explanation
  let intro;
  switch (level) {
    case 'HIGH':
      intro = 'Multiple indicators suggest this URL warrants serious caution before interaction.';
      break;
    case 'MEDIUM':
      intro = 'Some indicators were detected that suggest reviewing this URL carefully before proceeding.';
      break;
    default:
      intro = 'One or more minor indicators were noted in this URL.';
  }

  // If we built no specific sentences (shouldn't happen, but defensive)
  if (findings.length === 0) {
    return `${intro} Review the ${evidenceList.length} indicator(s) listed below for details.`;
  }

  return [intro, ...findings].join(' ');
}

/**
 * Return a fixed recommendation string based on risk level.
 *
 * @param {string} level
 * @returns {string}
 */
function buildRecommendation(level) {
  switch (level) {
    case 'HIGH':
      return (
        'Avoid interacting with this link. Do not enter passwords, OTPs, ' +
        'banking information, or payment details. If you need to ' +
        'verify an account or complete a transaction, navigate directly to the ' +
        "official website or use the service's official mobile application."
      );
    case 'MEDIUM':
      return (
        'Proceed with caution. Verify the sender and confirm the destination ' +
        'website carefully before entering any personal or financial information. ' +
        'When in doubt, access the service through its official website directly ' +
        'instead of following this link.'
      );
    case 'LOW':
    default:
      return (
        'No obvious suspicious indicators were detected. Continue with normal caution. ' +
        'Always verify the website address in your browser before entering ' +
        'sensitive information, regardless of how a link was received.'
      );
  }
}
