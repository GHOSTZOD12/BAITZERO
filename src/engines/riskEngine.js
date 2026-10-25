/**
 * riskEngine.js
 *
 * Calculates an internal risk classification from a list of evidence items.
 *
 * IMPORTANT DISCLAIMER:
 * The score and risk level produced here are internal project classifications
 * based on the weighted sum of detected URL indicators. They are NOT:
 * - A statistically validated probability of phishing
 * - A guarantee that a URL is safe or malicious
 * - A replacement for professional threat intelligence
 *
 * Risk Levels and Thresholds:
 *   LOW    — score  0 to 19  (few or weak indicators)
 *   MEDIUM — score 20 to 44  (multiple low-confidence or one moderate indicator)
 *   HIGH   — score 45+       (one strong indicator, or several moderate ones together)
 *
 * Thresholds are exported so they can be adjusted without changing engine logic.
 *
 * Example accumulations:
 *   https://example.com               → 0 items   → score  0 → LOW
 *   http://example.com                → 1 item    → score 15 → LOW
 *   http://example.com/verify-account → 2 items   → score 33 → MEDIUM
 *   http://192.168.1.10/login         → 3 items   → score 65 → HIGH
 *   https://paypal.login.attacker.com → 2 items   → score 45 → HIGH
 */

// ---------------------------------------------------------------------------
// Configurable thresholds
// Change these values here to adjust sensitivity without touching check logic.
// ---------------------------------------------------------------------------
export const RISK_THRESHOLDS = {
  LOW_MAX:    19, // Inclusive upper bound for LOW
  MEDIUM_MAX: 44, // Inclusive upper bound for MEDIUM
  // Anything above MEDIUM_MAX is HIGH
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Calculate the risk classification from an array of evidence items.
 *
 * @param {Array<object>} evidenceList - Output of evidenceEngine.collectEvidence()
 * @returns {{
 *   score: number,
 *   level: 'LOW' | 'MEDIUM' | 'HIGH',
 *   evidenceCount: number,
 *   highSeverityCount: number,
 *   mediumSeverityCount: number,
 *   lowSeverityCount: number,
 * }}
 */
export function calculateRisk(evidenceList) {
  if (!Array.isArray(evidenceList) || evidenceList.length === 0) {
    return {
      score:              0,
      level:              'LOW',
      evidenceCount:      0,
      highSeverityCount:  0,
      mediumSeverityCount: 0,
      lowSeverityCount:   0,
    };
  }

  // Sum the weight of all evidence items
  const score = evidenceList.reduce((total, item) => total + (item.weight || 0), 0);

  // Count items by severity
  const highSeverityCount   = evidenceList.filter(e => e.severity === 'high').length;
  const mediumSeverityCount = evidenceList.filter(e => e.severity === 'medium').length;
  const lowSeverityCount    = evidenceList.filter(e => e.severity === 'low').length;

  // Map score to level using thresholds
  let level;
  if (score <= RISK_THRESHOLDS.LOW_MAX) {
    level = 'LOW';
  } else if (score <= RISK_THRESHOLDS.MEDIUM_MAX) {
    level = 'MEDIUM';
  } else {
    level = 'HIGH';
  }

  return {
    score,
    level,
    evidenceCount:      evidenceList.length,
    highSeverityCount,
    mediumSeverityCount,
    lowSeverityCount,
  };
}

/**
 * Return a human-readable description of what the score represents.
 * Used in the UI to clarify that the score is not a phishing probability.
 *
 * @returns {string}
 */
export function getScoreDisclaimer() {
  return (
    'This is an internal risk classification score based on the weighted sum of ' +
    'detected URL indicators. It is not a probability and does not guarantee that ' +
    'the link is safe or malicious.'
  );
}
