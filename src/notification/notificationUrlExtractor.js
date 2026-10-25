/**
 * notificationUrlExtractor.js
 * Phase 3B-3: Notification URL Extraction Module
 *
 * Responsibilities:
 * 1. Identify and extract valid http:// and https:// URLs from raw notification text.
 * 2. Strip leading and trailing punctuation (parentheses, brackets, quotes, commas, trailing periods).
 * 3. Preserve valid URL query parameters, fragments, ports, and internal punctuation.
 * 4. Reject arbitrary text, emails, non-HTTP schemes, and malformed strings.
 * 5. Normalize valid URLs using standard URL parsing.
 * 6. Support multiple distinct URLs in a single notification.
 * 7. Deduplicate identical URLs within the same notification content.
 *
 * Privacy Guarantees:
 * - This function extracts ONLY URL strings.
 * - Does not store, log, or transmit any part of the surrounding message text.
 */

'use strict';

/**
 * Characters that frequently attach to URLs as sentence endings or enclosing quotes/brackets.
 */
const TRAILING_PUNCTUATION_REGEX = /[.,;:!?*'"`<>)}\]]+$/;
const LEADING_PUNCTUATION_REGEX = /^['"`(<[{]+/;

/**
 * Clean surrounding punctuation from a candidate URL token while preserving
 * balanced internal structure.
 *
 * @param {string} token - Raw candidate string
 * @returns {string} Stripped candidate string
 */
function cleanCandidateToken(token) {
  if (!token) return '';
  let cleaned = token.trim();

  // Strip leading punctuation
  cleaned = cleaned.replace(LEADING_PUNCTUATION_REGEX, '');

  // Strip trailing punctuation
  while (TRAILING_PUNCTUATION_REGEX.test(cleaned)) {
    // If it ends with ')', check if parentheses are balanced in the URL
    if (cleaned.endsWith(')')) {
      const openCount = (cleaned.match(/\(/g) || []).length;
      const closeCount = (cleaned.match(/\)/g) || []).length;
      if (closeCount > openCount) {
        cleaned = cleaned.slice(0, -1);
        continue;
      }
      break;
    }
    // If it ends with ']', check if brackets are balanced
    if (cleaned.endsWith(']')) {
      const openCount = (cleaned.match(/\[/g) || []).length;
      const closeCount = (cleaned.match(/\]/g) || []).length;
      if (closeCount > openCount) {
        cleaned = cleaned.slice(0, -1);
        continue;
      }
      break;
    }
    // If it ends with '}', check if braces are balanced
    if (cleaned.endsWith('}')) {
      const openCount = (cleaned.match(/\{/g) || []).length;
      const closeCount = (cleaned.match(/\}/g) || []).length;
      if (closeCount > openCount) {
        cleaned = cleaned.slice(0, -1);
        continue;
      }
      break;
    }
    // Strip other trailing sentence punctuation and quotes
    cleaned = cleaned.replace(/[.,;:!?*'"`<>]+$/, '');
  }

  return cleaned;
}

/**
 * Validate and normalize a candidate URL string.
 *
 * @param {string} candidate
 * @returns {string|null} Normalized URL string, or null if invalid
 */
export function normalizeNotificationUrl(candidate) {
  if (!candidate || typeof candidate !== 'string') return null;

  const cleaned = cleanCandidateToken(candidate);
  if (!cleaned) return null;

  // Must explicitly start with http:// or https://
  if (!cleaned.startsWith('http://') && !cleaned.startsWith('https://')) {
    return null;
  }

  try {
    const parsed = new URL(cleaned);

    // Strictly enforce http or https protocol
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    // Hostname must be present and valid
    const host = parsed.hostname;
    if (!host || host.length < 1) {
      return null;
    }

    // Hostname must not contain spaces or control characters
    if (/[\s<>"/\\`|{}[\]]/.test(host)) {
      return null;
    }

    // Hostname must have at least one dot unless it's localhost or an IPv4/IPv6 address
    const isLocalhost = host.toLowerCase() === 'localhost';
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
    const isIpv6 = host.startsWith('[') && host.endsWith(']');
    const hasDot = host.includes('.');

    if (!isLocalhost && !isIpv4 && !isIpv6 && !hasDot) {
      return null;
    }

    // Disallow hosts that are just dots or end in a dot with no domain
    if (host.startsWith('.') || (host.endsWith('.') && !hasDot)) {
      return null;
    }

    // Return the clean URL string.
    // If the input didn't have a trailing slash for a bare host, keep it clean or use parsed.href
    return parsed.href;
  } catch (_) {
    return null;
  }
}

/**
 * Extract all unique, valid URLs from raw notification text.
 *
 * @param {string} text - Raw notification text content
 * @returns {string[]} Array of unique, normalized URL strings
 */
export function extractNotificationUrls(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  // Quick rejection if neither scheme is present
  if (!text.includes('http://') && !text.includes('https://')) {
    return [];
  }

  // Regex matches candidate tokens starting with http:// or https:// until whitespace
  const urlRegex = /https?:\/\/[^\s<>"'`]+/gi;
  const matches = text.match(urlRegex);

  if (!matches || matches.length === 0) {
    return [];
  }

  const uniqueUrls = new Set();

  for (const match of matches) {
    const normalized = normalizeNotificationUrl(match);
    if (normalized) {
      uniqueUrls.add(normalized);
    }
  }

  return Array.from(uniqueUrls);
}
