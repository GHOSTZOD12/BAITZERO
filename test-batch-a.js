/**
 * test-batch-a.js
 * Automated regression test suite for Batch A: Local Scan Accuracy Fixes.
 *
 * Verifies:
 * 1. Authority '@' detection without false positives on query/fragment email addresses.
 * 2. Brand matching using label boundaries to avoid substring false positives (pineapple, amazonas).
 * 3. Multi-part country-code domain parsing (.co.uk, .com.au, .co.jp, etc.).
 */

import { parseUrl } from './src/engines/urlAnalyzer.js';
import { collectEvidence } from './src/engines/evidenceEngine.js';
import { calculateRisk } from './src/engines/riskEngine.js';
import { generateExplanation } from './src/engines/explanationEngine.js';

let passed = 0;
let failed = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName} - ${details}`);
    failed++;
  }
}

console.log('====================================================');
console.log(' BATCH A: LOCAL SCAN ACCURACY VERIFICATION');
console.log('====================================================\n');

// -------------------------------------------------------------------
// 1. At-Symbol (@) Authority Detection Tests
// -------------------------------------------------------------------
console.log('--- 1. At-Symbol (@) Authority Tests ---');

// 1.1 Query parameter with email must NOT trigger at-symbol-obfuscation
const t1_url = 'https://support.google.com/mail/answer/1234?user=alice@example.com';
const t1_parsed = parseUrl(t1_url);
const t1_ev = collectEvidence(t1_parsed.data);
const t1_hasAtFlag = t1_ev.some(e => e.id === 'at-symbol-obfuscation');
assert(!t1_parsed.data.hasAtSymbol, 'Test 1.1a: hasAtSymbol is false for query email');
assert(!t1_hasAtFlag, 'Test 1.1b: at-symbol-obfuscation evidence NOT present for query email');

// 1.2 Unsubscribe query parameter with email must NOT trigger
const t2_url = 'https://newsletter.sub.domain/unsubscribe?email=test@test.com';
const t2_parsed = parseUrl(t2_url);
const t2_ev = collectEvidence(t2_parsed.data);
const t2_hasAtFlag = t2_ev.some(e => e.id === 'at-symbol-obfuscation');
assert(!t2_parsed.data.hasAtSymbol, 'Test 1.2a: hasAtSymbol is false for newsletter query email');
assert(!t2_hasAtFlag, 'Test 1.2b: at-symbol-obfuscation evidence NOT present for newsletter query email');

// 1.3 URL fragment with email must NOT trigger
const t3_url = 'https://example.com/path#contact=user@example.com';
const t3_parsed = parseUrl(t3_url);
const t3_ev = collectEvidence(t3_parsed.data);
const t3_hasAtFlag = t3_ev.some(e => e.id === 'at-symbol-obfuscation');
assert(!t3_parsed.data.hasAtSymbol, 'Test 1.3a: hasAtSymbol is false for fragment email');
assert(!t3_hasAtFlag, 'Test 1.3b: at-symbol-obfuscation evidence NOT present for fragment email');

// 1.4 True authority confusion (user-info trick) MUST trigger
const t4_url = 'https://trusted.example@attacker.example/';
const t4_parsed = parseUrl(t4_url);
const t4_ev = collectEvidence(t4_parsed.data);
const t4_hasAtFlag = t4_ev.some(e => e.id === 'at-symbol-obfuscation');
assert(t4_parsed.data.hasAtSymbol, 'Test 1.4a: hasAtSymbol is true for authority userinfo');
assert(t4_hasAtFlag, 'Test 1.4b: at-symbol-obfuscation evidence IS present for authority userinfo');

// -------------------------------------------------------------------
// 2. Brand Substring Matching Tests
// -------------------------------------------------------------------
console.log('\n--- 2. Brand Boundary Matching Tests ---');

// 2.1 pineapple.com must not be flagged as Apple
const t5_url = 'https://pineapple.com';
const t5_parsed = parseUrl(t5_url);
const t5_ev = collectEvidence(t5_parsed.data);
const t5_hasApple = t5_ev.some(e => e.id === 'lookalike-apple');
assert(!t5_hasApple, 'Test 2.1a: pineapple.com NOT flagged as Apple lookalike');
assert(calculateRisk(t5_ev).level === 'LOW', 'Test 2.1b: pineapple.com overall risk is LOW');

// 2.2 amazonas.com must not be flagged as Amazon
const t6_url = 'https://amazonas.com';
const t6_parsed = parseUrl(t6_url);
const t6_ev = collectEvidence(t6_parsed.data);
const t6_hasAmazon = t6_ev.some(e => e.id === 'lookalike-amazon');
assert(!t6_hasAmazon, 'Test 2.2a: amazonas.com NOT flagged as Amazon lookalike');
assert(calculateRisk(t6_ev).level === 'LOW', 'Test 2.2b: amazonas.com overall risk is LOW');

// 2.3 apple.example.invalid must be flagged as Apple lookalike (MEDIUM risk)
const t7_url = 'https://apple.example.invalid';
const t7_parsed = parseUrl(t7_url);
const t7_ev = collectEvidence(t7_parsed.data);
const t7_hasApple = t7_ev.some(e => e.id === 'lookalike-apple');
const t7_risk = calculateRisk(t7_ev);
assert(t7_hasApple, 'Test 2.3a: apple.example.invalid IS flagged as Apple lookalike');
assert(t7_risk.level === 'MEDIUM', `Test 2.3b: apple.example.invalid risk is MEDIUM (got ${t7_risk.level}, score ${t7_risk.score})`);

// 2.4 secure-apple.example.invalid must be flagged as Apple lookalike (HIGH risk due to keyword 'secure')
const t8_url = 'https://secure-apple.example.invalid';
const t8_parsed = parseUrl(t8_url);
const t8_ev = collectEvidence(t8_parsed.data);
const t8_hasApple = t8_ev.some(e => e.id === 'lookalike-apple');
const t8_risk = calculateRisk(t8_ev);
assert(t8_hasApple, 'Test 2.4a: secure-apple.example.invalid IS flagged as Apple lookalike');
assert(t8_risk.level === 'HIGH', `Test 2.4b: secure-apple.example.invalid risk is HIGH (got ${t8_risk.level}, score ${t8_risk.score})`);

// -------------------------------------------------------------------
// 3. Multi-Part Country-Code Domain Parsing Tests
// -------------------------------------------------------------------
console.log('\n--- 3. Multi-Part ccTLD Parsing Tests ---');

// 3.1 paypal.co.uk -> domain: paypal.co.uk, subdomains: []
const t9_url = 'https://paypal.co.uk';
const t9_parsed = parseUrl(t9_url);
const t9_ev = collectEvidence(t9_parsed.data);
assert(t9_parsed.data.domain === 'paypal.co.uk', `Test 3.1a: paypal.co.uk domain is "paypal.co.uk" (got "${t9_parsed.data.domain}")`);
assert(t9_parsed.data.subdomains.length === 0, `Test 3.1b: paypal.co.uk subdomains is empty (got ${JSON.stringify(t9_parsed.data.subdomains)})`);
assert(!t9_ev.some(e => e.id === 'lookalike-paypal'), 'Test 3.1c: paypal.co.uk NOT flagged as impersonation');

// 3.2 login.paypal.co.uk -> domain: paypal.co.uk, subdomains: ['login']
const t10_url = 'https://login.paypal.co.uk';
const t10_parsed = parseUrl(t10_url);
const t10_ev = collectEvidence(t10_parsed.data);
assert(t10_parsed.data.domain === 'paypal.co.uk', `Test 3.2a: login.paypal.co.uk domain is "paypal.co.uk" (got "${t10_parsed.data.domain}")`);
assert(t10_parsed.data.subdomains.length === 1 && t10_parsed.data.subdomains[0] === 'login', `Test 3.2b: login.paypal.co.uk subdomains is ["login"] (got ${JSON.stringify(t10_parsed.data.subdomains)})`);
assert(!t10_ev.some(e => e.id === 'lookalike-paypal'), 'Test 3.2c: login.paypal.co.uk NOT flagged as impersonation');

// 3.3 example.com.au -> domain: example.com.au, subdomains: []
const t11_url = 'https://example.com.au';
const t11_parsed = parseUrl(t11_url);
assert(t11_parsed.data.domain === 'example.com.au', `Test 3.3a: example.com.au domain is "example.com.au" (got "${t11_parsed.data.domain}")`);
assert(t11_parsed.data.subdomains.length === 0, `Test 3.3b: example.com.au subdomains is empty`);

// 3.4 sub.example.co.jp -> domain: example.co.jp, subdomains: ['sub']
const t12_url = 'https://sub.example.co.jp';
const t12_parsed = parseUrl(t12_url);
assert(t12_parsed.data.domain === 'example.co.jp', `Test 3.4a: sub.example.co.jp domain is "example.co.jp" (got "${t12_parsed.data.domain}")`);
assert(t12_parsed.data.subdomains.length === 1 && t12_parsed.data.subdomains[0] === 'sub', `Test 3.4b: sub.example.co.jp subdomains is ["sub"]`);

// 3.5 Normal .com domain -> example.com
const t13_url = 'https://example.com';
const t13_parsed = parseUrl(t13_url);
assert(t13_parsed.data.domain === 'example.com', `Test 3.5a: normal .com domain is "example.com" (got "${t13_parsed.data.domain}")`);
assert(t13_parsed.data.subdomains.length === 0, `Test 3.5b: example.com subdomains is empty`);

// 3.6 Multi-level subdomain under supported suffix -> multi.level.sub.example.co.uk
const t14_url = 'https://multi.level.sub.example.co.uk';
const t14_parsed = parseUrl(t14_url);
assert(t14_parsed.data.domain === 'example.co.uk', `Test 3.6a: domain is "example.co.uk" (got "${t14_parsed.data.domain}")`);
assert(
  t14_parsed.data.subdomains.join('.') === 'multi.level.sub',
  `Test 3.6b: subdomains are ["multi", "level", "sub"] (got ${JSON.stringify(t14_parsed.data.subdomains)})`
);

// -------------------------------------------------------------------
// 4. IP Literal and Normalization Non-Regression Tests
// -------------------------------------------------------------------
console.log('\n--- 4. IP Literal & Normalization Tests ---');

const t15_url = 'http://192.168.1.1/admin';
const t15_parsed = parseUrl(t15_url);
assert(t15_parsed.data.isIPv4, 'Test 4.1a: IPv4 detected');
assert(t15_parsed.data.domain === '192.168.1.1', 'Test 4.1b: IPv4 domain retained as IP');

const t16_url = 'http://[::1]/admin';
const t16_parsed = parseUrl(t16_url);
assert(t16_parsed.data.isIPv6, 'Test 4.2a: IPv6 detected');

console.log('\n====================================================');
console.log(` BATCH A RESULTS: ${passed} Passed, ${failed} Failed`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
