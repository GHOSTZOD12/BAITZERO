//! deep_scan.rs
//!
//! Phase 2: On-demand Deep Scan implementation for BaitZero.
//!
//! Core responsibilities:
//! 1. Strict URL and hostname validation (rejection of credentials, malformed URLs, unsupported schemes).
//! 2. IPv4 and IPv6 prohibited-range validation (SSRF defense against loopback, private, link-local,
//!    CGNAT, multicast, documentation, broadcast, and IPv4-mapped IPv6 targets).
//! 3. Structured, serializable result model aligning with the 5 Deep Research investigation modules:
//!    WHOIS (RDAP), DNS (DoH), TLS Certificate, Reputation & Blocklists, and Redirect Chain.
//! 4. Live network inspection modules:
//!    - DNS-over-HTTPS (DoH via Cloudflare)
//!    - RDAP domain registration (rdap.org bootstrap)
//!    - Direct in-band TLS handshake and leaf X.509 certificate parser
//!    - Hop-by-hop SSRF-safe redirect tracer with DNS rebinding defense
//!    - Abuse.ch URLhaus threat reputation cross-reference
//! 5. Bounded timeout and independent check status reporting.
//! 6. Strict on-demand execution — zero background polling, zero startup network requests.
//! 7. Privacy guarantees: Never mark unavailable evidence as safe; never expose paths, query strings,
//!    fragments, or credentials to third-party reputation or domain services.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use url::Url;
use x509_parser::prelude::*;

// ---------------------------------------------------------------------------
// Structured Result Data Models
// ---------------------------------------------------------------------------

/// Status of an individual investigation check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Check resolved with clean/expected indicators.
    Verified,
    /// Check detected an anomaly or risk factor.
    Suspicious,
    /// Upstream source unreachable, timed out, or not yet integrated.
    Unavailable,
    /// Check was deliberately skipped (e.g. target is IP literal or validation failed).
    Skipped,
    /// Check encountered an unrecoverable failure during execution.
    Error,
}

/// Structured outcome of a single investigation module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub status: CheckStatus,
    pub summary: String,
    pub source: Option<String>,
    pub details: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl CheckResult {
    pub fn verified(summary: impl Into<String>, source: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self {
            status: CheckStatus::Verified,
            summary: summary.into(),
            source: Some(source.into()),
            details,
            error: None,
        }
    }

    pub fn suspicious(summary: impl Into<String>, source: impl Into<String>, details: Option<serde_json::Value>) -> Self {
        Self {
            status: CheckStatus::Suspicious,
            summary: summary.into(),
            source: Some(source.into()),
            details,
            error: None,
        }
    }

    pub fn unavailable(summary: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Unavailable,
            summary: summary.into(),
            source: Some(source.into()),
            details: None,
            error: None,
        }
    }

    pub fn skipped(reason: impl Into<String>, source: Option<String>) -> Self {
        Self {
            status: CheckStatus::Skipped,
            summary: reason.into(),
            source,
            details: None,
            error: None,
        }
    }

    #[allow(dead_code)]
    pub fn error(err: impl Into<String>, source: Option<String>) -> Self {
        let err_str = err.into();
        Self {
            status: CheckStatus::Error,
            summary: format!("Check failed: {}", err_str),
            source,
            details: None,
            error: Some(err_str),
        }
    }
}

/// The 5 investigation modules comprising BaitZero Deep Scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanChecks {
    pub whois: CheckResult,
    pub dns: CheckResult,
    pub tls: CheckResult,
    pub reputation: CheckResult,
    pub redirect: CheckResult,
}

/// Outcome of destination validation prior to initiating any network activity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "message")]
pub enum ValidationStatus {
    Valid,
    Invalid(String),
    ProhibitedDestination(String),
}

/// Overall assessment verdict categories for Phase 3.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentVerdict {
    SuspiciousFindings,
    NoKnownThreats,
    Inconclusive,
}

/// Overall high-level assessment synthesized across all Phase 2/3 investigation checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallAssessment {
    pub verdict: AssessmentVerdict,
    pub title: String,
    pub description: String,
    pub suspicious_count: usize,
    pub verified_count: usize,
    pub unavailable_count: usize,
    pub skipped_count: usize,
    pub key_findings: Vec<String>,
}

/// Root data model returned by the `run_deep_scan` Tauri command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanResult {
    pub target_url: String,
    pub canonical_domain: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub scheme: Option<String>,
    pub is_ip_host: bool,
    pub validation: ValidationStatus,
    pub checks: DeepScanChecks,
    pub assessment: OverallAssessment,
    pub timestamp_ms: u64,
}

/// Evaluates the overall assessment verdict based on target validation and individual module outcomes.
pub fn evaluate_overall_assessment(validation: &ValidationStatus, checks: &DeepScanChecks) -> OverallAssessment {
    let all_checks = [
        ("Domain Registration (RDAP)", &checks.whois),
        ("DNS Records (DoH)", &checks.dns),
        ("TLS Certificate", &checks.tls),
        ("Reputation & Blocklists (URLhaus)", &checks.reputation),
        ("Redirect Chain", &checks.redirect),
    ];

    let mut suspicious_count = 0;
    let mut verified_count = 0;
    let mut unavailable_count = 0;
    let mut skipped_count = 0;
    let mut key_findings = Vec::new();

    for (name, check) in &all_checks {
        match check.status {
            CheckStatus::Suspicious => {
                suspicious_count += 1;
                key_findings.push(format!("{}: {}", name, check.summary));
            }
            CheckStatus::Verified => verified_count += 1,
            CheckStatus::Unavailable | CheckStatus::Error => unavailable_count += 1,
            CheckStatus::Skipped => skipped_count += 1,
        }
    }

    match validation {
        ValidationStatus::ProhibitedDestination(reason) => {
            return OverallAssessment {
                verdict: AssessmentVerdict::SuspiciousFindings,
                title: "Suspicious findings detected".into(),
                description: format!(
                    "The target URL connects to a prohibited, private, or loopback destination ({}). Probing was halted for SSRF security.",
                    reason
                ),
                suspicious_count: suspicious_count.max(1),
                verified_count,
                unavailable_count,
                skipped_count,
                key_findings: vec![format!("Prohibited Destination: {}", reason)],
            };
        }
        ValidationStatus::Invalid(msg) => {
            return OverallAssessment {
                verdict: AssessmentVerdict::Inconclusive,
                title: "Inconclusive: important checks were unavailable or incomplete".into(),
                description: format!("Target URL could not be validated: {}", msg),
                suspicious_count,
                verified_count,
                unavailable_count: unavailable_count + 1,
                skipped_count,
                key_findings: vec![format!("Invalid URL Target: {}", msg)],
            };
        }
        ValidationStatus::Valid => {}
    }

    if suspicious_count > 0 {
        return OverallAssessment {
            verdict: AssessmentVerdict::SuspiciousFindings,
            title: "Suspicious findings detected".into(),
            description: format!(
                "Deep Scan identified {} security anomaly or risk finding(s). Review the evidence below before proceeding.",
                suspicious_count
            ),
            suspicious_count,
            verified_count,
            unavailable_count,
            skipped_count,
            key_findings,
        };
    }

    // Critical check availability evaluation
    let dns_unavailable = matches!(checks.dns.status, CheckStatus::Unavailable | CheckStatus::Error);
    let redir_unavailable = matches!(checks.redirect.status, CheckStatus::Unavailable | CheckStatus::Error);

    if dns_unavailable || redir_unavailable || unavailable_count >= 2 {
        return OverallAssessment {
            verdict: AssessmentVerdict::Inconclusive,
            title: "Inconclusive: important checks were unavailable or incomplete".into(),
            description: "Critical verification lookups (such as DNS resolution or HTTP redirect tracing) could not be completed or timed out. A definitive safety determination cannot be made.".into(),
            suspicious_count,
            verified_count,
            unavailable_count,
            skipped_count,
            key_findings: vec!["One or more primary lookup services timed out or were unreachable.".into()],
        };
    }

    OverallAssessment {
        verdict: AssessmentVerdict::NoKnownThreats,
        title: "No known threats detected by the checks performed".into(),
        description: "All accessible investigation checks completed without identifying known malicious indicators or suspicious configurations. Note: Absence from threat feeds or standard configurations does not establish that a website is safe.".into(),
        suspicious_count,
        verified_count,
        unavailable_count,
        skipped_count,
        key_findings: vec![],
    }
}

// ---------------------------------------------------------------------------
// IP Range Validation (SSRF & Intranet Defense)
// ---------------------------------------------------------------------------

/// Validates whether an IPv4 address belongs to a prohibited/restricted network range.
pub fn is_prohibited_ipv4(ip: &Ipv4Addr) -> Result<(), &'static str> {
    let octets = ip.octets();

    // 0.0.0.0/8 — Current network / unspecified source
    if octets[0] == 0 {
        return Err("0.0.0.0/8 (Unspecified / local source only)");
    }

    // 10.0.0.0/8 — RFC 1918 Private network
    if octets[0] == 10 {
        return Err("10.0.0.0/8 (Private network)");
    }

    // 100.64.0.0/10 — RFC 6598 Shared address space (CGNAT)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return Err("100.64.0.0/10 (Shared address space / CGNAT)");
    }

    // 127.0.0.0/8 — RFC 1122 Loopback
    if octets[0] == 127 {
        return Err("127.0.0.0/8 (Loopback address)");
    }

    // 169.254.0.0/16 — RFC 3927 Link-Local / Cloud Metadata (169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 {
        return Err("169.254.0.0/16 (Link-local / Cloud metadata address)");
    }

    // 172.16.0.0/12 — RFC 1918 Private network (172.16.0.0 – 172.31.255.255)
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return Err("172.16.0.0/12 (Private network)");
    }

    // 192.0.0.0/24 — RFC 6890 IETF Protocol Assignments
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return Err("192.0.0.0/24 (IETF protocol assignments)");
    }

    // 192.0.2.0/24 — RFC 5737 Documentation (TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return Err("192.0.2.0/24 (Documentation / TEST-NET-1)");
    }

    // 192.168.0.0/16 — RFC 1918 Private network
    if octets[0] == 192 && octets[1] == 168 {
        return Err("192.168.0.0/16 (Private network)");
    }

    // 198.18.0.0/15 — RFC 2544 Benchmarking network (198.18.0.0 – 198.19.255.255)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Err("198.18.0.0/15 (Benchmarking network)");
    }

    // 198.51.100.0/24 — RFC 5737 Documentation (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return Err("198.51.100.0/24 (Documentation / TEST-NET-2)");
    }

    // 203.0.113.0/24 — RFC 5737 Documentation (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return Err("203.0.113.0/24 (Documentation / TEST-NET-3)");
    }

    // 224.0.0.0/4 — RFC 5771 Multicast (224.0.0.0 – 239.255.255.255)
    if octets[0] >= 224 && octets[0] <= 239 {
        return Err("224.0.0.0/4 (Multicast address)");
    }

    // 240.0.0.0/4 — RFC 1112 Reserved / Future use
    if octets[0] >= 240 {
        if octets == [255, 255, 255, 255] {
            return Err("255.255.255.255/32 (Limited broadcast)");
        }
        return Err("240.0.0.0/4 (Reserved / Future use)");
    }

    Ok(())
}

/// Validates whether an IPv6 address belongs to a prohibited/restricted network range.
pub fn is_prohibited_ipv6(ip: &Ipv6Addr) -> Result<(), &'static str> {
    let segments = ip.segments();

    // ::1 — Loopback
    if ip.is_loopback() {
        return Err("::1 (IPv6 Loopback)");
    }

    // :: — Unspecified
    if ip.is_unspecified() {
        return Err(":: (IPv6 Unspecified)");
    }

    // ::ffff:0:0/96 — IPv4-mapped IPv6 (RFC 4291)
    if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0xffff {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xFF) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xFF) as u8,
        );
        return is_prohibited_ipv4(&v4);
    }

    // ::0:0/96 — IPv4-compatible IPv6 (deprecated RFC 4291)
    if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xFF) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xFF) as u8,
        );
        return is_prohibited_ipv4(&v4);
    }

    // fc00::/7 — RFC 4193 Unique Local Address (ULA / Private)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Err("fc00::/7 (IPv6 Unique Local / Private)");
    }

    // fe80::/10 — RFC 4291 Link-Local Unicast
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Err("fe80::/10 (IPv6 Link-Local Unicast)");
    }

    // ff00::/8 — RFC 4291 Multicast
    if (segments[0] & 0xff00) == 0xff00 {
        return Err("ff00::/8 (IPv6 Multicast)");
    }

    // 2001:db8::/32 — RFC 3849 Documentation
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Err("2001:db8::/32 (IPv6 Documentation)");
    }

    // fec0::/10 — Deprecated Site-Local Unicast (RFC 3879)
    if (segments[0] & 0xffc0) == 0xfec0 {
        return Err("fec0::/10 (Deprecated IPv6 Site-Local Unicast)");
    }

    // 2002::/16 — 6to4 Encapsulation (RFC 3056): validate encapsulated IPv4
    if segments[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xFF) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xFF) as u8,
        );
        return is_prohibited_ipv4(&v4);
    }

    // 64:ff9b::/96 — IPv4/IPv6 Translation (RFC 6052 NAT64 Well-Known Prefix)
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xFF) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xFF) as u8,
        );
        return is_prohibited_ipv4(&v4);
    }

    // 100::/64 — RFC 6666 Discard Prefix
    if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
        return Err("100::/64 (IPv6 Discard-only prefix)");
    }

    Ok(())
}

/// Generic IP address prohibited-range check.
#[allow(dead_code)]
pub fn is_prohibited_ip(ip: &IpAddr) -> Result<(), &'static str> {
    match ip {
        IpAddr::V4(v4) => is_prohibited_ipv4(v4),
        IpAddr::V6(v6) => is_prohibited_ipv6(v6),
    }
}

// ---------------------------------------------------------------------------
// Strict URL & Hostname Validation
// ---------------------------------------------------------------------------

/// Parsed and validated representation of an input URL.
#[derive(Debug)]
pub struct ValidatedTarget {
    pub url: Url,
    pub host: String,
    pub canonical_domain: Option<String>,
    pub is_ip: bool,
    pub port: u16,
    pub scheme: String,
}

/// Performs strict validation on raw input string according to Phase 1 constraints:
/// - Rejects malformed URL syntax.
/// - Requires http: or https: scheme.
/// - Rejects embedded credentials (username/password).
/// - Rejects local/prohibited domains (localhost, .local, .internal, etc.).
/// - Rejects IP addresses in prohibited private/loopback/link-local ranges.
pub fn validate_url_target(input: &str) -> Result<ValidatedTarget, ValidationStatus> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ValidationStatus::Invalid("Target URL cannot be empty.".to_string()));
    }

    // Attempt URL parse. If missing scheme, attempt https:// fallback.
    let parsed_url = match Url::parse(trimmed) {
        Ok(u) => u,
        Err(_) => {
            if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
                Url::parse(&format!("https://{}", trimmed)).map_err(|e| {
                    ValidationStatus::Invalid(format!("Malformed URL: {}", e))
                })?
            } else {
                return Err(ValidationStatus::Invalid("Malformed URL syntax.".to_string()));
            }
        }
    };

    // 1. Enforce supported scheme (http or https only)
    let scheme = parsed_url.scheme().to_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(ValidationStatus::Invalid(format!(
            "Unsupported scheme '{}'. Only http:// and https:// URLs are supported.",
            scheme
        )));
    }

    // 2. Reject credentials in URL
    if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
        return Err(ValidationStatus::Invalid(
            "URLs containing embedded credentials (username or password) are rejected for security.".to_string(),
        ));
    }

    // 3. Validate host presence
    let host_str = match parsed_url.host_str() {
        Some(h) if !h.trim().is_empty() => h.trim().to_lowercase(),
        _ => return Err(ValidationStatus::Invalid("URL does not contain a valid host.".to_string())),
    };

    let effective_port = parsed_url.port().unwrap_or(if scheme == "https" { 443 } else { 80 });

    // 4. Evaluate host type (IP vs Domain)
    match parsed_url.host() {
        Some(url::Host::Ipv4(v4)) => {
            if let Err(reason) = is_prohibited_ipv4(&v4) {
                return Err(ValidationStatus::ProhibitedDestination(format!(
                    "IP address {} is in a prohibited range: {}",
                    v4, reason
                )));
            }
            Ok(ValidatedTarget {
                url: parsed_url,
                host: host_str,
                canonical_domain: None,
                is_ip: true,
                port: effective_port,
                scheme,
            })
        }
        Some(url::Host::Ipv6(v6)) => {
            if let Err(reason) = is_prohibited_ipv6(&v6) {
                return Err(ValidationStatus::ProhibitedDestination(format!(
                    "IPv6 address {} is in a prohibited range: {}",
                    v6, reason
                )));
            }
            Ok(ValidatedTarget {
                url: parsed_url,
                host: host_str,
                canonical_domain: None,
                is_ip: true,
                port: effective_port,
                scheme,
            })
        }
        Some(url::Host::Domain(d)) => {
            let domain_lower = d.to_lowercase();

            // Reject prohibited local / internal domains
            if domain_lower == "localhost"
                || domain_lower.ends_with(".localhost")
                || domain_lower.ends_with(".local")
                || domain_lower.ends_with(".internal")
                || domain_lower.ends_with(".lan")
                || domain_lower.ends_with(".home.arpa")
            {
                return Err(ValidationStatus::ProhibitedDestination(format!(
                    "Domain '{}' refers to a reserved local/internal destination.",
                    domain_lower
                )));
            }

            // Validate domain length and RFC 1035 labels
            if domain_lower.len() > 253 {
                return Err(ValidationStatus::Invalid("Domain name exceeds maximum length of 253 characters.".to_string()));
            }

            let labels: Vec<&str> = domain_lower.split('.').collect();
            if labels.len() < 2 {
                return Err(ValidationStatus::Invalid("Domain must contain at least one top-level domain label.".to_string()));
            }

            for label in &labels {
                if label.is_empty() {
                    return Err(ValidationStatus::Invalid("Domain contains consecutive dots or empty labels.".to_string()));
                }
                if label.len() > 63 {
                    return Err(ValidationStatus::Invalid(format!("Domain label '{}' exceeds 63 characters.", label)));
                }
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(ValidationStatus::Invalid(format!("Domain label '{}' cannot start or end with a hyphen.", label)));
                }
                if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(ValidationStatus::Invalid(format!("Domain label '{}' contains invalid characters.", label)));
                }
            }

            let canonical = extract_canonical_domain(&domain_lower);

            Ok(ValidatedTarget {
                url: parsed_url,
                host: domain_lower,
                canonical_domain: Some(canonical),
                is_ip: false,
                port: effective_port,
                scheme,
            })
        }
        None => Err(ValidationStatus::Invalid("Unable to determine URL host.".to_string())),
    }
}

/// Extracts the canonical registrable domain from a validated hostname.
/// Supports common multi-part ccTLDs (.co.uk, .com.au, .co.in, etc.)
pub fn extract_canonical_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }

    // Common two-part ccTLD suffixes
    let known_two_part = [
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "co.in", "net.in", "org.in", "gen.in", "gov.in", "nic.in", "ac.in", "edu.in",
        "co.jp", "ne.jp", "ac.jp",
        "com.br", "net.br", "org.br",
        "com.mx", "org.mx",
        "com.sg", "edu.sg",
        "com.tr", "org.tr",
    ];

    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if known_two_part.iter().any(|&s| s == last_two) && labels.len() >= 3 {
        // e.g. login.sub.example.co.uk -> example.co.uk (take 3 labels)
        return labels[labels.len() - 3..].join(".");
    }

    // Standard single-part TLD: take last 2 labels (e.g. login.example.com -> example.com)
    labels[labels.len() - 2..].join(".")
}

// ---------------------------------------------------------------------------
// Phase 2 Network Inspection Modules
// ---------------------------------------------------------------------------

// 1. DNS Lookup via DNS-over-HTTPS (RFC 8484)
#[derive(Deserialize, Debug)]
struct DohAnswer {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL")]
    #[allow(dead_code)]
    ttl: Option<u32>,
    data: String,
}

#[derive(Deserialize, Debug)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: i32,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

/// Queries public DNS-over-HTTPS for A and AAAA records of the validated host.
/// Strictly sends only the hostname (never full URL, path, or credentials).
pub async fn query_doh_records(client: &reqwest::Client, host: &str) -> CheckResult {
    let source = "DNS-over-HTTPS (Cloudflare)";

    let url_a = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", host);
    let resp_a = client.get(&url_a)
        .header("Accept", "application/dns-json")
        .send()
        .await;

    let res_a: Option<DohResponse> = match resp_a {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        _ => None,
    };

    let url_aaaa = format!("https://cloudflare-dns.com/dns-query?name={}&type=AAAA", host);
    let resp_aaaa = client.get(&url_aaaa)
        .header("Accept", "application/dns-json")
        .send()
        .await;

    let res_aaaa: Option<DohResponse> = match resp_aaaa {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        _ => None,
    };

    if res_a.is_none() && res_aaaa.is_none() {
        return CheckResult::unavailable("DoH resolver query failed or timed out", source);
    }

    // Check for NXDOMAIN (Status == 3)
    if let Some(ref a) = res_a {
        if a.status == 3 {
            return CheckResult::suspicious(
                format!("Domain '{}' does not exist (NXDOMAIN returned by DoH)", host),
                source,
                Some(serde_json::json!({ "status": 3, "status_name": "NXDOMAIN" })),
            );
        }
    }

    let mut a_ips: Vec<String> = Vec::new();
    let mut aaaa_ips: Vec<String> = Vec::new();
    let mut prohibited_ips: Vec<String> = Vec::new();

    if let Some(doh) = res_a {
        if let Some(answers) = doh.answer {
            for ans in answers {
                if ans.record_type == 1 {
                    let cleaned = ans.data.trim();
                    if let Ok(ip) = cleaned.parse::<Ipv4Addr>() {
                        if let Err(reason) = is_prohibited_ipv4(&ip) {
                            prohibited_ips.push(format!("IPv4 {} ({})", ip, reason));
                        }
                        a_ips.push(ip.to_string());
                    }
                }
            }
        }
    }

    if let Some(doh) = res_aaaa {
        if let Some(answers) = doh.answer {
            for ans in answers {
                if ans.record_type == 28 {
                    let cleaned = ans.data.trim();
                    if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
                        if let Err(reason) = is_prohibited_ipv6(&ip) {
                            prohibited_ips.push(format!("IPv6 {} ({})", ip, reason));
                        }
                        aaaa_ips.push(ip.to_string());
                    }
                }
            }
        }
    }

    if !prohibited_ips.is_empty() {
        return CheckResult::suspicious(
            format!("DNS resolves to prohibited IP address: {}", prohibited_ips.join(", ")),
            source,
            Some(serde_json::json!({
                "prohibited": prohibited_ips,
                "a": a_ips,
                "aaaa": aaaa_ips,
            })),
        );
    }

    if a_ips.is_empty() && aaaa_ips.is_empty() {
        return CheckResult::unavailable(
            format!("No A or AAAA address records returned for '{}'", host),
            source,
        );
    }

    CheckResult::verified(
        format!("Resolved {} IPv4 and {} IPv6 address(es) via Cloudflare DoH", a_ips.len(), aaaa_ips.len()),
        source,
        Some(serde_json::json!({
            "a": a_ips,
            "aaaa": aaaa_ips,
        })),
    )
}

// 2. RDAP Domain Registration Lookup (RFC 7482/7484)
/// Retrieves domain registration data from free RDAP bootstrap.
/// Strictly queries only the canonical registrable domain.
pub async fn query_rdap(client: &reqwest::Client, canonical_domain: Option<&str>, is_ip: bool) -> CheckResult {
    let source = "RDAP (rdap.org)";
    if is_ip {
        return CheckResult::skipped("Target is an IP literal; domain registration lookup skipped.", Some(source.into()));
    }
    let domain = match canonical_domain {
        Some(d) if !d.is_empty() => d,
        _ => return CheckResult::skipped("No registrable domain found for target.", Some(source.into())),
    };

    let url = format!("https://rdap.org/domain/{}", domain);
    let resp = match client.get(&url)
        .header("Accept", "application/rdap+json, application/json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return CheckResult::unavailable(
                format!("RDAP lookup timed out or service unreachable: {}", e),
                source,
            );
        }
    };

    let status_code = resp.status();
    if status_code == reqwest::StatusCode::NOT_FOUND {
        return CheckResult::suspicious(
            format!("No registration record found in public RDAP bootstrap for '{}' (domain may be unregistered or ccTLD not supported by RDAP)", domain),
            source,
            Some(serde_json::json!({ "http_status": 404, "domain": domain })),
        );
    }
    if status_code == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return CheckResult::unavailable("RDAP bootstrap rate limit exceeded (HTTP 429)", source);
    }
    if !status_code.is_success() {
        return CheckResult::unavailable(
            format!("RDAP lookup returned HTTP {}", status_code),
            source,
        );
    }

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => return CheckResult::unavailable(format!("Failed to parse RDAP JSON: {}", e), source),
    };

    // Extract registrar name
    let mut registrar_name = "Unknown Registrar".to_string();
    if let Some(entities) = val.get("entities").and_then(|e| e.as_array()) {
        for ent in entities {
            let is_registrar = ent.get("roles")
                .and_then(|r| r.as_array())
                .map(|roles| roles.iter().any(|role| role.as_str() == Some("registrar")))
                .unwrap_or(false);
            if is_registrar {
                if let Some(vcard) = ent.get("vcardArray").and_then(|v| v.as_array()) {
                    if vcard.len() >= 2 {
                        if let Some(properties) = vcard[1].as_array() {
                            for prop in properties {
                                if let Some(arr) = prop.as_array() {
                                    if arr.first().and_then(|s| s.as_str()) == Some("fn") {
                                        if let Some(name) = arr.get(3).and_then(|s| s.as_str()) {
                                            registrar_name = name.to_string();
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if let Some(handle) = ent.get("handle").and_then(|h| h.as_str()) {
                    registrar_name = handle.to_string();
                }
                break;
            }
        }
    }

    // Extract registration and expiration events
    let mut created_date: Option<String> = None;
    let mut expires_date: Option<String> = None;
    if let Some(events) = val.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let action = ev.get("eventAction").and_then(|a| a.as_str()).unwrap_or_default();
            let date = ev.get("eventDate").and_then(|d| d.as_str()).unwrap_or_default();
            if !date.is_empty() {
                if action == "registration" {
                    created_date = Some(date.to_string());
                } else if action == "expiration" {
                    expires_date = Some(date.to_string());
                }
            }
        }
    }

    let mut summary_parts = Vec::new();
    summary_parts.push(format!("Registrar: {}", registrar_name));
    if let Some(ref c) = created_date {
        summary_parts.push(format!("Created: {}", c.split('T').next().unwrap_or(c)));
    }
    if let Some(ref e) = expires_date {
        summary_parts.push(format!("Expires: {}", e.split('T').next().unwrap_or(e)));
    }

    let summary = summary_parts.join(" | ");
    CheckResult::verified(
        summary,
        source,
        Some(serde_json::json!({
            "domain": domain,
            "registrar": registrar_name,
            "created": created_date,
            "expires": expires_date,
            "status": val.get("status"),
        })),
    )
}

// 3. TLS Certificate Inspection
/// Checks if certificate pattern matches target hostname (including wildcard *.example.com)
pub fn matches_cert_hostname(cert_pattern: &str, target_host: &str) -> bool {
    let pattern = cert_pattern.trim().to_lowercase();
    let host = target_host.trim().to_lowercase();

    if pattern == host {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host.ends_with(suffix) && host.len() > suffix.len() {
            let prefix = &host[..host.len() - suffix.len()];
            if prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.') {
                return true;
            }
        }
    }

    false
}

/// In-band TLS handshake and leaf X.509 certificate inspector.
pub fn inspect_tls_certificate(target_host: &str, port: u16, scheme: &str, is_ip: bool) -> CheckResult {
    let source = "Direct In-Band TLS Handshake (Schannel)";
    if scheme != "https" {
        return CheckResult::skipped(
            format!("Target uses unencrypted HTTP (port {}); TLS certificate inspection skipped.", port),
            Some(source.into()),
        );
    }

    // Resolve target host with SSRF check
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = match (target_host, port).to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => return CheckResult::unavailable(format!("DNS resolution failed for TLS connection: {}", e), source),
    };

    let mut target_addr: Option<SocketAddr> = None;
    for addr in addrs {
        if let Err(reason) = is_prohibited_ip(&addr.ip()) {
            return CheckResult::suspicious(
                format!("TLS target resolves to prohibited IP address {} ({}) - SSRF blocked", addr.ip(), reason),
                source,
                Some(serde_json::json!({ "prohibited_ip": addr.ip().to_string(), "reason": reason })),
            );
        }
        if target_addr.is_none() {
            target_addr = Some(addr);
        }
    }

    let socket_addr = match target_addr {
        Some(a) => a,
        None => return CheckResult::unavailable("No socket addresses found for host", source),
    };

    let tcp = match std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_millis(3500)) {
        Ok(t) => t,
        Err(e) => return CheckResult::unavailable(format!("TCP connection to {}:{} timed out or failed: {}", target_host, port, e), source),
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(3500)));
    let _ = tcp.set_write_timeout(Some(Duration::from_millis(3500)));

    let strict_connector = match native_tls::TlsConnector::builder().build() {
        Ok(c) => c,
        Err(e) => return CheckResult::error(format!("Failed to build TLS connector: {}", e), Some(source.into())),
    };

    let mut trust_error: Option<String> = None;

    let (der_bytes, system_trusted) = match strict_connector.connect(target_host, tcp) {
        Ok(tls_stream) => {
            let cert = match tls_stream.peer_certificate() {
                Ok(Some(c)) => c,
                Ok(None) => return CheckResult::suspicious("No server certificate presented during TLS handshake", source, None),
                Err(e) => return CheckResult::unavailable(format!("Failed to retrieve peer certificate: {}", e), source),
            };
            let bytes = match cert.to_der() {
                Ok(b) => b,
                Err(e) => return CheckResult::unavailable(format!("Failed to extract DER certificate bytes: {}", e), source),
            };
            (bytes, true)
        }
        Err(native_tls::HandshakeError::Failure(e)) => {
            // System trust verification failed on the certificate chain (e.g. self-signed, expired, untrusted CA).
            trust_error = Some(e.to_string());
            // Connect with permissive connector to retrieve the leaf certificate so we can parse and report details.
            let tcp_fallback = match std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_millis(3500)) {
                Ok(t) => t,
                Err(conn_err) => {
                    return CheckResult::suspicious(
                        format!("TLS certificate verification failed ({}) and fallback connection could not be established: {}", e, conn_err),
                        source,
                        None,
                    );
                }
            };
            let _ = tcp_fallback.set_read_timeout(Some(Duration::from_millis(3500)));
            let _ = tcp_fallback.set_write_timeout(Some(Duration::from_millis(3500)));

            let permissive = match native_tls::TlsConnector::builder().danger_accept_invalid_certs(true).build() {
                Ok(p) => p,
                Err(err) => return CheckResult::error(format!("Failed to build fallback TLS connector: {}", err), Some(source.into())),
            };

            let fallback_stream = match permissive.connect(target_host, tcp_fallback) {
                Ok(s) => s,
                Err(h_err) => return CheckResult::unavailable(format!("Fallback TLS handshake failed: {}", h_err), source),
            };

            let cert = match fallback_stream.peer_certificate() {
                Ok(Some(c)) => c,
                Ok(None) => return CheckResult::suspicious("No server certificate presented during fallback TLS handshake", source, None),
                Err(err) => return CheckResult::unavailable(format!("Failed to retrieve peer certificate: {}", err), source),
            };

            let bytes = match cert.to_der() {
                Ok(b) => b,
                Err(err) => return CheckResult::unavailable(format!("Failed to extract DER certificate bytes: {}", err), source),
            };
            (bytes, false)
        }
        Err(native_tls::HandshakeError::WouldBlock(_)) => {
            return CheckResult::unavailable("TLS handshake timed out", source);
        }
    };

    let (_, parsed_cert) = match parse_x509_certificate(&der_bytes) {
        Ok(res) => res,
        Err(e) => return CheckResult::unavailable(format!("Failed to parse X.509 certificate: {}", e), source),
    };

    let subject_str = parsed_cert.subject().to_string();
    let issuer_str = parsed_cert.issuer().to_string();
    let not_before = parsed_cert.validity().not_before.timestamp();
    let not_after = parsed_cert.validity().not_after.timestamp();

    let mut sans: Vec<String> = Vec::new();
    for ext in parsed_cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(s) => sans.push(s.to_string()),
                    GeneralName::IPAddress(b) => {
                        if b.len() == 4 {
                            sans.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string());
                        } else if b.len() == 16 {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(b);
                            sans.push(Ipv6Addr::from(arr).to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if now_secs > not_after {
        return CheckResult::suspicious(
            format!("TLS certificate expired (notAfter: {})", not_after),
            source,
            Some(serde_json::json!({
                "subject": subject_str,
                "issuer": issuer_str,
                "not_before": not_before,
                "not_after": not_after,
                "sans": sans,
                "expired": true,
            })),
        );
    }

    if now_secs < not_before {
        return CheckResult::suspicious(
            format!("TLS certificate is not yet valid (notBefore: {})", not_before),
            source,
            Some(serde_json::json!({
                "subject": subject_str,
                "issuer": issuer_str,
                "not_before": not_before,
                "not_after": not_after,
            })),
        );
    }

    let mut matches_host = false;
    for san in &sans {
        if matches_cert_hostname(san, target_host) {
            matches_host = true;
            break;
        }
    }
    if !matches_host {
        for cn in parsed_cert.subject().iter_common_name() {
            if let Ok(cn_str) = cn.as_str() {
                if matches_cert_hostname(cn_str, target_host) {
                    matches_host = true;
                    break;
                }
            }
        }
    }

    if !matches_host && !is_ip {
        return CheckResult::suspicious(
            format!("Certificate hostname mismatch: certificate does not match requested host '{}' (SANs: [{}])", target_host, sans.join(", ")),
            source,
            Some(serde_json::json!({
                "target_host": target_host,
                "sans": sans,
                "subject": subject_str,
                "issuer": issuer_str,
            })),
        );
    }

    let days_remaining = (not_after - now_secs) / 86400;

    if !system_trusted {
        let err_desc = trust_error.unwrap_or_else(|| "Untrusted authority or invalid certificate chain".into());
        return CheckResult::suspicious(
            format!("TLS certificate is not trusted by system store: {} (Issuer: {})", err_desc, issuer_str),
            source,
            Some(serde_json::json!({
                "trusted": false,
                "trust_error": err_desc,
                "subject": subject_str,
                "issuer": issuer_str,
                "days_remaining": days_remaining,
                "sans": sans,
            })),
        );
    }

    CheckResult::verified(
        format!("Valid TLS certificate ({} days remaining) | Issuer: {} | Subject: {}", days_remaining, issuer_str, subject_str),
        source,
        Some(serde_json::json!({
            "trusted": true,
            "subject": subject_str,
            "issuer": issuer_str,
            "days_remaining": days_remaining,
            "not_before": not_before,
            "not_after": not_after,
            "sans": sans,
        })),
    )
}

// 4. Safe Hop-by-Hop Redirect Tracer with DNS Rebinding Defense
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    pub hop: usize,
    pub url: String,
    pub status: u16,
    pub ip: String,
    pub location: Option<String>,
}

pub async fn trace_redirects(start_url: &str) -> CheckResult {
    let source = "Out-of-Band Hop Tracer";
    let mut current_url_str = start_url.to_string();
    let initial_scheme = match Url::parse(start_url) {
        Ok(u) => u.scheme().to_string(),
        Err(e) => return CheckResult::error(format!("Invalid start URL: {}", e), Some(source.into())),
    };

    let mut hops: Vec<HopInfo> = Vec::new();
    let max_hops = 5;

    for hop_idx in 1..=max_hops {
        let parsed = match Url::parse(&current_url_str) {
            Ok(u) => u,
            Err(e) => return CheckResult::suspicious(
                format!("Redirect hop {} encountered malformed URL '{}': {}", hop_idx, current_url_str, e),
                source,
                Some(serde_json::json!({ "hops": hops })),
            ),
        };

        let scheme = parsed.scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return CheckResult::suspicious(
                format!("Redirect hop {} redirected to unsupported scheme '{}'", hop_idx, scheme),
                source,
                Some(serde_json::json!({ "hops": hops })),
            );
        }

        let host_str = match parsed.host_str() {
            Some(h) => h.to_string(),
            None => return CheckResult::suspicious("URL missing host in redirect chain", source, None),
        };

        let host_lower = host_str.to_lowercase();
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower.ends_with(".local")
            || host_lower.ends_with(".internal")
            || host_lower.ends_with(".lan")
            || host_lower.ends_with(".home.arpa")
        {
            return CheckResult::suspicious(
                format!("Redirect hop {} attempted to connect to prohibited internal host '{}'", hop_idx, host_str),
                source,
                Some(serde_json::json!({ "hops": hops, "blocked_host": host_str })),
            );
        }

        let port = parsed.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let host_clean = host_str.trim_start_matches('[').trim_end_matches(']');

        // Resolve DNS for host (clean IPv6 brackets if present)
        let resolved_addrs = match tokio::net::lookup_host((host_clean, port)).await {
            Ok(iter) => iter.collect::<Vec<SocketAddr>>(),
            Err(e) => {
                return CheckResult::unavailable(
                    format!("DNS resolution failed on redirect hop {}: {}", hop_idx, e),
                    source,
                );
            }
        };

        if resolved_addrs.is_empty() {
            return CheckResult::unavailable(
                format!("No IP addresses resolved on redirect hop {}", hop_idx),
                source,
            );
        }

        // Validate EVERY resolved IP for SSRF defense
        for addr in &resolved_addrs {
            if let Err(reason) = is_prohibited_ip(&addr.ip()) {
                return CheckResult::suspicious(
                    format!("Redirect hop {} ({}) resolved to prohibited IP address {} ({}) - SSRF blocked", hop_idx, host_str, addr.ip(), reason),
                    source,
                    Some(serde_json::json!({ "hops": hops, "prohibited_ip": addr.ip().to_string(), "reason": reason })),
                );
            }
        }

        let validated_socket = resolved_addrs[0];

        // Pin connection to validated IP with redirect policy NONE (prevents DNS rebinding)
        let mut client_builder = reqwest::Client::builder()
            .resolve(&host_str, validated_socket)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(3500));
        if host_clean != host_str {
            client_builder = client_builder.resolve(host_clean, validated_socket);
        }

        let client = match client_builder.build() {
            Ok(c) => c,
            Err(e) => return CheckResult::error(format!("Failed to build HTTP hop client: {}", e), Some(source.into())),
        };

        let mut resp = match client.head(&current_url_str).send().await {
            Ok(r) => r,
            Err(e) => {
                return CheckResult::unavailable(
                    format!("HTTP request failed on hop {} ({}): {}", hop_idx, current_url_str, e),
                    source,
                );
            }
        };

        // If server disallows HEAD (405 Method Not Allowed or 501 Not Implemented), fallback to GET with zero byte range
        if resp.status().as_u16() == 405 || resp.status().as_u16() == 501 {
            if let Ok(get_resp) = client.get(&current_url_str).header("Range", "bytes=0-0").send().await {
                resp = get_resp;
            }
        }

        let status = resp.status().as_u16();
        let location = resp.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|val| val.to_str().ok())
            .map(|s| s.to_string());

        let hop_info = HopInfo {
            hop: hop_idx,
            url: current_url_str.clone(),
            status,
            ip: validated_socket.ip().to_string(),
            location: location.clone(),
        };
        hops.push(hop_info);

        if [301, 302, 303, 307, 308].contains(&status) {
            let loc_str = match location {
                Some(ref l) if !l.is_empty() => l,
                _ => return CheckResult::suspicious(
                    format!("Hop {} returned redirect status {} without Location header", hop_idx, status),
                    source,
                    Some(serde_json::json!({ "hops": hops })),
                ),
            };

            let next_url = match parsed.join(loc_str) {
                Ok(u) => u,
                Err(e) => return CheckResult::suspicious(
                    format!("Hop {} returned invalid Location header '{}': {}", hop_idx, loc_str, e),
                    source,
                    Some(serde_json::json!({ "hops": hops })),
                ),
            };

            // Immediate cycle detection: if next_url was already visited in the hop chain
            if hops.iter().any(|h| h.url == next_url.to_string()) {
                return CheckResult::suspicious(
                    format!("Redirect cycle detected: loop back to '{}'", next_url),
                    source,
                    Some(serde_json::json!({ "hops": hops, "cycle_url": next_url.to_string() })),
                );
            }

            if hop_idx == max_hops {
                return CheckResult::suspicious(
                    format!("Redirect limit of {} hops exceeded (potential redirect loop or evasion)", max_hops),
                    source,
                    Some(serde_json::json!({ "hops": hops })),
                );
            }

            current_url_str = next_url.to_string();
        } else {
            break;
        }
    }

    let final_url = hops.last().map(|h| h.url.clone()).unwrap_or_else(|| start_url.to_string());
    let final_scheme = Url::parse(&final_url).map(|u| u.scheme().to_string()).unwrap_or_default();

    if initial_scheme == "https" && final_scheme == "http" {
        return CheckResult::suspicious(
            format!("Insecure protocol downgrade: redirected from HTTPS to unencrypted HTTP destination ({})", final_url),
            source,
            Some(serde_json::json!({ "hops": hops, "final_url": final_url })),
        );
    }

    if hops.len() <= 1 {
        let first_status = hops.first().map(|h| h.status).unwrap_or(200);
        CheckResult::verified(
            format!("No redirects detected (HTTP {})", first_status),
            source,
            Some(serde_json::json!({ "hops": hops, "final_url": final_url })),
        )
    } else {
        CheckResult::verified(
            format!("Followed {} safe redirect(s) to destination: {}", hops.len() - 1, final_url),
            source,
            Some(serde_json::json!({ "hops": hops, "final_url": final_url })),
        )
    }
}

// 5. Threat Reputation Lookup via Abuse.ch URLhaus
/// Queries community threat intelligence for validated host or canonical domain.
/// Non-blocking, strictly queries hostname without full path or query parameters.
pub async fn query_urlhaus_reputation(client: &reqwest::Client, host_or_domain: &str) -> CheckResult {
    let source = "Abuse.ch URLhaus Community API";
    let url = "https://urlhaus-api.abuse.ch/v1/host/";

    let form_params = [("host", host_or_domain)];
    let resp = match client.post(url)
        .form(&form_params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return CheckResult::unavailable(
                format!("URLhaus query timed out or unreachable: {}", e),
                source,
            );
        }
    };

    if !resp.status().is_success() {
        return CheckResult::unavailable(
            format!("URLhaus returned HTTP status {}", resp.status()),
            source,
        );
    }

    let val: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return CheckResult::unavailable(
                format!("Failed to parse URLhaus response: {}", e),
                source,
            );
        }
    };

    let query_status = val.get("query_status").and_then(|s| s.as_str()).unwrap_or("unknown");
    match query_status {
        "ok" => {
            let url_count = val.get("url_count").and_then(|c| c.as_u64()).unwrap_or(0);
            let threat = val.get("threat").and_then(|t| t.as_str()).unwrap_or("malware");
            if url_count > 0 {
                CheckResult::suspicious(
                    format!("Flagged on Abuse.ch URLhaus: {} malicious URL(s) detected (threat: {})", url_count, threat),
                    source,
                    Some(serde_json::json!({
                        "query_status": "ok",
                        "url_count": url_count,
                        "threat": threat,
                        "firstseen": val.get("firstseen"),
                    })),
                )
            } else {
                CheckResult::verified(
                    "Listed on URLhaus with 0 active malicious URLs",
                    source,
                    Some(serde_json::json!({ "query_status": "ok", "url_count": 0 })),
                )
            }
        }
        "no_results" => {
            CheckResult::verified(
                "Not currently listed in Abuse.ch URLhaus malware feed (absence from feed does not guarantee safety)",
                source,
                Some(serde_json::json!({ "query_status": "no_results" })),
            )
        }
        other => {
            CheckResult::unavailable(
                format!("URLhaus returned status: {}", other),
                source,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Execution Engine (Async Bounded Dispatcher)
// ---------------------------------------------------------------------------

/// Executes Phase 2 on-demand Deep Scan for a target URL.
///
/// Bounded execution guarantees:
/// - Strictly on-demand; zero background loops or polling.
/// - Validates destination and rejects prohibited network targets immediately.
/// - Concurrently dispatches all 5 investigation modules with individual timeouts.
/// - Never marks unavailable evidence as safe.
pub async fn execute_deep_scan(raw_url: String) -> DeepScanResult {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // 1. Strict Validation
    match validate_url_target(&raw_url) {
        Err(ValidationStatus::ProhibitedDestination(reason)) => {
            let validation = ValidationStatus::ProhibitedDestination(reason.clone());
            let checks = DeepScanChecks {
                whois: CheckResult::skipped(format!("Skipped: Target is a prohibited destination ({})", reason), Some("RDAP".into())),
                dns: CheckResult::skipped(format!("Skipped: Target is a prohibited destination ({})", reason), Some("DNS-over-HTTPS".into())),
                tls: CheckResult::skipped(format!("Skipped: Target is a prohibited destination ({})", reason), Some("TLS Handshake".into())),
                reputation: CheckResult::skipped(format!("Skipped: Target is a prohibited destination ({})", reason), Some("Public Blocklists".into())),
                redirect: CheckResult::skipped(format!("Skipped: Target is a prohibited destination ({})", reason), Some("Redirect Tracer".into())),
            };
            let assessment = evaluate_overall_assessment(&validation, &checks);
            DeepScanResult {
                target_url: raw_url,
                canonical_domain: None,
                host: None,
                port: None,
                scheme: None,
                is_ip_host: false,
                validation,
                checks,
                assessment,
                timestamp_ms: now_ms,
            }
        }
        Err(ValidationStatus::Invalid(msg)) => {
            let validation = ValidationStatus::Invalid(msg.clone());
            let checks = DeepScanChecks {
                whois: CheckResult::skipped(format!("Skipped: Invalid URL ({})", msg), Some("RDAP".into())),
                dns: CheckResult::skipped(format!("Skipped: Invalid URL ({})", msg), Some("DNS-over-HTTPS".into())),
                tls: CheckResult::skipped(format!("Skipped: Invalid URL ({})", msg), Some("TLS Handshake".into())),
                reputation: CheckResult::skipped(format!("Skipped: Invalid URL ({})", msg), Some("Public Blocklists".into())),
                redirect: CheckResult::skipped(format!("Skipped: Invalid URL ({})", msg), Some("Redirect Tracer".into())),
            };
            let assessment = evaluate_overall_assessment(&validation, &checks);
            DeepScanResult {
                target_url: raw_url,
                canonical_domain: None,
                host: None,
                port: None,
                scheme: None,
                is_ip_host: false,
                validation,
                checks,
                assessment,
                timestamp_ms: now_ms,
            }
        }
        Err(ValidationStatus::Valid) => unreachable!(),
        Ok(target) => {
            let scan_future = async {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_millis(3500))
                    .user_agent("BaitZero-DeepScan/1.0")
                    .build()
                    .unwrap_or_default();

                let doh_future = query_doh_records(&client, &target.host);
                let rdap_future = query_rdap(&client, target.canonical_domain.as_deref(), target.is_ip);
                let urlhaus_future = query_urlhaus_reputation(&client, target.canonical_domain.as_deref().unwrap_or(&target.host));
                let target_url_str = target.url.to_string();
                let redir_future = trace_redirects(&target_url_str);

                let host_tls = target.host.clone();
                let scheme_tls = target.scheme.clone();
                let port_tls = target.port;
                let is_ip_tls = target.is_ip;
                let tls_future = tokio::task::spawn_blocking(move || {
                    inspect_tls_certificate(&host_tls, port_tls, &scheme_tls, is_ip_tls)
                });

                let (dns, whois, tls_res, reputation, redirect) = tokio::join!(
                    doh_future,
                    rdap_future,
                    tls_future,
                    urlhaus_future,
                    redir_future,
                );

                let tls = tls_res.unwrap_or_else(|e| {
                    CheckResult::unavailable(format!("TLS inspection task error: {}", e), "Direct In-Band TLS Handshake (Schannel)")
                });

                DeepScanChecks {
                    whois,
                    dns,
                    tls,
                    reputation,
                    redirect,
                }
            };

            let checks = match tokio::time::timeout(Duration::from_secs(8), scan_future).await {
                Ok(c) => c,
                Err(_) => DeepScanChecks {
                    whois: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "RDAP"),
                    dns: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "DNS-over-HTTPS"),
                    tls: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Direct In-Band TLS Handshake"),
                    reputation: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Abuse.ch URLhaus"),
                    redirect: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Out-of-Band Hop Tracer"),
                },
            };

            let assessment = evaluate_overall_assessment(&ValidationStatus::Valid, &checks);

            DeepScanResult {
                target_url: target.url.to_string(),
                canonical_domain: target.canonical_domain,
                host: Some(target.host),
                port: Some(target.port),
                scheme: Some(target.scheme),
                is_ip_host: target.is_ip,
                validation: ValidationStatus::Valid,
                checks,
                assessment,
                timestamp_ms: now_ms,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri Command Entry Point
// ---------------------------------------------------------------------------

/// On-demand Tauri command to run Phase 2 Deep Scan.
#[tauri::command]
pub async fn run_deep_scan(url: String) -> Result<DeepScanResult, String> {
    eprintln!("[DeepScan] Phase 2 on-demand scan invoked | length={}", url.len());
    let result = execute_deep_scan(url).await;
    eprintln!("[DeepScan] Phase 2 scan completed | validation={:?}", result.validation);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prohibited_ipv4_loopback() {
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(127, 0, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(127, 10, 20, 30)).is_err());
    }

    #[test]
    fn test_prohibited_ipv4_private() {
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(10, 0, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(172, 16, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(172, 31, 255, 254)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(192, 168, 1, 100)).is_err());
    }

    #[test]
    fn test_prohibited_ipv4_link_local_and_cgnat() {
        // Link-local / AWS metadata
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(169, 254, 169, 254)).is_err());
        // CGNAT
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(100, 64, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(100, 127, 255, 254)).is_err());
    }

    #[test]
    fn test_prohibited_ipv4_special() {
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(0, 0, 0, 0)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(224, 0, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(255, 255, 255, 255)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(240, 0, 0, 1)).is_err());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(192, 0, 2, 1)).is_err());
    }

    #[test]
    fn test_allowed_ipv4_public() {
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(8, 8, 8, 8)).is_ok());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(1, 1, 1, 1)).is_ok());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(93, 184, 216, 34)).is_ok());
        assert!(is_prohibited_ipv4(&Ipv4Addr::new(172, 32, 0, 1)).is_ok());
    }

    #[test]
    fn test_prohibited_ipv6_ranges() {
        // Loopback
        assert!(is_prohibited_ipv6(&Ipv6Addr::LOCALHOST).is_err());
        // Unspecified
        assert!(is_prohibited_ipv6(&Ipv6Addr::UNSPECIFIED).is_err());
        // Link-local unicast fe80::/10
        let fe80 = "fe80::1".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&fe80).is_err());
        // ULA fc00::/7
        let fc00 = "fc00::1".parse::<Ipv6Addr>().unwrap();
        let fd12 = "fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&fc00).is_err());
        assert!(is_prohibited_ipv6(&fd12).is_err());
    }

    #[test]
    fn test_prohibited_ipv6_mapped_ipv4() {
        // ::ffff:127.0.0.1
        let mapped_loopback = "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&mapped_loopback).is_err());
        // ::ffff:192.168.1.1
        let mapped_private = "::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&mapped_private).is_err());
        // ::ffff:8.8.8.8 (Public mapped)
        let mapped_public = "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&mapped_public).is_ok());
    }

    #[test]
    fn test_allowed_ipv6_public() {
        let cloudflare_v6 = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&cloudflare_v6).is_ok());
        let google_v6 = "2001:4860:4860::8888".parse::<Ipv6Addr>().unwrap();
        assert!(is_prohibited_ipv6(&google_v6).is_ok());
    }

    #[test]
    fn test_url_validation_rejection_credentials() {
        let res = validate_url_target("https://admin:secret@bank.com/login");
        assert!(matches!(res, Err(ValidationStatus::Invalid(_))));

        let res2 = validate_url_target("http://user@example.com/");
        assert!(matches!(res2, Err(ValidationStatus::Invalid(_))));
    }

    #[test]
    fn test_url_validation_rejection_unsupported_scheme() {
        let res_ftp = validate_url_target("ftp://ftp.example.com/file");
        assert!(matches!(res_ftp, Err(ValidationStatus::Invalid(_))));

        let res_file = validate_url_target("file:///C:/Windows/System32/calc.exe");
        assert!(matches!(res_file, Err(ValidationStatus::Invalid(_))));

        let res_js = validate_url_target("javascript:alert(1)");
        assert!(matches!(res_js, Err(ValidationStatus::Invalid(_))));
    }

    #[test]
    fn test_url_validation_rejection_prohibited_hostnames() {
        let res_localhost = validate_url_target("http://localhost/api");
        assert!(matches!(res_localhost, Err(ValidationStatus::ProhibitedDestination(_))));

        let res_sub_localhost = validate_url_target("https://app.localhost/");
        assert!(matches!(res_sub_localhost, Err(ValidationStatus::ProhibitedDestination(_))));

        let res_local = validate_url_target("https://myserver.local/");
        assert!(matches!(res_local, Err(ValidationStatus::ProhibitedDestination(_))));

        let res_internal = validate_url_target("https://intranet.internal/dashboard");
        assert!(matches!(res_internal, Err(ValidationStatus::ProhibitedDestination(_))));
    }

    #[test]
    fn test_url_validation_rejection_prohibited_ip_literals() {
        let res_loopback = validate_url_target("http://127.0.0.1:8080/test");
        assert!(matches!(res_loopback, Err(ValidationStatus::ProhibitedDestination(_))));

        let res_priv = validate_url_target("http://192.168.1.1/");
        assert!(matches!(res_priv, Err(ValidationStatus::ProhibitedDestination(_))));

        let res_meta = validate_url_target("http://169.254.169.254/latest/meta-data/");
        assert!(matches!(res_meta, Err(ValidationStatus::ProhibitedDestination(_))));
    }

    #[test]
    fn test_url_validation_valid_domain() {
        let res = validate_url_target("https://login.microsoftonline.com/path?query=val#hash");
        assert!(res.is_ok());
        let target = res.unwrap();
        assert_eq!(target.host, "login.microsoftonline.com");
        assert_eq!(target.canonical_domain.as_deref(), Some("microsoftonline.com"));
        assert_eq!(target.port, 443);
        assert_eq!(target.scheme, "https");
        assert!(!target.is_ip);
    }

    #[test]
    fn test_canonical_domain_extraction() {
        assert_eq!(extract_canonical_domain("example.com"), "example.com");
        assert_eq!(extract_canonical_domain("sub.example.com"), "example.com");
        assert_eq!(extract_canonical_domain("a.b.c.example.com"), "example.com");
        assert_eq!(extract_canonical_domain("sub.bank.co.uk"), "bank.co.uk");
        assert_eq!(extract_canonical_domain("gov.in"), "gov.in");
        assert_eq!(extract_canonical_domain("portal.gov.in"), "portal.gov.in");
    }

    #[test]
    fn test_deep_scan_prohibited_destination_execution() {
        tauri::async_runtime::block_on(async {
            let result = execute_deep_scan("http://127.0.0.1:8080/status".to_string()).await;
            assert!(matches!(result.validation, ValidationStatus::ProhibitedDestination(_)));
            assert_eq!(result.checks.whois.status, CheckStatus::Skipped);
            assert_eq!(result.checks.redirect.status, CheckStatus::Skipped);
        });
    }

    #[test]
    fn test_matches_cert_hostname_wildcard() {
        assert!(matches_cert_hostname("example.com", "example.com"));
        assert!(matches_cert_hostname("EXAMPLE.COM", "example.com"));
        assert!(matches_cert_hostname("*.example.com", "sub.example.com"));
        assert!(matches_cert_hostname("*.example.com", "api.example.com"));
        // RFC 6125: Wildcard does not match multi-level subdomains
        assert!(!matches_cert_hostname("*.example.com", "a.b.example.com"));
        // Does not match different domain
        assert!(!matches_cert_hostname("*.example.com", "other.com"));
    }

    #[test]
    fn test_tls_http_skipped() {
        let result = inspect_tls_certificate("example.com", 80, "http", false);
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(result.summary.contains("unencrypted HTTP"));
    }

    #[test]
    fn test_rdap_ip_skipped() {
        let client = reqwest::Client::new();
        tauri::async_runtime::block_on(async {
            let result = query_rdap(&client, None, true).await;
            assert_eq!(result.status, CheckStatus::Skipped);
            assert!(result.summary.contains("IP literal"));
        });
    }

    #[test]
    fn test_redirect_unsupported_scheme() {
        tauri::async_runtime::block_on(async {
            let result = trace_redirects("ftp://ftp.example.com/file").await;
            assert_eq!(result.status, CheckStatus::Suspicious);
            assert!(result.summary.contains("unsupported scheme"));
        });
    }

    #[test]
    fn test_redirect_prohibited_hop_blocked() {
        tauri::async_runtime::block_on(async {
            let result = trace_redirects("http://127.0.0.1:8080/").await;
            assert_eq!(result.status, CheckStatus::Suspicious);
            assert!(result.summary.contains("prohibited internal host") || result.summary.contains("SSRF blocked"));
        });
    }

    #[test]
    fn test_deep_scan_valid_destination_structure() {
        tauri::async_runtime::block_on(async {
            let result = execute_deep_scan("https://example.com/".to_string()).await;
            assert_eq!(result.validation, ValidationStatus::Valid);
            assert_eq!(result.host.as_deref(), Some("example.com"));
            assert_eq!(result.canonical_domain.as_deref(), Some("example.com"));
            assert_eq!(result.scheme.as_deref(), Some("https"));
            // All 5 checks must have valid independent statuses and source attribution
            assert!(result.checks.dns.source.is_some());
            assert!(result.checks.whois.source.is_some());
            assert!(result.checks.tls.source.is_some());
            assert!(result.checks.reputation.source.is_some());
            assert!(result.checks.redirect.source.is_some());
            // None of the checks should have panicking or invalid states
            assert!(matches!(result.checks.dns.status, CheckStatus::Verified | CheckStatus::Unavailable | CheckStatus::Suspicious));
        });
    }

    #[test]
    fn test_doh_nxdomain_detection() {
        let client = reqwest::Client::new();
        tauri::async_runtime::block_on(async {
            let result = query_doh_records(&client, "nonexistent-test-subdomain-12345-xyz.com").await;
            // NXDOMAIN must be flagged as Suspicious, or Unavailable if network offline
            assert!(matches!(result.status, CheckStatus::Suspicious | CheckStatus::Unavailable));
            if result.status == CheckStatus::Suspicious {
                assert!(result.summary.contains("NXDOMAIN") || result.summary.contains("does not exist"));
            }
        });
    }

    #[test]
    fn test_rdap_missing_domain_detection() {
        let client = reqwest::Client::new();
        tauri::async_runtime::block_on(async {
            let result = query_rdap(&client, Some("nonexistent-test-domain-987654321-abc.org"), false).await;
            // Missing domain in RDAP must be flagged as Suspicious, or Unavailable if bootstrap down
            assert!(matches!(result.status, CheckStatus::Suspicious | CheckStatus::Unavailable));
        });
    }

    #[test]
    fn test_urlhaus_clean_domain() {
        let client = reqwest::Client::new();
        tauri::async_runtime::block_on(async {
            let result = query_urlhaus_reputation(&client, "example.com").await;
            // example.com should be clean (Verified: no_results) or Unavailable if offline
            assert!(matches!(result.status, CheckStatus::Verified | CheckStatus::Unavailable));
        });
    }

    #[test]
    fn test_tls_certificate_live_inspection() {
        let result = inspect_tls_certificate("example.com", 443, "https", false);
        // On live internet, example.com TLS handshake succeeds with valid cert
        // or Unavailable if network is isolated
        assert!(matches!(result.status, CheckStatus::Verified | CheckStatus::Unavailable));
        if result.status == CheckStatus::Verified {
            assert!(result.summary.contains("Valid TLS certificate"));
            assert!(result.details.is_some());
        }
    }

    #[test]
    fn test_prohibited_ipv6_6to4_mapped() {
        // 2002:7f00:0001:: encapsulates 127.0.0.1 (Loopback)
        let ip_loopback: Ipv6Addr = "2002:7f00:0001::".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_loopback).is_err());

        // 2002:0a00:0001:: encapsulates 10.0.0.1 (RFC 1918 Private)
        let ip_priv: Ipv6Addr = "2002:0a00:0001::".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_priv).is_err());

        // 2002:a9fe:a9fe:: encapsulates 169.254.169.254 (Cloud metadata)
        let ip_meta: Ipv6Addr = "2002:a9fe:a9fe::".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_meta).is_err());
    }

    #[test]
    fn test_prohibited_ipv6_nat64_mapped() {
        // 64:ff9b::7f00:1 encapsulates 127.0.0.1 (Loopback)
        let ip_loopback: Ipv6Addr = "64:ff9b::7f00:1".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_loopback).is_err());

        // 64:ff9b::a9fe:a9fe encapsulates 169.254.169.254 (Cloud metadata)
        let ip_meta: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_meta).is_err());
    }

    #[test]
    fn test_prohibited_ipv6_site_local_and_discard() {
        // fec0::1 — Deprecated site-local unicast
        let ip_site: Ipv6Addr = "fec0::1".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_site).is_err());

        // 100::1 — RFC 6666 Discard prefix
        let ip_discard: Ipv6Addr = "100::1".parse().unwrap();
        assert!(is_prohibited_ipv6(&ip_discard).is_err());
    }

    #[test]
    fn test_redirect_bracket_host_cleansing() {
        tauri::async_runtime::block_on(async {
            // [::1] should be rejected by SSRF guard, not crash or panic on socket resolution
            let result = trace_redirects("http://[::1]:8080/").await;
            assert_eq!(result.status, CheckStatus::Suspicious);
        });
    }

    #[test]
    fn test_overall_deadline_timeout_structure() {
        let deadline_checks = DeepScanChecks {
            whois: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "RDAP"),
            dns: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "DNS-over-HTTPS"),
            tls: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Direct In-Band TLS Handshake"),
            reputation: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Abuse.ch URLhaus"),
            redirect: CheckResult::unavailable("Overall Deep Scan deadline (8s) exceeded", "Out-of-Band Hop Tracer"),
        };

        assert_eq!(deadline_checks.whois.status, CheckStatus::Unavailable);
        assert_eq!(deadline_checks.dns.status, CheckStatus::Unavailable);
        assert_eq!(deadline_checks.tls.status, CheckStatus::Unavailable);
        assert_eq!(deadline_checks.reputation.status, CheckStatus::Unavailable);
        assert_eq!(deadline_checks.redirect.status, CheckStatus::Unavailable);
    }

    #[test]
    fn test_overall_assessment_suspicious_verdict() {
        let checks = DeepScanChecks {
            whois: CheckResult::verified("Registered domain", "RDAP", None),
            dns: CheckResult::suspicious("Prohibited private IP returned in DNS", "DNS-over-HTTPS", None),
            tls: CheckResult::verified("Valid TLS certificate", "TLS", None),
            reputation: CheckResult::verified("No threat listings", "URLhaus", None),
            redirect: CheckResult::verified("No redirects", "Hop Tracer", None),
        };

        let assessment = evaluate_overall_assessment(&ValidationStatus::Valid, &checks);
        assert_eq!(assessment.verdict, AssessmentVerdict::SuspiciousFindings);
        assert_eq!(assessment.suspicious_count, 1);
        assert!(assessment.title.contains("Suspicious findings"));
        assert!(!assessment.key_findings.is_empty());
    }

    #[test]
    fn test_overall_assessment_no_known_threats() {
        let checks = DeepScanChecks {
            whois: CheckResult::verified("Registered domain", "RDAP", None),
            dns: CheckResult::verified("Resolved 2 public IPs", "DNS-over-HTTPS", None),
            tls: CheckResult::verified("Valid TLS certificate", "TLS", None),
            reputation: CheckResult::verified("No threat listings", "URLhaus", None),
            redirect: CheckResult::verified("No redirects", "Hop Tracer", None),
        };

        let assessment = evaluate_overall_assessment(&ValidationStatus::Valid, &checks);
        assert_eq!(assessment.verdict, AssessmentVerdict::NoKnownThreats);
        assert_eq!(assessment.suspicious_count, 0);
        assert_eq!(assessment.verified_count, 5);
        assert!(assessment.title.contains("No known threats detected"));
    }

    #[test]
    fn test_overall_assessment_inconclusive_dns_unavailable() {
        let checks = DeepScanChecks {
            whois: CheckResult::verified("Registered domain", "RDAP", None),
            dns: CheckResult::unavailable("DoH resolver timed out", "DNS-over-HTTPS"),
            tls: CheckResult::verified("Valid TLS certificate", "TLS", None),
            reputation: CheckResult::verified("No threat listings", "URLhaus", None),
            redirect: CheckResult::verified("No redirects", "Hop Tracer", None),
        };

        let assessment = evaluate_overall_assessment(&ValidationStatus::Valid, &checks);
        assert_eq!(assessment.verdict, AssessmentVerdict::Inconclusive);
        assert!(assessment.title.contains("Inconclusive"));
    }

    #[test]
    fn test_overall_assessment_inconclusive_all_unavailable() {
        let checks = DeepScanChecks {
            whois: CheckResult::unavailable("RDAP unreachable", "RDAP"),
            dns: CheckResult::unavailable("DoH unreachable", "DNS-over-HTTPS"),
            tls: CheckResult::unavailable("TLS timed out", "TLS"),
            reputation: CheckResult::unavailable("URLhaus unreachable", "URLhaus"),
            redirect: CheckResult::unavailable("Tracer timed out", "Hop Tracer"),
        };

        let assessment = evaluate_overall_assessment(&ValidationStatus::Valid, &checks);
        assert_eq!(assessment.verdict, AssessmentVerdict::Inconclusive);
        assert_eq!(assessment.unavailable_count, 5);
        assert!(assessment.title.contains("Inconclusive"));
    }

    #[test]
    fn test_overall_assessment_prohibited_destination() {
        let checks = DeepScanChecks {
            whois: CheckResult::skipped("Skipped", None),
            dns: CheckResult::skipped("Skipped", None),
            tls: CheckResult::skipped("Skipped", None),
            reputation: CheckResult::skipped("Skipped", None),
            redirect: CheckResult::skipped("Skipped", None),
        };

        let assessment = evaluate_overall_assessment(
            &ValidationStatus::ProhibitedDestination("127.0.0.1/8 (Loopback address)".into()),
            &checks,
        );
        assert_eq!(assessment.verdict, AssessmentVerdict::SuspiciousFindings);
        assert!(assessment.title.contains("Suspicious findings"));
        assert!(assessment.description.contains("prohibited"));
    }
}
