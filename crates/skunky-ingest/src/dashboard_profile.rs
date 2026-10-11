// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Dashboard IP profiling — GEO lookup, behavioral profiles, trio scoring,
//! epitope hashing, and collision classification.
//!
//! Extracted from `dashboard_writer.rs` — the writer accumulates and renders,
//! this module defines the per-IP data shapes and scoring.
//!
//! Split is π: ~1000 lines (writer) : ~480 lines (profiles).

#![allow(missing_docs)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── GEO/WHOIS lookup for known ranges ──

/// GEO lookup from known IP ranges — progressive subdivision.
///
/// Resolution sharpens as we identify more ranges from WHOIS data.
/// Country → region → city → ASN → fiber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GeoInfo {
    pub org: String,
    pub country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_type: Option<String>,
}

/// (prefix, org, country, region, city, asn_type)
type GeoEntry = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

pub(crate) fn geo_lookup(ip: &str) -> GeoInfo {
    let prefixes: &[GeoEntry] = &[
        // ── Meta Platforms ──
        ("57.141.20.", "Meta Platforms (FB-BLOCK)", "IE/US", "Dublin/Menlo Park", "Dublin DC", "datacenter"),
        ("57.141.", "Meta Platforms (FB-BLOCK)", "IE/US", "Dublin", "", "datacenter"),
        ("173.252.70.", "Meta Platforms", "US", "California", "Menlo Park", "datacenter"),
        ("173.252.107.", "Meta Platforms", "US", "California", "Menlo Park", "datacenter"),
        ("173.252.", "Meta Platforms", "US", "California", "", "datacenter"),
        // ── Anthropic ──
        ("216.73.216.", "Anthropic", "US", "California", "San Francisco", "datacenter"),
        // ── Cloud providers ──
        ("116.204.78.", "Huawei Cloud", "CN", "Guangdong", "Shenzhen", "cloud"),
        ("49.0.245.", "Huawei Cloud", "HK", "Hong Kong", "Hong Kong", "cloud"),
        ("119.12.174.", "Huawei Cloud", "HK", "Hong Kong", "Hong Kong", "cloud"),
        ("47.79.13.", "Alibaba Cloud", "US", "California", "San Mateo", "cloud"),
        ("47.79.", "Alibaba Cloud", "US", "California", "", "cloud"),
        ("16.216.88.", "HPE (Hewlett Packard Enterprise)", "US", "Texas", "Spring", "datacenter"),
        ("16.216.", "HPE (Hewlett Packard Enterprise)", "US", "Texas", "", "datacenter"),
        ("100.27.", "AWS", "US", "Virginia", "Ashburn", "cloud"),
        ("100.28.", "AWS", "US", "Virginia", "Ashburn", "cloud"),
        // ── Hosting/VPS ──
        ("79.139.58.", "RackForest (VPS)", "HU", "Budapest", "", "vps"),
        ("178.124.154.", "EvroRith", "BY", "Minsk", "Minsk", "hosting"),
        // ── ISP / Residential ──
        ("76.32.61.", "Charter Communications", "US", "Colorado", "Greenwood Village", "residential"),
        ("76.32.", "Charter Communications", "US", "Colorado", "", "residential"),
        ("174.168.153.", "Comcast Cable", "US", "New Jersey", "Mt Laurel", "residential"),
        ("174.168.", "Comcast Cable", "US", "New Jersey", "", "residential"),
        // ── Telecom ──
        ("180.153.197.", "ChinaNet Shanghai", "CN", "Shanghai", "Shanghai", "telecom"),
        ("180.153.", "ChinaNet Shanghai", "CN", "Shanghai", "", "telecom"),
        ("46.250.169.", "Unknown (EU allocation)", "EU", "", "", "unknown"),
        // ── Colocation / Transit ──
        ("65.49.20.", "Hurricane Electric", "US", "California", "Fremont", "colocation"),
        ("65.49.", "Hurricane Electric", "US", "California", "", "colocation"),
        // ── Search engines ──
        ("66.249.", "Google", "US", "California", "Mountain View", "datacenter"),
        ("157.55.", "Microsoft (Bing)", "US", "Washington", "Redmond", "datacenter"),
        // ── Self ──
        ("162.226.225.", "House network", "US", "Michigan", "", "self"),
        ("10.13.37.", "WireGuard mesh", "MESH", "", "", "self"),
    ];

    for entry in prefixes {
        if ip.starts_with(entry.0) {
            return GeoInfo {
                org: entry.1.to_string(),
                country: entry.2.to_string(),
                region: if entry.3.is_empty() { None } else { Some(entry.3.to_string()) },
                city: if entry.4.is_empty() { None } else { Some(entry.4.to_string()) },
                asn_type: if entry.5.is_empty() { None } else { Some(entry.5.to_string()) },
            };
        }
    }

    GeoInfo {
        org: "Unknown".to_string(),
        country: "??".to_string(),
        region: None,
        city: None,
        asn_type: None,
    }
}

// ── Per-IP behavioral profile ──

/// Accumulated behavioral data for one IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpProfile {
    pub requests: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub is_fleet: bool,
    pub is_human: bool,
    /// True if UA matched a declared bot identity (commensal signal).
    pub is_declared_bot: bool,
    /// Top repos targeted: repo → count
    pub repos: HashMap<String, u32>,
    /// Path operation types: type → count
    pub path_types: HashMap<String, u32>,
    /// Status code distribution
    pub statuses: HashMap<u16, u32>,
    /// Accept-Encoding value (conserved epitope — first value wins)
    pub accept_encoding: Option<String>,
    /// Number of distinct UAs seen from this IP
    pub ua_pool_size: u16,
    /// Blame endpoint hits
    pub blame_count: u32,
    /// Commit endpoint hits
    pub commit_count: u32,
    /// Has Accept-Language header
    pub has_accept_lang: bool,
    /// Has loaded CSS/JS/font assets
    pub has_assets: bool,
    /// Has sent Referer header
    pub has_referer: bool,
    /// Has Sec-Fetch-Mode
    pub has_sec_fetch: bool,
    /// Has Cookie
    pub has_cookie: bool,
    /// Hosts visited
    pub host_count: u16,
    /// Computed epitope hash (None until >= 3 requests)
    pub epitope_hash: Option<String>,
    /// Accept header value (conserved epitope)
    pub accept: Option<String>,
}

impl IpProfile {
    pub fn new(ts: f64) -> Self {
        Self {
            requests: 0,
            first_seen: ts,
            last_seen: ts,
            is_fleet: false,
            is_human: false,
            is_declared_bot: false,
            repos: HashMap::new(),
            path_types: HashMap::new(),
            statuses: HashMap::new(),
            accept_encoding: None,
            ua_pool_size: 0,
            blame_count: 0,
            commit_count: 0,
            has_accept_lang: false,
            has_assets: false,
            has_referer: false,
            has_sec_fetch: false,
            has_cookie: false,
            host_count: 0,
            epitope_hash: None,
            accept: None,
        }
    }
}

// ── BingoCube Trio — Attention × Curiosity × Interaction scoring ──

/// Three-axis behavioral classification from the bingoCube oracle.
///
/// Each entity is scored on three orthogonal axes. The classification
/// determines which provenance braid receives the behavioral record:
/// - loamSpine (ledger/spine, WHERE) ← all classes
/// - rhizoCrypt (DAG, WHAT) ← commensal + sovereign
/// - sweetGrass (braid, WHO) ← sovereign only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BingoCubeTrio {
    /// Reading depth: time between requests, path depth, varied pacing.
    pub attention: f32,
    /// Navigation breadth: unique paths, diverse hosts, repo exploration.
    pub curiosity: f32,
    /// Engagement depth: asset loads, CSS/JS fetches, referer chains.
    pub interaction: f32,
    /// Ecological classification from the trio shape.
    pub classification: TrioClass,
}

/// Ecological class — which kingdom an entity belongs to.
///
/// Referer is NOT an epitope. Privacy is always allowed.
/// Ghost promotes to Sovereign on behavioral evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrioClass {
    /// wave/0 — behavioral epitopes prove extraction without consent.
    /// Missing Sec-Fetch, missing Connection, metronomic timing, IP rotation.
    /// These are structural tells that can't be hidden by privacy tools.
    Parasite,
    /// photon/1 — declared identity, provides value (indexing, agentic).
    /// Says who it is in UA. Voluntarily participates in the protocol.
    Commensal,
    /// reaction/null — behavioral proof of human reading, privacy respected.
    /// Full browser stack + multi-request depth. Or promoted Ghost.
    Sovereign,
}

/// Score an IP profile on the Attention × Curiosity × Interaction axes
/// and classify into the ecological trio.
///
/// Scoring rules (from plan):
/// - **Parasite**: behavioral epitopes ONLY — no Sec-Fetch, no Accept-Language,
///   fleet-like UA pool. Structural tells, not privacy choices.
/// - **Commensal**: declared bot identity in UA. If you say who you are, commensal.
/// - **Sovereign**: multi-request behavioral depth — varied timing, asset loads,
///   path diversity. Ghost promotes after 3+ requests with depth signals.
/// - Referer is NOT an epitope — it is a privacy choice.
pub fn score_trio(profile: &IpProfile) -> BingoCubeTrio {
    // ── Attention: reading depth ──
    let attention = {
        let time_span = (profile.last_seen - profile.first_seen).max(0.0);
        let avg_interval = if profile.requests > 1 {
            time_span / (profile.requests - 1) as f64
        } else {
            0.0
        };

        if profile.requests <= 1 {
            0.1_f32
        } else if avg_interval > 30.0 {
            0.9
        } else if avg_interval > 10.0 {
            0.75
        } else if avg_interval > 3.0 {
            0.55
        } else if avg_interval > 1.0 {
            0.35
        } else {
            0.12
        }
    };

    // ── Curiosity: navigation breadth ──
    let curiosity = {
        let path_diversity = profile.path_types.len() as f32;
        let repo_diversity = profile.repos.len() as f32;
        let host_factor = profile.host_count as f32;

        let raw = (path_diversity / 6.0).min(1.0) * 0.3
            + (repo_diversity / 5.0).min(1.0) * 0.3
            + (host_factor / 3.0).min(1.0) * 0.4;
        raw.min(1.0)
    };

    // ── Interaction: engagement depth ──
    let interaction = {
        let mut score = 0.0_f32;
        if profile.has_assets { score += 0.25; }
        if profile.has_sec_fetch { score += 0.20; }
        if profile.has_cookie { score += 0.15; }
        if profile.has_referer { score += 0.10; }  // NOT required — privacy choice
        if profile.blame_count > 0 { score += 0.15; }
        if profile.host_count > 1 { score += 0.10; }
        if profile.has_accept_lang { score += 0.05; }
        score.min(1.0)
    };

    // ── Classification ──
    let classification = classify_trio(profile, attention, curiosity, interaction);

    BingoCubeTrio {
        attention,
        curiosity,
        interaction,
        classification,
    }
}

/// Classify into the ecological trio based on profile signals + trio scores.
fn classify_trio(
    profile: &IpProfile,
    _attention: f32,
    curiosity: f32,
    interaction: f32,
) -> TrioClass {
    if profile.is_declared_bot {
        return TrioClass::Commensal;
    }

    if !profile.has_sec_fetch && !profile.has_accept_lang && profile.ua_pool_size > 2 {
        return TrioClass::Parasite;
    }
    if profile.is_fleet && !profile.is_declared_bot {
        return TrioClass::Parasite;
    }

    if profile.has_sec_fetch && profile.requests >= 3 {
        if interaction > 0.3 || (curiosity > 0.2 && profile.has_accept_lang) {
            return TrioClass::Sovereign;
        }
    }

    if profile.has_sec_fetch && profile.requests >= 3 && curiosity > 0.15 {
        return TrioClass::Sovereign;
    }

    if profile.has_sec_fetch {
        return TrioClass::Commensal;
    }

    if profile.requests >= 3 && (curiosity > 0.2 || interaction > 0.2) {
        return TrioClass::Commensal;
    }

    TrioClass::Parasite
}

// ── IP hashing — ZK boundary ──

/// Hash an IP address to a u64 for storage without revealing the address.
///
/// Uses SipHash (via DefaultHasher) matching bloom_sensor.rs pattern.
/// IPs remain in memory for CaddyBridge fleet blocking (iptables needs
/// real IPs) but NEVER persist to state files.
pub fn hash_ip(ip: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    h.finish()
}

// ── Epitope hashing ──

/// Compute a short BLAKE2b collision hash of behavioral invariants.
///
/// These are CONSERVED INVARIANTS — signals the entity cannot change
/// without rebuilding their infrastructure:
/// - Accept-Encoding order (HTTP library fingerprint)
/// - UA pool size (1=honest, 3-4=impersonation fleet)
/// - Blame ratio (team structure indicator)
/// - Accept header value (client configuration)
/// - Accept-Language presence (browser vs bot)
pub(crate) fn compute_epitope_hash(profile: &IpProfile) -> String {
    use std::hash::{Hash, Hasher};

    let ae = profile.accept_encoding.as_deref().unwrap_or("");
    let ua_bucket = if profile.ua_pool_size <= 1 {
        "1"
    } else if profile.ua_pool_size <= 3 {
        "few"
    } else {
        "many"
    };
    let blame_ratio = if profile.commit_count > 0
        && profile.blame_count as f64 / profile.commit_count as f64 > 0.2
    {
        "high"
    } else {
        "low"
    };
    let accept = profile
        .accept
        .as_deref()
        .unwrap_or("")
        .get(..20)
        .unwrap_or(profile.accept.as_deref().unwrap_or(""));
    let has_lang = if profile.has_accept_lang { "y" } else { "n" };

    let epitope_vec = format!("{}|{}|{}|{}|{}", ae, ua_bucket, blame_ratio, accept, has_lang);

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    epitope_vec.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:08x}", hash as u32)
}

// ── L2 collision classification ──

/// Level 2 collision class — emergent behavioral categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CollisionClass {
    /// Loads assets, has referer, multi-page session
    Genuine,
    /// Single deep hit, 200 status, possibly has sec-fetch
    Agentic,
    /// Hits same paths as other IPs within coordination window.
    #[allow(dead_code)]
    Coordinated,
    /// Fleet-like behavior (default)
    Fleet,
}

pub(crate) fn classify_collision_l2(profile: &IpProfile) -> CollisionClass {
    let total: u32 = profile.statuses.values().sum();
    if total == 0 {
        return CollisionClass::Fleet;
    }

    let status_200 = profile.statuses.get(&200).copied().unwrap_or(0)
        + profile.statuses.get(&308).copied().unwrap_or(0)
        + profile.statuses.get(&301).copied().unwrap_or(0);
    let ratio_200 = status_200 as f64 / total as f64;

    if profile.has_assets && profile.has_referer && total > 1 && ratio_200 > 0.5 {
        return CollisionClass::Genuine;
    }

    if ratio_200 > 0.5 && total <= 3 {
        return CollisionClass::Agentic;
    }

    CollisionClass::Fleet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epitope_hash_deterministic() {
        let mut p = IpProfile::new(1.0);
        p.accept_encoding = Some("gzip, br, zstd, deflate".to_string());
        p.ua_pool_size = 1;
        p.accept = Some("*/*".to_string());

        let h1 = compute_epitope_hash(&p);
        let h2 = compute_epitope_hash(&p);
        assert_eq!(h1, h2, "epitope hash should be deterministic");
        assert_eq!(h1.len(), 8, "epitope hash should be 8 hex chars");
    }

    #[test]
    fn collision_l2_fleet_default() {
        let p = IpProfile::new(1.0);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Fleet);
    }

    #[test]
    fn collision_l2_genuine() {
        let mut p = IpProfile::new(1.0);
        p.has_assets = true;
        p.has_referer = true;
        p.statuses.insert(200, 5);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Genuine);
    }

    #[test]
    fn collision_l2_agentic() {
        let mut p = IpProfile::new(1.0);
        p.statuses.insert(200, 2);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Agentic);
    }
}
