// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Entity profile types and topology output structures.
//!
//! Extracted from entity_classifier.rs for modularity. Contains the
//! accumulated behavioral profile, epitope scoring, and comparative
//! fingerprint table.

#![allow(missing_docs)]

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::entity_classifier::{EntityId, PathOp};

/// Accumulated behavioral profile for one entity.
#[derive(Debug, Serialize)]
pub struct EntityProfile {
    pub entity: EntityId,
    pub label: String,
    pub is_fleet: bool,
    pub is_honest: bool,
    pub total_requests: u64,
    pub unique_ips: usize,
    pub unique_subnets: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_hours: f64,
    pub avg_rps: f64,

    /// Header fingerprint.
    pub header_fingerprint: HeaderFingerprint,

    /// Chrome version distribution.
    pub chrome_versions: BTreeMap<u16, u64>,
    pub chrome_lag: u16,

    /// UA impersonation pool.
    pub ua_os_distribution: BTreeMap<String, u64>,
    pub ua_pool_size: usize,

    /// IP rotation pattern.
    pub ip_rotation: IpRotation,

    /// Path operation breakdown.
    pub path_ops: BTreeMap<String, u64>,
    pub blame_pct: f64,

    /// Repository targeting.
    pub top_repos: Vec<(String, u64)>,
    pub targets_real_only: bool,
    pub targets_scatter_only: bool,

    /// Timing signature.
    pub timing: TimingProfile,

    /// Sub-systems detected within this entity.
    pub sub_systems: Vec<SubSystem>,

    /// Wave 166f: Conserved epitope scores — signals fleet can't cheaply evade.
    pub epitopes: EpitopeScores,
    /// Composite fleet confidence (% of epitopes triggered), reflected by vitality.
    pub fleet_confidence: f64,
    /// Mean vitality across evaluated epitopes.  High = near the mobility edge = uncertain = alive.
    pub vitality: f64,

    /// Wave 171: Negentropy — defensive information provided TO the organism.
    ///
    /// Vuln scanners, path probers, and traversal attempts generate information
    /// about the attack surface.  Every `.env` probe they run is a diagnostic
    /// the organism didn't have to pay for.  They are free pen testers.
    ///
    /// `negentropy` measures how much defensive information this entity provides:
    /// unique vulnerability paths probed × probe diversity.  Higher = more useful.
    /// Entities with high negentropy defend others by mapping the attack surface.
    pub negentropy: f64,
    /// The unique vulnerability paths this entity has probed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vuln_probes: Vec<String>,

    /// Wave 171: Per-surface request counts — which surfaces this entity visits.
    /// Keyed by hostname (e.g. "git.primals.eco", "detroit.primals.eco").
    pub hosts: BTreeMap<String, u64>,
}

/// Seven conserved epitopes from antigenic drift analysis (Wave 166f+167).
///
/// Each epitope costs the fleet more to evade than the last.
/// The terminal epitope (reading pauses) would reduce throughput to
/// human levels, collapsing the economics of scraping a $6 VPS.
#[derive(Debug, Serialize)]
pub struct EpitopeScores {
    /// Same Sec-Fetch triplet on >95% of requests (real browsers vary by type).
    pub sec_fetch_monotone: Option<EpitopeResult>,
    /// <10% of intervals >8s (can't add pauses without killing throughput).
    pub reading_deficit: Option<EpitopeResult>,
    /// Too few UAs for visit count (adding diversity requires tracking Chrome releases).
    pub ua_pool_poverty: Option<EpitopeResult>,
    /// No cookies across multi-page visits (stateful sessions kill parallelism).
    pub session_absent: Option<EpitopeResult>,
    /// No external referers (can't fake Google arrival).
    pub referer_self_loop: Option<EpitopeResult>,
    /// >50% of intervals <3s (reducing bursts conflicts with extraction economics).
    pub burst_ratio: Option<EpitopeResult>,
    /// Wave 167: >95% of Sec-Fetch-bearing requests have no referer.
    /// Residential proxy exits are programmatic → no referer chain.
    /// Faking referrer chains creates detectable patterns (self-loops, impossible
    /// navigation sequences). Absence is the conserved epitope.
    pub referer_absence: Option<EpitopeResult>,
}

/// Result for a single epitope check.
///
/// The `vitality` field is the reflected score — the mirror of the epitope
/// at the threshold boundary.  Entities far from the threshold in either
/// direction have vitality ≈ 0 (certain machine or certain human).
/// Entities *at* the threshold have maximum vitality — the uncertainty
/// itself is the sign of life.
///
/// Mathematically: `vitality = 1.0 - |score - threshold| / threshold`
/// clamped to \[0, 1\].  This is the Anderson delocalization signal:
/// at the mobility edge the localization length diverges.
#[derive(Debug, Serialize)]
pub struct EpitopeResult {
    pub score: f64,
    pub triggered: bool,
    /// Reflected life-signal: peaks at the threshold boundary.
    /// Uncertainty is a sign of life.
    pub vitality: f64,
    pub description: String,
}

// ── Epitope sort order (Paper 48 — information-content ordering) ──

/// The six conserved epitopes ordered by information content (compression power),
/// NOT by detection priority. This is the canonical sort key for the epitope
/// sort compression (Paper 48).
///
/// Ordering rationale — each epitope's mutual information with fleet identity:
///
/// 1. `burst_ratio`       — timing regularity is the strongest fleet signal (CV < 0.15
///                          is definitive). Cannot be cheaply evaded without throttling.
/// 2. `reading_deficit`   — absence of reading pauses (>8s gaps) cleanly separates
///                          machines from humans. Adding pauses kills throughput.
/// 3. `ua_pool_poverty`   — small UA pool ÷ visit count reveals coordinated fleet.
///                          Growing the pool requires tracking Chrome releases.
/// 4. `sec_fetch_monotone` — identical Sec-Fetch triplets across 95%+ of requests
///                          proves non-browser automation. Can be faked but creates
///                          new detectable patterns.
/// 5. `session_absent`    — no cookies/session across multi-page visits. Stateful
///                          sessions kill parallelism, but absence is not unique to
///                          fleets (privacy-conscious humans also block cookies).
/// 6. `referer_self_loop` — no external referrers. Weakest signal because privacy
///                          tools strip referrers (and we protect that choice).
pub const EPITOPE_SORT_ORDER: [&str; 6] = [
    "burst_ratio",
    "reading_deficit",
    "ua_pool_poverty",
    "sec_fetch_monotone",
    "session_absent",
    "referer_self_loop",
];

impl EpitopeScores {
    /// Returns a 6-byte sort key ordered by information content (Paper 48).
    ///
    /// Each byte encodes: 0x00 = not evaluated, 0x01 = evaluated but not triggered,
    /// 0x02 = triggered. The key sorts entities by their strongest-first epitope
    /// signature, maximizing compression of the fleet search space.
    ///
    /// The ordering is `burst_ratio > reading_deficit > ua_pool_poverty >
    /// sec_fetch_monotone > session_absent > referer_self_loop`.
    pub fn epitope_sort_key(&self) -> [u8; 6] {
        let fields: [&Option<EpitopeResult>; 6] = [
            &self.burst_ratio,
            &self.reading_deficit,
            &self.ua_pool_poverty,
            &self.sec_fetch_monotone,
            &self.session_absent,
            &self.referer_self_loop,
        ];
        let mut key = [0u8; 6];
        for (i, field) in fields.iter().enumerate() {
            key[i] = match field {
                None => 0x00,
                Some(r) if r.triggered => 0x02,
                Some(_) => 0x01,
            };
        }
        key
    }

    /// Returns the information-content compression score.
    ///
    /// Each triggered epitope contributes its rank weight (strongest = 6,
    /// weakest = 1). The score ranges from 0 (no epitopes triggered, no
    /// compression) to 21 (all 6 triggered, maximum compression).
    ///
    /// The score represents how many bits of fleet-vs-human uncertainty
    /// have been eliminated by the epitope sort.
    pub fn compression_score(&self) -> u32 {
        let fields: [&Option<EpitopeResult>; 6] = [
            &self.burst_ratio,
            &self.reading_deficit,
            &self.ua_pool_poverty,
            &self.sec_fetch_monotone,
            &self.session_absent,
            &self.referer_self_loop,
        ];
        let weights: [u32; 6] = [6, 5, 4, 3, 2, 1];
        fields.iter().zip(weights.iter())
            .filter_map(|(f, w)| {
                f.as_ref().filter(|r| r.triggered).map(|_| *w)
            })
            .sum()
    }
}

/// Header presence/absence fingerprint.
#[derive(Debug, Serialize)]
pub struct HeaderFingerprint {
    pub sec_fetch_pct: f64,
    pub sec_ch_ua_pct: f64,
    pub connection_pct: f64,
    pub accept_encoding_values: Vec<String>,
    pub accept_language_values: Vec<String>,
    pub accept_values: Vec<String>,
}

/// IP rotation pattern.
#[derive(Debug, Serialize)]
pub struct IpRotation {
    pub strategy: String,
    pub single_request_ips_pct: f64,
    pub max_per_ip: u64,
    pub median_per_ip: f64,
    pub all_generalists: bool,
}

/// Timing profile.
#[derive(Debug, Serialize)]
pub struct TimingProfile {
    pub mean_interval_ms: f64,
    pub median_interval_ms: f64,
    pub cv: f64,
    pub classification: String,
    pub burst_count: u64,
    pub pause_count: u64,
}

/// A detected sub-system within an entity.
#[derive(Debug, Serialize)]
pub struct SubSystem {
    pub name: String,
    pub description: String,
    pub evidence: Vec<String>,
}

// ── Known real repos (for scatter vs real classification) ──

/// Returns true if the repo name belongs to a real ecoPrimals repository.
fn is_real_repo(name: &str) -> bool {
    let known_orgs = ["ecoPrimals/", "syntheticChemistry/", "sporeGarden/"];
    known_orgs.iter().any(|org| name.starts_with(org))
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct EntityAccum {
    /// IP hashes (SipHash of raw IP). Raw IPs never stored — ZK boundary.
    pub(crate) ip_hashes: HashSet<u64>,
    pub(crate) subnets: HashSet<String>,
    pub(crate) uas: HashSet<String>,
    pub(crate) timestamps: Vec<f64>,
    pub(crate) chrome_versions: HashMap<u16, u64>,
    pub(crate) ua_os: HashMap<String, u64>,
    pub(crate) path_ops: HashMap<PathOp, u64>,
    pub(crate) repos: HashMap<String, u64>,
    pub(crate) accept_enc: HashSet<String>,
    pub(crate) accept_lang: HashSet<String>,
    pub(crate) accept: HashSet<String>,
    pub(crate) sec_fetch_present: u64,
    pub(crate) sec_fetch_absent: u64,
    pub(crate) sec_ch_ua_present: u64,
    pub(crate) sec_ch_ua_absent: u64,
    pub(crate) conn_present: u64,
    pub(crate) conn_absent: u64,
    pub(crate) total: u64,
    pub(crate) first_ts: f64,
    pub(crate) last_ts: f64,
    // Per-IP repo tracking (for specialist vs generalist detection) — keyed by ip hash
    pub(crate) ip_repos: HashMap<u64, HashMap<String, u64>>,
    // Wave 166f epitope tracking
    pub(crate) sec_fetch_triplets: HashMap<String, u64>,
    pub(crate) cookie_present: u64,
    pub(crate) cookie_absent: u64,
    pub(crate) referer_external: u64,
    pub(crate) referer_absent: u64,
    /// Wave 171: Per-surface request counts (keyed by host, e.g. "git.primals.eco").
    pub(crate) hosts: HashMap<String, u64>,
}

impl EntityAccum {
    /// Duration of the visit in minutes.
    ///
    /// Returns 0.0 if timestamps are invalid (first >= last).
    pub(crate) fn duration_min(&self) -> f64 {
        if self.last_ts > self.first_ts {
            (self.last_ts - self.first_ts) / 60.0
        } else {
            0.0
        }
    }

    /// Detect the visitor's platform from the most common UA OS entry.
    pub(crate) fn platform(&self) -> &'static str {
        if let Some((os, _)) = self.ua_os.iter().max_by_key(|(_, c)| *c) {
            if os.contains("Windows") || os.contains("Win") { return "Win"; }
            if os.contains("Macintosh") || os.contains("Mac") { return "Mac"; }
            if os.contains("iPhone") { return "iPhone"; }
            if os.contains("Android") { return "Android"; }
            if os.contains("Linux") { return "Linux"; }
        }
        "?"
    }

    /// Number of hits to the HUD polling surface.
    pub(crate) fn hud_polls(&self) -> u64 {
        self.hosts.get("hud.primals.eco")
            .or_else(|| self.hosts.get("signal.primals.eco"))
            .copied()
            .unwrap_or(0)
    }

    /// Surface keys with `.primals.eco` suffix stripped.
    pub(crate) fn surface_keys(&self) -> Vec<&str> {
        self.hosts.keys()
            .map(|h| crate::surface_registry::strip_host(h.as_str()))
            .collect()
    }

    pub(crate) fn new() -> Self {
        Self {
            ip_hashes: HashSet::new(),
            subnets: HashSet::new(),
            uas: HashSet::new(),
            timestamps: Vec::new(),
            chrome_versions: HashMap::new(),
            ua_os: HashMap::new(),
            path_ops: HashMap::new(),
            repos: HashMap::new(),
            accept_enc: HashSet::new(),
            accept_lang: HashSet::new(),
            accept: HashSet::new(),
            sec_fetch_present: 0,
            sec_fetch_absent: 0,
            sec_ch_ua_present: 0,
            sec_ch_ua_absent: 0,
            conn_present: 0,
            conn_absent: 0,
            total: 0,
            first_ts: f64::INFINITY,
            last_ts: 0.0,
            ip_repos: HashMap::new(),
            sec_fetch_triplets: HashMap::new(),
            cookie_present: 0,
            cookie_absent: 0,
            referer_external: 0,
            referer_absent: 0,
            hosts: HashMap::new(),
        }
    }
}

/// Chrome stable version. Updated when Chrome releases.
const CHROME_CURRENT_STABLE: u16 = 155;

pub(crate) fn build_profile(entity_id: EntityId, accum: EntityAccum) -> EntityProfile {
    let duration_secs = if accum.last_ts > accum.first_ts {
        accum.last_ts - accum.first_ts
    } else {
        0.0
    };
    let duration_hours = duration_secs / 3600.0;
    let avg_rps = if duration_secs > 0.0 {
        accum.total as f64 / duration_secs
    } else {
        0.0
    };

    // Chrome version lag
    let top_chrome: u16 = accum.chrome_versions.iter()
        .max_by_key(|(_, c)| *c)
        .map(|(v, _)| *v)
        .unwrap_or(0);
    let chrome_lag = if top_chrome > 0 {
        CHROME_CURRENT_STABLE.saturating_sub(top_chrome)
    } else {
        0
    };

    // Timing
    let mut ts_sorted: Vec<f64> = accum.timestamps;
    ts_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let intervals: Vec<f64> = ts_sorted.windows(2)
        .map(|w| w[1] - w[0])
        .filter(|&i| i > 0.001 && i < 60.0)
        .collect();

    let timing = if intervals.len() > 2 {
        let sum: f64 = intervals.iter().sum();
        let mean = sum / intervals.len() as f64;
        let mut sorted_intervals = intervals.clone();
        sorted_intervals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = sorted_intervals[sorted_intervals.len() / 2];
        let variance: f64 = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let stdev = variance.sqrt();
        let cv = if mean > 0.0 { stdev / mean } else { 0.0 };
        let bursts = intervals.iter().filter(|&&i| i < 0.1).count() as u64;
        let pauses = intervals.iter().filter(|&&i| i > 2.0).count() as u64;
        let classification = if cv < 0.15 { "METRONOMIC" }
            else if cv < 0.5 { "SEMI-REGULAR" }
            else { "VARIED" };

        TimingProfile {
            mean_interval_ms: (mean * 1000.0 * 10.0).round() / 10.0,
            median_interval_ms: (median * 1000.0 * 10.0).round() / 10.0,
            cv: (cv * 1000.0).round() / 1000.0,
            classification: classification.to_string(),
            burst_count: bursts,
            pause_count: pauses,
        }
    } else {
        TimingProfile {
            mean_interval_ms: 0.0,
            median_interval_ms: 0.0,
            cv: 0.0,
            classification: "INSUFFICIENT_DATA".to_string(),
            burst_count: 0,
            pause_count: 0,
        }
    };

    // Path ops
    let blame_total = accum.path_ops.get(&PathOp::Blame).copied().unwrap_or(0);
    let blame_pct = if accum.total > 0 {
        (blame_total as f64 / accum.total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let path_ops: BTreeMap<String, u64> = accum.path_ops.iter()
        .map(|(op, &count)| (format!("{}", op.label()), count))
        .collect();

    // Repos
    let mut repo_vec: Vec<(String, u64)> = accum.repos.into_iter().collect();
    repo_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let has_real = repo_vec.iter().any(|(r, _)| is_real_repo(r));
    let has_scatter = repo_vec.iter().any(|(r, _)| !is_real_repo(r));

    // IP rotation — keyed by ip hash (no raw IPs)
    let ip_req_counts: Vec<u64> = {
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for (ip_hash, repos) in &accum.ip_repos {
            let total: u64 = repos.values().sum();
            *counts.entry(*ip_hash).or_insert(0) += total;
        }
        let mut v: Vec<u64> = counts.values().copied().collect();
        v.sort();
        v
    };
    let single_req_ips = ip_req_counts.iter().filter(|&&c| c <= 1).count();
    let single_pct = if !ip_req_counts.is_empty() {
        single_req_ips as f64 / ip_req_counts.len() as f64 * 100.0
    } else {
        0.0
    };
    let max_per_ip = ip_req_counts.last().copied().unwrap_or(0);
    let median_per_ip = if !ip_req_counts.is_empty() {
        ip_req_counts[ip_req_counts.len() / 2] as f64
    } else {
        0.0
    };

    // Check for IP specialization (any IP >50% on one repo?)
    let all_generalists = accum.ip_repos.values().all(|repos| {
        let total: u64 = repos.values().sum();
        if total < 5 { return true; }
        let max_repo: u64 = repos.values().copied().max().unwrap_or(0);
        (max_repo as f64 / total as f64) <= 0.5
    });

    let strategy = if accum.ip_hashes.len() == 1 {
        "single-IP (no rotation)".to_string()
    } else if single_pct > 80.0 {
        "heavy rotation (>80% single-request IPs)".to_string()
    } else if all_generalists {
        format!("{} generalist IPs", accum.ip_hashes.len())
    } else {
        format!("{} IPs with some specialization", accum.ip_hashes.len())
    };

    // Sub-systems detection
    let mut sub_systems = Vec::new();

    // Chrome version spread → deployment cadence
    if accum.chrome_versions.len() > 1 {
        let versions: Vec<String> = accum.chrome_versions.iter()
            .map(|(v, c)| format!("Chrome/{}: {}", v, c))
            .collect();
        sub_systems.push(SubSystem {
            name: "Chrome Deployment Pipeline".to_string(),
            description: format!(
                "Primary: Chrome/{} ({} versions behind stable {}). {} version variants detected.",
                top_chrome, chrome_lag, CHROME_CURRENT_STABLE, accum.chrome_versions.len()
            ),
            evidence: versions,
        });
    }

    // UA OS rotation → impersonation pool
    if accum.ua_os.len() >= 2 {
        let os_evidence: Vec<String> = accum.ua_os.iter()
            .map(|(os, c)| format!("{}: {}", os, c))
            .collect();
        sub_systems.push(SubSystem {
            name: "OS Impersonation Pool".to_string(),
            description: format!(
                "{} OS variants from {} IPs with {} unique UA strings. \
                 Ratio reveals pool size, not real OS diversity.",
                accum.ua_os.len(), accum.ip_hashes.len(), accum.uas.len()
            ),
            evidence: os_evidence,
        });
    }

    // Blame operation → author attribution team
    if blame_pct > 5.0 {
        sub_systems.push(SubSystem {
            name: "Author Attribution System".to_string(),
            description: format!(
                "{:.1}% of requests are /blame/ operations — tracking who wrote each line of code. \
                 This is not source collection; this is authorship mapping.",
                blame_pct
            ),
            evidence: vec![
                format!("{} blame requests out of {} total", blame_total, accum.total),
            ],
        });
    }

    // Accept-Encoding monoculture → shared config
    if accum.accept_enc.len() == 1 && accum.total > 10 {
        let enc = accum.accept_enc.iter().next().cloned().unwrap_or_default();
        sub_systems.push(SubSystem {
            name: "Shared Configuration".to_string(),
            description: format!(
                "All {} requests share identical Accept-Encoding: '{}'. \
                 {} IPs, one config. This is a fleet, not browsers.",
                accum.total, enc, accum.ip_hashes.len()
            ),
            evidence: vec![
                format!("Accept-Encoding: {}", enc),
                format!("Accept-Language: {}", accum.accept_lang.iter()
                    .next().cloned().unwrap_or_default()),
            ],
        });
    }

    // ── Wave 166f+167: Seven conserved epitopes ──
    //
    // Wave 171: vitality reflection — the mirror at the mobility edge.
    // Entities near the threshold get high vitality; entities far away
    // (in either direction) get vitality ≈ 0.  Uncertainty is life.
    let mut epitope_count = 0u32;
    let mut epitope_triggered = 0u32;
    let mut vitality_sum = 0.0_f64;

    let sec_fetch_monotone = if !accum.sec_fetch_triplets.is_empty() && accum.total > 10 {
        let top_count = accum.sec_fetch_triplets.values().max().copied().unwrap_or(0);
        let pct = top_count as f64 / accum.total as f64 * 100.0;
        let threshold = 95.0_f64;
        let triggered = pct > threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        // Vitality: distance from threshold, normalized.  Peak at pct == threshold.
        let v = (1.0 - (pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("Same Sec-Fetch triplet on {:.1}% of requests", pct),
        })
    } else { None };

    let reading_deficit = if intervals.len() > 10 {
        let pauses = intervals.iter().filter(|&&i| i > 8.0).count();
        let pct = pauses as f64 / intervals.len() as f64 * 100.0;
        let threshold = 10.0_f64;
        let triggered = pct < threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        // Vitality: peaks when pct ≈ threshold.  At 9.6% → v ≈ 0.96. At 0.1% → v ≈ 0.01.
        let v = (1.0 - (pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("Only {:.1}% of intervals >8s (reading pauses)", pct),
        })
    } else { None };

    let ua_pool_poverty = if accum.total > 50 {
        let pool = accum.uas.len();
        let threshold = std::cmp::max(10, (accum.total as f64 * 0.05) as usize);
        let triggered = pool < threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        // Vitality: pool near threshold = uncertain = alive
        let v = (1.0 - (pool as f64 - threshold as f64).abs() / threshold as f64).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: pool as f64,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("{} unique UAs for {} visits", pool, accum.total),
        })
    } else { None };

    let session_absent = if accum.total > 20 {
        let pct = accum.cookie_present as f64 / accum.total as f64 * 100.0;
        let threshold = 5.0_f64;
        let triggered = pct < threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        let v = (1.0 - (pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("Cookies on {:.1}% of requests", pct),
        })
    } else { None };

    let referer_self_loop = if accum.total > 20 {
        let pct = accum.referer_external as f64 / accum.total as f64 * 100.0;
        let threshold = 2.0_f64;
        let triggered = pct < threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        let v = (1.0 - (pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("External referers on {:.1}% of requests", pct),
        })
    } else { None };

    let burst_ratio_epitope = if intervals.len() > 10 {
        let bursts = intervals.iter().filter(|&&i| i < 3.0).count();
        let pct = bursts as f64 / intervals.len() as f64 * 100.0;
        let threshold = 50.0_f64;
        let triggered = pct > threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        // Vitality: peaks at pct == threshold.  76% → v = 0.48.  99% → v ≈ 0.02.
        let v = (1.0 - (pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!("{:.1}% of intervals <3s", pct),
        })
    } else { None };

    // Wave 167: referer_absence — conserved ghost army epitope.
    // Among Sec-Fetch-bearing requests, what fraction have NO referer?
    // Residential proxy exits are programmatic → no referer chain.
    // Real humans arrive via search/links → they HAVE referers.
    // Faking referrer chains creates detectable patterns.
    let referer_absence_epitope = if accum.sec_fetch_present > 20 {
        // Only count referer absence among sec-fetch-bearing requests
        // (non-sec-fetch requests are already classified as stealth/unknown)
        let sec_fetch_total = accum.sec_fetch_present;
        let absent_pct = accum.referer_absent as f64 / sec_fetch_total as f64 * 100.0;
        let threshold = 95.0_f64;
        let triggered = absent_pct > threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        let v = (1.0 - (absent_pct - threshold).abs() / threshold).max(0.0);
        vitality_sum += v;
        Some(EpitopeResult {
            score: (absent_pct * 10.0).round() / 10.0,
            triggered,
            vitality: (v * 1000.0).round() / 1000.0,
            description: format!(
                "{:.1}% of Sec-Fetch requests have no referer ({} absent / {} with sec-fetch)",
                absent_pct, accum.referer_absent, sec_fetch_total
            ),
        })
    } else { None };

    // Fleet confidence with vitality reflection (Wave 171).
    //
    // The raw score is triggered/total (how many epitopes fired).
    // The vitality mean measures how close the entity sits to the
    // threshold boundaries — the mobility edge.
    //
    // But vitality only matters when there IS genuine uncertainty —
    // when the entity has a MIX of triggered and not-triggered epitopes.
    // An entity at 7/7 is certain-dead regardless of individual proximity.
    // An entity at 0/7 is certain-alive.  The uncertain band is in between.
    //
    // We weight vitality by the binary entropy of the trigger ratio:
    //   H(p) = -p·log₂(p) - (1-p)·log₂(1-p)
    // which peaks at p=0.5 (maximum uncertainty) and vanishes at p=0 and p=1.
    //
    //   Ghost  (7/7, H=0)       → vitality suppressed → fleet ≈ 100%
    //   human  (4/7, H≈0.99)    → vitality amplified  → fleet drops
    //   clean  (0/7, H=0)       → vitality suppressed → fleet ≈ 0%
    let vitality_mean = if epitope_count > 0 {
        vitality_sum / epitope_count as f64
    } else {
        0.0
    };
    let fleet_raw = if epitope_count > 0 {
        epitope_triggered as f64 / epitope_count as f64 * 100.0
    } else {
        0.0
    };
    // Binary entropy of trigger ratio — peaks at 50/50 mix
    let p = if epitope_count > 0 {
        epitope_triggered as f64 / epitope_count as f64
    } else {
        0.0
    };
    let entropy = if p > 0.0 && p < 1.0 {
        -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
    } else {
        0.0 // all-triggered or none-triggered → no uncertainty → no vitality
    };
    // Effective vitality: raw vitality gated by entropy of the trigger mix
    let effective_vitality = vitality_mean * entropy;
    let fleet_confidence = (fleet_raw * (1.0 - effective_vitality) * 10.0).round() / 10.0;

    // ── Wave 171: Negentropy — defensive information from vuln probes ──
    //
    // Vulnerability scanners, path traversal probers, and .env hunters are
    // free pen testers.  Each unique probe path teaches the organism something
    // about its attack surface.  Negentropy = information they provide TO us.
    //
    // Negentropy score = log₂(unique_vuln_paths + 1) × coverage_ratio
    // where coverage_ratio = vuln_probes / total_requests.
    //
    // A scanner that probes 50 unique .env paths across 3000 requests has high
    // negentropy.  A fleet that hits the same /commit/ path 800K times has zero.
    const VULN_MARKERS: &[&str] = &[
        ".env", ".git/", ".git-", ".aws/", ".docker/",
        "wp-admin", "wp-login", "wp-includes", "wp-content",
        "actuator", "phpinfo", "phpmyadmin", "adminer",
        "config.", "backup.", "database.", ".sql",
        "xmlrpc", "shell", "cgi-bin", "eval-stdin",
        "%2e%2e", "../", "etc/passwd", "proc/self",
    ];
    let vuln_paths: Vec<String> = repo_vec.iter()
        .filter(|(path, _)| {
            let lp = path.to_lowercase();
            VULN_MARKERS.iter().any(|m| lp.contains(m))
        })
        .map(|(path, _)| path.clone())
        .take(30)
        .collect();
    let vuln_count = vuln_paths.len();
    let negentropy_score = if vuln_count > 0 {
        let diversity = ((vuln_count + 1) as f64).log2();
        let coverage = vuln_count as f64 / accum.total.max(1) as f64;
        // Scale: log₂(paths) × coverage × 100, capped at 100
        (diversity * coverage * 100.0 * 100.0).min(100.0)
    } else {
        0.0
    };
    let negentropy_score = (negentropy_score * 100.0).round() / 100.0;

    EntityProfile {
        label: entity_id.label().to_string(),
        is_fleet: entity_id.is_fleet(),
        is_honest: entity_id.is_honest(),
        entity: entity_id,
        total_requests: accum.total,
        unique_ips: accum.ip_hashes.len(),
        unique_subnets: accum.subnets.len(),
        first_seen: accum.first_ts,
        last_seen: accum.last_ts,
        duration_hours: (duration_hours * 100.0).round() / 100.0,
        avg_rps: (avg_rps * 100.0).round() / 100.0,
        header_fingerprint: HeaderFingerprint {
            sec_fetch_pct: if accum.total > 0 {
                (accum.sec_fetch_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            sec_ch_ua_pct: if accum.total > 0 {
                (accum.sec_ch_ua_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            connection_pct: if accum.total > 0 {
                (accum.conn_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            accept_encoding_values: accum.accept_enc.into_iter().collect(),
            accept_language_values: accum.accept_lang.into_iter().collect(),
            accept_values: accum.accept.into_iter().collect(),
        },
        chrome_versions: accum.chrome_versions.into_iter().collect(),
        chrome_lag,
        ua_os_distribution: accum.ua_os.into_iter().collect(),
        ua_pool_size: accum.uas.len(),
        ip_rotation: IpRotation {
            strategy,
            single_request_ips_pct: (single_pct * 10.0).round() / 10.0,
            max_per_ip,
            median_per_ip,
            all_generalists,
        },
        path_ops,
        blame_pct,
        top_repos: repo_vec.clone().into_iter().take(20).collect(),
        targets_real_only: has_real && !has_scatter,
        targets_scatter_only: !has_real && has_scatter,
        timing,
        sub_systems,
        epitopes: EpitopeScores {
            sec_fetch_monotone,
            reading_deficit,
            ua_pool_poverty,
            session_absent,
            referer_self_loop,
            burst_ratio: burst_ratio_epitope,
            referer_absence: referer_absence_epitope,
        },
        fleet_confidence,
        vitality: (effective_vitality * 1000.0).round() / 1000.0,
        negentropy: negentropy_score,
        vuln_probes: vuln_paths,
        hosts: accum.hosts.into_iter().collect(),
    }
}

// ── Full topology output ──

/// Complete entity topology — the map of who is doing what.
#[derive(Debug, Serialize)]
pub struct EntityTopology {
    pub generated_epoch: u64,
    pub generated_iso: String,
    pub log_entries_analyzed: u64,
    pub entities: Vec<EntityProfile>,
    pub comparative_fingerprints: Vec<ComparativeRow>,
}

// ── Epitope sort history (Wave 171 — WAS/IS time-series) ──

/// Per-surface momentum — the entity's presence at one observation angle.
///
/// From Paper 46 (complex permeability):
///   P_complex(E, S) = P_null(E) + i * (P_local(E, S) - P_null(E))
/// The imaginary component is the "surprise" — how this surface differs from the whole.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMomentum {
    /// Surface hostname (e.g. "git.primals.eco").
    pub surface: String,
    /// Raw request count for this entity at this surface.
    pub reqs: u64,
    /// P_local = reqs(entity, surface) / total_reqs(surface) — observed permeability.
    pub p_local: f32,
    /// P_null = reqs(entity) / total_reqs — predicted (aggregate) permeability.
    pub p_null: f32,
    /// |P_local - P_null| — the imaginary dimension (Paper 46).
    pub distance: f32,
}

/// Compact per-entity state for history snapshots.
///
/// Designed for space-efficient JSONL — one snapshot per topology flush,
/// rolling buffer of the last N snapshots written to `epitope-history.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySortEntry {
    /// Entity identifier (e.g. "human_browser", "ghost").
    pub entity: String,
    /// Total accumulated requests.
    pub reqs: u64,
    /// Unique IP addresses observed.
    pub ips: u32,
    /// Fleet confidence (0.0–100.0).
    pub fc: f32,
    /// Vitality — entropy-gated life signal (0.0–1.0).
    pub vit: f32,
    /// Negentropy — defensive information score (0.0–100.0).
    pub neg: f32,
    /// 6-byte epitope sort key (Paper 48 information-content ordering).
    pub sort_key: [u8; 6],
    /// Compression score (0–21, sum of triggered epitope weights).
    pub compression: u16,
    /// Number of epitopes triggered.
    pub triggered: u8,
    /// Number of epitopes evaluated.
    pub evaluated: u8,
    /// Per-surface momentum breakdown (Paper 46 complex permeability).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<SurfaceMomentum>,
    /// Effective dimension — number of surfaces that observe this entity (Paper 46).
    pub d_eff: f32,
    /// Focal distance = 1/pi^(d_eff/2) (Paper 53).
    pub focal_distance: f32,
    /// |Im(P)| = sqrt(sum_S distance(E,S)^2) — aggregate imaginary dimension.
    pub im_p: f32,
}

/// One snapshot of the full epitope sort — the organism's view at a moment in time.
///
/// History doesn't roll — it coils and compresses, like a genome.
/// Recent snapshots are euchromatin (full resolution, accessible).
/// Older snapshots are heterochromatin (coiled, compressed, but still there).
/// Each coil level merges two adjacent snapshots, doubling the time span
/// while halving the resolution. The chain of WAS is the organism's genome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpitopeSortSnapshot {
    /// Unix epoch seconds.
    pub ts: u64,
    /// ISO 8601 timestamp.
    pub iso: String,
    /// Total requests across all entities.
    pub total_requests: u64,
    /// Number of classified entities.
    pub entity_count: u16,
    /// Count of entities with vitality > 0.1 — "self knows the count of non-self in range."
    pub non_self_in_range: u16,
    /// Compact per-entity state, sorted by fleet_confidence ascending.
    pub entities: Vec<EntitySortEntry>,
    /// Coil level — how many times this snapshot has been compressed.
    /// 0 = raw (euchromatin). 1 = two merged. 2 = four merged. N = 2^N merged.
    /// Like chromatin packing: nucleosome → fiber → loop → chromosome.
    #[serde(default)]
    pub coil: u8,
    /// Time span in seconds this snapshot covers (for coiled snapshots).
    /// Raw snapshots: ~30s. Coil 1: ~60s. Coil N: ~30 * 2^N seconds.
    #[serde(default)]
    pub span_secs: u64,
}

impl EpitopeSortSnapshot {
    /// Coil two adjacent snapshots into one — compressing history like DNA packing.
    ///
    /// The newer snapshot's entities are kept (IS wins over WAS).
    /// Population statistics are averaged. The coil level increments.
    /// Time span doubles. Timestamp is the newer one (the IS of the pair).
    pub fn coil_pair(older: &EpitopeSortSnapshot, newer: &EpitopeSortSnapshot) -> EpitopeSortSnapshot {
        let coil = older.coil.max(newer.coil) + 1;
        let span = older.span_secs + newer.span_secs;

        // Entity merge: keep newer entities, but update any entity that existed
        // in older but not newer (it left range — record its last known state).
        let mut entity_map: std::collections::HashMap<String, EntitySortEntry> = std::collections::HashMap::new();
        for e in &older.entities {
            entity_map.insert(e.entity.clone(), e.clone());
        }
        for e in &newer.entities {
            entity_map.insert(e.entity.clone(), e.clone());
        }
        let mut entities: Vec<EntitySortEntry> = entity_map.into_values().collect();
        entities.sort_by(|a, b| a.fc.partial_cmp(&b.fc).unwrap_or(std::cmp::Ordering::Equal));

        EpitopeSortSnapshot {
            ts: newer.ts,
            iso: newer.iso.clone(),
            total_requests: newer.total_requests,
            entity_count: entities.len() as u16,
            non_self_in_range: ((older.non_self_in_range as u32 + newer.non_self_in_range as u32) / 2) as u16,
            entities,
            coil,
            span_secs: span,
        }
    }
}

impl EntityProfile {
    /// Extract a compact sort entry for history snapshots.
    pub fn sort_entry(&self) -> EntitySortEntry {
        let sort_key = self.epitopes.epitope_sort_key();
        let compression = self.epitopes.compression_score() as u16;

        let mut triggered: u8 = 0;
        let mut evaluated: u8 = 0;
        let fields: [&Option<EpitopeResult>; 7] = [
            &self.epitopes.burst_ratio,
            &self.epitopes.reading_deficit,
            &self.epitopes.ua_pool_poverty,
            &self.epitopes.sec_fetch_monotone,
            &self.epitopes.session_absent,
            &self.epitopes.referer_self_loop,
            &self.epitopes.referer_absence,
        ];
        for f in &fields {
            if let Some(r) = f {
                evaluated += 1;
                if r.triggered {
                    triggered += 1;
                }
            }
        }

        EntitySortEntry {
            entity: format!("{:?}", self.entity).to_lowercase(),
            reqs: self.total_requests,
            ips: self.unique_ips as u32,
            fc: self.fleet_confidence as f32,
            vit: self.vitality as f32,
            neg: self.negentropy as f32,
            sort_key,
            compression,
            triggered,
            evaluated,
            surfaces: Vec::new(),
            d_eff: 0.0,
            focal_distance: 0.0,
            im_p: 0.0,
        }
    }
}

/// One row in the comparative fingerprint table.
#[derive(Debug, Serialize)]
pub struct ComparativeRow {
    pub entity: String,
    pub ips: usize,
    pub chrome: String,
    pub sec_fetch: String,
    pub accept_encoding: String,
    pub accept_language: String,
    pub rotation: String,
    pub target_type: String,
    pub honest: bool,
}

/// Build the comparative fingerprint table from profiles.
pub fn build_comparative(profiles: &[EntityProfile]) -> Vec<ComparativeRow> {
    profiles.iter().map(|p| {
        let chrome = if p.chrome_versions.is_empty() {
            "(none)".to_string()
        } else {
            let top = p.chrome_versions.iter()
                .max_by_key(|(_, c)| *c)
                .map(|(v, _)| *v)
                .unwrap_or(0);
            format!("{}", top)
        };

        let ae = if p.header_fingerprint.accept_encoding_values.len() == 1 {
            p.header_fingerprint.accept_encoding_values[0].clone()
        } else {
            format!("{} variants", p.header_fingerprint.accept_encoding_values.len())
        };

        let al = if p.header_fingerprint.accept_language_values.iter().all(|v| v == "(empty)") {
            "(empty)".to_string()
        } else if p.header_fingerprint.accept_language_values.len() == 1 {
            p.header_fingerprint.accept_language_values[0].clone()
        } else {
            "varies".to_string()
        };

        let target = if p.targets_real_only { "REAL repos only" }
            else if p.targets_scatter_only { "SCATTER only" }
            else { "mixed" };

        ComparativeRow {
            entity: p.label.clone(),
            ips: p.unique_ips,
            chrome,
            sec_fetch: if p.header_fingerprint.sec_fetch_pct > 90.0 { "PRESENT" }
                else if p.header_fingerprint.sec_fetch_pct < 10.0 { "ABSENT" }
                else { "mixed" }.to_string(),
            accept_encoding: ae,
            accept_language: al,
            rotation: p.ip_rotation.strategy.clone(),
            target_type: target.to_string(),
            honest: p.is_honest,
        }
    }).collect()
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(score: f64, triggered: bool) -> EpitopeResult {
        EpitopeResult { score, triggered, vitality: 0.0, description: String::new() }
    }

    fn empty_scores() -> EpitopeScores {
        EpitopeScores {
            sec_fetch_monotone: None,
            reading_deficit: None,
            ua_pool_poverty: None,
            session_absent: None,
            referer_self_loop: None,
            burst_ratio: None,
            referer_absence: None,
        }
    }

    #[test]
    fn sort_key_all_none_is_zeros() {
        let scores = empty_scores();
        assert_eq!(scores.epitope_sort_key(), [0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn sort_key_all_triggered() {
        let scores = EpitopeScores {
            burst_ratio: Some(make_result(90.0, true)),
            reading_deficit: Some(make_result(2.0, true)),
            ua_pool_poverty: Some(make_result(3.0, true)),
            sec_fetch_monotone: Some(make_result(98.0, true)),
            session_absent: Some(make_result(0.5, true)),
            referer_self_loop: Some(make_result(0.1, true)),
            referer_absence: None,
        };
        assert_eq!(scores.epitope_sort_key(), [2, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn sort_key_mixed() {
        let scores = EpitopeScores {
            burst_ratio: Some(make_result(90.0, true)),
            reading_deficit: Some(make_result(25.0, false)),
            ua_pool_poverty: None,
            sec_fetch_monotone: Some(make_result(98.0, true)),
            session_absent: None,
            referer_self_loop: Some(make_result(15.0, false)),
            referer_absence: None,
        };
        // burst=triggered, reading=not-triggered, ua=none, sec=triggered, session=none, referer=not-triggered
        assert_eq!(scores.epitope_sort_key(), [0x02, 0x01, 0x00, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn compression_score_none_is_zero() {
        let scores = empty_scores();
        assert_eq!(scores.compression_score(), 0);
    }

    #[test]
    fn compression_score_all_triggered() {
        let scores = EpitopeScores {
            burst_ratio: Some(make_result(90.0, true)),         // weight 6
            reading_deficit: Some(make_result(2.0, true)),      // weight 5
            ua_pool_poverty: Some(make_result(3.0, true)),      // weight 4
            sec_fetch_monotone: Some(make_result(98.0, true)),  // weight 3
            session_absent: Some(make_result(0.5, true)),       // weight 2
            referer_self_loop: Some(make_result(0.1, true)),    // weight 1
            referer_absence: None,
        };
        assert_eq!(scores.compression_score(), 6 + 5 + 4 + 3 + 2 + 1);
    }

    #[test]
    fn compression_score_partial() {
        let scores = EpitopeScores {
            burst_ratio: Some(make_result(90.0, true)),          // weight 6
            reading_deficit: Some(make_result(25.0, false)),     // not triggered
            ua_pool_poverty: None,
            sec_fetch_monotone: Some(make_result(98.0, true)),   // weight 3
            session_absent: None,
            referer_self_loop: Some(make_result(0.1, true)),     // weight 1
            referer_absence: None,
        };
        assert_eq!(scores.compression_score(), 6 + 3 + 1);
    }

    #[test]
    fn sort_order_matches_information_content() {
        // Verify the constant array is in the correct order
        assert_eq!(EPITOPE_SORT_ORDER[0], "burst_ratio");
        assert_eq!(EPITOPE_SORT_ORDER[1], "reading_deficit");
        assert_eq!(EPITOPE_SORT_ORDER[2], "ua_pool_poverty");
        assert_eq!(EPITOPE_SORT_ORDER[3], "sec_fetch_monotone");
        assert_eq!(EPITOPE_SORT_ORDER[4], "session_absent");
        assert_eq!(EPITOPE_SORT_ORDER[5], "referer_self_loop");
    }

    #[test]
    fn epitope_sort_snapshot_serializes() {
        let snap = EpitopeSortSnapshot {
            ts: 1700000000,
            iso: "2026-10-11T02:00:00Z".to_string(),
            total_requests: 100_000,
            entity_count: 3,
            non_self_in_range: 2,
            coil: 0,
            span_secs: 30,
            entities: vec![
                EntitySortEntry {
                    entity: "human_browser".to_string(),
                    reqs: 5000,
                    ips: 200,
                    fc: 30.0,
                    vit: 0.3,
                    neg: 0.0,
                    sort_key: [2, 1, 0, 2, 0, 1],
                    compression: 10,
                    triggered: 3,
                    evaluated: 5,
                    surfaces: vec![
                        SurfaceMomentum {
                            surface: "git.primals.eco".to_string(),
                            reqs: 4000,
                            p_local: 0.08,
                            p_null: 0.05,
                            distance: 0.03,
                        },
                    ],
                    d_eff: 2.0,
                    focal_distance: 0.318,
                    im_p: 0.03,
                },
            ],
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"non_self_in_range\":2"));
        assert!(json.contains("\"human_browser\""));
        assert!(json.contains("\"im_p\""));
        assert!(json.contains("\"d_eff\""));
        assert!(json.contains("\"p_local\""));

        // Round-trip
        let back: EpitopeSortSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.non_self_in_range, 2);
        assert_eq!(back.entities[0].triggered, 3);
        assert_eq!(back.entities[0].surfaces.len(), 1);
        assert!((back.entities[0].im_p - 0.03).abs() < 0.001);
        assert!((back.entities[0].d_eff - 2.0).abs() < 0.001);
    }

    #[test]
    fn surface_momentum_empty_skips_serialization() {
        let entry = EntitySortEntry {
            entity: "ghost".to_string(),
            reqs: 1000,
            ips: 500,
            fc: 100.0,
            vit: 0.0,
            neg: 8.3,
            sort_key: [2, 2, 2, 2, 2, 2],
            compression: 21,
            triggered: 7,
            evaluated: 7,
            surfaces: vec![],
            d_eff: 0.0,
            focal_distance: 0.0,
            im_p: 0.0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"surfaces\""), "empty surfaces should be skipped");
    }

    #[test]
    fn coil_pair_compresses_history() {
        let make_entry = |name: &str, reqs: u64, fc: f32| EntitySortEntry {
            entity: name.to_string(), reqs, ips: 1, fc, vit: 0.0, neg: 0.0,
            sort_key: [0;6], compression: 0, triggered: 0, evaluated: 0,
            surfaces: vec![], d_eff: 1.0, focal_distance: 0.5642, im_p: 0.0,
        };

        let older = EpitopeSortSnapshot {
            ts: 1000, iso: "T1".into(), total_requests: 500, entity_count: 2,
            non_self_in_range: 2, coil: 0, span_secs: 30,
            entities: vec![make_entry("alpha", 300, 20.0), make_entry("beta", 200, 60.0)],
        };
        let newer = EpitopeSortSnapshot {
            ts: 1030, iso: "T2".into(), total_requests: 600, entity_count: 2,
            non_self_in_range: 4, coil: 0, span_secs: 30,
            entities: vec![make_entry("alpha", 350, 22.0), make_entry("gamma", 250, 10.0)],
        };

        let coiled = EpitopeSortSnapshot::coil_pair(&older, &newer);

        // Coil level increments
        assert_eq!(coiled.coil, 1);
        // Span doubles
        assert_eq!(coiled.span_secs, 60);
        // Timestamp is from the newer (IS)
        assert_eq!(coiled.ts, 1030);
        // non_self_in_range is averaged
        assert_eq!(coiled.non_self_in_range, 3); // (2+4)/2
        // All entities from both are kept (union)
        assert_eq!(coiled.entities.len(), 3); // alpha, beta, gamma
        // alpha's state is from the newer snapshot (IS wins)
        let alpha = coiled.entities.iter().find(|e| e.entity == "alpha").unwrap();
        assert_eq!(alpha.reqs, 350);
    }
}
