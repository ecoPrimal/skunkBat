// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter server types — back pressure, opsonize cache, tarpit, metrics.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::scatter_prism::{PrismMode, PrismMix};

/// Back pressure gauge — a non-Newtonian viscosity dimension.
///
/// Tracks fleet request velocity as a rolling window. The harder they push,
/// the more the maze shifts against them:
///
/// - Higher pressure → shorter temporal epochs (maze reshuffles faster)
/// - Higher pressure → more cross-links per response (deeper maze)
/// - Higher pressure → more chimeric blending (less coherent data)
/// - Higher pressure → more varied scatter content types
///
/// The fleet cannot sense this dimension because they have no quality signal.
/// They optimize for throughput — they never check whether the data they got
/// is real, coherent, or even self-consistent. Like hitting a non-Newtonian
/// fluid: push slowly and it flows, hit it hard and it becomes a wall.
///
/// Biological parallel: a slime mold with central control. Real slime molds
/// (Physarum) are distributed — each cell senses its local environment and
/// adapts. This fleet is centrally orchestrated but has zero local sensation.
/// All nodes push the same way because the controller has no proprioception.
/// Back pressure exploits this: the defense stiffens exactly where they push
/// hardest, but they can't feel the stiffening.
#[derive(Debug, Clone)]
pub struct BackPressure {
    /// Rolling request count — incremented on every scatter request.
    request_count: Arc<AtomicU32>,
    /// Timestamp of last window reset (unix secs).
    window_start: Arc<std::sync::atomic::AtomicU64>,
    /// Window duration in seconds for rate calculation.
    window_secs: u64,
}

impl BackPressure {
    pub fn new(window_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            request_count: Arc::new(AtomicU32::new(0)),
            window_start: Arc::new(std::sync::atomic::AtomicU64::new(now)),
            window_secs,
        }
    }

    /// Record a request. Returns current pressure level (0.0 - 1.0).
    pub fn record_request(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);

        // Reset window if expired
        if now.saturating_sub(start) >= self.window_secs {
            self.request_count.store(1, Ordering::Relaxed);
            self.window_start.store(now, std::sync::atomic::Ordering::Relaxed);
            return self.compute_pressure(1);
        }

        let count = self.request_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.compute_pressure(count)
    }

    /// Current pressure level (0.0 = quiet, 1.0 = maximum pressure).
    pub fn read(&self) -> f64 {
        let count = self.request_count.load(Ordering::Relaxed);
        self.compute_pressure(count)
    }

    /// Requests per second in current window.
    pub fn rps(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = now.saturating_sub(start).max(1);
        let count = self.request_count.load(Ordering::Relaxed);
        count as f64 / elapsed as f64
    }

    /// Map request count to pressure (0.0-1.0) using a sigmoid curve.
    ///
    /// The curve is tuned so that:
    /// - < 1 rps → ~0.0 (human-like, maze is gentle)
    /// - ~5 rps → ~0.3 (light scraping, maze stiffens slightly)
    /// - ~13 rps → ~0.6 (steady fleet, maze is viscous)
    /// - ~30 rps → ~0.85 (heavy assault, maze is thick)
    /// - >50 rps → ~0.95+ (hammering, maze is nearly solid)
    fn compute_pressure(&self, count: u32) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = now.saturating_sub(start).max(1) as f64;
        let rps = count as f64 / elapsed;

        // Sigmoid: pressure = 1 / (1 + e^(-k*(rps - midpoint)))
        // midpoint=10 rps, k=0.25 → gentle ramp centered on typical fleet rate
        let k = 0.25_f64;
        let midpoint = 10.0_f64;
        let raw = 1.0 / (1.0 + (-k * (rps - midpoint)).exp());

        // Clamp and smooth — never quite 0 or 1
        raw.clamp(0.01, 0.99)
    }

    /// Pressure-adjusted temporal epoch length in minutes.
    ///
    /// At zero pressure: 30-minute epochs (content lives long enough to seem real).
    /// At max pressure: 5-minute epochs (maze reshuffles aggressively).
    /// The fleet cannot detect this because they don't re-request the same
    /// paths at known intervals — they just hammer forward.
    pub fn epoch_minutes(&self) -> u64 {
        let p = self.read();
        // Linear interpolation: 30 min at p=0, 5 min at p=1
        let minutes = 30.0 - (25.0 * p);
        (minutes as u64).max(5)
    }

    /// Pressure-adjusted cross-link density.
    ///
    /// Returns how many extra honeycomb cross-links to inject per response.
    /// At zero pressure: 1-2 links (subtle).
    /// At max pressure: 8-12 links (every response is a trap door).
    pub fn cross_link_count(&self) -> usize {
        let p = self.read();
        let count = 1.0 + (11.0 * p);
        count as usize
    }

    /// Pressure-adjusted content mutation factor.
    ///
    /// Controls how aggressively content is chimericized.
    /// At zero pressure: 0.0 (clean, coherent scatter — could pass for real).
    /// At max pressure: 1.0 (Frankenstein blending, function signatures
    /// don't match bodies, imports reference nonexistent packages).
    pub fn chimera_factor(&self) -> f64 {
        self.read()
    }
}

/// Shared confidence level from the opsonize pipeline.
///
/// Stored as confidence × 1000 (fixed-point) in an AtomicU32.
/// 0 = no tags yet (use base ratio), 1000 = 100% confidence.
///
/// The scatter server reads this to adapt:
/// - Higher confidence → higher effective poison ratio
/// - Higher confidence → richer content variety (repos, issues, wikis)
#[derive(Debug, Clone)]
pub struct SharedConfidence(pub Arc<AtomicU32>);

impl SharedConfidence {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU32::new(0)))
    }

    /// Update with latest confidence (0.0 - 1.0).
    pub fn update(&self, confidence: f64) {
        let fixed = (confidence.clamp(0.0, 1.0) * 1000.0) as u32;
        self.0.store(fixed, Ordering::Relaxed);
    }

    /// Read current confidence (0.0 - 1.0).
    pub fn read(&self) -> f64 {
        self.0.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Compute effective poison ratio given a base ratio and current confidence.
    ///
    /// At confidence 0.0 → base ratio (e.g. 0.3)
    /// At confidence 0.5 → midpoint (e.g. 0.55)
    /// At confidence 1.0 → max ratio (0.8)
    ///
    /// Never goes above 0.8 — always keep some 404s for plausible deniability.
    pub fn effective_ratio(&self, base_ratio: f32) -> f32 {
        let conf = self.read() as f32;
        let max_ratio = 0.8_f32;
        base_ratio + conf * (max_ratio - base_ratio)
    }
}

/// Cached opsonize tags from gossip — keyed by behavioral_hash.
///
/// The opsonize consumer periodically queries the gossip defense topic
/// for `defense.opsonize:*` entries and caches the results here. The scatter
/// server reads this cache to customize responses per-fleet:
/// - Known hashes get higher amplification intensity
/// - Detectors list drives content variant selection
/// - Multi-gate corroboration increases confidence
///
/// Population: skunky-ingest main loop calls `update_from_tag()` on each
/// opsonize emission, and `refresh_from_gossip()` on timer.
#[derive(Debug, Clone)]
pub struct OpsonizeCache {
    entries: Arc<RwLock<HashMap<String, CachedTag>>>,
    /// Conserved plasmid — generalized pathogen behaviors learned from ALL
    /// known fleet subgroups. Updated on every `update_from_tag()` call.
    /// Used by thymic_classify() for first-contact recognition of new fleets.
    plasmid: Arc<RwLock<ConservedPlasmid>>,
}

/// Conserved plasmid — the generalized fleet behavioral genome.
///
/// Biological analogy: a plasmid is a small circular DNA molecule that
/// transfers between bacteria, carrying genes useful for survival. The
/// conserved plasmid aggregates the behavioral signatures that ALL fleet
/// subgroups share — the epitopes that survive VPS rotation, UA changes,
/// and timing drift.
///
/// When a new entity appears with enough conserved epitopes, the thymus
/// recognizes it as fleet immediately — before individual detectors fire.
/// This closes the learning loop: new VPS, same pathogen.
#[derive(Debug, Clone, Default)]
pub struct ConservedPlasmid {
    /// Detector name → how many subgroups trigger it (frequency across population).
    pub detector_frequency: HashMap<String, u32>,
    /// Total number of distinct subgroups that have contributed to the plasmid.
    pub population_size: u32,
    /// Detectors that trigger in >50% of all subgroups — the conserved epitopes.
    /// These are the behavioral constants that define "fleet" regardless of which
    /// specific team is scraping.
    pub conserved_epitopes: Vec<String>,
    /// Average confidence across all known subgroups.
    pub mean_confidence: f64,
    /// Total observations across all subgroups.
    pub total_observations: u64,
    /// Last time the plasmid was rebuilt.
    pub last_rebuilt: u64,
}

/// A cached opsonize tag entry.
#[derive(Debug, Clone)]
pub struct CachedTag {
    /// Confidence from the detector pipeline (0.0-1.0).
    pub confidence: f64,
    /// Which detectors triggered (e.g. "content_gate", "stealth_ua").
    pub detectors: Vec<String>,
    /// How many times this hash has been matched.
    pub match_count: u64,
    /// Number of gates that have corroborated this hash.
    pub gate_count: usize,
    /// When this cache entry was last refreshed (epoch secs).
    pub last_refreshed: u64,
}

impl OpsonizeCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            plasmid: Arc::new(RwLock::new(ConservedPlasmid::default())),
        }
    }

    /// Update or insert a tag from the local opsonize pipeline.
    /// Also rebuilds the conserved plasmid from the updated population.
    /// Returns `true` if this was a **new** behavioral hash (first contact).
    pub async fn update_from_tag(&self, behavioral_hash: &str, confidence: f64, detectors: Vec<String>, match_count: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let is_new_hash;
        {
            let mut map = self.entries.write().await;
            is_new_hash = !map.contains_key(behavioral_hash);
            let entry = map.entry(behavioral_hash.to_owned()).or_insert_with(|| CachedTag {
                confidence: 0.0,
                detectors: Vec::new(),
                match_count: 0,
                gate_count: 1,
                last_refreshed: now,
            });
            entry.confidence = entry.confidence.max(confidence);
            entry.match_count += match_count;
            entry.last_refreshed = now;
            // Union detectors
            for d in detectors {
                if !entry.detectors.contains(&d) {
                    entry.detectors.push(d);
                }
            }
        }

        // Rebuild the conserved plasmid whenever a new subgroup appears
        // or periodically (every 60 seconds)
        if is_new_hash || now.saturating_sub(self.plasmid.read().await.last_rebuilt) > 60 {
            self.rebuild_plasmid(now).await;
        }

        is_new_hash
    }

    /// Rebuild the conserved plasmid from the entire population.
    /// Identifies which detectors are conserved (appear in >50% of subgroups)
    /// and computes population-level statistics.
    async fn rebuild_plasmid(&self, now: u64) {
        let map = self.entries.read().await;
        let pop = map.len() as u32;
        if pop == 0 {
            return;
        }

        let mut freq: HashMap<String, u32> = HashMap::new();
        let mut total_conf = 0.0;
        let mut total_obs = 0u64;

        for tag in map.values() {
            for d in &tag.detectors {
                *freq.entry(d.clone()).or_insert(0) += 1;
            }
            total_conf += tag.confidence;
            total_obs += tag.match_count;
        }

        // Conserved epitopes: present in >50% of all subgroups
        let threshold = (pop as f64 * 0.5).ceil() as u32;
        let mut conserved: Vec<String> = freq.iter()
            .filter(|(_, count)| **count >= threshold)
            .map(|(name, _)| name.clone())
            .collect();
        conserved.sort();

        let mut plasmid = self.plasmid.write().await;
        plasmid.detector_frequency = freq;
        plasmid.population_size = pop;
        plasmid.conserved_epitopes = conserved;
        plasmid.mean_confidence = total_conf / pop as f64;
        plasmid.total_observations = total_obs;
        plasmid.last_rebuilt = now;
    }

    /// Thymic classification — first-contact recognition of new fleet entities.
    ///
    /// Given a set of detector names from a NEW (unseen) observation, check
    /// how many match the conserved plasmid's epitopes. If enough match,
    /// the new entity is classified as fleet immediately.
    ///
    /// Returns (is_fleet, confidence, matching_epitopes).
    ///
    /// This is the thymus: it educates the immune system about what
    /// "pathogen" looks like in general, so new variants are recognized
    /// without needing individual antibody matching first.
    pub async fn thymic_classify(&self, detectors: &[String]) -> (bool, f64, Vec<String>) {
        let plasmid = self.plasmid.read().await;
        if plasmid.conserved_epitopes.is_empty() {
            return (false, 0.0, Vec::new());
        }

        let matching: Vec<String> = plasmid.conserved_epitopes.iter()
            .filter(|epi| detectors.iter().any(|d| d == *epi))
            .cloned()
            .collect();

        let match_ratio = matching.len() as f64 / plasmid.conserved_epitopes.len() as f64;

        // Thymic threshold: if >60% of conserved epitopes match, classify as fleet.
        // The confidence scales with match ratio and population evidence.
        let is_fleet = match_ratio > 0.6;
        let confidence = if is_fleet {
            // Confidence = match ratio × mean population confidence × log(population)
            // More subgroups confirming the epitopes = higher confidence
            let pop_factor = (plasmid.population_size as f64).ln().max(1.0) / 4.0;
            (match_ratio * plasmid.mean_confidence * pop_factor).min(1.0)
        } else {
            match_ratio * 0.1 // Low confidence for partial matches
        };

        (is_fleet, confidence, matching)
    }

    /// Get a snapshot of the conserved plasmid for diagnostics.
    pub async fn plasmid_snapshot(&self) -> ConservedPlasmid {
        self.plasmid.read().await.clone()
    }

    /// Export the conserved plasmid as a JSON string for the federation feed.
    ///
    /// This is the `/plasmid` endpoint: each golgi body publishes its local
    /// conserved plasmid so peer bodies can merge into their own federated
    /// threat intelligence feed. No body is central — any body's merge is valid.
    pub async fn export_plasmid_json(&self, layer_name: &str) -> String {
        let plasmid = self.plasmid.read().await;
        let entries = self.entries.read().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut epitopes_json = String::from("[");
        for (i, epi) in plasmid.conserved_epitopes.iter().enumerate() {
            if i > 0 { epitopes_json.push(','); }
            let freq = plasmid.detector_frequency.get(epi).copied().unwrap_or(0);
            let pct = if plasmid.population_size > 0 {
                (freq as f64 / plasmid.population_size as f64 * 100.0) as u32
            } else { 0 };
            epitopes_json.push_str(&format!(
                "{{\"name\":\"{epi}\",\"frequency_pct\":{pct},\"subgroups_matching\":{freq}}}"
            ));
        }
        epitopes_json.push(']');

        // Compute timing distribution across all known hashes
        let mut earliest_seen = now;
        let mut latest_seen = 0u64;
        let mut total_match_count = 0u64;

        let mut hashes_json = String::from("[");
        for (i, (hash, tag)) in entries.iter().enumerate() {
            if i > 0 { hashes_json.push(','); }
            let detectors_str: Vec<String> = tag.detectors.iter()
                .map(|d| format!("\"{d}\""))
                .collect();

            // Per-hash velocity: matches per hour since first seen
            let age_secs = now.saturating_sub(tag.last_refreshed).max(1);
            let velocity_per_hour = tag.match_count as f64 / (age_secs as f64 / 3600.0);

            hashes_json.push_str(&format!(
                "{{\"hash\":\"{}\",\"confidence\":{:.3},\"match_count\":{},\"gate_count\":{},\
                \"last_seen\":{},\"velocity_per_hour\":{:.1},\"detectors\":[{}]}}",
                &hash[..hash.len().min(16)],
                tag.confidence,
                tag.match_count,
                tag.gate_count,
                tag.last_refreshed,
                velocity_per_hour,
                detectors_str.join(","),
            ));

            if tag.last_refreshed < earliest_seen { earliest_seen = tag.last_refreshed; }
            if tag.last_refreshed > latest_seen { latest_seen = tag.last_refreshed; }
            total_match_count += tag.match_count;
        }
        hashes_json.push(']');

        // Observation window and aggregate velocity
        let window_secs = if latest_seen > earliest_seen { latest_seen - earliest_seen } else { 0 };
        let agg_velocity = if window_secs > 0 {
            total_match_count as f64 / (window_secs as f64 / 3600.0)
        } else { 0.0 };

        format!(
            "{{\
                \"schema\":\"ecoPrimals/layer-plasmid/v2\",\
                \"layer\":\"{layer_name}\",\
                \"generated\":{now},\
                \"population\":{{\
                    \"total_subgroups\":{},\
                    \"total_observations\":{},\
                    \"mean_confidence\":{:.3}\
                }},\
                \"timing\":{{\
                    \"observation_window_secs\":{window_secs},\
                    \"earliest_seen\":{earliest_seen},\
                    \"latest_seen\":{latest_seen},\
                    \"aggregate_velocity_per_hour\":{agg_velocity:.1},\
                    \"total_match_count\":{total_match_count}\
                }},\
                \"conserved_epitopes\":{epitopes_json},\
                \"behavioral_hashes\":{hashes_json}\
            }}",
            plasmid.population_size,
            plasmid.total_observations,
            plasmid.mean_confidence,
        )
    }

    /// Export plasmid JSON with Anderson profile appended.
    pub async fn export_plasmid_with_anderson(
        &self,
        layer_name: &str,
        anderson: &skunky_ingest::anderson_bridge::SharedAndersonProfile,
    ) -> String {
        let base = self.export_plasmid_json(layer_name).await;

        // Inject anderson_profile before the closing brace
        let profile_json = match anderson.read().await.as_ref() {
            Some(profile) => serde_json::to_string(profile).unwrap_or_else(|_| "null".into()),
            None => "null".into(),
        };

        if base.ends_with('}') {
            format!("{},\"anderson_profile\":{}}}", &base[..base.len()-1], profile_json)
        } else {
            base
        }
    }

    /// Look up a behavioral hash in the cache.
    pub async fn lookup(&self, behavioral_hash: &str) -> Option<CachedTag> {
        self.entries.read().await.get(behavioral_hash).cloned()
    }

    /// Count of known fleet hashes.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Evict stale entries older than the given age in seconds.
    pub async fn evict_stale(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.entries.write().await;
        map.retain(|_, tag| now.saturating_sub(tag.last_refreshed) < max_age_secs);
    }

    /// Get all known behavioral hashes (sorted for deterministic cross-referencing).
    pub async fn all_hashes(&self) -> Vec<String> {
        let map = self.entries.read().await;
        let mut hashes: Vec<String> = map.keys().cloned().collect();
        hashes.sort();
        hashes
    }

    /// Cross-mirror lookup: given a requesting fleet hash, return a DIFFERENT
    /// team's tag. Simple rotation for backward compatibility.
    ///
    /// Returns `(target_hash, target_tag)` or `None` if fewer than 2 teams known.
    pub async fn cross_mirror_lookup(&self, requesting_hash: &str) -> Option<(String, CachedTag)> {
        let mix = self.prism_mix(requesting_hash, 0, 0).await?;
        Some((mix.primary_hash, mix.primary_tag))
    }

    /// Prism mix — the maze/roach-motel evolution of cross-mirror.
    ///
    /// Instead of simple A→B rotation, the prism refracts fleet data through
    /// multiple lenses. Each honeycomb surface is a different lens. Each
    /// request mixes data from multiple teams. The fleet can't reverse-engineer
    /// which data belongs to whom.
    ///
    /// `surface_idx` maps to honeycomb subdomain (0=bloom, 1=thymus, etc.)
    /// `path_seed` adds per-path variation to the mix.
    ///
    /// Returns a PrismMix containing:
    /// - A primary target (heaviest weight)
    /// - Up to 3 secondary targets (blended in)
    /// - A mix_mode that determines content structure
    /// - Competitive intel that leaks to third-party scrapers (cytokine)
    pub async fn prism_mix(
        &self,
        requesting_hash: &str,
        surface_idx: u8,
        path_seed: u64,
    ) -> Option<PrismMix> {
        let map = self.entries.read().await;
        if map.len() < 2 {
            return None;
        }
        let mut hashes: Vec<&String> = map.keys().collect();
        hashes.sort();
        let pop = hashes.len();

        // Requester's position in the population
        let requester_idx = hashes.iter()
            .position(|h| h.as_str() == requesting_hash)
            .unwrap_or(0);

        // ── Primary target: surface_idx rotates the ring ──
        // Each honeycomb surface points to a different primary target
        // bloom(0) → next, thymus(1) → skip 2, opsonize(2) → skip 3, etc.
        let offset = (surface_idx as usize + 1).max(1);
        let primary_idx = (requester_idx + offset) % pop;
        let primary_idx = if hashes[primary_idx].as_str() == requesting_hash {
            (primary_idx + 1) % pop
        } else {
            primary_idx
        };
        let primary_hash = hashes[primary_idx].clone();
        let primary_tag = map.get(&primary_hash).cloned()?;

        // ── Secondary targets: path_seed selects additional data sources ──
        // The prism blends data from up to 3 other teams into the response.
        // Which teams are selected depends on the request path — so the same
        // URL always gives the same blend, but different URLs give different blends.
        let mut secondaries = Vec::new();
        if pop >= 4 {
            // Pick 1-3 additional teams, never self, never primary
            let blend_count = ((path_seed % 3) + 1) as usize;
            for i in 0..blend_count.min(pop - 2) {
                let sec_idx = (primary_idx + i + 2 + (path_seed as usize / (i + 1))) % pop;
                let sec_hash = hashes[sec_idx % pop];
                if sec_hash.as_str() != requesting_hash
                    && sec_hash.as_str() != primary_hash.as_str()
                    && !secondaries.iter().any(|(h, _): &(String, CachedTag)| h == sec_hash)
                {
                    if let Some(tag) = map.get(sec_hash) {
                        secondaries.push((sec_hash.clone(), tag.clone()));
                    }
                }
            }
        }

        // ── Mix mode: how the content blends primary + secondaries ──
        // Varies by surface + path for maximum unpredictability.
        // Wave 166f: epitope surfaces (9="epitope", 10="antigen") now serve
        // EpitopePress content — the evasion cost maze.
        let mix_mode = match (surface_idx % 6, (path_seed % 3) as u8) {
            // Dominant: 80% primary, light seasoning from secondaries
            (0, _) => PrismMode::Dominant,
            // Layered: primary structure, secondary details interleaved
            (1, _) => PrismMode::Layered,
            // Chimera: frankenstein blend — detectors from A, counts from B, framing from C
            (2, _) => PrismMode::Chimera,
            // Cytokine: structured for third-party ingestion — competitive intel payload
            (3, 0) => PrismMode::Cytokine,
            // Inverse: target gets fed its own data wrapped inside another team's structure
            (3, 1) => PrismMode::Inverse,
            // Apoptosis: surface pretends to be dying/removed, links to other honeycomb
            (3, _) => PrismMode::Apoptosis,
            // Wave 166f: EpitopePress — evasion cost maze
            (4, _) | (5, _) => PrismMode::EpitopePress,
            _ => PrismMode::Dominant,
        };

        Some(PrismMix {
            primary_hash,
            primary_tag,
            secondaries,
            mix_mode,
            surface_idx,
            requesting_hash: requesting_hash.to_owned(),
            population_size: pop,
        })
    }
}
// ══════════════════════════════════════════════════════════════════════
// Layer 1: Tarpit — mucus barrier
// ══════════════════════════════════════════════════════════════════════

/// Tarpit connection limiter — prevents self-DoS from too many slow-drip connections.
///
/// The mucus barrier's thickness is self-limiting. Too much mucus and the
/// organism suffocates. The TarpitState ensures we don't consume more
/// resources holding scanner connections than the scanners consume waiting.
#[derive(Debug, Clone)]
pub struct TarpitState {
    active: Arc<AtomicU32>,
    max_concurrent: u32,
}

impl TarpitState {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            active: Arc::new(AtomicU32::new(0)),
            max_concurrent,
        }
    }

    pub(crate) fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::SeqCst);
            if current >= self.max_concurrent {
                return false;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    pub(crate) fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn active_count(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}
// ══════════════════════════════════════════════════════════════════════
// Layer 2: Honeytokens — complement system
// ══════════════════════════════════════════════════════════════════════

/// Paths that scanners probe for credentials. When matched, the scatter
/// server serves fake-but-plausible credentials that trigger alerts
/// at the destination when the scanner tries to use them.
pub(crate) const HONEYTOKEN_PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.git/config",
    "/config/database.yml",
    "/config/database.yaml",
    "/api/v1/keys",
    "/debug/vars",
    "/server-info",
    "/.aws/credentials",
    "/config.json",
    "/config.yaml",
];

/// Check if a request path matches a known scanner credential probe.
pub(crate) fn is_honeytoken_path(path: &str) -> bool {
    let clean = path.split('?').next().unwrap_or(path);
    HONEYTOKEN_PATHS.iter().any(|p| clean == *p)
}

/// Live metrics for the scatter server — atomic counters for the /metrics endpoint.
#[derive(Debug, Clone)]
pub struct ScatterMetrics {
    pub total_requests: Arc<AtomicU32>,
    pub scatter_served: Arc<AtomicU32>,
    pub prism_served: Arc<AtomicU32>,
    pub mirror_served: Arc<AtomicU32>,
    pub tarpit_served: Arc<AtomicU32>,
    pub honeytoken_served: Arc<AtomicU32>,
    pub plasmid_served: Arc<AtomicU32>,
    pub nft_contributions: Arc<AtomicU32>,
    pub bytes_served: Arc<std::sync::atomic::AtomicU64>,
    pub started_at: Arc<std::sync::atomic::AtomicU64>,
}

impl ScatterMetrics {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            total_requests: Arc::new(AtomicU32::new(0)),
            scatter_served: Arc::new(AtomicU32::new(0)),
            prism_served: Arc::new(AtomicU32::new(0)),
            mirror_served: Arc::new(AtomicU32::new(0)),
            tarpit_served: Arc::new(AtomicU32::new(0)),
            honeytoken_served: Arc::new(AtomicU32::new(0)),
            plasmid_served: Arc::new(AtomicU32::new(0)),
            nft_contributions: Arc::new(AtomicU32::new(0)),
            bytes_served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Arc::new(std::sync::atomic::AtomicU64::new(now)),
        }
    }

    pub fn record(&self, bytes: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_served.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn export_json(&self, layer_name: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let started = self.started_at.load(std::sync::atomic::Ordering::Relaxed);
        let uptime = now.saturating_sub(started);
        let total = self.total_requests.load(Ordering::Relaxed);
        let bytes = self.bytes_served.load(std::sync::atomic::Ordering::Relaxed);
        let scatter = self.scatter_served.load(Ordering::Relaxed);
        let prism = self.prism_served.load(Ordering::Relaxed);
        let mirror = self.mirror_served.load(Ordering::Relaxed);
        let tarpit = self.tarpit_served.load(Ordering::Relaxed);
        let honey = self.honeytoken_served.load(Ordering::Relaxed);
        let plasmid = self.plasmid_served.load(Ordering::Relaxed);
        let rps = if uptime > 0 { total as f64 / uptime as f64 } else { 0.0 };
        let mbps = if uptime > 0 { bytes as f64 / uptime as f64 / 1024.0 / 1024.0 } else { 0.0 };

        format!(
            "{{\
                \"layer\":\"{layer_name}\",\
                \"uptime_secs\":{uptime},\
                \"total_requests\":{total},\
                \"requests_per_second\":{rps:.2},\
                \"bytes_served\":{bytes},\
                \"mb_per_second\":{mbps:.4},\
                \"breakdown\":{{\
                    \"scatter\":{scatter},\
                    \"prism\":{prism},\
                    \"mirror\":{mirror},\
                    \"tarpit\":{tarpit},\
                    \"honeytoken\":{honey},\
                    \"plasmid\":{plasmid}\
                }}\
            }}"
        )
    }
}

/// Scatter server configuration.
#[derive(Debug, Clone)]
pub struct ScatterConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Seed for deterministic content generation.
    pub seed: u64,
    /// Fraction of requests that get scatter content (0.0-1.0).
    /// Remaining requests get connection abort (status 444).
    pub poison_ratio: f32,
    /// Maximum concurrent tarpit (slow-drip) connections.
    /// Set to 0 to disable tarpitting (falls back to instant 429).
    pub max_tarpit_connections: u32,
}
