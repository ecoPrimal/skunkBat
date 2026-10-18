// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Entity topology builder and writer — accumulates request fingerprints
//! and periodically writes topology.json.
//!
//! Extracted from entity_classifier.rs for modularity.

#![allow(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::caddy;
use crate::entity_classifier::{EntityId, RequestFingerprint, classify, classify_with_registry};
use crate::entity_profile::{
    EntityAccum, EntityProfile, build_profile,
};
use crate::entity_sort::{
    EntityTopology, EpitopeSortSnapshot, build_comparative,
};

/// Maximum number of epitope sort snapshots to keep in the coiled genome.
/// History doesn't roll — it coils and compresses.
const MAX_HISTORY_SNAPSHOTS: usize = 200;

/// How many raw (coil=0) snapshots to keep at full resolution before coiling.
/// Recent history is euchromatin — accessible, full detail.
const EUCHROMATIN_WINDOW: usize = 100;

/// Accumulator for building entity profiles from raw request fingerprints.
pub struct TopologyBuilder {
    entities: HashMap<EntityId, EntityAccum>,
}

impl TopologyBuilder {
    /// Create a new topology builder.
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    /// Load a topology builder from a persisted state file (sourdough culture).
    /// Falls back to empty builder if file doesn't exist or is corrupt.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<HashMap<EntityId, EntityAccum>>(&json) {
                Ok(entities) => {
                    let total: u64 = entities.values().map(|a| a.total).sum();
                    tracing::info!(
                        entities = entities.len(),
                        requests = total,
                        path = %path.display(),
                        "🧬 topology culture loaded — sourdough warm start"
                    );
                    Self { entities }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "topology culture corrupt — starting fresh (should not happen)"
                    );
                    Self::new()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no topology culture file — first generation"
                );
                Self::new()
            }
        }
    }

    /// Save the accumulated state to disk (preserve the sourdough culture).
    pub fn save(&self, path: &Path) {
        match serde_json::to_string(&self.entities) {
            Ok(json) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, &json) {
                    tracing::warn!(error = %e, path = %path.display(), "topology culture save failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "topology culture serialization failed");
            }
        }
    }

    /// Ingest a request fingerprint (static classification fallback).
    pub fn ingest(&mut self, fp: &RequestFingerprint) {
        let entity_id = classify(fp);
        self.ingest_classified(fp, entity_id);
    }

    /// Ingest a request fingerprint using the culture-derived registry.
    pub fn ingest_with_registry(
        &mut self,
        fp: &RequestFingerprint,
        registry: &crate::epitope_registry::SharedRegistry,
    ) {
        let entity_id = classify_with_registry(fp, registry);
        // Record the match in the registry for observation counting
        if entity_id == EntityId::DeclaredBot {
            if let Ok(mut reg) = registry.write() {
                reg.record_match(&fp.user_agent);
            }
        }
        self.ingest_classified(fp, entity_id);
    }

    /// Ingest a request fingerprint with a pre-computed entity classification.
    fn ingest_classified(&mut self, fp: &RequestFingerprint, entity_id: EntityId) {
        let accum = self.entities.entry(entity_id).or_insert_with(EntityAccum::new);

        accum.ip_hashes.insert(crate::dashboard_profile::hash_ip(&fp.ip));
        accum.subnets.insert(fp.subnet());
        accum.uas.insert(fp.user_agent.clone());
        accum.timestamps.push(fp.timestamp);
        accum.total += 1;
        accum.first_ts = accum.first_ts.min(fp.timestamp);
        accum.last_ts = accum.last_ts.max(fp.timestamp);

        let cv = fp.chrome_major();
        if cv > 0 {
            *accum.chrome_versions.entry(cv).or_insert(0) += 1;
        }
        *accum.ua_os.entry(fp.ua_os().to_string()).or_insert(0) += 1;
        *accum.path_ops.entry(fp.path_op()).or_insert(0) += 1;

        if let Some(repo) = fp.repo_name() {
            *accum.repos.entry(repo.clone()).or_insert(0) += 1;
            *accum.ip_repos
                .entry(crate::dashboard_profile::hash_ip(&fp.ip))
                .or_default()
                .entry(repo)
                .or_insert(0) += 1;
        }

        if !fp.accept_encoding.is_empty() {
            accum.accept_enc.insert(fp.accept_encoding.clone());
        }
        if !fp.accept_language.is_empty() {
            accum.accept_lang.insert(fp.accept_language.clone());
        } else {
            accum.accept_lang.insert("(empty)".to_string());
        }
        if !fp.accept.is_empty() {
            accum.accept.insert(fp.accept.clone());
        }

        if fp.has_sec_fetch_mode { accum.sec_fetch_present += 1; }
        else { accum.sec_fetch_absent += 1; }
        if fp.has_sec_ch_ua { accum.sec_ch_ua_present += 1; }
        else { accum.sec_ch_ua_absent += 1; }
        if fp.has_connection { accum.conn_present += 1; }
        else { accum.conn_absent += 1; }

        // Wave 166f epitope collection
        if !fp.sec_fetch_triplet.is_empty() {
            *accum.sec_fetch_triplets.entry(fp.sec_fetch_triplet.clone()).or_insert(0) += 1;
        }
        if fp.has_cookie { accum.cookie_present += 1; }
        else { accum.cookie_absent += 1; }
        if fp.referer.is_empty() {
            accum.referer_absent += 1;
        } else if fp.referer.contains("google") || fp.referer.contains("bing")
                || fp.referer.contains("duckduckgo") {
            accum.referer_external += 1;
        } else if !fp.referer.contains(&fp.host) {
            accum.referer_external += 1;
        }

        // Wave 171: Per-surface host tracking
        if !fp.host.is_empty() {
            *accum.hosts.entry(fp.host.clone()).or_insert(0) += 1;
        }
    }

    /// Build the final topology — sorted by request count descending.
    /// Consumes the builder.
    pub fn build(self) -> Vec<EntityProfile> {
        let mut profiles: Vec<EntityProfile> = self.entities
            .into_iter()
            .map(|(entity_id, accum)| build_profile(entity_id, accum))
            .collect();
        profiles.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
        profiles
    }

    /// Total ingested requests across all entities.
    pub fn total_requests(&self) -> u64 {
        self.entities.values().map(|a| a.total).sum()
    }

    /// Extract UA sets from entities that would score high fleet_confidence.
    /// Used by the epitope registry to discover novel bot UA tokens.
    pub fn high_confidence_uas(&self) -> Vec<(EntityId, HashSet<String>)> {
        self.entities
            .iter()
            .filter(|(_, accum)| {
                // Quick pre-filter: needs enough data for meaningful epitope scoring
                accum.total > 50 && accum.ip_hashes.len() > 1
            })
            .filter_map(|(entity_id, accum)| {
                // Build a lightweight fleet_confidence estimate without the full profile
                let mut epitope_count = 0u32;
                let mut epitope_triggered = 0u32;

                // sec_fetch_monotone
                if !accum.sec_fetch_triplets.is_empty() && accum.total > 10 {
                    let top = accum.sec_fetch_triplets.values().max().copied().unwrap_or(0);
                    let pct = top as f64 / accum.total as f64 * 100.0;
                    epitope_count += 1;
                    if pct > 95.0 { epitope_triggered += 1; }
                }
                // session_absent
                if accum.total > 20 {
                    let pct = accum.cookie_present as f64 / accum.total as f64 * 100.0;
                    epitope_count += 1;
                    if pct < 5.0 { epitope_triggered += 1; }
                }
                // referer_self_loop
                if accum.total > 20 {
                    let pct = accum.referer_external as f64 / accum.total as f64 * 100.0;
                    epitope_count += 1;
                    if pct < 2.0 { epitope_triggered += 1; }
                }

                let confidence = if epitope_count > 0 {
                    epitope_triggered as f64 / epitope_count as f64 * 100.0
                } else {
                    0.0
                };

                if confidence > 80.0 {
                    Some((entity_id.clone(), accum.uas.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of distinct entity types seen.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Borrow the raw entity accumulators for campfire analysis.
    ///
    /// Returns references to the live data — no cloning.
    /// Used by campfire_writer to generate visitor/page/campfire JSON
    /// from the same data that feeds the topology.
    pub fn entity_accums(&self) -> Vec<(EntityId, &EntityAccum)> {
        self.entities.iter()
            .map(|(id, accum)| (id.clone(), accum))
            .collect()
    }

    /// Take a snapshot without consuming the builder — clones internal
    /// state so accumulation continues uninterrupted.
    pub fn snapshot(&self) -> Vec<EntityProfile> {
        let mut profiles: Vec<EntityProfile> = self.entities
            .iter()
            .map(|(entity_id, accum)| build_profile(entity_id.clone(), accum.clone()))
            .collect();
        profiles.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
        profiles
    }
}

/// Accumulates entity fingerprints and periodically writes `topology.json`.
///
/// Replaces `entity_topology.py` (534 lines) which re-parsed ALL Caddy logs
/// from scratch every ~30 seconds. This module classifies live from the
/// bloom sensor stream and writes the same JSON output.
///
/// ## Convergence
///
/// entity_topology.py → skunky-ingest entity_classifier:
/// - Classification engine → [`classify`] + [`TopologyBuilder`] (this module)
/// - Sub-system detection → [`build_profile`] (entity_profile)
/// - Epitope scoring → [`EpitopeScores`] (entity_profile)
/// - JSON output → [`TopologyWriter`] (this struct)
///
/// No more re-parsing. Topology is a side output of the existing pipeline.
pub struct TopologyWriter {
    builder: TopologyBuilder,
    output_path: PathBuf,
    /// Persistent state file — sourdough culture.
    state_path: PathBuf,
    /// How many ingest calls between flushes.
    flush_interval: u64,
    ingest_count: u64,
    /// Save culture every N flushes (don't write state on every topology flush).
    culture_save_counter: u32,
    /// Shared epitope registry — culture-fed bot detection.
    registry: crate::epitope_registry::SharedRegistry,
    /// Rolling history of epitope sort snapshots (WAS/IS time-series).
    history: Vec<EpitopeSortSnapshot>,
    /// Path to write the rolling epitope-history.json.
    history_path: PathBuf,
    /// Latest conservation result (Experiment 4, Paper 74).
    /// Wired into NullDimension via EpitopeFlipData.
    last_conservation: Option<crate::epitope_conservation::ConservationResult>,
}

impl TopologyWriter {
    /// Create a new topology writer with persistent culture.
    ///
    /// * `output_path` — where to write `topology.json`
    /// * `state_path` — where to persist the sourdough culture
    /// * `flush_interval` — write after this many ingested entries
    pub fn new(
        output_path: PathBuf,
        state_path: PathBuf,
        flush_interval: u64,
        registry: crate::epitope_registry::SharedRegistry,
    ) -> Self {
        let history_path = output_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("epitope-history.json");

        // Warm-start history from disk if it exists
        let history = match std::fs::read_to_string(&history_path) {
            Ok(json) => serde_json::from_str::<Vec<EpitopeSortSnapshot>>(&json)
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        let builder = TopologyBuilder::load(&state_path);
        let state = Self {
            builder,
            output_path,
            state_path,
            flush_interval,
            ingest_count: 0,
            culture_save_counter: 0,
            registry,
            history,
            history_path,
            last_conservation: None,
        };
        tracing::info!(
            output = %state.output_path.display(),
            culture = %state.state_path.display(),
            history = %state.history_path.display(),
            history_snapshots = state.history.len(),
            interval = state.flush_interval,
            "🗺️ topology writer loaded"
        );
        state
    }

    /// Ingest a parsed caddy log entry — uses the shared epitope registry
    /// for culture-derived bot detection.
    pub fn ingest(&mut self, entry: &caddy::LogEntry) {
        let fp = RequestFingerprint::from_caddy_entry(entry);
        self.builder.ingest_with_registry(&fp, &self.registry);
        self.ingest_count += 1;

        if self.ingest_count % self.flush_interval == 0 {
            self.flush();
        }
    }

    /// Get epitope flip data for NullDimension VDJ classification.
    ///
    /// Multi-scale: uses the LONGEST available timescale from history, not
    /// just the 30-second inter-flush delta. A mature system has conservation=1.0
    /// at short timescales (all epitopes are J). But over hours/days, entities
    /// appear, disappear, and shift — revealing which epitopes are truly Variable
    /// vs Diversity vs Joining.
    ///
    /// Falls back to short-scale conservation if history is too shallow.
    pub fn epitope_flip_data(&self) -> Option<crate::sort_compression::EpitopeFlipData> {
        // Try long-scale first (evolutionary timescale)
        if let Some(long) = self.long_scale_flip_data() {
            return Some(long);
        }
        // Fall back to short-scale (30-second conservation)
        self.short_scale_flip_data()
    }

    /// Short-scale flip data: consecutive level-0 snapshots (~30s).
    /// Used for compass stability (Experiment 4) and as fallback.
    fn short_scale_flip_data(&self) -> Option<crate::sort_compression::EpitopeFlipData> {
        let result = self.last_conservation.as_ref()?;
        let mut flipped = [0usize; 6];
        let mut evaluated = [0usize; 6];
        for entity in &result.entities {
            for i in 0..6 {
                let t0_eval = entity.sort_key_t0[i] != 0x00;
                let t1_eval = entity.sort_key_t1[i] != 0x00;
                if t0_eval && t1_eval {
                    evaluated[i] += 1;
                    let bit = (entity.flipped_mask >> i) & 1;
                    if bit == 1 { flipped[i] += 1; }
                }
            }
        }
        Some(crate::sort_compression::EpitopeFlipData {
            flipped,
            evaluated,
            matched: result.matched_entities,
        })
    }

    /// Long-scale flip data: compare oldest and newest snapshots.
    ///
    /// At evolutionary timescale, entities that appeared recently won't match
    /// the oldest snapshot (they're D — diversity). Entities that changed
    /// their sort key over hours are V (variable). Entities present in both
    /// with same sort key are J (joining/conserved).
    ///
    /// Requires at least 10 snapshots (≥ ~5 minutes of history).
    fn long_scale_flip_data(&self) -> Option<crate::sort_compression::EpitopeFlipData> {
        if self.history.len() < 10 {
            return None;
        }

        let oldest = self.history.first()?;
        let newest = self.history.last()?;

        // Need meaningful time separation (at least 2 minutes)
        let gap = newest.ts.saturating_sub(oldest.ts);
        if gap < 120 {
            return None;
        }

        let result = crate::epitope_conservation::epitope_conservation(oldest, newest);

        // Count entities in newest but NOT in oldest — these are "new arrivals"
        // and represent Diversity (not yet fully observed at evolutionary timescale)
        let oldest_entities: std::collections::HashSet<&str> = oldest.entities
            .iter()
            .map(|e| e.entity.as_str())
            .collect();
        let new_arrivals = newest.entities.iter()
            .filter(|e| !oldest_entities.contains(e.entity.as_str()))
            .count();

        let mut flipped = [0usize; 6];
        let mut evaluated = [0usize; 6];

        // Matched entities: compare their long-scale evolution
        for entity in &result.entities {
            for i in 0..6 {
                let t0_eval = entity.sort_key_t0[i] != 0x00;
                let t1_eval = entity.sort_key_t1[i] != 0x00;
                if t0_eval && t1_eval {
                    evaluated[i] += 1;
                    let bit = (entity.flipped_mask >> i) & 1;
                    if bit == 1 { flipped[i] += 1; }
                }
            }
        }

        // New arrivals contribute to the "not evaluated" pool — they lower
        // eval_rate for epitopes, pushing those epitopes toward D (Diversity).
        // This is correct: an epitope that new entities don't have data for
        // IS diversity — it's potential not yet expressed.
        let total_matched = result.matched_entities + new_arrivals;

        if total_matched == 0 {
            return None;
        }

        tracing::debug!(
            gap_secs = gap,
            matched = result.matched_entities,
            new_arrivals = new_arrivals,
            mean_hamming = format!("{:.3}", result.mean_hamming).as_str(),
            "🧬 long-scale VDJ conservation (evolutionary timescale)"
        );

        Some(crate::sort_compression::EpitopeFlipData {
            flipped,
            evaluated,
            matched: total_matched,
        })
    }

    /// Force a topology snapshot and write to disk.
    pub fn flush(&mut self) {
        let profiles = self.builder.snapshot();
        if profiles.is_empty() {
            return;
        }

        // Culture-fed epitope learning: extract bot UA tokens from entities
        // with high fleet_confidence and feed them to the registry.
        self.feed_registry(&profiles);

        let comparative = build_comparative(&profiles);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let topology = EntityTopology {
            generated_epoch: now,
            generated_iso: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            log_entries_analyzed: self.builder.total_requests(),
            entities: profiles,
            comparative_fingerprints: comparative,
        };

        match serde_json::to_string_pretty(&topology) {
            Ok(json) => {
                if let Some(parent) = self.output_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&self.output_path, &json) {
                    Ok(()) => {
                        tracing::info!(
                            entities = topology.entities.len(),
                            requests = topology.log_entries_analyzed,
                            bytes = json.len(),
                            "🗺️ topology.json updated"
                        );

                        // ── Falsification experiments (Paper 69) ──
                        // Run coprimality and sensitivity analyses on every flush.
                        self.run_falsification_experiments(&topology.entities);

                        // Campfire pipeline — write visitor/page/campfire JSON
                        // from the same entity data, in the same cycle.
                        // Replaces three Python cron scripts (807 lines).
                        let campfire_config = crate::campfire_writer::CampfireWriterConfig::golgi_default();
                        let accums = self.builder.entity_accums();
                        if let Err(e) = crate::campfire_writer::write_all(&campfire_config, &accums) {
                            tracing::warn!(error = %e, "🔥 campfire write failed");
                        } else {
                            tracing::debug!("🔥 campfire JSON updated");
                        }

                        // Symbiosis — tit-for-tat-forgive-one (Wave 180)
                        // Write symbiosis.json alongside topology.json
                        let symbiosis = crate::symbiosis::build_symbiosis(&topology.entities);
                        let sym_path = self.output_path.parent()
                            .unwrap_or(std::path::Path::new("."))
                            .join("symbiosis.json");
                        match serde_json::to_string_pretty(&symbiosis) {
                            Ok(json) => {
                                if let Err(e) = std::fs::write(&sym_path, &json) {
                                    tracing::warn!(error = %e, "symbiosis.json write failed");
                                } else {
                                    tracing::info!(
                                        mutualists = symbiosis.summary.mutualists,
                                        commensal = symbiosis.summary.commensal_active,
                                        parasites = symbiosis.summary.parasites,
                                        pathogens = symbiosis.summary.pathogens,
                                        "🤝 symbiosis.json updated — tit-for-tat-forgive-one"
                                    );
                                }
                            }
                            Err(e) => tracing::warn!(error = %e, "symbiosis serialization failed"),
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %self.output_path.display(),
                            "topology.json write failed"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "topology serialization failed");
            }
        }

        // ── Epitope sort history (Wave 171) ──
        // Build a compact snapshot and append to the rolling buffer.
        self.append_history_snapshot(&topology);

        // Save the sourdough culture every 10 topology flushes (~5000 entries).
        // Always save on explicit flush (shutdown path).
        self.culture_save_counter += 1;
        if self.culture_save_counter % 10 == 0 || self.culture_save_counter == 1 {
            self.save_culture();
        }
    }

    /// Run Paper 69 falsification experiments on the current entity population.
    ///
    /// Experiments 1 (coprimality) and 2 (epitope sensitivity) are cheap enough
    /// to run every flush cycle. Results are logged at info level.
    fn run_falsification_experiments(&self, profiles: &[EntityProfile]) {
        use crate::coprimality;
        use crate::epitope_sensitivity;

        // Experiment 1: coprimality
        let coprim = coprimality::epitope_coprimality(profiles, 3);
        tracing::info!(
            total_pairs = coprim.total_pairs,
            qualifying_pairs = coprim.qualifying_pairs,
            zero_shared_frac = format!("{:.4}", coprim.zero_shared_frac).as_str(),
            prediction = format!("{:.4}", coprim.prediction).as_str(),
            delta = format!("{:.4}", coprim.delta).as_str(),
            survives = coprim.claim_survives,
            "📐 Exp1 coprimality (Claim F: 6/π²)"
        );

        // Experiment 2: sensitivity
        let sens = epitope_sensitivity::epitope_sensitivity(profiles);
        tracing::info!(
            ks_5 = format!("{:.4}", sens.ks_5).as_str(),
            ks_6 = format!("{:.4}", sens.ks_6).as_str(),
            ks_7 = format!("{:.4}", sens.ks_7).as_str(),
            six_is_best = sens.six_is_best,
            survives = sens.claim_survives,
            "📐 Exp2 sensitivity (Claim B: T(6)=21)"
        );

        // Write experiment results alongside topology.json
        if let Some(parent) = self.output_path.parent() {
            let exp_path = parent.join("falsification.json");
            let data = serde_json::json!({
                "experiment_1_coprimality": coprim,
                "experiment_2_sensitivity": sens,
            });
            if let Ok(json) = serde_json::to_string_pretty(&data) {
                if let Err(e) = std::fs::write(&exp_path, &json) {
                    tracing::warn!(error = %e, "falsification.json write failed");
                }
            }
        }

        // ── Membrane geometry (Paper 75) ──
        // The membrane IS its own frame. 6 epitope axes → 19 hex positions.
        self.write_membrane_geometry(profiles);
    }

    /// Compute and write membrane geometry — parallelogram lattice from epitope sort.
    fn write_membrane_geometry(&self, profiles: &[EntityProfile]) {
        use crate::membrane_geometry;

        let entity_data: Vec<(String, u8)> = profiles
            .iter()
            .map(|p| (p.label.clone(), membrane_geometry::trigger_bits(p)))
            .collect();
        let geom = membrane_geometry::compute_membrane_geometry(&entity_data);

        tracing::info!(
            entities = geom.total_entities,
            occupied = geom.occupied,
            null_spaces = geom.null_spaces,
            null_ratio = format!("{:.3}", geom.null_ratio).as_str(),
            "🔬 membrane geometry ({} positions, {} shells)",
            geom.positions,
            geom.shells.len()
        );

        if let Some(parent) = self.output_path.parent() {
            let geom_path = parent.join("membrane.json");
            if let Ok(json) = serde_json::to_string_pretty(&geom) {
                if let Err(e) = std::fs::write(&geom_path, &json) {
                    tracing::warn!(error = %e, "membrane.json write failed");
                }
            }
        }
    }

    /// Build and append an epitope sort snapshot to the rolling history buffer,
    /// then write `epitope-history.json` to disk.
    ///
    /// Computes per-surface momentum using Paper 46 complex permeability:
    ///   P_local(E, S) = reqs(E,S) / total_reqs(S)
    ///   P_null(E) = reqs(E) / total_reqs
    ///   distance(E, S) = |P_local - P_null|
    ///   |Im(P)|(E) = sqrt(sum_S distance^2)
    ///   d_eff(E) = count of surfaces where reqs > 0
    ///   focal_distance(E) = 1/pi^(d_eff/2) (Paper 53)
    fn append_history_snapshot(&mut self, topology: &EntityTopology) {
        use crate::entity_sort::SurfaceMomentum;

        let total_reqs = topology.log_entries_analyzed as f64;

        // Phase 1: Collect per-surface totals across ALL entities.
        let mut surface_totals: HashMap<String, u64> = HashMap::new();
        for profile in &topology.entities {
            for (host, count) in &profile.hosts {
                *surface_totals.entry(host.clone()).or_insert(0) += count;
            }
        }

        // Phase 2: Build entries with per-surface momentum.
        let mut entries: Vec<_> = topology.entities
            .iter()
            .map(|p| {
                let mut entry = p.sort_entry();
                let p_null = if total_reqs > 0.0 {
                    p.total_requests as f32 / total_reqs as f32
                } else {
                    0.0
                };

                let mut surfaces = Vec::new();
                let mut im_p_sum = 0.0f64;
                let mut d_eff_count = 0u32;

                for (host, &reqs) in &p.hosts {
                    if reqs == 0 { continue; }
                    d_eff_count += 1;
                    let surface_total = *surface_totals.get(host).unwrap_or(&1);
                    let p_local = reqs as f32 / surface_total as f32;
                    let distance = (p_local - p_null).abs();
                    im_p_sum += (distance as f64) * (distance as f64);

                    surfaces.push(SurfaceMomentum {
                        surface: host.clone(),
                        reqs,
                        p_local,
                        p_null,
                        distance,
                    });
                }

                // Sort surfaces by request count descending
                surfaces.sort_by(|a, b| b.reqs.cmp(&a.reqs));

                let d_eff = d_eff_count as f32;
                let focal_distance = if d_eff > 0.0 {
                    1.0 / std::f32::consts::PI.powf(d_eff / 2.0)
                } else {
                    0.0
                };
                let im_p = im_p_sum.sqrt() as f32;

                entry.surfaces = surfaces;
                entry.d_eff = d_eff;
                entry.focal_distance = focal_distance;
                entry.im_p = im_p;
                entry
            })
            .collect();

        // Sort by fleet_confidence ascending (most alive first)
        entries.sort_by(|a, b| a.fc.partial_cmp(&b.fc).unwrap_or(std::cmp::Ordering::Equal));

        let non_self_in_range = topology.entities
            .iter()
            .filter(|e| e.vitality > 0.1)
            .count() as u16;

        let snapshot = EpitopeSortSnapshot {
            ts: topology.generated_epoch,
            iso: topology.generated_iso.clone(),
            total_requests: topology.log_entries_analyzed,
            entity_count: topology.entities.len() as u16,
            non_self_in_range,
            entities: entries,
            coil: 0,
            span_secs: 30,
        };

        self.history.push(snapshot);

        // ── Experiment 4: Epitope conservation (Paper 74) ──
        // Compare the last two raw snapshots BEFORE coiling compresses them.
        if self.history.len() >= 2 {
            let older = &self.history[self.history.len() - 2];
            let newer = &self.history[self.history.len() - 1];
            if older.coil == 0 && newer.coil == 0 {
                let result = crate::epitope_conservation::epitope_conservation(older, newer);
                tracing::info!(
                    matched = result.matched_entities,
                    mean_hamming = format!("{:.3}", result.mean_hamming).as_str(),
                    conservation = format!("{:.3}", result.conservation_ratio).as_str(),
                    stable = result.compass_stable,
                    gap_secs = result.gap_secs,
                    "🧭 Exp4 conservation (Paper 74: compass stability)"
                );
                self.last_conservation = Some(result);
            }
        }

        // ── Coil the genome ──
        // History doesn't roll — it coils and compresses.
        // Recent = euchromatin (full resolution). Old = heterochromatin (compressed).
        self.coil_history();

        // Write to disk
        match serde_json::to_string(&self.history) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.history_path, &json) {
                    tracing::warn!(
                        error = %e,
                        path = %self.history_path.display(),
                        "epitope-history.json write failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "epitope history serialization failed");
            }
        }
    }

    /// Coil the history genome — compress old snapshots instead of discarding them.
    ///
    /// Like chromatin packing: nucleosome (coil=0) → fiber (coil=1) → loop (coil=2) → chromosome.
    /// Recent history stays at full resolution (euchromatin). Older history coils tighter.
    /// Nothing is ever deleted — only compressed.
    fn coil_history(&mut self) {
        if self.history.len() <= MAX_HISTORY_SNAPSHOTS {
            return;
        }

        // Find the oldest pair of snapshots at the same coil level and merge them.
        // This naturally creates logarithmic time compression:
        //   Recent: coil=0 (every ~30s, full detail)
        //   Older:  coil=1 (every ~1min, two merged)
        //   Old:    coil=2 (every ~2min, four merged)
        //   Ancient:coil=3+ (every ~4min+, deeply compressed)

        // Count raw (coil=0) snapshots
        let raw_count = self.history.iter().filter(|s| s.coil == 0).count();

        if raw_count > EUCHROMATIN_WINDOW {
            // Find the first pair of adjacent snapshots at the lowest coil level
            // that are NOT in the euchromatin window (recent raw snapshots).
            // Coil from the oldest end — compress the deepest past first.
            let mut coiled = false;
            for level in 0u8..16 {
                // Find the two oldest adjacent snapshots at this level
                let mut first_idx = None;
                let mut second_idx = None;
                for (i, snap) in self.history.iter().enumerate() {
                    if snap.coil == level {
                        if first_idx.is_none() {
                            first_idx = Some(i);
                        } else if second_idx.is_none() {
                            second_idx = Some(i);
                            break;
                        }
                    }
                }

                if let (Some(a), Some(b)) = (first_idx, second_idx) {
                    // Don't coil if both are in the euchromatin window
                    // (recent raw snapshots should stay full-resolution)
                    if level == 0 {
                        let raw_after_b = self.history[b..].iter().filter(|s| s.coil == 0).count();
                        if raw_after_b > EUCHROMATIN_WINDOW - 2 {
                            // These are old enough to coil
                        } else {
                            continue; // too recent, try next level
                        }
                    }

                    let merged = EpitopeSortSnapshot::coil_pair(
                        &self.history[a],
                        &self.history[b],
                    );

                    // Remove both, insert merged at the earlier position
                    self.history.remove(b);
                    self.history.remove(a);
                    self.history.insert(a, merged);
                    coiled = true;
                    break;
                }
            }

            // Safety: if nothing was coiled but we're over budget, remove the very oldest
            if !coiled && self.history.len() > MAX_HISTORY_SNAPSHOTS {
                self.history.remove(0);
            }
        } else if self.history.len() > MAX_HISTORY_SNAPSHOTS {
            // Not enough raw snapshots to coil from — compress oldest non-raw pair
            for level in 0u8..16 {
                let positions: Vec<usize> = self.history.iter().enumerate()
                    .filter(|(_, s)| s.coil == level)
                    .map(|(i, _)| i)
                    .take(2)
                    .collect();
                if positions.len() == 2 {
                    let merged = EpitopeSortSnapshot::coil_pair(
                        &self.history[positions[0]],
                        &self.history[positions[1]],
                    );
                    self.history.remove(positions[1]);
                    self.history.remove(positions[0]);
                    self.history.insert(positions[0], merged);
                    break;
                }
            }
        }
    }

    /// Feed the epitope registry with novel bot UA tokens from high-confidence
    /// fleet entities. This is the unsupervised learning loop — the culture
    /// teaches the registry which UA patterns correlate with fleet behavior.
    fn feed_registry(&self, _profiles: &[EntityProfile]) {
        let high_conf = self.builder.high_confidence_uas();
        if high_conf.is_empty() {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut total_new = 0u32;
        if let Ok(mut registry) = self.registry.write() {
            for (_entity_id, uas) in &high_conf {
                let tokens = crate::epitope_registry::extract_bot_tokens(uas);
                for token in tokens {
                    // Only feed tokens that aren't already seed tokens at full confidence
                    if !registry.is_declared_bot(&token) {
                        registry.observe_token(token, 0.85, now);
                        total_new += 1;
                    }
                }
            }
            if total_new > 0 {
                registry.advance_generation();
                tracing::info!(
                    novel_tokens = total_new,
                    entities = high_conf.len(),
                    generation = registry.generation(),
                    "🧬 epitope registry fed from topology culture"
                );
            }
        }
    }

    /// Delegate entity count from inner builder.
    pub fn entity_count(&self) -> usize {
        self.builder.entity_count()
    }

    /// Persist the sourdough culture to disk — survives reboots.
    pub fn save_culture(&self) {
        self.builder.save(&self.state_path);
        tracing::info!(
            entities = self.builder.entity_count(),
            requests = self.builder.total_requests(),
            path = %self.state_path.display(),
            "🧬 topology culture saved"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_classifier::*;

    #[test]
    fn topology_builder_basics() {
        let mut builder = TopologyBuilder::new();
        for i in 0..10 {
            let fp = RequestFingerprint {
                ip: format!("203.0.113.{}", i),
                user_agent: "ClaudeBot/1.0".into(),
                host: "git.primals.eco".into(),
                uri: "/ecoPrimals/ecoPrimals/src/main/README.md".into(),
                accept: "*/*".into(),
                accept_encoding: "gzip, br, zstd, deflate".into(),
                accept_language: String::new(),
                has_sec_fetch_mode: false,
                has_sec_ch_ua: false,
                has_connection: false,
                has_cookie: false,
                timestamp: i as f64,
                status: 200,
                sec_fetch_triplet: String::new(),
                referer: String::new(),
            };
            builder.ingest(&fp);
        }

        assert_eq!(builder.total_requests(), 10);
        assert_eq!(builder.entity_count(), 1);

        let snapshot = builder.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].entity, EntityId::AnthropicClaudeBot);
        assert_eq!(snapshot[0].total_requests, 10);
        assert_eq!(snapshot[0].unique_ips, 10);

        // Builder still works after snapshot
        assert_eq!(builder.total_requests(), 10);
    }

    #[test]
    fn topology_writer_creates_output() {
        let dir = std::env::temp_dir().join("topology-writer-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("topology.json");
        let state = dir.join("topology-state.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = TopologyWriter::new(output.clone(), state.clone(), 5, registry.clone());
        for i in 0..5 {
            let entry = caddy::LogEntry {
                request: caddy::RequestInfo {
                    remote_ip: format!("10.0.0.{}", i),
                    host: "git.primals.eco".into(),
                    uri: "/ecoPrimals/ecoPrimals".into(),
                    method: "GET".into(),
                    headers: caddy::Headers {
                        user_agent: vec!["ClaudeBot/1.0".into()],
                        ..Default::default()
                    },
                },
                status: 200,
                size: 1000,
                duration: 0.01,
                ts: i as f64,
            };
            writer.ingest(&entry);
        }

        assert!(output.exists(), "topology.json should have been created");
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("Anthropic (ClaudeBot)"));
        assert!(content.contains("log_entries_analyzed"));

        // Culture should have been saved on first flush
        assert!(state.exists(), "topology state file should exist");

        // Simulate restart — new writer loads the culture
        let mut writer2 = TopologyWriter::new(output.clone(), state.clone(), 5, registry);
        // Should have warm state from previous generation
        writer2.flush();
        let content2 = std::fs::read_to_string(&output).unwrap();
        assert!(content2.contains("Anthropic (ClaudeBot)"), "sourdough culture should survive restart");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
