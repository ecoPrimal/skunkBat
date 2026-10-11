// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Entity sort output — topology, snapshots, and comparative tables.
//!
//! Extracted from `entity_profile.rs` — the profiling engine stays,
//! the sort output structures live here.
//!
//! Split is π: ~990 lines (profiling) : ~320 lines (sort output).
//!
//! Contains:
//! - [`EntityTopology`] — full topology output (the map)
//! - [`SurfaceMomentum`] — per-surface permeability (Paper 46)
//! - [`EntitySortEntry`] — compact per-entity state for history
//! - [`EpitopeSortSnapshot`] — one moment's view of the sort
//! - [`ComparativeRow`] + [`build_comparative`] — fingerprint table
//! - [`EntityProfile::sort_entry`] — profile → sort entry projection

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::entity_profile::{EntityProfile, EpitopeResult};

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

#[cfg(test)]
mod tests {
    use super::*;

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
            reqs: 1000, ips: 500, fc: 100.0, vit: 0.0, neg: 8.3,
            sort_key: [2, 2, 2, 2, 2, 2], compression: 21,
            triggered: 7, evaluated: 7, surfaces: vec![],
            d_eff: 0.0, focal_distance: 0.0, im_p: 0.0,
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
        assert_eq!(coiled.coil, 1);
        assert_eq!(coiled.span_secs, 60);
        assert_eq!(coiled.ts, 1030);
        assert_eq!(coiled.non_self_in_range, 3);
        assert_eq!(coiled.entities.len(), 3);
        let alpha = coiled.entities.iter().find(|e| e.entity == "alpha").unwrap();
        assert_eq!(alpha.reqs, 350);
    }
}
