// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Epitope conservation across consecutive topology flushes.
//!
//! Paper 74 (Falsification Experiment 4): is the epitope compass stable?
//! If epitopes are conserved between flushes, the sort has temporal
//! structure and prediction works. If they flip randomly, the compass
//! is broken.
//!
//! Method: for each entity present in both snapshot t and t+1,
//! compute the Hamming distance of their 6-bit trigger vectors.
//! Conservation ratio = 1 - (mean_hamming / 6).

use serde::Serialize;

use crate::entity_sort::EpitopeSortSnapshot;

/// Per-entity conservation record.
#[derive(Debug, Clone, Serialize)]
pub struct EntityConservation {
    pub entity: String,
    pub triggered_t0: u8,
    pub triggered_t1: u8,
    pub sort_key_t0: [u8; 6],
    pub sort_key_t1: [u8; 6],
    pub hamming: u8,
    /// Which epitopes flipped (bitmask of changed positions in sort_key).
    pub flipped_mask: u8,
}

/// Result of the conservation analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ConservationResult {
    /// Timestamp of the older snapshot.
    pub ts_t0: u64,
    /// Timestamp of the newer snapshot.
    pub ts_t1: u64,
    /// Time gap in seconds.
    pub gap_secs: u64,
    /// Entities present in both snapshots.
    pub matched_entities: usize,
    /// Total entities in t0.
    pub entities_t0: usize,
    /// Total entities in t1.
    pub entities_t1: usize,
    /// Mean Hamming distance across matched entities.
    pub mean_hamming: f64,
    /// Conservation ratio = 1 - (mean_hamming / 6).
    pub conservation_ratio: f64,
    /// Per-entity details.
    pub entities: Vec<EntityConservation>,
    /// Histogram: how many entities had hamming distance 0, 1, ..., 6.
    pub hamming_distribution: [u64; 7],
    /// Whether the compass is stable enough for prediction.
    pub compass_stable: bool,
}

/// Compute the Hamming distance between two 6-byte sort keys.
///
/// Each byte in the sort key encodes: 0x00 = not evaluated, 0x01 = not triggered,
/// 0x02 = triggered. We count positions where the triggered/not-triggered status
/// changed (ignoring transitions involving not-evaluated).
fn sort_key_hamming(a: &[u8; 6], b: &[u8; 6]) -> (u8, u8) {
    let mut hamming: u8 = 0;
    let mut mask: u8 = 0;

    for i in 0..6 {
        // Only count changes between triggered (0x02) and not-triggered (0x01)
        // Skip if either is not-evaluated (0x00)
        if a[i] != 0x00 && b[i] != 0x00 && a[i] != b[i] {
            hamming += 1;
            mask |= 1 << i;
        }
    }

    (hamming, mask)
}

/// Compare two consecutive snapshots and measure epitope conservation.
pub fn epitope_conservation(
    older: &EpitopeSortSnapshot,
    newer: &EpitopeSortSnapshot,
) -> ConservationResult {
    // Build lookup from entity name to sort entry in the older snapshot
    let older_map: std::collections::HashMap<&str, &crate::entity_sort::EntitySortEntry> = older
        .entities
        .iter()
        .map(|e| (e.entity.as_str(), e))
        .collect();

    let mut entities = Vec::new();
    let mut hamming_distribution = [0u64; 7];
    let mut hamming_sum = 0u64;

    for new_entry in &newer.entities {
        if let Some(old_entry) = older_map.get(new_entry.entity.as_str()) {
            let (hamming, mask) = sort_key_hamming(&old_entry.sort_key, &new_entry.sort_key);

            hamming_distribution[hamming as usize] += 1;
            hamming_sum += hamming as u64;

            entities.push(EntityConservation {
                entity: new_entry.entity.clone(),
                triggered_t0: old_entry.triggered,
                triggered_t1: new_entry.triggered,
                sort_key_t0: old_entry.sort_key,
                sort_key_t1: new_entry.sort_key,
                hamming,
                flipped_mask: mask,
            });
        }
    }

    let matched = entities.len();
    let mean_hamming = if matched > 0 {
        hamming_sum as f64 / matched as f64
    } else {
        0.0
    };
    let conservation_ratio = 1.0 - (mean_hamming / 6.0);

    let gap_secs = if newer.ts > older.ts {
        newer.ts - older.ts
    } else {
        0
    };

    ConservationResult {
        ts_t0: older.ts,
        ts_t1: newer.ts,
        gap_secs,
        matched_entities: matched,
        entities_t0: older.entities.len(),
        entities_t1: newer.entities.len(),
        mean_hamming,
        conservation_ratio,
        entities,
        hamming_distribution,
        compass_stable: conservation_ratio > 0.8,
    }
}

/// Format conservation result as a human-readable report.
pub fn format_report(result: &ConservationResult) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  EXPERIMENT 4: Epitope Conservation (Paper 74)\n");
    out.push_str("═══════════════════════════════════════════════════\n\n");

    out.push_str(&format!("  Snapshots:       t0={} → t1={} ({}s gap)\n", result.ts_t0, result.ts_t1, result.gap_secs));
    out.push_str(&format!("  Entities t0:     {}\n", result.entities_t0));
    out.push_str(&format!("  Entities t1:     {}\n", result.entities_t1));
    out.push_str(&format!("  Matched:         {}\n\n", result.matched_entities));

    out.push_str("  Hamming distance distribution:\n");
    for (i, &count) in result.hamming_distribution.iter().enumerate() {
        if count > 0 || i == 0 {
            let pct = if result.matched_entities > 0 {
                count as f64 / result.matched_entities as f64 * 100.0
            } else {
                0.0
            };
            let bar_len = (pct / 2.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            out.push_str(&format!(
                "    d={}: {:>4} entities ({:>5.1}%) {}\n",
                i, count, pct, bar
            ));
        }
    }

    out.push_str(&format!("\n  Mean Hamming:       {:.3}\n", result.mean_hamming));
    out.push_str(&format!("  Conservation ratio: {:.3}\n", result.conservation_ratio));
    out.push_str(&format!("  Random baseline:    0.500 (Hamming ≈ 3.0)\n\n"));

    if !result.entities.is_empty() {
        out.push_str("  Per-entity conservation:\n");
        for e in &result.entities {
            let status = if e.hamming == 0 {
                "conserved"
            } else {
                "mutated"
            };
            out.push_str(&format!(
                "    {:<25} d={} ({}) {}/{} → {}/{}\n",
                if e.entity.len() > 25 { &e.entity[..25] } else { &e.entity },
                e.hamming,
                status,
                e.triggered_t0,
                6,
                e.triggered_t1,
                6,
            ));
        }
    }

    out.push_str("\n");
    if result.compass_stable {
        out.push_str("  ▶ COMPASS STABLE: conservation > 0.8\n");
        out.push_str("    → Epitope sort has temporal structure. Prediction works.\n");
    } else {
        out.push_str("  ▶ COMPASS UNSTABLE: conservation ≤ 0.8\n");
        out.push_str("    → Epitope sort has weak temporal structure. Prediction unreliable.\n");
    }

    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_sort::{EntitySortEntry, EpitopeSortSnapshot};

    fn make_entry(entity: &str, sort_key: [u8; 6], triggered: u8) -> EntitySortEntry {
        EntitySortEntry {
            entity: entity.to_string(),
            reqs: 100,
            ips: 1,
            fc: 50.0,
            vit: 0.5,
            neg: 0.0,
            sort_key,
            compression: triggered as u16 * 3,
            triggered,
            evaluated: 6,
            surfaces: vec![],
            d_eff: 1.0,
            focal_distance: 0.5,
            im_p: 0.1,
        }
    }

    fn make_snapshot(ts: u64, entities: Vec<EntitySortEntry>) -> EpitopeSortSnapshot {
        let count = entities.len() as u16;
        EpitopeSortSnapshot {
            ts,
            iso: format!("2026-10-11T{:02}:00:00Z", ts % 24),
            total_requests: 1000,
            entity_count: count,
            non_self_in_range: count,
            entities,
            coil: 0,
            span_secs: 30,
        }
    }

    #[test]
    fn perfect_conservation() {
        let key = [0x02, 0x02, 0x01, 0x01, 0x02, 0x01]; // 3 triggered
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key, 3)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_a", key, 3)]);
        let result = epitope_conservation(&t0, &t1);
        assert_eq!(result.matched_entities, 1);
        assert_eq!(result.mean_hamming, 0.0);
        assert!((result.conservation_ratio - 1.0).abs() < 0.001);
        assert!(result.compass_stable);
    }

    #[test]
    fn single_flip() {
        let key_t0 = [0x02, 0x02, 0x01, 0x01, 0x02, 0x01];
        let key_t1 = [0x02, 0x01, 0x01, 0x01, 0x02, 0x01]; // reading_deficit flipped
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key_t0, 3)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_a", key_t1, 2)]);
        let result = epitope_conservation(&t0, &t1);
        assert_eq!(result.mean_hamming, 1.0);
        assert!((result.conservation_ratio - (5.0 / 6.0)).abs() < 0.01);
        assert!(result.compass_stable); // 5/6 > 0.8
    }

    #[test]
    fn total_mutation() {
        let key_t0 = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02]; // all triggered
        let key_t1 = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01]; // none triggered
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key_t0, 6)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_a", key_t1, 0)]);
        let result = epitope_conservation(&t0, &t1);
        assert_eq!(result.mean_hamming, 6.0);
        assert!((result.conservation_ratio - 0.0).abs() < 0.001);
        assert!(!result.compass_stable);
    }

    #[test]
    fn unmatched_entities_excluded() {
        let key = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key, 3)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_b", key, 3)]); // different entity
        let result = epitope_conservation(&t0, &t1);
        assert_eq!(result.matched_entities, 0);
    }

    #[test]
    fn unevaluated_ignored() {
        let key_t0 = [0x02, 0x00, 0x01, 0x01, 0x02, 0x01]; // slot 1 not evaluated
        let key_t1 = [0x02, 0x02, 0x01, 0x01, 0x02, 0x01]; // slot 1 now triggered
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key_t0, 2)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_a", key_t1, 3)]);
        let result = epitope_conservation(&t0, &t1);
        // Slot 1 was 0x00→0x02, should NOT count as a flip (was unevaluated)
        assert_eq!(result.entities[0].hamming, 0);
    }

    #[test]
    fn report_renders() {
        let key = [0x02, 0x02, 0x01, 0x01, 0x02, 0x01];
        let t0 = make_snapshot(100, vec![make_entry("fleet_a", key, 3)]);
        let t1 = make_snapshot(130, vec![make_entry("fleet_a", key, 3)]);
        let result = epitope_conservation(&t0, &t1);
        let report = format_report(&result);
        assert!(report.contains("EXPERIMENT 4"));
        assert!(report.contains("conservation"));
    }
}
