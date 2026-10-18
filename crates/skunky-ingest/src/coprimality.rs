// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Epitope coprimality — pairwise overlap statistics.
//!
//! Paper 69 (Falsification Experiment 1): do ~60.8% of entity-pairs
//! share zero triggered epitopes?
//!
//! If so, 6/π² = P(coprime) maps directly onto the immune system:
//! two random entities are "coprime" in epitope space with the same
//! probability as two random integers being coprime (Euler, 1735).

use serde::Serialize;

use crate::entity_profile::{EntityProfile, EpitopeResult};

/// Extract a 7-bit trigger vector from an entity's epitope scores.
///
/// Returns (trigger_bits, evaluated_count):
/// - trigger_bits: bit i is set if epitope i triggered
/// - evaluated_count: how many of the 7 epitopes had data (Some)
fn trigger_vector(profile: &EntityProfile) -> (u8, u8) {
    let epitopes: [&Option<EpitopeResult>; 7] = [
        &profile.epitopes.burst_ratio,
        &profile.epitopes.reading_deficit,
        &profile.epitopes.ua_pool_poverty,
        &profile.epitopes.sec_fetch_monotone,
        &profile.epitopes.session_absent,
        &profile.epitopes.referer_self_loop,
        &profile.epitopes.referer_absence,
    ];

    let mut bits: u8 = 0;
    let mut evaluated: u8 = 0;

    for (i, ep) in epitopes.iter().enumerate() {
        if let Some(result) = ep {
            evaluated += 1;
            if result.triggered {
                bits |= 1 << i;
            }
        }
    }

    (bits, evaluated)
}

/// Count the number of shared triggered epitopes between two trigger vectors.
fn shared_triggered(a: u8, b: u8) -> u8 {
    (a & b).count_ones() as u8
}

/// Result of the coprimality analysis.
#[derive(Debug, Clone, Serialize)]
pub struct CoprimResult {
    /// Total entity pairs compared.
    pub total_pairs: u64,
    /// Pairs where both entities had >= min_evaluated epitopes.
    pub qualifying_pairs: u64,
    /// Fraction of qualifying pairs sharing zero triggered epitopes.
    pub zero_shared_frac: f64,
    /// Distribution: index i = number of pairs sharing exactly i epitopes.
    pub shared_distribution: [u64; 8],
    /// Mean number of shared triggered epitopes per qualifying pair.
    pub mean_shared: f64,
    /// The theoretical prediction: 6/π² ≈ 0.6079.
    pub prediction: f64,
    /// |observed - predicted|
    pub delta: f64,
    /// Whether the observation falls within ±0.05 of prediction.
    pub claim_survives: bool,
    /// Per-entity trigger vectors (entity label, triggered count, evaluated count).
    pub entity_vectors: Vec<EntityTriggerSummary>,
}

/// Summary of one entity's trigger state.
#[derive(Debug, Clone, Serialize)]
pub struct EntityTriggerSummary {
    pub label: String,
    pub triggered: u8,
    pub evaluated: u8,
    pub trigger_bits: u8,
}

/// Compute pairwise epitope coprimality from a set of entity profiles.
///
/// Only considers pairs where both entities have at least `min_evaluated`
/// evaluated epitopes (default: 3). Entities with too few observations
/// don't have enough data for meaningful epitope evaluation.
pub fn epitope_coprimality(profiles: &[EntityProfile], min_evaluated: u8) -> CoprimResult {
    let prediction = 6.0 / (std::f64::consts::PI * std::f64::consts::PI);

    let vectors: Vec<(usize, u8, u8)> = profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let (bits, eval) = trigger_vector(p);
            (i, bits, eval)
        })
        .collect();

    let entity_vectors: Vec<EntityTriggerSummary> = vectors
        .iter()
        .map(|&(i, bits, eval)| EntityTriggerSummary {
            label: profiles[i].label.clone(),
            triggered: bits.count_ones() as u8,
            evaluated: eval,
            trigger_bits: bits,
        })
        .collect();

    let mut total_pairs: u64 = 0;
    let mut qualifying_pairs: u64 = 0;
    let mut shared_distribution = [0u64; 8];
    let mut shared_sum: u64 = 0;

    for i in 0..vectors.len() {
        for j in (i + 1)..vectors.len() {
            total_pairs += 1;
            let (_, bits_i, eval_i) = vectors[i];
            let (_, bits_j, eval_j) = vectors[j];

            if eval_i >= min_evaluated && eval_j >= min_evaluated {
                qualifying_pairs += 1;
                let shared = shared_triggered(bits_i, bits_j) as usize;
                shared_distribution[shared] += 1;
                shared_sum += shared as u64;
            }
        }
    }

    let zero_shared_frac = if qualifying_pairs > 0 {
        shared_distribution[0] as f64 / qualifying_pairs as f64
    } else {
        0.0
    };

    let mean_shared = if qualifying_pairs > 0 {
        shared_sum as f64 / qualifying_pairs as f64
    } else {
        0.0
    };

    let delta = (zero_shared_frac - prediction).abs();

    CoprimResult {
        total_pairs,
        qualifying_pairs,
        zero_shared_frac,
        shared_distribution,
        mean_shared,
        prediction,
        delta,
        claim_survives: delta < 0.05,
        entity_vectors,
    }
}

/// Format coprimality result as a human-readable report.
pub fn format_report(result: &CoprimResult) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  EXPERIMENT 1: Epitope Coprimality (Paper 69)\n");
    out.push_str("═══════════════════════════════════════════════════\n\n");

    out.push_str(&format!("  Entities:          {}\n", result.entity_vectors.len()));
    out.push_str(&format!("  Total pairs:       {}\n", result.total_pairs));
    out.push_str(&format!("  Qualifying pairs:  {} (both have ≥3 evaluated epitopes)\n\n", result.qualifying_pairs));

    out.push_str("  Per-entity trigger vectors:\n");
    for ev in &result.entity_vectors {
        let bits_str: String = (0..7)
            .map(|i| if ev.trigger_bits & (1 << i) != 0 { '█' } else if ev.evaluated > i { '░' } else { '·' })
            .collect();
        out.push_str(&format!(
            "    {:<25} [{}] {}/{} triggered\n",
            ev.label, bits_str, ev.triggered, ev.evaluated
        ));
    }

    out.push_str("\n  Shared epitope distribution:\n");
    for (i, &count) in result.shared_distribution.iter().enumerate() {
        if count > 0 || i == 0 {
            let pct = if result.qualifying_pairs > 0 {
                count as f64 / result.qualifying_pairs as f64 * 100.0
            } else {
                0.0
            };
            let bar_len = (pct / 2.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            out.push_str(&format!(
                "    {} shared: {:>4} pairs ({:>5.1}%) {}\n",
                i, count, pct, bar
            ));
        }
    }

    out.push_str(&format!("\n  Zero-shared fraction:  {:.4}\n", result.zero_shared_frac));
    out.push_str(&format!("  Prediction (6/π²):     {:.4}\n", result.prediction));
    out.push_str(&format!("  Delta:                 {:.4}\n", result.delta));
    out.push_str(&format!("  Mean shared:           {:.2}\n\n", result.mean_shared));

    if result.claim_survives {
        out.push_str("  ▶ CLAIM F SURVIVES: |observed - predicted| < 0.05\n");
    } else {
        out.push_str("  ▶ CLAIM F DIES: |observed - predicted| ≥ 0.05\n");
    }

    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_profile::{
        EpitopeResult, EpitopeScores, HeaderFingerprint, IpRotation, TimingProfile,
    };
    use crate::entity_classifier::EntityId;
    use std::collections::BTreeMap;

    fn make_result(triggered: bool) -> EpitopeResult {
        EpitopeResult {
            score: if triggered { 90.0 } else { 10.0 },
            triggered,
            vitality: 0.5,
            description: String::new(),
        }
    }

    fn make_profile(label: &str, triggers: [Option<bool>; 7]) -> EntityProfile {
        EntityProfile {
            entity: EntityId::HumanBrowser,
            label: label.to_string(),
            is_fleet: false,
            is_honest: true,
            total_requests: 100,
            unique_ips: 1,
            unique_subnets: 1,
            first_seen: 0.0,
            last_seen: 100.0,
            duration_hours: 1.0,
            avg_rps: 1.0,
            header_fingerprint: HeaderFingerprint {
                sec_fetch_pct: 0.0,
                sec_ch_ua_pct: 0.0,
                connection_pct: 0.0,
                accept_encoding_values: vec![],
                accept_language_values: vec![],
                accept_values: vec![],
            },
            chrome_versions: BTreeMap::new(),
            chrome_lag: 0,
            ua_os_distribution: BTreeMap::new(),
            ua_pool_size: 0,
            ip_rotation: IpRotation {
                strategy: "none".to_string(),
                single_request_ips_pct: 0.0,
                max_per_ip: 0,
                median_per_ip: 0.0,
                all_generalists: false,
            },
            path_ops: BTreeMap::new(),
            blame_pct: 0.0,
            top_repos: vec![],
            targets_real_only: false,
            targets_scatter_only: false,
            timing: TimingProfile {
                mean_interval_ms: 0.0,
                median_interval_ms: 0.0,
                cv: 0.0,
                classification: String::new(),
                burst_count: 0,
                pause_count: 0,
                transport_correction: 1.0,
                is_mobile: false,
            },
            sub_systems: vec![],
            vuln_probes: vec![],
            epitopes: EpitopeScores {
                burst_ratio: triggers[0].map(|t| make_result(t)),
                reading_deficit: triggers[1].map(|t| make_result(t)),
                ua_pool_poverty: triggers[2].map(|t| make_result(t)),
                sec_fetch_monotone: triggers[3].map(|t| make_result(t)),
                session_absent: triggers[4].map(|t| make_result(t)),
                referer_self_loop: triggers[5].map(|t| make_result(t)),
                referer_absence: triggers[6].map(|t| make_result(t)),
            },
            fleet_confidence: 0.0,
            vitality: 0.0,
            negentropy: 0.0,
            hosts: BTreeMap::new(),
            symbiotic_class: "commensal".to_string(),
            friction: 0.1,
            reciprocity: 1.0,
            consecutive_defections: 0,
            in_forgiveness: false,
            waste_offered: vec![],
        }
    }

    #[test]
    fn coprime_pair_shares_zero() {
        let profiles = vec![
            make_profile("fleet_a", [Some(true), Some(true), Some(true), Some(false), Some(false), Some(false), None]),
            make_profile("fleet_b", [Some(false), Some(false), Some(false), Some(true), Some(true), Some(true), None]),
        ];
        let result = epitope_coprimality(&profiles, 3);
        assert_eq!(result.qualifying_pairs, 1);
        assert_eq!(result.shared_distribution[0], 1);
        assert!((result.zero_shared_frac - 1.0).abs() < 0.001);
    }

    #[test]
    fn identical_pair_shares_all() {
        let profiles = vec![
            make_profile("fleet_a", [Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)]),
            make_profile("fleet_b", [Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)]),
        ];
        let result = epitope_coprimality(&profiles, 3);
        assert_eq!(result.qualifying_pairs, 1);
        assert_eq!(result.shared_distribution[7], 1);
        assert!((result.zero_shared_frac - 0.0).abs() < 0.001);
    }

    #[test]
    fn mixed_population() {
        let profiles = vec![
            make_profile("human", [Some(false), Some(false), Some(false), Some(false), Some(false), Some(false), None]),
            make_profile("ghost", [Some(true), Some(true), Some(false), Some(false), Some(true), Some(true), Some(true)]),
            make_profile("fleet", [Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)]),
        ];
        let result = epitope_coprimality(&profiles, 3);
        assert_eq!(result.total_pairs, 3);
        assert_eq!(result.qualifying_pairs, 3);
        // human-ghost: share 0 triggered (human has 0 triggered)
        // human-fleet: share 0 triggered (human has 0 triggered)
        // ghost-fleet: share 5 triggered (both have burst, reading, session, referer_loop, referer_absence)
        assert_eq!(result.shared_distribution[0], 2);
    }

    #[test]
    fn insufficient_data_excluded() {
        let profiles = vec![
            make_profile("sparse", [Some(true), Some(true), None, None, None, None, None]),
            make_profile("full", [Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)]),
        ];
        let result = epitope_coprimality(&profiles, 3);
        assert_eq!(result.qualifying_pairs, 0);
    }

    #[test]
    fn report_renders() {
        let profiles = vec![
            make_profile("human", [Some(false), Some(false), Some(false), Some(false), Some(false), Some(false), None]),
            make_profile("fleet", [Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)]),
        ];
        let result = epitope_coprimality(&profiles, 3);
        let report = format_report(&result);
        assert!(report.contains("EXPERIMENT 1"));
        assert!(report.contains("6/π²"));
    }
}
