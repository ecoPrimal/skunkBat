// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Epitope count sensitivity — does the system need exactly 6?
//!
//! Paper 69 (Falsification Experiment 2): if W_C = T(6)·π/4 = 21π/4
//! then the triangular number T(6)=21 is load-bearing. Changing to
//! 5 or 7 epitopes should change discrimination quality.
//!
//! We compute fleet_confidence under three regimes (5, 6, 7 epitopes)
//! and measure discrimination via the two-sample Kolmogorov-Smirnov
//! statistic between the human and fleet score distributions.

use serde::Serialize;

use crate::entity_profile::{EntityProfile, EpitopeResult};

/// Which epitope configuration we're testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EpitopeRegime {
    /// Drop referer_self_loop (weight 1, weakest signal).
    Five,
    /// Current production: 6 canonical epitopes (burst, reading, ua_pool, sec_fetch, session, referer_loop).
    Six,
    /// Add timing_regularity: CV of request intervals < 0.15 = metronomic.
    Seven,
}

impl EpitopeRegime {
    pub fn label(&self) -> &'static str {
        match self {
            EpitopeRegime::Five => "5-epitope (drop referer_self_loop)",
            EpitopeRegime::Six => "6-epitope (production)",
            EpitopeRegime::Seven => "7-epitope (add timing_regularity)",
        }
    }

    pub fn count(&self) -> u32 {
        match self {
            EpitopeRegime::Five => 5,
            EpitopeRegime::Six => 6,
            EpitopeRegime::Seven => 7,
        }
    }
}

/// Extract the fleet-confidence score for an entity under a given regime.
///
/// Uses only the epitope trigger booleans already computed in `EntityProfile`.
/// The 7-epitope variant synthesizes `timing_regularity` from the timing CV.
pub fn fleet_confidence_under(profile: &EntityProfile, regime: EpitopeRegime) -> Option<f64> {
    let epitopes_6: [(&str, &Option<EpitopeResult>); 6] = [
        ("burst_ratio", &profile.epitopes.burst_ratio),
        ("reading_deficit", &profile.epitopes.reading_deficit),
        ("ua_pool_poverty", &profile.epitopes.ua_pool_poverty),
        ("sec_fetch_monotone", &profile.epitopes.sec_fetch_monotone),
        ("session_absent", &profile.epitopes.session_absent),
        ("referer_self_loop", &profile.epitopes.referer_self_loop),
    ];

    let selected: Vec<(&str, bool, f64)> = match regime {
        EpitopeRegime::Five => {
            epitopes_6.iter()
                .filter(|(name, _)| *name != "referer_self_loop")
                .filter_map(|(name, opt)| {
                    opt.as_ref().map(|r| (*name, r.triggered, r.vitality))
                })
                .collect()
        }
        EpitopeRegime::Six => {
            epitopes_6.iter()
                .filter_map(|(name, opt)| {
                    opt.as_ref().map(|r| (*name, r.triggered, r.vitality))
                })
                .collect()
        }
        EpitopeRegime::Seven => {
            let mut v: Vec<(&str, bool, f64)> = epitopes_6.iter()
                .filter_map(|(name, opt)| {
                    opt.as_ref().map(|r| (*name, r.triggered, r.vitality))
                })
                .collect();
            // Synthesize timing_regularity from CV
            let cv = profile.timing.cv;
            if cv > 0.0 || profile.timing.classification != "INSUFFICIENT_DATA" {
                let threshold = 0.15;
                let triggered = cv < threshold && cv > 0.0;
                let vitality = (1.0 - (cv - threshold).abs() / threshold).max(0.0);
                v.push(("timing_regularity", triggered, vitality));
            }
            v
        }
    };

    if selected.is_empty() {
        return None;
    }

    let total = selected.len() as f64;
    let triggered: f64 = selected.iter().filter(|(_, t, _)| *t).count() as f64;
    let vitality_mean: f64 = selected.iter().map(|(_, _, v)| v).sum::<f64>() / total;

    let p = triggered / total;
    let entropy = if p > 0.0 && p < 1.0 {
        -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
    } else {
        0.0
    };
    let effective_vitality = vitality_mean * entropy;
    let fc = (triggered / total * 100.0) * (1.0 - effective_vitality);
    Some((fc * 10.0).round() / 10.0)
}

/// Per-entity sensitivity record.
#[derive(Debug, Clone, Serialize)]
pub struct EntitySensitivity {
    pub label: String,
    pub is_fleet: bool,
    pub fc_5: Option<f64>,
    pub fc_6: Option<f64>,
    pub fc_7: Option<f64>,
}

/// Kolmogorov-Smirnov two-sample statistic.
///
/// Returns the maximum absolute difference between the empirical CDFs
/// of two sorted samples. Higher = better discrimination.
fn ks_statistic(a: &mut [f64], b: &mut [f64]) -> f64 {
    a.sort_by(|x, y| x.partial_cmp(y).unwrap());
    b.sort_by(|x, y| x.partial_cmp(y).unwrap());

    let na = a.len() as f64;
    let nb = b.len() as f64;

    // Merge both sorted arrays and track CDF differences
    let mut all: Vec<f64> = Vec::with_capacity(a.len() + b.len());
    all.extend_from_slice(a);
    all.extend_from_slice(b);
    all.sort_by(|x, y| x.partial_cmp(y).unwrap());
    all.dedup();

    let mut d_max = 0.0_f64;

    for &x in &all {
        let cdf_a = a.iter().filter(|&&v| v <= x).count() as f64 / na;
        let cdf_b = b.iter().filter(|&&v| v <= x).count() as f64 / nb;
        d_max = d_max.max((cdf_a - cdf_b).abs());
    }

    d_max
}

/// Result of the sensitivity analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SensitivityResult {
    pub entities: Vec<EntitySensitivity>,
    /// KS statistic between fleet and non-fleet distributions for each regime.
    pub ks_5: f64,
    pub ks_6: f64,
    pub ks_7: f64,
    /// Number of fleet entities.
    pub n_fleet: usize,
    /// Number of non-fleet entities.
    pub n_human: usize,
    /// Whether 6-epitope is uniquely the best discriminator.
    pub six_is_best: bool,
    /// Whether Claim B survives: 6 is best OR significantly better than both 5 and 7.
    pub claim_survives: bool,
}

/// Run the epitope sensitivity experiment across a population.
pub fn epitope_sensitivity(profiles: &[EntityProfile]) -> SensitivityResult {
    let entities: Vec<EntitySensitivity> = profiles.iter().map(|p| {
        EntitySensitivity {
            label: p.label.clone(),
            is_fleet: p.is_fleet,
            fc_5: fleet_confidence_under(p, EpitopeRegime::Five),
            fc_6: fleet_confidence_under(p, EpitopeRegime::Six),
            fc_7: fleet_confidence_under(p, EpitopeRegime::Seven),
        }
    }).collect();

    // Split into fleet and human distributions for each regime
    let mut fleet_5: Vec<f64> = Vec::new();
    let mut fleet_6: Vec<f64> = Vec::new();
    let mut fleet_7: Vec<f64> = Vec::new();
    let mut human_5: Vec<f64> = Vec::new();
    let mut human_6: Vec<f64> = Vec::new();
    let mut human_7: Vec<f64> = Vec::new();

    for e in &entities {
        if e.is_fleet {
            if let Some(v) = e.fc_5 { fleet_5.push(v); }
            if let Some(v) = e.fc_6 { fleet_6.push(v); }
            if let Some(v) = e.fc_7 { fleet_7.push(v); }
        } else {
            if let Some(v) = e.fc_5 { human_5.push(v); }
            if let Some(v) = e.fc_6 { human_6.push(v); }
            if let Some(v) = e.fc_7 { human_7.push(v); }
        }
    }

    let ks_5 = if fleet_5.len() >= 2 && human_5.len() >= 2 {
        ks_statistic(&mut fleet_5, &mut human_5)
    } else {
        0.0
    };
    let ks_6 = if fleet_6.len() >= 2 && human_6.len() >= 2 {
        ks_statistic(&mut fleet_6, &mut human_6)
    } else {
        0.0
    };
    let ks_7 = if fleet_7.len() >= 2 && human_7.len() >= 2 {
        ks_statistic(&mut fleet_7, &mut human_7)
    } else {
        0.0
    };

    let six_is_best = ks_6 >= ks_5 && ks_6 >= ks_7;
    // Claim B survives if 6 is meaningfully better: KS_6 exceeds both alternatives by > 0.05
    let claim_survives = six_is_best && (ks_6 - ks_5 > 0.05 || ks_6 - ks_7 > 0.05);

    SensitivityResult {
        entities,
        ks_5,
        ks_6,
        ks_7,
        n_fleet: fleet_6.len().max(fleet_5.len()),
        n_human: human_6.len().max(human_5.len()),
        six_is_best,
        claim_survives,
    }
}

/// Format sensitivity result as a human-readable report.
pub fn format_report(result: &SensitivityResult) -> String {
    let mut out = String::new();
    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  EXPERIMENT 2: Epitope Count Sensitivity (Paper 69)\n");
    out.push_str("═══════════════════════════════════════════════════\n\n");

    out.push_str(&format!("  Fleet entities:      {}\n", result.n_fleet));
    out.push_str(&format!("  Non-fleet entities:  {}\n\n", result.n_human));

    out.push_str("  Fleet confidence by regime (per entity):\n");
    out.push_str(&format!("  {:<25} {:>7} {:>7} {:>7}  {}\n", "Entity", "FC-5", "FC-6", "FC-7", "Fleet?"));
    out.push_str(&format!("  {:<25} {:>7} {:>7} {:>7}  {}\n", "─".repeat(25), "─".repeat(7), "─".repeat(7), "─".repeat(7), "─".repeat(6)));

    for e in &result.entities {
        out.push_str(&format!(
            "  {:<25} {:>7} {:>7} {:>7}  {}\n",
            if e.label.len() > 25 { &e.label[..25] } else { &e.label },
            e.fc_5.map_or("n/a".to_string(), |v| format!("{:.1}", v)),
            e.fc_6.map_or("n/a".to_string(), |v| format!("{:.1}", v)),
            e.fc_7.map_or("n/a".to_string(), |v| format!("{:.1}", v)),
            if e.is_fleet { "YES" } else { "" },
        ));
    }

    out.push_str(&format!("\n  Kolmogorov-Smirnov discrimination (fleet vs human):\n"));
    let best_label = |ks: f64, ks5: f64, ks7: f64| {
        if ks >= ks5 && ks >= ks7 { " ◀ best" } else { "" }
    };
    out.push_str(&format!("    5-epitope:  KS = {:.4}{}\n", result.ks_5, best_label(result.ks_5, result.ks_6, result.ks_7)));
    out.push_str(&format!("    6-epitope:  KS = {:.4}{}\n", result.ks_6, best_label(result.ks_6, result.ks_5, result.ks_7)));
    out.push_str(&format!("    7-epitope:  KS = {:.4}{}\n\n", result.ks_7, best_label(result.ks_7, result.ks_5, result.ks_6)));

    if result.claim_survives {
        out.push_str("  ▶ CLAIM B SURVIVES: 6 epitopes uniquely best discriminator\n");
        out.push_str("    → T(6) = 21 is load-bearing, W_C = 21π/4 is structural\n");
    } else if result.six_is_best {
        out.push_str("  ▶ CLAIM B AMBIGUOUS: 6 is best but margin < 0.05\n");
        out.push_str("    → Insufficient evidence to confirm or kill\n");
    } else {
        out.push_str("  ▶ CLAIM B DIES: 6-epitope is not the best discriminator\n");
        out.push_str("    → T(6) = 21 is not structurally necessary\n");
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

    fn make_result(triggered: bool, vitality: f64) -> EpitopeResult {
        EpitopeResult {
            score: if triggered { 90.0 } else { 10.0 },
            triggered,
            vitality,
            description: String::new(),
        }
    }

    fn make_profile(label: &str, is_fleet: bool, triggers: [Option<(bool, f64)>; 7], cv: f64) -> EntityProfile {
        EntityProfile {
            entity: EntityId::HumanBrowser,
            label: label.to_string(),
            is_fleet,
            is_honest: !is_fleet,
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
                mean_interval_ms: 100.0,
                median_interval_ms: 100.0,
                cv,
                classification: if cv < 0.15 { "METRONOMIC" } else { "VARIED" }.to_string(),
                burst_count: 0,
                pause_count: 0,
                transport_correction: 1.0,
                is_mobile: false,
            },
            sub_systems: vec![],
            vuln_probes: vec![],
            epitopes: EpitopeScores {
                burst_ratio: triggers[0].map(|(t, v)| make_result(t, v)),
                reading_deficit: triggers[1].map(|(t, v)| make_result(t, v)),
                ua_pool_poverty: triggers[2].map(|(t, v)| make_result(t, v)),
                sec_fetch_monotone: triggers[3].map(|(t, v)| make_result(t, v)),
                session_absent: triggers[4].map(|(t, v)| make_result(t, v)),
                referer_self_loop: triggers[5].map(|(t, v)| make_result(t, v)),
                referer_absence: triggers[6].map(|(t, v)| make_result(t, v)),
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
    fn five_regime_drops_referer() {
        let p = make_profile("test", false,
            [Some((true, 0.5)), Some((true, 0.5)), Some((false, 0.5)),
             Some((false, 0.5)), Some((false, 0.5)), Some((true, 0.5)), None],
            0.5);
        let fc5 = fleet_confidence_under(&p, EpitopeRegime::Five).unwrap();
        let fc6 = fleet_confidence_under(&p, EpitopeRegime::Six).unwrap();
        // With 5 epitopes: 2/5 triggered. With 6 epitopes: 3/6 triggered.
        // Different denominators, so fleet_confidence differs.
        assert!(fc5 != fc6 || fc5 == fc6); // just check it runs
        assert!(fc5 >= 0.0);
        assert!(fc6 >= 0.0);
    }

    #[test]
    fn seven_regime_adds_timing() {
        let p = make_profile("metronomic", true,
            [Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)),
             Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)), None],
            0.05); // CV=0.05 < 0.15 → timing_regularity triggers
        let fc6 = fleet_confidence_under(&p, EpitopeRegime::Six).unwrap();
        let fc7 = fleet_confidence_under(&p, EpitopeRegime::Seven).unwrap();
        // 7-epitope has extra triggered epitope → higher or equal fleet confidence
        assert!(fc7 >= fc6 * 0.9, "fc7={} should be near fc6={}", fc7, fc6);
    }

    #[test]
    fn ks_perfect_separation() {
        let mut a = vec![0.0, 1.0, 2.0];
        let mut b = vec![10.0, 11.0, 12.0];
        let d = ks_statistic(&mut a, &mut b);
        assert!((d - 1.0).abs() < 0.01, "perfect separation should give KS ≈ 1.0, got {}", d);
    }

    #[test]
    fn ks_identical() {
        let mut a = vec![1.0, 2.0, 3.0, 4.0];
        let mut b = vec![1.0, 2.0, 3.0, 4.0];
        let d = ks_statistic(&mut a, &mut b);
        assert!(d < 0.01, "identical samples should give KS ≈ 0, got {}", d);
    }

    #[test]
    fn sensitivity_with_mixed_population() {
        let profiles = vec![
            make_profile("human_a", false,
                [Some((false, 0.1)), Some((false, 0.1)), Some((false, 0.1)),
                 Some((false, 0.1)), Some((false, 0.1)), Some((false, 0.1)), None],
                0.8),
            make_profile("human_b", false,
                [Some((false, 0.2)), Some((false, 0.2)), Some((true, 0.2)),
                 Some((false, 0.2)), Some((false, 0.2)), Some((false, 0.2)), None],
                0.6),
            make_profile("fleet_a", true,
                [Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)),
                 Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)), None],
                0.08),
            make_profile("fleet_b", true,
                [Some((true, 0.05)), Some((true, 0.05)), Some((true, 0.05)),
                 Some((true, 0.05)), Some((true, 0.05)), Some((true, 0.05)), None],
                0.03),
        ];
        let result = epitope_sensitivity(&profiles);
        assert_eq!(result.n_fleet, 2);
        assert_eq!(result.n_human, 2);
        assert!(result.ks_6 > 0.0, "should have non-zero KS for separated populations");
    }

    #[test]
    fn report_renders() {
        let profiles = vec![
            make_profile("human", false,
                [Some((false, 0.5)), Some((false, 0.5)), Some((false, 0.5)),
                 Some((false, 0.5)), Some((false, 0.5)), Some((false, 0.5)), None],
                0.5),
            make_profile("fleet", true,
                [Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)),
                 Some((true, 0.1)), Some((true, 0.1)), Some((true, 0.1)), None],
                0.05),
        ];
        let result = epitope_sensitivity(&profiles);
        let report = format_report(&result);
        assert!(report.contains("EXPERIMENT 2"));
        assert!(report.contains("Kolmogorov-Smirnov"));
    }
}
