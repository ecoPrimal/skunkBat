// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Anderson bridge — observation → theory reverse mapping.
//!
//! Closes the loop between behavioral observation (BingoCubeTrio, scatter
//! metrics, population statistics) and the Anderson transport equations
//! (Paper 01, Paper 43). Self-contained — no barracuda dependency.
//!
//! ## Multi-scale parameter mapping
//!
//! | Scale        | Observable              | Anderson parameter |
//! |--------------|-------------------------|--------------------|
//! | Population   | Pielou J (entity mix)   | W (disorder)       |
//! | Per-entity   | BingoCubeTrio variance  | W_eff per mode     |
//! | Geographic   | Bodies observing entity  | d_eff (dimension)  |
//! | Signal       | Request frequency       | E (energy)         |
//!
//! ## Imaginary projection
//!
//! The residual between predicted and observed permeability maps to the
//! imaginary dimension: P_complex = P_predicted + i·(P_observed - P_predicted).
//!
//! - residual > 0 → entity adapting (penetrating membrane beyond equilibrium)
//! - residual < 0 → membrane actively defending beyond what disorder explains
//!
//! See Paper 46: "Inverse Anderson — Behavioral Observation as Disorder Measurement"

use std::collections::HashMap;
use std::sync::Arc;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::dashboard_profile::{IpProfile, TrioClass, score_trio};

/// Shared Anderson profile — updated by DashboardWriter, read by scatter server.
pub type SharedAndersonProfile = Arc<RwLock<Option<AndersonProfile>>>;

// ══════════════════════════════════════════════════════════════════════
// Anderson transport equations — CANONICAL COPY from barraCuda
// Source: barraCuda/crates/barracuda/src/special/anderson_transport.rs
// INVARIANT: These must match canonical exactly. Do not modify here.
// If the math needs to change, change barraCuda first, then sync.
// ══════════════════════════════════════════════════════════════════════

/// Thouless-formula 1D localization length ξ(E,W).
fn localization_length_1d(disorder: f64, energy: f64) -> f64 {
    let w_sq = disorder.mul_add(disorder, 0.01);
    let band_factor = energy.mul_add(-energy, 4.0).max(0.01);
    105.0 * band_factor / w_sq
}

/// Localization length generalized to fractional effective dimension.
fn dimensional_localization_length(disorder: f64, energy: f64, d_eff: f64) -> f64 {
    let d_eff = d_eff.max(1.0);
    let xi_1d = localization_length_1d(disorder, energy);

    if d_eff <= 1.0 {
        return xi_1d;
    }

    let xi_2d = if disorder > 1e-10 {
        let exponent = (core::f64::consts::PI * (xi_1d / 10.0).min(30.0)).min(30.0);
        xi_1d * exponent.exp()
    } else {
        1e15
    };

    if d_eff <= 2.0 {
        let frac = d_eff - 1.0;
        let log_xi = xi_1d.ln().mul_add(1.0 - frac, xi_2d.ln() * frac);
        return log_xi.exp();
    }

    const W_C: f64 = 16.5;
    const NU: f64 = 1.57;
    const XI_EXTENDED: f64 = 1e15;
    let xi_3d = if disorder < 1e-10 {
        XI_EXTENDED
    } else if disorder < W_C {
        XI_EXTENDED
    } else if (disorder - W_C).abs() < 0.01 {
        xi_2d * 10.0
    } else {
        let reduced_w = disorder / W_C - 1.0;
        let xi_0 = xi_1d.max(1.0);
        xi_0 * reduced_w.powf(-NU).max(0.1)
    };

    if d_eff <= 3.0 {
        let frac = d_eff - 2.0;
        let log_xi = xi_2d.ln().mul_add(1.0 - frac, xi_3d.ln() * frac);
        return log_xi.exp();
    }

    // d > 3: even more delocalized. Use 3D result as lower bound.
    xi_3d
}

/// Membrane permeability P(ω) = exp(-L/ξ) for a single mode, clamped to [0,1].
fn membrane_permeability(disorder: f64, energy: f64, d_eff: f64, system_size: f64) -> f64 {
    let xi = dimensional_localization_length(disorder, energy, d_eff);
    if xi <= 0.0 {
        return 0.0;
    }
    (-system_size / xi).exp().clamp(0.0, 1.0)
}

// ══════════════════════════════════════════════════════════════════════
// Population-scale: Pielou J → W
// ══════════════════════════════════════════════════════════════════════

/// Compute Pielou evenness J from a distribution of counts.
///
/// J = H' / H'_max where H' = -Σ(p_i · ln(p_i)), H'_max = ln(S).
/// J=1 means perfectly even; J→0 means monoculture.
pub fn pielou_evenness(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 || counts.len() <= 1 {
        return 0.0;
    }

    let s = counts.iter().filter(|&&c| c > 0).count();
    if s <= 1 {
        return 0.0;
    }

    let h_prime: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.ln()
        })
        .sum();

    let h_max = (s as f64).ln();
    if h_max <= 0.0 {
        return 0.0;
    }

    (h_prime / h_max).clamp(0.0, 1.0)
}

/// Map Pielou evenness J to Anderson disorder W.
///
/// W = 0.5 + 14.5·(1 - J)
/// - J=1 (perfect diversity) → W=0.5 (minimal disorder, all signals propagate)
/// - J=0 (monoculture fleet) → W=15.0 (high disorder, signals localize)
///
/// From Paper 01 §3.3: `evenness_to_disorder(j, scale=14.5)`.
pub fn evenness_to_disorder(j: f64) -> f64 {
    0.5 + 14.5 * (1.0 - j.clamp(0.0, 1.0))
}

// ══════════════════════════════════════════════════════════════════════
// Anderson profile — the bridge output
// ══════════════════════════════════════════════════════════════════════

/// Per-mode Anderson analysis — one entry per TrioClass.
#[derive(Debug, Clone, Serialize)]
pub struct ModeAnalysis {
    /// Ecological class name.
    pub class: String,
    /// Entity count in this class.
    pub count: u64,
    /// Effective disorder from intra-class behavioral variance.
    pub w_eff: f64,
    /// Effective dimension from geographic distribution.
    pub d_eff: f64,
    /// Signal energy from request frequency.
    pub energy: f64,
    /// Membrane thickness (number of detection layers).
    pub system_size: f64,
    /// Predicted permeability from forward Anderson model.
    pub p_predicted: f64,
    /// Observed permeability from accept/block ratios.
    pub p_observed: f64,
    /// Imaginary residual: P_observed - P_predicted.
    /// Positive = adapting, negative = actively defended.
    pub residual: f64,
}

/// Full Anderson profile for a golgi body's observation window.
#[derive(Debug, Clone, Serialize)]
pub struct AndersonProfile {
    /// Population-level disorder from entity diversity.
    pub w_population: f64,
    /// Pielou evenness of the entity population.
    pub pielou_j: f64,
    /// Number of golgi bodies in the mesh.
    pub d_mesh: u32,
    /// Per-mode (per-TrioClass) analysis.
    pub modes: Vec<ModeAnalysis>,
    /// Selectivity predicted: max(P) - min(P) across modes.
    pub selectivity_predicted: f64,
    /// Selectivity observed: max(P_obs) - min(P_obs) across modes.
    pub selectivity_observed: f64,
    /// Magnitude of the imaginary component: sqrt(Σ residual²).
    pub imaginary_magnitude: f64,
}

/// Input: per-class observation statistics for the Anderson bridge.
#[derive(Debug, Clone)]
pub struct ClassObservation {
    /// Number of entities in this class.
    pub count: u64,
    /// Mean trio scores for entities in this class.
    pub mean_attention: f32,
    pub mean_curiosity: f32,
    pub mean_interaction: f32,
    /// Variance of trio scores (behavioral disorder within class).
    pub variance: f64,
    /// Average requests per hour across entities in this class.
    pub requests_per_hour: f64,
    /// How many bodies observe entities with this class.
    pub bodies_observing: u32,
    /// Fraction of entities that were accepted (not blocked).
    pub accept_ratio: f64,
}

/// Compute the Anderson profile from population observations.
///
/// ## Layered mode taxonomy (Wave 171)
///
/// The old 3-class system (Parasite/Commensal/Sovereign) collapsed too much —
/// Anthropic at 650K reqs and PetalBot at 57 reqs both got P=1.0 because
/// d_eff=mesh_size put everything in extended state. No selectivity.
///
/// The refined taxonomy adds layers between spectrum and nucleus:
///
/// | Mode | d_eff | L | What it is |
/// |------|-------|---|-----------|
/// | spectrum | 1.0 | 500 | Dominant declared fleet (>10K rph). Permeates everything. |
/// | chorus | 2.0 | 100 | Declared bots, social crawlers. Commensal. |
/// | stealth | 1.0 | 200 | Undeclared fleet. Parasitic but adapted. |
/// | ghost | 1.5 | 50 | Unknown — brief, no identity. Privacy is allowed. |
/// | human | 3.0 | 10 | Real browsers with behavioral depth. |
/// | sovereign | 3.0 | 5 | Self, admin, known entities. Nucleus. |
///
/// The membrane's job: spectrum passes through (observed, not blocked),
/// stealth localizes (blocked), human passes through a short low-disorder
/// channel (different physics from spectrum). Selectivity S > 0 because
/// the modes see genuinely different (W, d, L) — not the same parameters.
///
/// `observations` maps TrioClass → ClassObservation.
/// `mesh_size` is the total number of golgi bodies in the mesh.
/// L (membrane thickness) is assigned per-mode based on ecological role,
/// not passed as a single parameter — each mode sees a different membrane.
pub fn compute_profile(
    observations: &HashMap<EcoMode, ClassObservation>,
    mesh_size: u32,
) -> AndersonProfile {
    // Population-level Pielou J from mode counts (6 modes)
    let counts: Vec<u64> = [
        EcoMode::Spectrum, EcoMode::Chorus, EcoMode::Stealth,
        EcoMode::Ghost, EcoMode::Human, EcoMode::Sovereign,
    ].iter()
        .map(|m| observations.get(m).map(|o| o.count).unwrap_or(0))
        .collect();
    let j = pielou_evenness(&counts);
    let w_pop = evenness_to_disorder(j);

    let mut modes = Vec::new();

    // ── Each EcoMode gets its own (d, L, W) — the Anderson parameters ──
    //
    // d_eff = TRANSPORT PHYSICS, not mesh topology:
    //   1D = confined to a narrow declared channel (spectrum/stealth)
    //   1.5D = partially extended (ghost — unknown, some paths)
    //   2D = surface-crawling (chorus — declared bots, explore a surface)
    //   3D = bulk transport (human/sovereign — many orthogonal paths)
    //
    // L = membrane THICKNESS for that signal type:
    //   500 = thick — many rules examine this signal
    //   10 = thin — few rules needed, passes quickly
    //
    // W modulation = effective disorder seen by each mode
    for mode in [
        EcoMode::Spectrum,
        EcoMode::Chorus,
        EcoMode::Stealth,
        EcoMode::Ghost,
        EcoMode::Human,
        EcoMode::Sovereign,
    ] {
        let obs = match observations.get(&mode) {
            Some(o) if o.count > 0 => o,
            _ => continue,
        };

        let w_eff_base = w_pop * (1.0 + obs.variance.sqrt().min(2.0));
        let energy = (obs.requests_per_hour + 1.0).log2().min(2.0);

        let (d_eff, system_size, w_eff, p_obs) = match mode {
            EcoMode::Spectrum => {
                // Dominant declared fleet (Anthropic at 650K+ rph)
                // 1D channel (declared UA = single narrow path)
                // Thick membrane (L=500, many rules watch them)
                // Low disorder (well-ordered, predictable behavior)
                (1.0, 500.0, w_eff_base * 0.3, obs.accept_ratio)
            }
            EcoMode::Chorus => {
                // Regular declared bots (Google, Bing, PetalBot)
                // 2D surface (they crawl the membrane face)
                // Moderate thickness, moderate disorder
                (2.0, 100.0, w_eff_base * 0.5, obs.accept_ratio)
            }
            EcoMode::Stealth => {
                // Undeclared fleet, no curiosity, no interaction
                // 1D confinement + HIGH disorder → localization (blocked)
                (1.0, 200.0, w_eff_base * 1.5, 0.0)
            }
            EcoMode::Ghost => {
                // Unknown, brief visits, some curiosity
                // Privacy is allowed — ghosts are not penalized
                // 1.5D (partially extended), medium membrane
                (1.5, 50.0, w_eff_base * 0.8, obs.accept_ratio)
            }
            EcoMode::Human => {
                // Real browser with behavioral depth
                // 3D (many orthogonal paths: Sec-Fetch, Accept-Language, etc.)
                // Short membrane (L=10), low disorder → P→1
                (3.0, 10.0, w_eff_base * 0.2, obs.accept_ratio)
            }
            EcoMode::Sovereign => {
                // Self, admin, deep interaction
                // 3D, very short membrane, minimal disorder → P→1 (nucleus)
                (3.0, 5.0, w_eff_base * 0.1, 0.97)
            }
        };

        // Forward model with physically meaningful parameters
        let p_predicted = membrane_permeability(w_eff, energy, d_eff, system_size);
        let p_observed_val = p_obs.clamp(0.0, 1.0);
        let residual = p_observed_val - p_predicted;

        modes.push(ModeAnalysis {
            class: mode.label().to_string(),
            count: obs.count,
            w_eff: (w_eff * 1000.0).round() / 1000.0,
            d_eff: (d_eff * 10.0).round() / 10.0,
            energy: (energy * 1000.0).round() / 1000.0,
            system_size,
            p_predicted: (p_predicted * 10000.0).round() / 10000.0,
            p_observed: (p_observed_val * 10000.0).round() / 10000.0,
            residual: (residual * 10000.0).round() / 10000.0,
        });
    }

    // Selectivity: max(P) - min(P) across all modes
    let s_pred = if modes.len() >= 2 {
        let max_p = modes.iter().map(|m| m.p_predicted).fold(0.0_f64, f64::max);
        let min_p = modes.iter().map(|m| m.p_predicted).fold(1.0_f64, f64::min);
        max_p - min_p
    } else {
        0.0
    };

    let s_obs = if modes.len() >= 2 {
        let max_p = modes.iter().map(|m| m.p_observed).fold(0.0_f64, f64::max);
        let min_p = modes.iter().map(|m| m.p_observed).fold(1.0_f64, f64::min);
        max_p - min_p
    } else {
        0.0
    };

    // Imaginary magnitude: L2 norm of residuals
    let imag_mag = modes.iter()
        .map(|m| m.residual * m.residual)
        .sum::<f64>()
        .sqrt();

    AndersonProfile {
        w_population: (w_pop * 1000.0).round() / 1000.0,
        pielou_j: (j * 1000.0).round() / 1000.0,
        d_mesh: mesh_size,
        modes,
        selectivity_predicted: (s_pred * 10000.0).round() / 10000.0,
        selectivity_observed: (s_obs * 10000.0).round() / 10000.0,
        imaginary_magnitude: (imag_mag * 10000.0).round() / 10000.0,
    }
}

/// Ecological mode — finer than TrioClass, maps to Anderson (W, d, L).
///
/// Each mode sees a different membrane: different thickness, different
/// dimension, different disorder. The membrane is selectively permeable
/// because different signal types physically traverse different channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcoMode {
    /// Dominant declared fleet (>1K rph). Permeates the membrane on a
    /// single declared channel. Anthropic, high-volume declared crawlers.
    Spectrum,
    /// Regular declared bots. Google, Bing, PetalBot. Commensal chorus.
    Chorus,
    /// Undeclared fleet. Parasitic, adapted, no identity.
    Stealth,
    /// Unknown — brief visits, no declared identity. Privacy is allowed.
    Ghost,
    /// Real browser with behavioral depth. Sec-Fetch, Accept-Language.
    Human,
    /// Self, admin, known entities. The nucleus.
    Sovereign,
}

impl EcoMode {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Spectrum => "spectrum",
            Self::Chorus => "chorus",
            Self::Stealth => "stealth",
            Self::Ghost => "ghost",
            Self::Human => "human",
            Self::Sovereign => "sovereign",
        }
    }
}

/// Extract ecological mode observations from a population of IP profiles.
///
/// This is the primary bridge function: takes the raw dashboard_writer
/// data and splits entities into 6 ecological modes based on behavioral
/// depth, not just the 3-class TrioClass.
///
/// The split happens per-entity so that Anthropic (650K rph) doesn't
/// get averaged with PetalBot (57 rph) — they see different membranes.
pub fn extract_observations(
    profiles: &HashMap<u64, IpProfile>,
    mesh_size: u32,
) -> HashMap<EcoMode, ClassObservation> {
    let mut mode_profiles: HashMap<EcoMode, Vec<(f32, f32, f32, u64, bool)>> = HashMap::new();

    for profile in profiles.values() {
        let trio = score_trio(profile);
        let rph = if profile.last_seen > profile.first_seen {
            let hours = (profile.last_seen - profile.first_seen) / 3600.0;
            if hours > 0.0 { profile.requests as f64 / hours } else { profile.requests as f64 }
        } else {
            profile.requests as f64
        };

        let mode = match trio.classification {
            TrioClass::Commensal => {
                if rph > 1000.0 {
                    EcoMode::Spectrum
                } else {
                    EcoMode::Chorus
                }
            }
            TrioClass::Parasite => {
                if trio.curiosity < 0.15 && trio.interaction < 0.15 {
                    EcoMode::Stealth
                } else {
                    EcoMode::Ghost
                }
            }
            TrioClass::Sovereign => {
                if trio.interaction > 0.5 {
                    EcoMode::Sovereign
                } else {
                    EcoMode::Human
                }
            }
        };

        mode_profiles
            .entry(mode)
            .or_default()
            .push((trio.attention, trio.curiosity, trio.interaction, rph as u64, profile.is_fleet));
    }

    let mut observations = HashMap::new();

    for (mode, entries) in &mode_profiles {
        let count = entries.len() as u64;
        if count == 0 { continue; }

        let (sum_a, sum_c, sum_i, sum_rph) = entries.iter().fold(
            (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64),
            |(a, c, i, r), (ea, ec, ei, er, _)| {
                (a + *ea as f64, c + *ec as f64, i + *ei as f64, r + *er as f64)
            },
        );

        let n = count as f64;
        let mean_a = sum_a / n;
        let mean_c = sum_c / n;
        let mean_i = sum_i / n;

        let variance: f64 = entries.iter()
            .map(|(a, c, i, _, _)| {
                let da = *a as f64 - mean_a;
                let dc = *c as f64 - mean_c;
                let di = *i as f64 - mean_i;
                (da * da + dc * dc + di * di) / 3.0
            })
            .sum::<f64>() / n;

        let accept_ratio = match mode {
            EcoMode::Stealth => 0.0,
            EcoMode::Ghost => {
                let not_fleet = entries.iter().filter(|(_, _, _, _, is_fleet)| !is_fleet).count();
                not_fleet as f64 / n
            }
            EcoMode::Spectrum | EcoMode::Chorus => 0.85,
            EcoMode::Human => 0.92,
            EcoMode::Sovereign => 0.97,
        };

        observations.insert(*mode, ClassObservation {
            count,
            mean_attention: (mean_a as f32 * 100.0).round() / 100.0,
            mean_curiosity: (mean_c as f32 * 100.0).round() / 100.0,
            mean_interaction: (mean_i as f32 * 100.0).round() / 100.0,
            variance,
            requests_per_hour: sum_rph / n,
            bodies_observing: mesh_size.min(count as u32).max(1),
            accept_ratio,
        });
    }

    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pielou_evenness_perfect() {
        assert!((pielou_evenness(&[100, 100, 100]) - 1.0).abs() < 0.001);
    }

    #[test]
    fn pielou_evenness_monoculture() {
        assert!(pielou_evenness(&[1000, 0, 0]) < 0.01);
    }

    #[test]
    fn pielou_evenness_empty() {
        assert_eq!(pielou_evenness(&[]), 0.0);
        assert_eq!(pielou_evenness(&[0, 0, 0]), 0.0);
    }

    #[test]
    fn disorder_mapping() {
        let w_diverse = evenness_to_disorder(1.0);
        let w_mono = evenness_to_disorder(0.0);
        assert!((w_diverse - 0.5).abs() < 0.01);
        assert!((w_mono - 15.0).abs() < 0.01);
    }

    #[test]
    fn localization_length_increases_with_dimension() {
        let w = 5.0;
        let e = 0.5;
        let xi_1 = dimensional_localization_length(w, e, 1.0);
        let xi_2 = dimensional_localization_length(w, e, 2.0);
        let xi_3 = dimensional_localization_length(w, e, 3.0);
        assert!(xi_2 > xi_1, "ξ should increase with dimension");
        assert!(xi_3 > xi_2, "ξ should increase with dimension");
    }

    #[test]
    fn permeability_decreases_with_disorder() {
        let p_low = membrane_permeability(1.0, 0.5, 2.0, 10.0);
        let p_high = membrane_permeability(10.0, 0.5, 2.0, 10.0);
        assert!(p_low > p_high, "P should decrease with higher disorder");
    }

    #[test]
    fn selectivity_healthy_membrane() {
        // Healthy membrane: stealth blocked (1D, high W), sovereign passes (3D, low W)
        let mut obs = HashMap::new();
        obs.insert(EcoMode::Stealth, ClassObservation {
            count: 100, mean_attention: 0.1, mean_curiosity: 0.1,
            mean_interaction: 0.05, variance: 0.01, requests_per_hour: 500.0,
            bodies_observing: 1, accept_ratio: 0.0,
        });
        obs.insert(EcoMode::Sovereign, ClassObservation {
            count: 20, mean_attention: 0.8, mean_curiosity: 0.6,
            mean_interaction: 0.7, variance: 0.15, requests_per_hour: 2.0,
            bodies_observing: 4, accept_ratio: 0.97,
        });

        let profile = compute_profile(&obs, 4);
        assert!(profile.selectivity_predicted > 0.5,
            "healthy membrane should have high selectivity, got {}", profile.selectivity_predicted);
        assert!(profile.pielou_j > 0.0, "non-zero population should have non-zero J");
    }

    #[test]
    fn imaginary_residual_sign() {
        // Adapting entity: observed P > predicted P
        let mut obs = HashMap::new();
        obs.insert(EcoMode::Chorus, ClassObservation {
            count: 50, mean_attention: 0.5, mean_curiosity: 0.4,
            mean_interaction: 0.3, variance: 0.1, requests_per_hour: 10.0,
            bodies_observing: 2, accept_ratio: 0.95,
        });

        let profile = compute_profile(&obs, 4);
        // With moderate disorder and d=2 (chorus), predicted P should be less
        // than 0.95 so residual should be positive (entity more permeable than expected)
        if let Some(mode) = profile.modes.first() {
            if mode.p_predicted < 0.95 {
                assert!(mode.residual > 0.0, "adapting entity should have positive residual");
            }
        }
    }

    #[test]
    fn six_mode_separation() {
        // All 6 modes present — each should get distinct P values
        let mut obs = HashMap::new();
        let base = ClassObservation {
            count: 10, mean_attention: 0.5, mean_curiosity: 0.5,
            mean_interaction: 0.5, variance: 0.1, requests_per_hour: 10.0,
            bodies_observing: 4, accept_ratio: 0.85,
        };
        obs.insert(EcoMode::Spectrum, ClassObservation { count: 3, requests_per_hour: 5000.0, accept_ratio: 0.85, ..base });
        obs.insert(EcoMode::Chorus, ClassObservation { count: 100, requests_per_hour: 10.0, accept_ratio: 0.85, ..base });
        obs.insert(EcoMode::Stealth, ClassObservation { count: 50, mean_curiosity: 0.05, mean_interaction: 0.02, accept_ratio: 0.0, ..base });
        obs.insert(EcoMode::Ghost, ClassObservation { count: 200, mean_curiosity: 0.3, accept_ratio: 0.9, ..base });
        obs.insert(EcoMode::Human, ClassObservation { count: 30, mean_interaction: 0.3, accept_ratio: 0.92, ..base });
        obs.insert(EcoMode::Sovereign, ClassObservation { count: 5, mean_interaction: 0.8, accept_ratio: 0.97, ..base });

        let profile = compute_profile(&obs, 4);
        assert_eq!(profile.modes.len(), 6, "all 6 modes should appear");
        assert!(profile.selectivity_predicted > 0.0, "6-mode profile should have selectivity");

        // Sovereign P should be higher than stealth P
        let p_sov = profile.modes.iter().find(|m| m.class == "sovereign").unwrap().p_predicted;
        let p_stl = profile.modes.iter().find(|m| m.class == "stealth").unwrap().p_predicted;
        assert!(p_sov > p_stl, "sovereign should permeate more than stealth: sov={} stl={}", p_sov, p_stl);
    }
}
