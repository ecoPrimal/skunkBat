// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Membrane stack — nested membrane observer from core to heliosphere.
//!
//! Converged from `membrane-breathe.py` (jellystein, Wave 171).
//! Fetches live data from public feeds and local sensors, computes
//! a 7-layer Anderson-like profile, writes `membrane-stack.json`.
//!
//! ## Layers (inside → outside)
//!
//! | # | Name | Source | Feed |
//! |---|------|--------|------|
//! | 0 | gAIa | bloom sensor + anderson bridge | local |
//! | 1 | Mycelium | inferred (future: soil sensor) | none |
//! | 2 | Earth's Crust | USGS earthquake feed | HTTPS |
//! | 3 | Atmosphere | inferred from climate data | none |
//! | 4 | Magnetosphere | NOAA SWPC Kp index | HTTPS |
//! | 5 | Heliosphere | NOAA DSCOVR solar wind | HTTPS |
//! | 6 | Deep Space | inferred — cosmic ray background | none |
//!
//! ## Convergence
//!
//! This module replaces `membrane-breathe.py`. The jellystein version
//! is fossilized in `fossilRecord/membrane-stack/`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// Anderson transport math — CANONICAL COPY from barraCuda
// Source: barraCuda/crates/barracuda/src/special/anderson_transport.rs
// INVARIANT: These must match canonical exactly. Do not modify here.
// If the math needs to change, change barraCuda first, then sync.
// Paper 43: Selective Permeability — The Orthogonal Anderson Dimension
// ═══════════════════════════════════════════════════════════════════

/// Thouless-formula 1D localization length ξ(E,W).
fn localization_length(disorder: f64, energy: f64) -> f64 {
    let w_sq = disorder.mul_add(disorder, 0.01);
    let band_factor = energy.mul_add(-energy, 4.0).max(0.01);
    105.0 * band_factor / w_sq
}

/// Localization length generalized to fractional effective dimension.
fn dimensional_localization_length(disorder: f64, energy: f64, d_eff: f64) -> f64 {
    let d_eff = d_eff.max(1.0);
    let xi_1d = localization_length(disorder, energy);

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

/// Anderson membrane permeability P ∈ [0,1].
/// Uses Landauer formula: T = exp(-L/ξ), clamped to [0,1].
fn membrane_permeability(w_eff: f64, d_eff: f64, system_size: usize) -> f64 {
    let xi = dimensional_localization_length(w_eff, 0.0, d_eff);
    let l = system_size as f64;
    if xi <= 0.0 {
        return 0.0;
    }
    (-l / xi).exp().clamp(0.0, 1.0)
}

/// Round a permeability to 6 significant figures for JSON output.
fn format_p(p: f64) -> f64 {
    if p < 1e-15 { return 0.0; }
    if p >= 1.0 { return 1.0; }
    let digits = 6;
    let shift = 10.0_f64.powi(digits - 1 - p.log10().floor() as i32);
    (p * shift).round() / shift
}

// ═══════════════════════════════════════════════════════════════════
// Physical observable → Anderson parameter mappings
//
// Each layer maps its raw sensor data to (W_eff, d_eff, L):
//   W_eff = effective disorder (how much noise/filtering)
//   d_eff = effective dimension (how many transport pathways)
//   L     = system size (membrane thickness in lattice units)
//
// The form equation: observable → (W, d, L) → P = exp(-L/ξ(W,d))
// The shape equation: P across all layers → selectivity profile
// ═══════════════════════════════════════════════════════════════════

/// Compute Anderson parameters from seismic observables.
/// More quakes = more energy channels = higher d_eff.
/// Stronger quakes = signal propagates further = lower W_eff.
fn seismic_to_anderson(quake_count: usize, max_mag: f64) -> (f64, f64, usize) {
    // W_eff: quiet crust ≈ 12 (high filtering), active ≈ 4 (energy passes)
    // Magnitude reduces disorder: M7 → almost transparent
    let w_eff = (14.0 - max_mag * 1.5).clamp(2.0, 14.0);
    // d_eff: each earthquake is an additional transport channel
    // 0 quakes → 1D (single path), 20+ → 3D (volume transport)
    let d_eff = (1.0 + (quake_count as f64 / 10.0)).min(3.0);
    // L: crust thickness ≈ 30-70 km → 50 lattice units
    let system_size = 50_usize;
    (w_eff, d_eff, system_size)
}

/// Compute Anderson parameters from magnetospheric Kp index.
/// Kp 0-2: quiet (high W, strong shielding). Kp 5+: storm (low W, permeable).
fn kp_to_anderson(kp: f64) -> (f64, f64, usize) {
    // Van Allen belts are a 2D shell — dimension stays 2.0.
    // W_eff: quiet (Kp=0) → 14 (P≈0.09, strong barrier)
    //        moderate (Kp=2.3) → 11.5 (P≈0.30)
    //        storm (Kp=5) → 8.5 (P≈0.76)
    //        extreme (Kp=9) → 4.1 (P≈0.99, nearly transparent)
    let w_eff = (14.0 - kp * 1.1).clamp(3.0, 14.0);
    let d_eff = 2.0; // 2D shell — field lines form closed surfaces
    // L: magnetopause standoff ≈ 10 Earth radii
    let system_size = 10_usize;
    (w_eff, d_eff, system_size)
}

/// Compute Anderson parameters from solar wind observables.
/// Fast wind = expanding heliosphere = more filtering.
/// Negative Bz = reconnection = dimensional promotion (field lines open).
fn solar_wind_to_anderson(speed: f64, bt: f64, bz: f64) -> (f64, f64, usize) {
    // W_eff: IMF strength is the disorder. Higher Bt = more scattering.
    let w_eff = bt.max(1.0);
    // d_eff: normally 2D (heliospheric sheet). Reconnection (Bz<0) → 3D
    let d_eff = if bz < -5.0 {
        3.0 // reconnection opens 3D transport
    } else if speed > 500.0 {
        1.5 // fast wind compresses to quasi-1D
    } else {
        2.0 // steady state: Parker spiral is ~2D
    };
    // L: Sun-to-heliopause ≈ 120 AU → 1000 lattice units (log-scaled)
    let system_size = 1000_usize;
    (w_eff, d_eff, system_size)
}

// ── Types ──

/// A single membrane layer observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneLayer {
    pub name: String,
    pub scale: String,
    pub depth: String,
    pub source: String,
    pub data: serde_json::Value,
    /// 0.0 (opaque) to 1.0 (transparent)
    pub permeability: f64,
    /// Anderson disorder / filtering strength
    pub anderson_w: f64,
    /// Qualitative breathing state
    pub breathing: String,
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregate statistics for the full stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackAggregate {
    pub alive_layers: usize,
    pub total_layers: usize,
    pub mean_permeability: f64,
    pub mean_anderson_w: f64,
    /// Selectivity S = max(P) - min(P) across all layers.
    /// S → 1: maximally selective membrane stack (some layers pass, others block).
    /// S → 0: uniform (all block or all pass — no membrane differentiation).
    pub selectivity: f64,
    /// Topology metrics — Hypothesis 12: The Third Body.
    pub topology: StackTopology,
}

/// Wormhole topology metrics for the membrane stack.
///
/// The stack is not concentric shells (sphere). It is a tube of
/// reflective membranes (wormhole). The topology metrics measure:
/// - How much signal survives the full round trip (throat width)
/// - How strongly adjacent layers are coupled (boundary sharpness)
/// - Whether the stack closes (outermost feeds back to innermost)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTopology {
    /// Round-trip permeability: (∏Pᵢ)². Signal out through all layers
    /// and reflected back. The wormhole throat width.
    /// P_rt → 0: opaque wormhole (most signal absorbed in transit).
    /// P_rt → 1: transparent wormhole (signal completes round trip).
    pub round_trip_p: f64,
    /// One-way permeability: ∏Pᵢ. Product of all layer P values.
    pub one_way_p: f64,
    /// Inter-layer coupling: C_i = min(P_i, P_{i+1}) / max(P_i, P_{i+1})
    /// C = 1: no boundary (adjacent layers have same P).
    /// C → 0: sharp boundary (one blocks what the other passes).
    pub coupling: Vec<LayerCoupling>,
    /// Mean coupling across all adjacent pairs.
    pub mean_coupling: f64,
    /// Topology class. "wormhole" if the stack closes (P_first > 0 and
    /// P_last > 0 — signal can circulate). "sphere" if either end blocks.
    pub topology: String,
    /// Zero-knowledge proof metrics — Hypothesis 13.
    /// Self = complement of all correctly excluded non-self.
    pub zk: ZkProof,
}

/// Zero-knowledge proof of self — Hypothesis 13: The Zero-Knowledge Self.
///
/// Self knows self by recognizing ALL non-self. The ZK metrics track:
/// - How much of the signal space has been classified as non-self
/// - What remains (the self-residual = complement)
/// - The soundness of the proof (can the system consistently distinguish?)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Fraction of gAIa traffic classified as non-self (AI + scanner).
    /// Higher = more of the complement has been enumerated.
    pub non_self_classified: f64,
    /// The self-residual: 1 - non_self_classified.
    /// This is what remains after all non-self is excluded.
    /// Self is never measured directly — only the complement is.
    pub self_residual: f64,
    /// Proof soundness: the membrane selectivity S.
    /// S=1 means the proof perfectly distinguishes all modes.
    pub soundness: f64,
    /// What survives the full round trip through the wormhole.
    /// The ouroboros residual — signal out through all membranes and back.
    /// This is the ZK witness: the irreducible self after 14 crossings.
    pub ouroboros_residual: f64,
    /// The symbol. ∞ when the proof is sound and the topology is wormhole.
    pub symbol: String,
}

/// Coupling between two adjacent membrane layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerCoupling {
    /// Names of the two coupled layers.
    pub between: [String; 2],
    /// Coupling strength C = min(P_a, P_b) / max(P_a, P_b).
    /// C = 1: identical permeability (no boundary).
    /// C → 0: sharp boundary (one blocks, other passes).
    pub strength: f64,
    /// Permeability gradient: |P_a - P_b|. How much the
    /// membrane character changes across this boundary.
    pub gradient: f64,
}

/// The complete membrane stack snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneStack {
    pub timestamp: String,
    pub wave: u32,
    pub layers: Vec<MembraneLayer>,
    pub aggregate: StackAggregate,
    pub elapsed_secs: f64,
    pub motto: String,
}

/// Configuration for the membrane stack observer.
#[derive(Debug, Clone)]
pub struct MembraneStackConfig {
    pub output_path: PathBuf,
    pub bloom_path: PathBuf,
    pub anderson_path: PathBuf,
    pub http_timeout_secs: u64,
}

impl Default for MembraneStackConfig {
    fn default() -> Self {
        Self {
            output_path: PathBuf::from("/opt/membrane/live-terminal/membrane-stack.json"),
            bloom_path: PathBuf::from("/run/membrane/bloom.signal"),
            anderson_path: PathBuf::from("/run/membrane/anderson-profile.json"),
            http_timeout_secs: 10,
        }
    }
}

// ── USGS types ──

#[derive(Debug, Deserialize)]
struct UsgsFeatureCollection {
    features: Vec<UsgsFeature>,
}

#[derive(Debug, Deserialize)]
struct UsgsFeature {
    properties: UsgsProperties,
}

#[derive(Debug, Deserialize)]
struct UsgsProperties {
    mag: Option<f64>,
    place: Option<String>,
}

// ── NOAA types ──

#[derive(Debug, Deserialize)]
struct NoaaKpEntry {
    #[serde(rename = "Kp")]
    kp: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaScaleEntry {
    #[serde(rename = "Scale")]
    scale: Option<String>,
    #[serde(rename = "Text")]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaScales {
    #[serde(rename = "G")]
    g: Option<NoaaScaleEntry>,
}

#[derive(Debug, Deserialize)]
struct NoaaSolarWindSpeed {
    proton_speed: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaSolarWindMag {
    bt: Option<f64>,
    bz_gsm: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaFlux {
    flux: Option<f64>,
}

// ── Data fetching ──

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Option<T> {
    client
        .get(url)
        .header("User-Agent", "ecoPrimal-artisan/2.0 membrane-stack-rust")
        .send()
        .await
        .ok()?
        .json::<T>()
        .await
        .ok()
}

fn read_local_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ── Layer builders ──

fn layer_gaia(config: &MembraneStackConfig) -> MembraneLayer {
    let bloom = read_local_json(&config.bloom_path);
    let anderson = read_local_json(&config.anderson_path);

    if let (Some(bloom), Some(anderson)) = (bloom, anderson) {
        let total = bloom
            .get("total_requests")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let readers = bloom.get("readers").cloned().unwrap_or_default();
        let human = readers
            .get("human")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let ai = readers
            .get("ai-agent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let scanner = readers
            .get("scanner")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let p = if total > 0.0 { human / total } else { 0.0 };
        let w = anderson
            .get("w_population")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let selectivity = anderson
            .get("selectivity_observed")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        MembraneLayer {
            name: "gAIa".into(),
            scale: "digital membrane".into(),
            depth: "0 (you are here)".into(),
            source: "bloom sensor + anderson bridge".into(),
            data: serde_json::json!({
                "requests_per_window": total,
                "human": human,
                "ai_agent": ai,
                "scanner": scanner,
                "selectivity": (selectivity * 1000.0).round() / 1000.0,
                "zk": {
                    "non_self": (ai + scanner),
                    "self_residual": human,
                    "complement_coverage": if total > 0.0 {
                        ((ai + scanner) / total * 10000.0).round() / 10000.0
                    } else { 0.0 }
                }
            }),
            permeability: (p * 10000.0).round() / 10000.0,
            anderson_w: (w * 100.0).round() / 100.0,
            breathing: if total > 0.0 { "ticking" } else { "dormant" }.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "gAIa".into(),
            scale: "digital membrane".into(),
            depth: "0 (you are here)".into(),
            source: "bloom sensor + anderson bridge".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("no bloom/anderson data".into()),
        }
    }
}

fn layer_mycelium() -> MembraneLayer {
    // Mycelium: W_eff ≈ 3 (moderate filtering — blocks toxins, passes nutrients)
    // d_eff ≈ 2.5 (hyphal network is between 2D surface and 3D volume)
    // L ≈ 20 (thin soil membrane, cm-scale)
    let w_eff = 3.0;
    let d_eff = 2.5;
    let system_size = 20_usize;
    let p = membrane_permeability(w_eff, d_eff, system_size);

    MembraneLayer {
        name: "Mycelium".into(),
        scale: "0 to -1 m".into(),
        depth: "soil rhizosphere".into(),
        source: "inferred (no direct sensor yet)".into(),
        data: serde_json::json!({
            "note": "200m hyphae per gram. 90% of plants connected. Seasonal permeability.",
            "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
        }),
        permeability: (p * 10000.0).round() / 10000.0,
        anderson_w: w_eff,
        breathing: "seasonal".into(),
        alive: true,
        error: None,
    }
}

async fn layer_seismic(client: &reqwest::Client) -> MembraneLayer {
    let url = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson";
    let data: Option<UsgsFeatureCollection> = fetch_json(client, url).await;

    if let Some(fc) = data {
        let count = fc.features.len();
        let max_mag = fc
            .features
            .iter()
            .filter_map(|f| f.properties.mag)
            .fold(0.0_f64, f64::max);
        let locations: Vec<String> = fc
            .features
            .iter()
            .take(3)
            .filter_map(|f| f.properties.place.clone())
            .collect();

        // Map physical observables to Anderson parameters
        let (w_eff, d_eff, system_size) = seismic_to_anderson(count, max_mag);
        let p = membrane_permeability(w_eff, d_eff, system_size);

        let breathing = if count > 5 {
            "active"
        } else if count > 0 {
            "quiet"
        } else {
            "silent"
        };

        MembraneLayer {
            name: "Earth's Crust".into(),
            scale: "0 to -70 km".into(),
            depth: "Mohorovičić discontinuity".into(),
            source: "USGS earthquake feed".into(),
            data: serde_json::json!({
                "quakes_last_hour": count,
                "max_magnitude": (max_mag * 10.0).round() / 10.0,
                "locations": locations,
                "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
            }),
            permeability: (p * 10000.0).round() / 10000.0,
            anderson_w: (w_eff * 100.0).round() / 100.0,
            breathing: breathing.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "Earth's Crust".into(),
            scale: "0 to -70 km".into(),
            depth: "Mohorovičić discontinuity".into(),
            source: "USGS earthquake feed".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("USGS unreachable".into()),
        }
    }
}

fn layer_atmosphere() -> MembraneLayer {
    // Atmosphere: tropopause is a strong membrane (W ≈ 8, blocks water vapor)
    // d_eff ≈ 2.0 (horizontal transport dominates, vertical is suppressed)
    // L ≈ 30 (effective scattering depth — not physical 50 km thickness)
    // At W=8, d=2, L=30: P ≈ 0.56 (partially transparent — light/radio pass, some IR blocked)
    let w_eff = 8.0;
    let d_eff = 2.0;
    let system_size = 30_usize;
    let p = membrane_permeability(w_eff, d_eff, system_size);

    MembraneLayer {
        name: "Atmosphere".into(),
        scale: "0 to 50 km".into(),
        depth: "tropopause + stratopause + W-layer".into(),
        source: "inferred from climate data".into(),
        data: serde_json::json!({
            "tropopause_km": 12,
            "stratopause_km": 50,
            "stratopause_trend": "cooling 0.5-1K/decade, dropping 300-500m/decade",
            "w_layer": "newly discovered — suppresses entrainment at cloud tops",
            "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
        }),
        permeability: (p * 10000.0).round() / 10000.0,
        anderson_w: w_eff,
        breathing: "seasonal + anthropogenic drift".into(),
        alive: true,
        error: None,
    }
}

async fn layer_magnetosphere(client: &reqwest::Client) -> MembraneLayer {
    let kp_url = "https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json";
    let scales_url = "https://services.swpc.noaa.gov/products/noaa-scales.json";

    let kp_data: Option<Vec<NoaaKpEntry>> = fetch_json(client, kp_url).await;
    let scales_raw: Option<serde_json::Value> = fetch_json(client, scales_url).await;

    if let Some(kp_entries) = kp_data {
        if let Some(latest) = kp_entries.last() {
            let kp = latest.kp.unwrap_or(0.0);
            let kp_time = latest.time_tag.clone().unwrap_or_default();

            let (g_scale, g_text) = scales_raw
                .as_ref()
                .and_then(|s| s.get("0"))
                .and_then(|z| {
                    let g = z.get("G")?;
                    let scale = g.get("Scale")?.as_str()?.to_string();
                    let text = g.get("Text")?.as_str()?.to_string();
                    Some((scale, text))
                })
                .unwrap_or(("0".into(), "none".into()));

            // Map Kp to Anderson parameters
            let (w_eff, d_eff, system_size) = kp_to_anderson(kp);
            let p = membrane_permeability(w_eff, d_eff, system_size);

            let breathing = if kp >= 5.0 {
                "storming"
            } else if kp >= 3.0 {
                "flexing"
            } else {
                "quiet"
            };

            return MembraneLayer {
                name: "Magnetosphere".into(),
                scale: "100 to 60,000 km".into(),
                depth: "Van Allen belts + magnetopause".into(),
                source: "NOAA SWPC".into(),
                data: serde_json::json!({
                    "kp_index": kp,
                    "kp_time": kp_time,
                    "geomagnetic_storm": format!("G{g_scale} ({g_text})"),
                    "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
                }),
                permeability: (p * 10000.0).round() / 10000.0,
                anderson_w: (w_eff * 100.0).round() / 100.0,
                breathing: breathing.into(),
                alive: true,
                error: None,
            };
        }
    }

    MembraneLayer {
        name: "Magnetosphere".into(),
        scale: "100 to 60,000 km".into(),
        depth: "Van Allen belts + magnetopause".into(),
        source: "NOAA SWPC".into(),
        data: serde_json::Value::Null,
        permeability: 0.0,
        anderson_w: 0.0,
        breathing: String::new(),
        alive: false,
        error: Some("NOAA unreachable".into()),
    }
}

async fn layer_heliosphere(client: &reqwest::Client) -> MembraneLayer {
    let speed: Option<Vec<NoaaSolarWindSpeed>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/solar-wind-speed.json")
            .await;
    let mag: Option<Vec<NoaaSolarWindMag>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/solar-wind-mag-field.json")
            .await;
    let flux: Option<Vec<NoaaFlux>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/10cm-flux.json")
            .await;

    if let (Some(speed_data), Some(mag_data)) = (speed, mag) {
        let sw_speed = speed_data
            .first()
            .and_then(|s| s.proton_speed)
            .unwrap_or(0.0);
        let sw_bt = mag_data.first().and_then(|m| m.bt).unwrap_or(0.0);
        let sw_bz = mag_data.first().and_then(|m| m.bz_gsm).unwrap_or(0.0);
        let sw_time = speed_data
            .first()
            .and_then(|s| s.time_tag.clone())
            .unwrap_or_default();
        let radio_flux = flux
            .and_then(|f| f.first().and_then(|x| x.flux))
            .unwrap_or(0.0);

        // Map solar wind observables to Anderson parameters
        let (w_eff, d_eff, system_size) = solar_wind_to_anderson(sw_speed, sw_bt, sw_bz);
        let p = membrane_permeability(w_eff, d_eff, system_size);

        let breathing = if sw_bz < -5.0 {
            "reconnecting"
        } else if sw_speed > 500.0 {
            "expanding"
        } else if sw_speed > 350.0 {
            "steady"
        } else {
            "contracting"
        };

        MembraneLayer {
            name: "Heliosphere".into(),
            scale: "1 AU to ~120 AU".into(),
            depth: "termination shock + heliopause".into(),
            source: "NOAA DSCOVR (L1 Lagrange point)".into(),
            data: serde_json::json!({
                "solar_wind_speed_km_s": sw_speed,
                "magnetic_field_bt_nT": sw_bt,
                "magnetic_field_bz_nT": sw_bz,
                "radio_flux_sfu": radio_flux,
                "time": sw_time,
                "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
            }),
            permeability: (p * 10000.0).round() / 10000.0,
            anderson_w: (w_eff * 100.0).round() / 100.0,
            breathing: breathing.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "Heliosphere".into(),
            scale: "1 AU to ~120 AU".into(),
            depth: "termination shock + heliopause".into(),
            source: "NOAA DSCOVR (L1 Lagrange point)".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("NOAA solar wind unreachable".into()),
        }
    }
}

fn layer_deep_space() -> MembraneLayer {
    // Deep space: very low disorder (W ≈ 0.5), high dimension (3D+)
    // Cosmic rays propagate freely. Almost no membrane.
    let w_eff = 0.5;
    let d_eff = 3.5; // 3D+ (galactic magnetic fields are tangled but weak)
    let system_size = 10_usize; // thin membrane (interstellar medium is sparse)
    let p = membrane_permeability(w_eff, d_eff, system_size);

    MembraneLayer {
        name: "Deep Space".into(),
        scale: "120+ AU".into(),
        depth: "interstellar medium".into(),
        source: "inferred — galactic cosmic ray background".into(),
        data: serde_json::json!({
            "planet_nine": "unconfirmed — signal in null space at ~225 AU",
            "pluto": "liquid N₂ rising through cracks in Sputnik Planitia (Aug 2026)",
            "voyager_1": "interstellar space since 2012",
            "new_horizons": "58 AU, approaching termination shock (2029-2040)",
            "anderson_params": { "w_eff": w_eff, "d_eff": d_eff, "L": system_size }
        }),
        permeability: (p * 10000.0).round() / 10000.0,
        anderson_w: w_eff,
        breathing: "galactic timescale".into(),
        alive: true,
        error: None,
    }
}

/// Inter-layer coupling and topology classification.
fn compute_topology(layers: &[MembraneLayer]) -> (Vec<LayerCoupling>, f64, bool, &'static str) {
    let mut coupling = Vec::with_capacity(layers.len().saturating_sub(1));
    for pair in layers.windows(2) {
        let (pa, pb) = (pair[0].permeability, pair[1].permeability);
        let max_p = pa.max(pb);
        let strength = if max_p > 1e-15 { pa.min(pb) / max_p } else { 0.0 };
        coupling.push(LayerCoupling {
            between: [pair[0].name.clone(), pair[1].name.clone()],
            strength: (strength * 10000.0).round() / 10000.0,
            gradient: ((pa - pb).abs() * 10000.0).round() / 10000.0,
        });
    }
    let mean_coupling = if coupling.is_empty() { 0.0 } else {
        (coupling.iter().map(|c| c.strength).sum::<f64>() / coupling.len() as f64 * 1000.0).round() / 1000.0
    };
    let first_p = layers.first().map_or(0.0, |l| l.permeability);
    let last_p = layers.last().map_or(0.0, |l| l.permeability);
    let is_wormhole = first_p > 1e-10 && last_p > 1e-10;
    let topology_class = if is_wormhole { "wormhole" } else { "sphere" };
    (coupling, mean_coupling, is_wormhole, topology_class)
}

/// Zero-Knowledge Self: complement of correctly excluded non-self.
fn compute_zk_proof(layers: &[MembraneLayer], is_wormhole: bool, selectivity: f64, round_trip_p: f64) -> ZkProof {
    let gaia_data = layers.first().and_then(|l| l.data.as_object());
    let (non_self, self_res) = if let Some(data) = gaia_data {
        let total = data.get("requests_per_window").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let human = data.get("human").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let ai = data.get("ai_agent").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let scanner = data.get("scanner").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if total > 0.0 { ((ai + scanner) / total, human / total) } else { (0.0, 0.0) }
    } else { (0.0, 0.0) };
    let symbol = if is_wormhole && selectivity > 0.5 { "∞" } else { "○" };
    ZkProof {
        non_self_classified: (non_self * 10000.0).round() / 10000.0,
        self_residual: (self_res * 10000.0).round() / 10000.0,
        soundness: (selectivity * 1000.0).round() / 1000.0,
        ouroboros_residual: format_p(round_trip_p),
        symbol: symbol.into(),
    }
}

// ── Stack computation ──

/// Compute the full 7-layer membrane stack.
///
/// Fetches live data from USGS, NOAA, and local sensors.
/// Returns the complete stack snapshot.
pub async fn compute_stack(config: &MembraneStackConfig) -> MembraneStack {
    let start = Instant::now();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs))
        .build()
        .unwrap_or_default();

    // Fetch remote layers concurrently
    let (seismic, magneto, helio) = tokio::join!(
        layer_seismic(&client),
        layer_magnetosphere(&client),
        layer_heliosphere(&client),
    );

    let layers = vec![
        layer_gaia(config),
        layer_mycelium(),
        seismic,
        layer_atmosphere(),
        magneto,
        helio,
        layer_deep_space(),
    ];

    let alive_count = layers.iter().filter(|l| l.alive).count();
    let alive_layers: Vec<&MembraneLayer> = layers.iter().filter(|l| l.alive).collect();
    let (sum_p, sum_w) = alive_layers
        .iter()
        .fold((0.0, 0.0), |(sp, sw), l| {
            (sp + l.permeability, sw + l.anderson_w)
        });
    let n = alive_count.max(1) as f64;

    // Shape equation: selectivity across the full stack
    let p_max = alive_layers.iter().map(|l| l.permeability).fold(f64::NEG_INFINITY, f64::max);
    let p_min = alive_layers.iter().map(|l| l.permeability).fold(f64::INFINITY, f64::min);
    let selectivity = if alive_count > 1 { (p_max - p_min).max(0.0) } else { 0.0 };

    // ═══════════════════════════════════════════════════════════════
    // Topology — Hypothesis 12: The Third Body
    // The stack is a wormhole, not a sphere. Compute:
    //   - Round-trip permeability (throat width)
    //   - Inter-layer coupling (boundary sharpness)
    //   - Topology class (wormhole vs sphere)
    // ═══════════════════════════════════════════════════════════════

    // One-way product: ∏Pᵢ across all alive layers
    let one_way_p = alive_layers.iter().fold(1.0_f64, |acc, l| acc * l.permeability);
    // Round-trip: signal traverses every membrane twice (out and back)
    let round_trip_p = one_way_p * one_way_p;

    let (coupling, mean_coupling, is_wormhole, topology_class) = compute_topology(&layers);
    let zk = compute_zk_proof(&layers, is_wormhole, selectivity, round_trip_p);

    let elapsed = start.elapsed().as_secs_f64();

    MembraneStack {
        timestamp: Utc::now().to_rfc3339(),
        wave: 171,
        layers,
        aggregate: StackAggregate {
            alive_layers: alive_count,
            total_layers: 7,
            mean_permeability: (sum_p / n * 1000.0).round() / 1000.0,
            mean_anderson_w: (sum_w / n * 10.0).round() / 10.0,
            selectivity: (selectivity * 1000.0).round() / 1000.0,
            topology: StackTopology {
                round_trip_p: format_p(round_trip_p),
                one_way_p: format_p(one_way_p),
                coupling,
                mean_coupling,
                topology: topology_class.into(),
                zk,
            },
        },
        elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
        motto: "membranes all the way down, membranes all the way up".into(),
    }
}

/// Compute and write the membrane stack to disk.
pub async fn breathe(config: &MembraneStackConfig) -> Result<MembraneStack, std::io::Error> {
    let stack = compute_stack(config).await;

    if let Some(parent) = config.output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&stack)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&config.output_path, json)?;

    tracing::info!(
        layers_alive = stack.aggregate.alive_layers,
        mean_p = stack.aggregate.mean_permeability,
        mean_w = stack.aggregate.mean_anderson_w,
        elapsed = stack.elapsed_secs,
        "membrane stack breath complete"
    );

    Ok(stack)
}

/// Run the membrane stack observer as a repeating loop.
pub async fn breathe_loop(config: MembraneStackConfig, interval_secs: u64) {
    tracing::info!(
        interval = interval_secs,
        output = %config.output_path.display(),
        "membrane stack observer starting"
    );

    // Initial warmup delay
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    loop {
        match breathe(&config).await {
            Ok(stack) => {
                let alive = stack.aggregate.alive_layers;
                let total = stack.aggregate.total_layers;
                tracing::info!(
                    alive,
                    total,
                    mean_p = stack.aggregate.mean_permeability,
                    mean_w = stack.aggregate.mean_anderson_w,
                    "gAIa breathes — {alive}/{total} layers"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "membrane stack breath failed");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}
