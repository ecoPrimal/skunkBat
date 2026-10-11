// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BingoCube Decision Grid and Oracle — unified randomization + evolutionary learning.
//!
//! Replaces hand-rolled `% N` probability gates with a BingoCube color grid
//! that provides multi-axis deterministic decisions from (fleet_hash, path, epoch).
//!
//! The CubeOracle trait defines an IPC-ready boundary: any primal consuming
//! bingoCube gets the same interface, whether in-process or via IPC.

#![allow(missing_docs)]

use bingocube_nautilus::{
    InstanceId, NautilusShell, ReservoirInput, ShellConfig,
};

use crate::scatter_rng::CubePrng;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// CubeDecisionGrid and its enums (JitterType, ContentVariant, TenseGate,
// SortLevel) live in cube_grid.rs — the π split.
pub use crate::cube_grid::*;



// ══════════════════════════════════════════════════════════════════════
// ScatterObservation — what we learn from each fleet interaction
// ══════════════════════════════════════════════════════════════════════

/// An observation from a scatter interaction, fed to nautilus for training.
#[derive(Debug, Clone)]
pub struct ScatterObservation {
    /// Fleet identity hash.
    #[allow(dead_code)]
    pub fleet_hash: String,
    /// Epitope flags (8-bit): which behavioral markers were detected.
    pub epitope_flags: u8,
    /// Target classification (3-bit): what the fleet is trying to extract.
    pub target_class: u8,
    /// Detector bitmap (8-bit): which detectors fired.
    pub detector_bitmap: u8,
    /// Confidence score from the classifier (0.0-1.0).
    pub confidence: f64,
    /// How deep in the chain this fleet has gone.
    pub chain_depth: u8,
    /// What response type we served (for correlating with effectiveness).
    pub response_type: ResponseType,
}

/// What kind of scatter response was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResponseType {
    Normal,
    CrossType,
    PersonalityShift,
    ViolationMirror,
    Disperse,
    Honeytoken,
    TemporalPhaseout,
    TemporalGhost,
    /// Honeycomb prism — fleet team sees chimera'd data from other teams.
    Prism,
}

// ══════════════════════════════════════════════════════════════════════
// ScatterStrategy — what nautilus recommends
// ══════════════════════════════════════════════════════════════════════

/// Nautilus-predicted scatter strategy for a given fleet cluster.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScatterStrategy {
    /// Recommended jitter type weight adjustments.
    /// [0] = normal weight, [1] = cross-type weight, [2] = personality weight
    pub jitter_weights: [f64; 3],
    /// Preferred content variant indices (sorted by predicted effectiveness).
    pub content_preference: Vec<u8>,
    /// Recommended antibody chain variants (top-K).
    pub antibody_preference: Vec<u8>,
    /// Predicted amplify scale (0.0-1.0).
    pub amplify_factor: f64,
    /// Confidence in this prediction (0.0-1.0).
    /// Below threshold, caller falls back to CubeDecisionGrid.
    pub confidence: f64,
}

impl Default for ScatterStrategy {
    fn default() -> Self {
        Self {
            jitter_weights: [0.8, 0.125, 0.0625],
            content_preference: vec![0, 1, 2, 3, 4, 5],
            antibody_preference: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            amplify_factor: 0.5,
            confidence: 0.0,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// CubeOracle trait — IPC-ready boundary for any primal
// ══════════════════════════════════════════════════════════════════════

/// Trait defining how any primal consumes bingoCube for scatter decisions.
///
/// Two implementations:
/// - `InProcessOracle`: library crate, in-process (ships now)
/// - Future `IpcOracle`: JSON-RPC / tarpc client to bingoCube service
pub trait CubeOracle: Send + Sync {
    /// Create a PRNG from seed bytes (replaces XorShift64::new).
    fn roll(&self, seed: &[u8]) -> CubePrng;

    /// Create a decision grid from fleet context.
    fn decide(&self, fleet_hash: &str, path: &str, epoch: u64) -> CubeDecisionGrid;

    /// Record an observation for training.
    fn observe(&self, observation: ScatterObservation);

    /// Predict optimal strategy for fleet features.
    fn predict(&self, fleet_features: &[f64]) -> ScatterStrategy;

    /// Current generation of the nautilus shell (0 if untrained).
    fn generation(&self) -> u64;

    /// Whether the model has enough training data to make predictions.
    fn is_trained(&self) -> bool;

    /// Inject concept edges from entity_classifier topology changes.
    ///
    /// Concept edges are regions of input space where predictions fail.
    /// The nautilus shell biases new boards toward these regions during evolution.
    fn set_concept_edges(&self, edges: Vec<Vec<f64>>);

    /// Record a bloom sensor signal for training feedback.
    ///
    /// Signal rates from bloom_sensor indicate how effective scatter is
    /// at disrupting fleet behavior — high signal rates mean the fleet
    /// is persisting despite scatter, low rates mean disruption is working.
    fn record_bloom_signal(&self, fleet_hash: &str, signal_rate: f64);
}

// ══════════════════════════════════════════════════════════════════════
// InProcessOracle — library-linked implementation
// ══════════════════════════════════════════════════════════════════════

/// Observation batch size before triggering evolution.
const EVOLVE_BATCH_SIZE: usize = 100;

/// Confidence threshold below which predictions are ignored.
#[allow(dead_code)] // Nautilus integration point — used when predict() is wired to scatter serve path
const PREDICTION_CONFIDENCE_THRESHOLD: f64 = 0.3;

/// Number of targets the nautilus shell predicts:
/// [jitter_normal, jitter_cross, jitter_personality, amplify, antibody_pref]
const N_TARGETS: usize = 5;

/// Number of input features per observation:
/// [epitope_flags/255, target_class/7, detector_bitmap/255, confidence, chain_depth/255]
#[allow(dead_code)] // Nautilus integration point — used when predict() is wired to scatter serve path
const N_FEATURES: usize = 5;

/// In-process bingoCube oracle backed by bingocube-core + bingocube-nautilus.
pub(crate) struct InProcessOracle {
    /// Nautilus shell for evolutionary learning.
    shell: Mutex<NautilusShell>,
    /// Buffered observations awaiting batch evolution.
    observation_buffer: Mutex<Vec<(Vec<f64>, Vec<f64>)>>,
    /// Total observations processed.
    observation_count: AtomicU64,
    /// Path for sourdough persistence.
    persist_path: Option<PathBuf>,
}

impl InProcessOracle {
    /// Create a new oracle with a fresh nautilus shell.
    pub(crate) fn new(seed: u64) -> Self {
        let config = ShellConfig {
            population_size: 12,
            n_targets: N_TARGETS,
            ..Default::default()
        };
        let id = InstanceId::new("skunkbat-scatter");
        let shell = NautilusShell::from_seed(config, id, seed)
            .expect("nautilus shell config is valid");

        Self {
            shell: Mutex::new(shell),
            observation_buffer: Mutex::new(Vec::with_capacity(EVOLVE_BATCH_SIZE)),
            observation_count: AtomicU64::new(0),
            persist_path: None,
        }
    }

    /// Create an oracle that persists its shell to disk (sourdough pattern).
    pub(crate) fn with_persistence(seed: u64, path: PathBuf) -> Self {
        let oracle = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<NautilusShell>(&json) {
                    Ok(shell) => {
                        tracing::info!(
                            generation = shell.generation(),
                            "🧬 nautilus shell restored from sourdough"
                        );
                        Self {
                            shell: Mutex::new(shell),
                            observation_buffer: Mutex::new(Vec::with_capacity(EVOLVE_BATCH_SIZE)),
                            observation_count: AtomicU64::new(0),
                            persist_path: Some(path),
                        }
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ nautilus sourdough parse failed: {e}, starting fresh");
                        let mut o = Self::new(seed);
                        o.persist_path = Some(path);
                        o
                    }
                },
                Err(e) => {
                    tracing::warn!("⚠️ nautilus sourdough read failed: {e}, starting fresh");
                    let mut o = Self::new(seed);
                    o.persist_path = Some(path);
                    o
                }
            }
        } else {
            let mut o = Self::new(seed);
            o.persist_path = Some(path);
            o
        };
        oracle
    }

    /// Save shell to disk (sourdough).
    fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            if let Ok(shell) = self.shell.lock() {
                match serde_json::to_string(&*shell) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(path, json) {
                            tracing::warn!("⚠️ nautilus persist failed: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("⚠️ nautilus serialize failed: {e}"),
                }
            }
        }
    }

    /// Convert observation to feature vector for nautilus input.
    fn observation_to_features(obs: &ScatterObservation) -> Vec<f64> {
        vec![
            f64::from(obs.epitope_flags) / 255.0,
            f64::from(obs.target_class) / 7.0,
            f64::from(obs.detector_bitmap) / 255.0,
            obs.confidence,
            f64::from(obs.chain_depth) / 255.0,
        ]
    }

    /// Convert observation to target vector (what we want to optimize).
    ///
    /// Targets encode: how effective was the response type at disrupting this fleet?
    /// Higher values = more effective. This is a proxy; real effectiveness comes
    /// from subsequent observations of the same fleet_hash.
    fn observation_to_targets(obs: &ScatterObservation) -> Vec<f64> {
        let base_effectiveness = match obs.response_type {
            ResponseType::ViolationMirror => 0.9,
            ResponseType::PersonalityShift => 0.7,
            ResponseType::CrossType => 0.6,
            ResponseType::TemporalGhost => 0.5,
            ResponseType::TemporalPhaseout => 0.4,
            ResponseType::Honeytoken => 0.8,
            ResponseType::Prism => 0.85,
            ResponseType::Disperse => 0.3,
            ResponseType::Normal => 0.2,
        };

        // Scale by confidence — high-confidence detections mean we know what works
        let scaled = base_effectiveness * obs.confidence.max(0.1);

        vec![
            if obs.response_type == ResponseType::Normal { scaled } else { 0.0 },
            if obs.response_type == ResponseType::CrossType { scaled } else { 0.0 },
            if obs.response_type == ResponseType::PersonalityShift { scaled } else { 0.0 },
            scaled, // amplify factor proxy
            f64::from(obs.chain_depth) / 255.0 * scaled, // antibody depth effectiveness
        ]
    }
}

impl CubeOracle for InProcessOracle {
    fn roll(&self, seed: &[u8]) -> CubePrng {
        CubePrng::from_bytes(seed)
    }

    fn decide(&self, fleet_hash: &str, path: &str, epoch: u64) -> CubeDecisionGrid {
        CubeDecisionGrid::from_context(fleet_hash, path, epoch)
    }

    fn observe(&self, observation: ScatterObservation) {
        let features = Self::observation_to_features(&observation);
        let targets = Self::observation_to_targets(&observation);

        let count = self.observation_count.fetch_add(1, Ordering::Relaxed) + 1;

        if let Ok(mut buf) = self.observation_buffer.lock() {
            buf.push((features, targets));

            if buf.len() >= EVOLVE_BATCH_SIZE {
                let batch: Vec<_> = buf.drain(..).collect();
                drop(buf);

                let inputs: Vec<ReservoirInput> = batch.iter()
                    .map(|(f, _)| ReservoirInput::Continuous(f.clone()))
                    .collect();
                let targets: Vec<Vec<f64>> = batch.into_iter()
                    .map(|(_, t)| t)
                    .collect();

                if let Ok(mut shell) = self.shell.lock() {
                    match shell.evolve_generation(&inputs, &targets) {
                        Ok(mse) => {
                            tracing::info!(
                                generation = shell.generation(),
                                mse = %format!("{mse:.6}"),
                                observations = count,
                                "🧬 nautilus evolved — scatter strategy adapting"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ nautilus evolution failed: {e}");
                        }
                    }
                }

                // Persist after evolution
                self.persist();
            }
        }
    }

    fn predict(&self, fleet_features: &[f64]) -> ScatterStrategy {
        if let Ok(shell) = self.shell.lock() {
            if shell.generation() == 0 {
                return ScatterStrategy::default();
            }

            let input = ReservoirInput::Continuous(fleet_features.to_vec());
            let raw = shell.predict(&input);

            if raw.len() < N_TARGETS {
                return ScatterStrategy::default();
            }

            // Normalize jitter weights to sum to 1
            let jitter_sum = raw[0].abs() + raw[1].abs() + raw[2].abs();
            let jitter_weights = if jitter_sum > 0.0 {
                [
                    raw[0].abs() / jitter_sum,
                    raw[1].abs() / jitter_sum,
                    raw[2].abs() / jitter_sum,
                ]
            } else {
                [0.8, 0.125, 0.0625]
            };

            // Estimate confidence from generation depth + drift
            let gen_confidence = (shell.generation() as f64 / 50.0).min(1.0);
            let drift_penalty = if shell.is_drifting() { 0.5 } else { 1.0 };
            let confidence = gen_confidence * drift_penalty;

            ScatterStrategy {
                jitter_weights,
                content_preference: vec![0, 1, 2, 3, 4, 5],
                antibody_preference: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                amplify_factor: raw[3].clamp(0.0, 1.0),
                confidence,
            }
        } else {
            ScatterStrategy::default()
        }
    }

    fn generation(&self) -> u64 {
        self.shell
            .lock()
            .map(|s| s.generation() as u64)
            .unwrap_or(0)
    }

    fn is_trained(&self) -> bool {
        self.generation() > 0
    }

    fn set_concept_edges(&self, edges: Vec<Vec<f64>>) {
        if let Ok(mut shell) = self.shell.lock() {
            let edge_count = edges.len();
            shell.set_concept_edges(edges);
            tracing::info!(
                edges = edge_count,
                generation = shell.generation(),
                "🧬 concept edges injected — nautilus will bias toward failure regions"
            );
        }
    }

    fn record_bloom_signal(&self, fleet_hash: &str, signal_rate: f64) {
        // High signal rate → fleet is persisting → current strategy is failing
        // Low signal rate → fleet is disrupted → current strategy is effective
        // We encode this as a negative observation — inverse effectiveness
        let effectiveness = (1.0 - signal_rate).clamp(0.0, 1.0);
        let features = vec![
            0.0, // epitope_flags unknown from bloom alone
            0.0, // target_class unknown
            0.0, // detector_bitmap unknown
            effectiveness,
            0.0, // chain_depth unknown
        ];

        if let Ok(mut buf) = self.observation_buffer.lock() {
            let targets = vec![effectiveness; N_TARGETS];
            buf.push((features, targets));
        }

        tracing::debug!(
            fleet_hash = %fleet_hash,
            signal_rate = signal_rate,
            effectiveness = effectiveness,
            "🔬 bloom signal fed to nautilus"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
// Shared oracle instance for the scatter server
// ══════════════════════════════════════════════════════════════════════

/// Thread-safe shared oracle.
pub type SharedOracle = Arc<dyn CubeOracle>;

/// Create the default in-process oracle.
pub fn create_oracle(seed: u64, persist_path: Option<&Path>) -> SharedOracle {
    match persist_path {
        Some(path) => Arc::new(InProcessOracle::with_persistence(seed, path.to_path_buf())),
        None => Arc::new(InProcessOracle::new(seed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_grid_deterministic() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        for row in 0..5 {
            for col in 0..5 {
                assert_eq!(a.color(row, col), b.color(row, col));
            }
        }
    }

    #[test]
    fn decision_grid_varies_by_fleet() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_xyz", "/repo/blame/main.rs", 100);
        let mut diffs = 0;
        for row in 0..5 {
            for col in 0..5 {
                if a.color(row, col) != b.color(row, col) {
                    diffs += 1;
                }
            }
        }
        assert!(diffs > 5, "different fleets should get mostly different grids");
    }

    #[test]
    fn decision_grid_varies_by_epoch() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 101);
        let mut diffs = 0;
        for row in 0..5 {
            for col in 0..5 {
                if a.color(row, col) != b.color(row, col) {
                    diffs += 1;
                }
            }
        }
        assert!(diffs > 5, "different epochs should shift the grid");
    }

    #[test]
    fn jitter_type_distribution_reasonable() {
        let mut normal = 0;
        let mut cross = 0;
        let mut personality = 0;
        for i in 0..1000 {
            let grid = CubeDecisionGrid::from_context(
                &format!("fleet_{i}"), "/test", 42,
            );
            match grid.jitter_type() {
                JitterType::Normal => normal += 1,
                JitterType::CrossType => cross += 1,
                JitterType::PersonalityShift => personality += 1,
            }
        }
        // Normal should dominate, CrossType should be moderate, PersonalityShift should be rare
        assert!(normal > 700, "normal should be >70%, got {normal}/1000");
        assert!(cross > 50, "cross-type should be >5%, got {cross}/1000");
        assert!(personality > 20, "personality should be >2%, got {personality}/1000");
    }

    #[test]
    fn temporal_phase_all_values_reachable() {
        let mut seen = [false; 5];
        for i in 0..200 {
            let grid = CubeDecisionGrid::from_context(&format!("f{i}"), "/t", 1);
            let phase = grid.temporal_phase(0.1) as usize;
            assert!(phase < 5);
            seen[phase] = true;
        }
        assert!(seen.iter().all(|&s| s), "all 5 phases should be reachable");
    }

    #[test]
    fn oracle_roll_deterministic() {
        let oracle = InProcessOracle::new(42);
        let mut a = oracle.roll(b"test_seed");
        let mut b = oracle.roll(b"test_seed");
        for _ in 0..50 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn oracle_default_strategy() {
        let oracle = InProcessOracle::new(42);
        let strategy = oracle.predict(&[0.5, 0.3, 0.7, 0.8, 0.1]);
        assert_eq!(strategy.confidence, 0.0);
        assert!(!oracle.is_trained());
    }

    #[test]
    fn oracle_observe_buffers() {
        let oracle = InProcessOracle::new(42);
        for i in 0..50 {
            oracle.observe(ScatterObservation {
                fleet_hash: format!("fleet_{i}"),
                epitope_flags: (i % 256) as u8,
                target_class: (i % 7) as u8,
                detector_bitmap: (i % 256) as u8,
                confidence: (i as f64) / 50.0,
                chain_depth: (i % 10) as u8,
                response_type: ResponseType::Normal,
            });
        }
        // Not enough observations to trigger evolution
        assert_eq!(oracle.generation(), 0);
    }

    #[test]
    fn oracle_evolves_after_batch() {
        let oracle = InProcessOracle::new(42);
        for i in 0..EVOLVE_BATCH_SIZE {
            oracle.observe(ScatterObservation {
                fleet_hash: format!("fleet_{i}"),
                epitope_flags: (i % 256) as u8,
                target_class: (i % 7) as u8,
                detector_bitmap: (i % 256) as u8,
                confidence: (i as f64) / EVOLVE_BATCH_SIZE as f64,
                chain_depth: (i % 10) as u8,
                response_type: if i % 3 == 0 {
                    ResponseType::CrossType
                } else if i % 5 == 0 {
                    ResponseType::ViolationMirror
                } else {
                    ResponseType::Normal
                },
            });
        }
        assert_eq!(oracle.generation(), 1);
        assert!(oracle.is_trained());

        // Predictions should now be non-default
        let strategy = oracle.predict(&[0.5, 0.3, 0.7, 0.8, 0.1]);
        assert!(strategy.confidence > 0.0);
    }

    #[test]
    fn scalar_decision_modulus() {
        let grid = CubeDecisionGrid::from_context("test", "/path", 1);
        let val = grid.scalar_decision(3, 0, 100);
        assert!(val < 100);
    }

    // ── Row 3-4: Tense + sort dimension tests (Paper 48) ──

    #[test]
    fn tense_gate_all_values_reachable() {
        let mut seen_is = false;
        let mut seen_was = false;
        let mut seen_willbe = false;
        for i in 0..500 {
            let grid = CubeDecisionGrid::from_context(&format!("t{i}"), "/t", 1);
            match grid.tense_gate() {
                TenseGate::Is => seen_is = true,
                TenseGate::Was => seen_was = true,
                TenseGate::WillBe => seen_willbe = true,
            }
        }
        assert!(seen_is, "TenseGate::Is should be reachable");
        assert!(seen_was, "TenseGate::Was should be reachable");
        assert!(seen_willbe, "TenseGate::WillBe should be reachable");
    }

    #[test]
    fn tense_gate_distribution_reasonable() {
        let mut is_count = 0u32;
        let mut was_count = 0u32;
        let mut willbe_count = 0u32;
        for i in 0..1000 {
            let grid = CubeDecisionGrid::from_context(&format!("td{i}"), "/test", 42);
            match grid.tense_gate() {
                TenseGate::Is => is_count += 1,
                TenseGate::Was => was_count += 1,
                TenseGate::WillBe => willbe_count += 1,
            }
        }
        // Is ≈ 50%, Was ≈ 37.5%, WillBe ≈ 12.5%
        assert!(is_count > 350, "Is should be ~50%, got {is_count}/1000");
        assert!(was_count > 200, "Was should be ~37.5%, got {was_count}/1000");
        assert!(willbe_count > 50, "WillBe should be ~12.5%, got {willbe_count}/1000");
    }

    #[test]
    fn sort_level_all_values_reachable() {
        let mut seen_alpha = false;
        let mut seen_epitope = false;
        let mut seen_tense = false;
        for i in 0..500 {
            let grid = CubeDecisionGrid::from_context(&format!("s{i}"), "/s", 1);
            match grid.sort_level() {
                SortLevel::Alphabetic => seen_alpha = true,
                SortLevel::Epitope => seen_epitope = true,
                SortLevel::Tense => seen_tense = true,
            }
        }
        assert!(seen_alpha, "SortLevel::Alphabetic should be reachable");
        assert!(seen_epitope, "SortLevel::Epitope should be reachable");
        assert!(seen_tense, "SortLevel::Tense should be reachable");
    }

    #[test]
    fn sort_level_distribution_reasonable() {
        let mut alpha = 0u32;
        let mut epitope = 0u32;
        let mut tense = 0u32;
        for i in 0..1000 {
            let grid = CubeDecisionGrid::from_context(&format!("sd{i}"), "/test", 42);
            match grid.sort_level() {
                SortLevel::Alphabetic => alpha += 1,
                SortLevel::Epitope => epitope += 1,
                SortLevel::Tense => tense += 1,
            }
        }
        // Alphabetic ≈ 50%, Epitope ≈ 31.25%, Tense ≈ 18.75%
        assert!(alpha > 350, "Alphabetic should be ~50%, got {alpha}/1000");
        assert!(epitope > 150, "Epitope should be ~31.25%, got {epitope}/1000");
        assert!(tense > 80, "Tense should be ~18.75%, got {tense}/1000");
    }

    #[test]
    fn tense_invert_is_rare() {
        let inverted: u32 = (0..1000)
            .filter(|i| {
                CubeDecisionGrid::from_context(&format!("inv{i}"), "/test", 42).tense_invert()
            })
            .count() as u32;
        // 12.5% expected
        assert!(inverted > 50, "inversion should be ~12.5%, got {inverted}/1000");
        assert!(inverted < 250, "inversion should be rare, got {inverted}/1000");
    }

    #[test]
    fn tense_depth_and_grain_full_range() {
        let mut depths = std::collections::HashSet::new();
        let mut grains = std::collections::HashSet::new();
        for i in 0..2000 {
            let grid = CubeDecisionGrid::from_context(&format!("rng{i}"), "/r", 1);
            depths.insert(grid.tense_depth());
            grains.insert(grid.sort_grain());
        }
        // Should hit most of the 0-15 range
        assert!(depths.len() >= 12, "tense_depth should cover most of 0-15, got {} unique values", depths.len());
        assert!(grains.len() >= 12, "sort_grain should cover most of 0-15, got {} unique values", grains.len());
    }
}
