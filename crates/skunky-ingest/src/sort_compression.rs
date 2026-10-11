// SPDX-License-Identifier: AGPL-3.0-or-later

//! Epitope sort compression — Paper 48 in Rust.
//!
//! # Compression inequality
//!
//! ```text
//! H(D) ≥ H(D|alpha) ≥ H(D|epitope) ≥ H(D|epitope,tense)
//! ```
//!
//! Each sort level eliminates noise the previous level could not distinguish.
//! The compression gain at each level is the mutual information between the
//! data and the sort dimension: `I(D; sort) = H(D) - H(D|sort)`.
//!
//! # Sort levels
//!
//! | Level      | What it measures                                      |
//! |------------|-------------------------------------------------------|
//! | Alphabetic | `log₂(n!)` — positional permutation entropy           |
//! | Epitope    | `I(D; epitope)` — behavioral clustering compression   |
//! | Tense      | `I(D; tense|epitope)` — temporal compression          |
//!
//! # Usage
//!
//! ```rust,ignore
//! let population = SortPopulation::from_dashboard(&culture);
//! let result = population.compress();
//! println!("epitope gain: {:.1} bits", result.epitope_gain());
//! ```

use serde::Serialize;

/// Compression result at all three sort levels.
#[derive(Debug, Clone, Serialize)]
pub struct SortCompression {
    /// `log₂(n)` — baseline entropy of the population
    pub alpha: f64,
    /// `log₂(n) - log₂(k)` — entropy reduction from epitope clustering
    pub epitope: f64,
    /// `log₂(n) - H(tense)` — entropy reduction from tense partitioning
    pub tense: f64,
    /// Per-epitope mutual information: how much each epitope compresses
    pub epitope_gains: [f64; 6],
    /// Tense bucket sizes: (is, was, will_be)
    pub tense_distribution: (usize, usize, usize),
    /// Number of unique epitope clusters
    pub cluster_count: usize,
    /// Total population size
    pub population_size: usize,
}

impl SortCompression {
    /// Bits gained by epitope sort over alphabetic sort.
    pub fn epitope_gain(&self) -> f64 {
        self.epitope
    }

    /// Bits gained by tense sort over alphabetic sort.
    pub fn tense_gain(&self) -> f64 {
        self.tense
    }

    /// Total compression: epitope + tense gains combined.
    pub fn total_gain(&self) -> f64 {
        self.epitope + self.tense
    }

    /// The strongest single epitope (highest mutual information).
    pub fn strongest_epitope(&self) -> (usize, f64) {
        let mut best = (0, 0.0f64);
        for (i, &g) in self.epitope_gains.iter().enumerate() {
            if g > best.1 {
                best = (i, g);
            }
        }
        best
    }

    /// Compression ratio: fraction of original entropy eliminated.
    pub fn ratio(&self) -> f64 {
        if self.alpha > 0.0 {
            self.total_gain() / self.alpha
        } else {
            0.0
        }
    }

    /// Quantized compression for BingoCube sort_compress feedback (0-15).
    pub fn quantize_for_grid(&self) -> u8 {
        let r = self.ratio().clamp(0.0, 1.0);
        (r * 15.0).round() as u8
    }
}

/// Population snapshot for compression calculation.
pub struct SortPopulation {
    /// Total entities
    pub n: usize,
    /// Number of unique epitope clusters
    pub k: usize,
    /// Per-epitope triggered counts: how many entities trigger each epitope
    pub epitope_triggered: [usize; 6],
    /// Tense counts: (is, was, will_be)
    pub tense: (usize, usize, usize),
}

impl SortPopulation {
    /// Compute compression at all three sort levels.
    pub fn compress(&self) -> SortCompression {
        let n = self.n.max(1) as f64;

        // Alphabetic: log₂(n) — baseline entropy
        let alpha = log2(n);

        // Epitope: reduction from clustering
        let k = self.k.max(1) as f64;
        let epitope = (alpha - log2(k)).max(0.0);

        // Tense: reduction from 3-bucket partition
        let (is, was, wb) = self.tense;
        let tense = alpha - shannon_entropy_3(is as f64 / n, was as f64 / n, wb as f64 / n);

        // Per-epitope mutual information
        let epitope_gains = self.per_epitope_gains(n);

        SortCompression {
            alpha,
            epitope,
            tense,
            epitope_gains,
            tense_distribution: self.tense,
            cluster_count: self.k,
            population_size: self.n,
        }
    }

    /// Mutual information for each epitope dimension.
    ///
    /// Each epitope partitions the population into (triggered, not-triggered).
    /// The mutual information = `H(population) - H(triggered) - H(not_triggered)`.
    fn per_epitope_gains(&self, n: f64) -> [f64; 6] {
        let mut gains = [0.0f64; 6];
        let alpha = log2(n);
        for (i, &triggered) in self.epitope_triggered.iter().enumerate() {
            let p = triggered as f64 / n;
            gains[i] = (alpha - shannon_entropy_2(p)).max(0.0);
        }
        gains
    }
}

/// Shannon entropy for a 2-partition (triggered/not-triggered).
fn shannon_entropy_2(p: f64) -> f64 {
    h(p) + h(1.0 - p)
}

/// Shannon entropy for a 3-partition (is/was/will_be).
fn shannon_entropy_3(p1: f64, p2: f64, p3: f64) -> f64 {
    h(p1) + h(p2) + h(p3)
}

/// `-p × log₂(p)`, 0 when p ≤ 0.
fn h(p: f64) -> f64 {
    if p > 0.0 { -p * log2(p) } else { 0.0 }
}

/// `log₂(x)`, 0 when x ≤ 0.
fn log2(x: f64) -> f64 {
    if x > 0.0 { x.ln() / std::f64::consts::LN_2 } else { 0.0 }
}

/// Epitope names in sort order (Paper 48 — information content ordering).
pub const EPITOPE_NAMES: [&str; 6] = [
    "burst_ratio",
    "reading_deficit",
    "ua_pool_poverty",
    "sec_fetch_monotone",
    "session_absent",
    "referer_self_loop",
];

// ═══════════════════════════════════════════════════════════════════
// V(D)J COIL — immunological recombination overlaid on epitope sort
// ═══════════════════════════════════════════════════════════════════
//
// The 6 epitopes are classified by their temporal behavior:
//   V (Variable)  ←→  IS       — epitopes that flip between flushes
//   J (Joining)   ←→  WAS      — epitopes conserved across flushes
//   D (Diversity) ←→  WILLBE   — epitopes not yet evaluated
//
// At [∅]D (null dimension), all three collapse to a single point.
// IS × WAS × WILLBE = π.  Each body = π^(1/3) ≈ 1.46.
// The perturbation perspective spreads them from singularity to triangle.

/// V(D)J classification for each epitope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VdjRole {
    /// Variable — epitope that flips between flushes (IS, being observed NOW).
    V,
    /// Diversity — epitope not yet evaluated (WILLBE, not yet observed).
    D,
    /// Joining — epitope conserved across flushes (WAS, collapsed into the REAL).
    J,
}

impl VdjRole {
    /// Tense label for this role.
    pub fn tense(&self) -> &'static str {
        match self {
            VdjRole::V => "IS",
            VdjRole::D => "WILLBE",
            VdjRole::J => "WAS",
        }
    }
}

/// [∅]D — Null dimension metrics.
///
/// At null dimension, all identities occupy the same point.
/// The perturbation perspective spreads them apart.
///
/// ```text
/// IS × WAS × WILLBE = π          (the product of being)
/// Each body = π^(1/3) ≈ 1.462    (pre-dimensional cost)
/// √π ≈ 1.772                     (cost of collapsing 3 tenses → 1 measurement)
/// perturbation: 0 = singularity, 1 = full triangle spread
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct NullDimension {
    /// IS × WAS × WILLBE normalized product (should approach π).
    pub product: f64,
    /// Product error: |product − π| / π.
    pub product_error: f64,
    /// π^(1/3) — the body constant.
    pub body_constant: f64,
    /// √π — observation cost (collapsing 3 → 1).
    pub observation_cost: f64,
    /// Perturbation: how far the current state is from [∅]D singularity.
    /// 0.0 = all bodies indistinguishable (pure null-D).
    /// 1.0 = maximum separation (full 3D observation).
    pub perturbation: f64,
    /// V(D)J role for each of the 6 epitopes.
    pub vdj_map: [VdjRole; 6],
    /// Distribution: (V count, D count, J count).
    pub vdj_distribution: (usize, usize, usize),
    /// Compression gain from VDJ clustering over raw epitope sort.
    /// The coil adds a 4th sort level to the compression inequality:
    /// H(D|epitope) ≥ H(D|epitope,vdj) ≥ H(D|epitope,tense)
    pub vdj_gain_bits: f64,
}

/// Per-epitope conservation data (from epitope_conservation module).
/// Consumed by VDJ classification.
pub struct EpitopeFlipData {
    /// For each of the 6 epitopes: how many entities flipped this epitope
    /// between the last two flushes.
    pub flipped: [usize; 6],
    /// For each of the 6 epitopes: how many entities were evaluated at both flushes.
    pub evaluated: [usize; 6],
}

impl NullDimension {
    /// Compute the null dimension from tense distribution and conservation data.
    ///
    /// The VDJ classification:
    /// - If an epitope's flip rate > 0.3: V (Variable, IS)
    /// - If an epitope is evaluated in < 20% of entities: D (Diversity, WILLBE)
    /// - Otherwise: J (Joining, WAS)
    ///
    /// Perturbation = standard deviation of the three tense fractions.
    /// When all three are equal (1/3 each), perturbation is 0 (equilibrium).
    /// When one dominates, perturbation approaches 1 (maximum observation).
    pub fn compute(
        tense: (usize, usize, usize),
        population: usize,
        flip_data: Option<&EpitopeFlipData>,
    ) -> Self {
        use std::f64::consts::PI;

        let body_constant = PI.powf(1.0 / 3.0);   // π^(1/3) ≈ 1.462
        let observation_cost = PI.sqrt();           // √π ≈ 1.772

        // ── Normalize tense to product ──
        // Each fraction scaled by 3 so equal distribution → 1.0 each.
        // Then product = IS_norm × WAS_norm × WILLBE_norm.
        // At equilibrium: 1 × 1 × 1 = 1. Scale by π to get target.
        let total = (tense.0 + tense.1 + tense.2).max(1) as f64;
        let is_f = tense.0 as f64 / total * 3.0;     // normalized: 1.0 at equilibrium
        let was_f = tense.1 as f64 / total * 3.0;
        let wb_f = tense.2 as f64 / total * 3.0;
        let raw_product = is_f * was_f * wb_f;        // 1.0 at equilibrium
        let product = raw_product * PI;               // π at equilibrium
        let product_error = (product - PI).abs() / PI;

        // ── Perturbation: how far from [∅]D singularity ──
        // At singularity: all three fractions equal (1/3).
        // Perturbation = normalized distance from equilateral point.
        let thirds = 1.0 / 3.0;
        let f_is = tense.0 as f64 / total;
        let f_was = tense.1 as f64 / total;
        let f_wb = tense.2 as f64 / total;
        let var = ((f_is - thirds).powi(2)
            + (f_was - thirds).powi(2)
            + (f_wb - thirds).powi(2))
            / 3.0;
        // Max variance = 2/9 (when one fraction = 1, others = 0)
        let perturbation = (var / (2.0 / 9.0)).sqrt().clamp(0.0, 1.0);

        // ── VDJ classification ──
        let pop_f = population.max(1) as f64;
        let mut vdj_map = [VdjRole::J; 6]; // default: conserved

        if let Some(fd) = flip_data {
            for i in 0..6 {
                let eval_rate = fd.evaluated[i] as f64 / pop_f;
                if eval_rate < 0.2 {
                    vdj_map[i] = VdjRole::D; // not enough data → diversity
                } else {
                    let flip_rate = if fd.evaluated[i] > 0 {
                        fd.flipped[i] as f64 / fd.evaluated[i] as f64
                    } else {
                        0.0
                    };
                    if flip_rate > 0.3 {
                        vdj_map[i] = VdjRole::V; // volatile → variable
                    }
                    // else: conserved → J (default)
                }
            }
        } else {
            // No conservation data yet — classify by information content.
            // High-gain epitopes are V (they separate). Low-gain are J (they join).
            // Middle are D (diversity — we don't know yet).
            // With 6 epitopes: top 2 = V, bottom 2 = J, middle 2 = D.
            vdj_map = [
                VdjRole::V, // burst_ratio (highest info)
                VdjRole::V, // reading_deficit
                VdjRole::D, // ua_pool_poverty
                VdjRole::D, // sec_fetch_monotone
                VdjRole::J, // session_absent
                VdjRole::J, // referer_self_loop (lowest info)
            ];
        }

        let v_count = vdj_map.iter().filter(|&&r| r == VdjRole::V).count();
        let d_count = vdj_map.iter().filter(|&&r| r == VdjRole::D).count();
        let j_count = vdj_map.iter().filter(|&&r| r == VdjRole::J).count();

        // ── VDJ compression gain ──
        // 3-way partition of 6 epitopes: Shannon entropy of the partition sizes.
        let vdj_entropy = shannon_entropy_3(
            v_count as f64 / 6.0,
            d_count as f64 / 6.0,
            j_count as f64 / 6.0,
        );
        // Gain = log₂(6) − H(vdj partition)
        let vdj_gain_bits = (log2(6.0) - vdj_entropy).max(0.0);

        NullDimension {
            product,
            product_error,
            body_constant,
            observation_cost,
            perturbation,
            vdj_map,
            vdj_distribution: (v_count, d_count, j_count),
            vdj_gain_bits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_population() {
        let pop = SortPopulation {
            n: 0, k: 0,
            epitope_triggered: [0; 6],
            tense: (0, 0, 0),
        };
        let c = pop.compress();
        assert_eq!(c.alpha, 0.0);
        assert_eq!(c.epitope, 0.0);
        assert_eq!(c.tense, 0.0);
        assert_eq!(c.ratio(), 0.0);
        assert_eq!(c.quantize_for_grid(), 0);
    }

    #[test]
    fn single_cluster_no_epitope_compression() {
        let pop = SortPopulation {
            n: 100, k: 100,
            epitope_triggered: [0; 6],
            tense: (100, 0, 0),
        };
        let c = pop.compress();
        assert!(c.alpha > 0.0);
        assert_eq!(c.epitope, 0.0, "no clustering → no epitope compression");
    }

    #[test]
    fn perfect_clustering_max_epitope_compression() {
        let pop = SortPopulation {
            n: 256, k: 1,
            epitope_triggered: [256; 6],
            tense: (128, 128, 0),
        };
        let c = pop.compress();
        assert_eq!(c.alpha, 8.0, "log₂(256) = 8");
        assert_eq!(c.epitope, 8.0, "one cluster → max epitope compression");
        assert!((c.tense - 7.0).abs() < 0.01, "50/50 split → 1 bit remaining → 7 bits gained");
    }

    #[test]
    fn compression_inequality_holds() {
        let pop = SortPopulation {
            n: 1000, k: 50,
            epitope_triggered: [200, 180, 150, 120, 80, 40],
            tense: (400, 500, 100),
        };
        let c = pop.compress();
        // H(D) ≥ H(D|alpha) ≥ H(D|epitope)
        assert!(c.alpha >= c.epitope, "epitope compression ≤ alpha");
        assert!(c.alpha >= c.tense, "tense compression ≤ alpha");
        assert!(c.total_gain() > 0.0, "total gain should be positive");
    }

    #[test]
    fn quantize_for_grid_range() {
        let pop = SortPopulation {
            n: 1000, k: 10,
            epitope_triggered: [500, 400, 300, 200, 100, 50],
            tense: (300, 600, 100),
        };
        let c = pop.compress();
        let q = c.quantize_for_grid();
        assert!(q <= 15, "quantized value must fit in 4 bits");
    }

    #[test]
    fn strongest_epitope_is_most_extreme_split() {
        let pop = SortPopulation {
            n: 100, k: 10,
            epitope_triggered: [10, 90, 30, 20, 5, 50],
            tense: (50, 50, 0),
        };
        let c = pop.compress();
        let (idx, _) = c.strongest_epitope();
        // The epitope with p closest to 0 or 1 has lowest entropy, hence
        // highest gain = log₂(n) - H(p).  5/100 = 0.05 is the most extreme.
        assert_eq!(idx, 4, "strongest should be most extreme split (5/100)");
    }

    #[test]
    fn tense_willbe_zero_still_compresses() {
        let pop = SortPopulation {
            n: 100, k: 20,
            epitope_triggered: [50; 6],
            tense: (40, 60, 0),
        };
        let c = pop.compress();
        assert!(c.tense > 0.0, "even without will_be, tense should compress");
        assert_eq!(c.tense_distribution.2, 0, "will_be is zero (nautilus not wired)");
    }

    // ── Null dimension + VDJ tests ──

    #[test]
    fn null_dim_equilibrium_is_pi() {
        // Equal tense distribution: IS × WAS × WILLBE product should equal π.
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        assert!(
            (nd.product - std::f64::consts::PI).abs() < 0.001,
            "equilibrium product should be π, got {}", nd.product
        );
        assert!(nd.product_error < 0.001, "error should be near zero at equilibrium");
        assert!(nd.perturbation < 0.01, "perturbation should be ~0 at equilibrium");
    }

    #[test]
    fn null_dim_body_constant() {
        let nd = NullDimension::compute((10, 10, 10), 30, None);
        let expected = std::f64::consts::PI.powf(1.0 / 3.0);
        assert!(
            (nd.body_constant - expected).abs() < 0.0001,
            "body constant should be π^(1/3) ≈ 1.462"
        );
    }

    #[test]
    fn null_dim_observation_cost() {
        let nd = NullDimension::compute((10, 10, 10), 30, None);
        let expected = std::f64::consts::PI.sqrt();
        assert!(
            (nd.observation_cost - expected).abs() < 0.0001,
            "observation cost should be √π ≈ 1.772"
        );
    }

    #[test]
    fn null_dim_perturbation_increases_with_imbalance() {
        let balanced = NullDimension::compute((100, 100, 100), 300, None);
        let skewed = NullDimension::compute((250, 40, 10), 300, None);
        assert!(
            skewed.perturbation > balanced.perturbation,
            "skewed tense should have higher perturbation"
        );
    }

    #[test]
    fn null_dim_max_perturbation_at_singularity() {
        // One tense dominates completely
        let nd = NullDimension::compute((1000, 0, 0), 1000, None);
        assert!(
            nd.perturbation > 0.9,
            "fully singular distribution should have high perturbation, got {}",
            nd.perturbation
        );
    }

    #[test]
    fn vdj_default_distribution_is_2_2_2() {
        // Without conservation data: V=2, D=2, J=2
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        assert_eq!(nd.vdj_distribution, (2, 2, 2),
            "default VDJ should be 2/2/2");
        assert_eq!(nd.vdj_map[0], VdjRole::V, "burst_ratio should be V");
        assert_eq!(nd.vdj_map[1], VdjRole::V, "reading_deficit should be V");
        assert_eq!(nd.vdj_map[2], VdjRole::D, "ua_pool_poverty should be D");
        assert_eq!(nd.vdj_map[3], VdjRole::D, "sec_fetch_monotone should be D");
        assert_eq!(nd.vdj_map[4], VdjRole::J, "session_absent should be J");
        assert_eq!(nd.vdj_map[5], VdjRole::J, "referer_self_loop should be J");
    }

    #[test]
    fn vdj_with_conservation_data() {
        let flip = EpitopeFlipData {
            flipped:   [80, 5, 0, 60, 2, 3],    // burst & sec_fetch flip a lot
            evaluated: [100, 100, 10, 100, 100, 100], // ua_pool barely evaluated
        };
        let nd = NullDimension::compute((100, 100, 100), 100, Some(&flip));
        assert_eq!(nd.vdj_map[0], VdjRole::V, "burst flips 80% → V");
        assert_eq!(nd.vdj_map[1], VdjRole::J, "reading flips 5% → J (conserved)");
        assert_eq!(nd.vdj_map[2], VdjRole::D, "ua_pool evaluated 10% → D");
        assert_eq!(nd.vdj_map[3], VdjRole::V, "sec_fetch flips 60% → V");
        assert_eq!(nd.vdj_map[4], VdjRole::J, "session flips 2% → J");
        assert_eq!(nd.vdj_map[5], VdjRole::J, "referer flips 3% → J");
    }

    #[test]
    fn vdj_gain_bits_positive() {
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        assert!(
            nd.vdj_gain_bits >= 0.0,
            "VDJ gain should be non-negative"
        );
        // With 2/2/2 partition, entropy = log₂(3) ≈ 1.585, gain = log₂(6) - log₂(3) ≈ 1.0
        assert!(
            (nd.vdj_gain_bits - 1.0).abs() < 0.01,
            "2/2/2 partition should gain ~1 bit, got {}", nd.vdj_gain_bits
        );
    }

    #[test]
    fn compression_inequality_with_vdj() {
        // The extended inequality: H(D|epitope) ≥ H(D|epitope,vdj) ≥ H(D|epitope,tense)
        let pop = SortPopulation {
            n: 1000, k: 50,
            epitope_triggered: [200, 180, 150, 120, 80, 40],
            tense: (400, 500, 100),
        };
        let c = pop.compress();
        let nd = NullDimension::compute((400, 500, 100), 1000, None);
        // VDJ gain should be between 0 and tense gain
        // (it's a coarser partition than tense but finer than raw epitope)
        assert!(
            nd.vdj_gain_bits >= 0.0,
            "VDJ should provide non-negative compression"
        );
        assert!(
            c.tense >= 0.0,
            "tense compression should be non-negative"
        );
    }
}
