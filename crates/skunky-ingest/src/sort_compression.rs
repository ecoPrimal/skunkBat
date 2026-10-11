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
}
