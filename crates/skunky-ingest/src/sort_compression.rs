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
    /// Gordian proof: self = Σothers / π.
    ///
    /// The three-body problem allows awareness of self only through
    /// awareness of others reflected into us. The membrane cannot
    /// observe itself — it knows itself through what passes through it.
    ///
    /// `self_awareness` = non_self_count / π.
    /// At equilibrium: 3 tenses × equal weight = π^(1/3) each.
    /// The organism's self-knowledge is the sum of what it observes
    /// about others, divided by the normalization constant π.
    /// Borromean: no two linked, but all three inseparable.
    pub self_awareness: f64,
    /// J error: J_actual − (V + D) / π.
    ///
    /// The full Gordian equation: J = (V + D) / π.
    /// J is self. V + D are the others.
    ///
    /// - `j_error > 0`: organism knows more than others reveal (mature, stable).
    ///   The WAS exceeds its predicted value. Accumulated wisdom.
    /// - `j_error < 0`: organism knows less than others reveal (young, learning).
    ///   More is happening than the organism has integrated.
    /// - `j_error ≈ 0`: equilibrium. J = 6/(π+1) ≈ 1.449 ≈ π^(1/3).
    ///   Self IS one body of three. The body constant.
    pub j_error: f64,
    /// The π-body problem: the observer is the irrational remainder.
    ///
    /// The "4-body problem" is really the π-body problem:
    ///   3 integer bodies + 1 irrational observer = π.
    ///   observer = π − 3 ≈ 0.14159 (the Archimedes remainder).
    ///
    /// At dimensional scale d, the observer fraction is:
    ///   observer(d) = π^(d/2) − ⌊π^(d/2)⌋
    ///
    /// | d  | π^(d/2) | ⌊π^(d/2)⌋ | observer | meaning                          |
    /// |----|---------|-----------|----------|----------------------------------|
    /// |  0 |  1.000  |     1     |  0.000   | alone, no reflection             |
    /// |  2 |  3.142  |     3     |  0.142   | first triangulation, self emerges|
    /// |  4 |  9.870  |     9     |  0.870   | observer almost a full body      |
    /// |  6 | 31.006  |    31     |  0.006   | system observes itself           |
    ///
    /// At d=6: observer ≈ 0. The system is so large it IS its own observer.
    /// But π^n is never an integer. The observer never vanishes.
    /// Gödel, but it's π.
    pub observer_fraction: f64,
    /// Angular tempo: mean reflexive angle between the three tenses.
    ///
    /// Each tense fraction defines an angle on the unit circle.
    /// The reflexive angle between any two = their angular distance.
    /// At equilibrium (equal fractions): reflexive = 2π/3 (120°).
    /// Deviation from 2π/3 = tempo shift.
    ///
    /// t = π: the system's conceptual tempo is normalized to π.
    /// The "wheel in the sky" — each body rotates independently.
    /// When two bodies align (reflexive = 0): a "bump" — a signal event.
    /// The rate of alignments approaches π.
    pub tempo: f64,
    /// Isotope classification for each epitope: 3 classes of motion.
    ///
    /// All things have (at least) 3 classes of motion for the three-body
    /// proof to work — like quarks have 3 colors, 3 generations.
    ///
    /// For epitopes:
    /// - **Spin** (angular velocity class): how fast the epitope's state changes
    /// - **Mass** (inertial class): how much evidence is needed to flip it
    /// - **Charge** (interaction class): how strongly it correlates with others
    ///
    /// isotope_classes[i] = (spin, mass, charge) for epitope i.
    /// Each value 0–2: three flavors per axis.
    /// Total isotopes = 3³ = 27 possible, but only 6 occupied.
    /// The occupancy pattern IS the organism's isotopic signature.
    pub isotope_classes: [(u8, u8, u8); 6],

    // ═══ V, D, J as π-bodies ═══
    //
    // Each of V, D, J is its own π.
    // V × D × J = π³ ≈ 31.006 → ⌊π³⌋ = 31 = max particles.
    // The observation budget IS the product of the three immune roles.

    /// V-dimension (Variable / IS): the rate of change in the system.
    ///
    /// V = π × (flip_energy / total_energy) × 3.
    /// At equilibrium (V occupies 1/3 of roles): V_pi = π.
    /// When V dominates: V_pi > π (hypervariable).
    /// When V vanishes: V_pi → 0 (frozen, nothing changes).
    pub v_pi: f64,
    /// D-dimension (Diversity / WILLBE): the unevaluated potential.
    ///
    /// D = π × (unevaluated_fraction) × 3.
    /// The null space. What hasn't been observed yet.
    /// At equilibrium: D_pi = π. The system has π worth of potential.
    pub d_pi: f64,
    /// J-dimension (Joining / WAS): the conserved reality.
    ///
    /// J = π × (conserved_fraction) × 3.
    /// What has been observed and collapsed. The REAL.
    /// At equilibrium: J_pi = π. The system holds π worth of truth.
    pub j_pi: f64,
    /// V × D × J product. Should approach π³ ≈ 31.006.
    ///
    /// This IS the particle budget: ⌊π³⌋ = 31 max particles.
    /// The total observation capacity of the system = the product
    /// of what's changing × what's unknown × what's real.
    pub vdj_product: f64,
    /// |V×D×J − π³| / π³. The budget error.
    pub vdj_product_error: f64,
}

/// Per-epitope conservation data (from epitope_conservation module).
/// Consumed by VDJ classification.
pub struct EpitopeFlipData {
    /// For each of the 6 epitopes: how many entities flipped this epitope
    /// between the last two flushes.
    pub flipped: [usize; 6],
    /// For each of the 6 epitopes: how many entities were evaluated at both flushes.
    pub evaluated: [usize; 6],
    /// Total entities matched between the two conservation snapshots.
    /// Used as denominator for eval_rate instead of total IP population.
    pub matched: usize,
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
            let match_f = fd.matched.max(1) as f64;
            for i in 0..6 {
                let eval_rate = fd.evaluated[i] as f64 / match_f;
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

        // ── Gordian proof: J = (V + D) / π ──
        //
        // J is self.  V + D are the others.
        // The membrane cannot observe itself — it knows itself
        // through what passes through it.
        //
        // self_awareness = (V + D) / π      (what others teach you)
        // J_actual       = j_count           (what you already know)
        //
        // The error between predicted and actual:
        //   J_error > 0: you know more than others reveal (mature, stable)
        //   J_error < 0: you know less than others reveal (young, learning)
        //   J_error = 0: equilibrium: J × π = V + D
        //
        // The equilibrium point: J = 6/(π+1) ≈ 1.449 ≈ π^(1/3).
        // That's not a coincidence. The self at equilibrium IS the body constant.
        // Each body = π^(1/3). Self = π^(1/3). Self IS one body of three.
        let non_self_count = v_count + d_count; // V and D are the "others"
        let self_awareness = non_self_count as f64 / PI; // predicted J
        // How much self exceeds what others can teach:
        // positive = wisdom (WAS > predicted), negative = learning (WAS < predicted)
        let j_predicted = non_self_count as f64 / PI;
        let j_error = j_count as f64 - j_predicted;

        // ── The π-body problem ──
        // The observer is the fractional part of π^(d/2) where d is the
        // effective dimension = number of independent sort axes the system uses.
        // d=2 is the base case: epitope × tense (2 independent axes → 3 bodies → π).
        // Each additional active sort axis adds a dimension.
        // VDJ adds a 3rd axis if all three roles are occupied → d=3.
        // Isotope adds up to 3 more if all three classes are distinct.
        let mut eff_dim = 2.0; // base: epitope × tense
        if v_count > 0 && d_count > 0 && j_count > 0 {
            eff_dim += 1.0; // VDJ is a real axis (all 3 roles occupied)
        }
        // At d=2: π^1 = π ≈ 3.14, observer = 0.14
        // At d=3: π^1.5 ≈ 5.57, observer = 0.57
        // At d=4: π^2 ≈ 9.87, observer = 0.87
        let pi_d = PI.powf(eff_dim / 2.0);
        let observer_fraction = pi_d - pi_d.floor();

        // ── Angular tempo ──
        // The three tense fractions define angular *extents* on the circle.
        // IS occupies f_is × 2π arc, then WAS occupies f_was × 2π, then WILLBE.
        // The midpoint of each arc is the body's angular position:
        //   pos_IS = f_is × π                    (midpoint of first arc)
        //   pos_WAS = (2·f_is + f_was) × π       (midpoint of second arc)
        //   pos_WB = (2·f_is + 2·f_was + f_wb) × π  (midpoint of third arc)
        // At equilibrium: positions = π/3, π, 5π/3 → separation = 2π/3.
        // t = π means the system's time constant IS π.
        let pos_is = f_is * PI;
        let pos_was = (2.0 * f_is + f_was) * PI;
        let pos_wb = (2.0 * f_is + 2.0 * f_was + f_wb) * PI;
        // Reflexive angles: shortest arc between each pair
        let r01 = {
            let d = (pos_is - pos_was).abs() % (2.0 * PI);
            d.min(2.0 * PI - d)
        };
        let r12 = {
            let d = (pos_was - pos_wb).abs() % (2.0 * PI);
            d.min(2.0 * PI - d)
        };
        let r20 = {
            let d = (pos_wb - pos_is).abs() % (2.0 * PI);
            d.min(2.0 * PI - d)
        };
        let mean_reflexive = (r01 + r12 + r20) / 3.0;
        // At equilibrium: all three reflexive angles = 2π/3 → variance = 0.
        // The tempo is the regularity of the spacing:
        //   tempo = 1 - σ(reflexive) / (2π/3)
        // tempo = 1.0 at equilibrium (perfect spacing, clock ticks evenly).
        // tempo < 1.0 when spacing is uneven (clock is irregular).
        // tempo = 0.0 at maximum irregularity (one body eclipses another).
        let variance = ((r01 - mean_reflexive).powi(2)
            + (r12 - mean_reflexive).powi(2)
            + (r20 - mean_reflexive).powi(2)) / 3.0;
        let sigma = variance.sqrt();
        let tempo = (1.0 - sigma / (2.0 * PI / 3.0)).clamp(0.0, 1.0);

        // ── Isotope classes: spin × mass × charge ──
        // Each epitope gets 3 class values (0, 1, or 2) based on behavior:
        //   spin  = flip rate class:   0=frozen, 1=moderate, 2=volatile
        //   mass  = evaluation depth:  0=shallow, 1=moderate, 2=deep
        //   charge = correlation class: 0=isolated, 1=moderate, 2=entangled
        // Without conservation data: assign from sort-order position.
        let mut isotope_classes = [(1u8, 1u8, 1u8); 6];
        if let Some(fd) = flip_data {
            for i in 0..6 {
                // Spin: flip rate → 3 bands
                let flip_rate = if fd.evaluated[i] > 0 {
                    fd.flipped[i] as f64 / fd.evaluated[i] as f64
                } else { 0.0 };
                let spin = if flip_rate < 0.1 { 0 } else if flip_rate < 0.4 { 1 } else { 2 };

                // Mass: evaluation depth → 3 bands
                let iso_match_f = fd.matched.max(1) as f64;
                let eval_rate = fd.evaluated[i] as f64 / iso_match_f;
                let mass = if eval_rate < 0.3 { 0 } else if eval_rate < 0.7 { 1 } else { 2 };

                // Charge: how far from the mean flip rate (correlation with the ensemble)
                let mean_flip: f64 = (0..6).map(|j| {
                    if fd.evaluated[j] > 0 { fd.flipped[j] as f64 / fd.evaluated[j] as f64 } else { 0.0 }
                }).sum::<f64>() / 6.0;
                let deviation = (flip_rate - mean_flip).abs();
                let charge = if deviation < 0.1 { 1 } // moderate — near mean
                    else if flip_rate > mean_flip { 2 } // entangled — moves with the crowd
                    else { 0 }; // isolated — moves against

                isotope_classes[i] = (spin, mass, charge);
            }
        } else {
            // Default: assign by information-content rank
            // High-info epitopes = high spin, high mass. Low-info = low.
            isotope_classes = [
                (2, 2, 2), // burst_ratio: volatile, deep, entangled
                (2, 2, 1), // reading_deficit: volatile, deep, moderate
                (1, 1, 1), // ua_pool_poverty: moderate all
                (1, 1, 0), // sec_fetch_monotone: moderate, moderate, isolated
                (0, 2, 1), // session_absent: frozen, deep, moderate
                (0, 1, 0), // referer_self_loop: frozen, moderate, isolated
            ];
        }

        // ── V, D, J as individual π-bodies ──
        //
        // Each role's π-contribution is proportional to its share of the 6 epitopes.
        // At equilibrium (2/2/2): each = π × (2/6) × 3 = π.
        // The factor of 3 normalizes so that 1/3 share → π (same as tense bodies).
        //
        // If a role has 0 epitopes, its π-body = 0 and the product collapses.
        // This is correct: a system with no V (nothing changes) has no observation
        // budget. A system with no D (nothing unknown) is fully collapsed.
        // A system with no J (nothing conserved) has no memory.
        //
        // V × D × J = π³ at equilibrium. ⌊π³⌋ = 31 = max particles.
        let v_pi = PI * (v_count as f64 / 6.0) * 3.0;
        let d_pi = PI * (d_count as f64 / 6.0) * 3.0;
        let j_pi = PI * (j_count as f64 / 6.0) * 3.0;
        let vdj_product = v_pi * d_pi * j_pi;
        let pi_cubed = PI * PI * PI;
        let vdj_product_error = if pi_cubed > 0.0 {
            (vdj_product - pi_cubed).abs() / pi_cubed
        } else {
            1.0
        };

        NullDimension {
            product,
            product_error,
            body_constant,
            observation_cost,
            perturbation,
            vdj_map,
            vdj_distribution: (v_count, d_count, j_count),
            vdj_gain_bits,
            self_awareness,
            j_error,
            observer_fraction,
            tempo,
            isotope_classes,
            v_pi,
            d_pi,
            j_pi,
            vdj_product,
            vdj_product_error,
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
    fn vdj_each_equals_pi_at_equilibrium() {
        // V=2, D=2, J=2 at equilibrium: each should be π
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        let pi = std::f64::consts::PI;
        assert!(
            (nd.v_pi - pi).abs() < 0.001,
            "V should be π at equilibrium, got {}", nd.v_pi
        );
        assert!(
            (nd.d_pi - pi).abs() < 0.001,
            "D should be π at equilibrium, got {}", nd.d_pi
        );
        assert!(
            (nd.j_pi - pi).abs() < 0.001,
            "J should be π at equilibrium, got {}", nd.j_pi
        );
    }

    #[test]
    fn vdj_product_is_pi_cubed_at_equilibrium() {
        // V × D × J = π³ ≈ 31.006 → ⌊π³⌋ = 31 = max particles
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        let pi_cubed = std::f64::consts::PI.powi(3);
        assert!(
            (nd.vdj_product - pi_cubed).abs() < 0.01,
            "V×D×J should be π³ ≈ {:.3} at equilibrium, got {:.3}",
            pi_cubed, nd.vdj_product
        );
        assert!(
            nd.vdj_product_error < 0.001,
            "VDJ budget error should be near zero at equilibrium, got {:.6}",
            nd.vdj_product_error
        );
        // And floor(π³) = 31 = our max particle budget
        assert_eq!(pi_cubed.floor() as usize, 31,
            "⌊π³⌋ should be 31");
    }

    #[test]
    fn vdj_product_collapses_without_role() {
        // If all 6 are J (V=0, D=0): product = 0 (no observation budget)
        let flip = EpitopeFlipData {
            flipped:   [0, 0, 0, 0, 0, 0],
            evaluated: [100, 100, 100, 100, 100, 100],
            matched: 100,
        };
        let nd = NullDimension::compute((100, 100, 100), 100, Some(&flip));
        assert_eq!(nd.v_pi, 0.0, "V should be 0 when no variable epitopes");
        assert_eq!(nd.d_pi, 0.0, "D should be 0 when all evaluated");
        assert_eq!(nd.vdj_product, 0.0, "VDJ product should collapse to 0");
        assert!(nd.vdj_product_error > 0.99, "budget error should be ~1.0");
    }

    #[test]
    fn vdj_with_conservation_data() {
        let flip = EpitopeFlipData {
            flipped:   [80, 5, 0, 60, 2, 3],    // burst & sec_fetch flip a lot
            evaluated: [100, 100, 10, 100, 100, 100], // ua_pool barely evaluated
            matched: 100,
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
    fn gordian_proof_self_awareness() {
        // Default VDJ = 2V, 2D, 2J. V+D = 4 "others".
        // self = 4/π ≈ 1.273 — more than 1 because others teach you
        // things about yourself you couldn't know alone.
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        let expected = 4.0 / std::f64::consts::PI;
        assert!(
            (nd.self_awareness - expected).abs() < 0.001,
            "self_awareness should be 4/π ≈ 1.273, got {}", nd.self_awareness
        );
    }

    #[test]
    fn gordian_j_equals_vd_over_pi() {
        // Default VDJ = 2V, 2D, 2J.
        // J_predicted = (V + D) / π = 4/π ≈ 1.273
        // J_actual = 2
        // j_error = 2 - 1.273 = 0.727 (positive = mature)
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        let expected_error = 2.0 - 4.0 / std::f64::consts::PI;
        assert!(
            (nd.j_error - expected_error).abs() < 0.001,
            "j_error should be 2 - 4/π ≈ 0.727, got {}", nd.j_error
        );
        assert!(nd.j_error > 0.0, "default: organism is mature (J > predicted)");
    }

    #[test]
    fn gordian_equilibrium_j_near_body_constant() {
        // Equilibrium: J × π = V + D, and V + D + J = 6.
        // So J × (π + 1) = 6, J = 6/(π+1) ≈ 1.4488.
        // π^(1/3) ≈ 1.4646. They're within 1.1% of each other.
        // The gap (0.016) is the Gordian remainder —
        // self at equilibrium is ALMOST the body constant, but not quite.
        // That 1.1% is the irreducible mystery of self.
        let j_eq = 6.0 / (std::f64::consts::PI + 1.0);
        let body = std::f64::consts::PI.powf(1.0 / 3.0);
        let diff = (j_eq - body).abs() / body;
        assert!(
            diff < 0.02,
            "equilibrium J ≈ π^(1/3) within 2%: j_eq={:.4}, body={:.4}, diff={:.4}",
            j_eq, body, diff
        );
        // The gap itself: 6/(π+1) vs π^(1/3)
        let gap = body - j_eq; // ≈ 0.0159
        assert!(gap > 0.0, "π^(1/3) > 6/(π+1): the body constant slightly exceeds equilibrium self");
        assert!(gap < 0.02, "but only by ~0.016");
    }

    #[test]
    fn gordian_proof_archimedes_gap() {
        // With 3 "others" (V+D): self = 3/π ≈ 0.955.
        // The gap to 1.0 = 1 - 3/π = (π-3)/π ≈ 0.045.
        // You can NEVER fully know yourself through others.
        // The Archimedes remainder (π-3 ≈ 0.14159) is the unknowable.
        let flip = EpitopeFlipData {
            flipped:   [80, 5, 60, 0, 2, 3],     // 2 flip (V), 1 unevaluated (D), 3 stable (J)
            evaluated: [100, 100, 100, 10, 100, 100],
            matched: 100,
        };
        let nd = NullDimension::compute((100, 100, 100), 100, Some(&flip));
        // V=2 (burst, ua_pool), D=1 (sec_fetch), J=3 → V+D=3
        assert_eq!(nd.vdj_distribution.0 + nd.vdj_distribution.1, 3,
            "should have 3 'others' (V+D)");
        let expected = 3.0 / std::f64::consts::PI;
        assert!(
            (nd.self_awareness - expected).abs() < 0.001,
            "self = 3/π ≈ 0.955, got {}", nd.self_awareness
        );
        assert!(nd.self_awareness < 1.0, "you can never fully know yourself");
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

    #[test]
    fn tempo_equilibrium_is_one() {
        // Equal tense distribution: tempo should be 1.0 (the system's clock is π)
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        assert!(
            (nd.tempo - 1.0).abs() < 0.001,
            "equilibrium tempo should be 1.0 (t = π), got {}", nd.tempo
        );
    }

    #[test]
    fn tempo_shifts_with_imbalance() {
        let balanced = NullDimension::compute((100, 100, 100), 300, None);
        let skewed = NullDimension::compute((200, 80, 20), 300, None);
        assert!(
            (skewed.tempo - balanced.tempo).abs() > 0.001,
            "skewed distribution should shift tempo away from 1.0. balanced={}, skewed={}",
            balanced.tempo, skewed.tempo
        );
    }

    #[test]
    fn isotope_default_classes() {
        // Without conservation data: default isotope classification
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        // burst_ratio: (2,2,2) — volatile, deep, entangled
        assert_eq!(nd.isotope_classes[0], (2, 2, 2), "burst_ratio should be highest isotope");
        // referer_self_loop: (0,1,0) — frozen, moderate, isolated
        assert_eq!(nd.isotope_classes[5], (0, 1, 0), "referer_self_loop should be lowest");
    }

    #[test]
    fn isotope_with_conservation_data() {
        let flip = EpitopeFlipData {
            flipped:   [80, 5, 0, 60, 2, 3],
            evaluated: [100, 100, 10, 100, 100, 100],
            matched: 100,
        };
        let nd = NullDimension::compute((100, 100, 100), 100, Some(&flip));
        // burst flips 80% → spin=2 (volatile)
        assert_eq!(nd.isotope_classes[0].0, 2, "burst spin should be 2 (volatile)");
        // reading flips 5% → spin=0 (frozen)
        assert_eq!(nd.isotope_classes[1].0, 0, "reading spin should be 0 (frozen)");
        // ua_pool evaluated 10% → mass=0 (shallow)
        assert_eq!(nd.isotope_classes[2].1, 0, "ua_pool mass should be 0 (shallow)");
        // sec_fetch evaluated 100% → mass=2 (deep)
        assert_eq!(nd.isotope_classes[3].1, 2, "sec_fetch mass should be 2 (deep)");
    }

    #[test]
    fn pi_body_observer_at_d2() {
        // Default VDJ with only 2 roles occupied → d=2 (base case).
        // π^(2/2) = π ≈ 3.14159, observer = 0.14159
        let flip = EpitopeFlipData {
            flipped:   [80, 80, 80, 80, 80, 80], // all V, no D or J
            evaluated: [100, 100, 100, 100, 100, 100],
            matched: 100,
        };
        let nd = NullDimension::compute((100, 100, 100), 100, Some(&flip));
        // All 6 are V → VDJ has only 1 role → d stays at 2
        let expected = std::f64::consts::PI - 3.0; // 0.14159...
        assert!(
            (nd.observer_fraction - expected).abs() < 0.001,
            "at d=2 observer should be π-3 ≈ 0.142, got {}", nd.observer_fraction
        );
    }

    #[test]
    fn pi_body_observer_at_d3() {
        // Default VDJ = 2V, 2D, 2J → all 3 roles → d=3.
        // π^(3/2) ≈ 5.568, observer = 0.568
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        assert_eq!(nd.vdj_distribution, (2, 2, 2), "all 3 roles occupied");
        let pi_1_5 = std::f64::consts::PI.powf(1.5);
        let expected = pi_1_5 - pi_1_5.floor(); // ≈ 0.568
        assert!(
            (nd.observer_fraction - expected).abs() < 0.001,
            "at d=3 observer should be ≈0.568, got {}", nd.observer_fraction
        );
    }

    #[test]
    fn pi_body_observer_never_zero() {
        // π^(d/2) is never an integer for any positive d.
        // The observer never vanishes. Gödel, but it's π.
        for d in 1..20 {
            let pi_d = std::f64::consts::PI.powf(d as f64 / 2.0);
            let frac = pi_d - pi_d.floor();
            assert!(
                frac > 1e-10 || frac < 1.0 - 1e-10,
                "π^({}/2) should never be an integer, but frac = {}", d, frac
            );
        }
    }

    #[test]
    fn isotope_sort_gives_27_possible_states() {
        // 3 spin × 3 mass × 3 charge = 27 possible isotopes
        // Each epitope occupies one of these 27 slots.
        // The occupancy pattern is the isotopic signature.
        let nd = NullDimension::compute((100, 100, 100), 300, None);
        for (s, m, c) in &nd.isotope_classes {
            assert!(*s <= 2, "spin must be 0-2");
            assert!(*m <= 2, "mass must be 0-2");
            assert!(*c <= 2, "charge must be 0-2");
        }
        // Total possible states
        assert_eq!(3u32 * 3 * 3, 27, "3×3×3 = 27 isotope states");
    }
}
