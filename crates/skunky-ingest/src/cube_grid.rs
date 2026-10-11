// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BingoCube Decision Grid — multi-axis deterministic decision matrix.
//!
//! The 5×5 grid drives all scatter response decisions from a single
//! (fleet_hash, path, epoch) seed. Same seed → same grid → same decisions.
//!
//! Extracted from `cube_oracle.rs` — the grid is the input,
//! the oracle is the learning engine that evolves around it.

#![allow(missing_docs)]

use bingocube_core::{BingoCube, Color, Config};

// ══════════════════════════════════════════════════════════════════════
// CubeDecisionGrid — multi-axis decision matrix from BingoCube colors
// ══════════════════════════════════════════════════════════════════════

/// Cell assignments for the 5x5 decision grid.
///
/// Each cell's color (0-15) drives a different scatter decision axis.
/// The grid is seeded from (fleet_hash, path, epoch), so it is deterministic
/// for repeat requests but varies per fleet + epoch.
///
/// ```text
///         col0          col1          col2          col3          col4
/// row0  jitter_type   content_var   poison_gate   mirror_gate   crawl_density
/// row1  antibody_idx  header_var    inject_pos    federation    personality
/// row2  temporal_ph   lure_type     fluoro_layer  prism_mode    amplify_scale
/// row3  tense_gate    tense_depth   tense_conf    tense_decay   tense_invert
/// row4  sort_level    sort_grain    sort_compress  sort_epoch   sort_feedback
/// ```
///
/// Rows 3-4 wired in Wave 171 (Paper 48 — epitope sort compression):
///
/// - **Row 3 (tense)**: Controls the temporal dimension of the scatter response.
///   Which tense frame (is/was/will-be) does the response inhabit? How deep into
///   history? How confident is the tense classification? How fast does tense decay?
///
/// - **Row 4 (sort)**: Controls the epitope sort dimension. Which granularity level
///   does the maze apply this epoch? How much compression did the last pass achieve?
///   Feeds back to nautilus for adaptive compression scheduling.
pub struct CubeDecisionGrid {
    colors: [[Color; 5]; 5],
    scalars: [[u64; 5]; 5],
}

/// Jitter type derived from cell (0,0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterType {
    /// Normal path-based content (colors 0-12, ~81%)
    Normal,
    /// Cross-type: wrong content for the path (colors 13-14, ~12.5%)
    CrossType,
    /// Personality shift: different forge identity (color 15, ~6.25%)
    PersonalityShift,
}

/// Content variant for cross-type jitter, derived from cell (0,1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ContentVariant {
    Blame,
    Commit,
    File,
    Repo,
    Issue,
    Wiki,
    Release,
    Release2,
}

/// Tense gate — temporal frame for the scatter response (Paper 48).
///
/// Maps to the three temporal states of the epitope sort compression:
/// Is (present, observable), Was (past, recorded), WillBe (future, predicted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenseGate {
    /// Present — first observation, state = 0, polynomial.
    Is,
    /// Past — repeat pattern, state = 1, polynomial.
    Was,
    /// Future — nautilus prediction, state = null, NP-bounded.
    WillBe,
}

/// Sort level — which epitope sort dimension the maze applies this epoch (Paper 48).
///
/// The three sort levels form a compression hierarchy:
/// `H(data|tense) < H(data|epitope) < H(data|alphabetic) < H(data)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortLevel {
    /// Surface variation — content varies by path hash. Least informative.
    Alphabetic,
    /// Behavioral clustering — content varies by epitope. Structurally informative.
    Epitope,
    /// Temporal maze — content presents is/was/will-be frames. Most informative.
    Tense,
}

impl CubeDecisionGrid {
    /// Create a decision grid from context.
    ///
    /// Same (fleet_hash, path, epoch) -> same grid -> same decisions.
    pub fn from_context(fleet_hash: &str, path: &str, epoch: u64) -> Self {
        let seed = format!("scatter:decision:{fleet_hash}:{path}:{epoch}");
        let config = Config {
            grid_size: 5,
            universe_size: 100,
            palette_size: 16,
            free_cell: None,
        };
        let cube = BingoCube::from_seed(seed.as_bytes(), config)
            .expect("decision grid config is always valid");

        let mut colors = [[0u8; 5]; 5];
        let mut scalars = [[0u64; 5]; 5];
        for row in 0..5 {
            for col in 0..5 {
                colors[row][col] = cube.get_color(row, col).unwrap_or(0);
                scalars[row][col] = cube.get_scalar(row, col).unwrap_or(0);
            }
        }

        Self { colors, scalars }
    }

    /// Cell color at (row, col). Range 0-15.
    pub fn color(&self, row: usize, col: usize) -> u8 {
        self.colors[row][col]
    }

    /// Cell scalar at (row, col). Full u64 range.
    pub fn scalar(&self, row: usize, col: usize) -> u64 {
        self.scalars[row][col]
    }

    // ── Row 0: Response-level decisions ──

    /// Jitter type: Normal (81%), CrossType (12.5%), PersonalityShift (6.25%).
    pub fn jitter_type(&self) -> JitterType {
        match self.colors[0][0] {
            15 => JitterType::PersonalityShift,
            13 | 14 => JitterType::CrossType,
            _ => JitterType::Normal,
        }
    }

    /// Content variant for cross-type jitter (8 types from 16 colors).
    pub fn content_variant(&self) -> ContentVariant {
        match self.colors[0][1] % 8 {
            0 => ContentVariant::Blame,
            1 => ContentVariant::Commit,
            2 => ContentVariant::File,
            3 => ContentVariant::Repo,
            4 => ContentVariant::Issue,
            5 => ContentVariant::Wiki,
            6 => ContentVariant::Release,
            _ => ContentVariant::Release2,
        }
    }

    /// Poison gate: whether to serve poison vs 404 decoy. Returns 0-15.
    pub fn poison_gate(&self) -> u8 {
        self.colors[0][2]
    }

    /// Mirror probability gate. Returns 0-15.
    pub fn mirror_gate(&self) -> u8 {
        self.colors[0][3]
    }

    /// Crawl link density tier (0-15).
    pub fn crawl_density(&self) -> u8 {
        self.colors[0][4]
    }

    // ── Row 1: Injection-level decisions ──

    /// Antibody chain index (0-15 variants).
    pub fn antibody_index(&self) -> u8 {
        self.colors[1][0]
    }

    /// Header jitter variant (0-15).
    pub fn header_variant(&self) -> u8 {
        self.colors[1][1]
    }

    /// Antibody inject position in HTML (0=head, 1=div, 2=body, 3-15 new).
    pub fn inject_position(&self) -> u8 {
        self.colors[1][2]
    }

    /// Federation header inclusion flags (0-15).
    pub fn federation_flags(&self) -> u8 {
        self.colors[1][3]
    }

    /// Personality index (0-15).
    pub fn personality_index(&self) -> u8 {
        self.colors[1][4]
    }

    // ── Row 2: Content-level decisions ──

    /// Temporal phase (0-4 from 16 colors via pressure-dependent mapping).
    pub fn temporal_phase(&self, pressure: f64) -> u8 {
        let color = self.colors[2][0];
        if pressure < 0.3 {
            color % 5
        } else if pressure < 0.6 {
            match color {
                0 | 1 => 0,
                2 | 3 | 4 => 1,
                5 | 6 | 7 | 8 => 2,
                9 | 10 | 11 => 3,
                _ => 4,
            }
        } else {
            match color {
                0 => 0,
                1 => 1,
                2..=6 => 2,
                7..=11 => 3,
                _ => 4,
            }
        }
    }

    /// Lure type selection (0-15).
    pub fn lure_type(&self) -> u8 {
        self.colors[2][1]
    }

    /// Fluoro encoding layer emphasis (0-15).
    pub fn fluoro_layer(&self) -> u8 {
        self.colors[2][2]
    }

    /// Prism mix mode (0-15).
    pub fn prism_mode(&self) -> u8 {
        self.colors[2][3]
    }

    /// Amplify scale factor (0-15).
    pub fn amplify_scale(&self) -> u8 {
        self.colors[2][4]
    }

    // ── Row 3: Tense dimension (Paper 48) ──

    /// Tense gate — which temporal frame the scatter response inhabits.
    ///
    /// Colors 0-7 → Is (50%), 8-13 → Was (37.5%), 14-15 → WillBe (12.5%).
    pub fn tense_gate(&self) -> TenseGate {
        match self.colors[3][0] {
            0..=7 => TenseGate::Is,
            8..=13 => TenseGate::Was,
            _ => TenseGate::WillBe,
        }
    }

    /// Tense depth — how far into history/prediction. Returns 0-15.
    pub fn tense_depth(&self) -> u8 {
        self.colors[3][1]
    }

    /// Tense confidence — certainty of the tense classification. Returns 0-15.
    pub fn tense_confidence(&self) -> u8 {
        self.colors[3][2]
    }

    /// Tense decay — how quickly temporal context expires. Returns 0-15.
    pub fn tense_decay(&self) -> u8 {
        self.colors[3][3]
    }

    /// Tense inversion flag — colors 14-15 → invert (12.5%).
    pub fn tense_invert(&self) -> bool {
        self.colors[3][4] >= 14
    }

    // ── Row 4: Sort dimension (Paper 48) ──

    /// Sort level — which epitope sort dimension dominates.
    ///
    /// Colors 0-7 → Alphabetic (50%), 8-12 → Epitope (31.25%), 13-15 → Tense (18.75%).
    pub fn sort_level(&self) -> SortLevel {
        match self.colors[4][0] {
            0..=7 => SortLevel::Alphabetic,
            8..=12 => SortLevel::Epitope,
            _ => SortLevel::Tense,
        }
    }

    /// Sort grain — granularity within the sort level. Returns 0-15.
    pub fn sort_grain(&self) -> u8 {
        self.colors[4][1]
    }

    /// Sort compression — entropy reduction proxy. Returns 0-15.
    pub fn sort_compress(&self) -> u8 {
        self.colors[4][2]
    }

    /// Sort epoch — how often the sort level changes. Returns 0-15.
    pub fn sort_epoch(&self) -> u8 {
        self.colors[4][3]
    }

    /// Sort feedback — nautilus feedback strength. Returns 0-15.
    pub fn sort_feedback(&self) -> u8 {
        self.colors[4][4]
    }

    /// Full scalar for hash-based decisions (when 16 colors aren't enough).
    pub fn scalar_decision(&self, row: usize, col: usize, modulus: u64) -> u64 {
        self.scalars[row][col] % modulus
    }
}
