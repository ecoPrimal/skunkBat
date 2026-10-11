// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Membrane Geometry — the membrane IS its own frame (Paper 75).
//!
//! Six epitope axes project to 2D at 60° intervals, forming a hexagonal
//! lattice of 19 positions in 4 concentric shells.  Each entity's triggered
//! epitopes sum to a 2D position on this lattice.  The cells are
//! **parallelograms** with 60°/120° angles — the natural tiling of
//! non-orthogonal axes.  Not squares.  Not circles.  The shape the math makes.
//!
//! Life occurs in the **\[null\]** — unoccupied cells, the space between.
//! The space we make BETWEEN ourselves for others.
//!
//! # Geometry
//!
//! The 6 axes come in 3 opposition pairs (eₖ₊₃ = −eₖ):
//!
//! | Pair | Positive (+eₖ) | Negative (−eₖ) | Dimension |
//! |------|----------------|----------------|-----------|
//! | 0 | burst_ratio | sec_fetch_monotone | Structural |
//! | 1 | reading_deficit | session_absent | Behavioral |
//! | 2 | ua_pool_poverty | referer_self_loop | Identity |
//!
//! Triggering both sides of a pair cancels (net displacement = 0).
//! This creates **19 unique positions** from 64 bit patterns:
//!
//! | Shell | Radius | Cells | Bit patterns | Permeability | Nature |
//! |-------|--------|-------|--------------|--------------|--------|
//! | 0 | 0 | 1 | 10 | 1.000 | Maximum ambiguity — \[null\] |
//! | 1 | 1 | 6 | 36 | 0.600 | High diversity |
//! | 2 | √3 | 6 | 12 | 0.200 | Moderate |
//! | 3 | 2 | 6 | 6 | 0.100 | Definitive — pure archetype |
//!
//! Permeability = pattern_diversity / max_diversity (10).
//! Center is most permeable.  The gradient IS the membrane.
//!
//! # The ionosphere alignment
//!
//! The shells map to ionospheric layers: D (outer, reflects LF) →
//! E → F1 → F2 (inner, passes HF).  Each layer has characteristic
//! permeability to different signal frequencies.  The epitope membrane
//! has the same structure: each shell passes different entity types.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::entity_profile::EntityProfile;

const SQRT3_HALF: f64 = 0.866_025_403_784_438_6;
const SQRT3: f64 = 1.732_050_807_568_877_3;

/// The 6 epitope axes at 60° intervals.
///
/// Opposition pairs: (0,3), (1,4), (2,5).
/// `eₖ₊₃ = −eₖ` — triggering both sides cancels.
const AXES: [(f64, f64); 6] = [
    (1.0, 0.0),          // 0: burst_ratio
    (0.5, SQRT3_HALF),   // 1: reading_deficit
    (-0.5, SQRT3_HALF),  // 2: ua_pool_poverty
    (-1.0, 0.0),         // 3: sec_fetch_monotone
    (-0.5, -SQRT3_HALF), // 4: session_absent
    (0.5, -SQRT3_HALF),  // 5: referer_self_loop
];

/// Epitope names in sort order (matches `EPITOPE_SORT_ORDER`).
pub const EPITOPE_NAMES: [&str; 6] = [
    "burst_ratio",
    "reading_deficit",
    "ua_pool_poverty",
    "sec_fetch_monotone",
    "session_absent",
    "referer_self_loop",
];

/// Max pattern diversity (center position absorbs 10 of 64 bit patterns).
const MAX_DIVERSITY: f64 = 10.0;

/// Half-vectors for the parallelogram cell (e₀/2 and e₁/2).
const HALF_E0: (f64, f64) = (0.5, 0.0);
const HALF_E1: (f64, f64) = (0.25, SQRT3_HALF / 2.0);

// ══════════════════════════════════════════════════════════════════════
// Output types — the universal membrane interface (JSON)
// ══════════════════════════════════════════════════════════════════════

/// A single cell in the membrane geometry — one of 19 parallelogram positions.
#[derive(Debug, Serialize)]
pub struct MembraneCell {
    /// 2D position on the hexagonal lattice.
    pub position: (f64, f64),
    /// Concentric shell index (0 = center, 3 = outer).
    pub shell: u8,
    /// Distance from origin.
    pub radius: f64,
    /// Permeability = pattern_diversity / max_diversity.
    pub permeability: f64,
    /// How many distinct 6-bit patterns map to this position.
    pub pattern_count: usize,
    /// Entities currently in this cell.
    pub entity_count: u32,
    /// True when entity_count == 0 — this is \[null\] space.
    pub is_null: bool,
    /// Parallelogram corner vertices (4 points, 60°/120° angles).
    pub vertices: [(f64, f64); 4],
    /// All bit patterns mapping to this position (as "010110" strings).
    pub bit_patterns: Vec<String>,
    /// Entity labels occupying this cell (for diagnostics).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entity_labels: Vec<String>,
}

/// Statistics for one concentric shell.
#[derive(Debug, Serialize)]
pub struct ShellInfo {
    /// Shell index (0-3).
    pub shell: u8,
    /// Radius from origin (0, 1, √3, 2).
    pub radius: f64,
    /// Number of lattice positions in this shell.
    pub cell_count: usize,
    /// Total bit patterns absorbed by this shell.
    pub pattern_diversity: usize,
    /// Entities occupying this shell.
    pub entity_count: u32,
    /// Average permeability across cells in this shell.
    pub permeability: f64,
}

/// Full membrane geometry — the output interface for any renderer.
///
/// This is the universal contract: any membrane surface that produces
/// this structure can have its geometry rendered by any client.
#[derive(Debug, Serialize)]
pub struct MembraneGeometry {
    /// Total entities mapped.
    pub total_entities: u32,
    /// Lattice positions (always 19 for 6-epitope system).
    pub positions: usize,
    /// Cells with at least one entity.
    pub occupied: usize,
    /// Cells with zero entities — \[null\] space, where life moves.
    pub null_spaces: usize,
    /// Fraction of cells that are \[null\].
    pub null_ratio: f64,
    /// The 4 concentric shells.
    pub shells: Vec<ShellInfo>,
    /// All 19 cells with full detail.
    pub cells: Vec<MembraneCell>,
}

// ══════════════════════════════════════════════════════════════════════
// Core computation
// ══════════════════════════════════════════════════════════════════════

/// Extract 6-bit trigger vector from an EntityProfile's sort key.
///
/// Maps the 3-valued sort key (0x00=unevaluated, 0x01=quiet, 0x02=triggered)
/// to binary (0=not triggered, 1=triggered).  Unevaluated → 0 (conservative).
pub fn trigger_bits(profile: &EntityProfile) -> u8 {
    let key = profile.epitopes.epitope_sort_key();
    let mut bits: u8 = 0;
    for (i, &val) in key.iter().enumerate() {
        if val == 0x02 {
            bits |= 1 << i;
        }
    }
    bits
}

/// Compute 2D position from a 6-bit trigger vector.
///
/// Position = Σ eₖ for each triggered epitope k.
/// The result lands on one of 19 hexagonal lattice positions.
pub fn epitope_position(bits: u8) -> (f64, f64) {
    let mut x = 0.0_f64;
    let mut y = 0.0_f64;
    for i in 0..6 {
        if bits & (1 << i) != 0 {
            x += AXES[i].0;
            y += AXES[i].1;
        }
    }
    (round3(x), round3(y))
}

/// Compute parallelogram vertices centered at (cx, cy).
///
/// The parallelogram has sides along e₀ and e₁ with angles 60°/120°.
/// Area = |e₀ × e₁| = √3/2 per cell.
fn parallelogram_vertices(cx: f64, cy: f64) -> [(f64, f64); 4] {
    [
        (
            round3(cx - HALF_E0.0 - HALF_E1.0),
            round3(cy - HALF_E0.1 - HALF_E1.1),
        ),
        (
            round3(cx + HALF_E0.0 - HALF_E1.0),
            round3(cy + HALF_E0.1 - HALF_E1.1),
        ),
        (
            round3(cx + HALF_E0.0 + HALF_E1.0),
            round3(cy + HALF_E0.1 + HALF_E1.1),
        ),
        (
            round3(cx - HALF_E0.0 + HALF_E1.0),
            round3(cy - HALF_E0.1 + HALF_E1.1),
        ),
    ]
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Determine concentric shell from radius.
fn shell_from_radius(r: f64) -> u8 {
    if r < 0.1 {
        0
    } else if r < 1.5 {
        1
    } else if r < 1.9 {
        2
    } else {
        3
    }
}

fn bits_string(bits: u8) -> String {
    format!("{:06b}", bits & 0x3F)
}

/// Quantize position to a map key (avoid floating-point equality).
fn pos_key(x: f64, y: f64) -> (i64, i64) {
    ((x * 1000.0).round() as i64, (y * 1000.0).round() as i64)
}

/// Compute the full membrane geometry from entity trigger data.
///
/// # Arguments
///
/// * `entities` — list of `(entity_label, 6-bit trigger vector)` pairs.
///
/// # Returns
///
/// Complete `MembraneGeometry` with 19 parallelogram cells, 4 shells,
/// and \[null\] space statistics.
///
/// This function is the **universal interface**: any membrane that can
/// produce `(label, bits)` pairs can compute its geometry.
pub fn compute_membrane_geometry(entities: &[(String, u8)]) -> MembraneGeometry {
    // 1. Map all 64 possible bit patterns to lattice positions.
    let mut position_patterns: BTreeMap<(i64, i64), Vec<u8>> = BTreeMap::new();
    for bits in 0_u8..64 {
        let (x, y) = epitope_position(bits);
        position_patterns
            .entry(pos_key(x, y))
            .or_default()
            .push(bits);
    }

    // 2. Map entities to positions.
    let mut entity_map: BTreeMap<(i64, i64), Vec<String>> = BTreeMap::new();
    for (label, bits) in entities {
        let (x, y) = epitope_position(*bits);
        entity_map
            .entry(pos_key(x, y))
            .or_default()
            .push(label.clone());
    }

    // 3. Build cells.
    let mut cells = Vec::with_capacity(19);
    let mut shell_cells: BTreeMap<u8, usize> = BTreeMap::new();
    let mut shell_patterns: BTreeMap<u8, usize> = BTreeMap::new();
    let mut shell_entities: BTreeMap<u8, u32> = BTreeMap::new();

    for (pk, patterns) in &position_patterns {
        let x = pk.0 as f64 / 1000.0;
        let y = pk.1 as f64 / 1000.0;
        let radius = round3((x * x + y * y).sqrt());
        let shell = shell_from_radius(radius);
        let entities_here = entity_map.get(pk).cloned().unwrap_or_default();
        let entity_count = entities_here.len() as u32;
        let permeability = round3(patterns.len() as f64 / MAX_DIVERSITY);

        *shell_cells.entry(shell).or_insert(0) += 1;
        *shell_patterns.entry(shell).or_insert(0) += patterns.len();
        *shell_entities.entry(shell).or_insert(0) += entity_count;

        cells.push(MembraneCell {
            position: (x, y),
            shell,
            radius,
            permeability,
            pattern_count: patterns.len(),
            entity_count,
            is_null: entity_count == 0,
            vertices: parallelogram_vertices(x, y),
            bit_patterns: patterns.iter().map(|b| bits_string(*b)).collect(),
            entity_labels: entities_here,
        });
    }

    // Sort: shell ascending, then angle ascending (for consistent output).
    cells.sort_by(|a, b| {
        a.shell.cmp(&b.shell).then_with(|| {
            let angle_a = a.position.1.atan2(a.position.0);
            let angle_b = b.position.1.atan2(b.position.0);
            angle_a
                .partial_cmp(&angle_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    // 4. Build shell info.
    let shell_radii = [0.0, 1.0, SQRT3, 2.0];
    let shells: Vec<ShellInfo> = (0..4_u8)
        .map(|s| {
            let cc = shell_cells.get(&s).copied().unwrap_or(0);
            let pp = shell_patterns.get(&s).copied().unwrap_or(0);
            let ee = shell_entities.get(&s).copied().unwrap_or(0);
            let avg_div = if cc > 0 {
                pp as f64 / cc as f64
            } else {
                0.0
            };
            ShellInfo {
                shell: s,
                radius: round3(shell_radii[s as usize]),
                cell_count: cc,
                pattern_diversity: pp,
                entity_count: ee,
                permeability: round3(avg_div / MAX_DIVERSITY),
            }
        })
        .collect();

    let occupied = cells.iter().filter(|c| !c.is_null).count();
    let null_spaces = cells.iter().filter(|c| c.is_null).count();
    let total = cells.len();

    MembraneGeometry {
        total_entities: entities.len() as u32,
        positions: total,
        occupied,
        null_spaces,
        null_ratio: if total == 0 {
            1.0
        } else {
            round3(null_spaces as f64 / total as f64)
        },
        shells,
        cells,
    }
}

/// Format a human-readable report for logging.
pub fn format_report(geom: &MembraneGeometry) -> String {
    let mut r = String::with_capacity(1024);
    r.push_str(&format!(
        "🔬 Membrane Geometry — {} entities → {} positions ({} occupied, {} [null])\n",
        geom.total_entities, geom.positions, geom.occupied, geom.null_spaces
    ));
    r.push_str(&format!(
        "   Null ratio: {:.1}% — the space between, where life moves\n\n",
        geom.null_ratio * 100.0
    ));

    for shell in &geom.shells {
        r.push_str(&format!(
            "   Shell {} (r={:.3}): {} cells, {} patterns, {} entities, P={:.3}\n",
            shell.shell,
            shell.radius,
            shell.cell_count,
            shell.pattern_diversity,
            shell.entity_count,
            shell.permeability
        ));
    }

    let occupied_cells: Vec<&MembraneCell> = geom.cells.iter().filter(|c| !c.is_null).collect();
    if !occupied_cells.is_empty() {
        r.push_str("\n   Occupied cells:\n");
        for cell in occupied_cells {
            r.push_str(&format!(
                "     ({:+.3}, {:+.3}) shell={} entities={} P={:.3}\n",
                cell.position.0,
                cell.position.1,
                cell.shell,
                cell.entity_count,
                cell.permeability
            ));
        }
    }
    r
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lattice_has_19_positions() {
        let geom = compute_membrane_geometry(&[]);
        assert_eq!(geom.positions, 19, "6-axis hex lattice must have 19 positions");
    }

    #[test]
    fn shell_structure() {
        let geom = compute_membrane_geometry(&[]);
        assert_eq!(geom.shells.len(), 4);

        // Shell 0: 1 cell, 10 patterns
        assert_eq!(geom.shells[0].cell_count, 1);
        assert_eq!(geom.shells[0].pattern_diversity, 10);
        assert!((geom.shells[0].radius - 0.0).abs() < 0.01);

        // Shell 1: 6 cells, 36 patterns
        assert_eq!(geom.shells[1].cell_count, 6);
        assert_eq!(geom.shells[1].pattern_diversity, 36);
        assert!((geom.shells[1].radius - 1.0).abs() < 0.01);

        // Shell 2: 6 cells, 12 patterns
        assert_eq!(geom.shells[2].cell_count, 6);
        assert_eq!(geom.shells[2].pattern_diversity, 12);
        assert!((geom.shells[2].radius - SQRT3).abs() < 0.01);

        // Shell 3: 6 cells, 6 patterns
        assert_eq!(geom.shells[3].cell_count, 6);
        assert_eq!(geom.shells[3].pattern_diversity, 6);
        assert!((geom.shells[3].radius - 2.0).abs() < 0.01);
    }

    #[test]
    fn total_patterns_is_64() {
        let geom = compute_membrane_geometry(&[]);
        let total: usize = geom.shells.iter().map(|s| s.pattern_diversity).sum();
        assert_eq!(total, 64, "all 2^6 patterns must be accounted for");
    }

    #[test]
    fn permeability_decreases_outward() {
        let geom = compute_membrane_geometry(&[]);
        for i in 1..geom.shells.len() {
            assert!(
                geom.shells[i].permeability < geom.shells[i - 1].permeability,
                "shell {} P={} must be < shell {} P={}",
                i,
                geom.shells[i].permeability,
                i - 1,
                geom.shells[i - 1].permeability
            );
        }
    }

    #[test]
    fn center_permeability_is_one() {
        let geom = compute_membrane_geometry(&[]);
        let center = geom.cells.iter().find(|c| c.shell == 0).unwrap();
        assert!(
            (center.permeability - 1.0).abs() < 0.001,
            "center permeability must be 1.0"
        );
    }

    #[test]
    fn opposition_pairs_cancel() {
        // Triggering both sides of a pair → displacement cancels → center.
        // burst_ratio (bit 0) + sec_fetch_monotone (bit 3) = pair 0
        let pos = epitope_position(0b001001);
        assert!((pos.0).abs() < 0.01 && (pos.1).abs() < 0.01, "pair 0 cancel");

        // reading_deficit (bit 1) + session_absent (bit 4) = pair 1
        let pos = epitope_position(0b010010);
        assert!((pos.0).abs() < 0.01 && (pos.1).abs() < 0.01, "pair 1 cancel");

        // ua_pool_poverty (bit 2) + referer_self_loop (bit 5) = pair 2
        let pos = epitope_position(0b100100);
        assert!((pos.0).abs() < 0.01 && (pos.1).abs() < 0.01, "pair 2 cancel");

        // All 6 triggered = all 3 pairs cancel → center
        let pos = epitope_position(0b111111);
        assert!((pos.0).abs() < 0.01 && (pos.1).abs() < 0.01, "all cancel");
    }

    #[test]
    fn all_triggered_and_none_share_center() {
        let geom = compute_membrane_geometry(&[]);
        let center = geom.cells.iter().find(|c| c.shell == 0).unwrap();
        assert!(
            center.bit_patterns.contains(&"000000".to_string()),
            "none-triggered must map to center"
        );
        assert!(
            center.bit_patterns.contains(&"111111".to_string()),
            "all-triggered must map to center"
        );
    }

    #[test]
    fn entity_placement() {
        let entities = vec![
            ("fleet-meta".into(), 0b111111_u8), // all triggered → center
            ("human-alice".into(), 0b000000_u8), // none triggered → center
            ("partial-bot".into(), 0b000001_u8), // burst_ratio only → shell 1
        ];
        let geom = compute_membrane_geometry(&entities);

        assert_eq!(geom.total_entities, 3);
        assert_eq!(geom.occupied, 2); // center + one shell-1 position

        let center = geom.cells.iter().find(|c| c.shell == 0).unwrap();
        assert_eq!(center.entity_count, 2);
        assert!(center.entity_labels.contains(&"fleet-meta".to_string()));
        assert!(center.entity_labels.contains(&"human-alice".to_string()));
    }

    #[test]
    fn null_ratio_empty() {
        let geom = compute_membrane_geometry(&[]);
        assert_eq!(geom.null_spaces, 19);
        assert!((geom.null_ratio - 1.0).abs() < 0.001, "all cells null when empty");
    }

    #[test]
    fn parallelogram_is_60_120() {
        let verts = parallelogram_vertices(0.0, 0.0);
        // Check the angle at v0: vectors v0→v1 and v0→v3
        let v01 = (verts[1].0 - verts[0].0, verts[1].1 - verts[0].1);
        let v03 = (verts[3].0 - verts[0].0, verts[3].1 - verts[0].1);
        let dot = v01.0 * v03.0 + v01.1 * v03.1;
        let mag01 = (v01.0 * v01.0 + v01.1 * v01.1).sqrt();
        let mag03 = (v03.0 * v03.0 + v03.1 * v03.1).sqrt();
        let cos_angle = dot / (mag01 * mag03);
        let angle_deg = cos_angle.acos().to_degrees();
        assert!(
            (angle_deg - 60.0).abs() < 1.0,
            "parallelogram angle should be 60°, got {:.1}°",
            angle_deg
        );
    }

    #[test]
    fn outer_shell_pure_archetypes() {
        // Shell 3 positions each have exactly 1 bit pattern.
        let geom = compute_membrane_geometry(&[]);
        let outer: Vec<&MembraneCell> = geom.cells.iter().filter(|c| c.shell == 3).collect();
        assert_eq!(outer.len(), 6);
        for cell in &outer {
            assert_eq!(
                cell.pattern_count, 1,
                "outer shell cells must have exactly 1 pattern"
            );
            assert!(
                (cell.permeability - 0.1).abs() < 0.001,
                "outer shell permeability must be 0.1"
            );
        }
    }
}
