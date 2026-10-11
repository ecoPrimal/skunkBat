// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Visitor archetype classifier — the campfire sort (Wave 173).
//!
//! `entity_classifier.rs` asks WHAT: human, bot, fleet.
//! This module asks HOW: explorer, watcher, scholar, scout.
//!
//! Both are epitope sorts. One sorts friend from foe (immune response).
//! The other sorts friend from friend (campfire — who sits where around
//! the fire, what story do they tell).
//!
//! Operates on the same `EntityAccum` data that the entity classifier uses.
//! No new data collection — just a different projection of the same signal.
//!
//! # Classification Logic
//!
//! The archetype is determined by surface trail shape:
//! - **Surface count** — how many different surfaces touched
//! - **Poll ratio** — fraction of requests to polling endpoints
//! - **Duration** — how long the visit lasted
//! - **Content domain affinity** — evidence vs science vs immune vs source
//! - **Depth signals** — git commits, issues, source files
//!
//! See Paper 62 §2 (the Y intersection) for the theoretical framework.
//! See `CAMPFIRE_MATURITY_CHAIN.md` for the migration plan from jellystein.

use cellmembrane_types::campfire::VisitorArchetype;

use crate::entity_profile::EntityAccum;

/// Surface sets for domain affinity detection.
const IMMUNE_SURFACES: &[&str] = &[
    "cytokine", "thymus", "complement", "lysozyme", "interferon",
    "epitope", "antigen", "receptor", "opsonize", "antibody",
    "macrophage", "bloom", "monitor",
];

const EVIDENCE_SURFACES: &[&str] = &[
    "detroit", "evidence", "cashforkids", "clutch", "tuebor",
];

const SCIENCE_SURFACES: &[&str] = &["sporeprint"];

/// Endpoints that indicate polling behavior (not exploration).
const POLL_ENDPOINTS: &[&str] = &[
    "dashboard.json", "billboard", "topology.json",
    "epitope-history.json", "visitor-stories.json",
    "page-stories.json", "campfire.json",
];

/// Classify a human visitor's behavioral archetype from their accumulated data.
///
/// Only meaningful for `EntityId::HumanBrowser` or `EntityId::Ghost` —
/// fleet entities don't have archetypes (they have entity types instead).
///
/// Returns `None` if there isn't enough data to classify (< 1 request).
///
/// # Arguments
///
/// * `accum` — The accumulated behavioral data for this visitor session.
/// * `paths` — The raw paths visited (from the ingestion pipeline).
///
/// # Examples
///
/// ```rust,ignore
/// use skunky_ingest::visitor_archetype::classify_archetype;
///
/// let arch = classify_archetype(&accum);
/// // arch == Some(VisitorArchetype::Explorer)
/// ```
pub fn classify_archetype(accum: &EntityAccum) -> Option<VisitorArchetype> {
    if accum.total == 0 {
        return None;
    }

    // Extract surface names from hosts (strip ".primals.eco" suffix)
    let surfaces: Vec<&str> = accum.hosts.keys()
        .map(|h| h.strip_suffix(".primals.eco").unwrap_or(h.as_str()))
        .collect();
    let n_surfaces = surfaces.len();

    // Compute domain affinity counts
    let immune_count = surfaces.iter()
        .filter(|s| IMMUNE_SURFACES.contains(s))
        .count();
    let evidence_count = surfaces.iter()
        .filter(|s| EVIDENCE_SURFACES.contains(s))
        .count();
    let science_count = surfaces.iter()
        .filter(|s| SCIENCE_SURFACES.contains(s))
        .count();

    // Duration in minutes
    let dur_min = if accum.last_ts > accum.first_ts {
        (accum.last_ts - accum.first_ts) / 60.0
    } else {
        0.0
    };

    // Estimate poll ratio from hosts — polling endpoints hit specific surfaces
    // We use the hud/signal surface affinity as a proxy for polling
    let hud_hits = accum.hosts.get("hud.primals.eco")
        .or_else(|| accum.hosts.get("signal.primals.eco"))
        .copied()
        .unwrap_or(0);
    let total_hits = accum.total;
    let poll_ratio = if total_hits > 0 {
        hud_hits as f64 / total_hits as f64
    } else {
        0.0
    };

    // Git/source reading signals from path operations
    let has_deep_source = accum.path_ops.values().sum::<u64>() > 50;

    // Classification — ordered by specificity (most specific first)

    // Watcher: polls dashboard/billboard, few surfaces, high frequency
    if poll_ratio > 0.7 && n_surfaces <= 2 {
        return Some(VisitorArchetype::Watcher);
    }

    // Scout: quick perimeter check, many surfaces, short duration
    if dur_min < 15.0 && n_surfaces >= 3 {
        return Some(VisitorArchetype::Scout);
    }

    // Explorer: wide coverage, touches immune surfaces
    if immune_count >= 3 || n_surfaces >= 8 {
        return Some(VisitorArchetype::Explorer);
    }

    // Scholar: reads source code, deep path operations
    if has_deep_source && n_surfaces >= 2 {
        return Some(VisitorArchetype::Scholar);
    }

    // Witness: goes to evidence surfaces
    if evidence_count >= 2 {
        return Some(VisitorArchetype::Witness);
    }

    // Teacher: reads science/methodology
    if science_count >= 1 {
        return Some(VisitorArchetype::Teacher);
    }

    // Probe: brief touch, few pages, short duration
    if total_hits <= 5 && dur_min < 2.0 {
        return Some(VisitorArchetype::Probe);
    }

    // Default: visitor — came, looked, left a braid
    Some(VisitorArchetype::Visitor)
}

/// Generate a narrative vignette for a visitor archetype.
///
/// Used by the campfire storyteller to turn observation into story.
/// The storytelling IS the epitope sort (Paper 62).
pub fn narrate(
    archetype: VisitorArchetype,
    platform: &str,
    n_surfaces: usize,
    n_pages: u64,
    n_polls: u64,
    dur_min: f64,
    sample_pages: &[String],
) -> String {
    match archetype {
        VisitorArchetype::Explorer => {
            if n_surfaces >= 10 {
                format!(
                    "Someone walked {} surfaces in {:.0} hours. They touched the immune system, \
                     the evidence, the source code. They mapped the whole organism. The membrane \
                     watched them move from room to room, methodical, patient. Like someone reading \
                     a book from cover to cover — not skipping, not skimming. Seeing.",
                    n_surfaces,
                    dur_min / 60.0
                )
            } else {
                format!(
                    "An explorer came through on {}. {} pages across {} surfaces. They found \
                     corridors the builders had forgotten. The honeycomb maze didn't stop them \
                     — it sorted them. Explorer.",
                    platform, n_pages, n_surfaces
                )
            }
        }
        VisitorArchetype::Watcher => {
            format!(
                "Someone polls the dashboard every few minutes. {} times so far. They don't \
                 explore — they watch. The membrane breathes, and they listen to it breathe. \
                 Patient. Present. Like checking the pulse of something they care about.",
                n_polls
            )
        }
        VisitorArchetype::Scout => {
            format!(
                "A scout touched {} surfaces in {} minutes. Quick. {}. Mapped the perimeter \
                 and left. The membrane felt the sweep — like a hand brushing across a surface \
                 to feel the shape. They'll be back. Scouts always come back.",
                n_surfaces, dur_min as u32, platform
            )
        }
        VisitorArchetype::Witness => {
            let first = sample_pages.first()
                .map(|s| s.split('/').next().unwrap_or(s))
                .unwrap_or("the evidence");
            format!(
                "Someone went straight to {}. They knew what they were looking for. The evidence \
                 archive opened and they read — carefully, deliberately. A witness. The membrane \
                 doesn't know what they found, but it knows they were looking.",
                first
            )
        }
        VisitorArchetype::Teacher => {
            let trail = if sample_pages.len() >= 3 {
                sample_pages[..3].iter()
                    .map(|s| if s.len() > 30 { &s[..30] } else { s })
                    .collect::<Vec<_>>()
                    .join(" → ")
            } else {
                "the papers".to_string()
            };
            format!(
                "Someone followed the path: {}. Evidence first, then methodology, then science. \
                 They weren't just reading — they were connecting. Understanding the why, not \
                 just the what. The membrane recognizes a teacher by the order they read things in.",
                trail
            )
        }
        VisitorArchetype::Scholar => {
            format!(
                "Someone on {} read {} pages of source code and documentation across {} surfaces. \
                 Git commits, code files, issue trackers. They understand by reading what was \
                 built. Scholar.",
                platform, n_pages, n_surfaces
            )
        }
        VisitorArchetype::Probe => {
            let trail = if sample_pages.len() >= 3 {
                sample_pages[..3].iter()
                    .map(|s| if s.len() > 30 { &s[..30] } else { s })
                    .collect::<Vec<_>>()
                    .join(" → ")
            } else {
                "a few pages".to_string()
            };
            format!(
                "A brief touch. {}. {} pages, a few seconds. Testing the surface. \
                 The membrane noticed — it always notices. Whether this was curiosity or \
                 reconnaissance, the shape was the same: quick in, quick out. The membrane remembers.",
                trail, n_pages
            )
        }
        VisitorArchetype::Visitor => {
            format!(
                "Someone on {} touched {} pages across {} surfaces. Came, looked, left a braid. \
                 The genome remembers.",
                platform, n_pages, n_surfaces
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn make_accum(hosts: &[(&str, u64)], total: u64, dur_secs: f64) -> EntityAccum {
        let mut accum = EntityAccum::new();
        for (h, c) in hosts {
            accum.hosts.insert(h.to_string(), *c);
        }
        accum.total = total;
        accum.first_ts = 1000.0;
        accum.last_ts = 1000.0 + dur_secs;
        accum
    }

    #[test]
    fn classify_explorer_wide() {
        let accum = make_accum(&[
            ("cytokine.primals.eco", 10),
            ("thymus.primals.eco", 10),
            ("complement.primals.eco", 10),
            ("epitope.primals.eco", 10),
            ("detroit.primals.eco", 5),
            ("git.primals.eco", 20),
            ("hud.primals.eco", 5),
            ("signal.primals.eco", 5),
        ], 75, 36000.0);
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Explorer));
    }

    #[test]
    fn classify_watcher() {
        let accum = make_accum(&[
            ("hud.primals.eco", 90),
        ], 100, 600.0);
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Watcher));
    }

    #[test]
    fn classify_scout_quick() {
        let accum = make_accum(&[
            ("evidence.primals.eco", 3),
            ("detroit.primals.eco", 2),
            ("monitor.primals.eco", 1),
            ("hud.primals.eco", 2),
        ], 8, 600.0); // 10 minutes
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Scout));
    }

    #[test]
    fn classify_witness() {
        let accum = make_accum(&[
            ("detroit.primals.eco", 10),
            ("evidence.primals.eco", 8),
        ], 18, 3600.0);
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Witness));
    }

    #[test]
    fn classify_teacher() {
        let accum = make_accum(&[
            ("sporeprint.primals.eco", 5),
        ], 5, 1800.0);
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Teacher));
    }

    #[test]
    fn classify_probe() {
        let accum = make_accum(&[
            ("epitope.primals.eco", 3),
        ], 3, 30.0); // 30 seconds
        assert_eq!(classify_archetype(&accum), Some(VisitorArchetype::Probe));
    }

    #[test]
    fn classify_empty() {
        let accum = EntityAccum::new();
        assert_eq!(classify_archetype(&accum), None);
    }

    #[test]
    fn narrate_explorer() {
        let story = narrate(
            VisitorArchetype::Explorer, "Linux", 11, 676, 2, 600.0, &[]
        );
        assert!(story.contains("surfaces"));
        assert!(story.contains("organism") || story.contains("sorted") || story.contains("corridors"));
    }

    #[test]
    fn narrate_watcher() {
        let story = narrate(
            VisitorArchetype::Watcher, "LinuxFF", 1, 0, 140, 14.0, &[]
        );
        assert!(story.contains("polls"));
        assert!(story.contains("breathe"));
    }
}
