// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Page mirror — the other side of the braid (Wave 173).
//!
//! Flips the perspective: instead of "what did visitors do" (visitor → surfaces),
//! this asks "what does the knowledge know about itself" (surface → visitors).
//!
//! Each surface is its own epitope on the OTHER membrane, telling us:
//! - Its importance (how many visitors, how diverse)
//! - Its depth (how deep people go within it)
//! - What it offers (what kind of visitors it attracts)
//! - When it matters (temporal character — morning vs night knowledge)
//!
//! The value of knowledge is a matter of perspective.
//!
//! # Integration
//!
//! This module operates on the same `EntityAccum` data as the entity
//! classifier and visitor archetype classifier. It's a projection of
//! the topology builder's accumulated state, viewed from the content's
//! perspective rather than the visitor's.

use std::collections::BTreeMap;

use cellmembrane_types::campfire::{
    SurfaceMirror, SurfaceShape, TemporalCharacter, VisitorArchetype,
};

use crate::entity_classifier::EntityId;
use crate::entity_profile::EntityAccum;
use crate::surface_registry;
use crate::visitor_archetype::classify_archetype;

/// Build surface mirrors from the entity topology data.
///
/// Takes the accumulated data for all entities and computes
/// per-surface self-awareness: who visits each surface, what
/// archetypes it attracts, its shape and temporal character.
///
/// Only includes human-browser entities (fleet entities are excluded
/// from the page mirror — this is about reflecting visitors, not threats).
pub fn build_surface_mirrors(
    entities: &[(EntityId, &EntityAccum)],
) -> Vec<SurfaceMirror> {
    // Accumulate per-surface stats
    let mut surface_stats: BTreeMap<String, SurfaceAccum> = BTreeMap::new();

    for (entity_id, accum) in entities {
        if !entity_id.is_human() {
            continue;
        }

        let archetype = classify_archetype(accum)
            .unwrap_or(VisitorArchetype::Visitor);

        for (host, &count) in &accum.hosts {
            let surface = surface_registry::strip_host(host).to_string();

            let stats = surface_stats.entry(surface).or_insert_with(SurfaceAccum::new);
            stats.hits += count;
            stats.visitor_count += 1;
            *stats.archetype_counts.entry(archetype).or_insert(0) += 1;

            // Estimate page count from unique paths (approximation)
            stats.unique_pages += count.min(50) as usize;
        }
    }

    // Convert to SurfaceMirror
    let mut mirrors: Vec<SurfaceMirror> = surface_stats.into_iter()
        .filter(|(_, s)| s.hits >= 2)
        .map(|(surface, stats)| {
            let shape = classify_shape(stats.unique_pages, stats.hits);
            let temporal = TemporalCharacter::MorningKnowledge; // TODO: compute from timestamps
            let domain = surface_registry::surface_domain(&surface);

            let archetype_attraction: BTreeMap<String, usize> = stats.archetype_counts.iter()
                .map(|(arch, &count)| (arch.to_string(), count))
                .collect();

            SurfaceMirror {
                name: surface_registry::surface_name(&surface).to_string(),
                surface,
                hits: stats.hits,
                visitor_count: stats.visitor_count,
                unique_pages: stats.unique_pages,
                archetype_attraction,
                shape,
                temporal_character: temporal,
                domain,
            }
        })
        .collect();

    // Sort by hits descending
    mirrors.sort_by(|a, b| b.hits.cmp(&a.hits));
    mirrors
}

/// Classify the shape of a surface's knowledge topology.
fn classify_shape(unique_pages: usize, hits: u64) -> SurfaceShape {
    let avg_depth = if hits > 0 { unique_pages as f64 / hits as f64 } else { 0.0 };
    let is_wide = unique_pages > 20;
    let is_deep = avg_depth > 0.5;

    match (is_wide, is_deep) {
        (true, true) => SurfaceShape::DeepAndWide,
        (true, false) => SurfaceShape::WideButShallow,
        (false, true) => SurfaceShape::NarrowAndDeep,
        (false, false) => SurfaceShape::Focused,
    }
}

/// Internal accumulator for per-surface statistics.
struct SurfaceAccum {
    hits: u64,
    visitor_count: usize,
    unique_pages: usize,
    archetype_counts: BTreeMap<VisitorArchetype, usize>,
}

impl SurfaceAccum {
    fn new() -> Self {
        Self {
            hits: 0,
            visitor_count: 0,
            unique_pages: 0,
            archetype_counts: BTreeMap::new(),
        }
    }
}

/// Perspective descriptions — what a page means to each archetype.
pub fn perspective_text(archetype: VisitorArchetype) -> &'static str {
    match archetype {
        VisitorArchetype::Explorer => "To an Explorer, this is territory to map.",
        VisitorArchetype::Watcher => "To a Watcher, this is a pulse to monitor.",
        VisitorArchetype::Scholar => "To a Scholar, this is source to read.",
        VisitorArchetype::Scout => "To a Scout, this is a landmark to remember.",
        VisitorArchetype::Witness => "To a Witness, this is evidence to preserve.",
        VisitorArchetype::Teacher => "To a Teacher, this is a lesson to understand.",
        VisitorArchetype::Probe => "To a Probe, this is a surface to test.",
        VisitorArchetype::Visitor => "To a Visitor, this is a place to see.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cellmembrane_types::campfire::ContentDomain;

    #[test]
    fn surface_name_lookup() {
        assert_eq!(surface_registry::surface_name("git"), "Forge");
        assert_eq!(surface_registry::surface_name("detroit"), "Detroit Evidence");
        assert_eq!(surface_registry::surface_name("unknown_surface"), "unknown_surface");
    }

    #[test]
    fn surface_domain_lookup() {
        assert_eq!(surface_registry::surface_domain("detroit"), ContentDomain::Evidence);
        assert_eq!(surface_registry::surface_domain("cytokine"), ContentDomain::Immune);
        assert_eq!(surface_registry::surface_domain("git"), ContentDomain::Source);
        assert_eq!(surface_registry::surface_domain("unknown"), ContentDomain::Other);
    }

    #[test]
    fn shape_classification() {
        // 50 pages, 50 hits → ratio=1.0, wide+deep
        assert_eq!(classify_shape(50, 50), SurfaceShape::DeepAndWide);
        // 50 pages, 200 hits → ratio=0.25, wide but shallow
        assert_eq!(classify_shape(50, 200), SurfaceShape::WideButShallow);
        // 5 pages, 5 hits → ratio=1.0, narrow+deep
        assert_eq!(classify_shape(5, 5), SurfaceShape::NarrowAndDeep);
        // 5 pages, 100 hits → ratio=0.05, focused
        assert_eq!(classify_shape(5, 100), SurfaceShape::Focused);
    }

    #[test]
    fn perspective_text_nonempty() {
        for arch in [
            VisitorArchetype::Explorer,
            VisitorArchetype::Watcher,
            VisitorArchetype::Scholar,
            VisitorArchetype::Scout,
            VisitorArchetype::Witness,
            VisitorArchetype::Teacher,
            VisitorArchetype::Probe,
            VisitorArchetype::Visitor,
        ] {
            let text = perspective_text(arch);
            assert!(!text.is_empty());
            assert!(text.starts_with("To a") || text.starts_with("To an"));
        }
    }

    #[test]
    fn build_mirrors_empty() {
        let mirrors = build_surface_mirrors(&[]);
        assert!(mirrors.is_empty());
    }

    #[test]
    fn build_mirrors_skips_fleet() {
        let accum = {
            let mut a = EntityAccum::new();
            a.hosts.insert("git.primals.eco".into(), 100);
            a.total = 100;
            a
        };
        let mirrors = build_surface_mirrors(&[(EntityId::MetaFleet, &accum)]);
        assert!(mirrors.is_empty(), "fleet entities should be excluded (is_human=false)");
    }

    #[test]
    fn build_mirrors_includes_human() {
        let accum = {
            let mut a = EntityAccum::new();
            a.hosts.insert("git.primals.eco".into(), 50);
            a.hosts.insert("detroit.primals.eco".into(), 10);
            a.total = 60;
            a.first_ts = 1000.0;
            a.last_ts = 37000.0;
            a
        };
        let mirrors = build_surface_mirrors(&[(EntityId::HumanBrowser, &accum)]);
        assert_eq!(mirrors.len(), 2);
        assert_eq!(mirrors[0].surface, "git"); // higher hits first
        assert_eq!(mirrors[0].name, "Forge");
        assert_eq!(mirrors[0].hits, 50);
        assert_eq!(mirrors[0].domain, ContentDomain::Source);
    }
}
