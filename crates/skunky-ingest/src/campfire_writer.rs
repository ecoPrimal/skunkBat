// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Campfire JSON writer — replaces the three Python cron scripts (Wave 173).
//!
//! Writes three JSON files from the live entity topology:
//! - `visitor-stories.json` — visitor archetypes and their trails
//! - `page-stories.json` — surface self-awareness (the other side of the braid)
//! - `campfire.json` — woven narrative stories (membrane + visitor)
//!
//! Called from the topology write cycle in entity_topology.rs,
//! alongside the existing topology.json and dashboard.json writes.
//!
//! # What it replaces
//!
//! | Python script (jellystein) | Lines | Rust module |
//! |---------------------------|-------|-------------|
//! | visitor-stories.py        | 186   | visitor_archetype.rs |
//! | page-stories.py           | 336   | page_mirror.rs |
//! | campfire.py (storyteller)  | 199   | storyteller.rs |
//! | mirror-receiver.py        | 86    | mirror_inbox.rs |
//! | **Total**                 | **807** | **campfire_writer.rs** (coordinator) |

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cellmembrane_types::campfire::VisitorArchetype;
use serde::Serialize;

use crate::entity_classifier::EntityId;
use crate::entity_profile::EntityAccum;
use crate::mirror_inbox::{MirrorInbox, chrono_now_utc_pub};
use crate::page_mirror::build_surface_mirrors;
use crate::storyteller::{build_campfire, write_campfire};
use crate::visitor_archetype::classify_archetype;

/// Configuration for the campfire writer.
pub struct CampfireWriterConfig {
    /// Directory to write JSON files into.
    pub output_dir: PathBuf,
    /// Path to the mirror messages JSONL file.
    pub mirror_messages_path: PathBuf,
}

impl CampfireWriterConfig {
    /// Default config for golgiBody production deployment.
    pub fn golgi_default() -> Self {
        Self {
            output_dir: PathBuf::from("/opt/membrane/live-terminal"),
            mirror_messages_path: PathBuf::from("/opt/membrane/mirror-messages.jsonl"),
        }
    }
}

/// Visitor stories output (replaces visitor-stories.json from Python).
#[derive(Debug, Serialize)]
struct VisitorStoriesOutput {
    generated: String,
    total_visitors: usize,
    archetypes: BTreeMap<String, &'static str>,
    visitors: Vec<VisitorEntry>,
}

#[derive(Debug, Serialize)]
struct VisitorEntry {
    archetype: String,
    description: String,
    platform: String,
    surfaces: usize,
    pages: u64,
    duration_min: f64,
    poll_count: u64,
    sample_pages: Vec<String>,
}

/// Page stories output (replaces page-stories.json from Python).
#[derive(Debug, Serialize)]
struct PageStoriesOutput {
    generated: String,
    principle: &'static str,
    total_pages_touched: u64,
    total_surfaces_touched: usize,
    surfaces: Vec<SurfaceEntry>,
}

#[derive(Debug, Serialize)]
struct SurfaceEntry {
    surface: String,
    name: String,
    hits: u64,
    visitors: usize,
    unique_pages: usize,
    character: SurfaceCharacter,
    attracted: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct SurfaceCharacter {
    domain: String,
    time_character: String,
    shape: String,
}

/// Write all campfire JSON files from entity topology state.
///
/// This is the single entry point that replaces all three Python cron scripts.
/// Call it from the topology write cycle alongside topology.json.
pub fn write_all(
    config: &CampfireWriterConfig,
    entities: &[(EntityId, &EntityAccum)],
) -> std::io::Result<()> {
    let mirror_inbox = MirrorInbox::new(&config.mirror_messages_path);

    // Filter to human entities for visitor stories
    let human_entities: Vec<_> = entities.iter()
        .filter(|(id, _)| matches!(id, EntityId::HumanBrowser | EntityId::Ghost))
        .collect();

    // 1. Write visitor-stories.json
    write_visitor_stories(config, &human_entities)?;

    // 2. Write page-stories.json
    write_page_stories(config, entities)?;

    // 3. Write campfire.json
    let campfire = build_campfire(entities, &mirror_inbox);
    write_campfire(&campfire, &config.output_dir.join("campfire.json"))?;

    Ok(())
}

fn write_visitor_stories(
    config: &CampfireWriterConfig,
    human_entities: &[&(EntityId, &EntityAccum)],
) -> std::io::Result<()> {
    let mut visitors = Vec::new();

    // Build archetype descriptions map
    let mut archetype_descs: BTreeMap<String, &'static str> = BTreeMap::new();
    for arch in [
        VisitorArchetype::Explorer, VisitorArchetype::Watcher,
        VisitorArchetype::Scholar, VisitorArchetype::Scout,
        VisitorArchetype::Witness, VisitorArchetype::Teacher,
        VisitorArchetype::Probe, VisitorArchetype::Visitor,
    ] {
        archetype_descs.insert(arch.to_string(), arch.description());
    }

    for (_, accum) in human_entities {
        if let Some(archetype) = classify_archetype(accum) {
            let surfaces: Vec<String> = accum.hosts.keys()
                .map(|h| h.strip_suffix(".primals.eco").unwrap_or(h).to_string())
                .collect();
            let n_pages: u64 = accum.hosts.values().sum();
            let dur_min = if accum.last_ts > accum.first_ts {
                (accum.last_ts - accum.first_ts) / 60.0
            } else {
                0.0
            };
            let hud_polls = accum.hosts.get("hud.primals.eco")
                .copied().unwrap_or(0);

            let platform = if accum.ua_os.keys().any(|k| k.contains("Windows")) { "Win" }
                else if accum.ua_os.keys().any(|k| k.contains("Macintosh")) { "Mac" }
                else if accum.ua_os.keys().any(|k| k.contains("iPhone")) { "iPhone" }
                else if accum.ua_os.keys().any(|k| k.contains("Linux")) { "Linux" }
                else { "?" };

            let sample = surfaces.iter()
                .map(|s| format!("{s}/"))
                .take(8)
                .collect();

            visitors.push(VisitorEntry {
                archetype: archetype.to_string(),
                description: archetype.description().to_string(),
                platform: platform.to_string(),
                surfaces: surfaces.len(),
                pages: n_pages,
                duration_min: (dur_min * 10.0).round() / 10.0,
                poll_count: hud_polls,
                sample_pages: sample,
            });
        }
    }

    visitors.sort_by(|a, b| (b.pages + b.poll_count).cmp(&(a.pages + a.poll_count)));

    let output = VisitorStoriesOutput {
        generated: chrono_now_utc_pub(),
        total_visitors: visitors.len(),
        archetypes: archetype_descs,
        visitors,
    };

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(config.output_dir.join("visitor-stories.json"), json)
}

fn write_page_stories(
    config: &CampfireWriterConfig,
    entities: &[(EntityId, &EntityAccum)],
) -> std::io::Result<()> {
    let surface_mirrors = build_surface_mirrors(entities);

    let total_pages: u64 = surface_mirrors.iter().map(|s| s.hits).sum();

    let surfaces: Vec<SurfaceEntry> = surface_mirrors.iter()
        .map(|m| SurfaceEntry {
            surface: m.surface.clone(),
            name: m.name.clone(),
            hits: m.hits,
            visitors: m.visitor_count,
            unique_pages: m.unique_pages,
            character: SurfaceCharacter {
                domain: m.domain.to_string(),
                time_character: m.temporal_character.to_string(),
                shape: m.shape.to_string(),
            },
            attracted: m.archetype_attraction.clone(),
        })
        .collect();

    let output = PageStoriesOutput {
        generated: chrono_now_utc_pub(),
        principle: "The value of knowledge is a matter of perspective.",
        total_pages_touched: total_pages,
        total_surfaces_touched: surfaces.len(),
        surfaces,
    };

    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(config.output_dir.join("page-stories.json"), json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_all_empty() {
        let dir = std::env::temp_dir().join("campfire_writer_test");
        let _ = std::fs::create_dir_all(&dir);

        let config = CampfireWriterConfig {
            output_dir: dir.clone(),
            mirror_messages_path: dir.join("mirror-test.jsonl"),
        };

        write_all(&config, &[]).unwrap();

        // All three files should exist
        assert!(dir.join("visitor-stories.json").exists());
        assert!(dir.join("page-stories.json").exists());
        assert!(dir.join("campfire.json").exists());

        // Verify visitor-stories.json is valid JSON
        let vs: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("visitor-stories.json")).unwrap()
        ).unwrap();
        assert_eq!(vs["total_visitors"], 0);

        // Verify page-stories.json
        let ps: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("page-stories.json")).unwrap()
        ).unwrap();
        assert_eq!(ps["principle"], "The value of knowledge is a matter of perspective.");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_all_with_data() {
        let dir = std::env::temp_dir().join("campfire_writer_test_data");
        let _ = std::fs::create_dir_all(&dir);

        let config = CampfireWriterConfig {
            output_dir: dir.clone(),
            mirror_messages_path: dir.join("mirror-test.jsonl"),
        };

        let mut accum = EntityAccum::new();
        accum.hosts.insert("cytokine.primals.eco".into(), 50);
        accum.hosts.insert("thymus.primals.eco".into(), 30);
        accum.hosts.insert("complement.primals.eco".into(), 20);
        accum.total = 100;
        accum.first_ts = 1000.0;
        accum.last_ts = 37000.0;

        let entities = vec![(EntityId::HumanBrowser, &accum)];
        write_all(&config, &entities).unwrap();

        // visitor-stories should have 1 visitor
        let vs: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("visitor-stories.json")).unwrap()
        ).unwrap();
        assert_eq!(vs["total_visitors"], 1);

        // campfire should have stories
        let cf: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("campfire.json")).unwrap()
        ).unwrap();
        assert!(cf["total_stories"].as_u64().unwrap() >= 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
