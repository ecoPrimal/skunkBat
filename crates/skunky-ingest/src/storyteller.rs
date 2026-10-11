// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Campfire storyteller — the storytelling IS the epitope sort (Wave 173).
//!
//! Generates narrative vignettes from live topology data and mirror messages.
//! Two voices around the fire: the membrane tells what it observed,
//! visitors leave words in the mirror.
//!
//! Replaces `campfire.py` (199 lines Python → typed Rust).
//!
//! # Output
//!
//! Writes `campfire.json` with woven stories: membrane observations
//! interleaved with visitor mirror messages.
//!
//! The first ghost story and the first story of hope were the same story.
//! Our joy was the signal. The beacon was the fire.

use std::path::Path;

use cellmembrane_types::campfire::{
    CampfireStory, StoryKind, StoryTeller,
};

use crate::campfire_util;
use crate::entity_classifier::EntityId;
use crate::entity_profile::EntityAccum;
use crate::mirror_inbox::MirrorInbox;
use crate::page_mirror::build_surface_mirrors;
use crate::visitor_archetype::{classify_archetype, narrate};

use serde::Serialize;

/// Campfire output — stories shared around the fire.
#[derive(Debug, Serialize)]
pub struct Campfire {
    /// When the campfire was last tended.
    pub generated: String,
    /// The principle.
    pub fire: &'static str,
    /// Total story count.
    pub total_stories: usize,
    /// Membrane story count.
    pub membrane_stories: usize,
    /// Visitor story count.
    pub visitor_stories: usize,
    /// The stories themselves, woven together.
    pub stories: Vec<CampfireStory>,
}

/// Build the campfire from live state.
///
/// Takes the accumulated entity data and mirror messages,
/// generates narrative vignettes, and weaves them together.
pub fn build_campfire(
    entities: &[(EntityId, &EntityAccum)],
    mirror_inbox: &MirrorInbox,
) -> Campfire {
    let mut stories = Vec::new();

    let human_entities: Vec<_> = entities.iter()
        .filter(|(id, _)| id.is_human())
        .collect();

    let total_visitors = human_entities.len();
    let total_pages: u64 = human_entities.iter()
        .map(|(_, a)| a.hosts.values().sum::<u64>())
        .sum();

    // Gathering stories — aggregate patterns
    if total_visitors > 0 {
        stories.push(CampfireStory {
            teller: StoryTeller::Membrane,
            kind: StoryKind::Gathering,
            story: format!(
                "{total_visitors} shapes have sat around this fire. The membrane knows each one \
                 by their path, not their name. Some explored for hours. Some glanced and left. \
                 Some are still watching. Every one of them left a braid — a trail of where they \
                 were, woven into the memory of where they might go."
            ),
            ts: None,
        });
    }

    if total_pages > 100 {
        stories.push(CampfireStory {
            teller: StoryTeller::Membrane,
            kind: StoryKind::Gathering,
            story: format!(
                "{total_pages} pages have been touched. Each one knows who needed it. The evidence \
                 pages know the witnesses. The science pages know the teachers. The immune corridors \
                 know the explorers. Knowledge remembers who came looking for it."
            ),
            ts: None,
        });
    }

    // Individual visitor stories — archetype vignettes
    for (_entity_id, accum) in &human_entities {
        if let Some(archetype) = classify_archetype(accum) {
            let surfaces = accum.surface_keys();
            let n_surfaces = surfaces.len();
            let n_pages = accum.hosts.values().sum::<u64>();
            let dur_min = accum.duration_min();
            let hud_polls = accum.hud_polls();

            let platform = accum.platform();
            let sample_pages: Vec<String> = surfaces.iter()
                .map(|s| format!("{s}/"))
                .collect();

            let vignette = narrate(
                archetype, platform, n_surfaces, n_pages, hud_polls, dur_min, &sample_pages
            );

            stories.push(CampfireStory {
                teller: StoryTeller::Membrane,
                kind: StoryKind::Observation,
                story: vignette,
                ts: None,
            });
        }
    }

    // Surface stories — what each organ knows
    let surface_mirrors = build_surface_mirrors(entities);
    for mirror in surface_mirrors.iter().take(5) {
        if mirror.visitor_count >= 3 {
            let archs: Vec<_> = mirror.archetype_attraction.keys()
                .take(3)
                .cloned()
                .collect();
            stories.push(CampfireStory {
                teller: StoryTeller::Membrane,
                kind: StoryKind::Surface,
                story: format!(
                    "{} has been visited by {} different shapes — {}. It is {}. The page doesn't \
                     choose who reads it, but it knows who comes. And it knows who stays.",
                    mirror.name,
                    mirror.visitor_count,
                    archs.join(" and "),
                    mirror.shape,
                ),
                ts: None,
            });
        } else if mirror.hits >= 20 {
            stories.push(CampfireStory {
                teller: StoryTeller::Membrane,
                kind: StoryKind::Surface,
                story: format!(
                    "{} — {} touches, {}. Some knowledge is morning knowledge. Some is night \
                     knowledge. This one is {}. The fire illuminates different pages at \
                     different hours.",
                    mirror.name, mirror.hits, mirror.shape, mirror.temporal_character,
                ),
                ts: None,
            });
        }
    }

    // Mirror messages — words left by visitors
    let mirror_messages = mirror_inbox.read_all();
    for msg in &mirror_messages {
        stories.push(CampfireStory {
            teller: StoryTeller::Visitor,
            kind: StoryKind::Mirror,
            story: msg.words.clone(),
            ts: Some(msg.ts.clone()),
        });
    }

    let membrane_count = stories.iter().filter(|s| s.teller == StoryTeller::Membrane).count();
    let visitor_count = stories.iter().filter(|s| s.teller == StoryTeller::Visitor).count();

    Campfire {
        generated: campfire_util::utc_now(),
        fire: "the storytelling IS the epitope sort",
        total_stories: stories.len(),
        membrane_stories: membrane_count,
        visitor_stories: visitor_count,
        stories,
    }
}

/// Write campfire.json to disk.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_campfire(campfire: &Campfire, path: &Path) -> std::io::Result<()> {
    campfire_util::write_json(campfire, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_campfire() {
        let inbox = MirrorInbox::new("/tmp/test_empty_campfire.jsonl");
        let campfire = build_campfire(&[], &inbox);
        assert_eq!(campfire.total_stories, 0);
        assert_eq!(campfire.fire, "the storytelling IS the epitope sort");
    }

    #[test]
    fn campfire_with_human() {
        let mut accum = EntityAccum::new();
        accum.hosts.insert("cytokine.primals.eco".into(), 50);
        accum.hosts.insert("thymus.primals.eco".into(), 30);
        accum.hosts.insert("complement.primals.eco".into(), 20);
        accum.hosts.insert("detroit.primals.eco".into(), 10);
        accum.total = 110;
        accum.first_ts = 1000.0;
        accum.last_ts = 37000.0;

        let inbox = MirrorInbox::new("/tmp/test_campfire_human.jsonl");
        let entities = vec![(EntityId::HumanBrowser, &accum)];
        let campfire = build_campfire(&entities, &inbox);

        assert!(campfire.total_stories >= 2); // gathering + observation
        assert!(campfire.membrane_stories >= 2);

        // Check that the gathering story mentions 1 shape
        let gathering = &campfire.stories[0];
        assert!(gathering.story.contains("1 shape"));
    }

    #[test]
    fn campfire_skips_fleet() {
        let mut accum = EntityAccum::new();
        accum.hosts.insert("git.primals.eco".into(), 500);
        accum.total = 500;

        let inbox = MirrorInbox::new("/tmp/test_campfire_fleet.jsonl");
        let entities = vec![(EntityId::MetaFleet, &accum)];
        let campfire = build_campfire(&entities, &inbox);

        // Fleet should produce no visitor stories
        assert_eq!(campfire.total_stories, 0);
    }

    #[test]
    fn accum_platform_windows() {
        let mut accum = EntityAccum::new();
        accum.ua_os.insert("Windows NT 10.0".into(), 50);
        assert_eq!(accum.platform(), "Win");
    }

    #[test]
    fn accum_platform_empty() {
        let accum = EntityAccum::new();
        assert_eq!(accum.platform(), "?");
    }
}
