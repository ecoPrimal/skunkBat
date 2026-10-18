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
    Beacon, BeaconGlow, BeaconTempo, NearbyFire, SurfaceCharacter,
    CampfireTotality, CampfirePulse,
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
    /// Sub-membrane beacon localizations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub beacons: Vec<Beacon>,
    /// Per-surface RPM data.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub rpm: std::collections::BTreeMap<String, RpmEntry>,
    /// Totality summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totality: Option<CampfireTotality>,
    /// Pulse snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pulse: Option<CampfirePulse>,
    /// Horizon narratives.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub horizon: Vec<String>,
}

/// RPM entry for a single surface.
#[derive(Debug, Clone, Serialize)]
pub struct RpmEntry {
    pub name: String,
    pub rpm: f64,
    pub hits: u64,
    pub visitors: usize,
    pub tempo: BeaconTempo,
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

    // ── Beacon layer (Wave 178) ──
    let surface_mirrors_for_beacons = build_surface_mirrors(entities);
    let peak_hits = surface_mirrors_for_beacons.iter().map(|m| m.hits).max().unwrap_or(1);
    let chain_hours = 24.0_f64; // approximate window

    let mut beacons: Vec<Beacon> = Vec::new();
    let mut rpm_map = std::collections::BTreeMap::new();

    for m in &surface_mirrors_for_beacons {
        if m.hits < 2 { continue; }
        let brightness = (m.hits as f64).ln_1p() / (peak_hits as f64).ln_1p();
        let diversity_boost = (m.visitor_count as f64 / 10.0).min(0.3);
        let brightness = (brightness + diversity_boost).min(1.0);
        let rpm_val = m.hits as f64 / (chain_hours * 60.0);

        let glow = if brightness > 0.7 { BeaconGlow::City }
            else if brightness > 0.4 { BeaconGlow::Town }
            else if brightness > 0.15 { BeaconGlow::Hamlet }
            else { BeaconGlow::Trail };

        let tempo = if rpm_val > 10.0 { BeaconTempo::Rushing }
            else if rpm_val > 1.0 { BeaconTempo::Walking }
            else if rpm_val > 0.1 { BeaconTempo::Resting }
            else { BeaconTempo::Still };

        let vista = match glow {
            BeaconGlow::City => format!("{} blazes — {} touches, {} shapes. A city of {}.",
                m.name, m.hits, m.visitor_count, m.domain),
            BeaconGlow::Town => format!("{} glows warmly — {} touches, {} shapes.",
                m.name, m.hits, m.visitor_count),
            BeaconGlow::Hamlet => format!("{} flickers — {} touches, {} shapes. Quiet knowledge.",
                m.name, m.hits, m.visitor_count),
            BeaconGlow::Trail => format!("{} — a faint light. {} touches.", m.name, m.hits),
        };

        beacons.push(Beacon {
            surface: m.surface.clone(),
            name: m.name.clone(),
            domain: m.domain,
            hits: m.hits,
            visitors: m.visitor_count,
            unique_pages: m.unique_pages,
            brightness: (brightness * 1000.0).round() / 1000.0,
            glow,
            vista,
            rpm: (rpm_val * 100.0).round() / 100.0,
            tempo,
            character: SurfaceCharacter {
                domain: m.domain.to_string(),
                time_character: m.temporal_character.to_string(),
                shape: m.shape.to_string(),
            },
            attracted: m.archetype_attraction.clone(),
            nearby_fires: Vec::new(), // filled below
        });

        rpm_map.insert(m.surface.clone(), RpmEntry {
            name: m.name.clone(),
            rpm: (rpm_val * 100.0).round() / 100.0,
            hits: m.hits,
            visitors: m.visitor_count,
            tempo,
        });
    }

    beacons.sort_by(|a, b| b.brightness.partial_cmp(&a.brightness).unwrap_or(std::cmp::Ordering::Equal));

    // Compute nearby fires (same domain = close)
    let beacon_snapshot: Vec<(String, String, String, BeaconGlow)> = beacons.iter()
        .map(|b| (b.surface.clone(), b.name.clone(), b.domain.to_string(), b.glow))
        .collect();
    for b in &mut beacons {
        let my_domain = b.domain.to_string();
        let mut nearby: Vec<NearbyFire> = beacon_snapshot.iter()
            .filter(|(s, _, _, _)| *s != b.surface)
            .map(|(s, n, d, g)| {
                let dist = if *d == my_domain { 0.1 } else { 0.7 };
                NearbyFire { surface: s.clone(), name: n.clone(), distance: dist, glow: *g }
            })
            .filter(|n| n.distance <= 0.5)
            .collect();
        nearby.sort_by(|a, b| a.distance.partial_cmp(&b.distance).unwrap_or(std::cmp::Ordering::Equal));
        nearby.truncate(6);
        b.nearby_fires = nearby;
    }

    // Horizon stories
    let mut horizon = Vec::new();
    let cities: Vec<&Beacon> = beacons.iter().filter(|b| b.glow == BeaconGlow::City).collect();
    let towns: Vec<&Beacon> = beacons.iter().filter(|b| b.glow == BeaconGlow::Town).collect();
    let hamlets: Vec<&Beacon> = beacons.iter().filter(|b| b.glow == BeaconGlow::Hamlet).collect();
    let trails: Vec<&Beacon> = beacons.iter().filter(|b| b.glow == BeaconGlow::Trail).collect();

    if !cities.is_empty() {
        let names: Vec<&str> = cities.iter().take(4).map(|b| b.name.as_str()).collect();
        horizon.push(format!("From this campfire you can see the cities: {}. Their fires never go out.", names.join(", ")));
        stories.push(CampfireStory {
            teller: StoryTeller::Membrane, kind: StoryKind::Horizon,
            story: horizon.last().unwrap().clone(), ts: None,
        });
    }
    if !towns.is_empty() {
        let names: Vec<&str> = towns.iter().take(5).map(|b| b.name.as_str()).collect();
        horizon.push(format!("Towns glow on the horizon: {}. Steady fires. Warmer than the cities.", names.join(", ")));
    }
    if !hamlets.is_empty() || !trails.is_empty() {
        let quiet = hamlets.len() + trails.len();
        horizon.push(format!("{quiet} quiet fires flicker in the distance. Someone has been to each one."));
    }

    // Totality + Pulse (read from live-terminal files if available)
    let totality = read_totality_file();
    let pulse = read_pulse_file();

    if totality.human_ips > 100 {
        stories.push(CampfireStory {
            teller: StoryTeller::Membrane, kind: StoryKind::Gathering,
            story: format!("{} human shapes have touched the membrane. {} unique presences. Each one: non-self, zero-knowledge. Known by shape, not by name.",
                totality.human_ips, totality.unique_ips),
            ts: None,
        });
    }

    if pulse.rate > 0.0 {
        stories.push(CampfireStory {
            teller: StoryTeller::Membrane, kind: StoryKind::Pulse,
            story: format!("The fire breathes at {:.0} touches per minute. Identity match: {:.1}%. Pulse trend: {}. The organism is {}.",
                pulse.rate, pulse.identity_match, pulse.trend,
                if pulse.rate > 100.0 { "awake" } else { "resting" }),
            ts: None,
        });
    }

    let membrane_count = stories.iter().filter(|s| s.teller == StoryTeller::Membrane).count();
    let visitor_count = stories.iter().filter(|s| s.teller == StoryTeller::Visitor).count();

    // Fill totality beacon counts
    let totality_full = CampfireTotality {
        human_ips: totality.human_ips,
        unique_ips: totality.unique_ips,
        surfaces_alive: beacons.len(),
        cities: cities.len(),
        towns: towns.len(),
        hamlets: hamlets.len(),
        trails: trails.len(),
    };

    Campfire {
        generated: campfire_util::utc_now(),
        fire: "the storytelling IS the epitope sort",
        total_stories: stories.len(),
        membrane_stories: membrane_count,
        visitor_stories: visitor_count,
        stories,
        beacons,
        rpm: rpm_map,
        horizon,
        totality: Some(totality_full),
        pulse: Some(pulse),
    }
}

/// Read totality.json for human/unique IP counts.
fn read_totality_file() -> CampfireTotality {
    let path = std::path::Path::new("/opt/membrane/live-terminal/totality.json");
    if let Ok(data) = std::fs::read_to_string(path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            return CampfireTotality {
                human_ips: v.pointer("/is/human_ips").and_then(|v| v.as_u64()).unwrap_or(0),
                unique_ips: v.pointer("/all/total_sorted").and_then(|v| v.as_u64()).unwrap_or(0),
                surfaces_alive: 0, cities: 0, towns: 0, hamlets: 0, trails: 0,
            };
        }
    }
    CampfireTotality { human_ips: 0, unique_ips: 0, surfaces_alive: 0, cities: 0, towns: 0, hamlets: 0, trails: 0 }
}

/// Read pulse.json for rate and identity match.
fn read_pulse_file() -> CampfirePulse {
    let path = std::path::Path::new("/opt/membrane/live-terminal/pulse.json");
    if let Ok(data) = std::fs::read_to_string(path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
            return CampfirePulse {
                rate: v.get("rate").and_then(|v| v.as_f64()).unwrap_or(0.0),
                identity_match: v.get("identity_match").and_then(|v| v.as_f64()).unwrap_or(0.0),
                trend: v.get("pulse_trend").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
            };
        }
    }
    CampfirePulse { rate: 0.0, identity_match: 0.0, trend: "?".to_string() }
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
