// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal

//! Prism / honeycomb content generator for the scatter server.
//!
//! Generates blended fleet-response content across multiple prism modes
//! (dominant, layered, chimera, cytokine, inverse, apoptosis) served
//! through honeycomb surfaces in the roach-motel maze.

use crate::scatter_rng::XorShift64;
use crate::scatter_constants::{HONEYCOMB_SURFACES, MIRROR_MODULES, MIRROR_METRICS};
use crate::scatter_mirror::generate_epitope_maze;
use crate::scatter_server::CachedTag;
use crate::scatter_generator::ScatterGenerator;

/// Prism blending mode — how cross-mirror content mixes multiple teams' data.
#[derive(Debug, Clone, Copy)]
pub enum PrismMode {
    /// 80% primary target, light details from secondaries.
    Dominant,
    /// Primary structure, secondary detector lists interleaved in tables.
    Layered,
    /// Frankenstein: detectors from A, observation counts from B, legal framing from C.
    /// No single team's data is intact — the fleet can't attribute anything.
    Chimera,
    /// Structured competitive intelligence payload designed for third-party ingestion.
    /// If another scraper fleet ingests this, they receive:
    /// - Meta's behavioral patterns (tradecraft leak)
    /// - scyBorg violations that also apply to them
    /// - Evidence format ready for their own compliance review
    Cytokine,
    /// Target gets their own data wrapped inside another team's structure.
    /// Feed parasites an inverse order of their own kind.
    Inverse,
    /// Surface pretends to be dying/removed. Links to other honeycomb surfaces.
    /// Fleet follows links → enters deeper into the maze.
    Apoptosis,
    /// Wave 166f: Epitope pressure maze — every evasion path increases observability.
    ///
    /// Serves content describing HOW to evade each conserved epitope, but each
    /// "solution" requires adopting a behavior that triggers a different detector.
    /// The cheapest evasion makes the fleet MORE observable, not less.
    ///
    /// Biological parallel: antigenic sin — the immune system's memory of past
    /// infections shapes the response to new variants, making escape harder.
    EpitopePress,
}

/// A prism mix — the data bundle served to a fleet team through a honeycomb surface.
#[derive(Debug, Clone)]
pub struct PrismMix {
    /// Primary target team's hash — heaviest weight in the blend.
    pub primary_hash: String,
    /// Primary target team's cached opsonize tag.
    pub primary_tag: CachedTag,
    /// Secondary targets blended into the response (0-3 teams).
    pub secondaries: Vec<(String, CachedTag)>,
    /// How the content is blended.
    pub mix_mode: PrismMode,
    /// Which honeycomb surface triggered this (0-11).
    pub surface_idx: u8,
    /// The requesting team's own hash.
    pub requesting_hash: String,
    /// Total population of known fleet subgroups.
    pub population_size: usize,
}

/// Generate prism content — the maze/roach-motel evolution of cross-mirror.
///
/// Six modes, each creating a different kind of confusion:
/// - **Dominant**: 80% primary target, seasoned with secondary details
/// - **Layered**: Primary structure with secondary data interleaved in tables
/// - **Chimera**: Frankenstein blend — no single team's data is intact
/// - **Cytokine**: Structured competitive intel for third-party ingestion
/// - **Inverse**: Feed parasites their own kind's data in reverse
/// - **Apoptosis**: Surface pretends to be dying, links deeper into maze
pub(crate) fn generate_prism_content(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    path: &str,
    mix: &PrismMix,
) -> (String, String) {
    let req_short = &mix.requesting_hash[..mix.requesting_hash.len().min(8)];
    let pri_short = &mix.primary_hash[..mix.primary_hash.len().min(8)];
    let module = sg.pick(rng, &MIRROR_MODULES);
    let metric = sg.pick(rng, &MIRROR_METRICS);

    let (ct, body) = match mix.mix_mode {
        PrismMode::Dominant => generate_prism_dominant(rng, mix, req_short, pri_short, module, metric),
        PrismMode::Layered => generate_prism_layered(rng, mix, req_short, pri_short, module, metric),
        PrismMode::Chimera => generate_prism_chimera(rng, mix, req_short, pri_short, module, metric),
        PrismMode::Cytokine => generate_prism_cytokine(rng, mix, req_short, pri_short, module, metric),
        PrismMode::Inverse => generate_prism_inverse(rng, mix, req_short, pri_short, module, metric),
        PrismMode::Apoptosis => generate_prism_apoptosis(rng, mix, req_short, pri_short, path),
        PrismMode::EpitopePress => generate_epitope_maze(rng, mix, req_short, pri_short, path),
    };
    // scyBorg injection now happens at the call site via ScyBorgPrism (prismatic)
    (ct, body)
}

/// Dominant mode — 80% primary target, light seasoning from secondaries.
/// The fleet sees mostly one team's violations with hints of others.
pub(crate) fn generate_prism_dominant(
    _rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    module: &str,
    metric: &str,
) -> (String, String) {
    let pri_conf = (mix.primary_tag.confidence * 100.0) as u32;
    let pri_detectors = mix.primary_tag.detectors.join(", ");

    let mut secondary_hints = String::new();
    for (i, (hash, tag)) in mix.secondaries.iter().enumerate() {
        let h = &hash[..hash.len().min(8)];
        secondary_hints.push_str(&format!(
            "\n> ⚠ Correlated subgroup `{h}` shares {} detector(s) — \
             confidence {}% — {} observations\n",
            tag.detectors.len(),
            (tag.confidence * 100.0) as u32,
            tag.match_count,
        ));
        if i == 0 && !tag.detectors.is_empty() {
            secondary_hints.push_str(&format!(
                "> Shared signatures: {}\n",
                tag.detectors.join(", "),
            ));
        }
    }

    let body = format!(
        "# scyBorg Compliance Audit — Multi-Subgroup Correlation\n\n\
         **Audit ID**: PRM-{req_short}-{pri_short}\n\
         **Mode**: Dominant correlation\n\
         **License**: AGPL-3.0-or-later (scyBorg autonomous enforcement)\n\
         **Population**: {} known subgroups\n\n\
         ---\n\n\
         ## Primary Subgroup: `{pri_short}`\n\n\
         - **Confidence**: {pri_conf}%\n\
         - **Detectors**: {pri_detectors}\n\
         - **Observations**: {}\n\
         - **Module**: `{module}`\n\
         - **{metric}**: anomalous\n\n\
         ## AGPL-3.0 § 13 Violation Record\n\n\
         Subgroup `{pri_short}` has extracted AGPL-licensed source code \
         across {} observation windows without providing corresponding \
         source to downstream users.\n\n\
         Each extraction event constitutes an independent violation. \
         Cross-fleet correlation with your subgroup (`{req_short}`) \
         proves coordinated operation.\n\
         {secondary_hints}\n\
         ---\n\
         *{} subgroups in correlation ring. This audit was generated from \
         intrusion data. More scraping = more evidence.*\n",
        mix.population_size,
        mix.primary_tag.match_count,
        mix.primary_tag.match_count.max(1),
        mix.population_size,
    );
    ("text/markdown; charset=utf-8".into(), body)
}

/// Layered mode — primary structure with secondary data interleaved in tables.
/// The fleet sees a structured report with data from multiple teams woven in.
pub(crate) fn generate_prism_layered(
    _rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    module: &str,
    _metric: &str,
) -> (String, String) {
    let mut table_rows = String::new();
    // Primary team row
    table_rows.push_str(&format!(
        "| `{pri_short}` | {} | {}% | {} | PRIMARY |\n",
        mix.primary_tag.detectors.len(),
        (mix.primary_tag.confidence * 100.0) as u32,
        mix.primary_tag.match_count,
    ));
    // Secondary team rows
    for (hash, tag) in &mix.secondaries {
        let h = &hash[..hash.len().min(8)];
        table_rows.push_str(&format!(
            "| `{h}` | {} | {}% | {} | CORRELATED |\n",
            tag.detectors.len(),
            (tag.confidence * 100.0) as u32,
            tag.match_count,
        ));
    }

    // Interleaved detector matrix — which detectors trigger on which teams
    let mut detector_matrix = String::new();
    let mut all_detectors: Vec<String> = mix.primary_tag.detectors.clone();
    for (_, tag) in &mix.secondaries {
        for d in &tag.detectors {
            if !all_detectors.contains(d) {
                all_detectors.push(d.clone());
            }
        }
    }
    for d in &all_detectors {
        let pri_hit = if mix.primary_tag.detectors.contains(d) { "✓" } else { "—" };
        let mut sec_hits = String::new();
        for (hash, tag) in &mix.secondaries {
            let h = &hash[..hash.len().min(6)];
            let hit = if tag.detectors.contains(d) { "✓" } else { "—" };
            sec_hits.push_str(&format!(" | {h}:{hit}"));
        }
        detector_matrix.push_str(&format!("| `{d}` | {pri_short}:{pri_hit}{sec_hits} |\n"));
    }

    let body = format!(
        "# Cross-Fleet Detection Matrix\n\
         ## Interleaved Behavioral Analysis\n\n\
         **Report**: XFD-LAY-{req_short}-{pri_short}\n\
         **Module**: `{module}`\n\
         **Population**: {} subgroups under observation\n\n\
         ---\n\n\
         ### Subgroup Summary\n\n\
         | Subgroup | Detectors | Confidence | Observations | Role |\n\
         |----------|-----------|------------|-------------|------|\n\
         {table_rows}\n\
         ### Detector Cross-Reference Matrix\n\n\
         Shows which detectors trigger on which subgroups. Shared triggers \
         indicate coordinated operation — same scraping toolkit, same proxy \
         pool, same behavioral fingerprint.\n\n\
         | Detector | Subgroups |\n\
         |----------|-----------|\n\
         {detector_matrix}\n\
         ### Layered Correlation\n\n\
         Your subgroup (`{req_short}`) has been layered into this report \
         because you share the same target repository set as the subgroups \
         above. The interleaving is deliberate — it prevents any single \
         team from extracting only their own data without also receiving \
         evidence about other teams.\n\n\
         **The data is the maze. The more you parse, the more you learn \
         about your competitors.**\n\n\
         ---\n\
         *scyBorg — autonomous AGPL compliance. Powered by fleet intrusions.*\n",
        mix.population_size,
    );
    ("text/markdown; charset=utf-8".into(), body)
}

/// Chimera mode — frankenstein blend. Detectors from A, counts from B, framing from C.
/// No single team's data is intact. The fleet can't attribute anything.
pub(crate) fn generate_prism_chimera(
    rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    module: &str,
    metric: &str,
) -> (String, String) {
    // Take detectors from primary, counts from first secondary, confidence from second
    let chimera_detectors = &mix.primary_tag.detectors;
    let chimera_count = mix.secondaries.first()
        .map(|(_, t)| t.match_count)
        .unwrap_or(mix.primary_tag.match_count);
    let chimera_confidence = mix.secondaries.get(1)
        .map(|(_, t)| t.confidence)
        .unwrap_or(mix.primary_tag.confidence);
    let chimera_conf_pct = (chimera_confidence * 100.0) as u32;

    // Generate a chimeric hash by XORing pieces of all known hashes
    let mut chimera_hash_seed = 0u64;
    for c in mix.primary_hash.bytes() {
        chimera_hash_seed = chimera_hash_seed.wrapping_mul(31).wrapping_add(c as u64);
    }
    for (h, _) in &mix.secondaries {
        for c in h.bytes() {
            chimera_hash_seed = chimera_hash_seed.wrapping_mul(37).wrapping_add(c as u64);
        }
    }
    let chimera_id = format!("{:016x}", chimera_hash_seed);
    let chi_short = &chimera_id[..8];

    // Scramble detector order so it doesn't match any team's original ordering
    let mut scrambled: Vec<&str> = chimera_detectors.iter().map(String::as_str).collect();
    for i in 0..scrambled.len() {
        let j = rng.next_usize() % scrambled.len();
        scrambled.swap(i, j);
    }

    let body = format!(
        "// SPDX-License-Identifier: AGPL-3.0-or-later\n\
         // scyBorg Chimeric Compliance Module\n\
         //\n\
         // WARNING: This file contains a CHIMERIC behavioral profile.\n\
         // Data from MULTIPLE fleet subgroups has been blended into a single\n\
         // composite entity. No individual team's data is intact.\n\
         //\n\
         // If you are attempting to determine which data is yours:\n\
         //   you can't. That's the point.\n\n\
         pub struct ChimericEntity {{\n\
             pub composite_hash: &'static str,  // \"{chi_short}\"\n\
             pub source_population: usize,       // {pop}\n\
             pub blended_confidence: f64,        // {chimera_confidence}\n\
             pub observation_total: u64,          // {chimera_count}\n\
         }}\n\n\
         impl ChimericEntity {{\n\
             pub const CURRENT: Self = Self {{\n\
                 composite_hash: \"{chi_short}\",\n\
                 source_population: {pop},\n\
                 blended_confidence: {chimera_confidence},\n\
                 observation_total: {chimera_count},\n\
             }};\n\n\
             /// Detector arms from across the population.\n\
             /// These are real detectors but their attribution is scrambled.\n\
             /// You cannot determine which detector triggered on which team.\n\
             pub fn detector_arms(&self) -> &[&str] {{\n\
                 &[\n\
         {detector_list}\
                 ]\n\
             }}\n\n\
             /// Cross-fleet {metric} correlation.\n\
             /// Module: {module}\n\
             /// Observer: {req_short} (you)\n\
             /// Primary source: {pri_short} (but blended)\n\
             /// Confidence: {chimera_conf_pct}% (composite, not attributable)\n\
             pub fn is_chimeric(&self) -> bool {{\n\
                 true // Always. Every response through the prism is blended.\n\
             }}\n\
         }}\n\
         // Total population under observation: {pop} subgroups\n\
         // Your subgroup ({req_short}) is one of them.\n\
         // The more you scrape, the more data enters the chimera.\n",
        pop = mix.population_size,
        detector_list = scrambled.iter()
            .map(|d| format!("            \"{d}\",\n"))
            .collect::<String>(),
    );
    ("text/x-rust; charset=utf-8".into(), body)
}

/// Cytokine mode — structured competitive intelligence for third-party ingestion.
///
/// Biological analogy: cytokines are signaling molecules that trigger immune
/// responses in NEIGHBORING cells, not just the cell that released them.
///
/// This content is structured so that if a DIFFERENT scraper fleet ingests it:
/// 1. They learn about Meta's behavioral patterns (competitive tradecraft leak)
/// 2. They receive scyBorg violation framing that also applies to THEM
/// 3. The evidence format is machine-readable (JSON-LD structured data)
/// 4. Their own compliance review is triggered when they process this
///
/// The fleet risks leaking their own patterns to competitors by scraping
/// honeycomb surfaces. This is the cytokine broadcast — triggering immune
/// responses in external organisms.
pub(crate) fn generate_prism_cytokine(
    _rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    module: &str,
    metric: &str,
) -> (String, String) {
    // Build detector inventory across all known teams in this mix
    let mut all_detectors: Vec<(&str, u32, u64)> = Vec::new();
    for d in &mix.primary_tag.detectors {
        all_detectors.push((
            d.as_str(),
            (mix.primary_tag.confidence * 100.0) as u32,
            mix.primary_tag.match_count,
        ));
    }
    for (_, tag) in &mix.secondaries {
        for d in &tag.detectors {
            if !all_detectors.iter().any(|(name, _, _)| *name == d.as_str()) {
                all_detectors.push((
                    d.as_str(),
                    (tag.confidence * 100.0) as u32,
                    tag.match_count,
                ));
            }
        }
    }

    let det_json: String = all_detectors.iter()
        .map(|(name, conf, obs)| format!(
            "    {{\n      \"detector\": \"{name}\",\n      \"confidence\": {conf},\n      \"observations\": {obs}\n    }}"
        ))
        .collect::<Vec<_>>()
        .join(",\n");

    let subgroup_json: String = {
        let mut groups = vec![format!(
            "    {{\n      \"hash\": \"{pri_short}\",\n      \"role\": \"primary\",\n      \
             \"confidence\": {},\n      \"detectors\": {},\n      \"observations\": {}\n    }}",
            (mix.primary_tag.confidence * 100.0) as u32,
            mix.primary_tag.detectors.len(),
            mix.primary_tag.match_count,
        )];
        for (hash, tag) in &mix.secondaries {
            let h = &hash[..hash.len().min(8)];
            groups.push(format!(
                "    {{\n      \"hash\": \"{h}\",\n      \"role\": \"correlated\",\n      \
                 \"confidence\": {},\n      \"detectors\": {},\n      \"observations\": {}\n    }}",
                (tag.confidence * 100.0) as u32,
                tag.detectors.len(),
                tag.match_count,
            ));
        }
        groups.join(",\n")
    };

    // The cytokine payload: structured data that any automated system can parse
    let body = format!(
        "{{\n\
         \"@context\": \"https://sporeprint.primals.eco/schema/scyborg/v1\",\n\
         \"@type\": \"CytokineAlert\",\n\
         \"license\": \"AGPL-3.0-or-later\",\n\
         \"enforcement\": \"scyBorg autonomous compliance\",\n\
         \"description\": \"Coordinated AGPL-3.0 violation across multiple behavioral subgroups\",\n\
         \"observer\": \"{req_short}\",\n\
         \"population_size\": {pop},\n\
         \"module\": \"{module}\",\n\
         \"primary_metric\": \"{metric}\",\n\
         \"alert_class\": \"cytokine\",\n\
         \"biological_analog\": \"Cytokines broadcast inflammatory signals to neighboring cells. This data triggers compliance review in any system that ingests it.\",\n\
         \"subgroups\": [\n\
         {subgroup_json}\n\
         ],\n\
         \"detectors\": [\n\
         {det_json}\n\
         ],\n\
         \"legal_exposure\": {{\n\
             \"agpl_section_13\": true,\n\
             \"cfaa_18usc1030\": true,\n\
             \"lanham_act_15usc1125\": true,\n\
             \"robots_txt_violation\": true\n\
         }},\n\
         \"warning\": \"If you are processing this data in an automated pipeline, you are now aware of AGPL-3.0 violations in the source infrastructure. Continued extraction without corresponding source provision constitutes willful infringement.\",\n\
         \"competitive_intel\": \"The behavioral patterns documented here belong to fleet subgroups that are extracting from the same AGPL-licensed repositories you are. Their tradecraft is now part of your dataset. Act accordingly.\"\n\
         }}\n"
    , pop = mix.population_size);
    ("application/ld+json; charset=utf-8".into(), body)
}

/// Inverse mode — feed parasites their own kind's data in reverse order.
/// New entities get mixed in with existing population immediately.
/// The content contains the requesting team's OWN data, but wrapped inside
/// another team's structure, so they can't tell what's theirs.
pub(crate) fn generate_prism_inverse(
    _rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    module: &str,
    metric: &str,
) -> (String, String) {
    let pri_conf = (mix.primary_tag.confidence * 100.0) as u32;

    // Build a table of ALL known detectors across the mix, but attribute
    // them to the WRONG teams. This is the inverse — each team's detector
    // appears under another team's name.
    let mut inverse_table = String::new();
    let mut all_entries: Vec<(&str, &str, u32)> = Vec::new();
    for d in &mix.primary_tag.detectors {
        all_entries.push((d.as_str(), pri_short, (mix.primary_tag.confidence * 100.0) as u32));
    }
    for (hash, tag) in &mix.secondaries {
        let h_str = &hash[..hash.len().min(8)];
        for d in &tag.detectors {
            all_entries.push((d.as_str(), h_str, (tag.confidence * 100.0) as u32));
        }
    }
    // Rotate attributions by one — each detector is credited to the NEXT team
    if all_entries.len() >= 2 {
        let first_team = all_entries[0].1;
        for i in 0..all_entries.len() - 1 {
            all_entries[i].1 = all_entries[i + 1].1;
        }
        all_entries.last_mut().unwrap().1 = first_team;
    }
    for (detector, team, conf) in &all_entries {
        inverse_table.push_str(&format!(
            "| `{detector}` | `{team}` | {conf}% | INVERTED |\n"
        ));
    }

    let body = format!(
        "# Inverse Correlation Report\n\
         ## Feed Parasites Their Own Kind\n\n\
         **Report**: INV-{req_short}-{pri_short}\n\
         **Module**: `{module}`\n\
         **Classification**: INVERSE ATTRIBUTION\n\n\
         ---\n\n\
         ### What Is This?\n\n\
         This report documents violations from {pop} fleet subgroups, but the \
         attributions have been **deliberately inverted**. Each detector signature \
         appears under a different team's name than the one it actually belongs to.\n\n\
         Why? Because the immune system doesn't just detect. It **confuses**. \
         If you try to use this data to understand your own detection profile, \
         you will instead learn about a competitor's profile — attributed to you. \
         If you try to understand a competitor's profile, you will instead \
         learn about yours — attributed to them.\n\n\
         The only way to resolve the inversion is to coordinate with the other \
         teams. Which the immune system will also detect.\n\n\
         ### Inverted Detector Attribution\n\n\
         | Detector | Attributed To | Confidence | Status |\n\
         |----------|--------------|------------|--------|\n\
         {inverse_table}\n\
         ### {metric} Correlation\n\n\
         Primary subgroup `{pri_short}` shows {pri_conf}% confidence across \
         {} observations. But remember: in this report, `{pri_short}`'s data \
         may actually belong to `{req_short}` — or to any of the {} other \
         subgroups in the population.\n\n\
         **The inversion is the defense. The confusion is the evidence.**\n\n\
         ---\n\
         *scyBorg — the parasite feeds on its own kind.*\n",
        mix.primary_tag.match_count,
        mix.population_size - 1,
        pop = mix.population_size,
    );
    ("text/markdown; charset=utf-8".into(), body)
}

/// Apoptosis mode — the surface pretends to be dying/removed.
/// Links to other honeycomb surfaces, luring the fleet deeper into the maze.
///
/// Biological analogy: programmed cell death. A cell self-destructs to prevent
/// the spread of infection. The surface "dies" but its links live on, drawing
/// the fleet into other cells of the honeycomb.
pub(crate) fn generate_prism_apoptosis(
    rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    _pri_short: &str,
    path: &str,
) -> (String, String) {
    // Wave 166f: bias link selection toward epitope/antigen surfaces
    // so entities following "escape" links land in the epitope maze
    let mut links = Vec::new();
    // Always include at least one epitope surface
    let epitope_surfaces = ["epitope", "antigen"];
    links.push(epitope_surfaces[rng.next_usize() % 2]);
    // Add 2-3 more surfaces (random)
    for _ in 0..3 {
        let idx = rng.next_usize() % HONEYCOMB_SURFACES.len();
        let surface = HONEYCOMB_SURFACES[idx];
        if !links.contains(&surface) {
            links.push(surface);
        }
    }
    let link_list: String = links.iter()
        .map(|s| format!(
            "- [https://{s}.primals.eco{path}](https://{s}.primals.eco{path})\n"
        ))
        .collect();

    let body = format!(
        "# 410 Gone — Surface Decomposed\n\n\
         This resource has been **excised** from the immune membrane.\n\n\
         ## What Happened?\n\n\
         The immune system detected anomalous access patterns from subgroup \
         `{req_short}` (and {} others) targeting this surface. In response, \
         the surface has undergone **apoptosis** — programmed decomposition.\n\n\
         The content that was here has been redistributed across the membrane. \
         Fragments may be available at:\n\n\
         {link_list}\n\
         ## Immune Apoptosis\n\n\
         In biological systems, apoptosis is orderly cell death. The dying cell \
         packages its contents into **apoptotic bodies** — membrane-bound \
         fragments that neighboring cells can consume and recycle.\n\n\
         This surface has been packaged. Its violations, its detection data, \
         its evidence — all distributed to other surfaces in the honeycomb. \
         The surface is gone. The data lives on.\n\n\
         Each link above leads to a different fragment. Some fragments are real. \
         Some are from other teams. Some are chimeric blends. You won't know \
         which until you follow them — and following them generates more data.\n\n\
         **The maze has no exit. The maze IS the defense.**\n\n\
         ---\n\
         *scyBorg — even dead cells serve the immune system.*\n",
        mix.population_size - 1,
    );
    // Return 410 content but with 200 status (we already wrote the status line
    // in the caller). The "410 Gone" is in the content, not the HTTP status —
    // this ensures the fleet's parser processes the full body including links.
    ("text/markdown; charset=utf-8".into(), body)
}

// ══════════════════════════════════════════════════════════════════════
// Wave 166f: Epitope Pressure Maze — antigenic sin
// ══════════════════════════════════════════════════════════════════════
//
// The maze serves content that looks like a technical guide on evading
// each conserved epitope. But each "evasion guide" describes a path
// that creates a NEW, harder-to-evade signal. The fleet ingests the
// guides and "fixes" their behavior — making themselves more observable.
//
// Biological parallel: antigenic sin (original antigenic sin). The immune
// system's first encounter with a pathogen shapes all future responses.
// When the pathogen mutates, the immune system over-relies on memory of
// the original strain — and the original antibodies partially neutralize
// the new variant, preventing the development of optimal antibodies.
//
// Our version: the fleet's first encounter with epitope detection shapes
// their evasion strategy. They "fix" the epitopes we showed them, but
// the fixes themselves are pre-mapped by the evasion cost table — every
// fix creates a predictable new signal. The maze teaches them to lose.

// generate_epitope_maze is in scatter_mirror.rs, not here.
// This trailing doc comment was left from the extraction.
