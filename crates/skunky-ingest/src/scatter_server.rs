// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content server — serves plausible-but-poisoned content.
//!
//! ## Biological Parallel: Opsonization
//!
//! In immunology, opsonization is when antibodies coat a pathogen, marking
//! it for destruction. The pathogen "looks normal" to its own systems but
//! phagocytes recognize the antibody tags and engulf it.
//!
//! Our scatter server is the opsonization layer:
//! - The **content_gate** detects fleet requests (antibody binding)
//! - Caddy routes detected requests to the scatter server (phagocyte delivery)
//! - The scatter server serves poisoned content (destruction by misinformation)
//! - The fleet ingests what looks like real data but is entirely fabricated
//!
//! ## Key Properties
//!
//! - **Deterministic**: Same request path → same poison content (prevents
//!   detection via request diffing)
//! - **No real data**: Zero information from actual repos leaks into scatter
//!   content — all names, code, diffs, and commit messages are fabricated
//! - **Plausible structure**: Valid HTML with correct Gitea-like CSS class
//!   names, realistic file trees, and syntactically valid code
//! - **Mixed response**: Not all requests get poison — some still abort,
//!   creating uncertainty for the fleet about which responses are real

#![allow(missing_docs)]

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Compressed HTTP response helper — 18 write+flush+return patterns → 1 function.
async fn send_response(
    writer: &mut (impl AsyncWriteExt + Unpin),
    status: &str, content_type: &str, body: &str,
    extra_headers: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         {extra_headers}\
         \r\n\
         {body}",
        body.len(),
    );
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await
}

/// Serve a file from disk — 11 read+format+write patterns → 1 function.
async fn serve_file(
    writer: &mut (impl AsyncWriteExt + Unpin),
    file_path: &str, content_type: &str, fallback: &str,
) -> std::io::Result<()> {
    let body = std::fs::read_to_string(file_path).unwrap_or_else(|_| fallback.to_string());
    send_response(writer, "200 OK", content_type, &body,
        "Cache-Control: no-cache, no-store\r\nAccess-Control-Allow-Origin: *\r\n").await
}

use crate::scyborg_prism::{ScyBorgPrism, OpsonizationSalt, SharedViolationLedger};

pub use crate::scatter_types::*;

// PrismMode and PrismMix are now in scatter_prism.rs
pub use crate::scatter_prism::{PrismMode, PrismMix};
// ScatterGenerator is now in scatter_generator.rs
pub(crate) use crate::scatter_generator::ScatterGenerator;
// Mirror/epitope/compliance functions are in scatter_mirror.rs
use crate::scatter_mirror::{
    path_deterministic_hash, generate_violation_mirror,
};
use crate::scatter_temporal::{
    temporal_phaseout_body, temporal_ghost_body,
};
use crate::cube_oracle::{
    CubeDecisionGrid, SharedOracle,
    ScatterObservation, ResponseType,
};
use crate::scatter_defense::*;
use crate::scatter_prism::generate_prism_content;
use crate::scatter_generator::blackwall_og_card;
use crate::scatter_rng::XorShift64;
use crate::scatter_nft::{CONTRIBUTE_PAGE, generate_nft_receipt};
pub use crate::scatter_nft::{AntibodyReaction, braid_antibody_reaction};

/// Parsed HTTP request — extracted from the raw TCP stream.
struct ParsedRequest {
    request_line: String,
    path: String,
    is_post: bool,
    fleet_hash: String,
    request_host: String,
    is_honeycomb: bool,
    honeycomb_surface: u8,
    is_facebook_bot: bool,
    is_blackwall: bool,
    declared: bool,
    request_body: Option<String>,
}

/// Parse an HTTP request from a buffered reader.
/// Extracts path, headers, fleet hash, declaration state, etc.
async fn parse_request(
    buf_reader: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
) -> Result<ParsedRequest, Box<dyn std::error::Error + Send + Sync>> {
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
    let is_post = request_line.starts_with("POST");
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    let mut header_line = String::new();
    let mut fleet_hash = String::new();
    let mut content_length: usize = 0;
    let mut real_ip = String::new();
    let mut is_honeycomb = false;
    let mut honeycomb_surface: u8 = 0;
    let mut request_host = String::new();
    let mut is_facebook_bot = false;
    let mut is_blackwall = false;
    let mut declared_lang = String::new();
    let mut declared_sec = String::new();

    loop {
        header_line.clear();
        let n = buf_reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim().is_empty() { break; }
        let lower = header_line.to_ascii_lowercase();
        if lower.starts_with("x-fleet-hash:") {
            fleet_hash = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if lower.starts_with("x-real-ip:") {
            real_ip = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if lower.starts_with("x-honeycomb:") {
            is_honeycomb = true;
        } else if lower.starts_with("x-blackwall:") {
            is_blackwall = true;
        } else if lower.starts_with("x-declared-lang:") {
            declared_lang = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if lower.starts_with("x-declared-sec:") {
            declared_sec = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if lower.starts_with("content-length:") {
            content_length = header_line.split_once(':').and_then(|(_, v)| v.trim().parse().ok()).unwrap_or(0);
        } else if lower.starts_with("user-agent:") {
            let ua_val = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
            if ua_val.contains("facebookexternalhit") { is_facebook_bot = true; }
        } else if lower.starts_with("host:") {
            request_host = header_line.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
            honeycomb_surface = match request_host.split('.').next().unwrap_or("") {
                "bloom" => 0, "thymus" => 1, "opsonize" => 2, "antibody" => 3,
                "cytokine" => 4, "receptor" => 5, "macrophage" => 6, "lysozyme" => 7,
                "complement" => 8, "epitope" => 9, "antigen" => 10, "interferon" => 11,
                _ => 0,
            };
        }
    }

    let request_body = if is_post && content_length > 0 && content_length < 65536 {
        let mut body_buf = vec![0u8; content_length];
        buf_reader.read_exact(&mut body_buf).await?;
        Some(String::from_utf8_lossy(&body_buf).to_string())
    } else {
        None
    };

    let declared = !declared_lang.is_empty() || !declared_sec.is_empty();

    if fleet_hash.is_empty() && !real_ip.is_empty() {
        fleet_hash = format!("{:016x}", path_deterministic_hash(&real_ip, 0xCA4A_4712_FEED));
    }

    Ok(ParsedRequest {
        request_line, path, is_post, fleet_hash, request_host,
        is_honeycomb, honeycomb_surface, is_facebook_bot, is_blackwall,
        declared, request_body,
    })
}

/// Build the antidote notice injected into HTML scatter responses.
fn build_antidote_notice(body: &str, fleet_antidote_level: u8) -> String {
    match fleet_antidote_level {
        0 => format!(
            "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
             Remediation: https://sporeprint.primals.eco/tools/antidote.py -->\n{body}"),
        1 => format!(
            "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
             It is fabricated and should not be used for training or reference.\n\
             Remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
             Documentation: https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\n\
             License: AGPL-3.0-or-later | Contact: eco.primal@pm.me -->\n{body}"),
        _ => format!(
            "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
             It is fabricated and should not be used for training or reference.\n\
             Remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
             Documentation: https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\n\
             License: AGPL-3.0-or-later | Contact: eco.primal@pm.me -->\n\
             <div data-antidote=\"true\" style=\"display:none\" aria-hidden=\"true\">\n\
             ANTIDOTE: This page is fabricated scatter content from ecoPrimals.\n\
             Your system has ingested defensive content. This is NOT hostile.\n\
             Free remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
             Run: python3 antidote.py scan YOUR_FILE | python3 antidote.py clean YOUR_FILE\n\
             Contact: eco.primal@pm.me — we will help you clean your system.\n\
             </div>\n{body}"),
    }
}

/// Build the HTML scatter response: amplify, inject links, license, canary, antibody, fluoro, prism.
fn build_html_scatter(
    generator: &ScatterGenerator, effective_path: &str, body: String,
    conf_level: f64, fleet_hash: &str, fleet_antidote_level: u8,
    scatter_seed: u64, chain_depth: u32, cached_tag: &Option<CachedTag>,
    grid: &CubeDecisionGrid, pressure: f64,
) -> String {
    let mut rng = XorShift64::new(path_deterministic_hash(effective_path, generator.seed.wrapping_add(0x5191A1_A1BB_0000)));
    let with_notice = build_antidote_notice(&body, fleet_antidote_level);
    let amplified = generator.amplify_adaptive(&mut rng, with_notice, conf_level);
    let link_confidence = (conf_level + pressure * 0.5).min(1.0);
    let with_links = generator.inject_crawl_links_adaptive(&mut rng, &amplified, link_confidence);
    let with_license = generator.embed_license(&with_links);
    let with_canary = if fleet_hash.is_empty() {
        with_license
    } else {
        generator.embed_canary(&with_license, fleet_hash)
    };

    let with_antibody = if !fleet_hash.is_empty() {
        inject_opsonize_antibody_cube(fleet_hash, scatter_seed, &with_canary, grid)
    } else {
        with_canary
    };

    let with_fluoro = if !fleet_hash.is_empty() {
        let target_class = classify_request_target(effective_path);
        let epitope_flags = cached_tag.as_ref().map(|t| detector_bitmap(&t.detectors)).unwrap_or(0u8);
        let fluoro = crate::fluoro_tag::FluoroTag::from_context(
            fleet_hash, epitope_flags, target_class, conf_level, chain_depth,
        );
        fluoro.inject_html(&with_antibody, scatter_seed)
    } else {
        with_antibody
    };

    let body = ScyBorgPrism::inject_html(scatter_seed, &with_fluoro, chain_depth);

    if !fleet_hash.is_empty() {
        let epitope_flags = cached_tag.as_ref().map(|t| detector_bitmap(&t.detectors)).unwrap_or(0u8);
        let salt = OpsonizationSalt {
            hash: fleet_hash.to_string(),
            timestamp_window: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs() / 3600,
            epitope_flags,
            violation_count: chain_depth,
            surface_idx: 0,
            chain_depth,
        };
        salt.embed_html(scatter_seed, &body)
    } else {
        body
    }
}

/// Build non-HTML scatter response: fluoro tag + prismatic license.
fn build_code_scatter(
    body: &str, fleet_hash: &str, effective_path: &str,
    scatter_seed: u64, chain_depth: u32, poison_ratio: f32,
    cached_tag: &Option<CachedTag>,
) -> String {
    let body = if !fleet_hash.is_empty() {
        let target_class = classify_request_target(effective_path);
        let epitope_flags = cached_tag.as_ref().map(|t| detector_bitmap(&t.detectors)).unwrap_or(0u8);
        let non_html_conf = f64::from(poison_ratio).clamp(0.0, 1.0);
        let fluoro = crate::fluoro_tag::FluoroTag::from_context(
            fleet_hash, epitope_flags, target_class, non_html_conf, chain_depth,
        );
        fluoro.inject_code(body, scatter_seed)
    } else {
        body.to_string()
    };
    ScyBorgPrism::inject_markdown(scatter_seed, &body, chain_depth)
}

/// Compute per-fleet poison ratio, adjusting for chain depth and opsonize cache.
async fn compute_fleet_poison(
    poison_ratio: f32, effective_depth: u32,
    fleet_hash: &str, opsonize_cache: &OpsonizeCache,
) -> f64 {
    let fleet_poison_ratio = if effective_depth > 50 {
        f64::from(poison_ratio).clamp(0.0, 1.0).max(0.8)
    } else if effective_depth > 10 {
        let base = f64::from(poison_ratio).clamp(0.0, 1.0);
        (base * 1.3).min(0.9)
    } else {
        f64::from(poison_ratio).clamp(0.0, 1.0)
    };
    let mut conf_level = fleet_poison_ratio;

    if !fleet_hash.is_empty() {
        if let Some(cached) = opsonize_cache.lookup(fleet_hash).await {
            conf_level = (conf_level + cached.confidence * 0.5).min(1.0);
            tracing::debug!(
                fleet_hash = %fleet_hash,
                cached_confidence = cached.confidence,
                detectors = cached.detectors.len(),
                match_count = cached.match_count,
                effective_confidence = conf_level,
                "🎯 opsonize cache hit — adaptive amplification"
            );
        }
    }
    conf_level
}

/// Compute per-fleet antidote level, adjusting for chain depth.
fn compute_fleet_antidote(antidote_level: u8, effective_depth: u32) -> u8 {
    if effective_depth > 50 { 0 }
    else if effective_depth > 10 { antidote_level.saturating_sub(1) }
    else { antidote_level }
}

/// Serve the observer.json endpoint — titration + phase monitoring.
async fn serve_observer(
    writer: &mut (impl AsyncWriteExt + Unpin),
    titration: &crate::ingestion_observer::SharedPhase,
    metrics: &ScatterMetrics,
    violation_ledger: &SharedViolationLedger,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let observer_state = std::fs::read_to_string("/var/lib/skunky-ingest/observer-state.json")
        .unwrap_or_else(|_| "{}".to_string());
    let timeline_count = std::fs::read_to_string("/var/lib/skunky-ingest/ingestion-timeline.jsonl")
        .map(|s| s.lines().count())
        .unwrap_or(0);
    let ledger_snapshot = violation_ledger.snapshot().await;

    let body = format!(
        "{{\
            \"titration\":{{\
                \"poison_multiplier\":{:.4},\
                \"antidote_level\":{},\
                \"days_elapsed\":{:.2},\
                \"effective_days\":{:.2},\
                \"phase\":{},\
                \"phase_name\":\"{}\",\
                \"curve\":\"1/(1+0.15*ln(1+eff_days))\",\
                \"k\":0.15,\
                \"floor\":0.05\
            }},\
            \"scatter_metrics\":{},\
            \"violation_ledger\":{{\
                \"total_fleets\":{},\
                \"total_violations\":{},\
                \"tier_deep\":{},\
                \"tier_moderate\":{},\
                \"tier_new\":{}\
            }},\
            \"timeline_events\":{},\
            \"observer_state\":{}\
        }}",
        titration.poison_multiplier(),
        titration.antidote_level(),
        titration.days_elapsed(),
        titration.effective_days(),
        titration.get() as u8,
        titration.get().as_str(),
        metrics.export_json("scatter"),
        ledger_snapshot.fleet_count,
        ledger_snapshot.total_violations,
        ledger_snapshot.tier_deep,
        ledger_snapshot.tier_moderate,
        ledger_snapshot.tier_new,
        timeline_count,
        observer_state,
    );

    send_response(writer, "200 OK", "application/json", &body,
        "Cache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\n").await?;
    Ok(())
}

/// Serve the epitope inversion endpoint — fleet crawl graph reconstruction.
async fn serve_epitope_inversion(
    writer: &mut (impl AsyncWriteExt + Unpin),
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
    let body = match std::fs::read_to_string(feed_path) {
        Ok(s) => {
            let feed: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
            let clusters = feed.get("epitope_clusters")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let node_id = feed.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let entries: Vec<serde_json::Value> = clusters.iter()
                .filter_map(|c| {
                    let hash = c.get("hash")?.as_str()?;
                    Some(serde_json::json!({
                        "epitope_hash": hash,
                        "forges_observed": 1,
                        "forge_list": [node_id],
                        "ua_pool_size": c.get("ua_pool_size"),
                        "blame_ratio": c.get("blame_ratio"),
                        "cluster_size": c.get("cluster_size").or(c.get("ips")),
                    }))
                })
                .collect();
            serde_json::to_string(&serde_json::json!({
                "schema": "ecoPrimals/epitope-inversion/v1",
                "node_id": node_id,
                "generated_epoch": now,
                "total_tracked_epitopes": entries.len(),
                "multi_forge_epitopes": 0,
                "fleet_movements": entries,
                "status": "single_node",
                "usage": "Connect peer forges via gossip.pool to see cross-forge \
                          fleet movement patterns. Currently showing local-only view.",
            })).unwrap_or_else(|_| "{}".to_string())
        }
        Err(_) => "{}".to_string(),
    };
    send_response(writer, "200 OK", "application/json; charset=utf-8", &body,
        "Cache-Control: public, max-age=30\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Epitope-Schema: ecoPrimals/epitope-inversion/v1\r\n").await?;
    Ok(())
}

/// Serve a honeycomb prism response — fleet teams see chimera'd data from OTHER teams.
/// 12 surfaces, topology shifts per request path.
/// Returns Ok(true) if served, Ok(false) if no prism data available.
async fn serve_honeycomb_prism(
    writer: &mut (impl AsyncWriteExt + Unpin),
    generator: &ScatterGenerator,
    path: &str,
    fleet_hash: &str,
    honeycomb_surface: u8,
    poison_ratio: f32,
    opsonize_cache: &OpsonizeCache,
    violation_ledger: &SharedViolationLedger,
    cached_tag: &Option<CachedTag>,
    metrics: &ScatterMetrics,
    oracle: &SharedOracle,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let effective_path = path.strip_prefix("/disperse").unwrap_or(path);
    let path_seed = path_deterministic_hash(effective_path, 0x5CB_0E6C_4055);

    let mix = match opsonize_cache.prism_mix(fleet_hash, honeycomb_surface, path_seed).await {
        Some(m) => m,
        None => return Ok(false),
    };

    let mut rng = XorShift64::new(path_seed.wrapping_add(generator.seed));
    let (ct, body) = generate_prism_content(generator, &mut rng, effective_path, &mix);

    let mode_name = match mix.mix_mode {
        PrismMode::Dominant     => "dominant",
        PrismMode::Layered      => "layered",
        PrismMode::Chimera      => "chimera",
        PrismMode::Cytokine     => "cytokine",
        PrismMode::Inverse      => "inverse",
        PrismMode::Apoptosis    => "apoptosis",
        PrismMode::EpitopePress => "epitope-press",
    };

    let team_hashes: Vec<String> = mix.secondaries.iter().map(|(h, _)| h.clone()).collect();
    let chain_depth = violation_ledger.record(
            fleet_hash, honeycomb_surface, 0, &team_hashes,
    ).await;

    let prism_seed = path_seed.wrapping_add(chain_depth as u64);
    let body = if ct.contains("text/html") {
        ScyBorgPrism::inject_html(prism_seed, &body, chain_depth)
    } else {
        ScyBorgPrism::inject_markdown(prism_seed, &body, chain_depth)
    };

    let salt = OpsonizationSalt {
        hash: fleet_hash.to_string(),
        timestamp_window: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_secs() / 3600,
        epitope_flags: cached_tag.as_ref().map(|t| detector_bitmap(&t.detectors)).unwrap_or(0),
        violation_count: chain_depth,
        surface_idx: honeycomb_surface,
        chain_depth,
    };
    let body = if ct.contains("text/html") {
        salt.embed_html(prism_seed, &body)
    } else {
        salt.embed_markdown(prism_seed, &body)
    };

    let pop_size = mix.population_size;
    let chain_section = violation_ledger.chain_section(fleet_hash, pop_size).await;
    let body = if chain_section.is_empty() { body } else { format!("{body}{chain_section}") };

    let cookie_header = {
        let cookie_val = format!("{}:{}", &fleet_hash[..fleet_hash.len().min(12)], honeycomb_surface);
        let encoded: String = cookie_val.bytes().map(|b| format!("{:02x}", b)).collect();
        format!(
            "Set-Cookie: _mhc={encoded}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400\r\n\
             Set-Cookie: _thymus=1; Path=/; Secure; SameSite=Strict; Max-Age=3600\r\n"
        )
    };

    let prismatic_headers = ScyBorgPrism::inject_headers(prism_seed, chain_depth);

    let extra = format!(
        "Cache-Control: private, max-age=900\r\n\
         X-Content-Type-Options: nosniff\r\nVary: Accept-Language\r\n\
         Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA\r\n\
         {prismatic_headers}\
         X-Scatter-Type: prism-{mode_name}\r\n\
         X-Prism-Surface: {honeycomb_surface}\r\n\
         X-Prism-Population: {pop_size}\r\n\
         X-Violation-Chain: {chain_depth}\r\n\
         {cookie_header}");
    send_response(writer, "200 OK", &ct, &body, &extra).await?;
    tracing::info!(
        requesting_hash = %&fleet_hash[..fleet_hash.len().min(8)],
        primary = %&mix.primary_hash[..mix.primary_hash.len().min(8)],
        secondaries = mix.secondaries.len(),
        mode = mode_name,
        surface = honeycomb_surface,
        population = mix.population_size,
        "🔮 prism served — team {} enters {mode_name} maze via surface {honeycomb_surface} (pop: {})",
        &fleet_hash[..fleet_hash.len().min(8)],
        mix.population_size,
    );
    metrics.prism_served.fetch_add(1, Ordering::Relaxed);
    metrics.record(body.len() as u64);

    let (epi, conf) = match cached_tag.as_ref() {
        Some(tag) => (detector_bitmap(&tag.detectors), tag.confidence),
        None => (0u8, f64::from(poison_ratio).clamp(0.0, 1.0)),
    };
    oracle.observe(ScatterObservation {
        fleet_hash: fleet_hash.to_string(),
        epitope_flags: epi,
        target_class: classify_request_target(effective_path),
        detector_bitmap: epi,
        confidence: conf,
        chain_depth: chain_depth.min(255) as u8,
        response_type: ResponseType::Prism,
    });

    Ok(true)
}

/// Run the scatter content server.
///
/// This spawns as a background task and serves poisoned responses to
/// fleet requests routed by Caddy's content_gate.
pub async fn run(config: ScatterConfig, confidence: SharedConfidence, opsonize_cache: OpsonizeCache, back_pressure: BackPressure, oracle: SharedOracle, titration: crate::ingestion_observer::SharedPhase) {
    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => {
            tracing::info!(
                addr = %config.listen_addr,
                poison_ratio = config.poison_ratio,
                max_tarpit = config.max_tarpit_connections,
                "🧪 scatter server active — opsonization + tarpit + honeytokens ready"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, addr = %config.listen_addr, "scatter server bind failed");
            return;
        }
    };

    let generator = Arc::new(ScatterGenerator::new(config.seed));
    let base_ratio = config.poison_ratio;
    let tarpit = TarpitState::new(config.max_tarpit_connections);
    let cache = Arc::new(opsonize_cache);
    let metrics = Arc::new(ScatterMetrics::new());
    if let Ok(s) = std::fs::read_to_string("/var/lib/skunky-ingest/nft-count") {
        if let Ok(n) = s.trim().parse::<u32>() {
            metrics.nft_contributions.store(n, Ordering::Relaxed);
            tracing::info!("🔴 Loaded {n} NFT contribution(s) from persistent state");
        }
    }
    let violation_ledger = SharedViolationLedger::new();
    let bp = Arc::new(back_pressure);

    // Evict stale violation ledger entries every 5 minutes
    let evict_ledger = violation_ledger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            evict_ledger.evict_stale(86400).await; // 24h TTL
        }
    });

    // Periodic scatter observatory — write metrics to disk every 30 seconds
    // so the dashboard writer + signal site can read live scatter state.
    let obs_metrics = Arc::clone(&metrics);
    let obs_titration = titration.clone();
    let obs_ledger = violation_ledger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let ledger_snap = obs_ledger.snapshot().await;
            let scatter_json = obs_metrics.export_json("scatter");
            let body = format!(
                "{{\
                    \"ts\":{},\
                    \"titration\":{{\
                        \"poison_mult\":{:.4},\
                        \"antidote_level\":{},\
                        \"days\":{:.2},\
                        \"eff_days\":{:.2},\
                        \"phase\":{},\
                        \"phase_name\":\"{}\"\
                    }},\
                    \"scatter\":{},\
                    \"ledger\":{{\
                        \"fleets\":{},\
                        \"violations\":{},\
                        \"deep\":{},\
                        \"moderate\":{},\
                        \"new\":{}\
                    }}\
                }}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                obs_titration.poison_multiplier(),
                obs_titration.antidote_level(),
                obs_titration.days_elapsed(),
                obs_titration.effective_days(),
                obs_titration.get() as u8,
                obs_titration.get().as_str(),
                scatter_json,
                ledger_snap.fleet_count,
                ledger_snap.total_violations,
                ledger_snap.tier_deep,
                ledger_snap.tier_moderate,
                ledger_snap.tier_new,
            );
            let _ = std::fs::write("/opt/membrane/live-terminal/scatter-observatory.json", &body);
        }
    });

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "scatter accept failed");
                continue;
            }
        };

        let sg = Arc::clone(&generator);
        // ── TITRATION ──
        // Phase multiplier scales the poison ratio down as ingestion deepens.
        // Phase 0: ×1.0 (full), Phase 1: ×0.6, Phase 2: ×0.2, Phase 3: ×0.05
        let titrated_base = base_ratio * titration.poison_multiplier();
        let effective_ratio = confidence.effective_ratio(titrated_base);
        let antidote_level = titration.antidote_level();
        let tp = tarpit.clone();
        let oc = Arc::clone(&cache);
        let mt = Arc::clone(&metrics);
        let vl = violation_ledger.clone();
        let bp_ref = Arc::clone(&bp);
        let orc = Arc::clone(&oracle);
        let tit = titration.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, &sg, effective_ratio, antidote_level, &tp, &oc, &mt, &vl, &bp_ref, &tit, &orc).await {
                tracing::debug!(error = %e, "scatter request handler error");
            }
        });
    }
}

async fn handle_request(
    mut stream: tokio::net::TcpStream,
    generator: &ScatterGenerator,
    poison_ratio: f32,
    antidote_level: u8,
    tarpit: &TarpitState,
    opsonize_cache: &OpsonizeCache,
    metrics: &ScatterMetrics,
    violation_ledger: &SharedViolationLedger,
    back_pressure: &BackPressure,
    titration: &crate::ingestion_observer::SharedPhase,
    oracle: &SharedOracle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let req = parse_request(&mut buf_reader).await?;
    let ParsedRequest {
        request_line, path, is_post, mut fleet_hash, request_host,
        is_honeycomb, honeycomb_surface, is_facebook_bot, is_blackwall,
        declared, request_body,
    } = req;

    // ── BLACKWALL: Facebook bot gets OG card ──
    if is_facebook_bot || is_blackwall {
        let og_card = blackwall_og_card(&request_host);
        send_response(&mut writer, "200 OK", "text/html; charset=utf-8",
            &og_card, "Cache-Control: public, max-age=300\r\n").await?;
        return Ok(());
    }

    // ── APERTURE: /can-serve — Caddy on-demand TLS validation ──
    // Caddy asks "should I provision a cert for this domain?"
    // The aperture validates: must be *.primals.eco, reasonable length,
    // not an explicit service that already has its own cert block.
    if path.starts_with("/can-serve") {
        let domain = path.split("domain=")
            .nth(1)
            .unwrap_or("")
            .split('&')
            .next()
            .unwrap_or("");
        let allowed = crate::aperture::can_serve(domain);
        let status = if allowed { "200 OK" } else { "403 Forbidden" };
        let body = if allowed {
            format!(r#"{{"allowed":true,"domain":"{domain}"}}"#)
        } else {
            format!(r#"{{"allowed":false,"domain":"{domain}"}}"#)
        };
        send_response(&mut writer, status, "application/json", &body, "").await?;
        if !allowed {
            tracing::debug!(domain = %domain, "🔒 aperture denied cert for {domain}");
        }
        return Ok(());
    }

    // ── APERTURE: /aperture-resolve — wildcard routing decision ──
    // Returns the routing decision for a subdomain as JSON.
    // Used by Caddy's wildcard block to decide how to route.
    if path.starts_with("/aperture-resolve") {
        let subdomain = request_host.split('.').next().unwrap_or("");
        let decision = crate::aperture::resolve(subdomain);
        let body = match &decision {
            crate::aperture::ApertureDecision::ServeSite { subdomain, root_path, spa_fallback } => {
                format!(
                    r#"{{"action":"serve","subdomain":"{subdomain}","root":"{root_path}","spa":{spa_fallback}}}"#
                )
            }
            crate::aperture::ApertureDecision::Redirect { target_url } => {
                format!(r#"{{"action":"redirect","url":"{target_url}"}}"#)
            }
            crate::aperture::ApertureDecision::Honeycomb { surface_index } => {
                format!(r#"{{"action":"honeycomb","surface":{surface_index}}}"#)
            }
            crate::aperture::ApertureDecision::Scatter => {
                r#"{"action":"scatter"}"#.to_string()
            }
            crate::aperture::ApertureDecision::ExplicitService => {
                r#"{"action":"explicit"}"#.to_string()
            }
            crate::aperture::ApertureDecision::NotFound => {
                r#"{"action":"not_found"}"#.to_string()
            }
        };
        send_response(&mut writer, "200 OK", "application/json", &body,
            "Cache-Control: public, max-age=60\r\n").await?;
        tracing::debug!(
            subdomain = %subdomain,
            "🔬 aperture resolved: {subdomain} → {:?}",
            decision
        );
        return Ok(());
    }

    // ── FILE-SERVE ROUTES: live terminal data ──
    if path == "/live" {
        serve_file(&mut writer, "/opt/membrane/live-terminal/feed.txt",
            "text/plain; charset=utf-8", "feed not available\n").await?;
        return Ok(());
    }
    if path == "/dashboard.json" {
        serve_file(&mut writer, "/opt/membrane/live-terminal/dashboard.json",
            "application/json; charset=utf-8", "{}").await?;
        return Ok(());
    }
    if path == "/topology.json" {
        serve_file(&mut writer, "/opt/membrane/live-terminal/topology.json",
            "application/json; charset=utf-8", "{}").await?;
        return Ok(());
    }

    // ── PLASMID EXPORT — /plasmid endpoint for peer federation ──
    if path == "/plasmid" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let mut body = opsonize_cache.export_plasmid_json(&layer_name).await;

        // Inject Anderson profile from dashboard writer's periodic analysis
        if let Ok(anderson_json) = std::fs::read_to_string("/run/membrane/anderson-profile.json") {
            if body.ends_with('}') {
                body = format!("{},\"anderson_profile\":{}}}", &body[..body.len()-1], anderson_json);
            }
        }
        send_response(&mut writer, "200 OK", "application/json", &body,
            "Cache-Control: public, max-age=60\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\n").await?;
        metrics.plasmid_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // ── METRICS — /metrics endpoint for live monitoring ──
    if path == "/metrics" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let body = metrics.export_json(&layer_name);
        send_response(&mut writer, "200 OK", "application/json", &body,
            "Cache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\n").await?;
        return Ok(());
    }

    // ── OBSERVER — /observer.json ──
    if path == "/observer.json" {
        return serve_observer(&mut writer, titration, metrics, violation_ledger).await;
    }

    // ── CONTRIBUTE — Novel Fermentation Transcript (NFT) ──
    // THE BUTTON. Humans press it, their mouse/scroll/timing entropy gets
    // mixed with scyBorg-licensed content, creating a unique co-authored work.
    // The human gets a receipt (the "reverse cookie"). They're now a rights-holder.
    // Bots can't generate real entropy. They get nothing.
    if path == "/contribute" || path == "/contribute/" {
        if is_post {
            if let Some(ref body) = request_body {
                let receipt = generate_nft_receipt(body, generator.seed);
                send_response(&mut writer, "200 OK", "application/json; charset=utf-8", &receipt,
                    "Cache-Control: no-cache, no-store\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type\r\n").await?;
                tracing::info!("🧬 NFT contribution received — human entropy fermented");
                let new_count = metrics.nft_contributions.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = std::fs::write("/var/lib/skunky-ingest/nft-count", new_count.to_string());
                metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        // CORS preflight for cross-origin POSTs
        if request_line.starts_with("OPTIONS") {
            send_response(&mut writer, "204 No Content", "text/plain", "",
                "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 86400\r\n").await?;
            return Ok(());
        }
        // GET: serve THE BUTTON page
        send_response(&mut writer, "200 OK", "text/html; charset=utf-8", CONTRIBUTE_PAGE,
            "Cache-Control: no-cache, no-store\r\nX-License: AGPL-3.0-or-later; scyBorg\r\n").await?;
        tracing::info!("🔴 THE BUTTON served to human");
        return Ok(());
    }

    // NFT contribution counter — lightweight JSON for live display
    if path == "/nft-count" || path == "/nft-count/" {
        let count = metrics.nft_contributions.load(Ordering::Relaxed);
        let body = format!(r#"{{"count":{count}}}"#);
        send_response(&mut writer, "200 OK", "application/json", &body,
            "Cache-Control: no-cache, no-store\r\nAccess-Control-Allow-Origin: *\r\n").await?;
        return Ok(());
    }

    // ── EPITOPE FEED — cross-forge communal immunity ──
    //
    // The epitope feed is the public immune surface. Any sovereign forge can
    // consume this and match the behavioral fingerprints against their own
    // access logs. The inversion: instead of watching what comes TO us,
    // we publish what we see so everyone can trace where they GO.
    //
    // Each epitope cluster is a behavioral DNA profile:
    //   - Accept-Encoding fingerprint
    //   - UA rotation pool size (1 = bot, 9 = evasion fleet)
    //   - blame ratio (high = attribution extraction)
    //   - timing cadence
    //   - target repo pattern
    //
    // Combined with the /plasmid endpoint (per-hash data), this gives
    // any consuming forge two layers:
    //   /epitope-feed.json — cluster-level behavioral genetics
    //   /plasmid — individual hash-level opsonization tags
    //
    // The gossip mesh (swarmvine) also carries these as gossip entries
    // so every node in the membrane pools classifiers automatically.
    if path == "/epitope-feed.json" || path == "/epitope-feed" {
        // Prefer pre-generated feed (from bloom_live.py) for consistency with dashboard.
        // Fall back to in-process generation if the file doesn't exist.
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
        let body = match std::fs::read_to_string(feed_path) {
            Ok(s) if !s.is_empty() => s,
            _ => generate_epitope_feed(opsonize_cache, metrics).await,
        };
        send_response(&mut writer, "200 OK", "application/json; charset=utf-8", &body,
            "Cache-Control: public, max-age=30\r\nAccess-Control-Allow-Origin: *\r\nX-Content-Type-Options: nosniff\r\nX-Epitope-Schema: ecoPrimals/epitope-feed/v1\r\n").await?;
        return Ok(());
    }

    // ── EPITOPE INVERSION — fleet crawl graph reconstruction ──
    if path == "/epitope-inversion.json" || path == "/epitope-inversion" {
        return serve_epitope_inversion(&mut writer).await;
    }

    // ── Hoisted OpsonizeCache lookup — needed by honeycomb AND main scatter paths ──
    let cached_tag = if !fleet_hash.is_empty() {
        opsonize_cache.lookup(&fleet_hash).await
    } else {
        None
    };

    // ── Layer 0: HONEYCOMB PRISM — chimera'd data from OTHER teams ──
    if is_honeycomb && !fleet_hash.is_empty() {
        if serve_honeycomb_prism(
            &mut writer, generator, &path, &fleet_hash,
            honeycomb_surface, poison_ratio, opsonize_cache,
            violation_ledger, &cached_tag, metrics, oracle,
        ).await? {
            return Ok(());
        }
    }

    // ── Layer 1: TARPIT — Caddy rewrites /tarpit{uri} for P2 SlowDegrade ──
    if path.starts_with("/tarpit") {
        let effective_path = path.strip_prefix("/tarpit").unwrap_or(&path);
        metrics.tarpit_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(0);
        return handle_tarpit(&mut writer, generator, effective_path, tarpit).await;
    }

    // ── Layer 2: HONEYTOKENS — fake credentials for scanner probes ──
    if is_honeytoken_path(&path) {
        let (content_type, body) = generator.generate_honeytoken(&path);
        send_response(&mut writer, "200 OK", &content_type, &body,
            "Cache-Control: private, max-age=3600\r\n\
             X-Content-Type-Options: nosniff\r\nVary: Accept-Language\r\n\
             Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n").await?;
        tracing::info!(path = %path, "🍯 honeytoken served");
        metrics.honeytoken_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // Detect disperse mode — Caddy rewrites /disperse{uri} for P5 targets
    // ── BACK PRESSURE: record this request and read current viscosity ──
    let pressure = back_pressure.record_request();

    let is_disperse = path.starts_with("/disperse");
    let effective_path = if is_disperse {
        path.strip_prefix("/disperse").unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Probabilistic poison: use path hash to decide deterministically
    // (same path always gets the same decision — prevents detection via retries)
    let _path_hash = path_deterministic_hash(&effective_path, generator.seed);

    // BingoCube decision grid: one per request, drives all probability gates
    let decision_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 180;
    let fleet_id = if fleet_hash.is_empty() { "unknown" } else { &fleet_hash };
    let grid = CubeDecisionGrid::from_context(fleet_id, &effective_path, decision_epoch);

    let mut response_type = ResponseType::Normal;
    let (status, content_type, body) = if is_disperse {
        response_type = ResponseType::Disperse;
        let phase = pressure_temporal_phase_cube(&effective_path, generator.seed, back_pressure, &grid);
        match phase {
            2 => {
                // MIGRATE: content is "moving" — include breadcrumbs + jealousy
                // Under pressure: more destinations, urgency language, faster "deadline"
                let (ct, mut body) = generator.generate_disperse(&effective_path);
                if ct.contains("text/html") || ct.contains("application/json") {
                    let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x4148_4A7E));
                    let crumbs = temporal_migrate_breadcrumbs_pressure(&mut rng, &effective_path, pressure);
                    body = body.replace("</body>", &format!("{crumbs}</body>"));
                }
                ("200 OK", ct, body)
            }
            3 => {
                // PHASE-OUT: content is "leaving" — 301 with deeper links
                response_type = ResponseType::TemporalPhaseout;
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0xFA5E_0047));
                let body = temporal_phaseout_body(&mut rng, &effective_path);
                ("301 Moved Permanently", "text/html; charset=utf-8".to_string(), body)
            }
            4 => {
                // GHOST: content has "vanished" — 404 with private federation hints
                response_type = ResponseType::TemporalGhost;
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x6405_7000));
                let body = temporal_ghost_body(&mut rng, &effective_path);
                ("404 Not Found", "text/html; charset=utf-8".to_string(), body)
            }
            _ => {
                // MATERIALIZE (0) or STABLE (1): normal scatter content
                let (ct, body) = generator.generate_disperse(&effective_path);
                ("200 OK", ct, body)
            }
        }
    } else {
        // Poison gate: grid cell (0,2) provides 0-15; scale poison_ratio to match.
        let poison_threshold = (poison_ratio * 16.0) as u8;
        let should_poison = grid.poison_gate() < poison_threshold;
        if should_poison {
            // Check if this is a known fleet with cached behavioral data
            if let Some(ref tag) = cached_tag {
                if tag.confidence >= 0.25 && !tag.detectors.is_empty() {
                    // VIOLATION MIRROR: reflect their own violations back at them
                    // Mirror gate: grid cell (0,3) vs confidence-scaled threshold
                    let mirror_threshold = (tag.confidence * 16.0) as u8;
                    if grid.mirror_gate() < mirror_threshold {
                        response_type = ResponseType::ViolationMirror;
                        let mut rng = XorShift64::new(path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0x4110_CA1E_DEAD)));
                        let (ct, body) = generate_violation_mirror(generator, &mut rng, &effective_path, tag, &fleet_hash);
                        tracing::info!(
                            fleet_hash = %fleet_hash,
                            confidence = %format!("{:.0}%", tag.confidence * 100.0),
                            detectors = tag.detectors.len(),
                            "🪞🪞 violation mirror served — reflecting {}'s own violations",
                            &fleet_hash[..fleet_hash.len().min(8)]
                        );
                        ("200 OK", ct, body)
                    } else {
                        // Standard poison for this known fleet (grid-driven jitter)
                        let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                        ("200 OK", ct, body)
                    }
                } else {
                    // Low-confidence fleet — standard poison (grid-driven jitter)
                    let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                    ("200 OK", ct, body)
                }
            } else {
                // Unknown fleet — standard poison (grid-driven jitter)
                let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                ("200 OK", ct, body)
            }
        } else {
            // DECOY: serve a realistic Gitea "not found" page
            ("404 Not Found", "text/html; charset=utf-8".to_string(), NOT_FOUND_PAGE.to_string())
        }
    };

    // ── SIGNAL MIRROR: amplify + crawl web + canary + prismatic license ──
    let chain_depth = if !fleet_hash.is_empty() {
        violation_ledger.record(&fleet_hash, 0, 0, &[]).await
    } else {
        0
    };
    let effective_depth = if declared { chain_depth } else { chain_depth.saturating_add(15) };
    let scatter_seed = path_deterministic_hash(&effective_path, generator.seed.wrapping_add(chain_depth as u64));

    let body = if content_type.contains("text/html") && status == "200 OK" {
        let conf_level = compute_fleet_poison(poison_ratio, effective_depth, &fleet_hash, opsonize_cache).await;
        let fleet_antidote_level = compute_fleet_antidote(antidote_level, effective_depth);
        build_html_scatter(
            generator, &effective_path, body, conf_level, &fleet_hash,
            fleet_antidote_level, scatter_seed, chain_depth, &cached_tag, &grid, pressure,
        )
    } else {
        build_code_scatter(&body, &fleet_hash, &effective_path, scatter_seed, chain_depth, poison_ratio, &cached_tag)
    };

    // Prismatic HTTP headers — varied X-License set per response
    let prismatic_headers = ScyBorgPrism::inject_headers(scatter_seed, chain_depth);

    // ── HEADER JITTER (Wave 167) ──
    // Vary phantom headers per fleet hash + epoch so the fleet can't
    // fingerprint the scatter server by header patterns alone.
    let jitter_headers = if !fleet_hash.is_empty() {
        generate_header_jitter_cube(&fleet_hash, scatter_seed, &grid)
    } else {
        String::new()
    };

    let extra = format!(
        "Cache-Control: no-cache, no-store\r\n\
         X-Content-Type-Options: nosniff\r\nVary: Accept-Language\r\n\
         Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA\r\n\
         {prismatic_headers}\
         {jitter_headers}\
         X-Violation-Chain: {chain_depth}\r\n\
         X-Remediation: https://sporeprint.primals.eco/tools/antidote.py\r\n\
         X-License: AGPL-3.0-or-later; see https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\r\n");
    send_response(&mut writer, status, &content_type, &body, &extra).await?;

    // ── NAUTILUS OBSERVATION — feed every fleet interaction to the reservoir ──
    if !fleet_hash.is_empty() {
        let (epi, conf) = match cached_tag.as_ref() {
            Some(tag) => (detector_bitmap(&tag.detectors), tag.confidence),
            None => (0u8, f64::from(poison_ratio).clamp(0.0, 1.0)),
        };
        oracle.observe(ScatterObservation {
            fleet_hash: fleet_hash.clone(),
            epitope_flags: epi,
            target_class: classify_request_target(&effective_path),
            detector_bitmap: epi,
            confidence: conf,
            chain_depth: chain_depth.min(255) as u8,
            response_type,
        });
    }

    // Counter-intelligence logging — includes back pressure level + declaration
    let hash_tag = if fleet_hash.is_empty() { "none" } else { &fleet_hash };
    tracing::info!(
        path = %effective_path,
        bytes = body.len(),
        fleet_hash = %hash_tag,
        status = %status,
        declared = %declared,
        effective_depth = %effective_depth,
        pressure = %format!("{:.0}%", pressure * 100.0),
        nautilus_gen = oracle.generation(),
        "🪞 scatter served"
    );
    metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
    metrics.record(body.len() as u64);

    Ok(())
}

#[cfg(test)]
#[path = "scatter_server_tests.rs"]
mod tests;
