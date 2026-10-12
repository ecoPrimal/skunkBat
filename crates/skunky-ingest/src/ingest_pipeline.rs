// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Per-line ingest pipeline — parse, aggregate, escalate, and emit observations.

use skunky_ingest::{
    abuse_reporter, aggregator, bloom_sensor, caddy, caddy_bridge, dashboard_writer,
    entity_classifier, fleet, lysogeny, rpc, scatter_server, signal_spine,
    threat_feed,
};

use cellmembrane_types::fleet::DefensePosture;
use std::path::Path;
use std::time::Instant;

/// Tracking counters for the tail loop.
pub(crate) struct TailState {
    pub byte_offset: u64,
    pub lines_read: u64,
    pub lines_failed: u64,
    pub observations_sent: u64,
    pub fleet_posture: DefensePosture,
    pub fleet_escalations: u64,
    /// Inode of the currently-open log file (for rotation detection).
    #[cfg(unix)]
    pub log_inode: u64,
    /// Last time we checked for log rotation.
    pub last_rotation_check: Instant,
    /// Last time we wrote the heartbeat file.
    pub last_heartbeat: Instant,
}

/// Write the bloom signal file — JSON snapshot of the latest observation window.
pub(crate) async fn write_bloom_signal(path: &Path, obs: &bloom_sensor::BloomObservation) {
    match serde_json::to_string_pretty(obs) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(path, json).await {
                tracing::warn!(error = %e, path = %path.display(), "bloom signal write failed");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "bloom signal serialization failed");
        }
    }
}

pub(crate) async fn process_line(
    trimmed: &str,
    aggregator: &mut aggregator::Aggregator,
    fleet_agg: Option<&mut fleet::FleetAggregator>,
    bridge: Option<&mut caddy_bridge::CaddyBridge>,
    mut sentinel: Option<&mut lysogeny::LysogenySentinel>,
    rpc: &mut rpc::RpcClient,
    state: &mut TailState,
    dry_run: bool,
    scatter_confidence: &scatter_server::SharedConfidence,
    base_scatter_ratio: f32,
    bloom: &mut bloom_sensor::BloomSensor,
    bloom_signal_path: &Path,
    spine: &mut signal_spine::SignalSpine,
    threat_indicators: &mut Vec<threat_feed::ThreatIndicator>,
    threat_feed_path: &Path,
    abuse_queue: &abuse_reporter::AbuseReportQueue,
    window_secs: u64,
    opsonize_cache: &scatter_server::OpsonizeCache,
    // signal_acc: fossilized (Wave 170 → fossilRecord/signal-writer-rust-wave170)
    mut topology_writer: Option<&mut entity_classifier::TopologyWriter>,
    mut dashboard: Option<&mut dashboard_writer::DashboardWriter>,
    oracle: Option<&skunky_ingest::cube_oracle::SharedOracle>,
) {
    if trimmed.is_empty() {
        return;
    }

    let Some(entry) = caddy::parse_line(trimmed) else {
        state.lines_failed += 1;
        tracing::debug!(line = trimmed, "skipping malformed line");
        return;
    };

    state.lines_read += 1;

    // Entity topology — classify every request into entity profiles.
    if let Some(tw) = topology_writer.as_mut() {
        tw.ingest(&entry);
    }

    // Wire conservation flip data from topology → dashboard (Wave 176).
    if let (Some(tw), Some(dw)) = (&topology_writer, &mut dashboard) {
        dw.set_epitope_flip(tw.epitope_flip_data());
        dw.set_entity_count(tw.entity_count());
    }

    // Dashboard — per-IP behavioral tracking for signal site.
    if let Some(dw) = dashboard.as_mut() {
        dw.ingest(&entry);
    }

    // Feed to lysogeny sentinel for self-behavioral tracking
    if let Some(s) = sentinel.as_mut() {
        s.observe(&entry);
    }

    // Bloom sensor — afferent signal accumulation
    if let Some(obs) = bloom.ingest(&entry) {
        tracing::info!(
            requests = obs.total_requests,
            ips = obs.unique_ips,
            cross_domain = obs.cross_domain_sessions,
            langs = obs.languages.len(),
            "🌸 bloom observation"
        );
        write_bloom_signal(bloom_signal_path, &obs).await;

        // Feed bloom observation to nautilus oracle — signal rates
        // indicate how effectively scatter is disrupting fleet behavior.
        if let Some(orc) = oracle {
            if obs.total_requests > 0 {
                // Signal rate = normalized request intensity per unique IP
                let signal_rate = if obs.unique_ips > 0 {
                    (obs.total_requests as f64 / obs.unique_ips as f64 / 100.0).min(1.0)
                } else {
                    0.0
                };
                orc.record_bloom_signal("bloom_aggregate", signal_rate);
            }
        }

        // signal_writer: fossilized (Wave 170). dashboard_writer superseded it.

        // Signal spine — chain the observation into immune memory.
        if let Some(spine_entry) = spine.ingest(&obs) {
            tracing::info!(
                date = %spine_entry.date,
                windows = spine_entry.window_count,
                root = %spine_entry.merkle_root,
                "📜 spine day committed"
            );

            // Layer 4: Generate threat intelligence feed on day commit
            let feed = threat_feed::generate_feed(&spine_entry, threat_indicators);
            if let Err(e) = threat_feed::write_feed(&feed, threat_feed_path) {
                tracing::warn!(error = %e, "threat feed write failed");
            }
            threat_indicators.clear();
        }
    }

    // Per-IP aggregation
    let observations = aggregator.ingest(&entry);
    for obs in &observations {
        if dry_run {
            tracing::info!(
                rate = obs.http.request_rate,
                err_4xx = obs.http.error_rate_4xx,
                paths = obs.http.path_diversity,
                "[dry-run] would send observation"
            );
        } else {
            match rpc.observe(obs).await {
                Ok(()) => {
                    state.observations_sent += 1;
                    tracing::debug!("observation accepted");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "observe failed (dropped, next window is fresh)");
                }
            }
        }
    }

    // Population-level fleet aggregation + escalation pipeline
    if let Some(fleet) = fleet_agg {
        if let Some(result) = fleet.ingest(&entry) {
            let fleet_obs = &result.observation;
            if dry_run {
                tracing::info!(
                    requests = fleet_obs.total_requests,
                    ips = fleet_obs.unique_ips,
                    ua_count = fleet_obs.ua_fingerprint.ua_count,
                    commit_pct = %format!("{:.1}%", fleet_obs.path_pattern.commit_url_pct * 100.0),
                    hides_id = fleet_obs.deception.hides_identity,
                    "[dry-run] would send fleet observation"
                );
                return;
            }

            // Step 1: Feed observation to skunkBat (may generate antibody)
            if let Err(e) = rpc.fleet_observe(fleet_obs).await {
                tracing::warn!(error = %e, "fleet observe failed");
                return;
            }
            tracing::info!(
                requests = fleet_obs.total_requests,
                ips = fleet_obs.unique_ips,
                "fleet observation sent"
            );

            // Step 2: Check which stored antibodies match this observation
            let matched_ids = match rpc.fleet_match(fleet_obs).await {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(error = %e, "fleet.match failed");
                    return;
                }
            };

            if matched_ids.is_empty() {
                return;
            }

            tracing::info!(
                matched = matched_ids.len(),
                "fleet antibodies matched — ticking escalation"
            );

            // Step 2b: Compute behavioral hash + emit opsonize tag
            let bhash = cellmembrane_types::fleet::behavioral_hash(fleet_obs);
            let invariants = cellmembrane_types::fleet::extract_invariants(fleet_obs);
            let mut detectors: Vec<String> = {
                let mut d = Vec::new();
                if fleet_obs.path_pattern.commit_url_pct > 0.5 { d.push("content_gate".to_string()); }
                if fleet_obs.deception.hides_identity { d.push("stealth_ua".to_string()); }
                if fleet_obs.deception.rotates_ips { d.push("ip_rotation".to_string()); }
                if fleet_obs.deception.encoding_uniform { d.push("encoding_uniform".to_string()); }
                if fleet_obs.deception.ignores_rejection { d.push("ignores_rejection".to_string()); }
                if fleet_obs.ua_fingerprint.ua_count <= 5 { d.push("narrow_ua_pool".to_string()); }
                d
            };

            // Additional detectors from newer fleet.rs signals
            if fleet_obs.deception.header_poverty { detectors.push("header_poverty".to_string()); }
            if fleet_obs.deception.stale_chrome { detectors.push("stale_chrome".to_string()); }
            if fleet_obs.deception.accept_monoculture { detectors.push("accept_monoculture".to_string()); }
            if fleet_obs.deception.connection_absent { detectors.push("connection_absent".to_string()); }
            if fleet_obs.deception.blame_ratio { detectors.push("blame_ratio".to_string()); }
            if fleet_obs.deception.pagination_walk { detectors.push("pagination_walk".to_string()); }

            if !detectors.is_empty() {
                // ── Thymic pre-classification: conserved plasmid matching ──
                // If this behavioral hash is NEW, check against conserved epitopes.
                // The plasmid contains what "fleet in general" looks like — if the
                // new entity matches enough conserved epitopes, boost confidence
                // immediately. This is thymic education: first-contact recognition
                // from generalized pathogen memory.
                let base_confidence = fleet_obs.deception.hides_identity as u8 as f64 * 0.25
                    + fleet_obs.deception.rotates_ips as u8 as f64 * 0.25
                    + fleet_obs.deception.ignores_rejection as u8 as f64 * 0.25
                    + fleet_obs.deception.encoding_uniform as u8 as f64 * 0.25;

                let (thymic_hit, thymic_conf, matching_epitopes) =
                    opsonize_cache.thymic_classify(&detectors).await;

                let confidence = if thymic_hit {
                    // Thymic match: new hash recognized as fleet variant via conserved epitopes.
                    // Blend base confidence with thymic confidence for immediate escalation.
                    let blended = base_confidence.max(thymic_conf);
                    tracing::info!(
                        hash = %bhash,
                        thymic_conf = %format!("{:.0}%", thymic_conf * 100.0),
                        epitopes = matching_epitopes.len(),
                        matching = %matching_epitopes.join(", "),
                        "🧬 thymic recognition — new hash matches conserved plasmid"
                    );

                    // Braid thymic recognition into sweetGrass — permanent provenance
                    let braid_hash = bhash.clone();
                    let braid_epitopes = matching_epitopes.clone();
                    tokio::spawn(async move {
                        scatter_server::braid_antibody_reaction(
                            scatter_server::AntibodyReaction::ThymicRecognition {
                                behavioral_hash: braid_hash,
                                matching_epitopes: braid_epitopes,
                                thymic_confidence: thymic_conf,
                            }
                        ).await;
                    });

                    blended
                } else {
                    base_confidence
                };

                let origin = std::env::var("LAYER_NAME")
                    .unwrap_or_else(|_| "unknown".to_string());
                let tag = cellmembrane_types::fleet::OpsonizeTag {
                    behavioral_hash: bhash.clone(),
                    detectors: detectors.clone(),
                    confidence,
                    origin_gate: origin,
                    invariants,
                    response: cellmembrane_types::fleet::OpsonizeResponse::Scatter { ratio: 0.3 },
                    created_epoch: fleet_obs.timestamp_epoch,
                    last_confirmed_epoch: fleet_obs.timestamp_epoch,
                    match_count: 1,
                };

                // Update scatter server's confidence — higher confidence = richer poison
                scatter_confidence.update(tag.confidence);

                // Feed opsonize cache — scatter server uses this for per-hash adaptive responses
                let is_new_hash = opsonize_cache.update_from_tag(
                    &bhash,
                    tag.confidence,
                    detectors.clone(),
                    tag.match_count,
                ).await;

                tracing::info!(
                    hash = %bhash,
                    detectors = detectors.len(),
                    confidence = %format!("{:.0}%", tag.confidence * 100.0),
                    effective_ratio = %format!("{:.0}%", scatter_confidence.effective_ratio(base_scatter_ratio) * 100.0),
                    "🏷️ opsonize tag emitted — behavioral hash {bhash}"
                );

                // Braid first-contact into sweetGrass — new fleet actor appeared
                if is_new_hash {
                    let fc_hash = bhash.clone();
                    let fc_detectors = detectors.clone();
                    let fc_conf = tag.confidence;
                    tokio::spawn(async move {
                        scatter_server::braid_antibody_reaction(
                            scatter_server::AntibodyReaction::FirstContact {
                                behavioral_hash: fc_hash,
                                detectors: fc_detectors,
                                confidence: fc_conf,
                            }
                        ).await;
                    });
                }

                // Layer 4: Accumulate threat indicator for daily feed
                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                threat_indicators.push(threat_feed::ThreatIndicator {
                    behavioral_hash: bhash.clone(),
                    detectors: detectors.clone(),
                    confidence: tag.confidence,
                    probe_paths: Vec::new(),
                    timing_signature: if fleet_obs.deception.encoding_uniform {
                        "metronomic".to_string()
                    } else {
                        "varied".to_string()
                    },
                    estimated_fleet_size: fleet_obs.unique_ips,
                    first_observed: today.clone(),
                    last_observed: today,
                });

                // Emit via skunkBat RPC for gossip propagation
                let tag_json = serde_json::to_value(&tag).unwrap_or_default();
                if let Err(e) = rpc.call_raw(
                    "gossip.inject",
                    &serde_json::json!({
                        "topic": "defense",
                        "key": format!("defense.opsonize:{bhash}"),
                        "payload": tag_json,
                    }),
                ).await {
                    tracing::debug!(error = %e, "gossip.inject failed (swarmVine may not be running)");
                }
            }

            // Step 3: Tick the escalation engine (tit-for-tat)
            match rpc.fleet_tick(&matched_ids).await {
                Ok(events) => {
                    for event in &events {
                        // Track the highest posture we've reached
                        if event.to > state.fleet_posture {
                            state.fleet_posture = event.to;
                        }
                        state.fleet_escalations += 1;

                        tracing::warn!(
                            antibody = %event.antibody_id,
                            from = %event.from,
                            to = %event.to,
                            defections = event.defection_count,
                            reason = %event.reason,
                            "🦨 POSTURE ESCALATION"
                        );

                        // Braid escalation into sweetGrass — permanent record
                        let esc_hash = bhash.clone();
                        let from_str = format!("{}", event.from);
                        let to_str = format!("{}", event.to);
                        let reason_str = event.reason.clone();
                        let defections = event.defection_count;
                        tokio::spawn(async move {
                            scatter_server::braid_antibody_reaction(
                                scatter_server::AntibodyReaction::Escalation {
                                    behavioral_hash: esc_hash,
                                    from_posture: from_str,
                                    to_posture: to_str,
                                    reason: reason_str,
                                    defection_count: defections,
                                }
                            ).await;
                        });
                    }

                    // Step 4: Inject fleet IPs into CaddyBridge at current posture
                    // Pass behavioral hash so Caddy emits X-Fleet-Hash header
                    // to scatter_server for per-hash adaptive amplification
                    if let Some(bridge) = bridge {
                        bridge.add_fleet_ips_with_hash(
                            &result.ips,
                            state.fleet_posture,
                            if bhash.is_empty() { None } else { Some(&bhash) },
                        );

                        match bridge.sync() {
                            Ok(true) => {
                                tracing::info!(
                                    posture = %state.fleet_posture,
                                    ips = result.ips.len(),
                                    tracked = bridge.tracked_count(),
                                    "🦨 Caddy updated — fleet posture applied"
                                );
                                // Notify lysogeny sentinel that WE wrote the Caddyfile
                                // so it doesn't flag our own write as a genome mutation
                                if let Some(s) = sentinel.as_mut() {
                                    s.notify_self_write(&bridge.caddyfile_path());
                                }
                            }
                            Ok(false) => {}
                            Err(e) => {
                                tracing::error!(error = %e, "Caddy bridge sync failed");
                            }
                        }
                    }

                    // Step 5: Cytokine signaling — queue abuse reports at Scatter+
                    //
                    // When the immune system has confirmed a fleet is hostile
                    // (escalated to Scatter or higher), generate an abuse report
                    // for the hosting provider. Reports queue for manual review —
                    // never auto-sent. This is the immune system recruiting
                    // external help via cytokine signals.
                    for event in &events {
                        if event.to >= DefensePosture::Scatter
                            && event.from < DefensePosture::Scatter
                        {
                            let now = chrono::Utc::now();
                            let report = abuse_reporter::build_report(
                                &bhash,
                                "unknown",
                                "unknown",
                                fleet_obs.unique_ips as u32,
                                fleet_obs.total_requests as u64,
                                detectors.clone(),
                                &(now - chrono::Duration::seconds(window_secs as i64))
                                    .to_rfc3339(),
                                &now.to_rfc3339(),
                            );
                            if let Err(e) = abuse_queue.enqueue(&report) {
                                tracing::warn!(
                                    error = %e,
                                    antibody = %event.antibody_id,
                                    "abuse report queue failed"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "fleet.tick failed");
                }
            }
        }
    }
}
