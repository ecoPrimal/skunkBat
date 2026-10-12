// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Tails structured JSON access logs (Caddy format), aggregates per-source-IP
//! metrics over a configurable window, and pushes `baseline.observe` JSON-RPC
//! calls to skunkBat over TCP.
//!
//! Module declarations live in `lib.rs` for reuse; binary owns CLI + tail loop.

use skunky_ingest::{
    aggregator, anderson_bridge, bloom_emitter, caddy_bridge, cloudflare, cursor,
    dashboard_writer, entity_classifier, epitope_registry, error, federation, fleet,
    inflammatory, ingestion_observer, lysogeny, membrane_stack,
    rpc, abuse_reporter, bloom_sensor, scatter_server, signal_spine,
    threat_feed,
};

use error::IngestError;

mod ingest_pipeline;

use ingest_pipeline::{TailState, process_line, write_bloom_signal};

use std::path::PathBuf;
use std::time::{Duration, Instant};

use cellmembrane_types::fleet::DefensePosture;
use clap::Parser;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

/// skunky-ingest: feed live Caddy access logs into skunkBat's behavioral profiler.
#[derive(Parser, Debug)]
#[command(name = "skunky-ingest", version, about)]
struct Cli {
    /// Path to the Caddy JSON access log file.
    #[arg(long, default_value = "/var/log/caddy/access.log")]
    log_path: PathBuf,

    /// skunkBat TCP address (host:port).
    #[arg(long, default_value = "127.0.0.1:9750")]
    skunkbat_addr: String,

    /// Aggregation window in seconds.
    #[arg(long, default_value_t = 60)]
    window_secs: u64,

    /// Cursor file for tracking file position across restarts.
    #[arg(long, default_value = "/var/lib/skunky-ingest/cursor.pos")]
    cursor_path: PathBuf,

    /// Tail poll interval in milliseconds (when log has no new data).
    #[arg(long, default_value_t = 500)]
    poll_ms: u64,

    /// Dry-run mode: parse and aggregate but don't send to skunkBat.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Cloudflare API token for analytics polling (or set `CF_API_TOKEN`).
    #[arg(long)]
    cf_api_token: Option<String>,

    /// Cloudflare zone ID for analytics polling (or set `CF_ZONE_ID`).
    #[arg(long)]
    cf_zone_id: Option<String>,

    /// Cloudflare analytics poll interval in seconds.
    #[arg(long, default_value_t = 300)]
    cf_poll_secs: u64,

    /// Target host for fleet detection (population-level analysis).
    /// Empty string disables fleet aggregation.
    #[arg(long, default_value = "git.primals")]
    fleet_target_host: String,

    /// Enable Caddy bridge — write posture-aware directives into Caddyfile.
    #[arg(long, default_value_t = false)]
    caddy_bridge: bool,

    /// Path to the Caddyfile (used with --caddy-bridge).
    #[arg(long, default_value = "/etc/membrane/Caddyfile")]
    caddyfile_path: PathBuf,

    /// Caddy reload command (used with --caddy-bridge).
    #[arg(
        long,
        default_value = "/opt/membrane/caddy reload --config /etc/membrane/Caddyfile --address localhost:2019"
    )]
    caddy_reload_cmd: String,

    /// IP TTL in seconds for Caddy bridge (how long fleet IPs stay blocked).
    #[arg(long, default_value_t = 3600)]
    ip_ttl_secs: u64,

    /// Path to self-IPs file for thymic negative selection.
    /// One IP per line, `#` comments allowed. IPs in this file
    /// will never be added to fleet block lists.
    #[arg(long, default_value = "/etc/membrane/self-ips.txt")]
    self_ips_file: PathBuf,

    /// Enable scatter (opsonization) server — serves poisoned content
    /// to fleet requests routed by Caddy's content_gate.
    #[arg(long, default_value_t = false)]
    scatter_server: bool,

    /// Scatter server listen port.
    #[arg(long, default_value_t = 9753)]
    scatter_port: u16,

    /// Scatter seed for deterministic poison content.
    #[arg(long, default_value_t = 0xdead_beef_cafe_babe)]
    scatter_seed: u64,

    /// Fraction of detected requests that receive scatter content (0.0-1.0).
    /// Remaining requests get connection abort.
    #[arg(long, default_value_t = 0.3)]
    scatter_ratio: f32,

    /// Maximum concurrent tarpit connections (Layer 1 active defense).
    /// Each tarpit connection holds a scanner thread for 30-60 seconds.
    /// Set to 0 to disable tarpitting (falls back to instant 429).
    #[arg(long, default_value_t = 100)]
    max_tarpit_connections: u32,

    // signal_writer: fossilized (Wave 170 → fossilRecord/signal-writer-rust-wave170)
    // --signal-writer, --signal-data-path, --signal-state-path removed.
    // dashboard_writer superseded it; signal-data.js was orphaned.

    /// Enable entity topology writer — replaces entity_topology.py cron.
    /// Classifies traffic entities and writes topology.json periodically.
    #[arg(long, default_value_t = false)]
    entity_classifier: bool,

    /// Output path for topology.json (used with --entity-classifier).
    #[arg(long, default_value = "/opt/membrane/live-terminal/topology.json")]
    topology_path: PathBuf,

    /// Flush topology.json after this many log entries.
    #[arg(long, default_value_t = 500)]
    topology_flush_interval: u64,

    /// State file for entity topology cumulative culture.
    /// Persistent storage — survives reboots (sourdough starter).
    #[arg(long, default_value = "/var/lib/skunky-ingest/topology-state.json")]
    topology_state_path: PathBuf,

    /// Directory for signal spine immune memory chain.
    /// Persistent storage — this is ecoBin DNA, not ephemeral.
    #[arg(long, default_value = "/var/lib/skunky-ingest/signal-spine")]
    signal_spine_dir: PathBuf,

    /// Enable dashboard writer — replaces bloom_live.py.
    /// Writes dashboard.json, state.json, epitope_caddy.json.
    #[arg(long, default_value_t = false)]
    dashboard_writer: bool,

    /// Output path for dashboard.json (used with --dashboard-writer).
    #[arg(long, default_value = "/opt/membrane/live-terminal/dashboard.json")]
    dashboard_path: PathBuf,

    /// State file for dashboard sourdough culture.
    #[arg(long, default_value = "/var/lib/skunky-ingest/dashboard-culture.json")]
    dashboard_state_path: PathBuf,

    /// Persist path for epitope registry (culture-derived bot patterns).
    #[arg(long, default_value = "/var/lib/skunky-ingest/epitope-registry.json")]
    epitope_registry_path: PathBuf,

    /// OSINT bot token feed (merged into epitope registry at startup).
    #[arg(long, default_value = "/var/lib/skunky-ingest/osint-bots.json")]
    osint_bots_path: PathBuf,

    /// Flush dashboard.json after this many log entries.
    #[arg(long, default_value_t = 200)]
    dashboard_flush_interval: u64,

    /// Announce membrane observations to squirrel AI coordination primal.
    /// Fire-and-forget via capabilities.announce to /run/membrane/squirrel.sock.
    /// Off by default — enable with --squirrel-announce after verifying squirrel
    /// is running and accepting connections.
    #[arg(long, default_value_t = false)]
    squirrel_announce: bool,

    /// Enable ingestion observer — tracks scatter content lifecycle.
    /// Reads phase from Python observer state, exposes to dashboard,
    /// appends Rust-side volume to the timeline ledger.
    #[arg(long, default_value_t = false)]
    ingestion_observer: bool,

    /// State file for ingestion observer (shared with Python observer).
    #[arg(long, default_value = "/var/lib/skunky-ingest/observer-state.json")]
    observer_state_path: PathBuf,

    /// Timeline ledger for ingestion observer (shared with Python observer).
    #[arg(long, default_value = "/var/lib/skunky-ingest/ingestion-timeline.jsonl")]
    observer_timeline_path: PathBuf,

    /// Enable bloom emitter — efferent IndexNow + Wayback signal push.
    /// Runs a full cascade every bloom_emitter_interval_secs.
    #[arg(long, default_value_t = false)]
    bloom_emitter: bool,

    /// Bloom emitter cascade interval in seconds (default: 6 hours).
    #[arg(long, default_value_t = 21600)]
    bloom_emitter_interval_secs: u64,

    /// Enable membrane stack observer — nested membrane profile from core to heliosphere.
    /// Writes membrane-stack.json every membrane_stack_interval_secs.
    #[arg(long, default_value_t = false)]
    membrane_stack: bool,

    /// Membrane stack observer interval in seconds (default: 5 minutes).
    #[arg(long, default_value_t = 300)]
    membrane_stack_interval_secs: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!(
        log = %cli.log_path.display(),
        addr = %cli.skunkbat_addr,
        window = cli.window_secs,
        dry_run = cli.dry_run,
        "skunky-ingest starting"
    );

    if let Err(e) = run(cli).await {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
}

async fn open_log(cli: &Cli) -> Result<(BufReader<File>, u64, u64), IngestError> {
    if let Some(parent) = cli.cursor_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let saved_offset = cursor::load(&cli.cursor_path).await;
    tracing::info!(offset = saved_offset, "resuming from cursor");

    let file = File::open(&cli.log_path).await?;
    let metadata = file.metadata().await?;

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        metadata.ino()
    };
    #[cfg(not(unix))]
    let inode = 0u64;

    let mut reader = BufReader::new(file);

    let start_offset = if saved_offset > metadata.len() {
        tracing::warn!(
            saved = saved_offset,
            file_len = metadata.len(),
            "cursor beyond file size (rotation?), starting from beginning"
        );
        0
    } else {
        saved_offset
    };

    if start_offset > 0 {
        reader.seek(std::io::SeekFrom::Start(start_offset)).await?;
    }

    Ok((reader, start_offset, inode))
}

/// Check if the log file has been rotated by comparing the on-disk inode
/// to the inode of our open file descriptor. Caddy's `roll_size` renames
/// the active log to `.log.1` and creates a fresh file — the old fd
/// follows the renamed file, so we must detect and reopen.
#[cfg(unix)]
async fn check_log_rotation(
    log_path: &std::path::Path,
    current_inode: u64,
) -> Option<u64> {
    let meta = tokio::fs::metadata(log_path).await.ok()?;
    use std::os::unix::fs::MetadataExt;
    let disk_inode = meta.ino();
    if disk_inode != current_inode {
        Some(disk_inode)
    } else {
        None
    }
}

/// Write the heartbeat file — a plain epoch timestamp.
/// If the heartbeat goes stale, the inflammatory watchdog activates.
async fn write_heartbeat(path: &std::path::Path) {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(e) = tokio::fs::write(path, epoch.to_string()).await {
        tracing::warn!(error = %e, path = %path.display(), "heartbeat write failed");
    }
}

async fn run(cli: Cli) -> Result<(), IngestError> {
    let cf_config = cloudflare::CfConfig::from_args(
        cli.cf_api_token.clone(),
        cli.cf_zone_id.clone(),
        cli.cf_poll_secs,
    );
    if cf_config.is_some() {
        tracing::info!(
            "Cloudflare analytics credentials present — HTTP/GraphQL client not yet implemented"
        );
    }

    let (mut reader, start_offset, log_inode) = open_log(&cli).await?;

    let mut rpc = rpc::RpcClient::new(cli.skunkbat_addr.clone());
    let mut aggregator = aggregator::Aggregator::new(Duration::from_secs(cli.window_secs));
    let mut fleet_agg = if cli.fleet_target_host.is_empty() {
        None
    } else {
        tracing::info!(host = %cli.fleet_target_host, "fleet aggregation enabled");
        Some(fleet::FleetAggregator::new(
            Duration::from_secs(cli.window_secs),
            cli.fleet_target_host.clone(),
        ))
    };

    let mut caddy_bridge = if cli.caddy_bridge {
        let self_ips = caddy_bridge::load_self_ips(&cli.self_ips_file);
        tracing::info!(
            caddyfile = %cli.caddyfile_path.display(),
            self_ips = self_ips.len(),
            "Caddy bridge enabled — posture-aware fleet directives with negative selection"
        );
        Some(caddy_bridge::CaddyBridge::new(
            caddy_bridge::CaddyBridgeConfig {
                caddyfile_path: cli.caddyfile_path.clone(),
                caddy_reload_cmd: cli.caddy_reload_cmd.clone(),
                ip_ttl_secs: cli.ip_ttl_secs,
                ..Default::default()
            },
            self_ips,
        ))
    } else {
        None
    };

    // Lysogeny sentinel — watches for foreign integration into self
    let self_ips_for_lysogeny = if cli.caddy_bridge {
        caddy_bridge::load_self_ips(&cli.self_ips_file)
    } else {
        std::collections::HashSet::new()
    };
    let mut lysogeny_sentinel = if cli.caddy_bridge {
        let genome_files = vec![
            (
                cli.caddyfile_path.clone(),
                Some((
                    "~~FLEET_PRESSURE_START~~".to_string(),
                    "~~FLEET_PRESSURE_END~~".to_string(),
                )),
            ),
            (cli.self_ips_file.clone(), None),
        ];
        let sentinel = lysogeny::LysogenySentinel::new(lysogeny::LysogenyConfig {
            genome_files,
            self_ips: self_ips_for_lysogeny,
            check_interval_secs: 60,
            behavioral_window_secs: cli.window_secs,
        });
        tracing::info!(
            "🧬 lysogeny sentinel active — genome integrity + self-behavioral + process watchdog"
        );
        Some(sentinel)
    } else {
        None
    };

    // Shared confidence level — opsonize pipeline updates, scatter server reads
    let scatter_confidence = scatter_server::SharedConfidence::new();

    // Shared ingestion phase — observer writes, scatter server reads for titration.
    // Phase 0 = full poison, Phase 2 = mostly antidote. Automatic ramp-down.
    let shared_phase = ingestion_observer::SharedPhase::new();

    // Back pressure gauge — non-Newtonian viscosity dimension
    // 60-second rolling window: the maze stiffness adapts to fleet velocity
    let back_pressure = scatter_server::BackPressure::new(60);

    // Opsonize cache — aggregates defense gossip for per-hash adaptive scatter
    let opsonize_cache = scatter_server::OpsonizeCache::new();

    // BingoCube oracle — sourdough-persistent nautilus shell for evolutionary learning.
    // Shared between scatter server and ingest pipeline for the feedback loop.
    let oracle = skunky_ingest::cube_oracle::create_oracle(
        cli.scatter_seed,
        Some(std::path::Path::new("/var/lib/skunky-ingest/nautilus-shell.json")),
    );

    // Scatter (opsonization) server — serves poison content to fleet
    if cli.scatter_server {
        let scatter_config = scatter_server::ScatterConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], cli.scatter_port)),
            seed: cli.scatter_seed,
            poison_ratio: cli.scatter_ratio,
            max_tarpit_connections: cli.max_tarpit_connections,
        };
        tokio::spawn(scatter_server::run(scatter_config, scatter_confidence.clone(), opsonize_cache.clone(), back_pressure.clone(), oracle.clone(), shared_phase.clone()));
    }

    // Inflammatory watchdog — heartbeat failover (replaces membrane-inflammatory.timer)
    if cli.caddy_bridge {
        tokio::spawn(inflammatory::run(inflammatory::InflammatoryConfig::default()));

        // Plasmid federation — peer-to-peer merge across all golgi bodies
        let layer_name_fed = std::env::var("LAYER_NAME").unwrap_or_else(|_| "golgiBody".into());
        tokio::spawn(async move {
            let config = federation::FederationConfig::peer_mesh(&layer_name_fed);
            loop {
                match federation::run_once(&config).await {
                    Ok(path) => tracing::info!(path = %path.display(), "🧬 plasmid federation cycle complete"),
                    Err(e) => tracing::warn!(error = %e, "plasmid federation cycle failed"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            }
        });
    }

    // Bloom emitter — efferent IndexNow + Wayback signal push
    if cli.bloom_emitter {
        let interval = Duration::from_secs(cli.bloom_emitter_interval_secs);
        tracing::info!(
            interval_secs = cli.bloom_emitter_interval_secs,
            "🌺 bloom emitter active — efferent signal propagation (IndexNow + Wayback)"
        );
        tokio::spawn(async move {
            let config = bloom_emitter::EmitterConfig::default();
            let emitter = bloom_emitter::BloomEmitter::new(config);
            // Initial cascade on startup (after 60s warmup)
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                match emitter.cascade().await {
                    Ok(report) => {
                        tracing::info!(
                            indexnow_urls = report.indexnow_total_urls,
                            wayback_pages = report.wayback_total_pages,
                            errors = report.errors.len(),
                            elapsed_secs = report.elapsed.as_secs(),
                            "🌺 bloom cascade complete"
                        );
                    }
                    Err(e) => tracing::warn!(error = %e, "bloom cascade failed"),
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    // Membrane stack observer — nested membrane profile from core to heliosphere
    if cli.membrane_stack {
        let interval = cli.membrane_stack_interval_secs;
        tracing::info!(
            interval_secs = interval,
            "🫧 membrane stack observer active — gAIa breathes"
        );
        tokio::spawn(async move {
            let config = membrane_stack::MembraneStackConfig::default();
            membrane_stack::breathe_loop(config, interval).await;
        });
    }

    // Bloom sensor — afferent signal accumulation (all hosts)
    let mut bloom_sensor = bloom_sensor::BloomSensor::new(Duration::from_secs(cli.window_secs));
    let bloom_signal_path = PathBuf::from("/run/membrane/bloom.signal");
    tracing::info!("🌸 bloom sensor active — afferent signal accumulation");

    // signal_writer fossilized (Wave 170 → fossilRecord/signal-writer-rust-wave170).
    // dashboard_writer superseded it; signal-data.js was orphaned.

    // Epitope registry — culture-derived bot detection (replaces hardcoded is_declared_bot).
    // Loads sourdough culture + OSINT feed, evolves with topology observations.
    let epitope_registry = epitope_registry::create_shared_registry(
        Some(&cli.epitope_registry_path),
    );
    epitope_registry::load_osint_feed(&cli.osint_bots_path, &epitope_registry);
    {
        let Ok(guard) = epitope_registry.read() else {
            tracing::error!("epitope registry lock poisoned — cannot read stats");
            return Ok(());
        };
        let stats = guard.stats();
        tracing::info!(
            active = stats.active_tokens,
            seed = stats.seed_count,
            culture = stats.culture_count,
            osint = stats.osint_count,
            generation = stats.generation,
            "🧬 epitope registry active — immune memory loaded"
        );
    }

    // Entity topology writer — replaces entity_topology.py (534 lines of Python → 0)
    // Classifies every request into entity profiles and writes topology.json.
    // Loads sourdough culture from persistent state — never cold-starts.
    let mut topology_writer = if cli.entity_classifier {
        tracing::info!("🗺️ entity classifier active — entity_topology.py convergence");
        Some(entity_classifier::TopologyWriter::new(
            cli.topology_path.clone(),
            cli.topology_state_path.clone(),
            cli.topology_flush_interval,
            epitope_registry.clone(),
        ))
    } else {
        None
    };

    // Shared Anderson profile — updated by dashboard writer, read by /plasmid endpoint
    let anderson_profile: anderson_bridge::SharedAndersonProfile =
        std::sync::Arc::new(tokio::sync::RwLock::new(None));

    // Dashboard writer — replaces bloom_live.py (793 lines of Python → 0)
    // Writes dashboard.json for the signal site from live pipeline data.
    let mut dashboard_writer = if cli.dashboard_writer {
        tracing::info!("📊 dashboard writer active — bloom_live.py convergence");
        let mut dw = dashboard_writer::DashboardWriter::with_anderson(
            cli.dashboard_path.clone(),
            cli.dashboard_state_path.clone(),
            cli.dashboard_flush_interval,
            epitope_registry.clone(),
            anderson_profile.clone(),
            cli.squirrel_announce,
        );
        dw.set_oracle(oracle.clone());
        Some(dw)
    } else {
        None
    };

    // Ingestion observer — tracks scatter content lifecycle phases.
    // Reads from Python observer state, exposes phase to dashboard,
    // appends Rust-side scatter volume to shared timeline ledger.
    let mut ingestion_observer = if cli.ingestion_observer {
        tracing::info!("🔭 ingestion observer active — jellystein wired");
        Some(ingestion_observer::IngestionObserver::new(
            cli.observer_state_path.clone(),
            cli.observer_timeline_path.clone(),
            shared_phase.clone(),
        ))
    } else {
        None
    };

    // Signal spine — immune memory (content-addressed observation chain)
    // Persistent storage — this is ecoBin DNA, not ephemeral tmpfs.
    let spine_dir = cli.signal_spine_dir.clone();
    if let Err(e) = std::fs::create_dir_all(&spine_dir) {
        tracing::warn!(error = %e, "failed to create signal-spine directory");
    }
    let mut signal_spine = signal_spine::SignalSpine::new(&spine_dir);
    tracing::info!("📜 signal spine active — immune memory chain");

    // Abuse report queue — cytokine signaling (Layer 3)
    let abuse_queue_dir = PathBuf::from("/run/membrane/abuse-queue");
    let abuse_queue = abuse_reporter::AbuseReportQueue::new(&abuse_queue_dir);
    tracing::info!(
        path = %abuse_queue_dir.display(),
        "📨 abuse report queue initialized (manual review gate active)"
    );

    // Threat intelligence feed — MHC presentation (Layer 4)
    let threat_feed_path = PathBuf::from("/opt/ecoPrimals/detroit/public/defense/feed.json");
    if let Some(parent) = threat_feed_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut threat_indicators: Vec<threat_feed::ThreatIndicator> = Vec::new();
    tracing::info!(
        path = %threat_feed_path.display(),
        "📡 threat feed path configured"
    );

    let poll_interval = Duration::from_millis(cli.poll_ms);

    let mut line_buf = String::new();
    // Heartbeat path — inflammatory watchdog checks this
    let heartbeat_path = PathBuf::from("/run/membrane/skunky-ingest.heartbeat");
    if let Some(parent) = heartbeat_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    write_heartbeat(&heartbeat_path).await;

    let now = Instant::now();
    let mut state = TailState {
        byte_offset: start_offset,
        lines_read: 0,
        lines_failed: 0,
        observations_sent: 0,
        fleet_posture: DefensePosture::Observe,
        fleet_escalations: 0,
        #[cfg(unix)]
        log_inode,
        last_rotation_check: now,
        last_heartbeat: now,
    };

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        line_buf.clear();

        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                let bytes_read = result?;

                if bytes_read == 0 {
                    // ── Heartbeat (every 30s) ──
                    if state.last_heartbeat.elapsed() >= Duration::from_secs(30) {
                        write_heartbeat(&heartbeat_path).await;
                        state.last_heartbeat = Instant::now();
                    }

                    // ── Log rotation detection (every 30s) ──
                    #[cfg(unix)]
                    if state.last_rotation_check.elapsed() >= Duration::from_secs(30) {
                        state.last_rotation_check = Instant::now();
                        if let Some(new_inode) = check_log_rotation(&cli.log_path, state.log_inode).await {
                            tracing::warn!(
                                old_inode = state.log_inode,
                                new_inode,
                                "🔄 log rotation detected — reopening {}",
                                cli.log_path.display()
                            );
                            match File::open(&cli.log_path).await {
                                Ok(new_file) => {
                                    reader = BufReader::new(new_file);
                                    state.log_inode = new_inode;
                                    state.byte_offset = 0;
                                    tracing::info!("log file reopened after rotation");
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to reopen log after rotation");
                                }
                            }
                        }
                    }

                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                state.byte_offset += bytes_read as u64;

                process_line(
                    line_buf.trim(),
                    &mut aggregator,
                    fleet_agg.as_mut(),
                    caddy_bridge.as_mut(),
                    lysogeny_sentinel.as_mut(),
                    &mut rpc,
                    &mut state,
                    cli.dry_run,
                    &scatter_confidence,
                    cli.scatter_ratio,
                    &mut bloom_sensor,
                    &bloom_signal_path,
                    &mut signal_spine,
                    &mut threat_indicators,
                    &threat_feed_path,
                    &abuse_queue,
                    cli.window_secs,
                    &opsonize_cache,
                    topology_writer.as_mut(),
                    dashboard_writer.as_mut(),
                    Some(&oracle),
                ).await;

                if state.lines_read > 0 && state.lines_read.is_multiple_of(1000) {
                    cursor::save(&cli.cursor_path, state.byte_offset).await?;
                    tracing::info!(
                        lines = state.lines_read,
                        failed = state.lines_failed,
                        sent = state.observations_sent,
                        offset = state.byte_offset,
                        "progress checkpoint"
                    );

                    // Ingestion observer periodic flush (every 5000 lines)
                    if state.lines_read.is_multiple_of(5000) {
                        if let Some(ref mut obs) = ingestion_observer {
                            obs.flush();
                        }
                    }

                    // Lysogeny sentinel periodic tick
                    if let Some(ref mut sentinel) = lysogeny_sentinel {
                        let alerts = sentinel.tick();
                        for alert in &alerts {
                            match alert.severity {
                                lysogeny::Severity::Critical => {
                                    tracing::error!(
                                        kind = ?alert.kind,
                                        "🧬🔴 LYSOGENY CRITICAL: {}",
                                        alert.message,
                                    );
                                }
                                lysogeny::Severity::Warning => {
                                    tracing::warn!(
                                        kind = ?alert.kind,
                                        "🧬🟡 LYSOGENY WARNING: {}",
                                        alert.message,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    let remaining = aggregator.flush_remaining();
    for obs in &remaining {
        if !cli.dry_run {
            if let Err(e) = rpc.observe(obs).await {
                tracing::warn!(error = %e, "final flush observe failed");
            } else {
                state.observations_sent += 1;
            }
        }
    }

    if let Some(ref mut fleet) = fleet_agg {
        if let Some(result) = fleet.flush_remaining() {
            if !cli.dry_run {
                if let Err(e) = rpc.fleet_observe(&result.observation).await {
                    tracing::warn!(error = %e, "final fleet observe failed");
                }
            } else {
                tracing::info!(
                    requests = result.observation.total_requests,
                    ips = result.observation.unique_ips,
                    "[dry-run] would send fleet observation"
                );
            }
        }
    }

    // Flush remaining bloom sensor window
    if let Some(obs) = bloom_sensor.flush_remaining() {
        tracing::info!(
            requests = obs.total_requests,
            ips = obs.unique_ips,
            "🌸 final bloom flush"
        );
        write_bloom_signal(&bloom_signal_path, &obs).await;

        // signal_writer: fossilized (Wave 170)

        // Feed the final observation into the spine before shutdown.
        if let Some(spine_entry) = signal_spine.ingest(&obs) {
            tracing::info!(
                date = %spine_entry.date,
                windows = spine_entry.window_count,
                "📜 spine day committed (pre-shutdown)"
            );
        }
    }

    // Flush entity topology — final snapshot + culture save before shutdown.
    if let Some(ref mut tw) = topology_writer {
        tw.flush();
        tw.save_culture();
        tracing::info!("🗺️ topology writer final flush — culture preserved");
    }

    // Wire conservation flip data from topology → dashboard (Wave 176).
    if let (Some(tw), Some(dw)) = (&topology_writer, &mut dashboard_writer) {
        dw.set_epitope_flip(tw.epitope_flip_data());
    }

    // Flush dashboard — final write + culture save before shutdown.
    if let Some(ref mut dw) = dashboard_writer {
        dw.flush();
        dw.save_culture();
        tracing::info!("📊 dashboard writer final flush — culture preserved");
    }

    // Flush epitope registry — save immune memory before shutdown.
    if let Ok(reg) = epitope_registry.read() {
        reg.save(&cli.epitope_registry_path);
        let stats = reg.stats();
        tracing::info!(
            active = stats.active_tokens,
            culture = stats.culture_count,
            generation = stats.generation,
            lookups = stats.total_lookups,
            matches = stats.total_matches,
            "🧬 epitope registry saved — immune memory preserved"
        );
    }

    // Flush ingestion observer — final timeline entry before shutdown.
    if let Some(ref mut obs) = ingestion_observer {
        obs.flush();
        tracing::info!("🔭 ingestion observer final flush");
    }

    // Flush signal spine — commit whatever we have for today.
    if let Some(spine_entry) = signal_spine.flush() {
        tracing::info!(
            date = %spine_entry.date,
            windows = spine_entry.window_count,
            root = %spine_entry.merkle_root,
            "📜 signal spine flushed on shutdown"
        );

        // Layer 4: Generate final threat feed on shutdown
        let feed = threat_feed::generate_feed(&spine_entry, &threat_indicators);
        if let Err(e) = threat_feed::write_feed(&feed, &threat_feed_path) {
            tracing::warn!(error = %e, "threat feed write failed on shutdown");
        }
    }

    cursor::save(&cli.cursor_path, state.byte_offset).await?;

    tracing::info!(
        lines = state.lines_read,
        failed = state.lines_failed,
        sent = state.observations_sent,
        offset = state.byte_offset,
        "skunky-ingest shutting down"
    );

    Ok(())
}

