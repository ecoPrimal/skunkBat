// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Pulse writer — replaces pulse-pollen.py (102 lines Python → Rust).
//!
//! Runs on a configurable interval (default: 120s = same as cron */2).
//! Reads fail2ban jail stats + existing membrane JSON files,
//! writes `ban-pulse.json` and `pollen.json` to the live terminal.
//!
//! # What it replaces
//!
//! | Python script    | Lines | Function                            |
//! |------------------|-------|-------------------------------------|
//! | pulse-pollen.py  | 102   | ban-pulse + pollen JSON generation  |
//!
//! # Output files
//!
//! - `ban-pulse.json` — fail2ban jail stats + scatter overlay
//! - `pollen.json`    — cross-pollination data from membrane feeds

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

// ─── Ban Pulse ───

#[derive(Debug, Default, Serialize)]
struct JailStats {
    banned: u64,
    total: u64,
}

#[derive(Debug, Serialize)]
struct BanPulse {
    timestamp: String,
    jails: HashMap<String, JailStats>,
    scatter_total: u64,
    mesh_nodes: usize,
}

fn query_fail2ban_jail(jail: &str) -> Option<JailStats> {
    let output = Command::new("fail2ban-client")
        .args(["status", jail])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut stats = JailStats::default();
    for line in text.lines() {
        if line.contains("Currently banned") {
            if let Some(val) = line.split(':').nth(1) {
                stats.banned = val.trim().parse().unwrap_or(0);
            }
        }
        if line.contains("Total banned") {
            if let Some(val) = line.split(':').nth(1) {
                stats.total = val.trim().parse().unwrap_or(0);
            }
        }
    }
    Some(stats)
}

fn generate_ban_pulse(live_dir: &Path) -> BanPulse {
    let jails = ["sshd", "caddy-badbots", "caddy-ratelimit"];
    let mut jail_data = HashMap::new();
    for jail in &jails {
        if let Some(stats) = query_fail2ban_jail(jail) {
            jail_data.insert((*jail).to_string(), stats);
        }
    }

    let scatter_total = read_json_u64(
        &live_dir.join("scatter-observatory.json"),
        &["scatter", "total_requests"],
    );

    let mesh_nodes = read_json_array_len(
        &live_dir.join("mesh-ring.json"),
        "nodes",
    );

    BanPulse {
        timestamp: chrono::Utc::now().to_rfc3339(),
        jails: jail_data,
        scatter_total,
        mesh_nodes,
    }
}

// ─── Pollen ───

#[derive(Debug, Serialize)]
struct Pollen {
    timestamp: String,
    scatter: PollenScatter,
    braid: PollenBraid,
    chipmunk: PollenChipmunk,
    human: PollenHuman,
    ban_pulse: PollenBanPulse,
    health: &'static str,
}

#[derive(Debug, Serialize)]
struct PollenScatter { total: u64, bytes: u64 }

#[derive(Debug, Serialize)]
struct PollenBraid { nodes: usize, edges: usize }

#[derive(Debug, Serialize)]
struct PollenChipmunk { sessions: u64, commands: u64 }

#[derive(Debug, Serialize)]
struct PollenHuman { visitors: u64 }

#[derive(Debug, Serialize)]
struct PollenBanPulse { jails: usize }

fn generate_pollen(live_dir: &Path) -> Pollen {
    Pollen {
        timestamp: chrono::Utc::now().to_rfc3339(),
        scatter: PollenScatter {
            total: read_json_u64(&live_dir.join("scatter-observatory.json"), &["scatter", "total_requests"]),
            bytes: read_json_u64(&live_dir.join("scatter-observatory.json"), &["scatter", "bytes_served"]),
        },
        braid: PollenBraid {
            nodes: read_json_array_len(&live_dir.join("braid.json"), "nodes"),
            edges: read_json_array_len(&live_dir.join("braid.json"), "edges"),
        },
        chipmunk: PollenChipmunk {
            sessions: read_json_u64(&live_dir.join("chipmunk.json"), &["total_sessions"]),
            commands: read_json_u64(&live_dir.join("chipmunk.json"), &["total_commands"]),
        },
        human: PollenHuman {
            visitors: read_json_u64(&live_dir.join("human.json"), &["total_visitors"]),
        },
        ban_pulse: PollenBanPulse {
            jails: read_json_object_len(&live_dir.join("ban-pulse.json"), "jails"),
        },
        health: "nominal",
    }
}

// ─── JSON helpers ───

fn read_json_file(path: &Path) -> Option<serde_json::Value> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn read_json_u64(path: &Path, keys: &[&str]) -> u64 {
    let Some(mut val) = read_json_file(path) else { return 0 };
    for key in keys {
        val = val.get(*key).cloned().unwrap_or(serde_json::Value::Null);
    }
    val.as_u64().unwrap_or(0)
}

fn read_json_array_len(path: &Path, key: &str) -> usize {
    read_json_file(path)
        .and_then(|v| v.get(key)?.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

fn read_json_object_len(path: &Path, key: &str) -> usize {
    read_json_file(path)
        .and_then(|v| v.get(key)?.as_object().map(|o| o.len()))
        .unwrap_or(0)
}

fn write_json<T: Serialize>(path: &Path, data: &T) {
    match serde_json::to_string_pretty(data) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!(error = %e, path = %path.display(), "pulse_writer: write failed");
            }
        }
        Err(e) => tracing::warn!(error = %e, "pulse_writer: serialize failed"),
    }
}

// ─── Public API ───

/// Configuration for the pulse writer.
pub struct PulseWriterConfig {
    /// Directory containing live-terminal JSON files.
    pub live_dir: PathBuf,
    /// Interval between pulse writes in seconds.
    pub interval_secs: u64,
}

impl Default for PulseWriterConfig {
    fn default() -> Self {
        Self {
            live_dir: PathBuf::from("/opt/membrane/live-terminal"),
            interval_secs: 120,
        }
    }
}

/// Run the pulse writer loop (call from tokio::spawn).
pub async fn pulse_loop(config: PulseWriterConfig) {
    let interval = std::time::Duration::from_secs(config.interval_secs);
    let live_dir = config.live_dir;

    // Initial warmup delay
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    loop {
        // Generate ban-pulse (spawn_blocking for fail2ban subprocess)
        let ban_pulse = {
            let ld = live_dir.clone();
            tokio::task::spawn_blocking(move || generate_ban_pulse(&ld))
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "ban pulse task panicked");
                    BanPulse {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        jails: HashMap::new(),
                        scatter_total: 0,
                        mesh_nodes: 0,
                    }
                })
        };

        write_json(&live_dir.join("ban-pulse.json"), &ban_pulse);

        // Generate pollen
        let pollen = generate_pollen(&live_dir);
        write_json(&live_dir.join("pollen.json"), &pollen);

        tracing::debug!(
            jails = ban_pulse.jails.len(),
            scatter = ban_pulse.scatter_total,
            "🌼 pulse-pollen written"
        );

        tokio::time::sleep(interval).await;
    }
}
