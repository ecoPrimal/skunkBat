// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Ntfy → Neutron bridge — replaces neutron-notify-bridge.py (76 lines Python → Rust).
//!
//! Polls ntfy topic on a configurable interval, bridges messages into
//! opsonize discuss API (neutron inbox).
//!
//! # What it replaces
//!
//! | Python script             | Lines | Function                           |
//! |---------------------------|-------|------------------------------------|
//! | neutron-notify-bridge.py  | 76    | ntfy poll → neutron inbox bridge   |

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct NtfyMessage {
    event: Option<String>,
    title: Option<String>,
    message: Option<String>,
    topic: Option<String>,
    #[allow(dead_code)]
    time: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DiscussPost {
    page: String,
    author: String,
    body: String,
}

/// Configuration for the ntfy bridge.
pub struct NtfyBridgeConfig {
    /// ntfy topic URL (with JSON poll params).
    pub ntfy_url: String,
    /// opsonize discuss API endpoint.
    pub discuss_url: String,
    /// Poll interval in seconds.
    pub interval_secs: u64,
}

impl Default for NtfyBridgeConfig {
    fn default() -> Self {
        Self {
            ntfy_url: "https://notify.primals.eco/membrane/json?poll=1&since=10m".into(),
            discuss_url: "http://127.0.0.1:8097/api/discuss".into(),
            interval_secs: 300,
        }
    }
}

async fn fetch_ntfy(url: &str) -> Vec<NtfyMessage> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("neutron-bridge/2.0-rust")
        .build()
        .unwrap_or_default();

    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "ntfy fetch failed");
            return Vec::new();
        }
    };

    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    text.lines()
        .filter_map(|line| {
            let msg: NtfyMessage = serde_json::from_str(line.trim()).ok()?;
            if msg.event.as_deref() == Some("message") {
                Some(msg)
            } else {
                None
            }
        })
        .collect()
}

async fn post_to_neutron(discuss_url: &str, body: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let post = DiscussPost {
        page: "neutron-inbox".into(),
        author: "ntfy\u{2192}neutron".into(),
        body: body.into(),
    };

    match client.post(discuss_url).json(&post).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(e) => {
            tracing::debug!(error = %e, "discuss post failed");
            false
        }
    }
}

/// Run the ntfy bridge loop (call from tokio::spawn).
pub async fn bridge_loop(config: NtfyBridgeConfig) {
    let interval = Duration::from_secs(config.interval_secs);

    // Initial warmup
    tokio::time::sleep(Duration::from_secs(30)).await;

    loop {
        let messages = fetch_ntfy(&config.ntfy_url).await;
        let mut bridged = 0u32;

        for msg in &messages {
            let mut body = String::new();
            if let Some(ref title) = msg.title {
                body.push_str(title);
                body.push('\n');
            }
            if let Some(ref message) = msg.message {
                body.push_str(message);
            }
            if let Some(ref topic) = msg.topic {
                if topic != "membrane" {
                    body.push_str("\n[topic: ");
                    body.push_str(topic);
                    body.push(']');
                }
            }

            let trimmed = body.trim();
            if !trimmed.is_empty() && post_to_neutron(&config.discuss_url, trimmed).await {
                bridged += 1;
            }
        }

        if bridged > 0 {
            tracing::info!(count = bridged, "📨 ntfy → neutron bridged");
        }

        tokio::time::sleep(interval).await;
    }
}
