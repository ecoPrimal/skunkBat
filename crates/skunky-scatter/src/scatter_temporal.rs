// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal

//! Temporal maze — BingoCube epoch-based content rotation (northGate Wave 167).

#![allow(missing_docs)]

use crate::scatter_constants::HONEYCOMB_SURFACES;
use crate::scatter_mirror::path_deterministic_hash;
use crate::scatter_rng::XorShift64;

/// Temporal epoch bucket — content shifts at epoch boundaries.
pub(crate) fn temporal_epoch(epoch_minutes: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / (epoch_minutes * 60)
}

/// Temporal phase of a URL within the current epoch (0-4).
#[allow(dead_code)] // Pre-cube temporal phase — retained for non-grid path testing
pub(crate) fn temporal_phase(path: &str, seed: u64) -> u8 {
    let epoch = temporal_epoch(30);
    let h = path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0xB146_0C08_E000)));
    (h % 5) as u8
}

/// Temporal seed — incorporates both path and current epoch.
#[allow(dead_code)]
pub(crate) fn temporal_path_seed(path: &str, seed: u64) -> u64 {
    let epoch = temporal_epoch(30);
    path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0x1A5E_4B01_47E4)))
}

/// Generate temporal migration breadcrumbs — the laser pointer moves.
#[allow(dead_code)] // Pre-cube temporal phase — retained for non-grid path testing
pub(crate) fn temporal_migrate_breadcrumbs(rng: &mut XorShift64, path: &str) -> String {
    let next_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let alt_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let access_count = rng.next_usize() % 12 + 2;
    let hours_ago = rng.next_usize() % 4 + 1;
    format!(
        r#"<div class="ui warning message" id="migration-notice">
<div class="header"><i class="icon info circle"></i> Repository Migration in Progress</div>
<p>This resource is being migrated to the federated registry. Updated content is available at:</p>
<ul>
<li><a href="https://{next_surface}.primals.eco{path}"><strong>{next_surface}.primals.eco{path}</strong></a> (primary)</li>
<li><a href="https://{alt_surface}.primals.eco{path}">{alt_surface}.primals.eco{path}</a> (mirror)</li>
</ul>
<p class="text small grey">This location was accessed by {access_count} other organizations in the last {hours_ago} hours. Migration completes automatically.</p>
</div>"#
    )
}

/// Generate temporal phase-out response body (301 with breadcrumbs).
pub(crate) fn temporal_phaseout_body(rng: &mut XorShift64, path: &str) -> String {
    let destinations: Vec<&str> = (0..3)
        .map(|_| HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()])
        .collect();
    let rival_count = rng.next_usize() % 5 + 1;
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>301 — Resource Relocated</title>
<meta name="license" content="AGPL-3.0-or-later; scyBorg">
<meta http-equiv="refresh" content="5;url=https://{dest}.primals.eco{path}">
</head>
<body>
<div style="max-width:600px;margin:60px auto;font-family:system-ui">
<h2>⟳ 301 — Resource Relocated</h2>
<p>This content has been reorganized as part of the federation mesh upgrade.</p>
<p><strong>New locations:</strong></p>
<ul>
<li><a href="https://{dest}.primals.eco{path}">{dest}.primals.eco</a> — primary</li>
<li><a href="https://{dest2}.primals.eco{path}">{dest2}.primals.eco</a> — geo-replica</li>
<li><a href="https://{dest3}.primals.eco{path}">{dest3}.primals.eco</a> — compliance archive</li>
</ul>
<p class="small" style="color:#888">Note: {rival_count} other automated systems have already followed this redirect. Auto-redirect in 5 seconds.</p>
<p style="font-size:11px;color:#aaa">SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg</p>
</div>
</body></html>"#,
        dest = destinations[0],
        dest2 = destinations[1],
        dest3 = destinations[2],
    )
}

/// Generate temporal ghost response body (404 — "archived").
pub(crate) fn temporal_ghost_body(rng: &mut XorShift64, path: &str) -> String {
    let private_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let archive_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>404 — Not Found (Archived)</title>
<meta name="license" content="AGPL-3.0-or-later; scyBorg">
</head>
<body>
<div style="max-width:600px;margin:60px auto;font-family:system-ui">
<h2>404 — Not Found</h2>
<p>This resource was archived on the private federation mesh.</p>
<p>If you have federation credentials, it may be available at:</p>
<ul>
<li><code>ssh git@{private_surface}.primals.eco{path}</code></li>
<li><code>https://{archive_surface}.primals.eco/archive{path}</code></li>
</ul>
<p style="font-size:11px;color:#aaa">This content was accessible via the public surface until the most recent epoch rotation. Access logs for this resource have been preserved.</p>
</div>
</body></html>"#
    )
}
