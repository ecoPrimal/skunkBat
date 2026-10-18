// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Library crate exposing all modules for reuse (integration tests, federation,
//! future tooling). The binary crate (`main.rs`) owns the CLI and tail loop.

pub mod aggregator;
pub mod anderson_bridge;
pub mod aperture;
pub mod caddy;
pub mod caddy_bridge;
pub mod cloudflare;
pub mod coprimality;
pub mod cube_grid;
pub mod epitope_conservation;
pub mod epitope_sensitivity;
pub mod cube_oracle;
pub mod dashboard_profile;
pub mod dashboard_analysis;
pub mod dashboard_writer;
pub mod cursor;
pub mod entity_classifier;
pub mod entity_profile;
pub mod entity_sort;
pub mod entity_topology;
pub mod epitope_defs;
// dormant: epitope_inversion (Wave 171 — tests only, never wired)
pub mod epitope_registry;
// dormant: epitope_lure (Wave 171 — tests only, never wired)
pub mod error;
pub mod federation;
pub mod fleet;
pub mod fluoro_tag;
pub mod ingestion_observer;
pub mod inflammatory;
pub mod lysogeny;
pub(crate) mod ribocipher_const;
pub mod rpc;
pub mod abuse_reporter;
pub mod bloom_sensor;
pub mod bloom_emitter;
pub mod membrane_geometry;
pub mod membrane_stack;
pub mod ntfy_bridge;
pub mod pulse_writer;
// dormant: journey_tracer (Wave 171 — tests only, never wired)
pub mod scatter_nft;
pub mod scatter_rng;
pub mod scatter_generator;
pub mod scatter_constants;
pub mod scatter_mirror;
pub mod scatter_prism;
pub mod scatter_types;
pub mod scatter_defense;
pub mod scatter_server;
pub mod scatter_temporal;
pub mod scyborg_prism;
pub mod signal_spine;
// fossilized: signal_writer (Wave 170 → fossilRecord/signal-writer-rust-wave170)
// Replaced gen-signal-data.py, then superseded by dashboard_writer.
// Output (signal-data.js) was orphaned when signal-exploration.js was deleted.
pub mod sort_compression;
pub(crate) mod squirrel_announce;
// dormant: plasmid (Wave 171 — behavioral tokens, tests only; ConservedPlasmid in scatter_types is live)
pub mod campfire_util;
pub mod campfire_writer;
pub mod mirror_inbox;
pub mod page_mirror;
pub mod storyteller;
pub mod surface_registry;
pub mod threat_feed;
pub mod visitor_archetype;
pub mod symbiosis;
