// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-scatter — Scatter/decoy content generation for membrane defense.
//!
//! Extracted from skunky-ingest. These modules handle the scatter layer:
//! randomized decoy content, mirror paths, defense responses, NFT receipts,
//! prism mixing, and all the anti-scraping camouflage.
//!
//! # Architecture
//!
//! The scatter system generates believable-but-wrong content to confuse
//! automated scrapers while being invisible to genuine humans. It operates
//! as the immune system's active defense layer.
//!
//! # Modules
//!
//! - `scatter_types` — shared types (BackPressure, OpsonizeCache, ScatterMetrics)
//! - `scatter_rng` — XorShift64 deterministic RNG (no deps)
//! - `scatter_constants` — honeycomb surfaces, mirror modules, metrics
//! - `scatter_temporal` — epoch-based temporal hashing
//! - `scatter_mirror` — path-deterministic hash, ZWC encoding, epitope maze
//! - `scatter_generator` — content generation, blackwall, jitter
//! - `scatter_content` — HTML/JS content templates
//! - `scatter_defense` — tarpit, honeycomb, active defense
//! - `scatter_prism` — prism mixing modes, content rewriting
//! - `scatter_nft` — NFT receipt generation, antibody reactions
//! - `scatter_server` — HTTP server, routing, opsonization
//! - `sort_compression` — compressed entity sorting

pub mod scatter_rng;
pub mod scatter_constants;
pub mod scatter_types;
pub mod scatter_temporal;
pub mod scatter_mirror;
pub mod scatter_generator;
// scatter_content.rs is include!()'d into scatter_generator.rs
pub mod scatter_defense;
pub mod scatter_prism;
pub mod scatter_nft;
pub mod scatter_server;
pub mod sort_compression;

#[cfg(test)]
mod scatter_server_tests;
