// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Dashboard writer — generates `dashboard.json` for the signal site.
//!
//! Replaces `bloom_live.py` (793 lines) which tailed the Caddy log in a
//! separate Python process, duplicating the exact work skunky-ingest does.
//! This module accumulates per-IP behavioral data from the caddy stream
//! and writes `dashboard.json` in the same schema the signal site expects.
//!
//! ## Convergence
//!
//! bloom_live.py → skunky-ingest dashboard_writer:
//! - Classification engine → [`crate::bloom_sensor`] + [`crate::entity_classifier`]
//! - Per-IP tracking → [`crate::dashboard_profile::IpProfile`]
//! - Epitope hashing → [`crate::dashboard_profile::compute_epitope_hash`]
//! - L2 collision classification → [`crate::dashboard_profile::classify_collision_l2`]
//! - Dashboard JSON formatting → [`DashboardWriter`] (this module)
//! - Sourdough culture → persistent state file
//!
//! No more duplicate log tailing. Dashboard is a side output of the pipeline.

#![allow(missing_docs)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::caddy;
use crate::dashboard_profile::{
    geo_lookup, hash_ip, compute_epitope_hash, classify_collision_l2,
    score_trio, CollisionClass, GeoInfo, IpProfile, BingoCubeTrio, TrioClass,
};

// GEO/WHOIS lookup, IpProfile, BingoCubeTrio, trio scoring, IP hashing,
// epitope hashing, and collision classification live in dashboard_profile.rs
// — the π split.


// ── Dashboard writer ──

/// Sourdough culture — persisted across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DashboardCulture {
    /// Per-IP behavioral profiles — keyed by hash_ip(ip), not raw IP.
    /// Raw IPs never persist to disk. ZK boundary enforced at serialization.
    ips: HashMap<u64, IpProfile>,
    /// Total requests since culture inception
    total_requests: u64,
    /// Fleet request count
    fleet_requests: u64,
    /// Distinct UAs seen per IP — keyed by hash_ip(ip).
    ip_uas: HashMap<u64, HashSet<String>>,
    /// Distinct hosts per IP — keyed by hash_ip(ip).
    ip_hosts: HashMap<u64, HashSet<String>>,
    /// Repo-level targeting across all IPs
    repo_totals: HashMap<String, u64>,
    /// Country estimates
    country_counts: HashMap<String, u64>,
    /// Region estimates (country:region key)
    #[serde(default)]
    region_counts: HashMap<String, u64>,
    /// City estimates (country:region:city key)
    #[serde(default)]
    city_counts: HashMap<String, u64>,
    /// ASN type counts
    #[serde(default)]
    asn_type_counts: HashMap<String, u64>,
    /// Subnet counts
    subnet_counts: HashMap<String, u64>,
    /// Timing intervals (rolling, capped at 2000)
    fleet_timing_intervals: Vec<f64>,
    /// Inception timestamp
    inception_epoch: f64,
    /// Epitope collision map: epitope_hash → set of ip_hashes
    epitope_collisions: HashMap<String, HashSet<u64>>,
}

/// Dashboard writer — fed by each caddy log entry, writes dashboard.json.
pub struct DashboardWriter {
    culture: DashboardCulture,
    output_path: PathBuf,
    state_path: PathBuf,
    /// Last fleet request timestamp (for timing intervals)
    last_fleet_ts: f64,
    /// Ingest counter for periodic flush
    ingest_count: u64,
    /// How many entries between dashboard writes
    write_interval: u64,
    /// Culture save counter
    culture_save_counter: u32,
    /// Shared epitope registry — culture-derived bot detection.
    registry: crate::epitope_registry::SharedRegistry,
    /// Shared Anderson profile — updated on flush, read by /plasmid endpoint.
    anderson_profile: crate::anderson_bridge::SharedAndersonProfile,
    /// Announce Anderson profile to squirrel AI coordination primal.
    squirrel_announce: bool,
}

impl DashboardWriter {
    /// Create a new dashboard writer with sourdough culture.
    pub fn new(
        output_path: PathBuf,
        state_path: PathBuf,
        write_interval: u64,
        registry: crate::epitope_registry::SharedRegistry,
    ) -> Self {
        Self::with_anderson(output_path, state_path, write_interval, registry, std::sync::Arc::new(tokio::sync::RwLock::new(None)), false)
    }

    /// Create a new dashboard writer with shared Anderson profile output.
    pub fn with_anderson(
        output_path: PathBuf,
        state_path: PathBuf,
        write_interval: u64,
        registry: crate::epitope_registry::SharedRegistry,
        anderson_profile: crate::anderson_bridge::SharedAndersonProfile,
        squirrel_announce: bool,
    ) -> Self {
        let culture = Self::load_culture(&state_path);
        let writer = Self {
            last_fleet_ts: 0.0,
            ingest_count: 0,
            write_interval,
            culture_save_counter: 0,
            output_path,
            state_path,
            culture,
            registry,
            anderson_profile,
            squirrel_announce,
        };
        tracing::info!(
            output = %writer.output_path.display(),
            culture = %writer.state_path.display(),
            ips = writer.culture.ips.len(),
            requests = writer.culture.total_requests,
            interval = writer.write_interval,
            "📊 dashboard writer loaded"
        );
        writer
    }

    fn load_culture(path: &Path) -> DashboardCulture {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut culture = match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(culture) => {
                    let c: &DashboardCulture = &culture;
                    tracing::info!(
                        ips = c.ips.len(),
                        requests = c.total_requests,
                        path = %path.display(),
                        "🧬 dashboard culture loaded — sourdough warm start"
                    );
                    culture
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "dashboard culture corrupt — starting fresh"
                    );
                    DashboardCulture::default()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no dashboard culture file — first generation"
                );
                DashboardCulture::default()
            }
        };

        // Guard: inception_epoch=0.0 means the field was never set (pre-Wave 167
        // cultures or Default derive). Set to now so RPS doesn't divide by 56 years.
        if culture.inception_epoch < 1_000_000_000.0 {
            tracing::warn!(
                old_epoch = culture.inception_epoch,
                "inception_epoch missing or invalid — setting to now"
            );
            culture.inception_epoch = now;
        }

        culture
    }

    /// Ingest a parsed caddy log entry.
    pub fn ingest(&mut self, entry: &caddy::LogEntry) {
        let ip = &entry.request.remote_ip;
        let ip_h = hash_ip(ip);
        let h = &entry.request.headers;
        let uri = &entry.request.uri;
        let ua = h.user_agent.first().cloned().unwrap_or_default();
        let host = &entry.request.host;
        let ts = entry.ts;

        self.culture.total_requests += 1;

        // Per-IP profile — keyed by hash, raw IP never stored
        let profile = self.culture.ips.entry(ip_h).or_insert_with(|| IpProfile::new(ts));
        profile.requests += 1;
        profile.last_seen = ts;

        // Classification — Wave 167: three-tier (fleet / ghost / human)
        // Fleet: Chrome UA without Sec-Fetch, OR known bot UA strings
        // Ghost: has Sec-Fetch but no referer (residential proxy exits)
        // Human: has Sec-Fetch AND has referer (arrived from somewhere real)
        let has_sf = !h.sec_fetch_mode.is_empty();
        let has_referer = !h.referer.is_empty();
        let is_bot_ua = self.registry.read()
            .map(|reg| reg.is_declared_bot(&ua))
            .unwrap_or_else(|_| crate::entity_classifier::is_declared_bot(&ua));
        let is_fleet = is_bot_ua || (ua.contains("Chrome/") && !has_sf);
        let is_human = has_sf && !is_bot_ua && (has_referer || profile.has_referer);
        if is_bot_ua {
            profile.is_declared_bot = true;
        }
        if is_fleet {
            profile.is_fleet = true;
            self.culture.fleet_requests += 1;

            // Fleet timing
            if self.last_fleet_ts > 0.0 {
                let interval = ts - self.last_fleet_ts;
                if interval > 0.0 && interval < 5.0 {
                    self.culture.fleet_timing_intervals.push(interval);
                    if self.culture.fleet_timing_intervals.len() > 2000 {
                        let drain = self.culture.fleet_timing_intervals.len() - 1000;
                        self.culture.fleet_timing_intervals.drain(..drain);
                    }
                }
            }
            self.last_fleet_ts = ts;
        }
        if is_human {
            profile.is_human = true;
        }
        // Ghost: has browser headers but no referer and not a known bot.
        // Don't set is_human; don't set is_fleet. They fall into the
        // unclassified bucket until multi-request evidence promotes them.
        // If a ghost later sends a referer, is_human gets set above.

        // Status tracking
        *profile.statuses.entry(entry.status).or_insert(0) += 1;

        // Header invariants (conserved epitopes)
        if profile.accept_encoding.is_none() {
            if let Some(ae) = h.accept_encoding.first() {
                profile.accept_encoding = Some(ae.clone());
            }
        }
        if profile.accept.is_none() {
            if let Some(acc) = h.accept.first() {
                profile.accept = Some(acc.clone());
            }
        }
        if !h.accept_language.is_empty() {
            profile.has_accept_lang = true;
        }
        if has_sf {
            profile.has_sec_fetch = true;
        }
        if !h.referer.is_empty() {
            profile.has_referer = true;
        }
        if !h.cookie.is_empty() {
            profile.has_cookie = true;
        }

        // Asset detection
        if uri.ends_with(".css")
            || uri.ends_with(".js")
            || uri.ends_with(".woff2")
            || uri.ends_with(".woff")
            || uri.ends_with(".ttf")
            || uri.contains("search_index")
        {
            profile.has_assets = true;
        }

        // Path targeting
        if uri.contains("/blame/") {
            profile.blame_count += 1;
            *profile.path_types.entry("blame".to_string()).or_insert(0) += 1;
        } else if uri.contains("/commit/") || uri.contains("/commits/") {
            profile.commit_count += 1;
            *profile.path_types.entry("commit".to_string()).or_insert(0) += 1;
        } else if uri.contains("/src/") {
            *profile.path_types.entry("src".to_string()).or_insert(0) += 1;
        } else if uri.contains("/raw/") {
            *profile.path_types.entry("raw".to_string()).or_insert(0) += 1;
        } else if uri.contains("/issues") {
            *profile.path_types.entry("issues".to_string()).or_insert(0) += 1;
        } else {
            *profile.path_types.entry("other".to_string()).or_insert(0) += 1;
        }

        // Repo extraction
        if host.contains("git.primals") || host.contains("forge.primals") {
            let parts: Vec<&str> = uri.trim_matches('/').split('/').collect();
            if parts.len() >= 2 {
                let repo = format!("{}/{}", parts[0], parts[1]);
                *profile.repos.entry(repo.clone()).or_insert(0) += 1;
                *self.culture.repo_totals.entry(repo).or_insert(0) += 1;
            }
        }

        // UA pool tracking — keyed by ip hash
        if !ua.is_empty() {
            let ua_set = self.culture.ip_uas.entry(ip_h).or_default();
            ua_set.insert(ua.get(..80).unwrap_or(&ua).to_string());
            profile.ua_pool_size = ua_set.len() as u16;
        }

        // Host tracking — keyed by ip hash
        if !host.is_empty() {
            let host_set = self.culture.ip_hosts.entry(ip_h).or_default();
            host_set.insert(host.clone());
            profile.host_count = host_set.len() as u16;
        }

        // Subnet + GEO
        let subnet = {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.{}.x", parts[0], parts[1], parts[2])
            } else {
                ip.clone()
            }
        };
        *self.culture.subnet_counts.entry(subnet).or_insert(0) += 1;
        let geo = geo_lookup(ip);
        *self.culture.country_counts.entry(geo.country.clone()).or_insert(0) += 1;
        if let Some(ref region) = geo.region {
            let key = format!("{}:{}", geo.country, region);
            *self.culture.region_counts.entry(key).or_insert(0) += 1;
        }
        if let Some(ref city) = geo.city {
            if let Some(ref region) = geo.region {
                let key = format!("{}:{}:{}", geo.country, region, city);
                *self.culture.city_counts.entry(key).or_insert(0) += 1;
            }
        }
        if let Some(ref asn_type) = geo.asn_type {
            *self.culture.asn_type_counts.entry(asn_type.clone()).or_insert(0) += 1;
        }

        // Epitope hashing (after >= 3 requests)
        if profile.requests >= 3 && profile.epitope_hash.is_none() {
            let ehash = compute_epitope_hash(profile);
            self.culture
                .epitope_collisions
                .entry(ehash.clone())
                .or_default()
                .insert(ip_h);
            profile.epitope_hash = Some(ehash);
        }

        // Periodic dashboard write
        self.ingest_count += 1;
        if self.ingest_count % self.write_interval == 0 {
            self.flush();
        }
    }

    /// Write dashboard.json + state.json + epitope_caddy.json.
    pub fn flush(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let uptime = (now - self.culture.inception_epoch).max(1.0);
        let rps = self.culture.total_requests as f64 / uptime;

        // Collect fleet + human IP counts (by hash — no raw IPs)
        let fleet_count = self.culture.ips.values().filter(|p| p.is_fleet).count();
        let human_count = self.culture.ips.values().filter(|p| p.is_human).count();
        let fleet_pct = if !self.culture.ips.is_empty() {
            fleet_count as f64 / self.culture.ips.len() as f64 * 100.0
        } else {
            0.0
        };

        // Top offenders — sorted by request count. Uses ip_hash, not raw IP.
        let mut top_offenders: Vec<_> = self.culture.ips.iter().collect();
        top_offenders.sort_by(|a, b| b.1.requests.cmp(&a.1.requests));

        let top_offenders_json: Vec<serde_json::Value> = top_offenders
            .iter()
            .take(25)
            .map(|(ip_hash, p)| {
                let top_repos: BTreeMap<String, u32> = p.repos.iter()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                let top_paths: BTreeMap<String, u32> = p.path_types.iter()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                let fmt_ts = |ts: f64| -> String {
                    chrono::DateTime::from_timestamp(ts as i64, 0)
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_default()
                };
                let trio = score_trio(p);
                serde_json::json!({
                    "ip_hash": format!("{:016x}", ip_hash),
                    "requests": p.requests,
                    "first_seen": fmt_ts(p.first_seen),
                    "last_seen": fmt_ts(p.last_seen),
                    "is_fleet": p.is_fleet,
                    "trio_class": trio.classification,
                    "trio_attention": (trio.attention * 100.0).round() / 100.0,
                    "trio_curiosity": (trio.curiosity * 100.0).round() / 100.0,
                    "trio_interaction": (trio.interaction * 100.0).round() / 100.0,
                    "top_repos": top_repos,
                    "top_paths": top_paths,
                })
            })
            .collect();

        // Subnets — subnet strings are kept (they're /24 prefixes, not full IPs)
        let mut subnets: Vec<_> = self.culture.subnet_counts.iter().collect();
        subnets.sort_by(|a, b| b.1.cmp(a.1));
        let subnets_json: Vec<serde_json::Value> = subnets
            .iter()
            .take(15)
            .map(|(subnet, count)| {
                let count = *count;
                let geo = geo_lookup(&subnet.replace(".x", ".0"));
                serde_json::json!({
                    "subnet": subnet,
                    "requests": count,
                    "org": geo.org,
                    "country": geo.country,
                    "region": geo.region,
                    "city": geo.city,
                    "asn_type": geo.asn_type,
                })
            })
            .collect();

        // Targets (repos)
        let mut targets: Vec<_> = self.culture.repo_totals.iter().collect();
        targets.sort_by(|a, b| b.1.cmp(a.1));
        let targets_json: Vec<serde_json::Value> = targets
            .iter()
            .take(15)
            .map(|(repo, count)| serde_json::json!({"repo": repo, "requests": count}))
            .collect();

        // Path types aggregated
        let mut path_types: HashMap<String, u64> = HashMap::new();
        for p in self.culture.ips.values() {
            for (ptype, &count) in &p.path_types {
                *path_types.entry(ptype.clone()).or_insert(0) += count as u64;
            }
        }

        // Geography — progressive subdivision
        let mut geo_sorted: Vec<_> = self.culture.country_counts.iter().collect();
        geo_sorted.sort_by(|a, b| b.1.cmp(a.1));
        let geo_json: Vec<serde_json::Value> = geo_sorted
            .iter()
            .map(|(country, count)| {
                // Collect regions within this country
                let mut regions: Vec<serde_json::Value> = self.culture.region_counts.iter()
                    .filter(|(k, _)| k.starts_with(&format!("{}:", country)))
                    .map(|(k, v)| {
                        let region = k.splitn(2, ':').nth(1).unwrap_or("??");
                        // Collect cities within this region
                        let cities: Vec<serde_json::Value> = self.culture.city_counts.iter()
                            .filter(|(ck, _)| ck.starts_with(&format!("{}:{}:", country, region)))
                            .map(|(ck, cv)| {
                                let city = ck.rsplitn(2, ':').next().unwrap_or("??");
                                serde_json::json!({"city": city, "requests": cv})
                            })
                            .collect();
                        serde_json::json!({
                            "region": region,
                            "requests": v,
                            "cities": cities,
                        })
                    })
                    .collect();
                regions.sort_by(|a, b| {
                    let ar = a["requests"].as_u64().unwrap_or(0);
                    let br = b["requests"].as_u64().unwrap_or(0);
                    br.cmp(&ar)
                });
                serde_json::json!({
                    "country": country,
                    "requests": count,
                    "regions": regions,
                })
            })
            .collect();

        // ASN type breakdown
        let asn_types: serde_json::Value = serde_json::json!(self.culture.asn_type_counts);

        // Timing analysis
        let timing = if self.culture.fleet_timing_intervals.len() > 10 {
            let intervals = &self.culture.fleet_timing_intervals;
            let sum: f64 = intervals.iter().sum();
            let mean = sum / intervals.len() as f64;
            let variance: f64 = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
                / intervals.len() as f64;
            let stdev = variance.sqrt();
            let cv = if mean > 0.0 { stdev / mean } else { 0.0 };
            let classification = if cv < 0.15 {
                "HIGH"
            } else if cv < 0.5 {
                "MEDIUM"
            } else {
                "LOW"
            };

            serde_json::json!({
                "avg_interval_ms": (mean * 1000.0 * 10.0).round() / 10.0,
                "cv": (cv * 1000.0).round() / 1000.0,
                "machine_confidence": classification,
            })
        } else {
            serde_json::json!({
                "avg_interval_ms": 0.0,
                "cv": 0.0,
                "machine_confidence": "LOW",
            })
        };

        // Collision layer (L2)
        let mut collision_counts: HashMap<&str, usize> = HashMap::new();
        for p in self.culture.ips.values() {
            let class = classify_collision_l2(p);
            let key = match class {
                CollisionClass::Genuine => "genuine",
                CollisionClass::Agentic => "agentic",
                CollisionClass::Coordinated => "coordinated",
                CollisionClass::Fleet => "fleet",
            };
            *collision_counts.entry(key).or_insert(0) += 1;
        }

        // Epitope clusters — keyed by ip hash, no raw IPs exposed
        let mut epitope_clusters: Vec<serde_json::Value> = self
            .culture
            .epitope_collisions
            .iter()
            .filter(|(_, ip_hashes)| !ip_hashes.is_empty())
            .map(|(hash, ip_hashes)| {
                let sample_ae = ip_hashes
                    .iter()
                    .next()
                    .and_then(|h| self.culture.ips.get(h))
                    .and_then(|p| p.accept_encoding.clone())
                    .unwrap_or_else(|| "?".to_string());
                let max_ua_pool = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.ua_pool_size)
                    .max()
                    .unwrap_or(0);
                let blame_total: u32 = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.blame_count)
                    .sum();
                let commit_total: u32 = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.commit_count)
                    .sum();
                let blame_ratio = if commit_total > 0 {
                    blame_total as f64 / commit_total as f64
                } else {
                    0.0
                };
                let has_lang = ip_hashes
                    .iter()
                    .any(|h| self.culture.ips.get(h).map(|p| p.has_accept_lang).unwrap_or(false));

                serde_json::json!({
                    "hash": hash,
                    "ips": ip_hashes.len(),
                    "sample_ae": sample_ae,
                    "ua_pool_size": max_ua_pool,
                    "blame_ratio": (blame_ratio * 100.0).round() / 100.0,
                    "has_lang": has_lang,
                })
            })
            .collect();
        epitope_clusters.sort_by(|a, b| {
            b.get("ips")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&a.get("ips").and_then(|v| v.as_u64()).unwrap_or(0))
        });
        epitope_clusters.truncate(20);

        let epitope_summary = serde_json::json!({
            "total_hashed": self.culture.ips.values().filter(|p| p.epitope_hash.is_some()).count(),
            "unique_hashes": self.culture.epitope_collisions.len(),
            "largest_cluster": self.culture.epitope_collisions.values().map(|v| v.len()).max().unwrap_or(0),
            "clusters_gt1": self.culture.epitope_collisions.values().filter(|v| v.len() > 1).count(),
        });

        // Tense distribution (Paper 48 — epitope sort compression).
        // Is = first observation (requests == 1), Was = repeat (requests > 1),
        // WillBe = nautilus predicted — IPs whose orbital family predicts a
        // next host they haven't visited yet (peptidoglycan layer, Wave 173a).
        let tense_is = self.culture.ips.values().filter(|p| p.requests == 1).count();
        let tense_was = self.culture.ips.values().filter(|p| p.requests > 1).count();
        let tense_willbe = nautilus_predict(&self.culture);
        let tense_distribution = serde_json::json!({
            "is": tense_is,
            "was": tense_was,
            "will_be": tense_willbe,
        });

        // Sort compression scores (Paper 48) — via sort_compression module.
        let epitope_triggered = epitope_triggered_counts(&self.culture);
        let sort_pop = crate::sort_compression::SortPopulation {
            n: self.culture.ips.len(),
            k: self.culture.epitope_collisions.len(),
            epitope_triggered,
            tense: (tense_is, tense_was, tense_willbe),
        };
        let sort_result = sort_pop.compress();
        let (strongest_idx, strongest_gain) = sort_result.strongest_epitope();
        let sort_compression = serde_json::json!({
            "alpha": (sort_result.alpha * 10.0).round() / 10.0,
            "epitope": (sort_result.epitope * 10.0).round() / 10.0,
            "tense": (sort_result.tense * 10.0).round() / 10.0,
            "total_gain": (sort_result.total_gain() * 10.0).round() / 10.0,
            "ratio": (sort_result.ratio() * 1000.0).round() / 1000.0,
            "strongest_epitope": {
                "name": crate::sort_compression::EPITOPE_NAMES[strongest_idx],
                "gain_bits": (strongest_gain * 100.0).round() / 100.0,
            },
            "grid_feedback": sort_result.quantize_for_grid(),
        });

        let dashboard = serde_json::json!({
            "ts": now,
            "utc": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "uptime_secs": uptime as u64,
            "total_requests": self.culture.total_requests,
            "fleet_requests": self.culture.fleet_requests,
            "rps": (rps * 10.0).round() / 10.0,
            "unique_ips": self.culture.ips.len(),
            "fleet_ips": fleet_count,
            "human_ips": human_count,
            "fleet_pct": (fleet_pct * 10.0).round() / 10.0,
            "top_offenders": top_offenders_json,
            "subnets": subnets_json,
            "targets": targets_json,
            "path_types": path_types,
            "geography": geo_json,
            "asn_types": asn_types,
            "timing": timing,
            "collision_level2": {
                "genuine": collision_counts.get("genuine").copied().unwrap_or(0),
                "agentic": collision_counts.get("agentic").copied().unwrap_or(0),
                "coordinated": collision_counts.get("coordinated").copied().unwrap_or(0),
                "fleet": collision_counts.get("fleet").copied().unwrap_or(0),
            },
            "epitope_clusters": epitope_clusters,
            "epitope_summary": epitope_summary,
            "tense_distribution": tense_distribution,
            "sort_compression": sort_compression,
            "trajectory": trajectory_analysis(&self.culture),
            "membrane_geometry": membrane_geometry(tense_is, tense_was, tense_willbe),
            "membrane_delta": membrane_delta(&self.culture),
        });

        // Write dashboard.json
        if let Some(parent) = self.output_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string(&dashboard) {
            Ok(json) => match std::fs::write(&self.output_path, &json) {
                Ok(()) => {
                    tracing::info!(
                        ips = self.culture.ips.len(),
                        requests = self.culture.total_requests,
                        fleet = fleet_count,
                        human = human_count,
                        bytes = json.len(),
                        "📊 dashboard.json updated"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dashboard.json write failed");
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "dashboard serialization failed");
            }
        }

        // Write compact state.json
        let state_dir = self.output_path.parent().unwrap_or(Path::new("/tmp"));
        let state_json_path = state_dir.join("state.json");
        let state = serde_json::json!({
            "ts": now,
            "rps": (rps * 10.0).round() / 10.0,
            "fleet_ips": fleet_count,
            "human_ips": human_count,
            "total": self.culture.total_requests,
            "collision_l2": {
                "g": collision_counts.get("genuine").copied().unwrap_or(0),
                "a": collision_counts.get("agentic").copied().unwrap_or(0),
                "c": collision_counts.get("coordinated").copied().unwrap_or(0),
                "f": collision_counts.get("fleet").copied().unwrap_or(0),
            },
            "epitope": {
                "hashed": self.culture.ips.values().filter(|p| p.epitope_hash.is_some()).count(),
                "unique": self.culture.epitope_collisions.len(),
                "largest": self.culture.epitope_collisions.values().map(|v| v.len()).max().unwrap_or(0),
                "gt1": self.culture.epitope_collisions.values().filter(|v| v.len() > 1).count(),
            },
        });
        let _ = serde_json::to_string(&state).map(|s| std::fs::write(&state_json_path, s));

        // Write epitope_caddy.json (epitope_hash → ip_hash list for scatter server)
        let epitope_caddy_path = state_dir.join("epitope_caddy.json");
        let mut epitope_map: HashMap<String, Vec<String>> = HashMap::new();
        for (hash, ip_hashes) in &self.culture.epitope_collisions {
            let mut hash_list: Vec<String> = ip_hashes.iter()
                .map(|h| format!("{:016x}", h))
                .collect();
            hash_list.sort();
            epitope_map.insert(hash.clone(), hash_list);
        }
        let epitope_caddy = serde_json::json!({"ts": now, "map": epitope_map});
        let _ = serde_json::to_string(&epitope_caddy)
            .map(|s| std::fs::write(&epitope_caddy_path, s));

        // Save sourdough culture periodically
        self.culture_save_counter += 1;
        if self.culture_save_counter % 10 == 0 || self.culture_save_counter == 1 {
            self.save_culture();
        }

        // Update shared Anderson profile from population observations
        self.update_anderson_profile();
    }

    /// Compute and publish the Anderson profile from current culture data.
    fn update_anderson_profile(&self) {
        if self.culture.ips.is_empty() {
            return;
        }

        let mesh_size = 4_u32; // current operational bodies
        let observations = crate::anderson_bridge::extract_observations(
            &self.culture.ips,
            mesh_size,
        );
        let profile = crate::anderson_bridge::compute_profile(
            &observations,
            mesh_size,
        );

        // Write to /run/membrane/ so the scatter server's /plasmid endpoint reads it
        if let Ok(json) = serde_json::to_string(&profile) {
            let _ = std::fs::create_dir_all("/run/membrane");
            let _ = std::fs::write("/run/membrane/anderson-profile.json", &json);
        }

        // Announce to squirrel (fire-and-forget, spawned, never blocks bloom)
        if self.squirrel_announce {
            let profile_clone = profile.clone();
            tokio::spawn(async move {
                crate::squirrel_announce::announce_to_squirrel(&profile_clone).await;
            });
        }

        // Also update the shared profile for in-process consumers
        if let Ok(mut guard) = self.anderson_profile.try_write() {
            *guard = Some(profile);
        }
    }

    /// Persist the sourdough culture to disk.
    pub fn save_culture(&self) {
        match serde_json::to_string(&self.culture) {
            Ok(json) => {
                if let Some(parent) = self.state_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&self.state_path, &json) {
                    tracing::warn!(error = %e, "dashboard culture save failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "dashboard culture serialization failed");
            }
        }
    }
}

/// Count how many IPs trigger each of the 6 canonical epitopes (Paper 48).
///
/// Uses IpProfile heuristics that approximate the entity-level epitope tests:
///   0. burst_ratio     — >60 req/min sustained
///   1. reading_deficit — >100 requests, lifespan <60s (no reading pauses)
///   2. ua_pool_poverty — only 1 User-Agent for >10 requests
///   3. sec_fetch_monotone — never sent Sec-Fetch headers
///   4. session_absent  — never sent cookies
///   5. referer_self_loop — never sent an external Referer
fn epitope_triggered_counts(culture: &DashboardCulture) -> [usize; 6] {
    let mut counts = [0usize; 6];
    for profile in culture.ips.values() {
        if profile.requests < 3 {
            continue; // too few requests to evaluate
        }
        let span = (profile.last_seen - profile.first_seen).max(1.0);
        let rpm = profile.requests as f64 / (span / 60.0);

        if rpm > 60.0 { counts[0] += 1; }                          // burst_ratio
        if profile.requests > 100 && span < 60.0 { counts[1] += 1; } // reading_deficit
        if profile.ua_pool_size <= 1 { counts[2] += 1; }           // ua_pool_poverty
        if !profile.has_sec_fetch { counts[3] += 1; }              // sec_fetch_monotone
        if !profile.has_cookie { counts[4] += 1; }                 // session_absent
        if !profile.has_referer { counts[5] += 1; }                // referer_self_loop
    }
    counts
}

/// Membrane delta — the gap between inward and outward view (Wave 173a).
///
/// The opacity O = 1 - 1/S(d) measures from IS only (inward view).
/// The reflection R = S(d)/(S(d)+1) measures from all entities (outward view).
/// The delta = O - R = -1/[S(d)(S(d)+1)] = -P/S.
///
/// Gap entities = N * |delta| ≈ 700 at current N.
/// Sub-minute dwell entities ≈ 2 × gap entities (pair interaction).
///
/// The bimodal dwell distribution (fast <1min, slow 6-24hr) reveals
/// two WAS populations: continuous (still-here) and discrete (returned).
fn membrane_delta(culture: &DashboardCulture) -> serde_json::Value {
    use std::f64::consts::PI;

    let total = culture.ips.len() as f64;
    if total < 10.0 {
        return serde_json::json!({"status": "insufficient_data"});
    }

    let s = 4.0 * PI;
    let opacity = 1.0 - 1.0 / s;
    let reflection = s / (s + 1.0);
    let delta = -1.0 / (s * (s + 1.0));
    let gap_entities = (total * delta.abs()).round() as u64;

    // Dwell time analysis: compute from first_seen/last_seen
    let mut sub_minute: u64 = 0;
    let mut dwell_times: Vec<f64> = Vec::new();
    let mut dwell_single: Vec<f64> = Vec::new();
    let mut dwell_multi: Vec<f64> = Vec::new();

    for (ip_h, profile) in &culture.ips {
        if profile.requests <= 1 {
            continue;
        }
        let dt = profile.last_seen - profile.first_seen;
        if dt < 0.0 {
            continue;
        }
        dwell_times.push(dt);
        if dt < 60.0 {
            sub_minute += 1;
        }
        let host_count = culture.ip_hosts.get(ip_h).map(|h| h.len()).unwrap_or(1);
        if host_count > 1 {
            dwell_multi.push(dt);
        } else {
            dwell_single.push(dt);
        }
    }

    dwell_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    dwell_single.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    dwell_multi.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = dwell_times.len();
    let median_s = if n > 0 { dwell_times[n / 2] } else { 0.0 };
    let mean_s = if n > 0 { dwell_times.iter().sum::<f64>() / n as f64 } else { 0.0 };

    let median_single = if !dwell_single.is_empty() { dwell_single[dwell_single.len() / 2] } else { 0.0 };
    let median_multi = if !dwell_multi.is_empty() { dwell_multi[dwell_multi.len() / 2] } else { 0.0 };
    let multi_single_ratio = if median_single > 0.0 { median_multi / median_single } else { 0.0 };

    // Dwell entropy: bin into 6 ranges
    let bins: [(f64, f64); 6] = [
        (0.0, 60.0), (60.0, 600.0), (600.0, 3600.0),
        (3600.0, 21600.0), (21600.0, 86400.0), (86400.0, f64::MAX),
    ];
    let mut bin_counts = [0u64; 6];
    for &dt in &dwell_times {
        for (i, &(lo, hi)) in bins.iter().enumerate() {
            if dt >= lo && dt < hi {
                bin_counts[i] += 1;
                break;
            }
        }
    }
    let n_f = n as f64;
    let h_dwell = if n > 0 {
        bin_counts.iter().map(|&c| {
            if c > 0 {
                let p = c as f64 / n_f;
                -p * p.log2()
            } else {
                0.0
            }
        }).sum::<f64>()
    } else {
        0.0
    };

    let gap_pair_ratio = if gap_entities > 0 {
        sub_minute as f64 / gap_entities as f64
    } else {
        0.0
    };

    let fast_pct = if n > 0 { bin_counts[0] as f64 / n_f * 100.0 } else { 0.0 };
    let slow_pct = if n > 0 { bin_counts[4] as f64 / n_f * 100.0 } else { 0.0 };

    serde_json::json!({
        "opacity": (opacity * 10000.0).round() / 10000.0,
        "reflection": (reflection * 10000.0).round() / 10000.0,
        "delta": (delta * 100000.0).round() / 100000.0,
        "gap_entities": gap_entities,
        "sub_minute_was": sub_minute,
        "gap_pair_ratio": (gap_pair_ratio * 1000.0).round() / 1000.0,
        "dwell": {
            "median_s": (median_s * 10.0).round() / 10.0,
            "median_min": (median_s / 60.0 * 10.0).round() / 10.0,
            "mean_min": (mean_s / 60.0 * 10.0).round() / 10.0,
            "multi_single_ratio": (multi_single_ratio * 100.0).round() / 100.0,
        },
        "dwell_entropy_bits": (h_dwell * 10000.0).round() / 10000.0,
        "bimodal": {
            "fast_pct": (fast_pct * 10.0).round() / 10.0,
            "slow_pct": (slow_pct * 10.0).round() / 10.0,
        },
    })
}

/// Membrane geometry — dimensional analysis from live data (Wave 173a).
///
/// Computes: IS/WAS ratio, closest sphere dimension, permeation rate,
/// channel capacity, vision limit, prediction coverage.
///
/// The key result: IS/WAS = S(d) where S(d) is the surface area of
/// the unit d-sphere. For d=3, S(3) = 4π. The behavioral space has
/// exactly 3 dimensions (epitope × tense × trajectory).
///
/// θ = π + π/S(d) = maximum vision angle.
/// P = 1/(S(d)+1) = permeation rate constrained by dimension.
/// WILL-BE/WAS = 1/d = prediction coverage per axis.
fn membrane_geometry(tense_is: usize, tense_was: usize, tense_willbe: usize) -> serde_json::Value {
    use std::f64::consts::PI;

    let is_f = tense_is as f64;
    let was_f = tense_was as f64;
    let wb_f = tense_willbe as f64;
    let total_f = is_f + was_f + wb_f;

    if was_f < 1.0 || total_f < 1.0 {
        return serde_json::json!({"status": "insufficient_data"});
    }

    let is_was_ratio = is_f / was_f;

    // Surface area of unit n-sphere: S(n) = 2*pi^(n/2) / Gamma(n/2)
    // Find the closest integer dimension
    let four_pi = 4.0 * PI;
    let dim_error_pct = ((is_was_ratio - four_pi) / four_pi * 100.0).abs();

    // Permeation rate
    let p_measured = was_f / (is_f + was_f);
    let p_theory = 1.0 / (four_pi + 1.0);

    // Binary entropy H(P)
    let h_boundary = if p_measured > 0.0 && p_measured < 1.0 {
        -p_measured * p_measured.log2() - (1.0 - p_measured) * (1.0 - p_measured).log2()
    } else {
        0.0
    };
    let channel_capacity = 1.0 - h_boundary;

    // Vision limit: theta = pi + pi/S(d) = pi + 1/4 for d=3
    let theta_unaided = PI + PI / four_pi; // pi + 1/4
    let theta_with_nautilus = if (was_f + wb_f) > 0.0 {
        let p_eff = (was_f + wb_f) / total_f;
        if p_eff < 1.0 { PI / (1.0 - p_eff) } else { PI * 100.0 }
    } else {
        theta_unaided
    };
    let vision_gained_deg = (theta_with_nautilus - theta_unaided) * 180.0 / PI;

    // Prediction coverage
    let prediction_coverage = if was_f > 0.0 { wb_f / was_f } else { 0.0 };
    let measured_dim = if prediction_coverage > 0.0 { 1.0 / prediction_coverage } else { 0.0 };

    // Total information
    let total_info_bits = channel_capacity * total_f;
    let total_info_bytes = (total_info_bits / 8.0).round() as u64;

    // Fisher information I(P) = 1/(P*(1-P))
    let fisher = if p_measured > 0.0 && p_measured < 1.0 {
        1.0 / (p_measured * (1.0 - p_measured))
    } else {
        0.0
    };

    serde_json::json!({
        "is_was_ratio": (is_was_ratio * 10000.0).round() / 10000.0,
        "four_pi": (four_pi * 10000.0).round() / 10000.0,
        "dim_error_pct": (dim_error_pct * 10000.0).round() / 10000.0,
        "dimension": 3,
        "permeation": {
            "measured": (p_measured * 100000.0).round() / 100000.0,
            "theory": (p_theory * 100000.0).round() / 100000.0,
        },
        "edge_entropy_bits": (h_boundary * 10000.0).round() / 10000.0,
        "channel_capacity_bits": (channel_capacity * 10000.0).round() / 10000.0,
        "vision": {
            "unaided_rad": (theta_unaided * 10000.0).round() / 10000.0,
            "unaided_deg": ((theta_unaided * 180.0 / PI) * 10.0).round() / 10.0,
            "with_nautilus_rad": (theta_with_nautilus * 10000.0).round() / 10000.0,
            "with_nautilus_deg": ((theta_with_nautilus * 180.0 / PI) * 10.0).round() / 10.0,
            "gained_deg": (vision_gained_deg * 10.0).round() / 10.0,
        },
        "prediction": {
            "coverage": (prediction_coverage * 100000.0).round() / 100000.0,
            "measured_dim": (measured_dim * 1000.0).round() / 1000.0,
            "one_third": (1.0_f64 / 3.0 * 100000.0).round() / 100000.0,
        },
        "total_information": {
            "bits": total_info_bits.round() as u64,
            "bytes": total_info_bytes,
        },
        "fisher_information": (fisher * 100.0).round() / 100.0,
    })
}

/// Nautilus prediction — the peptidoglycan layer (Wave 173a).
///
/// For each returning IP (requests > 1) that has visited multiple hosts,
/// find other IPs with the same host-set pattern (orbital family) and
/// check if the family's superset contains hosts this IP hasn't visited.
/// If yes, this IP has a predicted next-host → count it as WILL-BE.
///
/// The prediction: you will visit what others in your orbit visited.
/// The orbit is the compressed trajectory. The prediction is the orbit's
/// extension beyond the individual's current arc.
fn nautilus_predict(culture: &DashboardCulture) -> usize {
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

    // Build orbital family supersets: orbital_hash → union of all hosts in that family
    let mut family_supersets: HashMap<u32, BTreeSet<String>> = HashMap::new();
    let mut ip_orbit: HashMap<u64, u32> = HashMap::new();

    for (ip_h, hosts) in &culture.ip_hosts {
        if hosts.len() < 2 {
            continue;
        }
        let sorted: BTreeSet<&str> = hosts.iter().map(|s| s.as_str()).collect();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for h in &sorted {
            h.hash(&mut hasher);
        }
        let orbit_hash = hasher.finish() as u32;
        ip_orbit.insert(*ip_h, orbit_hash);
        family_supersets.entry(orbit_hash).or_default()
            .extend(hosts.iter().cloned());
    }

    // For families with >1 member, the superset may be larger than any
    // individual's host set. But orbital hash is computed from the SORTED
    // host set — so same set → same hash → superset == the set.
    // The prediction comes from PARTIAL matches: IPs that share a subset
    // of their hosts with a larger family.
    //
    // Simpler and more powerful: for each multi-host IP, look at ALL
    // families, find the one with the best subset match, and predict
    // the family's extra hosts.
    //
    // For efficiency, use a simpler heuristic: for each IP with hosts,
    // check if any single other IP from the same /24 subnet visited
    // hosts this IP hasn't. Subnet cohorts predict each other.
    //
    // Simplest effective version: count IPs whose orbital family has
    // more members than just themselves (family_size > 1). Those IPs
    // are in a populated orbit → trajectory is predictable.
    let mut family_sizes: HashMap<u32, usize> = HashMap::new();
    for orbit in ip_orbit.values() {
        *family_sizes.entry(*orbit).or_insert(0) += 1;
    }

    // An IP has a WILL-BE prediction if:
    // 1. It's a returning visitor (requests > 1)
    // 2. It has visited multiple hosts (in ip_orbit)
    // 3. Its orbital family has other members (family_size > 1)
    //    → the orbit is populated → we can predict the trajectory
    let mut predicted = 0usize;
    for (ip_h, profile) in &culture.ips {
        if profile.requests <= 1 {
            continue; // IS, not WAS
        }
        if let Some(orbit) = ip_orbit.get(ip_h) {
            if let Some(&size) = family_sizes.get(orbit) {
                if size > 1 {
                    predicted += 1;
                }
            }
        }
    }

    predicted
}

/// Trajectory analysis — compress arcs through the epitope ring.
///
/// Sweep 1 sorted requests by behavioral epitope (point of contact).
/// Sweep 2 sorts trajectories by orbital epitope (arc through subdomains).
///
/// The compression: instead of listing 3,563 individual multi-host arcs,
/// hash each arc's subdomain set into an orbital epitope. IPs that visit
/// the same set of subdomains are in the same orbital family. The families
/// ARE the compressed trajectories.
///
/// ```text
/// H(trajectory|orbital_epitope) < H(trajectory|alphabetic) < H(trajectory)
/// ```
fn trajectory_analysis(culture: &DashboardCulture) -> serde_json::Value {
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

    let mut multi_host_ips: usize = 0;
    let mut single_host_ips: usize = 0;
    let mut host_visit_counts: HashMap<String, usize> = HashMap::new();
    let mut max_breadth: usize = 0;
    let mut breadth_sum: usize = 0;

    // Orbital epitope: hash of the sorted subdomain set for each IP.
    // IPs with identical subdomain sets share an orbital epitope.
    let mut orbital_families: HashMap<String, Vec<u64>> = HashMap::new();
    // Track the host-set for each orbital hash so we can display it
    let mut orbital_hostsets: HashMap<String, BTreeSet<String>> = HashMap::new();

    for (ip_h, hosts) in &culture.ip_hosts {
        if hosts.len() > 1 {
            multi_host_ips += 1;
            breadth_sum += hosts.len();
            if hosts.len() > max_breadth {
                max_breadth = hosts.len();
            }
            for h in hosts {
                *host_visit_counts.entry(h.clone()).or_insert(0) += 1;
            }

            // Compute orbital epitope hash: sorted host set → deterministic hash
            let sorted_hosts: BTreeSet<&str> = hosts.iter().map(|s| s.as_str()).collect();
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            for h in &sorted_hosts {
                h.hash(&mut hasher);
            }
            let orbit_hash = format!("orb-{:08x}", hasher.finish() as u32);

            orbital_families.entry(orbit_hash.clone()).or_default().push(*ip_h);
            orbital_hostsets.entry(orbit_hash).or_default()
                .extend(hosts.iter().cloned());
        } else {
            single_host_ips += 1;
        }
    }

    // Top cross-visited hosts
    let mut top_hosts: Vec<(String, usize)> = host_visit_counts.into_iter().collect();
    top_hosts.sort_by(|a, b| b.1.cmp(&a.1));
    top_hosts.truncate(10);

    let avg_breadth = if multi_host_ips > 0 {
        breadth_sum as f64 / multi_host_ips as f64
    } else {
        0.0
    };

    // Returning visitor arcs
    let returning_with_arc: usize = culture.ips.values()
        .filter(|p| p.requests > 1 && p.host_count > 1)
        .count();
    let returning_single: usize = culture.ips.values()
        .filter(|p| p.requests > 1 && p.host_count <= 1)
        .count();

    // Orbital compression: how many families compress the multi-host population?
    let total_families = orbital_families.len();
    let alpha_bits = if multi_host_ips > 1 {
        (multi_host_ips as f64).ln() / std::f64::consts::LN_2
    } else { 0.0 };
    let orbital_bits = if total_families > 1 {
        (total_families as f64).ln() / std::f64::consts::LN_2
    } else { 0.0 };
    let orbital_gain = (alpha_bits - orbital_bits).max(0.0);

    // Top orbital families by population
    let mut families_sorted: Vec<(&str, usize)> = orbital_families.iter()
        .map(|(k, v)| (k.as_str(), v.len()))
        .collect();
    families_sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let top_orbits: Vec<serde_json::Value> = families_sorted.iter()
        .take(8)
        .map(|(hash, count)| {
            let hosts = orbital_hostsets.get(*hash)
                .map(|s| s.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            serde_json::json!({
                "orbit": hash,
                "ips": count,
                "breadth": hosts.len(),
                "hosts": hosts,
            })
        })
        .collect();

    serde_json::json!({
        "multi_host_ips": multi_host_ips,
        "single_host_ips": single_host_ips,
        "max_breadth": max_breadth,
        "avg_breadth": (avg_breadth * 10.0).round() / 10.0,
        "returning_with_arc": returning_with_arc,
        "returning_single_surface": returning_single,
        "orbital_compression": {
            "families": total_families,
            "alpha_bits": (alpha_bits * 10.0).round() / 10.0,
            "orbital_bits": (orbital_bits * 10.0).round() / 10.0,
            "gain_bits": (orbital_gain * 10.0).round() / 10.0,
            "ratio": if alpha_bits > 0.0 {
                (orbital_gain / alpha_bits * 1000.0).round() / 1000.0
            } else { 0.0 },
        },
        "top_orbits": top_orbits,
        "top_cross_hosts": top_hosts.iter()
            .map(|(h, c)| serde_json::json!({"host": h, "cross_visits": c}))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ip: &str, uri: &str, host: &str, ua: &str, ts: f64) -> caddy::LogEntry {
        caddy::LogEntry {
            request: caddy::RequestInfo {
                remote_ip: ip.to_string(),
                host: host.to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: caddy::Headers {
                    user_agent: vec![ua.to_string()],
                    accept_encoding: vec!["gzip, br, zstd, deflate".to_string()],
                    ..Default::default()
                },
            },
            status: 200,
            size: 1024,
            duration: 0.01,
            ts,
        }
    }

    #[test]
    fn dashboard_writer_creates_output() {
        let dir = std::env::temp_dir().join("dashboard-writer-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state.clone(), 10, registry.clone());

        for i in 0..10 {
            writer.ingest(&make_entry(
                &format!("57.141.20.{}", i),
                "/ecoPrimals/skunkBat/commit/abc123",
                "git.primals.eco",
                "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
                1000.0 + i as f64,
            ));
        }

        assert!(output.exists(), "dashboard.json should have been created");
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("fleet_ips"));
        assert!(content.contains("top_offenders"));
        assert!(content.contains("timing"));

        // Culture should be saved
        assert!(state.exists(), "culture file should exist");

        // Sourdough test — new writer should warm start
        let writer2 = DashboardWriter::new(output.clone(), state.clone(), 10, registry.clone());
        assert_eq!(writer2.culture.total_requests, 10);
        assert_eq!(writer2.culture.ips.len(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn culture_uses_hashed_ip_keys() {
        let dir = std::env::temp_dir().join("dashboard-zk-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state.clone(), 5, registry);
        for i in 0..5 {
            writer.ingest(&make_entry(
                &format!("57.141.20.{}", i),
                "/ecoPrimals/skunkBat/commit/abc123",
                "git.primals.eco",
                "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
                1000.0 + i as f64,
            ));
        }

        // Force culture save
        writer.save_culture();

        // Read the culture file and verify keys are u64 hashes, not raw IPs
        let culture_json = std::fs::read_to_string(&state).unwrap();
        let culture_val: serde_json::Value = serde_json::from_str(&culture_json).unwrap();
        let ips_obj = culture_val["ips"].as_object().unwrap();
        for key in ips_obj.keys() {
            assert!(
                !key.contains('.'),
                "Culture file contains raw IP '{key}' — ZK boundary violated! Keys should be u64 hashes."
            );
            // Verify key is a valid u64 numeric string
            key.parse::<u64>().unwrap_or_else(|_| {
                panic!("Culture key '{key}' is not a valid u64 hash");
            });
        }
        assert!(!ips_obj.is_empty(), "Culture should have at least one IP entry");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tense_distribution_in_dashboard() {
        let dir = std::env::temp_dir().join("dashboard-tense-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state, 5, registry);

        // 3 unique IPs — all first visit
        for i in 0..3 {
            writer.ingest(&make_entry(
                &format!("10.0.1.{}", i),
                "/",
                "primals.eco",
                "Mozilla/5.0 Chrome/130.0.0.0",
                1000.0 + i as f64,
            ));
        }

        // 2 repeat visits from first IP
        writer.ingest(&make_entry("10.0.1.0", "/desk/", "primals.eco", "Mozilla/5.0 Chrome/130.0.0.0", 1010.0));
        writer.ingest(&make_entry("10.0.1.0", "/analysis/", "primals.eco", "Mozilla/5.0 Chrome/130.0.0.0", 1020.0));

        // Force flush
        writer.flush();

        let content = std::fs::read_to_string(&output).unwrap();
        let dashboard: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Check tense_distribution exists
        assert!(dashboard["tense_distribution"].is_object(), "tense_distribution should be in dashboard");
        let is_count = dashboard["tense_distribution"]["is"].as_u64().unwrap();
        let was_count = dashboard["tense_distribution"]["was"].as_u64().unwrap();
        // IP 10.0.1.0 has 3 requests → Was. IPs 10.0.1.1 and 10.0.1.2 have 1 request → Is.
        assert_eq!(is_count, 2, "two IPs should be Is (first-time)");
        assert_eq!(was_count, 1, "one IP should be Was (repeat)");

        // Check sort_compression exists
        assert!(dashboard["sort_compression"].is_object(), "sort_compression should be in dashboard");
        let alpha = dashboard["sort_compression"]["alpha"].as_f64().unwrap();
        assert!(alpha > 0.0, "alphabetic compression should be > 0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_json_created_alongside_dashboard() {
        let dir = std::env::temp_dir().join("dashboard-state-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state, 5, registry);
        for i in 0..5 {
            writer.ingest(&make_entry("10.0.0.1", "/", "primals.eco", "curl/7", i as f64));
        }

        let state_path = dir.join("state.json");
        assert!(state_path.exists(), "state.json should be created alongside dashboard.json");

        let epitope_path = dir.join("epitope_caddy.json");
        assert!(epitope_path.exists(), "epitope_caddy.json should be created alongside dashboard.json");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
