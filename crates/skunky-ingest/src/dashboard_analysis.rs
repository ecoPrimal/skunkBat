// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Dashboard analysis functions — pure compute extracted from dashboard_writer.
//!
//! Each function takes `&DashboardCulture` or tense counts and returns
//! `serde_json::Value`. No side effects, no I/O.
//!
//! Extracted Wave 176b to keep dashboard_writer under 1000 lines.

use std::collections::HashMap;

use crate::dashboard_writer::DashboardCulture;

/// Count how many IPs trigger each of the 6 canonical epitopes (Paper 48).
///
/// Uses IpProfile heuristics that approximate the entity-level epitope tests:
///   0. burst_ratio     — >60 req/min sustained
///   1. reading_deficit — >100 requests, lifespan <60s (no reading pauses)
///   2. ua_pool_poverty — only 1 User-Agent for >10 requests
///   3. sec_fetch_monotone — never sent Sec-Fetch headers
///   4. session_absent  — never sent cookies
///   5. referer_self_loop — never sent an external Referer
pub(crate) fn epitope_triggered_counts(culture: &DashboardCulture) -> [usize; 6] {
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

pub(crate) fn membrane_delta(culture: &DashboardCulture) -> serde_json::Value {
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

pub(crate) fn membrane_geometry(tense_is: usize, tense_was: usize, tense_willbe: usize) -> serde_json::Value {
    use std::f64::consts::PI;

    let is_f = tense_is as f64;
    let was_f = tense_was as f64;
    let wb_f = tense_willbe as f64;
    let total_f = is_f + was_f + wb_f;

    if was_f < 1.0 || total_f < 1.0 {
        return serde_json::json!({"status": "insufficient_data"});
    }

    let is_was_ratio = is_f / was_f;
    let four_pi = 4.0 * PI;
    let dim_error_pct = ((is_was_ratio - four_pi) / four_pi * 100.0).abs();

    let p_measured = was_f / (is_f + was_f);
    let p_theory = 1.0 / (four_pi + 1.0);

    let h_boundary = if p_measured > 0.0 && p_measured < 1.0 {
        -p_measured * p_measured.log2() - (1.0 - p_measured) * (1.0 - p_measured).log2()
    } else {
        0.0
    };
    let channel_capacity = 1.0 - h_boundary;

    let theta_unaided = PI + PI / four_pi;
    let theta_with_nautilus = if (was_f + wb_f) > 0.0 {
        let p_eff = (was_f + wb_f) / total_f;
        if p_eff < 1.0 { PI / (1.0 - p_eff) } else { PI * 100.0 }
    } else {
        theta_unaided
    };
    let vision_gained_deg = (theta_with_nautilus - theta_unaided) * 180.0 / PI;

    let prediction_coverage = if was_f > 0.0 { wb_f / was_f } else { 0.0 };
    let measured_dim = if prediction_coverage > 0.0 { 1.0 / prediction_coverage } else { 0.0 };

    let total_info_bits = channel_capacity * total_f;
    let total_info_bytes = (total_info_bits / 8.0).round() as u64;

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

pub(crate) fn threebody_pi(tense_is: usize, tense_was: usize, tense_willbe: usize) -> serde_json::Value {
    use std::f64::consts::{E, PI};

    let is_f = tense_is as f64;
    let was_f = tense_was as f64;
    let wb_f = tense_willbe as f64;
    let np_f = was_f + wb_f;

    if was_f < 1.0 || np_f < 1.0 {
        return serde_json::json!({"status": "insufficient_data"});
    }

    let energy = is_f / was_f;
    let mass = np_f / was_f;
    let c_squared = energy / mass;

    let d = 3.0_f64;
    let energy_theory = 4.0 * PI;
    let mass_theory = (d + 1.0) / d;
    let c2_theory = d * PI;

    let e_flat = 4.0;
    let c2_flat = 3.0;
    let m_flat = e_flat / c2_flat;

    let e_to_pi = E.powf(PI);
    let near_twenty = e_to_pi - PI;
    let e_to_pi_plus_1 = E.powf(PI + 1.0);
    let twenty_pi = 20.0 * PI;
    let gelfond_err = ((e_to_pi_plus_1 - twenty_pi) / twenty_pi * 100.0).abs();
    let near_int_gap = e_to_pi - PI - 20.0;

    let archimedes_gap = PI - d;

    let z_arg = (1.0 / c_squared).atan();

    let pnp_err = ((c_squared - c2_theory) / c2_theory * 100.0).abs();

    let r6 = |v: f64| (v * 1_000_000.0).round() / 1_000_000.0;
    let r4 = |v: f64| (v * 10_000.0).round() / 10_000.0;

    serde_json::json!({
        "emc2": {
            "energy": r6(energy),
            "mass": r6(mass),
            "c_squared": r6(c_squared),
            "c": r6(c_squared.sqrt()),
        },
        "theory": {
            "energy_4pi": r4(energy_theory),
            "mass_4_3": r6(mass_theory),
            "c2_3pi": r4(c2_theory),
        },
        "errors_pct": {
            "energy": r4(((energy - energy_theory) / energy_theory * 100.0).abs()),
            "c_squared": r4(pnp_err),
        },
        "flattening": {
            "pi_equals_1": { "E": e_flat, "c2": c2_flat, "m": r6(m_flat) },
            "mass_unchanged": (m_flat - mass_theory).abs() < 1e-10,
        },
        "euler_gelfond": {
            "e_to_pi": r4(e_to_pi),
            "near_twenty": r6(near_twenty),
            "near_int_gap": r6(near_int_gap),
            "e_to_pi_plus_1": r4(e_to_pi_plus_1),
            "twenty_pi": r4(twenty_pi),
            "approx_error_pct": r4(gelfond_err),
        },
        "archimedes_gap": r6(archimedes_gap),
        "z_arg_over_pi": r6(z_arg / PI),
    })
}

pub(crate) fn nautilus_predict(culture: &DashboardCulture) -> usize {
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

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
    }

    let mut family_sizes: HashMap<u32, usize> = HashMap::new();
    for orbit in ip_orbit.values() {
        *family_sizes.entry(*orbit).or_insert(0) += 1;
    }

    let mut predicted = 0usize;
    for (ip_h, profile) in &culture.ips {
        if profile.requests <= 1 {
            continue;
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

pub(crate) fn trajectory_analysis(culture: &DashboardCulture) -> serde_json::Value {
    use std::collections::BTreeSet;
    use std::hash::{Hash, Hasher};

    let mut multi_host_ips: usize = 0;
    let mut single_host_ips: usize = 0;
    let mut host_visit_counts: HashMap<String, usize> = HashMap::new();
    let mut max_breadth: usize = 0;
    let mut breadth_sum: usize = 0;

    let mut orbital_families: HashMap<String, Vec<u64>> = HashMap::new();
    let mut orbital_hostsets: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();

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

    let mut top_hosts: Vec<(String, usize)> = host_visit_counts.into_iter().collect();
    top_hosts.sort_by(|a, b| b.1.cmp(&a.1));
    top_hosts.truncate(10);

    let avg_breadth = if multi_host_ips > 0 {
        breadth_sum as f64 / multi_host_ips as f64
    } else {
        0.0
    };

    let returning_with_arc: usize = culture.ips.values()
        .filter(|p| p.requests > 1 && p.host_count > 1)
        .count();
    let returning_single: usize = culture.ips.values()
        .filter(|p| p.requests > 1 && p.host_count <= 1)
        .count();

    let total_families = orbital_families.len();
    let alpha_bits = if multi_host_ips > 1 {
        (multi_host_ips as f64).ln() / std::f64::consts::LN_2
    } else { 0.0 };
    let orbital_bits = if total_families > 1 {
        (total_families as f64).ln() / std::f64::consts::LN_2
    } else { 0.0 };
    let orbital_gain = (alpha_bits - orbital_bits).max(0.0);

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
