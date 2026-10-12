// Tests for scatter_server — extracted for file size discipline.
// Included via `#[cfg(test)] #[path = "scatter_server_tests.rs"] mod tests;`

use super::*;
use crate::scatter_mirror::encode_zwc;

#[test]
fn deterministic_scatter() {
    let sg = ScatterGenerator::new(42);
    let (ct1, body1) = sg.generate("/org/repo/commit/abc123");
    let (ct2, body2) = sg.generate("/org/repo/commit/abc123");
    assert_eq!(ct1, ct2);
    assert_eq!(body1, body2);
}

#[test]
fn different_paths_different_poison() {
    let sg = ScatterGenerator::new(42);
    let (_, body1) = sg.generate("/org/repo/commit/abc123");
    let (_, body2) = sg.generate("/org/repo/commit/def456");
    assert_ne!(body1, body2);
}

#[test]
fn no_real_names_leak() {
    let sg = ScatterGenerator::new(42);
    for path in [
        "/org/repo/commit/abc",
        "/org/repo/src/branch/main/lib.rs",
        "/org/repo/issues/1",
        "/org/repo/wiki/page",
        "/org/repo/releases/tag/v1",
        "/org/repo",
    ] {
        let (_, body) = sg.generate(path);
        assert!(!body.contains("ecoPrimal"), "leaked in {path}");
        assert!(!body.contains("skunkBat"), "leaked in {path}");
        assert!(!body.contains("swarmVine"), "leaked in {path}");
        assert!(!body.contains("primals"), "leaked in {path}");
        assert!(!body.contains("wateringHole"), "leaked in {path}");
    }
}

#[test]
fn poison_ratio_deterministic() {
    let hash1 = path_deterministic_hash("/test/path", 42);
    let hash2 = path_deterministic_hash("/test/path", 42);
    assert_eq!(hash1, hash2);

    let hash3 = path_deterministic_hash("/other/path", 42);
    assert_ne!(hash1, hash3);
}

#[test]
fn commit_page_looks_like_gitea() {
    // Use generate_with_grid to ensure Normal jitter (bypasses BingoCube jitter)
    use crate::cube_oracle::{CubeDecisionGrid, JitterType};
    let sg = ScatterGenerator::new(42);
    // Find a grid that gives Normal jitter for this path
    let mut found = false;
    for epoch in 0..100u64 {
        let grid = CubeDecisionGrid::from_context("test", "/org/repo/commit/abc123def456", epoch);
        if grid.jitter_type() == JitterType::Normal {
            let (ct, body) = sg.generate_with_grid("/org/repo/commit/abc123def456", Some(&grid));
            assert_eq!(ct, "text/html; charset=utf-8");
            assert!(body.contains("diff"), "commit body missing 'diff' at epoch {epoch}");
            assert!(body.contains("chroma"), "commit body missing 'chroma' at epoch {epoch}");
            assert!(body.contains("commit-summary"), "commit body missing 'commit-summary' at epoch {epoch}");
            found = true;
            break;
        }
    }
    assert!(found, "should find a Normal jitter epoch within 100 tries");
}

#[test]
fn file_page_has_code() {
    use crate::cube_oracle::{CubeDecisionGrid, JitterType};
    let sg = ScatterGenerator::new(42);
    let mut found = false;
    for epoch in 0..100u64 {
        let grid = CubeDecisionGrid::from_context("test", "/org/repo/src/branch/main/lib.rs", epoch);
        if grid.jitter_type() == JitterType::Normal {
            let (_, body) = sg.generate_with_grid("/org/repo/src/branch/main/lib.rs", Some(&grid));
            assert!(body.contains("file-view"), "file body missing 'file-view' at epoch {epoch}");
            assert!(body.contains("<code>"), "file body missing '<code>' at epoch {epoch}");
            found = true;
            break;
        }
    }
    assert!(found, "should find a Normal jitter epoch within 100 tries");
}

#[test]
fn wiki_page_has_content() {
    use crate::cube_oracle::{CubeDecisionGrid, JitterType};
    let sg = ScatterGenerator::new(42);
    let mut found = false;
    for epoch in 0..100u64 {
        let grid = CubeDecisionGrid::from_context("test", "/org/repo/wiki/setup", epoch);
        if grid.jitter_type() == JitterType::Normal {
            let (_, body) = sg.generate_with_grid("/org/repo/wiki/setup", Some(&grid));
            assert!(body.contains("wiki-view"), "wiki body missing 'wiki-view' at epoch {epoch}");
            assert!(body.contains("Configuration"), "wiki body missing 'Configuration' at epoch {epoch}");
            found = true;
            break;
        }
    }
    assert!(found, "should find a Normal jitter epoch within 100 tries");
}

#[test]
fn release_page_has_changelog() {
    use crate::cube_oracle::{CubeDecisionGrid, JitterType};
    let sg = ScatterGenerator::new(42);
    let mut found = false;
    for epoch in 0..100u64 {
        let grid = CubeDecisionGrid::from_context("test", "/org/repo/releases/tag/v1.0.0", epoch);
        if grid.jitter_type() == JitterType::Normal {
            let (_, body) = sg.generate_with_grid("/org/repo/releases/tag/v1.0.0", Some(&grid));
            assert!(body.contains("release-view"), "release body missing 'release-view' at epoch {epoch}");
            assert!(body.contains("Changelog"), "release body missing 'Changelog' at epoch {epoch}");
            found = true;
            break;
        }
    }
    assert!(found, "should find a Normal jitter epoch within 100 tries");
}

#[test]
fn shared_confidence_effective_ratio() {
    let conf = SharedConfidence::new();
    let base = 0.3;

    // No confidence -> base ratio
    assert!((conf.effective_ratio(base) - 0.3).abs() < 0.01);

    // Half confidence -> midpoint between base and max (0.8)
    conf.update(0.5);
    let r = conf.effective_ratio(base);
    assert!(r > 0.5 && r < 0.6, "expected ~0.55, got {r}");

    // Full confidence -> max ratio (0.8)
    conf.update(1.0);
    let r = conf.effective_ratio(base);
    assert!((r - 0.8).abs() < 0.01, "expected 0.8, got {r}");
}

#[test]
fn hash_distribution_uniform_for_fleet_paths() {
    let seed = 0xdead_beef_cafe_babe_u64;
    let ratio = 0.42_f32;
    let mut poison = 0;
    let total = 1000;

    for i in 0..total {
        let path = format!(
            "/ecoPrimals/wateringHole/src/commit/{:040x}/handlers/main.rs",
            i * 0x1234_5678_9abc_def0_u128
        );
        let h = path_deterministic_hash(&path, seed);
        if (h % 100) < (ratio * 100.0) as u64 {
            poison += 1;
        }
    }

    let pct = poison as f64 / total as f64;
    assert!(
        pct > 0.32 && pct < 0.52,
        "poison ratio {:.1}% should be near 42% (was {})",
        pct * 100.0,
        poison
    );
}

#[test]
fn disperse_deterministic() {
    let sg = ScatterGenerator::new(42);
    let (ct1, body1) = sg.generate_disperse("/org/repo/commit/abc123");
    let (ct2, body2) = sg.generate_disperse("/org/repo/commit/abc123");
    assert_eq!(ct1, ct2);
    assert_eq!(body1, body2);
}

#[test]
fn disperse_different_from_scatter() {
    let sg = ScatterGenerator::new(42);
    let (_, scatter_body) = sg.generate("/org/repo/commit/abc123");
    let (_, disperse_body) = sg.generate_disperse("/org/repo/commit/abc123");
    assert_ne!(scatter_body, disperse_body);
}

#[test]
fn disperse_no_real_names_leak() {
    let sg = ScatterGenerator::new(42);
    for i in 0..20 {
        let path = format!("/org/repo/commit/{:040x}", i);
        let (_, body) = sg.generate_disperse(&path);
        assert!(!body.contains("ecoPrimal"), "leaked ecoPrimal in disperse variant");
        assert!(!body.contains("skunkBat"), "leaked skunkBat in disperse variant");
        assert!(!body.contains("wateringHole"), "leaked wateringHole in disperse variant");
    }
}

// -- Signal Mirror tests --

#[test]
fn amplify_inflates_response() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let base_len = base.len();
    let mut rng = XorShift64::new(12345);
    let amplified = sg.amplify(&mut rng, base);
    assert!(
        amplified.len() > base_len * 2,
        "amplified ({}) should be >2x base ({})",
        amplified.len(),
        base_len
    );
    assert!(amplified.contains("repository-file-list"));
    assert!(amplified.contains("repository-commits"));
    assert!(amplified.contains("contributors"));
    assert!(amplified.contains("</body>"));
}

#[test]
fn amplify_deterministic() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let mut rng1 = XorShift64::new(12345);
    let mut rng2 = XorShift64::new(12345);
    let a1 = sg.amplify(&mut rng1, base.clone());
    let a2 = sg.amplify(&mut rng2, base);
    assert_eq!(a1, a2);
}

#[test]
fn amplify_no_real_names() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let mut rng = XorShift64::new(99);
    let amplified = sg.amplify(&mut rng, base);
    assert!(!amplified.contains("whitePaper"));
    assert!(!amplified.contains("sporePrint"));
    assert!(!amplified.contains("siltPond"));
}

#[test]
fn crawl_links_injected() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let mut rng = XorShift64::new(777);
    let with_links = sg.inject_crawl_links(&mut rng, &base);
    assert!(with_links.len() > base.len());
    assert!(with_links.contains("related"));
    let link_count = with_links.matches("<a href=\"/").count();
    assert!(link_count >= 15, "expected >=15 links, got {link_count}");
}

#[test]
fn canary_embedded() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let marked = sg.embed_canary(&base, "49e77ea75aa7666e");
    assert!(marked.contains("m-49e77ea75aa7666e"));
    assert!(marked.contains("c-49e77ea7"));
    assert!(marked.contains("sr-only"));
    assert!(marked.contains('\u{200B}') || marked.contains('\u{200C}'));
}

#[test]
fn canary_deterministic_within_hour() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let m1 = sg.embed_canary(&base, "abcdef0123456789");
    let m2 = sg.embed_canary(&base, "abcdef0123456789");
    assert_eq!(m1, m2);
}

#[test]
fn canary_different_per_hash() {
    let sg = ScatterGenerator::new(42);
    let (_, base) = sg.generate("/org/repo/commit/abc123");
    let m1 = sg.embed_canary(&base, "aaaa000011112222");
    let m2 = sg.embed_canary(&base, "bbbb333344445555");
    assert_ne!(m1, m2);
}

#[test]
fn zwc_encode_roundtrip() {
    let encoded = encode_zwc("deadbeef");
    assert!(encoded.starts_with('\u{FEFF}'));
    assert!(encoded.ends_with('\u{FEFF}'));
    assert!(encoded.len() > 10);
}

#[test]
fn shared_confidence_clamps() {
    let conf = SharedConfidence::new();
    conf.update(5.0); // over 1.0
    assert!((conf.read() - 1.0).abs() < 0.01);

    conf.update(-1.0); // under 0.0
    assert!(conf.read() < 0.01);
}

// -- Back Pressure tests --

#[test]
fn back_pressure_starts_low() {
    let bp = BackPressure::new(60);
    let p = bp.read();
    assert!(p < 0.2, "fresh back pressure should be low, got {p}");
}

#[test]
fn back_pressure_rises_with_requests() {
    let bp = BackPressure::new(60);
    // Slam 1000 requests instantly — should raise pressure
    for _ in 0..1000 {
        bp.record_request();
    }
    let p = bp.read();
    assert!(p > 0.5, "after 1000 instant requests, pressure should be high, got {p}");
}

#[test]
fn back_pressure_epoch_minutes_range() {
    let bp = BackPressure::new(60);
    // At low pressure: should be near 30
    let low = bp.epoch_minutes();
    assert!(low >= 25, "low-pressure epoch should be ~30 min, got {low}");

    // After heavy load: epoch should shrink
    for _ in 0..5000 {
        bp.record_request();
    }
    let high = bp.epoch_minutes();
    assert!(high <= 15, "high-pressure epoch should be <=15 min, got {high}");
}

#[test]
fn back_pressure_cross_link_count_range() {
    let bp = BackPressure::new(60);
    let low = bp.cross_link_count();
    assert!(low <= 3, "low-pressure cross-links should be <=3, got {low}");

    for _ in 0..5000 {
        bp.record_request();
    }
    let high = bp.cross_link_count();
    assert!(high >= 5, "high-pressure cross-links should be >=5, got {high}");
}

#[test]
fn back_pressure_chimera_factor_bounded() {
    let bp = BackPressure::new(60);
    let f = bp.chimera_factor();
    assert!(f >= 0.0 && f <= 1.0, "chimera factor must be 0-1, got {f}");
}

#[test]
fn pressure_temporal_phase_more_volatile_under_load() {
    let bp = BackPressure::new(60);
    let seed = 0xDEAD_BEEF;

    // Count phases at low pressure
    let mut low_unstable = 0;
    for i in 0..100 {
        let path = format!("/test/path/{i}");
        let phase = pressure_temporal_phase(&path, seed, &bp);
        if phase >= 2 { low_unstable += 1; }
    }

    // Slam requests
    for _ in 0..5000 {
        bp.record_request();
    }

    // Count phases at high pressure
    let mut high_unstable = 0;
    for i in 0..100 {
        let path = format!("/test/path/{i}");
        let phase = pressure_temporal_phase(&path, seed, &bp);
        if phase >= 2 { high_unstable += 1; }
    }

    assert!(
        high_unstable >= low_unstable,
        "high pressure should produce at least as many unstable phases: low={low_unstable}, high={high_unstable}"
    );
}

// -- Layer 1: Tarpit tests --

#[test]
fn tarpit_acquire_and_release() {
    let tp = TarpitState::new(2);
    assert!(tp.try_acquire());
    assert!(tp.try_acquire());
    assert!(!tp.try_acquire()); // at capacity
    assert_eq!(tp.active_count(), 2);

    tp.release();
    assert_eq!(tp.active_count(), 1);
    assert!(tp.try_acquire()); // slot freed
}

#[test]
fn tarpit_zero_max_rejects_all() {
    let tp = TarpitState::new(0);
    assert!(!tp.try_acquire());
}

// -- Layer 2: Honeytoken tests --

#[test]
fn honeytoken_path_detection() {
    assert!(is_honeytoken_path("/.env"));
    assert!(is_honeytoken_path("/.env.local"));
    assert!(is_honeytoken_path("/wp-config.php"));
    assert!(is_honeytoken_path("/.git/config"));
    assert!(is_honeytoken_path("/api/v1/keys"));
    assert!(is_honeytoken_path("/.aws/credentials"));
    assert!(is_honeytoken_path("/config/database.yml"));
    assert!(is_honeytoken_path("/.env?cachebust=1"));

    assert!(!is_honeytoken_path("/"));
    assert!(!is_honeytoken_path("/org/repo/commit/abc"));
    assert!(!is_honeytoken_path("/robots.txt"));
}

#[test]
fn honeytoken_env_has_aws_keys() {
    let sg = ScatterGenerator::new(42);
    let (ct, body) = sg.generate_honeytoken("/.env");
    assert_eq!(ct, "text/plain; charset=utf-8");
    assert!(body.contains("AKIA"), "should contain AWS key prefix");
    assert!(body.contains("AWS_SECRET_ACCESS_KEY="));
    assert!(body.contains("STRIPE_SECRET_KEY=sk_live_"));
    assert!(body.contains("GITHUB_TOKEN=ghp_"));
    assert!(body.contains("DATABASE_URL=postgres://"));
}

#[test]
fn honeytoken_env_deterministic() {
    let sg = ScatterGenerator::new(42);
    let (_, body1) = sg.generate_honeytoken("/.env");
    let (_, body2) = sg.generate_honeytoken("/.env");
    assert_eq!(body1, body2);
}

#[test]
fn honeytoken_env_different_seeds() {
    let sg1 = ScatterGenerator::new(42);
    let sg2 = ScatterGenerator::new(99);
    let (_, body1) = sg1.generate_honeytoken("/.env");
    let (_, body2) = sg2.generate_honeytoken("/.env");
    assert_ne!(body1, body2);
}

#[test]
fn honeytoken_wp_config() {
    let sg = ScatterGenerator::new(42);
    let (ct, body) = sg.generate_honeytoken("/wp-config.php");
    assert!(ct.contains("php"));
    assert!(body.contains("DB_PASSWORD"));
    assert!(body.contains("AUTH_KEY"));
    assert!(body.contains("wordpress_prod"));
}

#[test]
fn honeytoken_git_config() {
    let sg = ScatterGenerator::new(42);
    let (_, body) = sg.generate_honeytoken("/.git/config");
    assert!(body.contains("[remote \"origin\"]"));
    assert!(body.contains("github.com"));
    assert!(body.contains("@"));
}

#[test]
fn honeytoken_aws_credentials() {
    let sg = ScatterGenerator::new(42);
    let (_, body) = sg.generate_honeytoken("/.aws/credentials");
    assert!(body.contains("AKIA"));
    assert!(body.contains("[default]"));
    assert!(body.contains("[production]"));
}

#[test]
fn honeytoken_api_keys_json() {
    let sg = ScatterGenerator::new(42);
    let (ct, body) = sg.generate_honeytoken("/api/v1/keys");
    assert!(ct.contains("json"));
    assert!(body.contains("sk_prod_"));
    assert!(body.contains("sk_stg_"));
}

#[test]
fn honeytoken_database_yml() {
    let sg = ScatterGenerator::new(42);
    let (ct, body) = sg.generate_honeytoken("/config/database.yml");
    assert!(ct.contains("yaml"));
    assert!(body.contains("production:"));
    assert!(body.contains("password:"));
    assert!(body.contains("postgresql"));
}

#[test]
fn honeytoken_no_real_data_leaked() {
    let sg = ScatterGenerator::new(42);
    for path in HONEYTOKEN_PATHS {
        let (_, body) = sg.generate_honeytoken(path);
        assert!(!body.contains("ecoPrimal"), "leaked ecoPrimal in {path}");
        assert!(!body.contains("primals.eco"), "leaked primals.eco in {path}");
        assert!(!body.contains("skunkBat"), "leaked skunkBat in {path}");
        assert!(!body.contains("golgiBody"), "leaked golgiBody in {path}");
    }
}

#[test]
fn xorshift_alphanum_len() {
    let mut rng = XorShift64::new(42);
    assert_eq!(rng.alphanum(16).len(), 16);
    assert_eq!(rng.upper_alphanum(20).len(), 20);
    assert_eq!(rng.base64ish(40).len(), 40);
}

// -- Violation Mirror tests --

fn test_tag() -> CachedTag {
    CachedTag {
        confidence: 0.75,
        detectors: vec![
            "content_gate".to_string(),
            "stealth_ua".to_string(),
            "ip_rotation".to_string(),
        ],
        match_count: 47,
        gate_count: 2,
        last_refreshed: 1000,
    }
}

#[test]
fn mirror_commit_contains_violation_data() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng = XorShift64::new(99);
    let (ct, body) = generate_violation_mirror(&sg, &mut rng, "/org/repo/commit/abc123", &tag, "deadbeef12345678");
    assert_eq!(ct, "text/html; charset=utf-8");
    assert!(body.contains("deadbeef"), "should contain fleet hash");
    assert!(body.contains("75%") || body.contains("75"), "should contain confidence");
    assert!(body.contains("content_gate"), "should contain detector name");
    assert!(body.contains("stealth_ua"), "should contain detector name");
    assert!(body.contains("47"), "should contain match count");
}

#[test]
fn mirror_code_contains_classifier() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng = XorShift64::new(99);
    let (_, body) = generate_violation_mirror(&sg, &mut rng, "/org/repo/src/branch/main/lib.rs", &tag, "aabb112233445566");
    assert!(body.contains("BehavioralClassifier"), "should contain classifier code");
    assert!(body.contains("content_gate"), "should contain detector in code");
    assert!(body.contains("ip_rotation"), "should contain detector in code");
}

#[test]
fn mirror_issue_contains_compliance() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng = XorShift64::new(99);
    let (_, body) = generate_violation_mirror(&sg, &mut rng, "/org/repo/issues/42", &tag, "1122334455667788");
    assert!(body.contains("Violation Summary"), "should have violation summary");
    assert!(body.contains("robots.txt"), "should reference robots.txt");
    assert!(body.contains("CFAA"), "should reference legal framework");
    assert!(body.contains("11223344"), "should contain hash short");
}

#[test]
fn mirror_audit_contains_metrics() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng = XorShift64::new(99);
    let (_, body) = generate_violation_mirror(&sg, &mut rng, "/org/repo/wiki/audit", &tag, "ffeeddcc00112233");
    assert!(body.contains("Behavioral Audit Report"), "should have audit title");
    assert!(body.contains("confidence"), "should mention confidence");
    assert!(body.contains("ffeeddcc"), "should contain hash");
}

#[test]
fn mirror_dashboard_has_monitoring() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng = XorShift64::new(99);
    let (_, body) = generate_violation_mirror(&sg, &mut rng, "/org/repo", &tag, "0011223344556677");
    assert!(body.contains("observations"), "should show observation count");
    assert!(body.contains("detectors active"), "should show detector count");
    assert!(body.contains("00112233"), "should contain hash");
}

#[test]
fn mirror_deterministic() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    let mut rng1 = XorShift64::new(99);
    let mut rng2 = XorShift64::new(99);
    let (_, body1) = generate_violation_mirror(&sg, &mut rng1, "/org/repo/commit/abc", &tag, "deadbeef12345678");
    let (_, body2) = generate_violation_mirror(&sg, &mut rng2, "/org/repo/commit/abc", &tag, "deadbeef12345678");
    assert_eq!(body1, body2);
}

#[test]
fn mirror_no_real_names_leak() {
    let sg = ScatterGenerator::new(42);
    let tag = test_tag();
    for path in [
        "/org/repo/commit/abc",
        "/org/repo/src/branch/main/lib.rs",
        "/org/repo/issues/1",
        "/org/repo/wiki/page",
        "/org/repo",
    ] {
        let mut rng = XorShift64::new(12345);
        let (_, body) = generate_violation_mirror(&sg, &mut rng, path, &tag, "aaaa111122223333");
        assert!(!body.contains("ecoPrimal"), "leaked ecoPrimal in mirror {path}");
        assert!(!body.contains("skunkBat"), "leaked skunkBat in mirror {path}");
        assert!(!body.contains("swarmVine"), "leaked swarmVine in mirror {path}");
        assert!(!body.contains("primals"), "leaked primals in mirror {path}");
        assert!(!body.contains("wateringHole"), "leaked wateringHole in mirror {path}");
        assert!(!body.contains("skunky"), "leaked skunky in mirror {path}");
        assert!(!body.contains("golgi"), "leaked golgi in mirror {path}");
    }
}

#[test]
fn mirror_scales_with_detectors() {
    let sg = ScatterGenerator::new(42);
    let small_tag = CachedTag {
        confidence: 0.5,
        detectors: vec!["content_gate".to_string()],
        match_count: 3,
        gate_count: 1,
        last_refreshed: 1000,
    };
    let big_tag = CachedTag {
        confidence: 1.0,
        detectors: vec![
            "content_gate".to_string(),
            "stealth_ua".to_string(),
            "ip_rotation".to_string(),
            "encoding_uniform".to_string(),
            "ignores_rejection".to_string(),
            "narrow_ua_pool".to_string(),
        ],
        match_count: 500,
        gate_count: 4,
        last_refreshed: 1000,
    };
    let mut rng1 = XorShift64::new(42);
    let mut rng2 = XorShift64::new(42);
    let (_, body_small) = generate_violation_mirror(&sg, &mut rng1, "/org/repo/src/branch/main/lib.rs", &small_tag, "aaaa111122223333");
    let (_, body_big) = generate_violation_mirror(&sg, &mut rng2, "/org/repo/src/branch/main/lib.rs", &big_tag, "aaaa111122223333");
    // More detectors = more code in the classifier = bigger response
    assert!(body_big.len() > body_small.len(),
        "big tag ({} bytes) should produce larger mirror than small tag ({} bytes)",
        body_big.len(), body_small.len()
    );
}
