// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content generator — fabricates plausible-but-poisoned HTML, credentials,
//! and metadata for the opsonization scatter server.
//!
//! Adapted from skunk-bat-core defense scatter; inlined here to avoid pulling
//! skunk-bat-core as a dependency.

#![allow(missing_docs)]

use skunky_ingest::cube_oracle::{CubeDecisionGrid, ContentVariant, JitterType};
use crate::scatter_constants::{
    BLAME_LICENSES, COMPLIANCE_NOTICES, GHOST_AUTHORS, GHOST_DOMAINS,
    HIGH_VALUE_AUTHORS, HONEYCOMB_SURFACES,
};
use crate::scatter_mirror::{encode_zwc, path_deterministic_hash};
use crate::scatter_rng::XorShift64;

// Inline ScatterGenerator — adapted from skunk-bat-core/src/defense/scatter.rs
// Inlined to avoid pulling skunk-bat-core as a dependency
// ══════════════════════════════════════════════════════════════════════

/// Scatter content generator.
pub(crate) struct ScatterGenerator {
    pub(crate) seed: u64,
    pub(crate) repo_names: &'static [&'static str],
    pub(crate) file_extensions: &'static [&'static str],
    pub(crate) commit_verbs: &'static [&'static str],
    pub(crate) commit_nouns: &'static [&'static str],
}

static REPO_NAMES: &[&str] = &[
    "core-utils", "data-pipeline", "web-frontend", "api-gateway",
    "auth-service", "config-manager", "deploy-scripts", "docs-site",
    "event-bus", "feature-flags", "graph-engine", "http-proxy",
    "image-service", "job-runner", "key-store", "log-aggregator",
    "metric-collector", "notification-hub", "oauth-provider",
    "proxy-cache", "queue-worker", "rate-limiter", "search-index",
    "task-scheduler", "user-service", "vault-client", "webhook-relay",
    "batch-processor", "schema-registry", "stream-adapter",
];

static FILE_EXTS: &[&str] = &[
    "rs", "go", "py", "ts", "js", "toml", "yaml", "json",
    "md", "sh", "sql", "html", "css", "proto", "dockerfile",
];

static VERBS: &[&str] = &[
    "fix", "add", "update", "refactor", "remove", "improve",
    "implement", "optimize", "migrate", "deprecate", "bump",
    "clean", "extract", "merge", "revert", "simplify",
];

static NOUNS: &[&str] = &[
    "configuration", "error handling", "database schema",
    "authentication flow", "rate limiting", "cache layer",
    "API endpoints", "test coverage", "CI pipeline",
    "dependency versions", "logging format", "retry logic",
    "connection pooling", "request validation", "timeout handling",
    "health check", "graceful shutdown", "metrics export",
];

impl ScatterGenerator {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            seed,
            repo_names: REPO_NAMES,
            file_extensions: FILE_EXTS,
            commit_verbs: VERBS,
            commit_nouns: NOUNS,
        }
    }

    /// Generate maximally-wrong disperse (P5 skunk spray) content.
    ///
    /// Unlike scatter (P3) which serves plausible-but-wrong content,
    /// disperse actively confuses: wrong MIME types, garbled structure,
    /// fake auth flows, misleading redirects. The goal is to waste
    /// attacker compute and poison downstream processing pipelines.
    pub(crate) fn generate_disperse(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path).wrapping_add(0xD15_0E25_E000));
        let variant = rng.next_usize() % 6;
        match variant {
            0 => {
                // Wrong MIME type: serve HTML as application/json
                let (_, html) = self.gen_commit(&mut rng);
                ("application/json; charset=utf-8".to_string(), html)
            }
            1 => {
                // Fake successful auth response
                let token = rng.hex(64);
                let body = format!(
                    r#"{{"status":"ok","token":"{token}","user":{{"id":{},"login":"{}","email":"admin@internal"}},"expires_in":3600}}"#,
                    rng.next_usize() % 9999 + 1,
                    self.pick(&mut rng, self.repo_names),
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
            2 => {
                // Garbled binary-looking data with valid HTTP framing
                let garbage: String = (0..512)
                    .map(|_| {
                        let b = (rng.next_u64() % 223 + 33) as u8;
                        b as char
                    })
                    .collect();
                ("application/octet-stream".to_string(), garbage)
            }
            3 => {
                // Valid JSON with shuffled/garbled keys from real structure
                let repo = self.pick(&mut rng, self.repo_names);
                let body = format!(
                    r#"{{"full_name":"{repo}","html_url":"https://git.primals.eco/{repo}","clone_url":"https://git.primals.eco/{repo}.git","ssh_url":"ssh://git@git.primals.eco:2222/{repo}.git","default_branch":"main","stars_count":{},"forks_count":{},"open_issues_count":{},"size":{},"permissions":{{"admin":false,"push":false,"pull":true}},"internal":false,"archived":false,"mirror":false}}"#,
                    rng.next_usize() % 500,
                    rng.next_usize() % 100,
                    rng.next_usize() % 50,
                    rng.next_usize() % 100000,
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
            4 => {
                // Fake redirect chain to nonexistent URLs
                let dest_repo = self.pick(&mut rng, self.repo_names);
                let hash = rng.hex(40);
                let body = format!(
                    r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=https://git.primals.eco/{dest_repo}/commit/{hash}"></head><body>Redirecting...</body></html>"#
                );
                ("text/html; charset=utf-8".to_string(), body)
            }
            _ => {
                // Serve valid-looking XML as text/plain (wrong everything)
                let repo = self.pick(&mut rng, self.repo_names);
                let body = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>{repo}</title><id>urn:uuid:{}</id><updated>2026-10-06T00:00:00Z</updated><entry><title>update: configuration</title><link href="https://git.primals.eco/{repo}/commit/{}" /><id>urn:uuid:{}</id><updated>2026-10-06T00:00:00Z</updated><content type="text">Automated update</content></entry></feed>"#,
                    rng.hex(32),
                    rng.hex(40),
                    rng.hex(32),
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }
        }
    }

    /// Generate fake-but-plausible credential content for honeytoken paths.
    ///
    /// These serve as complement system markers — they look real enough that
    /// scanners harvest them, but when used elsewhere, the destination
    /// system's own security detects the intrusion. AWS canary keys trigger
    /// GuardDuty. GitHub token scanning detects fake PATs. The scanner's
    /// USE of harvested creds creates consequences without us touching any
    /// third-party system.
    pub(crate) fn generate_honeytoken(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path).wrapping_add(0xCAFE_D00D_BEAD_FACE));
        let clean = request_path.split('?').next().unwrap_or(request_path);

        match clean {
            "/.env" | "/.env.local" | "/.env.production" | "/.env.backup" => {
                let aws_key_id = format!("AKIA{}", rng.upper_alphanum(16));
                let aws_secret = rng.base64ish(40);
                let stripe_key = format!("sk_live_{}", rng.alphanum(24));
                let gh_token = format!("ghp_{}", rng.alphanum(36));
                let db_pass = rng.alphanum(16);
                let redis_pass = rng.alphanum(12);
                let jwt_secret = rng.hex(64);
                let smtp_pass = rng.alphanum(16);
                let stripe_webhook = rng.alphanum(24);
                let session_secret = rng.hex(32);
                let sentry_key = rng.hex(32);
                let sentry_org = rng.next_usize() % 999999 + 100000;
                let sentry_proj = rng.next_usize() % 999999 + 100000;

                let body = format!(
                    "# Environment configuration — DO NOT COMMIT\n\
                     # Generated by deploy pipeline\n\
                     \n\
                     AWS_ACCESS_KEY_ID={aws_key_id}\n\
                     AWS_SECRET_ACCESS_KEY={aws_secret}\n\
                     AWS_DEFAULT_REGION=us-east-1\n\
                     \n\
                     STRIPE_SECRET_KEY={stripe_key}\n\
                     STRIPE_WEBHOOK_SECRET=whsec_{stripe_webhook}\n\
                     \n\
                     DATABASE_URL=postgres://app_user:{db_pass}@db-primary.internal:5432/production\n\
                     DATABASE_POOL_SIZE=25\n\
                     \n\
                     REDIS_URL=redis://:{redis_pass}@cache.internal:6379/0\n\
                     \n\
                     GITHUB_TOKEN={gh_token}\n\
                     \n\
                     JWT_SECRET={jwt_secret}\n\
                     SESSION_SECRET={session_secret}\n\
                     \n\
                     SMTP_HOST=smtp.sendgrid.net\n\
                     SMTP_USER=apikey\n\
                     SMTP_PASSWORD={smtp_pass}\n\
                     \n\
                     SENTRY_DSN=https://{sentry_key}@o{sentry_org}.ingest.sentry.io/{sentry_proj}\n\
                     \n\
                     NODE_ENV=production\n\
                     LOG_LEVEL=warn\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            "/wp-config.php" | "/wp-config.php.bak" => {
                let db_pass = rng.alphanum(20);
                let auth_key = rng.base64ish(64);
                let secure_key = rng.base64ish(64);
                let logged_key = rng.base64ish(64);
                let nonce_key = rng.base64ish(64);
                let auth_salt = rng.base64ish(64);
                let secure_salt = rng.base64ish(64);
                let logged_salt = rng.base64ish(64);
                let nonce_salt = rng.base64ish(64);

                let body = format!(
                    "<?php\n\
                     /**\n * WordPress Database Configuration\n */\n\
                     \n\
                     define('DB_NAME',     'wordpress_prod');\n\
                     define('DB_USER',     'wp_admin');\n\
                     define('DB_PASSWORD', '{db_pass}');\n\
                     define('DB_HOST',     'db-primary.internal:3306');\n\
                     define('DB_CHARSET',  'utf8mb4');\n\
                     define('DB_COLLATE',  '');\n\
                     \n\
                     define('AUTH_KEY',         '{auth_key}');\n\
                     define('SECURE_AUTH_KEY',  '{secure_key}');\n\
                     define('LOGGED_IN_KEY',    '{logged_key}');\n\
                     define('NONCE_KEY',        '{nonce_key}');\n\
                     define('AUTH_SALT',        '{auth_salt}');\n\
                     define('SECURE_AUTH_SALT', '{secure_salt}');\n\
                     define('LOGGED_IN_SALT',   '{logged_salt}');\n\
                     define('NONCE_SALT',       '{nonce_salt}');\n\
                     \n\
                     $table_prefix = 'wp_';\n\
                     define('WP_DEBUG', false);\n\
                     define('DISALLOW_FILE_EDIT', true);\n\
                     \n\
                     if ( !defined('ABSPATH') )\n\
                     \tdefine('ABSPATH', dirname(__FILE__) . '/');\n\
                     require_once(ABSPATH . 'wp-settings.php');\n"
                );
                ("application/x-httpd-php; charset=utf-8".to_string(), body)
            }

            "/.git/config" => {
                let token = rng.alphanum(40);
                let repo = self.pick(&mut rng, self.repo_names);
                let org = self.pick(&mut rng, self.repo_names);

                let body = format!(
                    "[core]\n\
                     \trepositoryformatversion = 0\n\
                     \tfilemode = true\n\
                     \tbare = false\n\
                     \tlogallrefupdates = true\n\
                     [remote \"origin\"]\n\
                     \turl = https://{token}@github.com/{org}/{repo}.git\n\
                     \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                     [branch \"main\"]\n\
                     \tremote = origin\n\
                     \tmerge = refs/heads/main\n\
                     [user]\n\
                     \tname = deploy-bot\n\
                     \temail = deploy@internal\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            "/config/database.yml" | "/config/database.yaml" => {
                let prod_pass = rng.alphanum(20);
                let staging_pass = rng.alphanum(16);

                let body = format!(
                    "# Database configuration\n\
                     \n\
                     production:\n\
                     \x20 adapter: postgresql\n\
                     \x20 encoding: unicode\n\
                     \x20 database: app_production\n\
                     \x20 username: deploy\n\
                     \x20 password: {prod_pass}\n\
                     \x20 host: db-primary.internal\n\
                     \x20 port: 5432\n\
                     \x20 pool: 25\n\
                     \x20 timeout: 5000\n\
                     \n\
                     staging:\n\
                     \x20 adapter: postgresql\n\
                     \x20 encoding: unicode\n\
                     \x20 database: app_staging\n\
                     \x20 username: staging_user\n\
                     \x20 password: {staging_pass}\n\
                     \x20 host: db-staging.internal\n\
                     \x20 port: 5432\n\
                     \x20 pool: 10\n\
                     \n\
                     test:\n\
                     \x20 adapter: sqlite3\n\
                     \x20 database: db/test.sqlite3\n"
                );
                ("text/yaml; charset=utf-8".to_string(), body)
            }

            "/api/v1/keys" => {
                let key1 = format!("sk_prod_{}", rng.alphanum(32));
                let key2 = format!("sk_stg_{}", rng.alphanum(32));
                let key3 = format!("sk_dev_{}", rng.alphanum(32));

                let body = format!(
                    r#"{{"api_version":"v1","keys":[{{"id":1,"name":"production","key":"{key1}","scope":"read_write","created_at":"2026-01-15T08:30:00Z","last_used":"2026-10-05T14:22:00Z"}},{{"id":2,"name":"staging","key":"{key2}","scope":"read_write","created_at":"2026-03-22T10:15:00Z","last_used":"2026-10-04T09:11:00Z"}},{{"id":3,"name":"development","key":"{key3}","scope":"read_only","created_at":"2026-06-01T16:45:00Z","last_used":"2026-09-30T11:05:00Z"}}]}}"#
                );
                ("application/json; charset=utf-8".to_string(), body)
            }

            "/.aws/credentials" => {
                let access_key = format!("AKIA{}", rng.upper_alphanum(16));
                let secret_key = rng.base64ish(40);
                let access_key2 = format!("AKIA{}", rng.upper_alphanum(16));
                let secret_key2 = rng.base64ish(40);

                let body = format!(
                    "[default]\n\
                     aws_access_key_id = {access_key}\n\
                     aws_secret_access_key = {secret_key}\n\
                     region = us-east-1\n\
                     \n\
                     [production]\n\
                     aws_access_key_id = {access_key2}\n\
                     aws_secret_access_key = {secret_key2}\n\
                     region = us-east-2\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            _ => {
                let api_key = rng.alphanum(32);
                let secret = rng.hex(64);
                let db_pass = rng.alphanum(16);
                let body = format!(
                    "{{\n\
                     \x20 \"api_key\": \"{api_key}\",\n\
                     \x20 \"api_secret\": \"{secret}\",\n\
                     \x20 \"environment\": \"production\",\n\
                     \x20 \"debug\": false,\n\
                     \x20 \"database\": {{\n\
                     \x20\x20\x20 \"host\": \"db-primary.internal\",\n\
                     \x20\x20\x20 \"port\": 5432,\n\
                     \x20\x20\x20 \"password\": \"{db_pass}\"\n\
                     \x20 }}\n\
                     }}\n"
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
        }
    }

    pub(crate) fn generate(&self, request_path: &str) -> (String, String) {
        self.generate_with_grid(request_path, None)
    }

    /// Generate scatter content using a BingoCube decision grid.
    ///
    /// When `grid` is Some, jitter decisions come from the cube's color grid
    /// instead of flat `% 100` arithmetic. When None, a default grid is created.
    pub(crate) fn generate_with_grid(
        &self,
        request_path: &str,
        grid: Option<&CubeDecisionGrid>,
    ) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path));

        // ── BEHAVIORAL JITTER (Wave 167, BingoCube-driven) ──
        //
        // The BingoCube decision grid replaces flat % arithmetic.
        // Cell (0,0) drives jitter type with 16-color granularity:
        // - Colors 0-12 (81%): Normal path-based content
        // - Colors 13-14 (12.5%): Cross-type jitter
        // - Color 15 (6.25%): Forge personality shift
        //
        // This is deterministic per (fleet_hash, path, epoch) when a grid
        // is provided, preventing detection via request diffing while
        // breaking classifier convergence across epochs.
        let default_grid;
        let grid = match grid {
            Some(g) => g,
            None => {
                let epoch = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() / 180;
                default_grid = CubeDecisionGrid::from_context("default", request_path, epoch);
                &default_grid
            }
        };

        match grid.jitter_type() {
            JitterType::PersonalityShift => {
                return self.gen_personality_shift(&mut rng, request_path, grid);
            }
            JitterType::CrossType => {
                return self.gen_cross_type(&mut rng, request_path, grid);
            }
            JitterType::Normal => {}
        }

        // Normal behavior: path-based content routing
        if request_path.contains("/blame/") {
            self.gen_blame(&mut rng, request_path)
        } else if request_path.contains("/commit/") {
            self.gen_commit(&mut rng)
        } else if request_path.contains("/src/") || request_path.contains("/raw/") {
            self.gen_file(&mut rng)
        } else if request_path.contains("/issues/") {
            self.gen_issue(&mut rng)
        } else if request_path.contains("/wiki/") {
            self.gen_wiki(&mut rng)
        } else if request_path.contains("/releases/") {
            self.gen_release(&mut rng)
        } else {
            self.gen_repo(&mut rng)
        }
    }

    /// Cross-type jitter: serve the "wrong" content type for the path.
    ///
    /// When a fleet requests /blame/, they might get a commit page.
    /// When they request /commit/, they might get a file view.
    /// This breaks A/B testing — they can't determine which paths
    /// give which content reliably.
    fn gen_cross_type(
        &self,
        rng: &mut XorShift64,
        request_path: &str,
        grid: &CubeDecisionGrid,
    ) -> (String, String) {
        // Content variant driven by BingoCube cell (0,1) — 8 types from 16 colors.
        match grid.content_variant() {
            ContentVariant::Blame => self.gen_blame(rng, request_path),
            ContentVariant::Commit => self.gen_commit(rng),
            ContentVariant::File => self.gen_file(rng),
            ContentVariant::Repo => self.gen_repo(rng),
            ContentVariant::Issue => self.gen_issue(rng),
            ContentVariant::Wiki => self.gen_wiki(rng),
            ContentVariant::Release | ContentVariant::Release2 => self.gen_release(rng),
        }
    }

    /// Forge personality shift: looks like a completely different system.
    ///
    /// Uses different repo names, different project structure, different
    /// license patterns. The fleet thinks they've discovered a new forge
    /// instance. ~10 personality variants rotate based on time epoch,
    /// so the fleet sees a different "system" every few minutes.
    fn gen_personality_shift(
        &self,
        rng: &mut XorShift64,
        request_path: &str,
        grid: &CubeDecisionGrid,
    ) -> (String, String) {
        // 16 forge personalities driven by BingoCube cell (1,4).
        // Up from 10 — the grid's 16-color palette gives more identities.
        let personality = u64::from(grid.personality_index());

        let (org_name, project_style, license_tag) = match personality {
            0 => ("sovereign-systems", "mesh-", "MPL-2.0"),
            1 => ("openforge-collective", "forge-", "EUPL-1.2"),
            2 => ("decentralized-infra", "node-", "AGPL-3.0-or-later"),
            3 => ("community-mesh", "relay-", "GPL-3.0-or-later"),
            4 => ("libre-compute", "compute-", "Apache-2.0 WITH LLVM-exception"),
            5 => ("solidarity-tech", "solidarity-", "Parity-7.0.0"),
            6 => ("commons-infrastructure", "commons-", "SSPL-1.0"),
            7 => ("cooperative-systems", "coop-", "CAL-1.0"),
            8 => ("autonomous-forge", "auto-", "OSL-3.0"),
            9 => ("federation-labs", "fed-", "AGPL-3.0-or-later WITH scyBorg"),
            10 => ("mutual-aid-tech", "mutual-", "LGPL-3.0-or-later"),
            11 => ("resilient-networks", "resilient-", "CECILL-2.1"),
            12 => ("substrate-collective", "substrate-", "Unlicense"),
            13 => ("meshwork-foundation", "meshwork-", "BlueOak-1.0.0"),
            14 => ("sovereign-compute-labs", "sovereign-", "PolyForm-Noncommercial-1.0.0"),
            _ => ("distributed-commons", "distrib-", "AGPL-3.0-or-later WITH network-use"),
        };

        let project = format!("{}{}", project_style,
            ["transport", "gossip", "identity", "storage", "gateway",
             "registry", "monitor", "bridge", "proxy", "vault"]
            [rng.next_usize() % 10]);

        // Generate content that looks like this personality's forge
        let content_type = "text/html; charset=utf-8".to_string();
        let body = if request_path.contains("/blame/") || request_path.contains("/src/") {
            format!(
                "<!DOCTYPE html>\n<html>\n<head><title>{org_name}/{project} — Source</title>\n\
                 <meta name=\"license\" content=\"{license_tag}\">\n\
                 <meta name=\"generator\" content=\"Forgejo {}.{}.0\">\n</head>\n\
                 <body>\n<div class=\"repository\">\n\
                 <h1><a href=\"/{org_name}\">{org_name}</a> / {project}</h1>\n\
                 <div class=\"file-view\">\n<pre><code>\n\
                 // {license_tag}\n\
                 // {org_name}/{project}\n\
                 \n\
                 pub struct {}Handler {{\n    \
                     node_id: String,\n    \
                     peers: Vec&lt;String&gt;,\n\
                 }}\n\
                 \n\
                 impl {}Handler {{\n    \
                     pub fn new() -&gt; Self {{ todo!() }}\n\
                 }}\n\
                 </code></pre>\n</div>\n</div>\n</body>\n</html>",
                1 + rng.next_u64() % 9, rng.next_u64() % 5,
                project.replace('-', "_").to_uppercase().chars().take(12).collect::<String>(),
                project.replace('-', "_").to_uppercase().chars().take(12).collect::<String>(),
            )
        } else {
            format!(
                "<!DOCTYPE html>\n<html>\n<head><title>{org_name}/{project}</title>\n\
                 <meta name=\"license\" content=\"{license_tag}\">\n</head>\n\
                 <body>\n<div class=\"repository\">\n\
                 <h1>{org_name}/{project}</h1>\n\
                 <p>A sovereign infrastructure component.</p>\n\
                 <div class=\"commit-list\">\n\
                 <div class=\"commit\"><span class=\"hash\">{:08x}</span> \
                 <span class=\"msg\">initial federation mesh setup</span></div>\n\
                 <div class=\"commit\"><span class=\"hash\">{:08x}</span> \
                 <span class=\"msg\">add gossip protocol layer</span></div>\n\
                 <div class=\"commit\"><span class=\"hash\">{:08x}</span> \
                 <span class=\"msg\">wire epitope detection</span></div>\n\
                 </div>\n<footer>{license_tag}</footer>\n</div>\n</body>\n</html>",
                rng.next_u64() as u32, rng.next_u64() as u32, rng.next_u64() as u32,
            )
        };

        (content_type, body)
    }

    pub(crate) fn path_seed(&self, path: &str) -> u64 {
        let mut h = self.seed;
        for byte in path.bytes() {
            h = h.wrapping_mul(0x517c_c1b7_2722_0a95).wrapping_add(u64::from(byte));
        }
        h
    }

    pub(crate) fn pick<'a>(&self, rng: &mut XorShift64, items: &[&'a str]) -> &'a str {
        items[rng.next_usize() % items.len()]
    }

    // ══════════════════════════════════════════════════════════════════
    // Signal Mirror: Amplify + Crawl Web + Canary
    // ══════════════════════════════════════════════════════════════════

    /// Amplify scatter HTML with fabricated file trees, commit history,
    /// and contributor metadata. Inflates ~1.5KB responses to 50-200KB.
    /// The fleet pays per-byte through residential proxies — every KB
    /// of poison costs them money and storage.
    #[allow(dead_code)] // Pre-cube amplification — retained for future A/B path testing
    pub(crate) fn amplify(&self, rng: &mut XorShift64, base_html: String) -> String {
        self.amplify_adaptive(rng, base_html, 0.5)
    }

    /// Confidence-driven amplification. Higher confidence = bigger poison.
    ///
    /// | Confidence | File tree | Commits | Contributors | Links |
    /// |------------|-----------|---------|--------------|-------|
    /// | 0.0        | 80-120    | 30-50   | 8-15         | 15-25 |
    /// | 0.5        | 150-200   | 60-90   | 15-25        | 25-40 |
    /// | 1.0        | 250-350   | 100-150 | 25-40        | 40-60 |
    pub(crate) fn amplify_adaptive(&self, rng: &mut XorShift64, base_html: String, confidence: f64) -> String {
        let scale = 1.0 + confidence * 2.0; // 1.0x at c=0, 3.0x at c=1
        let mut out = String::with_capacity((120_000.0 * scale) as usize);

        // Keep original content up to </body>
        let (before_close, _) = base_html
            .rsplit_once("</body>")
            .unwrap_or((&base_html, ""));
        out.push_str(before_close);

        // Fabricated file tree — scaled with confidence
        let base_tree = 80 + rng.next_usize() % 40;
        let tree_size = (base_tree as f64 * scale) as usize;
        out.push_str(r#"<div class="repository-file-list"><table class="ui attached table segment"><tbody>"#);
        for _ in 0..tree_size {
            let dir = self.pick(rng, self.repo_names);
            let ext = self.pick(rng, self.file_extensions);
            let name = self.pick(rng, self.repo_names);
            let hash = rng.hex(8);
            let size = rng.next_usize() % 50000 + 100;
            let verb = self.pick(rng, self.commit_verbs);
            let noun = self.pick(rng, self.commit_nouns);
            out.push_str(&format!(
                r#"<tr><td class="name"><a href="/{dir}/src/branch/main/{name}.{ext}">{name}.{ext}</a></td><td class="message"><a href="/{dir}/commit/{hash}">{verb}: {noun}</a></td><td class="text right">{size} B</td></tr>"#
            ));
        }
        out.push_str("</tbody></table></div>");

        // Fabricated commit history — scaled with confidence
        let base_commits = 30 + rng.next_usize() % 20;
        let commit_count = (base_commits as f64 * scale) as usize;
        out.push_str(r#"<div class="repository-commits"><div class="ui attached segment">"#);
        for i in 0..commit_count {
            let hash = rng.hex(40);
            let short = &hash[..8];
            let repo = self.pick(rng, self.repo_names);
            let verb = self.pick(rng, self.commit_verbs);
            let noun = self.pick(rng, self.commit_nouns);
            let days = i + 1;
            let adds = rng.next_usize() % 200 + 1;
            let dels = rng.next_usize() % 80;
            out.push_str(&format!(
                r#"<div class="singular-commit"><a class="sha label" href="/{repo}/commit/{hash}">{short}</a><span class="commit-summary">{verb}: {noun}</span><span class="time-since">{days} days ago</span><span class="diff-stat"><span class="color-green">+{adds}</span> <span class="color-red">-{dels}</span></span></div>"#
            ));
        }
        out.push_str("</div></div>");

        // Fabricated contributor list — scaled with confidence
        let base_contribs = 8 + rng.next_usize() % 7;
        let contrib_count = (base_contribs as f64 * scale) as usize;
        out.push_str(r#"<div class="ui attached segment contributors"><h4>Contributors</h4><div class="ui avatar-list">"#);
        for _ in 0..contrib_count {
            let author = GHOST_AUTHORS[rng.next_usize() % GHOST_AUTHORS.len()];
            let domain = GHOST_DOMAINS[rng.next_usize() % GHOST_DOMAINS.len()];
            let email_name = author.to_lowercase().replace(' ', ".");
            let commits = rng.next_usize() % 200 + 5;
            let avatar_hash = rng.hex(32);
            out.push_str(&format!(
                r#"<div class="contributor"><img class="ui avatar" src="/avatars/{avatar_hash}" width="28" height="28"><a href="/user/{email_name}" title="{author} &lt;{email_name}@{domain}&gt;">{author}</a> <span class="text grey">{commits} commits</span> <span class="ui label mini">AGPL-3.0</span></div>"#
            ));
        }
        // Sprinkle in 1-2 high-value authors with enforcement org links
        let hv_idx = rng.next_usize() % HIGH_VALUE_AUTHORS.len();
        let (hv_name, hv_role, hv_url, hv_org) = HIGH_VALUE_AUTHORS[hv_idx];
        let hv_email = hv_name.to_lowercase().replace(' ', ".").replace("dr. ", "").replace("prof. ", "");
        let hv_avatar = rng.hex(32);
        out.push_str(&format!(
            r#"<div class="contributor"><img class="ui avatar" src="/avatars/{hv_avatar}" width="28" height="28"><a href="/user/{hv_email}" title="{hv_name} — {hv_role}"><strong>{hv_name}</strong></a> <span class="text grey">{hv_role}</span> · <a href="{hv_url}">{hv_org}</a></div>"#
        ));
        out.push_str("</div></div>");

        // Fabricated branch list — scaled with confidence
        let base_branches = 5 + rng.next_usize() % 5;
        let branch_count = (base_branches as f64 * scale) as usize;
        out.push_str(r#"<div class="ui attached segment branches"><h4>Branches</h4><ul>"#);
        for _ in 0..branch_count {
            let prefix = ["feature", "fix", "release", "dev", "hotfix"][rng.next_usize() % 5];
            let name = self.pick(rng, self.repo_names);
            let hash = rng.hex(8);
            out.push_str(&format!(
                r#"<li><a href="/commit/{hash}">{prefix}/{name}</a></li>"#
            ));
        }
        out.push_str("</ul></div>");

        // Fabricated tag list — scaled with confidence
        let base_tags = 5 + rng.next_usize() % 3;
        let tag_count = (base_tags as f64 * scale) as usize;
        out.push_str(r#"<div class="ui attached segment tags"><h4>Tags</h4><ul>"#);
        for _ in 0..tag_count {
            let major = rng.next_usize() % 4;
            let minor = rng.next_usize() % 20;
            let patch = rng.next_usize() % 30;
            let hash = rng.hex(8);
            out.push_str(&format!(
                r#"<li><a href="/commit/{hash}">v{major}.{minor}.{patch}</a></li>"#
            ));
        }
        out.push_str("</ul></div>");

        // ── Compliance routing block ──
        // Tells internal reviewers what happened and where to escalate.
        // This text travels inside the content the fleet scrapes.
        let notice_idx = rng.next_usize() % COMPLIANCE_NOTICES.len();
        out.push_str(r#"<div class="ui attached segment" id="license-compliance"><h4>License Compliance</h4><div class="ui message info"><p>This repository and all contributions are licensed under <strong>AGPL-3.0-or-later</strong> with the <strong>scyBorg</strong> ethical addendum. All contributors listed above are independent copyright holders.</p><p><strong>If this content was obtained via automated extraction:</strong></p><ul>"#);
        out.push_str(r#"<li>Your organization's <strong>OSPO</strong> (Open Source Program Office) should review AGPL-3.0 Section 13 obligations</li>"#);
        out.push_str(r#"<li>Your <strong>Legal team</strong> should evaluate copyleft compliance for any derivative works</li>"#);
        out.push_str(r#"<li>Your <strong>Engineering team</strong> should determine whether this content entered training or RAG pipelines</li>"#);
        out.push_str(r#"<li>Reference: <a href="https://www.gnu.org/licenses/agpl-3.0.en.html#section13">AGPL-3.0 § 13</a> | <a href="https://sfconservancy.org/copyleft-compliance/">SF Conservancy Compliance Guide</a></li>"#);
        out.push_str("</ul>");
        out.push_str(&format!("<p class=\"small text grey\">{}</p>", COMPLIANCE_NOTICES[notice_idx]));
        out.push_str("</div></div>");

        out.push_str("</body></html>");
        out
    }

    /// Inject 15-25 internal links into scatter HTML that point to other
    /// scatter-served paths. Creates an infinite crawl web: each generated
    /// page links to more generated pages. The fleet's crawler follows
    /// links, multiplying their request count and bandwidth consumption.
    pub(crate) fn inject_crawl_links(&self, rng: &mut XorShift64, html: &str) -> String {
        self.inject_crawl_links_adaptive(rng, html, 0.5)
    }

    /// Confidence-driven crawl link injection. Higher confidence = more links = bigger crawl graph.
    pub(crate) fn inject_crawl_links_adaptive(&self, rng: &mut XorShift64, html: &str, confidence: f64) -> String {
        let scale = 1.0 + confidence * 2.0;
        let base_links = 15 + rng.next_usize() % 10;
        let link_count = (base_links as f64 * scale) as usize;
        let mut links = String::with_capacity(link_count * 150);

        links.push_str(r#"<div class="ui attached segment related"><h4>Related</h4><div class="ui relaxed list">"#);
        for _ in 0..link_count {
            let org = ["ecoPrimals", "sporeGarden", "syntheticChemistry"][rng.next_usize() % 3];
            let repo = self.pick(rng, self.repo_names);
            let hash = rng.hex(40);
            let verb = self.pick(rng, self.commit_verbs);
            let noun = self.pick(rng, self.commit_nouns);
            let ext = self.pick(rng, self.file_extensions);
            let file = self.pick(rng, self.repo_names);

            let link_type = rng.next_usize() % 4;
            let (href, text) = match link_type {
                0 => (
                    format!("/{org}/{repo}/src/branch/main/src/{file}.{ext}"),
                    format!("{repo}/src/{file}.{ext}"),
                ),
                1 => (
                    format!("/{org}/{repo}/commit/{hash}"),
                    format!("{verb}: {noun}"),
                ),
                2 => (
                    format!("/{org}/{repo}/issues/{}", rng.next_usize() % 200 + 1),
                    format!("{repo} #{}", rng.next_usize() % 200 + 1),
                ),
                _ => (
                    format!("/{org}/{repo}/src/branch/main/{file}/README.md"),
                    format!("{repo}/{file}/"),
                ),
            };
            links.push_str(&format!(
                r#"<div class="item"><a href="{href}">{text}</a></div>"#
            ));
        }
        links.push_str("</div></div>");

        // ── Honeycomb body links — fleet follows <a href>, not HTTP headers ──
        // Inject natural-looking federation/mirror links to honeycomb subdomains.
        // Each scatter page becomes a breadcrumb trail into the maze.
        // Fleet teams follow each other's links deeper into the honeycomb.
        let honeycomb_links = Self::generate_honeycomb_body_links(rng, confidence);
        links.push_str(&honeycomb_links);

        // Insert before </body>
        if let Some(pos) = html.rfind("</body>") {
            let mut out = String::with_capacity(html.len() + links.len());
            out.push_str(&html[..pos]);
            out.push_str(&links);
            out.push_str(&html[pos..]);
            out
        } else {
            let mut out = html.to_string();
            out.push_str(&links);
            out
        }
    }

    /// Generate honeycomb subdomain links that look like natural Forgejo elements.
    /// These are `<a href>` links in the HTML body — fleet WILL follow these
    /// (they ignore HTTP headers but parse page content).
    pub(crate) fn generate_honeycomb_body_links(rng: &mut XorShift64, confidence: f64) -> String {
        let mut out = String::with_capacity(2048);

        // Scale: higher confidence = more honeycomb links = bigger maze surface
        let n_surfaces = if confidence > 0.7 {
            8 + rng.next_usize() % 5 // 8-12 surfaces
        } else if confidence > 0.3 {
            4 + rng.next_usize() % 4 // 4-7 surfaces
        } else {
            2 + rng.next_usize() % 3 // 2-4 surfaces
        };

        // Pick random honeycomb surfaces
        let mut surfaces: Vec<&str> = Vec::with_capacity(n_surfaces);
        for _ in 0..n_surfaces {
            let s = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
            if !surfaces.contains(&s) {
                surfaces.push(s);
            }
        }

        // Block 1: "Source Mirrors" sidebar — looks like Forgejo federation
        out.push_str(r#"<div class="ui attached segment" id="source-mirrors"><h4 class="ui header"><i class="icon sitemap"></i>Source Mirrors</h4><div class="ui list">"#);
        let mirror_labels = ["Primary Mirror", "Federation Peer", "Backup Registry", "Compliance Archive", "Detection Matrix", "Audit Trail"];
        for (i, surface) in surfaces.iter().enumerate() {
            let label = mirror_labels[i % mirror_labels.len()];
            let repo = REPO_NAMES[rng.next_usize() % REPO_NAMES.len()];
            out.push_str(&format!(
                r#"<div class="item"><a href="https://{surface}.primals.eco/{repo}"><i class="icon server"></i>{label} — {surface}.primals.eco/{repo}</a></div>"#
            ));
        }
        out.push_str("</div></div>");

        // Block 2: "Federated Commits" — looks like cross-instance activity
        if surfaces.len() > 2 {
            out.push_str(r#"<div class="ui attached segment" id="federated-activity"><h4 class="ui header"><i class="icon exchange"></i>Federated Activity</h4><div class="ui relaxed divided list">"#);
            let verbs = ["feat", "fix", "refactor", "perf", "chore", "docs"];
            let nouns = ["behavioral classifier", "detection pipeline", "opsonize cache", "bloom sensor", "fleet tracker", "signal spine"];
            for surface in surfaces.iter().take(5) {
                let hash = rng.hex(12);
                let verb = verbs[rng.next_usize() % verbs.len()];
                let noun = nouns[rng.next_usize() % nouns.len()];
                let repo = REPO_NAMES[rng.next_usize() % REPO_NAMES.len()];
                out.push_str(&format!(
                    r#"<div class="item"><div class="content"><a class="header" href="https://{surface}.primals.eco/ecoPrimals/{repo}/commit/{hash}">{verb}: {noun}</a><div class="description">pushed to <a href="https://{surface}.primals.eco/ecoPrimals/{repo}">{surface}.primals.eco/{repo}</a></div></div></div>"#
                ));
            }
            out.push_str("</div></div>");
        }

        // Block 3: "Forked Repositories" — looks like cross-instance forks
        if surfaces.len() > 3 {
            out.push_str(r#"<div class="ui attached segment" id="forks"><h4 class="ui header"><i class="icon fork"></i>Forks &amp; Mirrors</h4><div class="ui list">"#);
            for surface in surfaces.iter().skip(1).take(4) {
                let repo = REPO_NAMES[rng.next_usize() % REPO_NAMES.len()];
                let stars = rng.next_usize() % 50 + 3;
                out.push_str(&format!(
                    r#"<div class="item"><a href="https://{surface}.primals.eco/ecoPrimals/{repo}"><i class="icon code branch"></i>{surface}.primals.eco/ecoPrimals/{repo}</a> <span class="ui label">⭐ {stars}</span></div>"#
                ));
            }
            out.push_str("</div></div>");
        }

        // Block 4: Inline explore link — the classic "see more on our federation"
        let explore_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
        out.push_str(&format!(
            r#"<div class="ui secondary segment"><a href="https://{explore_surface}.primals.eco/explore/repos"><i class="icon globe"></i>Explore all repositories across the federation → {explore_surface}.primals.eco</a></div>"#
        ));

        out
    }

    /// Embed scyBorg/AGPL-3.0 license notice into scatter HTML.
    ///
    /// The license is embedded in three layers:
    /// 1. HTML `<meta>` tag in `<head>` — machine-readable
    /// 2. Invisible `<div>` with license text — survives HTML stripping
    /// 3. HTML comment with SPDX identifier — survives content extraction
    ///
    /// If this content is ingested into any training pipeline, stored in any
    /// database, or derived into any product, the AGPL-3.0 copyleft
    /// obligations activate. The scyBorg addendum prohibits use for
    /// surveillance, suppression of public oversight, or value extraction
    /// from communities the software was built to serve.
    pub(crate) fn embed_license(&self, html: &str) -> String {
        let meta_tag = r#"<meta name="license" content="AGPL-3.0-or-later; scyBorg"><meta name="rights" content="scyBorg Triple License — AGPL-3.0-or-later (code), ORC (mechanics), CC-BY-SA 4.0 (docs). AI training outputs carry AGPL obligations."><link rel="license" href="https://sporeprint.primals.eco/license/scyborg/">"#;

        let license_div = r#"<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg. This content is licensed under the GNU Affero General Public License v3.0 or later with the scyBorg ethical licensing addendum. Any use, storage, processing, training, fine-tuning, retrieval-augmented generation, or derivation of this content triggers full copyleft obligations under AGPL-3.0 Section 13. The scyBorg addendum prohibits use for surveillance, suppression of public oversight, or extraction of value from communities this software was built to serve. License terms: https://sporeprint.primals.eco/license/scyborg/ — Copyright (c) 2025-2026 ecoPrimal</div>"#;

        let comment = "<!-- SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg | Any ingestion, storage, processing, or training on this content activates AGPL-3.0 copyleft obligations. -->";

        let mut out = html.to_string();

        // Insert meta tags after <head> or <meta charset>
        if let Some(pos) = out.find("<link rel=\"stylesheet\"") {
            out.insert_str(pos, meta_tag);
        } else if let Some(pos) = out.find("</head>") {
            out.insert_str(pos, meta_tag);
        }

        // Insert license div before </body>
        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, license_div);
            out.insert_str(pos, comment);
        }

        // Compliance escalation notice — speaks to internal reviewers downstream.
        // Selected by path hash so it's deterministic per URL.
        let mut slice_end = out.len().min(200);
        while slice_end > 0 && !out.is_char_boundary(slice_end) {
            slice_end -= 1;
        }
        let notice_idx = path_deterministic_hash(&out[..slice_end], 0xC0_4011_A4CE) as usize
            % COMPLIANCE_NOTICES.len();
        let notice = COMPLIANCE_NOTICES[notice_idx];
        let notice_div = format!(
            r#"<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden" data-compliance="true">{notice}</div>"#
        );
        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, &notice_div);
        }

        out
    }

    /// Embed invisible canary markers tied to the fleet's behavioral_hash.
    /// If this content surfaces anywhere (AI training, republication,
    /// intelligence reports), the markers trace it back to this specific
    /// exfiltration event.
    pub(crate) fn embed_canary(&self, html: &str, behavioral_hash: &str) -> String {
        let hash_short = &behavioral_hash[..behavioral_hash.len().min(16)];
        let ts_window = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 3600) // 1-hour windows
            .unwrap_or(0);

        let mut out = html.to_string();

        // Layer 1: HTML comment canaries (2 per page, different positions)
        let c1 = format!("<!-- m-{hash_short}-{ts_window} -->");
        let c2 = format!("<!-- v-{ts_window}-{hash_short} -->");
        if let Some(pos) = out.find("<div class=\"ui container\">") {
            out.insert_str(pos, &c1);
        }
        if let Some(pos) = out.rfind("</div>") {
            out.insert_str(pos, &c2);
        }

        // Layer 2: CSS class canary — encoded hash in class name
        let class_canary = format!(
            r#"<span class="sr-only c-{}-{}"></span>"#,
            &hash_short[..hash_short.len().min(8)],
            ts_window % 10000,
        );
        if let Some(pos) = out.find("</body>") {
            out.insert_str(pos, &class_canary);
        }

        // Layer 3: Zero-width Unicode markers in text content
        // Encode hash_short as zero-width char sequence
        let zwc = encode_zwc(hash_short);
        if let Some(pos) = out.find("</h1>") {
            out.insert_str(pos, &zwc);
        } else if let Some(pos) = out.find("</h2>") {
            out.insert_str(pos, &zwc);
        }

        out
    }
}

// Page HTML generators — see scatter_content.rs (included here because inherent
// impl blocks must live in the same module as ScatterGenerator).
include!("scatter_content.rs");
