// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Entity classifier — topographical map of all observed systems.
//!
//! The fleet keeps sending us signal. Every request carries behavioral
//! fingerprints that reveal the entity, sub-system, and team structure
//! behind it. This module classifies entities from conserved epitopes
//! and builds a live topology of who is doing what.
//!
//! # Entity hierarchy
//!
//! ```text
//! Entity (org-level: Meta, Anthropic, Google, ...)
//!   └── Fleet (coordinated system: Meta/FB-BLOCK, Anthropic/ClaudeBot)
//!         └── Sub-system (behavioral cluster within a fleet)
//!               └── Campaign (time-bounded targeting pattern)
//! ```
//!
//! # Conserved epitopes that identify entities
//!
//! Each entity has a unique combination of behavioral invariants —
//! "conserved epitopes" in immune system terms. These are the signals
//! they cannot change without breaking their own infrastructure:
//!
//! - Accept-Encoding order (config fingerprint)
//! - Header presence/absence patterns (Sec-Fetch, Sec-Ch-Ua, Connection)
//! - Chrome version lag (deployment cadence)
//! - UA string pool size and OS distribution
//! - IP rotation vs single-IP strategy
//! - Target selection (real repos vs scatter)
//! - Path operation mix (commit vs blame vs src)
//! - Timing signature (metronomic vs varied)

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use crate::caddy;

// ── Entity identification ──

/// Known entity type, identified by behavioral fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityId {
    /// Meta Platforms — confirmed via WHOIS (57.141.0.0/13 = FB-BLOCK).
    MetaFleet,
    /// Meta's official link preview bot (facebookexternalhit).
    MetaFacebookBot,
    /// Anthropic's training crawler (ClaudeBot/1.0).
    AnthropicClaudeBot,
    /// Google search crawler.
    GoogleBot,
    /// Microsoft search crawler.
    MicrosoftBingBot,
    /// OpenAI training crawler.
    OpenAiGptBot,
    /// ByteDance training crawler.
    ByteDanceBytespider,
    /// Huawei search crawler.
    HuaweiPetalBot,
    /// Apple search crawler.
    AppleBot,
    /// SEO analysis tools (Semrush, Ahrefs, Moz, etc.)
    SeoTooling,
    /// Declared bot — sends Sec-Fetch headers but identifies as a bot in UA.
    /// Wave 167: Amazon Reflectionbot, AI search crawlers, etc.
    DeclaredBot,
    /// Real human browser (Sec-Fetch-Mode present, no bot UA).
    HumanBrowser,
    /// Ghost — single-request with browser headers but no referer.
    /// Wave 167: residential proxy exits for fleet crawlers.
    Ghost,
    /// Stealth scraper — Chrome UA without mandatory headers.
    StealthScraper,
    /// Vulnerability scanner / probe.
    VulnScanner,
    /// Not enough signal to classify.
    Unknown,
}

impl EntityId {
    /// Human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MetaFleet => "Meta Platforms (Fleet)",
            Self::MetaFacebookBot => "Meta (Facebook Bot)",
            Self::AnthropicClaudeBot => "Anthropic (ClaudeBot)",
            Self::GoogleBot => "Google (Googlebot)",
            Self::MicrosoftBingBot => "Microsoft (Bingbot)",
            Self::OpenAiGptBot => "OpenAI (GPTBot)",
            Self::ByteDanceBytespider => "ByteDance (Bytespider)",
            Self::HuaweiPetalBot => "Huawei (PetalBot)",
            Self::AppleBot => "Apple (Applebot)",
            Self::SeoTooling => "SEO Tooling",
            Self::DeclaredBot => "Declared Bot (browser headers)",
            Self::HumanBrowser => "Human (Browser)",
            Self::Ghost => "Ghost (proxy exit)",
            Self::StealthScraper => "Stealth Scraper",
            Self::VulnScanner => "Vulnerability Scanner",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this entity is a confirmed corporate scraping fleet.
    pub fn is_fleet(&self) -> bool {
        matches!(self, Self::MetaFleet | Self::AnthropicClaudeBot |
                 Self::OpenAiGptBot | Self::ByteDanceBytespider |
                 Self::DeclaredBot)
    }

    /// Whether this entity is a human visitor (browser or ghost).
    ///
    /// Used by campfire modules to filter for visitor-facing analysis.
    /// Fleet entities don't get archetypes — they get entity types.
    pub fn is_human(&self) -> bool {
        matches!(self, Self::HumanBrowser | Self::Ghost)
    }

    /// Whether this entity is a ghost (residential proxy exit).
    pub fn is_ghost(&self) -> bool {
        matches!(self, Self::Ghost)
    }

    /// Whether this entity honestly identifies itself.
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::AnthropicClaudeBot | Self::GoogleBot |
                 Self::MicrosoftBingBot | Self::HuaweiPetalBot |
                 Self::AppleBot | Self::MetaFacebookBot | Self::HumanBrowser |
                 Self::DeclaredBot)
    }
}

// ── Per-request fingerprint ──

/// Minimal per-request data needed for entity classification.
#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    pub ip: String,
    pub user_agent: String,
    pub host: String,
    pub uri: String,
    pub accept: String,
    pub accept_encoding: String,
    pub accept_language: String,
    pub has_sec_fetch_mode: bool,
    pub has_sec_ch_ua: bool,
    pub has_connection: bool,
    pub has_cookie: bool,
    pub timestamp: f64,
    pub status: u16,
    /// Sec-Fetch triplet (Mode|Dest|Site) for monotone detection.
    pub sec_fetch_triplet: String,
    /// Referer header value (empty string if absent).
    pub referer: String,
}

impl RequestFingerprint {
    /// Build a fingerprint from a parsed Caddy log entry.
    pub fn from_caddy_entry(entry: &caddy::LogEntry) -> Self {
        let h = &entry.request.headers;
        let ua = h.user_agent.first().cloned().unwrap_or_default();
        let mode = h.sec_fetch_mode.first().cloned().unwrap_or_default();
        let dest = h.sec_fetch_dest.first().cloned().unwrap_or_default();
        let site = h.sec_fetch_site.first().cloned().unwrap_or_default();
        let triplet = if mode.is_empty() {
            String::new()
        } else {
            format!("{}|{}|{}", mode, dest, site)
        };

        Self {
            ip: entry.request.remote_ip.clone(),
            user_agent: ua,
            host: entry.request.host.clone(),
            uri: entry.request.uri.clone(),
            accept: h.accept.first().cloned().unwrap_or_default(),
            accept_encoding: h.accept_encoding.first().cloned().unwrap_or_default(),
            accept_language: h.accept_language.first().cloned().unwrap_or_default(),
            has_sec_fetch_mode: !h.sec_fetch_mode.is_empty(),
            has_sec_ch_ua: !h.sec_ch_ua.is_empty(),
            has_connection: !h.connection.is_empty(),
            has_cookie: !h.cookie.is_empty(),
            timestamp: entry.ts,
            status: entry.status,
            sec_fetch_triplet: triplet,
            referer: h.referer.first().cloned().unwrap_or_default(),
        }
    }

    /// Extract Chrome major version from the UA string.
    pub fn chrome_major(&self) -> u16 {
        if let Some(idx) = self.user_agent.find("Chrome/") {
            let after = &self.user_agent[idx + 7..];
            let end = after.find('.').unwrap_or(after.len());
            after[..end].parse().unwrap_or(0)
        } else {
            0
        }
    }

    /// Extract the impersonated OS from the UA string.
    pub fn ua_os(&self) -> &'static str {
        if self.user_agent.contains("Windows NT 10.0") { "Windows" }
        else if self.user_agent.contains("Macintosh") { "macOS" }
        else if self.user_agent.contains("X11; Linux") { "Linux" }
        else { "other" }
    }

    /// Extract the path operation type.
    pub fn path_op(&self) -> PathOp {
        if self.uri.contains("/commit/") || self.uri.contains("/commits/") {
            PathOp::Commit
        } else if self.uri.contains("/blame/") {
            PathOp::Blame
        } else if self.uri.contains("/src/") {
            PathOp::Src
        } else if self.uri.contains("/raw/") {
            PathOp::Raw
        } else if self.uri.contains("/issues") {
            PathOp::Issues
        } else {
            PathOp::Other
        }
    }

    /// Extract the repo name from the URI.
    pub fn repo_name(&self) -> Option<String> {
        let parts: Vec<&str> = self.uri.trim_matches('/').split('/').collect();
        if parts.len() >= 2 {
            Some(format!("{}/{}", parts[0], parts[1]))
        } else {
            None
        }
    }

    /// IP /24 subnet.
    pub fn subnet(&self) -> String {
        let parts: Vec<&str> = self.ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.x", parts[0], parts[1], parts[2])
        } else {
            self.ip.clone()
        }
    }
}

/// Path operation type — what data the entity extracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOp {
    /// `/commit/` — source diffs, full change content.
    Commit,
    /// `/blame/` — author attribution per line.
    Blame,
    /// `/src/` — file contents.
    Src,
    /// `/raw/` — binary/raw file download.
    Raw,
    /// `/issues` — issue tracker.
    Issues,
    /// Anything else.
    Other,
}

impl PathOp {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit (source diffs)",
            Self::Blame => "blame (author attribution)",
            Self::Src => "src (file contents)",
            Self::Raw => "raw (binary download)",
            Self::Issues => "issues (tracker)",
            Self::Other => "other",
        }
    }
}

// ── Classify a single request ──

/// Classify a request fingerprint into an entity.
///
/// This is the static fallback — uses the hardcoded `is_declared_bot()` list.
/// Prefer `classify_with_registry()` when a shared registry is available.
pub fn classify(fp: &RequestFingerprint) -> EntityId {
    classify_inner(fp, |ua| is_declared_bot(ua))
}

/// Classify a request fingerprint using the culture-derived epitope registry.
///
/// Same classification logic as `classify()`, but bot detection is backed by
/// the living registry instead of the static phone book.
pub fn classify_with_registry(
    fp: &RequestFingerprint,
    registry: &crate::epitope_registry::SharedRegistry,
) -> EntityId {
    classify_inner(fp, |ua| {
        registry.read()
            .map(|reg| reg.is_declared_bot(ua))
            .unwrap_or_else(|_| is_declared_bot(ua))
    })
}

/// Core classification logic — parametric over how bot detection is performed.
fn classify_inner(fp: &RequestFingerprint, check_declared_bot: impl Fn(&str) -> bool) -> EntityId {
    let ua = &fp.user_agent;

    // Tier 1: Explicit bot identifiers (named entities with specific tracking)
    if ua.contains("ClaudeBot") { return EntityId::AnthropicClaudeBot; }
    if ua.contains("facebookexternalhit") { return EntityId::MetaFacebookBot; }
    if ua.contains("Googlebot") { return EntityId::GoogleBot; }
    if ua.contains("bingbot") { return EntityId::MicrosoftBingBot; }
    if ua.contains("GPTBot") { return EntityId::OpenAiGptBot; }
    if ua.contains("Bytespider") { return EntityId::ByteDanceBytespider; }
    if ua.contains("PetalBot") { return EntityId::HuaweiPetalBot; }
    if ua.contains("Applebot") { return EntityId::AppleBot; }
    if ua.contains("SemrushBot") || ua.contains("AhrefsBot") ||
       ua.contains("DotBot") || ua.contains("MJ12bot") {
        return EntityId::SeoTooling;
    }

    // Confirmed Meta fleet IP range (WHOIS: FB-BLOCK)
    if fp.ip.starts_with("57.141.") { return EntityId::MetaFleet; }

    // Vulnerability scanner / probe patterns
    if fp.uri.contains("/logincheck") || fp.uri.contains("/remote/") ||
       fp.uri.contains("/api/v2/") || fp.uri.contains("/.env") ||
       fp.uri.contains("/wp-login") || fp.uri.contains("/actuator") {
        return EntityId::VulnScanner;
    }

    // Tier 2: Culture-derived bot detection — uses registry or static fallback.
    // Bot identity is an evolving epitope: they can't stop declaring without
    // losing robots.txt treatment. The registry learns new patterns from
    // topology culture observations.
    if check_declared_bot(ua) {
        return EntityId::DeclaredBot;
    }

    // Tier 3: Behavioral classification from header patterns.
    // Real browser (Sec-Fetch-Mode is mandatory since Chrome 76)
    // Referer-absent single-request IPs are ghosts, not humans.
    if fp.has_sec_fetch_mode {
        if fp.referer.is_empty() && !fp.accept_language.is_empty() {
            return EntityId::Ghost;
        }
        return EntityId::HumanBrowser;
    }

    // Stealth scraper — Chrome UA without mandatory headers
    if ua.contains("Chrome/") && !fp.has_sec_fetch_mode {
        return EntityId::StealthScraper;
    }

    EntityId::Unknown
}

/// Wave 167: Detect bots that send browser-grade headers (Sec-Fetch) but
/// identify as bots in their UA string. This is an evolving epitope set —
/// each bot identity is a conserved surface protein. They can't stop
/// declaring without losing crawler-specific treatment in robots.txt.
///
/// The list grows as new declared bots appear in the culture.
pub fn is_declared_bot(ua: &str) -> bool {
    // Amazon product crawlers
    if ua.contains("Reflectionbot") { return true; }
    if ua.contains("Amazonbot") { return true; }
    // AI search/training crawlers that send browser headers
    if ua.contains("ChatGPT-User") { return true; }
    if ua.contains("Claude-SearchBot") { return true; }
    if ua.contains("Claude-User") { return true; }
    if ua.contains("Perplexity-User") { return true; }
    if ua.contains("PerplexityBot") { return true; }
    if ua.contains("xAI-Grok") || ua.contains("GrokBot") { return true; }
    if ua.contains("DeepSeekBot") { return true; }
    if ua.contains("KimiBot") || ua.contains("Kimi-SearchBot") || ua.contains("MoonshotBot") { return true; }
    if ua.contains("MistralAI-User") { return true; }
    if ua.contains("cohere-ai") { return true; }
    if ua.contains("Qwenbot") { return true; }
    if ua.contains("PanguBot") { return true; }
    if ua.contains("Hunyuan") { return true; }
    if ua.contains("YiBot") { return true; }
    if ua.contains("ChatGLM-Spider") { return true; }
    if ua.contains("Meta-ExternalAgent") { return true; }
    if ua.contains("Google-Extended") { return true; }
    if ua.contains("Bravebot") { return true; }
    if ua.contains("YouBot") { return true; }
    if ua.contains("DuckAssistBot") { return true; }
    if ua.contains("CCBot") { return true; }
    if ua.contains("Baiduspider") { return true; }
    // Generic bot pattern: "compatible; *Bot/" with browser Accept headers
    if ua.contains("HeadlessChrome") { return true; }
    if ua.contains("okhttp/") { return true; }
    false
}

pub use crate::entity_profile::{
    EntityProfile, EpitopeResult, EpitopeScores, HeaderFingerprint,
    IpRotation, SubSystem, TimingProfile,
};
pub use crate::entity_sort::{
    build_comparative, ComparativeRow, EntityTopology,
};
pub use crate::entity_topology::{TopologyBuilder, TopologyWriter};


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_claudebot() {
        let fp = RequestFingerprint {
            ip: "216.73.216.1".into(),
            user_agent: "Mozilla/5.0 AppleWebKit/537.36 ClaudeBot/1.0".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/src/branch/main/README.md".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::AnthropicClaudeBot);
        assert!(fp.chrome_major() == 0);
    }

    #[test]
    fn classify_human_browser() {
        // Real human: has sec-fetch AND a referer (arrived from search/link)
        let fp = RequestFingerprint {
            ip: "203.0.113.1".into(),
            user_agent: "Mozilla/5.0 Chrome/155.0.0.0".into(),
            host: "primals.eco".into(),
            uri: "/".into(),
            accept: "text/html".into(),
            accept_encoding: "gzip, deflate, br".into(),
            accept_language: "en-US,en;q=0.9".into(),
            has_sec_fetch_mode: true,
            has_sec_ch_ua: true,
            has_connection: true,
            has_cookie: true,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: "navigate|document|none".into(),
            referer: "https://www.google.com/".into(),
        };
        assert_eq!(classify(&fp), EntityId::HumanBrowser);
        assert_eq!(fp.chrome_major(), 155);
    }

    #[test]
    fn classify_ghost() {
        // Ghost: has sec-fetch + accept-lang but NO referer
        let fp = RequestFingerprint {
            ip: "69.141.210.241".into(),
            user_agent: "Mozilla/5.0 Chrome/155.0.0.0".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/wateringHole".into(),
            accept: "text/html,application/xhtml+xml".into(),
            accept_encoding: "gzip, deflate, br".into(),
            accept_language: "en-US,en;q=0.9".into(),
            has_sec_fetch_mode: true,
            has_sec_ch_ua: true,
            has_connection: true,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: "navigate|document|none".into(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::Ghost);
    }

    #[test]
    fn classify_declared_bot() {
        // Reflectionbot: has sec-fetch but identifies as bot in UA
        let fp = RequestFingerprint {
            ip: "16.216.88.116".into(),
            user_agent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Reflectionbot/1.0; +https://developer.amazon.com/)".into(),
            host: "git.primals.eco".into(),
            uri: "/event-bus/commit/abc123".into(),
            accept: "text/html,application/xhtml+xml".into(),
            accept_encoding: "gzip, deflate, br".into(),
            accept_language: "en-US,en;q=0.9".into(),
            has_sec_fetch_mode: true,
            has_sec_ch_ua: false,
            has_connection: true,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: "navigate|document|none".into(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::DeclaredBot);
        assert!(EntityId::DeclaredBot.is_fleet());
    }

    #[test]
    fn classify_stealth_scraper() {
        let fp = RequestFingerprint {
            ip: "198.51.100.1".into(),
            user_agent: "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/commit/abc123".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::StealthScraper);
        assert_eq!(fp.chrome_major(), 130);
        assert_eq!(fp.path_op(), PathOp::Commit);
    }

    #[test]
    fn classify_meta_fleet() {
        let fp = RequestFingerprint {
            ip: "57.141.10.5".into(),
            user_agent: "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/blame/branch/main/README.md".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::MetaFleet);
        assert_eq!(fp.path_op(), PathOp::Blame);
    }

    #[test]
    fn from_caddy_entry_builds_fingerprint() {
        let entry = caddy::LogEntry {
            request: caddy::RequestInfo {
                remote_ip: "203.0.113.50".into(),
                host: "primals.eco".into(),
                uri: "/wp-login.php".into(),
                method: "GET".into(),
                headers: caddy::Headers {
                    user_agent: vec!["curl/7.88.1".into()],
                    accept_encoding: vec!["gzip".into()],
                    sec_fetch_mode: vec!["navigate".into()],
                    sec_fetch_dest: vec!["document".into()],
                    sec_fetch_site: vec!["none".into()],
                    cookie: vec!["session=abc".into()],
                    ..Default::default()
                },
            },
            status: 404,
            size: 0,
            duration: 0.001,
            ts: 1791400000.0,
        };

        let fp = RequestFingerprint::from_caddy_entry(&entry);
        assert_eq!(fp.ip, "203.0.113.50");
        assert!(fp.has_sec_fetch_mode);
        assert!(fp.has_cookie);
        assert_eq!(fp.sec_fetch_triplet, "navigate|document|none");
        assert_eq!(fp.status, 404);
        // URI /wp-login.php triggers VulnScanner before Sec-Fetch check
        assert_eq!(classify(&fp), EntityId::VulnScanner);
    }
}
