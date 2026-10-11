// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Surface registry — single source of truth for surface metadata.
//!
//! Previously scattered across `page_mirror.rs` (SURFACE_NAMES, DOMAIN_MAP)
//! and `visitor_archetype.rs` (IMMUNE_SURFACES, EVIDENCE_SURFACES, SCIENCE_SURFACES).
//!
//! One table, one truth. The epitope sort says: if three modules keep
//! reinventing the same knowledge independently, the knowledge wants
//! to be born as its own module.
//!
//! Every surface in the organism gets:
//! - A machine key (e.g. "cytokine")
//! - A human name (e.g. "Cytokine")
//! - A content domain (e.g. Immune)
//!
//! Domain groups (immune, evidence, science) are derived from the domain,
//! not maintained as separate lists.

use cellmembrane_types::campfire::ContentDomain;

/// A surface entry — one organ of the organism.
struct Entry {
    key: &'static str,
    name: &'static str,
    domain: ContentDomain,
}

/// The registry. Sorted by domain then alphabetically.
const REGISTRY: &[Entry] = &[
    // Evidence surfaces
    Entry { key: "cashforkids", name: "CashForKids", domain: ContentDomain::Evidence },
    Entry { key: "clutch", name: "Clutch", domain: ContentDomain::Evidence },
    Entry { key: "detroit", name: "Detroit Evidence", domain: ContentDomain::Evidence },
    Entry { key: "evidence", name: "Evidence Archive", domain: ContentDomain::Evidence },
    Entry { key: "tuebor", name: "Tuebor", domain: ContentDomain::Evidence },
    // Immune surfaces
    Entry { key: "antibody", name: "Antibody", domain: ContentDomain::Immune },
    Entry { key: "antigen", name: "Antigen", domain: ContentDomain::Immune },
    Entry { key: "bloom", name: "Bloom", domain: ContentDomain::Immune },
    Entry { key: "complement", name: "Complement", domain: ContentDomain::Immune },
    Entry { key: "cytokine", name: "Cytokine", domain: ContentDomain::Immune },
    Entry { key: "epitope", name: "Epitope", domain: ContentDomain::Immune },
    Entry { key: "interferon", name: "Interferon", domain: ContentDomain::Immune },
    Entry { key: "lysozyme", name: "Lysozyme", domain: ContentDomain::Immune },
    Entry { key: "macrophage", name: "Macrophage", domain: ContentDomain::Immune },
    Entry { key: "monitor", name: "Monitor", domain: ContentDomain::Immune },
    Entry { key: "opsonize", name: "Opsonize", domain: ContentDomain::Immune },
    Entry { key: "receptor", name: "Receptor", domain: ContentDomain::Immune },
    Entry { key: "thymus", name: "Thymus", domain: ContentDomain::Immune },
    // Infrastructure
    Entry { key: "beacon", name: "Beacon", domain: ContentDomain::Infrastructure },
    Entry { key: "hud", name: "HUD", domain: ContentDomain::Infrastructure },
    Entry { key: "layer2", name: "Layer2", domain: ContentDomain::Infrastructure },
    Entry { key: "signal", name: "Signal", domain: ContentDomain::Infrastructure },
    // Science
    Entry { key: "sporeprint", name: "sporePrint", domain: ContentDomain::Science },
    // Source
    Entry { key: "git", name: "Forge", domain: ContentDomain::Source },
];

/// The host suffix to strip when extracting surface keys.
const HOST_SUFFIX: &str = ".primals.eco";

/// Strip the `.primals.eco` suffix from a hostname to get the surface key.
///
/// # Examples
///
/// ```rust,ignore
/// assert_eq!(strip_host("cytokine.primals.eco"), "cytokine");
/// assert_eq!(strip_host("unknown.example.com"), "unknown.example.com");
/// ```
pub fn strip_host(host: &str) -> &str {
    host.strip_suffix(HOST_SUFFIX).unwrap_or(host)
}

/// Look up the human-readable name for a surface key.
///
/// Returns the key itself if not in the registry.
pub fn surface_name(key: &str) -> &str {
    REGISTRY.iter()
        .find(|e| e.key == key)
        .map(|e| e.name)
        .unwrap_or(key)
}

/// Look up the content domain for a surface key.
///
/// Returns `ContentDomain::Other` if not in the registry.
pub fn surface_domain(key: &str) -> ContentDomain {
    REGISTRY.iter()
        .find(|e| e.key == key)
        .map(|e| e.domain)
        .unwrap_or(ContentDomain::Other)
}

/// Whether a surface key belongs to the immune domain.
pub fn is_immune(key: &str) -> bool {
    surface_domain(key) == ContentDomain::Immune
}

/// Whether a surface key belongs to the evidence domain.
pub fn is_evidence(key: &str) -> bool {
    surface_domain(key) == ContentDomain::Evidence
}

/// Whether a surface key belongs to the science domain.
pub fn is_science(key: &str) -> bool {
    surface_domain(key) == ContentDomain::Science
}

/// Count how many of the given surface keys belong to a domain.
pub fn domain_count(keys: &[&str], domain: ContentDomain) -> usize {
    keys.iter().filter(|k| surface_domain(k) == domain).count()
}

/// Endpoints that indicate polling behavior (watching, not exploring).
pub const POLL_ENDPOINTS: &[&str] = &[
    "dashboard.json", "billboard", "topology.json",
    "epitope-history.json", "visitor-stories.json",
    "page-stories.json", "campfire.json",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_host_known() {
        assert_eq!(strip_host("cytokine.primals.eco"), "cytokine");
        assert_eq!(strip_host("detroit.primals.eco"), "detroit");
        assert_eq!(strip_host("git.primals.eco"), "git");
    }

    #[test]
    fn strip_host_unknown() {
        assert_eq!(strip_host("something.example.com"), "something.example.com");
        assert_eq!(strip_host("bare"), "bare");
    }

    #[test]
    fn name_lookup() {
        assert_eq!(surface_name("git"), "Forge");
        assert_eq!(surface_name("detroit"), "Detroit Evidence");
        assert_eq!(surface_name("cytokine"), "Cytokine");
        assert_eq!(surface_name("unknown"), "unknown");
    }

    #[test]
    fn domain_lookup() {
        assert_eq!(surface_domain("detroit"), ContentDomain::Evidence);
        assert_eq!(surface_domain("cytokine"), ContentDomain::Immune);
        assert_eq!(surface_domain("sporeprint"), ContentDomain::Science);
        assert_eq!(surface_domain("git"), ContentDomain::Source);
        assert_eq!(surface_domain("hud"), ContentDomain::Infrastructure);
        assert_eq!(surface_domain("nope"), ContentDomain::Other);
    }

    #[test]
    fn domain_predicates() {
        assert!(is_immune("cytokine"));
        assert!(is_immune("thymus"));
        assert!(!is_immune("detroit"));

        assert!(is_evidence("detroit"));
        assert!(is_evidence("cashforkids"));
        assert!(!is_evidence("cytokine"));

        assert!(is_science("sporeprint"));
        assert!(!is_science("detroit"));
    }

    #[test]
    fn domain_count_works() {
        let keys = ["cytokine", "thymus", "detroit", "git", "bloom"];
        assert_eq!(domain_count(&keys, ContentDomain::Immune), 3);
        assert_eq!(domain_count(&keys, ContentDomain::Evidence), 1);
        assert_eq!(domain_count(&keys, ContentDomain::Source), 1);
    }

    #[test]
    fn registry_no_dupes() {
        let mut seen = std::collections::HashSet::new();
        for entry in REGISTRY {
            assert!(seen.insert(entry.key), "duplicate key: {}", entry.key);
        }
    }

    #[test]
    fn monitor_is_immune() {
        // Verify monitor stayed in immune domain (was in IMMUNE_SURFACES)
        assert!(is_immune("monitor"));
    }
}
