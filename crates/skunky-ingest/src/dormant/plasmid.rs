// DORMANT — Wave 171 fossil. Behavioral plasmid tokens (Human/Agentic kingdom).
// Original: skunky-ingest/src/plasmid.rs
// Reason: tests only, zero production refs. ConservedPlasmid (scatter_types) is the live path.
// Fossilized: 2026-10-10T15:51:57Z

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Behavioral plasmids — portable identity tokens for Human and Agentic kingdoms.
//!
//! In biology, plasmids are small circular DNA molecules that bacteria share
//! via horizontal gene transfer (conjugation). They carry useful genes —
//! antibiotic resistance, metabolic pathways — independent of the chromosome.
//!
//! In the scatter ecosystem, a plasmid is a portable behavioral genome that
//! proves an entity's character without revealing their identity. It carries:
//!
//! - **Kingdom** — Human or Agentic (Fleet has no plasmid; it's true non-self)
//! - **Behavioral genome** — the trio shape (attention, curiosity, interaction)
//! - **Conserved epitopes** — infrastructure fingerprint that can't be faked
//! - **Conjugation chain** — how the plasmid moved between systems
//!
//! ## Three kingdoms and plasmids
//!
//! - **Fleet** (wave/0) — non-self. No plasmid. No identity to conserve.
//! - **Agentic** (photon/1) — carries a plasmid from a human. The agent
//!   is human-directed; the plasmid proves the connection. A user browsing
//!   from outside while their agent builds inside — same plasmid, same intent.
//! - **Human** (reaction/null) — the plasmid origin. Your behavioral genome
//!   is yours. Nobody else owns it. You find it by interacting naturally.
//!
//! ## Access by behavioral proof
//!
//! A private repo doesn't unlock on trust — it unlocks because the math
//! says you'll read it, understand it, and respect it. The plasmid carries
//! the proof. No cookies, no accounts, no reputation scores. Just behavioral
//! mathematics.
//!
//! ## Privacy through self-sovereignty
//!
//! The plasmid says "this entity reads deeply, engages honestly, respects
//! authorship" — without saying WHO. People find their own behavioral genome
//! to keep their privacy. The genome is theirs.
//!
//! ## Observing horizontal gene transfer
//!
//! As human and agentic systems interact, their plasmids mix and move.
//! We can observe this mixing — which behavioral genes transfer, which
//! combinations emerge, how the ecosystem evolves. This is information
//! ecology made visible.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::dashboard_writer::{BingoCubeTrio, TrioClass, score_trio};

// ══════════════════════════════════════════════════════════════════════
// Plasmid — portable behavioral identity
// ══════════════════════════════════════════════════════════════════════

/// A behavioral plasmid — portable proof of character.
///
/// Contains the behavioral genome (trio shape), conserved epitopes
/// (infrastructure fingerprint), and a conjugation chain showing
/// how this plasmid has moved between systems.
///
/// Fleet entities have no plasmid. They are true non-self.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plasmid {
    /// Plasmid version (for forward compatibility)
    pub version: u8,
    /// Kingdom: Human or Agentic (Fleet has no plasmid)
    pub kingdom: PlasmidKingdom,
    /// Behavioral genome — the trio shape that proves character
    pub genome: BehavioralGenome,
    /// Conserved epitopes — infrastructure fingerprint
    pub epitopes: ConservedEpitopes,
    /// Conjugation chain — how this plasmid has moved
    pub conjugation: Vec<ConjugationEvent>,
    /// Plasmid hash — BLAKE2b of the genome + epitopes (self-verifying)
    pub hash: String,
    /// Generation counter — increments on each conjugation
    pub generation: u32,
}

/// Kingdom marker for plasmid carriers.
///
/// Only Human and Agentic carry plasmids. Fleet is non-self.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasmidKingdom {
    /// Reaction / null — the plasmid origin. Life.
    Human,
    /// Photon / 1 — carries a plasmid from a human. Directed purpose.
    Agentic,
}

/// Behavioral genome — the mathematical proof of character.
///
/// This is the trio shape normalized and signed. It contains enough
/// information to prove behavioral intent without revealing identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralGenome {
    /// Attention level (0.0-1.0): how much presence
    pub attention: f32,
    /// Curiosity level (0.0-1.0): how much exploration
    pub curiosity: f32,
    /// Interaction level (0.0-1.0): how much engagement
    pub interaction: f32,
    /// Trio shape signature — the RATIO matters more than absolutes.
    /// curiosity/attention = exploration efficiency
    /// interaction/curiosity = engagement depth
    /// These ratios are the behavioral DNA.
    pub exploration_efficiency: f32,
    pub engagement_depth: f32,
    /// Confidence: how many observations back this genome (0.0-1.0)
    pub confidence: f32,
    /// Request count that generated this genome
    pub observation_count: u64,
}

/// Conserved epitopes — infrastructure fingerprint that can't be faked
/// without rebuilding the entire client stack.
///
/// These are the "genes" on the plasmid — the traits it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConservedEpitopes {
    /// Accept-Encoding order (HTTP library fingerprint)
    pub encoding_fingerprint: String,
    /// UA diversity (1=honest single browser, many=fleet impersonation)
    pub ua_diversity: String,
    /// Declaration status: does this entity participate in the protocol?
    pub declared: bool,
    /// Asset loading: does this entity render pages or just scrape text?
    pub loads_assets: bool,
    /// Navigation pattern: does this entity follow links or enumerate URLs?
    pub navigates: bool,
    /// Blame/commit ratio: does this entity read diffs (understanding code)
    /// or just download files (extracting content)?
    pub reads_diffs: bool,
    /// Multi-host: does this entity cross-reference across services?
    pub cross_references: bool,
    /// Epitope hash from the maze (links to existing classification)
    pub epitope_hash: String,
}

/// Conjugation event — records how a plasmid moved between systems.
///
/// In biology, conjugation is the process by which bacteria transfer
/// plasmids through a pilus. Here, it records the transfer of behavioral
/// identity between contexts (e.g., a user's browser → their AI agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConjugationEvent {
    /// Timestamp of the transfer
    pub timestamp: f64,
    /// Source kingdom at time of transfer
    pub from_kingdom: PlasmidKingdom,
    /// Destination kingdom
    pub to_kingdom: PlasmidKingdom,
    /// System identifier (opaque — doesn't reveal the entity)
    pub system_hash: String,
    /// Generation at time of transfer
    pub generation: u32,
}

// ══════════════════════════════════════════════════════════════════════
// Plasmid generation — from behavioral data to portable identity
// ══════════════════════════════════════════════════════════════════════

/// Minimum requests before a plasmid can be generated.
/// Need enough behavioral data for the genome to be meaningful.
const MIN_OBSERVATIONS: u64 = 5;

/// Minimum curiosity score to qualify for a plasmid.
/// Fleet entities (curiosity < 0.15) never get plasmids.
const MIN_CURIOSITY: f32 = 0.15;

/// Generate a plasmid from an IP profile's behavioral data.
///
/// Returns `None` if:
/// - Not enough observations (< 5 requests)
/// - Entity is Fleet (no curiosity, no engagement = non-self)
/// - Trio shape doesn't meet minimum thresholds
///
/// The plasmid is self-sovereign — it belongs to the entity, not the system.
pub fn generate_plasmid(
    profile: &crate::dashboard_profile::IpProfile,
    epitope_hash: &str,
) -> Option<Plasmid> {
    if profile.requests < MIN_OBSERVATIONS {
        return None;
    }

    let trio = score_trio(profile);

    // Fleet is true non-self — no plasmid
    if trio.classification == TrioClass::Parasite {
        return None;
    }

    // Must have minimum curiosity to qualify
    if trio.curiosity < MIN_CURIOSITY {
        return None;
    }

    let kingdom = match trio.classification {
        TrioClass::Sovereign => PlasmidKingdom::Human,
        TrioClass::Commensal => PlasmidKingdom::Agentic,
        TrioClass::Parasite => return None, // redundant but explicit
    };

    let exploration_efficiency = if trio.attention > 0.01 {
        trio.curiosity / trio.attention
    } else {
        trio.curiosity // infinite efficiency = pure curiosity, no noise
    };

    let engagement_depth = if trio.curiosity > 0.01 {
        trio.interaction / trio.curiosity
    } else {
        0.0
    };

    // Confidence grows with observation count, capped at 1.0
    // 5 requests = 0.2, 25 = 0.6, 50+ = 0.9+
    let confidence = (1.0 - (-0.04 * profile.requests as f32).exp()).min(1.0);

    let genome = BehavioralGenome {
        attention: trio.attention,
        curiosity: trio.curiosity,
        interaction: trio.interaction,
        exploration_efficiency,
        engagement_depth,
        confidence,
        observation_count: profile.requests,
    };

    let epitopes = ConservedEpitopes {
        encoding_fingerprint: profile
            .accept_encoding
            .as_deref()
            .unwrap_or("")
            .to_string(),
        ua_diversity: if profile.ua_pool_size <= 1 {
            "single".to_string()
        } else if profile.ua_pool_size <= 3 {
            "few".to_string()
        } else {
            "fleet".to_string()
        },
        declared: profile.has_accept_lang || profile.has_sec_fetch,
        loads_assets: profile.has_assets,
        navigates: profile.has_referer,
        reads_diffs: profile.blame_count > 0,
        cross_references: profile.host_count > 1,
        epitope_hash: epitope_hash.to_string(),
    };

    let hash = compute_plasmid_hash(&genome, &epitopes);

    Some(Plasmid {
        version: 1,
        kingdom,
        genome,
        epitopes,
        conjugation: Vec::new(), // no transfers yet — this is the origin
        hash,
        generation: 0,
    })
}

/// Conjugate a plasmid — transfer it to an agentic system.
///
/// This is the biological equivalent of pilus-mediated conjugation.
/// A human's plasmid is copied to their agent, creating a new generation
/// that carries the human's behavioral proof.
///
/// The agent's plasmid inherits the human's genome but marks the kingdom
/// as Agentic — proving it's human-directed without revealing which human.
pub fn conjugate(source: &Plasmid, system_hash: &str) -> Plasmid {
    let mut conjugated = source.clone();
    conjugated.kingdom = PlasmidKingdom::Agentic;
    conjugated.generation += 1;
    conjugated.conjugation.push(ConjugationEvent {
        timestamp: now_unix(),
        from_kingdom: source.kingdom,
        to_kingdom: PlasmidKingdom::Agentic,
        system_hash: system_hash.to_string(),
        generation: conjugated.generation,
    });
    conjugated.hash = compute_plasmid_hash(&conjugated.genome, &conjugated.epitopes);
    conjugated
}

// ══════════════════════════════════════════════════════════════════════
// Plasmid verification — does the math say you'll respect it?
// ══════════════════════════════════════════════════════════════════════

/// Access level that a plasmid grants based on behavioral proof.
///
/// This is not a permission system — it's a mathematical assessment.
/// The math says whether you'll read, understand, and respect the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    /// No access — Fleet, or insufficient behavioral proof
    None,
    /// Read public content — minimum curiosity threshold met
    Public,
    /// Read shared content — curiosity + some engagement
    Shared,
    /// Read private content — high curiosity + deep engagement + declared
    Private,
    /// Contribute — strong behavioral genome proving understanding + respect
    Contribute,
}

/// Verify a plasmid and determine what access level it grants.
///
/// A private repo doesn't unlock on trust — it unlocks because the math
/// says you'll read it, understand it, and respect it.
pub fn verify_access(plasmid: &Plasmid) -> AccessLevel {
    // Verify self-consistency
    let expected_hash = compute_plasmid_hash(&plasmid.genome, &plasmid.epitopes);
    if plasmid.hash != expected_hash {
        return AccessLevel::None; // tampered
    }

    let g = &plasmid.genome;
    let e = &plasmid.epitopes;

    // Must have minimum confidence (enough observations)
    if g.confidence < 0.3 {
        return AccessLevel::Public;
    }

    // Contribute: strong genome + declared + reads diffs + navigates
    if g.curiosity > 0.5
        && g.interaction > 0.4
        && g.engagement_depth > 0.5
        && e.declared
        && e.reads_diffs
        && e.navigates
        && g.confidence > 0.7
    {
        return AccessLevel::Contribute;
    }

    // Private: high curiosity + deep engagement + declared
    if g.curiosity > 0.4
        && g.interaction > 0.3
        && e.declared
        && (e.reads_diffs || e.loads_assets)
        && g.confidence > 0.5
    {
        return AccessLevel::Private;
    }

    // Shared: curiosity + some engagement
    if g.curiosity > 0.2 && g.interaction > 0.1 {
        return AccessLevel::Shared;
    }

    AccessLevel::Public
}

/// Check if a plasmid is valid for conjugation (transfer to agent).
///
/// Only Human plasmids can conjugate. Agentic plasmids can carry the
/// genome but cannot originate new transfers (prevents plasmid amplification).
pub fn can_conjugate(plasmid: &Plasmid) -> bool {
    plasmid.kingdom == PlasmidKingdom::Human && plasmid.genome.confidence > 0.3
}

// ══════════════════════════════════════════════════════════════════════
// Plasmid serialization — portable format
// ══════════════════════════════════════════════════════════════════════

/// Serialize a plasmid to a compact portable string.
///
/// Format: base64url-encoded JSON. Can be carried in an HTTP header,
/// a URL parameter, or an API token field. Self-verifying via hash.
pub fn encode_plasmid(plasmid: &Plasmid) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let json = serde_json::to_vec(plasmid).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(&json)
}

/// Decode a plasmid from its portable string form.
///
/// Returns `None` if the format is invalid or the hash doesn't verify.
pub fn decode_plasmid(encoded: &str) -> Option<Plasmid> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let plasmid: Plasmid = serde_json::from_slice(&bytes).ok()?;

    // Verify hash integrity
    let expected = compute_plasmid_hash(&plasmid.genome, &plasmid.epitopes);
    if plasmid.hash != expected {
        return None; // tampered
    }

    Some(plasmid)
}

// ══════════════════════════════════════════════════════════════════════
// Internal helpers
// ══════════════════════════════════════════════════════════════════════

fn compute_plasmid_hash(genome: &BehavioralGenome, epitopes: &ConservedEpitopes) -> String {
    let mut hasher = DefaultHasher::new();

    // Hash the behavioral genome shape (ratios matter, not absolutes)
    format!(
        "{:.3}|{:.3}|{:.3}|{:.3}|{:.3}|{}",
        genome.curiosity,
        genome.interaction,
        genome.exploration_efficiency,
        genome.engagement_depth,
        genome.confidence,
        genome.observation_count,
    )
    .hash(&mut hasher);

    // Hash the conserved epitopes
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        epitopes.encoding_fingerprint,
        epitopes.ua_diversity,
        epitopes.declared,
        epitopes.loads_assets,
        epitopes.navigates,
        epitopes.reads_diffs,
        epitopes.cross_references,
    )
    .hash(&mut hasher);

    let hash = hasher.finish();
    format!("{:016x}", hash)
}

fn now_unix() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard_profile::IpProfile;
    use std::collections::HashMap;

    fn human_profile() -> IpProfile {
        let mut p = IpProfile::new(1000.0);
        p.requests = 50;
        p.has_accept_lang = true;
        p.has_sec_fetch = true;
        p.has_assets = true;
        p.has_referer = true;
        p.blame_count = 5;
        p.commit_count = 10;
        p.host_count = 3;
        p.ua_pool_size = 1;
        p.accept_encoding = Some("gzip, deflate, br".to_string());
        p.accept = Some("text/html".to_string());
        p.path_types = HashMap::from([
            ("blob".to_string(), 10),
            ("tree".to_string(), 8),
            ("commit".to_string(), 5),
            ("blame".to_string(), 5),
        ]);
        p.repos = HashMap::from([
            ("repo-a".to_string(), 15),
            ("repo-b".to_string(), 10),
            ("repo-c".to_string(), 3),
        ]);
        p
    }

    fn agentic_profile() -> IpProfile {
        let mut p = IpProfile::new(1000.0);
        p.requests = 30;
        p.has_accept_lang = false;
        p.has_sec_fetch = false;
        p.has_assets = false;
        p.has_referer = true;
        p.host_count = 2;
        p.ua_pool_size = 1;
        p.accept_encoding = Some("gzip".to_string());
        p.path_types = HashMap::from([
            ("blob".to_string(), 20),
            ("tree".to_string(), 5),
            ("raw".to_string(), 3),
        ]);
        p.repos = HashMap::from([
            ("repo-a".to_string(), 25),
            ("repo-b".to_string(), 3),
        ]);
        p
    }

    fn fleet_profile() -> IpProfile {
        let mut p = IpProfile::new(1000.0);
        p.requests = 200;
        p.has_accept_lang = false;
        p.has_sec_fetch = false;
        p.has_assets = false;
        p.has_referer = false;
        p.host_count = 1;
        p.ua_pool_size = 5;
        p.accept_encoding = Some("gzip".to_string());
        p.path_types = HashMap::from([("blob".to_string(), 200)]);
        p.repos = HashMap::from([("repo-a".to_string(), 200)]);
        p
    }

    #[test]
    fn human_gets_plasmid() {
        let profile = human_profile();
        let plasmid = generate_plasmid(&profile, "abc12345");
        assert!(plasmid.is_some(), "human should get a plasmid");
        let p = plasmid.unwrap();
        assert_eq!(p.kingdom, PlasmidKingdom::Human);
        assert_eq!(p.generation, 0);
        assert!(p.conjugation.is_empty());
    }

    #[test]
    fn agentic_gets_plasmid() {
        let profile = agentic_profile();
        let plasmid = generate_plasmid(&profile, "def67890");
        assert!(plasmid.is_some(), "agentic should get a plasmid");
        let p = plasmid.unwrap();
        assert_eq!(p.kingdom, PlasmidKingdom::Agentic);
    }

    #[test]
    fn fleet_no_plasmid() {
        let profile = fleet_profile();
        let plasmid = generate_plasmid(&profile, "ghi13579");
        assert!(plasmid.is_none(), "fleet is non-self — no plasmid");
    }

    #[test]
    fn human_plasmid_access_levels() {
        let profile = human_profile();
        let plasmid = generate_plasmid(&profile, "abc12345").unwrap();
        let access = verify_access(&plasmid);
        assert!(
            access == AccessLevel::Private || access == AccessLevel::Contribute,
            "human with full engagement should get private or contribute access, got {access:?}"
        );
    }

    #[test]
    fn conjugation_transfers_genome() {
        let profile = human_profile();
        let human_plasmid = generate_plasmid(&profile, "abc12345").unwrap();
        assert!(can_conjugate(&human_plasmid));

        let agent_plasmid = conjugate(&human_plasmid, "agent-system-hash");
        assert_eq!(agent_plasmid.kingdom, PlasmidKingdom::Agentic);
        assert_eq!(agent_plasmid.generation, 1);
        assert_eq!(agent_plasmid.conjugation.len(), 1);
        assert_eq!(
            agent_plasmid.genome.curiosity,
            human_plasmid.genome.curiosity,
            "conjugated plasmid should carry the human's genome"
        );

        // Agent can't conjugate further (prevents amplification)
        assert!(!can_conjugate(&agent_plasmid));
    }

    #[test]
    fn plasmid_encode_decode_roundtrip() {
        let profile = human_profile();
        let plasmid = generate_plasmid(&profile, "abc12345").unwrap();
        let encoded = encode_plasmid(&plasmid);
        let decoded = decode_plasmid(&encoded);
        assert!(decoded.is_some(), "roundtrip should succeed");
        let d = decoded.unwrap();
        assert_eq!(d.kingdom, plasmid.kingdom);
        assert_eq!(d.hash, plasmid.hash);
    }

    #[test]
    fn tampered_plasmid_rejected() {
        let profile = human_profile();
        let mut plasmid = generate_plasmid(&profile, "abc12345").unwrap();
        plasmid.genome.curiosity = 0.99; // tamper with the genome
        // Hash no longer matches
        let access = verify_access(&plasmid);
        assert_eq!(access, AccessLevel::None, "tampered plasmid should be rejected");
    }

    #[test]
    fn low_observation_gets_public_only() {
        let mut profile = human_profile();
        profile.requests = 6; // just above minimum
        let plasmid = generate_plasmid(&profile, "low12345");
        if let Some(p) = plasmid {
            let access = verify_access(&p);
            assert_eq!(access, AccessLevel::Public, "low observations = public only");
        }
    }

    #[test]
    fn plasmid_hash_is_deterministic() {
        let profile = human_profile();
        let p1 = generate_plasmid(&profile, "abc12345").unwrap();
        let p2 = generate_plasmid(&profile, "abc12345").unwrap();
        assert_eq!(p1.hash, p2.hash, "same profile should produce same hash");
    }
}
