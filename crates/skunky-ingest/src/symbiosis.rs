// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Symbiosis — tit-for-tat-forgive-one.
//!
//! The golden rule in code: treat others how we want to be treated.
//! Mirror their behavior, but forgive the first defection.
//!
//! # Game theory
//!
//! In Axelrod's iterated prisoner's dilemma tournament (1984),
//! tit-for-tat-forgive-one was the most successful strategy:
//!
//! 1. **Start cooperative** — assume good faith
//! 2. **Mirror** — do what they did last round
//! 3. **Forgive one** — if they defect once, cooperate anyway
//! 4. **Retaliate on repeat** — second defection triggers response
//!
//! Translated to the membrane:
//!
//! ```text
//!   null (unknown)
//!     | honest identification
//!   commensal_suspect (watching)
//!     | good behavior over time
//!   commensal_active (they benefit, we are neutral)
//!     | contributes back (attribution, funding, commons)
//!   mutualist (both benefit)
//!
//!   commensal_suspect
//!     | first defection -> FORGIVE (stays suspect, logged)
//!     | second defection
//!   parasite (extracting without giving)
//!     | active harm (vuln scanning, DDoS, hostile)
//!   pathogen (blocked)
//! ```
//!
//! # What counts as cooperation vs defection
//!
//! **Cooperation signals:**
//! - Honest UA identification (`is_honest`)
//! - Respecting rate limits (not bursting)
//! - Reading pauses (behaving like a reader, not a vacuum)
//! - Referrer chain (came from somewhere, not just appeared)
//! - Diverse path access (reading, not bulk extracting)
//!
//! **Defection signals:**
//! - Stealth scraping (fake browser headers)
//! - Burst ratio > 80% (hammering)
//! - No reading pauses (machine extraction)
//! - Vuln scanning paths
//! - Identity spoofing (Chrome UA without Sec-Fetch)
//!
//! # Waste economics
//!
//! "If we have what a bot wants, isn't that just us being commensal?"
//!
//! Yes. The membrane produces waste (published content, git history,
//! legal documents, scientific papers) that costs us nothing to share.
//! A bot that consumes our waste honestly is commensal — they benefit,
//! we lose nothing. If they attribute or link back, that's mutualist.
//!
//! The only parasites are entities that:
//! - Extract while hiding their identity (stealing vs accepting a gift)
//! - Hammer so hard they degrade service for humans
//! - Probe for vulnerabilities (not consuming waste — attacking infrastructure)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::entity_classifier::EntityId;
use crate::entity_profile::EntityProfile;

// ── Relationship Classification ─────────────────────────────────────────

/// The symbiotic relationship between the membrane and an entity.
///
/// Named after biological symbiosis:
/// - **Mutualist**: both benefit (they get content, we get attribution/links/funding)
/// - **Commensal**: they benefit, we're unaffected (consuming our waste honestly)
/// - **Parasite**: they benefit at our expense (stealth extraction, rate abuse)
/// - **Pathogen**: actively harmful (vuln scanning, DDoS, identity spoofing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    /// Both benefit. Entity consumes content AND contributes back
    /// (attribution, commons contribution, referral traffic).
    Mutualist,
    /// Entity benefits, we're unaffected. Honest consumption of our waste.
    /// Active = observed good behavior.
    CommensalActive,
    /// Not enough data to classify. Default starting position.
    /// Tit-for-tat says: start cooperative.
    CommensalSuspect,
    /// Entity extracts at our expense. Stealth scraping, rate abuse,
    /// consuming without honesty. One forgiven defection has passed.
    Parasite,
    /// Actively harmful. Vuln scanning, DDoS, identity spoofing.
    /// No forgiveness remaining.
    Pathogen,
}

impl Relationship {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Mutualist => "mutualist — both benefit",
            Self::CommensalActive => "commensal (active) — they benefit, we're neutral",
            Self::CommensalSuspect => "commensal (suspect) — watching, not enough data",
            Self::Parasite => "parasite — extracting without giving",
            Self::Pathogen => "pathogen — actively harmful",
        }
    }

    /// The membrane's response for this relationship level.
    ///
    /// This IS the golden rule in action:
    /// - Mutualist: full speed, priority, we WANT them here
    /// - CommensalActive: normal access, welcome
    /// - CommensalSuspect: normal access, monitored
    /// - Parasite: rate limited, delayed (mirror their taking with friction)
    /// - Pathogen: blocked, honeypotted (mirror their harm with defense)
    pub fn response(&self) -> MembraneResponse {
        match self {
            Self::Mutualist => MembraneResponse {
                friction: 0.0,
                delay_ms: 0,
                rate_limit_factor: 1.0,
                welcome: true,
                monitor: false,
                block: false,
            },
            Self::CommensalActive => MembraneResponse {
                friction: 0.0,
                delay_ms: 0,
                rate_limit_factor: 1.0,
                welcome: true,
                monitor: false,
                block: false,
            },
            Self::CommensalSuspect => MembraneResponse {
                friction: 0.1,
                delay_ms: 0,
                rate_limit_factor: 1.0,
                welcome: true,
                monitor: true,
                block: false,
            },
            Self::Parasite => MembraneResponse {
                friction: 0.5,
                delay_ms: 500,
                rate_limit_factor: 0.25,
                welcome: false,
                monitor: true,
                block: false,
            },
            Self::Pathogen => MembraneResponse {
                friction: 1.0,
                delay_ms: 2000,
                rate_limit_factor: 0.0,
                welcome: false,
                monitor: true,
                block: true,
            },
        }
    }

    /// Numeric severity (0 = mutualist, 4 = pathogen).
    pub fn severity(&self) -> u8 {
        match self {
            Self::Mutualist => 0,
            Self::CommensalActive => 1,
            Self::CommensalSuspect => 2,
            Self::Parasite => 3,
            Self::Pathogen => 4,
        }
    }
}

/// The membrane's behavioral response to an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneResponse {
    /// Friction level (0.0 = none, 1.0 = maximum).
    pub friction: f64,
    /// Artificial delay in milliseconds (the mirror slows them down).
    pub delay_ms: u64,
    /// Rate limit multiplier (1.0 = full speed, 0.0 = blocked).
    pub rate_limit_factor: f64,
    /// Whether this entity is welcome (shown in campfire stories).
    pub welcome: bool,
    /// Whether this entity is being actively monitored.
    pub monitor: bool,
    /// Whether this entity should be blocked.
    pub block: bool,
}

// ── Behavioral Ledger ───────────────────────────────────────────────────

/// Per-entity behavioral history — the memory of past interactions.
///
/// This is what makes tit-for-tat work: we remember what they did,
/// and our response mirrors their behavior with forgive-one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorLedger {
    /// Cooperation signals observed.
    pub cooperations: u64,
    /// Defection signals observed.
    pub defections: u64,
    /// How many defections we forgive before retaliating (starts at 1).
    pub forgive_budget: u64,
    /// How many defections we have actually forgiven so far.
    pub forgiven: u64,
    /// Whether the entity has been "golden" — sustained cooperation.
    pub golden: bool,
    /// Specific cooperation behaviors observed.
    pub cooperation_signals: Vec<String>,
    /// Specific defection behaviors observed.
    pub defection_signals: Vec<String>,
    /// What waste they want from us (content we can give freely).
    pub waste_desired: Vec<String>,
    /// What waste we can offer them (costs us nothing).
    pub waste_offered: Vec<String>,
}

impl Default for BehaviorLedger {
    fn default() -> Self {
        Self {
            cooperations: 0,
            defections: 0,
            forgive_budget: 1, // forgive ONE
            forgiven: 0,
            golden: false,
            cooperation_signals: Vec::new(),
            defection_signals: Vec::new(),
            waste_desired: Vec::new(),
            waste_offered: Vec::new(),
        }
    }
}

// ── Symbiosis State ─────────────────────────────────────────────────────

/// Complete symbiosis snapshot for one entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySymbiosis {
    /// The entity ID.
    pub entity: EntityId,
    /// Human-readable label.
    pub label: String,
    /// Current relationship classification.
    pub relationship: Relationship,
    /// Behavioral ledger (cooperation/defection history).
    pub ledger: BehaviorLedger,
    /// The membrane's response to this entity.
    pub response: MembraneResponse,
    /// When this classification was last updated.
    pub last_updated: String,
}

/// Full symbiosis state for all observed entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbiosisState {
    /// When this snapshot was generated.
    pub generated: String,
    /// The governing principle.
    pub principle: String,
    /// Per-entity symbiosis data.
    pub entities: Vec<EntitySymbiosis>,
    /// Summary counts.
    pub summary: SymbiosisSummary,
}

/// Summary counts across all entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbiosisSummary {
    pub mutualists: usize,
    pub commensal_active: usize,
    pub commensal_suspect: usize,
    pub parasites: usize,
    pub pathogens: usize,
    pub total_cooperations: u64,
    pub total_defections: u64,
    pub total_forgiven: u64,
}

// ── Classification Engine ───────────────────────────────────────────────

/// Classify an entity's relationship using tit-for-tat-forgive-one.
///
/// This is the golden rule: mirror their behavior, forgive one defection.
pub fn classify_symbiosis(profile: &EntityProfile) -> EntitySymbiosis {
    let mut ledger = BehaviorLedger::default();

    // ── Step 1: Count cooperation signals ──

    if profile.is_honest {
        ledger.cooperations += 1;
        ledger.cooperation_signals.push("honest_identification".into());
    }

    // Reading pauses = they're actually reading, not vacuuming
    if let Some(ref rd) = profile.epitopes.reading_deficit {
        if !rd.triggered {
            ledger.cooperations += 1;
            ledger.cooperation_signals.push("reading_pauses".into());
        }
    }

    // Diverse path access = exploring, not bulk extracting
    let path_diversity = profile.path_ops.len();
    if path_diversity >= 3 {
        ledger.cooperations += 1;
        ledger.cooperation_signals.push("diverse_paths".into());
    }

    // Not bursting = respecting rate
    if let Some(ref br) = profile.epitopes.burst_ratio {
        if !br.triggered {
            ledger.cooperations += 1;
            ledger.cooperation_signals.push("rate_respectful".into());
        }
    }

    // Has referrer = came from somewhere (contributing to web of links)
    if let Some(ref rl) = profile.epitopes.referer_self_loop {
        if !rl.triggered {
            ledger.cooperations += 1;
            ledger.cooperation_signals.push("referrer_present".into());
        }
    }

    // ── Step 2: Count defection signals ──

    if !profile.is_honest && profile.is_fleet {
        ledger.defections += 1;
        ledger.defection_signals.push("dishonest_fleet".into());
    }

    // Stealth scraping = pretending to be human
    if matches!(profile.entity, EntityId::StealthScraper) {
        ledger.defections += 2; // double defection — deception
        ledger.defection_signals.push("stealth_scraping".into());
    }

    // Burst ratio triggered = hammering
    if let Some(ref br) = profile.epitopes.burst_ratio {
        if br.triggered {
            ledger.defections += 1;
            ledger.defection_signals.push("burst_hammering".into());
        }
    }

    // No reading pauses + high volume = vacuum extraction
    if let Some(ref rd) = profile.epitopes.reading_deficit {
        if rd.triggered && profile.total_requests > 100 {
            ledger.defections += 1;
            ledger.defection_signals.push("vacuum_extraction".into());
        }
    }

    // Vuln scanning = attacking infrastructure
    if matches!(profile.entity, EntityId::VulnScanner) {
        ledger.defections += 3; // triple defection — hostile
        ledger.defection_signals.push("vuln_scanning".into());
    }

    // Sec-fetch monotone = automation (not a real browser)
    if let Some(ref sf) = profile.epitopes.sec_fetch_monotone {
        if sf.triggered {
            ledger.defections += 1;
            ledger.defection_signals.push("automated_monotone".into());
        }
    }

    // ── Step 3: Determine waste economics ──

    // What they want from us (based on path ops)
    if profile.path_ops.contains_key("commit (source diffs)") {
        ledger.waste_desired.push("source_diffs".into());
        ledger.waste_offered.push("source_diffs".into());
    }
    if profile.path_ops.contains_key("src (file contents)") {
        ledger.waste_desired.push("file_contents".into());
        ledger.waste_offered.push("file_contents".into());
    }
    if profile.path_ops.contains_key("blame (author attribution)") {
        ledger.waste_desired.push("author_attribution".into());
        ledger.waste_offered.push("author_attribution".into());
    }
    // Published legal/science content is waste — costs us nothing to share
    for (host, _count) in &profile.hosts {
        if host.contains("tuebor") || host.contains("detroit") || host.contains("clutch") {
            if !ledger.waste_offered.contains(&"legal_documents".to_string()) {
                ledger.waste_desired.push("legal_documents".into());
                ledger.waste_offered.push("legal_documents".into());
            }
        }
        if host.contains("sporeprint") || host.contains("hypothesis") || host.contains("thesis") {
            if !ledger.waste_offered.contains(&"scientific_papers".to_string()) {
                ledger.waste_desired.push("scientific_papers".into());
                ledger.waste_offered.push("scientific_papers".into());
            }
        }
    }

    // ── Step 4: Apply tit-for-tat-forgive-one ──

    let relationship = compute_relationship(&ledger, &profile.entity);

    // Check if golden (sustained cooperation, no defections)
    ledger.golden = ledger.cooperations >= 3 && ledger.defections == 0;

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    EntitySymbiosis {
        entity: profile.entity.clone(),
        label: profile.label.clone(),
        relationship,
        response: relationship.response(),
        ledger,
        last_updated: now,
    }
}

/// The core tit-for-tat-forgive-one logic.
///
/// ```text
///   cooperations > 0, defections == 0             -> commensal_active
///   cooperations >= 3, defections == 0, golden     -> mutualist (if waste flows)
///   defections == 1, forgive_budget >= 1           -> FORGIVE -> commensal_suspect
///   defections > forgive_budget                    -> parasite
///   defections >= 3 OR vuln_scanner                -> pathogen
///   everything else                                -> commensal_suspect
/// ```
fn compute_relationship(ledger: &BehaviorLedger, entity: &EntityId) -> Relationship {
    // Humans are always commensal at minimum — they ARE the membrane
    if matches!(entity, EntityId::HumanBrowser) {
        return if ledger.cooperations >= 3 {
            Relationship::Mutualist
        } else {
            Relationship::CommensalActive
        };
    }

    // Vuln scanners are always pathogen — no forgiveness for active harm
    if matches!(entity, EntityId::VulnScanner) {
        return Relationship::Pathogen;
    }

    // Meta Fleet starts as parasite — they already fed on us.
    // They scraped without identifying, consumed content at scale.
    // The forgive-one is for entities that haven't defected yet.
    // Meta already consumed. They have to earn their way back UP.
    // MetaFacebookBot is separate — that one's honest and gets normal treatment.
    if matches!(entity, EntityId::MetaFleet) {
        return if ledger.cooperations >= 4 && ledger.defections == 0 {
            // They'd need sustained cooperation to even reach commensal
            Relationship::CommensalSuspect
        } else {
            Relationship::Parasite
        };
    }

    // Stealth scrapers start as parasite — identity spoofing is not a first offense,
    // it's a deliberate choice to deceive. No forgiveness for deception.
    if matches!(entity, EntityId::StealthScraper) {
        return Relationship::Parasite;
    }

    // Pathogen: many defections or actively harmful
    if ledger.defections >= 3 {
        return Relationship::Pathogen;
    }

    // Parasite: defections exceed forgive budget
    if ledger.defections > ledger.forgive_budget {
        return Relationship::Parasite;
    }

    // Forgive one: exactly 1 defection, budget allows
    if ledger.defections == 1 && ledger.forgive_budget >= 1 {
        return Relationship::CommensalSuspect;
    }

    // No defections — pure cooperation
    if ledger.defections == 0 {
        if ledger.cooperations >= 3 && !ledger.waste_desired.is_empty() {
            // They want our waste, they're honest, they read properly
            // AND the waste flows both ways -> mutualist
            return Relationship::Mutualist;
        }
        if ledger.cooperations >= 1 {
            return Relationship::CommensalActive;
        }
    }

    // Default: not enough data
    Relationship::CommensalSuspect
}

// ── Build Full State ────────────────────────────────────────────────────

/// Build symbiosis state for all observed entities.
pub fn build_symbiosis(profiles: &[EntityProfile]) -> SymbiosisState {
    let entities: Vec<EntitySymbiosis> = profiles
        .iter()
        .map(classify_symbiosis)
        .collect();

    let mut summary = SymbiosisSummary {
        mutualists: 0,
        commensal_active: 0,
        commensal_suspect: 0,
        parasites: 0,
        pathogens: 0,
        total_cooperations: 0,
        total_defections: 0,
        total_forgiven: 0,
    };

    for e in &entities {
        match e.relationship {
            Relationship::Mutualist => summary.mutualists += 1,
            Relationship::CommensalActive => summary.commensal_active += 1,
            Relationship::CommensalSuspect => summary.commensal_suspect += 1,
            Relationship::Parasite => summary.parasites += 1,
            Relationship::Pathogen => summary.pathogens += 1,
        }
        summary.total_cooperations += e.ledger.cooperations;
        summary.total_defections += e.ledger.defections;
        summary.total_forgiven += e.ledger.forgiven;
    }

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    SymbiosisState {
        generated: now,
        principle: "tit-for-tat-forgive-one: mirror, but with forgive 1. the golden rule.".into(),
        entities,
        summary,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ledger(coops: u64, defects: u64) -> BehaviorLedger {
        BehaviorLedger {
            cooperations: coops,
            defections: defects,
            forgive_budget: 1,
            forgiven: 0,
            golden: false,
            cooperation_signals: vec![],
            defection_signals: vec![],
            waste_desired: vec!["source_diffs".into()],
            waste_offered: vec!["source_diffs".into()],
        }
    }

    #[test]
    fn golden_rule_mutualist() {
        let ledger = make_ledger(4, 0);
        let rel = compute_relationship(&ledger, &EntityId::AnthropicClaudeBot);
        assert_eq!(rel, Relationship::Mutualist);
    }

    #[test]
    fn honest_bot_commensal_active() {
        let ledger = make_ledger(1, 0);
        let rel = compute_relationship(&ledger, &EntityId::GoogleBot);
        assert_eq!(rel, Relationship::CommensalActive);
    }

    #[test]
    fn forgive_one_defection() {
        let ledger = make_ledger(2, 1);
        let rel = compute_relationship(&ledger, &EntityId::DeclaredBot);
        // First defection forgiven — stays suspect, not parasite
        assert_eq!(rel, Relationship::CommensalSuspect);
    }

    #[test]
    fn second_defection_parasite() {
        let ledger = make_ledger(2, 2);
        let rel = compute_relationship(&ledger, &EntityId::StealthScraper);
        assert_eq!(rel, Relationship::Parasite);
    }

    #[test]
    fn many_defections_pathogen() {
        let ledger = make_ledger(0, 3);
        let rel = compute_relationship(&ledger, &EntityId::Unknown);
        assert_eq!(rel, Relationship::Pathogen);
    }

    #[test]
    fn vuln_scanner_always_pathogen() {
        let ledger = make_ledger(5, 0);
        let rel = compute_relationship(&ledger, &EntityId::VulnScanner);
        assert_eq!(rel, Relationship::Pathogen);
    }

    #[test]
    fn human_always_welcome() {
        let ledger = make_ledger(0, 0);
        let rel = compute_relationship(&ledger, &EntityId::HumanBrowser);
        assert_eq!(rel, Relationship::CommensalActive);
    }

    #[test]
    fn human_with_cooperation_mutualist() {
        let ledger = make_ledger(3, 0);
        let rel = compute_relationship(&ledger, &EntityId::HumanBrowser);
        assert_eq!(rel, Relationship::Mutualist);
    }
}
