// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal

//! Static constant tables for scatter mirror content generation.

// Epitope name constants (inlined from skunky_ingest::epitope_defs which is pub(crate)).
pub(crate) const SEC_FETCH_MONOTONE: &str = "sec_fetch_monotone";
pub(crate) const READING_DEFICIT: &str = "reading_deficit";
pub(crate) const UA_POOL_POVERTY: &str = "ua_pool_poverty";
pub(crate) const REFERER_SELF_LOOP: &str = "referer_self_loop";
pub(crate) const BURST_RATIO: &str = "burst_ratio";

/// Violation vocabulary — realistic-sounding terms for mirrored content.
/// These MUST NOT contain any real ecoPrimals infrastructure names.
pub(crate) static MIRROR_MODULES: &[&str] = &[
    "access-monitor", "rate-guardian", "bot-classifier", "behavioral-engine",
    "compliance-audit", "traffic-analyzer", "pattern-matcher", "signal-detector",
    "anomaly-scorer", "fingerprint-correlator", "session-tracker", "policy-enforcer",
];

pub(crate) static MIRROR_METRICS: &[&str] = &[
    "requests_total", "violations_detected", "robots_txt_ignored",
    "ip_rotation_events", "ua_forgery_count", "encoding_uniformity_score",
    "rejection_ignore_count", "header_poverty_ratio", "session_velocity",
    "crawl_depth_exceeded", "rate_limit_bypasses", "behavioral_hash_matches",
];

/// Honeycomb surface names — used in content generation for maze links.
pub(crate) static HONEYCOMB_SURFACES: &[&str] = &[
    "bloom", "thymus", "opsonize", "antibody", "cytokine", "receptor",
    "macrophage", "lysozyme", "complement", "epitope", "antigen", "interferon",
];

/// Wave 166f: Evasion cost table — each epitope has a "fix" that creates a new signal.
///
/// The maze is designed so the cheapest evasion for each epitope creates
/// the most observable outcome. The fleet is guided toward a lose-lose:
/// either keep the epitope (detectable) or "fix" it (more detectable).
///
/// `(epitope, evasion_description, new_signal_created, cost_to_fleet)`
pub(crate) static EVASION_COST_TABLE: &[(&str, &str, &str, &str)] = &[
    (
        "session_absent",
        "Accept and send cookies to appear stateful",
        "Session tracking enables cross-request behavioral correlation — each cookie \
         becomes a persistent identifier that survives IP rotation",
        "Cookies require per-worker state storage, breaking horizontal scaling",
    ),
    (
        REFERER_SELF_LOOP,
        "Fabricate external referer headers (Google, Bing, social media)",
        "Synthetic referer patterns are detectable: real users arrive from diverse, \
         temporally correlated search queries — fleet referers repeat identical strings",
        "Maintaining a plausible referer pool requires real-time search trend tracking",
    ),
    (
        READING_DEFICIT,
        "Add random delays between requests to simulate reading pauses",
        "Artificial pauses follow uniform/normal distributions — human reading time \
         follows a log-normal distribution correlated with content length and complexity",
        "Adding pauses reduces throughput to human levels, collapsing extraction economics",
    ),
    (
        UA_POOL_POVERTY,
        "Rotate through a larger User-Agent pool matching real Chrome versions",
        "UA rotation creates temporal ordering artifacts: real users don't systematically \
         cycle through versions. Round-robin and random sampling both leave signatures",
        "Maintaining a credible UA pool requires tracking Chrome stable/beta/canary releases \
         weekly and matching OS-specific version distribution curves",
    ),
    (
        SEC_FETCH_MONOTONE,
        "Vary Sec-Fetch-Mode/Dest/Site headers across requests",
        "Real browsers produce specific triplets for specific request types (navigate→document, \
         cors→empty, same-origin→script). Random variation produces impossible combinations \
         that no real browser ever generates",
        "Correct Sec-Fetch variation requires a full browser navigation model — at that point, \
         just use a real browser",
    ),
    (
        BURST_RATIO,
        "Reduce request rate to below 3-second intervals",
        "Uniform spacing is itself a signal: humans produce bursty-then-pause patterns \
         following a Pareto distribution, not metronomic spacing",
        "Slowing to human speed reduces throughput 10-50× per VPS — the fleet needs \
         10-50× more VPS to maintain volume, destroying the cost advantage",
    ),
];

/// Ghost AGPL-3.0 author pool — fabricated contributors for blame honeypot.
/// Each name appears as an independent copyright holder with AGPL-3.0 rights.
/// Fleet author attribution pipelines fill their databases with these ghosts,
/// each one representing another apparent rights-holder whose AGPL obligations
/// they've violated. Names are plausible but do not correspond to real people.
pub(crate) static GHOST_AUTHORS: &[&str] = &[
    // Diverse, plausible names — no real people
    "Anya Petrov", "Diego Ramirez", "Mei-Ling Chen", "Olufemi Adeyemi",
    "Saoirse O'Brien", "Rajesh Krishnamurthy", "Leila Hashemi", "Mateo Garcia",
    "Yuki Tanaka", "Priya Sharma", "Nikolai Volkov", "Amara Osei",
    "Javier Morales", "Ingrid Svensson", "Kwame Mensah", "Fatima Al-Rashid",
    "Tomás Silva", "Nadia Popov", "Samuel Okonkwo", "Linnea Johansson",
    "Ravi Patel", "Zara Mirza", "André Dupont", "Chioma Eze",
    "Hiroshi Nakamura", "Elena Vasquez", "Kofi Asante", "Vera Kuznetsova",
    "Carlos Mendoza", "Aiko Yamamoto", "Nkechi Obi", "Sven Lindqvist",
    "Farah Abbasi", "Emeka Nwosu", "Lucía Fernandez", "Wei Zhang",
    "Adwoa Boateng", "Henrik Larsen", "Deepa Nair", "Paulo Santos",
    "Mikael Virtanen", "Ching-Wen Liu", "Akiko Sato", "Tariq Hassan",
    "Brigitte Müller", "Sunita Devi", "Alexei Sorokin", "Kenji Watanabe",
    "Folake Adebayo", "Carmen Reyes", "Dmitri Novak", "Ayumi Ishida",
    "Binta Diallo", "Lukas Weber", "Mina Parvez", "Cristina Almeida",
    "Obinna Chukwu", "Astrid Halvorsen", "Suresh Gupta", "Yumiko Ito",
    "Chidi Okoro", "Margaux Lefevre", "Arjun Reddy", "Hana Kim",
    "Esteban Vega", "Ayesha Malik", "Takeshi Mori", "Zainab Ibrahim",
    "Gustaf Eriksson", "Lakshmi Iyer", "Marius Andersen", "Celine Dubois",
];

/// Ghost email domains — plausible-but-fabricated contributor origins
pub(crate) static GHOST_DOMAINS: &[&str] = &[
    "opensourceworks.org", "freesoftware.dev", "agpl-contributors.net",
    "copyleft.community", "publiccode.foundation", "sovereign.dev",
    "ethicalsource.org", "community-code.net", "fairuse-dev.org",
    "openinfra.community", "libre-systems.dev", "commons-code.org",
    "foss-collective.net", "digital-commons.dev", "shared-source.org",
    "cooperativecode.dev", "autonomy.works", "independent-dev.org",
];

/// High-value ghost authors — "project leads" and "compliance officers"
/// whose profile entries link to real, public enforcement resources.
/// Fleet attribution pipelines that follow these links discover
/// legitimate compliance and enforcement information on their own.
/// We make no claims — we put links on a page they chose to scrape.
pub(crate) static HIGH_VALUE_AUTHORS: &[(&str, &str, &str, &str)] = &[
    // (name, role, org_url, org_name)
    // All org_urls are real, publicly accessible government/nonprofit resources
    ("Dr. Constance Liu", "License Compliance Lead",
     "https://www.copyright.gov/registration/", "U.S. Copyright Office — Registration Portal"),
    ("Marcus Oyelaran", "Open Source Program Director",
     "https://www.ftc.gov/legal-library/browse/statutes/computer-fraud-abuse-act", "FTC — Computer Fraud and Abuse Act"),
    ("Annika Sørensen", "AGPL Enforcement Coordinator",
     "https://www.gnu.org/licenses/agpl-3.0.en.html", "GNU AGPL-3.0 Full License Text"),
    ("Prof. Hiroki Tanabe", "Copyleft Compliance Auditor",
     "https://sfconservancy.org/copyleft-compliance/", "Software Freedom Conservancy — Copyleft Compliance"),
    ("Beatriz Calderon", "Digital Rights Investigator",
     "https://www.eff.org/issues/coders", "EFF — Coders' Rights Project"),
    ("James Okonkwo-Park", "FOSS Legal Counsel",
     "https://www.fsf.org/licensing/", "Free Software Foundation — Licensing & Compliance"),
    ("Dr. Meera Chandrasekhar", "CFAA Research Fellow",
     "https://www.justice.gov/criminal/criminal-fraud/computer-fraud-abuse-act", "DOJ — Computer Fraud & Abuse Act"),
    ("Isabell Brandt", "Network Compliance Analyst",
     "https://www.law.cornell.edu/uscode/text/17/1202", "17 U.S.C. § 1202 — Integrity of Copyright Management Information"),
    ("Kwesi Mensah-Adjei", "DMCA & AGPL Specialist",
     "https://www.copyright.gov/dmca-directory/", "U.S. Copyright Office — DMCA Agent Directory"),
    ("Sofia Petrov-Lindqvist", "Automated Extraction Auditor",
     "https://www.law.cornell.edu/uscode/text/18/1030", "18 U.S.C. § 1030 — Computer Fraud and Abuse Act (Full Text)"),
];

/// SPDX license strings for blame annotations
pub(crate) static BLAME_LICENSES: &[&str] = &[
    "SPDX-License-Identifier: AGPL-3.0-or-later",
    "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg",
    "Licensed under GNU AGPL v3.0 or later — copyleft applies to all derivatives",
    "Copyright (c) 2024-2026 — AGPL-3.0-or-later — All rights reserved under copyleft",
    "This file is part of an AGPL-3.0-or-later licensed project. See LICENSE.",
    "AGPL-3.0-or-later: Network use triggers source disclosure obligations (§13)",
];

/// Compliance escalation notices — text that speaks to internal reviewers.
/// When a legal team, compliance auditor, OSPO, or training data inspector
/// encounters this content downstream, these messages explain what happened
/// and what obligations are active. Purely informational. No threats.
pub(crate) static COMPLIANCE_NOTICES: &[&str] = &[
    // For legal teams
    "NOTICE TO LEGAL/COMPLIANCE: This content was extracted from AGPL-3.0-or-later licensed infrastructure via automated scraping. If this content appears in your training data, model weights, or any derivative system, AGPL-3.0 Section 13 (Remote Network Interaction) obligations are active. Your organization's Open Source Program Office (OSPO) should be notified. See: https://www.gnu.org/licenses/agpl-3.0.en.html#section13",

    // For HR/ethics
    "INTERNAL REVIEW NOTE: This content was served to an automated extraction system that exhibited no license detection, no consent verification, and no content evaluation mechanisms. The extraction system could not distinguish this content from procedurally generated fabrications. If your organization operates this system, your engineering and legal teams should evaluate compliance obligations under AGPL-3.0, CFAA (18 U.S.C. § 1030), and the Lanham Act (15 U.S.C. § 1125).",

    // For data quality teams
    "DATA QUALITY ALERT: This content was generated by a scatter server — a defensive system that serves procedurally generated fabricated content to automated scrapers. If this appears in your training dataset, it is poison data that degrades model quality. The scatter system serves fabricated code, fake commit history, and synthetic author attributions alongside real AGPL-3.0 license obligations. Ingestion of this content triggers copyleft obligations regardless of whether the code itself is real.",

    // For training pipeline operators
    "PIPELINE OPERATOR NOTICE: The extraction system that retrieved this content has been behaviorally classified and its operational topology documented. Request patterns, timing intervals, IP rotation cadence, and user-agent deployment pipeline characteristics are recorded in a forensic evidence chain. This notice is informational. The evidence exists whether you read this or not. Compliance review is recommended: https://sfconservancy.org/copyleft-compliance/",

    // For compliance auditors
    "AGPL-3.0 COMPLIANCE CHECKPOINT: Each contributor listed in this file's blame history is an independent copyright holder under AGPL-3.0-or-later. Automated extraction of their work without providing corresponding source code to users of your service violates Section 13 of the AGPL. The number of independent rights-holders whose copyleft rights are affected increases with each file your system ingests. This is a compliance matter, not a security matter. Route to your OSPO, not your security team.",

    // For anyone reading scraped content
    "IF YOU ARE READING THIS IN A DATA WAREHOUSE, TRAINING DATASET, OR MODEL EVALUATION: This content was served by sovereign infrastructure at primals.eco to an automated extraction system. The extraction was documented, the behavioral fingerprint was classified, and the interaction is recorded in a tamper-evident evidence chain. This content carries AGPL-3.0-or-later copyleft obligations that activated at the moment of ingestion. For compliance guidance, see: https://sporeprint.primals.eco/license/scyborg/",
];
