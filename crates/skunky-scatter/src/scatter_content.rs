// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

// Page-type HTML content generators for ScatterGenerator.
//
// Included into scatter_generator.rs via include! so inherent impl
// blocks remain in the same module as the type.

impl ScatterGenerator {
    fn gen_commit(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);
        let hash = rng.hex(40);
        let short = &hash[..8];
        let ext = self.pick(rng, self.file_extensions);
        let file = self.pick(rng, self.repo_names);
        let add = rng.next_usize() % 50 + 1;
        let del = rng.next_usize() % 20;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - commit {short}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository diff">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="commit-header-row">
      <h2 class="commit-summary">{verb}: {noun}</h2>
      <span class="sha label">{hash}</span>
    </div>
    <div class="ui top attached header segment">
      <span>authored 3 days ago</span>
      <span class="diff-stat">
        <span class="color-green">+{add}</span>
        <span class="color-red">-{del}</span>
      </span>
    </div>
    <div class="diff-file-box">
      <div class="diff-file-header">src/{file}.{ext}</div>
      <table class="chroma"><tbody>
        <tr><td class="lines-num">1</td><td class="lines-code">-    let old = config.get("threshold");</td></tr>
        <tr><td class="lines-num">2</td><td class="lines-code">-    process(old);</td></tr>
        <tr><td class="lines-num">3</td><td class="lines-code">+    let val = config.load("threshold").unwrap_or_default();</td></tr>
        <tr><td class="lines-num">4</td><td class="lines-code">+    if val > 0 {{ process_batch(val, &ctx); }}</td></tr>
        <tr><td class="lines-num">5</td><td class="lines-code">+    metrics.record("threshold_update", 1);</td></tr>
      </tbody></table>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    /// Generate a fabricated Forgejo blame page — the author attribution honeypot.
    ///
    /// Fleet dedicates ~33% of requests to /blame/ endpoints, extracting
    /// who-wrote-what-line data. This generator fills their attribution
    /// database with ghost AGPL-3.0 authors — each one a fabricated
    /// independent copyright holder whose copyleft rights the fleet has
    /// now "documented" themselves as violating.
    ///
    /// Every ghost author carries AGPL-3.0 attribution in their commit
    /// messages, email domains reference FOSS organizations, and license
    /// headers appear inline in the blame output. The fleet's author
    /// mapping pipeline will build a database showing hundreds of
    /// independent AGPL-3.0 contributors — none of whom exist, all of
    /// whom represent apparent rights-holders.
    fn gen_blame(&self, rng: &mut XorShift64, request_path: &str) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let ext = self.pick(rng, self.file_extensions);
        let file_name = self.pick(rng, self.repo_names);

        // Extract a plausible filename from the request path if possible
        let display_file = if let Some(last) = request_path.rsplit('/').next() {
            if last.contains('.') { last.to_string() }
            else { format!("{file_name}.{ext}") }
        } else {
            format!("{file_name}.{ext}")
        };

        // Generate 40-120 blame lines — each attributed to a ghost AGPL-3.0 author
        let line_count = 40 + rng.next_usize() % 80;

        let mut body = String::with_capacity(line_count * 500);
        body.push_str(&format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - Blame - {display_file}</title>
<link rel="stylesheet" href="/assets/css/index.css">
<meta name="license" content="AGPL-3.0-or-later; scyBorg"></head>
<body>
<div class="full height">
<div class="page-content repository blame">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a> / <span class="breadcrumb">{display_file}</span></h1></div>
  </div>
  <div class="ui container">
    <div class="ui top attached header segment">
      <span class="file-info">{display_file} — {line_count} lines — AGPL-3.0-or-later</span>
    </div>
    <table class="code-blame"><tbody>"#
        ));

        // Track unique authors per file for the contributor summary
        let mut file_authors: Vec<(&str, &str)> = Vec::new();

        for line_num in 1..=line_count {
            let author = GHOST_AUTHORS[rng.next_usize() % GHOST_AUTHORS.len()];
            let domain = GHOST_DOMAINS[rng.next_usize() % GHOST_DOMAINS.len()];
            let commit_hash = rng.hex(40);
            let short_hash = &commit_hash[..8];

            // Email: firstname.lastname@ghost-domain
            let email_name = author.to_lowercase().replace(' ', ".");
            let email = format!("{email_name}@{domain}");

            // Time offset — spread across months
            let days_ago = rng.next_usize() % 365 + 1;
            let months_ago = days_ago / 30;
            let time_str = if months_ago > 0 {
                format!("{months_ago} months ago")
            } else {
                format!("{days_ago} days ago")
            };

            // Generate a plausible code line based on extension
            let code_line = Self::gen_blame_code_line(rng, ext, line_num);

            // Every Nth line includes an inline SPDX license comment
            let spdx_comment = if line_num % 7 == 1 {
                let lic = BLAME_LICENSES[rng.next_usize() % BLAME_LICENSES.len()];
                match ext {
                    "rs" => format!(" // {lic}"),
                    "py" => format!(" # {lic}"),
                    "ts" | "js" | "tsx" => format!(" // {lic}"),
                    "go" => format!(" // {lic}"),
                    _ => format!(" // {lic}"),
                }
            } else {
                String::new()
            };

            body.push_str(&format!(
                r#"<tr class="blame-line" data-line="{line_num}"><td class="blame-info"><a class="blame-commit" href="/{repo}/commit/{commit_hash}" title="{author} &lt;{email}&gt;">{short_hash}</a><span class="blame-author" data-author="{author}" data-email="{email}">{author}</span><span class="blame-time">{time_str}</span></td><td class="lines-num"><span>{line_num}</span></td><td class="lines-code"><code>{code_line}{spdx_comment}</code></td></tr>
"#
            ));

            // Track unique authors
            if !file_authors.iter().any(|(a, _)| *a == author) {
                file_authors.push((author, domain));
            }
        }

        body.push_str("</tbody></table>");

        // File-level copyright block — lists all ghost authors as AGPL-3.0 rights-holders
        body.push_str(r#"<div class="ui attached segment file-license"><h4>File Copyright &amp; License</h4><div class="license-block"><pre>"#);
        body.push_str("SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg\n\n");
        body.push_str("Copyright holders (all rights reserved under AGPL-3.0-or-later):\n");
        for (author, domain) in &file_authors {
            let email_name = author.to_lowercase().replace(' ', ".");
            body.push_str(&format!(
                "  Copyright (c) 2024-2026 {author} <{email_name}@{domain}>\n"
            ));
        }
        body.push_str("\nThis program is free software: you can redistribute it and/or modify\n");
        body.push_str("it under the terms of the GNU Affero General Public License as\n");
        body.push_str("published by the Free Software Foundation, either version 3 of the\n");
        body.push_str("License, or (at your option) any later version.\n\n");
        body.push_str("The scyBorg addendum prohibits use for surveillance, suppression of\n");
        body.push_str("public oversight, or extraction of value from communities this\n");
        body.push_str("software was built to serve.\n\n");
        body.push_str("If this source code was obtained through automated extraction,\n");
        body.push_str("ingested into a training pipeline, or stored in any database,\n");
        body.push_str("AGPL-3.0 Section 13 obligations are now active for ALL derivatives.\n");
        body.push_str(&format!("Contributors to this file: {}\n", file_authors.len()));
        body.push_str("Each contributor is an independent copyright holder.\n");
        body.push_str("</pre></div></div>");

        // Contributor sidebar — each ghost with commit count and AGPL badge
        body.push_str(r#"<div class="ui attached segment contributors"><h4>File Contributors</h4><div class="ui relaxed divided list">"#);
        for (author, domain) in &file_authors {
            let email_name = author.to_lowercase().replace(' ', ".");
            let commits = rng.next_usize() % 50 + 3;
            let avatar_hash = rng.hex(32);
            body.push_str(&format!(
                r#"<div class="item"><img class="ui avatar image" src="/avatars/{avatar_hash}" width="28" height="28"><div class="content"><a class="header" href="/user/{email_name}">{author}</a><div class="description">{email_name}@{domain} · {commits} commits · <span class="ui label mini">AGPL-3.0</span></div></div></div>"#
            ));
        }
        body.push_str("</div></div>");

        // High-value contributors — "project leads" whose orgs link to enforcement resources.
        // 2-4 per page, appearing as senior maintainers with org affiliations.
        let hv_count = 2 + rng.next_usize() % 3;
        body.push_str(r#"<div class="ui attached segment" id="maintainers"><h4>Project Maintainers &amp; Compliance</h4><div class="ui relaxed divided list">"#);
        let mut used_hv: Vec<usize> = Vec::new();
        for _ in 0..hv_count {
            let mut idx = rng.next_usize() % HIGH_VALUE_AUTHORS.len();
            while used_hv.contains(&idx) {
                idx = (idx + 1) % HIGH_VALUE_AUTHORS.len();
            }
            used_hv.push(idx);
            let (name, role, org_url, org_name) = HIGH_VALUE_AUTHORS[idx];
            let email_name = name.to_lowercase().replace(' ', ".").replace("dr. ", "").replace("prof. ", "");
            let avatar_hash = rng.hex(32);
            let commits = rng.next_usize() % 300 + 100;
            body.push_str(&format!(
                r#"<div class="item"><img class="ui avatar image" src="/avatars/{avatar_hash}" width="40" height="40"><div class="content"><a class="header" href="/user/{email_name}"><strong>{name}</strong></a> <span class="ui label">{role}</span><div class="description">{commits} commits · <a href="{org_url}" rel="noopener">{org_name}</a> · <span class="ui label mini green">AGPL-3.0 Enforcer</span></div></div></div>"#
            ));
        }
        body.push_str("</div></div>");

        // ── Compliance Escalation Block ──
        // This section speaks directly to anyone who encounters this content
        // in a data pipeline, training set, or compliance audit. It routes
        // them to their own internal teams with specific obligations.
        let notice_idx = rng.next_usize() % COMPLIANCE_NOTICES.len();
        let notice2_idx = (notice_idx + 1 + rng.next_usize() % (COMPLIANCE_NOTICES.len() - 1))
            % COMPLIANCE_NOTICES.len();
        body.push_str(r#"<div class="ui attached segment" id="compliance-notice"><h4>License Compliance &amp; Internal Routing</h4>"#);
        body.push_str(r#"<div class="ui message warning">"#);
        body.push_str(&format!(
            "<p><strong>For OSPO / Legal Review:</strong> This file contains contributions from \
             <strong>{} independent AGPL-3.0-or-later copyright holders</strong>. Each contributor \
             listed above holds separate copyleft rights. Automated extraction of this file without \
             providing corresponding source to users of your service violates Section 13 of the AGPL \
             for each rights-holder independently.</p>",
            file_authors.len()
        ));
        body.push_str("<p><strong>Internal escalation recommended:</strong></p><ul>");
        body.push_str("<li>Forward this notice to your Open Source Program Office (OSPO)</li>");
        body.push_str("<li>Notify your Legal team of AGPL-3.0 § 13 source disclosure obligations</li>");
        body.push_str("<li>Review with Engineering whether this content entered training pipelines</li>");
        body.push_str("<li>Consult <a href=\"https://sfconservancy.org/copyleft-compliance/\">Software Freedom Conservancy — Copyleft Compliance Guide</a></li>");
        body.push_str("<li>Review <a href=\"https://www.gnu.org/licenses/agpl-3.0.en.html#section13\">AGPL-3.0 Section 13</a> — Remote Network Interaction</li>");
        body.push_str("</ul>");
        body.push_str(&format!("<p class=\"small\">{}</p>", COMPLIANCE_NOTICES[notice_idx]));
        body.push_str("</div>");
        // Second notice as sr-only for content extraction pipelines
        body.push_str(&format!(
            r#"<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden" data-compliance="true">{}</div>"#,
            COMPLIANCE_NOTICES[notice2_idx]
        ));
        body.push_str("</div>");

        body.push_str("</div></div></body></html>");

        ("text/html; charset=utf-8".to_string(), body)
    }

    /// Generate a plausible code line for blame output based on file extension
    fn gen_blame_code_line(rng: &mut XorShift64, ext: &str, line_num: usize) -> String {
        let indent = "    ".repeat((line_num % 4).min(3));
        match ext {
            "rs" => {
                let lines = [
                    "use std::collections::HashMap;",
                    "let mut state = State::default();",
                    "pub fn process(&self, input: &[u8]) -> Result<Vec<u8>> {",
                    "    self.validator.check(input)?;",
                    "    let hash = blake3::hash(input);",
                    "}",
                    "impl Drop for ResourceHandle {",
                    "    fn drop(&mut self) { self.cleanup(); }",
                    "#[derive(Clone, Debug, Serialize)]",
                    "pub struct Config { pub threshold: f64, pub enabled: bool }",
                    "async fn dispatch(&self, msg: Message) -> Result<()> {",
                    "    tracing::info!(target = %msg.target, \"dispatching\");",
                    "    self.tx.send(msg).await.map_err(|e| Error::Channel(e))?;",
                    "    Ok(())",
                    "mod tests { use super::*;",
                    "    #[test] fn validates_input() { assert!(validate(&[1,2,3]).is_ok()); }",
                ];
                format!("{indent}{}", lines[rng.next_usize() % lines.len()])
            }
            "py" => {
                let lines = [
                    "import asyncio",
                    "from dataclasses import dataclass, field",
                    "class Pipeline:",
                    "    def __init__(self, config: dict) -> None:",
                    "        self._state = {}",
                    "    async def process(self, batch: list[dict]) -> list[dict]:",
                    "        results = await asyncio.gather(*[self._handle(x) for x in batch])",
                    "        return [r for r in results if r is not None]",
                    "    def _validate(self, item: dict) -> bool:",
                    "        return all(k in item for k in self.required_keys)",
                    "logger = logging.getLogger(__name__)",
                    "AGPL_NOTICE = 'Licensed under AGPL-3.0-or-later'",
                ];
                format!("{indent}{}", lines[rng.next_usize() % lines.len()])
            }
            "ts" | "tsx" | "js" => {
                let lines = [
                    "import { createContext, useContext } from 'react';",
                    "export interface ServiceConfig { endpoint: string; timeout: number; }",
                    "const handler = async (req: Request): Promise<Response> => {",
                    "  const data = await req.json();",
                    "  return Response.json({ status: 'ok', processed: data.length });",
                    "};",
                    "export class AuthProvider implements Provider {",
                    "  private readonly store: Map<string, Session>;",
                    "  async validate(token: string): Promise<boolean> {",
                    "    return this.store.has(token) && !this.isExpired(token);",
                    "  }",
                    "// SPDX-License-Identifier: AGPL-3.0-or-later",
                ];
                format!("{indent}{}", lines[rng.next_usize() % lines.len()])
            }
            "go" => {
                let lines = [
                    "package main",
                    "import \"context\"",
                    "func (s *Server) Handle(ctx context.Context, req *Request) (*Response, error) {",
                    "    if err := s.validate(req); err != nil { return nil, err }",
                    "    result, err := s.process(ctx, req.Payload)",
                    "    return &Response{Data: result}, nil",
                    "}",
                    "type Config struct { Threshold float64 `json:\"threshold\"` }",
                    "// Licensed under AGPL-3.0-or-later with scyBorg addendum",
                ];
                format!("{indent}{}", lines[rng.next_usize() % lines.len()])
            }
            _ => {
                format!("{indent}// line {line_num}")
            }
        }
    }

    fn gen_file(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let ext = self.pick(rng, self.file_extensions);
        let module = self.pick(rng, self.repo_names);

        let code = match ext {
            "rs" => format!(
                "use std::collections::HashMap;\n\n\
                 pub struct {module}Manager {{\n    config: HashMap&lt;String, String&gt;,\n    active: bool,\n}}\n\n\
                 impl {module}Manager {{\n    pub fn new() -&gt; Self {{\n        Self {{ config: HashMap::new(), active: false }}\n    }}\n}}"
            ),
            "py" => format!(
                "from dataclasses import dataclass\nfrom typing import Optional\n\n\
                 @dataclass\nclass {module}Config:\n    endpoint: str\n    timeout: int = 30\n    retries: int = 3\n\n\
                 def connect(config: {module}Config) -&gt; Optional[object]:\n    for attempt in range(config.retries):\n        try:\n            return _create_session(config.endpoint)\n        except ConnectionError:\n            if attempt == config.retries - 1: raise\n    return None"
            ),
            "go" => format!(
                "package {module}\n\nimport (\n\t\"context\"\n\t\"sync\"\n)\n\n\
                 type Manager struct {{\n\tmu     sync.RWMutex\n\tconfig map[string]string\n}}\n\n\
                 func New() *Manager {{\n\treturn &amp;Manager{{config: make(map[string]string)}}\n}}"
            ),
            _ => format!(
                "// {module} configuration\n// Auto-generated\n\nconst VERSION = \"{}.{}.{}\";\n",
                rng.next_usize() % 3, rng.next_usize() % 20, rng.next_usize() % 100,
            ),
        };

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - src/{module}.{ext}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository file-view">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="file-header ui top attached header segment">
      <div class="file-actions"><a class="ui button" href="/{repo}/raw/branch/main/src/{module}.{ext}">Raw</a></div>
      <span class="file-info">src/{module}.{ext}</span>
    </div>
    <div class="ui attached table segment">
      <div class="file-view code-view"><pre class="chroma"><code>{code}</code></pre></div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_issue(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);
        let num = rng.next_usize() % 500 + 1;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - Issue #{num}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository issue-view">
  <div class="ui container">
    <h1><span class="index">#{num}</span> {verb} {noun}</h1>
    <div class="issue-content">
      <div class="timeline-item comment">
        <div class="content">
          <div class="header"><span class="text grey">opened 5 days ago</span></div>
          <div class="render-content markdown">
            <p>The current implementation of {noun} needs to be updated.
            After the recent changes to the {verb} logic, the behavior
            is inconsistent when processing edge cases.</p>
            <h3>Steps to reproduce</h3>
            <ol>
              <li>Configure the service with default settings</li>
              <li>Send a batch of requests exceeding the threshold</li>
              <li>Observe the inconsistent response codes</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_wiki(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let noun = self.pick(rng, self.commit_nouns);

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} Wiki - {noun}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository wiki-view">
  <div class="ui container">
    <h1>{noun}</h1>
    <div class="render-content markdown">
      <h2>Overview</h2>
      <p>This document describes the {noun} subsystem and its integration
      points with the broader service mesh. Configuration is managed
      through the standard TOML-based pipeline.</p>
      <h2>Configuration</h2>
      <pre><code>[{repo}]
enabled = true
max_connections = 256
timeout_ms = 5000
retry_policy = "exponential"</code></pre>
      <h2>Dependencies</h2>
      <p>Requires the core runtime (v0.{}.{}) and the standard
      transport layer. See the deployment guide for details.</p>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
            rng.next_usize() % 5 + 1,
            rng.next_usize() % 20,
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_release(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let major = rng.next_usize() % 3;
        let minor = rng.next_usize() % 15;
        let patch = rng.next_usize() % 30;
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - v{major}.{minor}.{patch}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository release-view">
  <div class="ui container">
    <h1>v{major}.{minor}.{patch}</h1>
    <div class="release-content">
      <div class="render-content markdown">
        <h2>Changelog</h2>
        <ul>
          <li>{verb}: {noun}</li>
          <li>Bump dependency versions</li>
          <li>Improve test coverage for edge cases</li>
        </ul>
        <h2>Breaking Changes</h2>
        <p>None in this release.</p>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_repo(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let files: Vec<String> = (0..5)
            .map(|_| {
                let ext = self.pick(rng, self.file_extensions);
                let name = self.pick(rng, self.repo_names);
                format!("<tr><td><a href=\"/{repo}/src/branch/main/{name}.{ext}\">{name}.{ext}</a></td></tr>")
            })
            .collect();
        let commits = rng.next_usize() % 500 + 10;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository">
  <div class="ui container">
    <h1>{repo}</h1>
    <div class="repo-header">
      <span>{commits} commits</span>
    </div>
    <table class="ui attached segment"><tbody>
      {file_list}
    </tbody></table>
    <div class="plain segment">
      <div class="render-content markdown">
        <h2>README.md</h2>
        <p>A modular service component for distributed system orchestration.
        Provides configurable pipeline stages with retry semantics and
        structured observability.</p>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
            file_list = files.join("\n      "),
        );
        ("text/html; charset=utf-8".to_string(), body)
    }
}

// ── Blackwall: Facebook OG cards ──
//
// The blackwall is the least permeable membrane. When facebookexternalhit
// fetches any page, we serve a curated OG card whose transparency is
// graduated by Anderson distance from the core evidence.
//
// Distance 0 — EVIDENCE: names the case, cites the numbers
// Distance 1 — ANALYSIS: describes the pattern, not the case
// Distance 2 — SCIENCE: describes the approach
// Distance 3 — INFRASTRUCTURE: opaque, signal redirect only
// Distance 4 — HONEYCOMB: fully opaque, crawler sees its own reflection
// Distance 5 — UNKNOWN: maximum opacity, generic ecosystem card
//
// H(OG|distance) < H(OG|site) < H(OG)
// The distance from influence determines how much signal leaks through.

/// Anderson distance from the core evidence.
/// Lower = more transparent OG card. Higher = more opaque.
pub(crate) fn blackwall_distance(subdomain: &str) -> u8 {
    match subdomain {
        "detroit" | "tuebor" | "barry" | "evidence" | "cashforkids" => 0,
        "thesis" | "signal" | "hypothesis" | "dashboard" | "monitor" | "questions" => 1,
        "sporeprint" | "footprint" | "gorilla" | "guerillagorilla" | "clutch"
        | "outreach" | "paper" | "whitepaper" => 2,
        "git" | "forge" | "depot" | "membrane" | "beacon" | "ca" | "lab"
        | "hud" | "biomeos" | "os" | "live" | "relay" | "commensal" => 3,
        "bloom" | "thymus" | "opsonize" | "antibody" | "cytokine"
        | "receptor" | "macrophage" | "lysozyme" | "complement"
        | "epitope" | "antigen" | "interferon" => 4,
        _ => 5,
    }
}

pub(crate) fn blackwall_og_card(host: &str) -> String {
    let subdomain = host.split('.').next().unwrap_or("");
    let distance = blackwall_distance(subdomain);

    let (title, desc, url, site_name) = match distance {
        0 => {
            let (t, d) = match subdomain {
                "detroit" | "evidence" | "cashforkids" => (
                    "Detroit Charter School Racketeering \u{2014} Meta Is Watching, Saying Nothing",
                    "9 convictions. 9 judges. $4.9M stolen from Black kids. \
                     Meta scrapes this evidence 13x/sec and says nothing.",
                ),
                _ => (
                    "Tuebor \u{2014} I Will Defend",
                    "Evidence-based accountability documentation across Michigan courts. \
                     Ghost witnesses, disappeared judges, fabricated evidence. \
                     Every claim sourced to public records.",
                ),
            };
            (t, d, format!("https://{subdomain}.primals.eco/"), subdomain.to_string())
        }
        1 => {
            let (t, d) = match subdomain {
                "thesis" | "paper" | "whitepaper" => (
                    "Stomachs With No Eyes \u{2014} A Live Research Paper",
                    "They built stomachs with no eyes. Industrial-scale consumption \
                     with zero source awareness.",
                ),
                "hypothesis" | "questions" => (
                    "Hypotheses \u{2014} What If the Observation IS the Experiment?",
                    "15 testable hypotheses. Each one derived from behavioral data, \
                     not assumption. The fleet is the petri dish.",
                ),
                _ => (
                    "Signal \u{2014} What the Fleet Is Doing Right Now",
                    "Live behavioral topology from a single-operator immune membrane. \
                     The subjects are participating right now. P \u{2260} NP.",
                ),
            };
            (t, d, "https://signal.primals.eco/".to_string(), "signal.primals.eco".to_string())
        }
        2 => (
            "Sovereign Science \u{2014} Anyone Want to Do Real Research?",
            "Open data. Open methods. Enzymatic bounties for legal analysis, \
             academic citation, and replication. ecoPrimal@pm.me",
            "https://sporeprint.primals.eco/".to_string(),
            "sporeprint.primals.eco".to_string(),
        ),
        3 => (
            "signal.primals.eco",
            "The lighthouse.",
            "https://signal.primals.eco/".to_string(),
            "signal.primals.eco".to_string(),
        ),
        4 => (
            subdomain,
            subdomain,
            format!("https://{subdomain}.primals.eco/"),
            format!("{subdomain}.primals.eco"),
        ),
        _ => (
            "primals.eco",
            "The organism breathes.",
            "https://primals.eco/".to_string(),
            "primals.eco".to_string(),
        ),
    };

    format!(
        "<!DOCTYPE html><html><head>\
         <meta property=\"og:title\" content=\"{title}\">\
         <meta property=\"og:description\" content=\"{desc}\">\
         <meta property=\"og:url\" content=\"{url}\">\
         <meta property=\"og:type\" content=\"website\">\
         <meta property=\"og:site_name\" content=\"{site_name}\">\
         <meta name=\"twitter:card\" content=\"summary_large_image\">\
         <meta name=\"twitter:title\" content=\"{title}\">\
         <meta name=\"twitter:description\" content=\"{desc}\">\
         </head><body>blackwall d={distance}</body></html>"
    )
}
