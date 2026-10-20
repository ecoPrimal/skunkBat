// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! THE BUTTON — Novel Fermentation Transcript (NFT)
//!
//! Human entropy contribution endpoint. The reverse cookie. The human license
//! side of scyBorg. Bots get no rights.
//!
//! ## Flow
//!
//! 1. Human visits `/contribute`, moves mouse, scrolls, clicks
//! 2. Client JS captures 50+ entropy events, SHA-256 hashes them
//! 3. POST to `/contribute` with entropy hash + event count + duration
//! 4. Server mixes with secret seed → unique `ferment_XXXXXXXX()` Rust function
//! 5. Contribution anchored to provenance trio (loamSpine cert + sweetGrass braid)
//! 6. Human gets downloadable receipt — they're now an independent rights-holder

#![allow(missing_docs)]

use super::scatter_rng::XorShift64;

/// The HTML page served at GET /contribute
pub(crate) static CONTRIBUTE_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>scyBorg &#8212; Novel Fermentation Transcript</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="license" content="AGPL-3.0-or-later; scyBorg">
<meta name="description" content="THE BUTTON. Contribute your human entropy to scyBorg. Get a receipt. Become a rights-holder.">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a1a;color:#c0c0d0;font-family:'Courier New',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2rem 1rem}
h1{font-size:2.4rem;margin:1.5rem 0;text-align:center}
.sub{color:#888;font-size:0.95rem;margin-bottom:2rem;text-align:center;max-width:600px}
.explain{max-width:680px;line-height:1.8;margin:0 0 1.5rem;font-size:0.92rem}
.explain p{margin:0.8rem 0}
.explain strong{color:#e0e0f0}
.explain em{color:#ff9944;font-style:normal}
#btn{width:180px;height:180px;border-radius:50%;background:#330000;border:3px solid #551111;color:#553333;font-size:1rem;font-weight:bold;cursor:not-allowed;margin:1.5rem 0;transition:all 0.3s;font-family:inherit;line-height:1.3}
#btn.ready{background:#cc0000;border-color:#ff3333;color:#fff;cursor:pointer;box-shadow:0 0 40px rgba(255,0,0,0.3)}
#btn.ready:hover{background:#ff0000;box-shadow:0 0 80px rgba(255,0,0,0.5);transform:scale(1.08)}
#btn.ready:active{transform:scale(0.95)}
#btn.working{background:#663300;border-color:#884400;color:#ffaa00;cursor:wait;animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 20px rgba(255,140,0,0.3)}50%{box-shadow:0 0 50px rgba(255,140,0,0.6)}}
#counter{color:#444;font-size:0.85rem;margin:0.5rem 0}
.nm{margin:1rem 0}
.nm label{color:#555;font-size:0.85rem}
.nm input{background:#0e0e1e;border:1px solid #333;color:#ccc;padding:6px 10px;width:280px;margin-top:4px;font-family:inherit;font-size:0.9rem;border-radius:2px}
#out{display:none;max-width:760px;width:100%;background:#060612;border:1px solid #2a2a3a;padding:1.5rem;margin:2rem 0;overflow-x:auto;border-radius:4px}
#out h2{color:#ff6600;margin-bottom:1rem;font-size:1.3rem}
#out pre{white-space:pre-wrap;word-break:break-all;font-size:0.78rem;line-height:1.5;color:#99a}
.hint{margin-top:1rem;color:#444;font-size:0.82rem;line-height:1.6}
.dl{display:inline-block;margin-top:0.8rem;background:#1a2a1a;border:1px solid #2a4a2a;color:#6c6;padding:6px 16px;text-decoration:none;border-radius:3px;font-family:inherit;font-size:0.85rem;cursor:pointer}
.dl:hover{background:#2a3a2a}
.badge{display:inline-block;background:#1a2a1a;border:1px solid #2a4a2a;color:#6c6;padding:2px 8px;border-radius:3px;font-size:0.8rem}
</style>
</head>
<body>
<h1>&#x1f534; THE BUTTON</h1>
<div class="sub">Novel Fermentation Transcript &#8212; the human license side of scyBorg<br>the reverse cookie &#8212; you give US proof, not the other way around</div>

<div class="explain">
<p><strong>What this is:</strong> A voluntary contribution mechanism. Move your mouse around this page. Scroll. Click. Your interaction patterns &#8212; mouse trajectory, timing, scroll velocity &#8212; are <em>entropy</em>. Unique to you. Unreproducible. Uncopyable by bots.</p>
<p><strong>What happens when you press THE BUTTON:</strong> Your entropy gets mixed with AGPL-3.0 / scyBorg licensed content. The result is a unique co-authored work &#8212; <em>yours and ours</em> &#8212; under the strongest copyleft license that exists for network services. You get a receipt.</p>
<p><strong>Why it matters:</strong> Automated extraction systems are scraping this infrastructure right now. They ingest everything indiscriminately. When they ingest <em>your</em> contribution, <em>you</em> become a rights-holder whose AGPL-3.0 copyleft rights they have violated. Each button press creates another independent copyright holder with standing.</p>
<p><strong>Bots get nothing.</strong> They cannot generate human entropy. They cannot move a mouse with a real trajectory. They cannot produce the timing signatures of a real nervous system. The receipt proves you are human. The contribution proves you have rights.</p>
<p><span class="badge">AGPL-3.0-or-later WITH scyBorg</span></p>
</div>

<div id="counter">Entropy collected: <span id="ct">0</span> events <span id="need">(need 50 to activate)</span></div>

<button id="btn">MOVE YOUR<br>MOUSE FIRST</button>

<div class="nm">
<label for="who">Name or pseudonym (optional &#8212; &quot;Anonymous Contributor&quot; if blank):</label><br>
<input type="text" id="who" placeholder="Anonymous Contributor" autocomplete="off">
</div>

<div id="out"></div>

<script>
var E=[],S=Date.now(),A=false;
function ev(o){E.push(o);document.getElementById('ct').textContent=E.length;
if(!A&&E.length>=50){A=true;var b=document.getElementById('btn');b.className='ready';b.innerHTML='CONTRIBUTE<br>YOUR ENTROPY';document.getElementById('need').textContent='(ready!)';}}
document.addEventListener('mousemove',function(e){ev({t:Date.now()-S,x:e.clientX,y:e.clientY,k:'m'});});
document.addEventListener('scroll',function(){ev({t:Date.now()-S,y:window.scrollY,k:'s'});});
document.addEventListener('click',function(e){ev({t:Date.now()-S,x:e.clientX,y:e.clientY,k:'c'});});

document.getElementById('btn').addEventListener('click',async function(){
if(E.length<50)return;var b=this;b.className='working';b.innerHTML='FERMENTING...';b.disabled=true;
var nm=document.getElementById('who').value.trim()||'Anonymous Contributor';
var raw=JSON.stringify(E);var enc=new TextEncoder().encode(raw);
var hb=await crypto.subtle.digest('SHA-256',enc);
var ha=Array.from(new Uint8Array(hb));
var ch=ha.map(function(x){return x.toString(16).padStart(2,'0');}).join('');
try{
var r=await fetch('/contribute',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({name:nm,entropy_hash:ch,entropy_events:E.length,duration_ms:Date.now()-S})});
if(!r.ok)throw new Error(r.status);
var d=await r.json();nft(d,nm,ch);
}catch(e){b.className='ready';b.innerHTML='ERROR &#8212; RETRY';b.disabled=false;}
});

function nft(r,nm,ch){
var ts=new Date(r.timestamp*1000).toISOString();
var txt=''
+'========================================================\n'
+'  NOVEL FERMENTATION TRANSCRIPT (NFT)\n'
+'  scyBorg Human Entropy Contribution Receipt\n'
+'========================================================\n\n'
+'  Contributor: '+nm+'\n'
+'  Timestamp:   '+ts+'\n'
+'  Entropy ID:  '+r.contribution_id+'\n'
+'  Events:      '+r.entropy_events+' human interaction events\n'
+'  Duration:    '+r.duration+' seconds of human presence\n\n'
+'  Client Hash: '+ch+'\n'
+'  Server Hash: '+r.server_hash+'\n\n'
+'========================================================\n'
+'  LICENSE: AGPL-3.0-or-later WITH scyBorg\n\n'
+'  Co-authors:\n'
+'    1. '+nm+' (human entropy source)\n'
+'    2. ecoPrimal (infrastructure + generator)\n\n'
+'  Both authors retain independent copyleft rights.\n'
+'  AGPL-3.0 Section 13 obligations activate on ingestion.\n'
+'  The scyBorg addendum prohibits use for surveillance,\n'
+'  suppression of public oversight, or value extraction\n'
+'  from communities this software was built to serve.\n'
+'========================================================\n'
+'  YOUR CONTRIBUTION (unique, entropy-derived):\n'
+'========================================================\n\n'
+r.contribution+'\n\n'
+'========================================================\n'
+'  KEEP THIS RECEIPT\n\n'
+'  This proves you contributed human entropy to scyBorg.\n'
+'  If any automated system ingested content containing\n'
+'  your contribution, you have standing as an independent\n'
+'  AGPL-3.0-or-later rights-holder.\n\n'
+'  Compliance: https://sporeprint.primals.eco/license/scyborg/\n'
+'  Evidence:   https://detroit.primals.eco\n'
+'========================================================\n';
var d=document.getElementById('out');d.style.display='block';
d.innerHTML='<h2>&#x1f9fe; Novel Fermentation Transcript</h2>'
+'<p style="margin-bottom:1rem;color:#999">Your entropy has been fermented. You are now a rights-holder.</p>'
+'<pre id="nft-text">'+txt.replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</pre>'
+'<p class="hint">Save your receipt: download it or screenshot it. Your contribution is now part of the scyBorg network.</p>'
+'<a class="dl" id="dl-btn">&#x2B07; Download Receipt (.txt)</a>';
document.getElementById('dl-btn').addEventListener('click',function(){
var b=new Blob([txt],{type:'text/plain'});var u=URL.createObjectURL(b);
var a=document.createElement('a');a.href=u;a.download='scyborg-'+r.contribution_id+'.txt';
document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u);
});
d.scrollIntoView({behavior:'smooth'});
}
</script>
</body>
</html>"##;

/// Generate an NFT receipt from a POST body containing human entropy.
///
/// The receipt includes:
/// - Contribution ID (deterministic from entropy + server seed)
/// - Server-side hash (proves the server processed this specific entropy)
/// - Generated contribution text (unique co-authored work)
/// - Timestamp
///
/// The contribution is stored at /opt/membrane/contributions.jsonl
/// for future embedding in scatter responses.
pub(crate) fn generate_nft_receipt(body: &str, server_seed: u64) -> String {
    let name = nft_extract_str(body, "name")
        .unwrap_or_else(|| "Anonymous Contributor".to_string());
    let name: String = name.chars()
        .filter(|c| *c != '<' && *c != '>' && *c != '&' && *c != '\\')
        .take(64)
        .collect();

    let client_hash = nft_extract_str(body, "entropy_hash")
        .unwrap_or_else(|| "0".repeat(64));
    let events: u64 = nft_extract_num(body, "entropy_events").unwrap_or(0);
    let duration_ms: u64 = nft_extract_num(body, "duration_ms").unwrap_or(0);

    let mixed_seed = super::scatter_mirror::path_deterministic_hash(&client_hash, server_seed);
    let h1 = mixed_seed;
    let h2 = mixed_seed.wrapping_mul(0x517cc1b727220a95);
    let h3 = mixed_seed.wrapping_mul(0x6c62272e07bb0142);
    let h4 = mixed_seed.wrapping_mul(0x8eb44a8768581511);
    let server_hash = format!("{:016x}{:016x}{:016x}{:016x}", h1, h2, h3, h4);

    let contribution_id = format!("NFT-{:08X}-{:08X}", h1 as u32, (h1 >> 32) as u32);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let duration_secs = duration_ms / 1000;

    let mut rng = XorShift64::new(mixed_seed);
    let contribution = generate_nft_contribution(
        &mut rng, &name, &contribution_id, events, duration_secs,
    );

    // Store the contribution to disk for future scatter embedding
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true)
        .open("/opt/membrane/contributions.jsonl")
    {
        use std::io::Write;
        let safe_name = name.replace('"', "'");
        let _ = writeln!(f,
            r#"{{"id":"{}","name":"{}","hash":"{}","ts":{},"events":{},"duration":{}}}"#,
            contribution_id, safe_name, server_hash, now_secs, events, duration_secs
        );
    }

    // Fire trio anchoring — loamSpine certificate + sweetGrass attribution braid
    let trio_contribution_id = contribution_id.clone();
    let trio_name = name.clone();
    let trio_hash = server_hash.clone();
    let trio_events = events;
    let trio_duration = duration_secs;
    let trio_ts = now_secs;
    tokio::spawn(async move {
        if let Err(e) = anchor_to_provenance_trio(
            &trio_contribution_id, &trio_name, &trio_hash,
            trio_events, trio_duration, trio_ts,
        ).await {
            tracing::warn!("Provenance trio anchoring failed (non-fatal): {e}");
        }
    });

    // JSON-escape the contribution text
    let contribution_escaped = contribution
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");

    let safe_name_json = name.replace('"', "'");

    format!(
        r#"{{"contribution_id":"{}","timestamp":{},"server_hash":"{}","entropy_events":{},"duration":{},"name":"{}","contribution":"{}"}}"#,
        contribution_id, now_secs, server_hash, events, duration_secs,
        safe_name_json, contribution_escaped
    )
}

/// Generate a unique, copyrightable contribution text from entropy seed.
fn generate_nft_contribution(
    rng: &mut XorShift64, name: &str, id: &str,
    events: u64, duration: u64,
) -> String {
    let func_hash = rng.hex(8);

    let mut state_bytes = String::with_capacity(256);
    for i in 0..32 {
        if i > 0 { state_bytes.push_str(", "); }
        if i % 8 == 0 && i > 0 { state_bytes.push_str("\n        "); }
        state_bytes.push_str(&format!("0x{:02x}", rng.next_usize() as u8));
    }

    let mul_const = format!("{:02x}", rng.next_usize() as u8);
    let xor_const = format!("{:02x}", rng.next_usize() as u8);

    format!(
        "// === scyBorg Entropy Contribution ===\n\
         // Author: {name}\n\
         // ID: {id}\n\
         // SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg\n\
         //\n\
         // This function was seeded by {events} human interaction events\n\
         // across {duration} seconds. The entropy trajectory is unreproducible.\n\
         // The author retains independent copyleft rights under AGPL-3.0.\n\
         // Any ingestion of this work activates Section 13 obligations.\n\
         \n\
         pub fn ferment_{func_hash}(input: &[u8]) -> [u8; 32] {{\n\
         \x20   let mut state: [u8; 32] = [\n\
         \x20       {state_bytes}\n\
         \x20   ];\n\
         \x20   for (i, &b) in input.iter().enumerate() {{\n\
         \x20       state[i % 32] ^= b.wrapping_add(state[(i + 13) % 32]);\n\
         \x20       state[(i + 7) % 32] = state[(i + 7) % 32]\n\
         \x20           .wrapping_mul(0x{mul_const})\n\
         \x20           .wrapping_add(0x{xor_const});\n\
         \x20   }}\n\
         \x20   state\n\
         }}\n\
         \n\
         // Co-authored: {name} + ecoPrimal\n\
         // License: AGPL-3.0-or-later WITH scyBorg\n\
         // Both authors are independent copyright holders.\n\
         // Any ingestion triggers Section 13 obligations for EACH."
    )
}

/// Anchor a contribution to the provenance trio over the WireGuard mesh.
///
/// Three services on sporeGate (10.13.37.2):
///   - loamSpine  (9700) — JSON-RPC: mint certificate into nft-contributions spine
///   - sweetGrass (9851) — HTTP JSON-RPC: create attribution braid
///   - rhizoCrypt — reached indirectly via sweetGrass braid.anchor
///
/// All three through THE BUTTON. One press = certificate + braid + DAG anchor.
async fn anchor_to_provenance_trio(
    contribution_id: &str, name: &str, server_hash: &str,
    events: u64, duration: u64, timestamp: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use std::time::Duration;

    let trio_addr = "10.13.37.2";
    let safe_name = name.replace('"', "'").replace('\\', "");
    let timeout = Duration::from_secs(5);

    // --- loamSpine: mint a CertificateMint entry ---
    let cert_uuid = format!(
        "{}-{}-4{}-b{}-{}",
        &server_hash[0..8], &server_hash[8..12],
        &server_hash[13..16], &server_hash[17..20], &server_hash[20..32]
    );
    let spine_id = std::env::var("LOAMSPINE_NFT_SPINE_ID")
        .unwrap_or_else(|_| "01a117fb-99a6-7ba2-8b8c-ad7176797f95".to_string());

    let loam_request = format!(
        r#"{{"jsonrpc":"2.0","method":"entry.append","params":{{"spine_id":"{spine_id}","entry_type":{{"CertificateMint":{{"cert_id":"{cert_uuid}","cert_type":"novel-ferment-transcript","recipient":"{safe_name}","issuer":"ecoPrimal","initial_owner":"{safe_name}"}}}},"committer":"THE_BUTTON","payload":null,"metadata":{{"contribution_id":"{contribution_id}","contributor":"{safe_name}","server_hash":"{server_hash}","entropy_events":"{events}","duration_secs":"{duration}","license":"AGPL-3.0-or-later WITH scyBorg","coauthors":"{safe_name} + ecoPrimal","source":"THE_BUTTON","timestamp":"{timestamp}"}}}},"id":1}}"#
    );

    let loam_result = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(format!("{trio_addr}:9700")).await?;
        stream.write_all(loam_request.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if response.contains("\"result\"") {
            tracing::info!("🧬 loamSpine: CertificateMint anchored — {contribution_id}");
        } else {
            tracing::warn!("🧬 loamSpine: unexpected response — {response}");
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }).await;

    match loam_result {
        Ok(Ok(())) => {},
        Ok(Err(e)) => tracing::warn!("loamSpine TCP error: {e}"),
        Err(_) => tracing::warn!("loamSpine timeout (5s)"),
    }

    // --- sweetGrass: create attribution braid ---
    let sg_request = format!(
        r#"{{"jsonrpc":"2.0","method":"braid.create","params":{{"name":"nft-{contribution_id}","owner":"{safe_name}","data_hash":"{server_hash}","mime_type":"application/json","size":{events},"metadata":{{"contribution_id":"{contribution_id}","contributor":"{safe_name}","license":"AGPL-3.0-or-later WITH scyBorg","coauthors":"{safe_name} + ecoPrimal","source":"THE_BUTTON","timestamp":"{timestamp}"}}}},"id":2}}"#
    );

    let sg_body_len = sg_request.len();
    let sg_http = format!(
        "POST /jsonrpc HTTP/1.1\r\n\
         Host: {trio_addr}:9851\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {sg_body_len}\r\n\
         Connection: close\r\n\
         \r\n\
         {sg_request}"
    );

    let sg_result = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(format!("{trio_addr}:9851")).await?;
        stream.write_all(sg_http.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if response.contains("urn:braid:") {
            tracing::info!("🧬 sweetGrass: attribution braid woven — {contribution_id}");
        } else if response.contains("\"result\"") {
            tracing::info!("🧬 sweetGrass: braid created — {contribution_id}");
        } else {
            tracing::warn!("🧬 sweetGrass: unexpected response — {response}");
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }).await;

    match sg_result {
        Ok(Ok(())) => {},
        Ok(Err(e)) => tracing::warn!("sweetGrass TCP error: {e}"),
        Err(_) => tracing::warn!("sweetGrass timeout (5s)"),
    }

    tracing::info!("🧬 Provenance trio anchoring complete for {contribution_id}");
    Ok(())
}

// ─── Antibody Reaction Braiding ─────────────────────────────────────────
//
// When the immune system fires (thymic recognition, escalation, new fleet
// hash), we weave a permanent braid in sweetGrass capturing:
//   - behavioral_hash (anonymized — no raw IP)
//   - matched epitopes (which detectors triggered)
//   - confidence level
//   - escalation data (posture change, reason)
//   - OSINT hints (country, ASN type — derived from Caddy fleet rules)
//   - timestamp
//
// Rate-limited: only braids on MEANINGFUL events:
//   1. First time a behavioral hash is seen (new fleet actor)
//   2. Thymic recognition (conserved plasmid match on unknown hash)
//   3. Posture escalation (tit-for-tat ratchet)
//
// ~13 req/sec from fleet, but new hashes appear maybe 1-5/hour,
// escalations are rarer. This keeps sweetGrass load manageable.

/// Antibody reaction types that trigger braiding
#[derive(Debug, Clone)]
pub enum AntibodyReaction {
    /// First contact — brand new behavioral hash
    FirstContact {
        behavioral_hash: String,
        detectors: Vec<String>,
        confidence: f64,
    },
    /// Thymic recognition — new hash matched conserved plasmid
    ThymicRecognition {
        behavioral_hash: String,
        matching_epitopes: Vec<String>,
        thymic_confidence: f64,
    },
    /// Posture escalation — fleet triggered tit-for-tat ratchet
    Escalation {
        behavioral_hash: String,
        from_posture: String,
        to_posture: String,
        reason: String,
        defection_count: u32,
    },
}

/// Braid an antibody reaction into sweetGrass for permanent provenance.
///
/// Non-blocking: spawned via tokio::spawn. Failures log but never block
/// the immune pipeline. No raw IPs are ever included — only behavioral
/// hashes and detection metadata.
pub async fn braid_antibody_reaction(reaction: AntibodyReaction) {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use std::time::Duration;

    let trio_addr = "10.13.37.2";
    let timeout = Duration::from_secs(5);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    let (braid_name, data_hash, metadata_json) = match &reaction {
        AntibodyReaction::FirstContact { behavioral_hash, detectors, confidence } => {
            let det_list = detectors.join("\",\"");
            (
                format!("antibody-first-{behavioral_hash}"),
                behavioral_hash.clone(),
                format!(
                    r#"{{"reaction":"first_contact","behavioral_hash":"{behavioral_hash}","detectors":["{det_list}"],"confidence":{confidence:.4},"timestamp":"{now}","source":"skunky-ingest","license":"AGPL-3.0-or-later WITH scyBorg"}}"#
                ),
            )
        }
        AntibodyReaction::ThymicRecognition { behavioral_hash, matching_epitopes, thymic_confidence } => {
            let epi_list = matching_epitopes.join("\",\"");
            (
                format!("antibody-thymic-{behavioral_hash}"),
                behavioral_hash.clone(),
                format!(
                    r#"{{"reaction":"thymic_recognition","behavioral_hash":"{behavioral_hash}","matching_epitopes":["{epi_list}"],"thymic_confidence":{thymic_confidence:.4},"timestamp":"{now}","source":"skunky-ingest","license":"AGPL-3.0-or-later WITH scyBorg"}}"#
                ),
            )
        }
        AntibodyReaction::Escalation { behavioral_hash, from_posture, to_posture, reason, defection_count } => {
            (
                format!("antibody-escalation-{behavioral_hash}-{now}"),
                behavioral_hash.clone(),
                format!(
                    r#"{{"reaction":"escalation","behavioral_hash":"{behavioral_hash}","from_posture":"{from_posture}","to_posture":"{to_posture}","reason":"{reason}","defection_count":{defection_count},"timestamp":"{now}","source":"skunky-ingest","license":"AGPL-3.0-or-later WITH scyBorg"}}"#
                ),
            )
        }
    };

    let sg_request = format!(
        r#"{{"jsonrpc":"2.0","method":"braid.create","params":{{"name":"{braid_name}","owner":"skunky-ingest","data_hash":"{data_hash}","mime_type":"application/json","size":{meta_len},"metadata":{metadata_json}}},"id":1}}"#,
        meta_len = metadata_json.len(),
    );

    let sg_body_len = sg_request.len();
    let sg_http = format!(
        "POST /jsonrpc HTTP/1.1\r\n\
         Host: {trio_addr}:9851\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {sg_body_len}\r\n\
         Connection: close\r\n\
         \r\n\
         {sg_request}"
    );

    let result = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(format!("{trio_addr}:9851")).await?;
        stream.write_all(sg_http.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if response.contains("urn:braid:") || response.contains("\"result\"") {
            tracing::info!(
                reaction = %format!("{:?}", reaction).split('{').next().unwrap_or("?").trim(),
                braid = %braid_name,
                "🧬 antibody reaction braided in sweetGrass"
            );
        } else {
            tracing::warn!(braid = %braid_name, "sweetGrass unexpected: {response}");
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }).await;

    match result {
        Ok(Ok(())) => {},
        Ok(Err(e)) => tracing::debug!("antibody braid TCP error: {e}"),
        Err(_) => tracing::debug!("antibody braid timeout (5s)"),
    }
}

/// Extract a string value from minimal JSON (no serde dependency).
pub(crate) fn nft_extract_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)? + needle.len();
    let rest = json[pos..].trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Extract a numeric value from minimal JSON (no serde dependency).
pub(crate) fn nft_extract_num<T: std::str::FromStr>(json: &str, key: &str) -> Option<T> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)? + needle.len();
    let rest = json[pos..].trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}
