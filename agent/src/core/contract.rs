//! Execution-contract verification: signature, plan hash, target, freshness,
//! replay protection and capability enforcement — all before any collection.

use super::canonical::{canonical_json, digest, now, parse_time, sha256_hex};
use super::schema::entity;
use anyhow::{anyhow, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

pub const CONTRACT_FORMAT: &str = "jocky.contract/0.1";
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Serialize, Clone)]
pub struct Check {
    pub check: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Verification {
    pub ok: bool,
    pub checks: Vec<Check>,
    pub required_capabilities: Vec<String>,
}

impl Verification {
    fn add(&mut self, check: &str, passed: bool, detail: impl Into<String>) {
        self.checks.push(Check { check: check.into(), passed, detail: detail.into() });
        if !passed {
            self.ok = false;
        }
    }
    pub fn failures(&self) -> Vec<String> {
        self.checks.iter().filter(|c| !c.passed).map(|c| format!("{}: {}", c.check, c.detail)).collect()
    }
}

pub fn key_id(public_key: &[u8]) -> String {
    sha256_hex(public_key)[..16].to_string()
}

fn match_pattern(pattern: &str, cap: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => cap.starts_with(prefix),
        None => pattern == cap,
    }
}

fn predicate_fields(p: &Value, out: &mut BTreeSet<String>) {
    match p["op"].as_str() {
        Some("and") | Some("or") => p["args"].as_array().into_iter().flatten().for_each(|a| predicate_fields(a, out)),
        Some("not") => predicate_fields(&p["arg"], out),
        Some("cmp") => {
            if let Some(f) = p["field"].as_str() {
                out.insert(f.to_string());
            }
        }
        _ => {}
    }
}

/// Recompute the capabilities a plan needs from what its streams actually read.
pub fn plan_capabilities(plan: &Value) -> Result<BTreeSet<String>> {
    let mut caps = BTreeSet::new();
    for s in plan["streams"].as_array().ok_or_else(|| anyhow!("plan has no streams"))? {
        let ent = entity(s["entity"].as_str().unwrap_or(""))?;
        caps.insert(ent.capability.clone());
        let mut read = BTreeSet::new();
        match s["fields"].as_array() {
            None => read.extend(ent.fields.keys().cloned()),
            Some(fs) => {
                read.extend(fs.iter().filter_map(|f| f.as_str().map(String::from)));
                predicate_fields(&s["predicate"], &mut read);
            }
        }
        for f in &read {
            if let Some(c) = ent.fields.get(f).and_then(|x| x.capability.clone()) {
                caps.insert(c);
            }
        }
        if s["acquire_content"].as_bool() == Some(true) {
            caps.insert("acquire:file.content".into());
        }
    }
    if plan["central"].as_array().map(|c| c.iter().any(|n| n["op"] == "preserve")).unwrap_or(false) {
        caps.insert("preserve:records".into());
    }
    Ok(caps)
}

pub struct VerifyInput<'a> {
    pub contract_bytes: &'a [u8],
    pub signature: &'a [u8],
    pub trusted_key: &'a VerifyingKey,
    pub host_id: &'a str,
    pub platform: &'a str,
    pub allow: &'a [String],
    pub seen_nonces: &'a BTreeSet<String>,
    pub supported_collectors: &'a [String],
}

/// Verify a contract.  Returns the parsed body together with the verification report.
pub fn verify(input: VerifyInput) -> (Option<Value>, Verification) {
    let mut v = Verification { ok: true, ..Default::default() };
    // 1. signature over the exact received bytes
    let sig_ok = Signature::from_slice(input.signature)
        .map(|s| input.trusted_key.verify(input.contract_bytes, &s).is_ok())
        .unwrap_or(false);
    v.add("signature", sig_ok, if sig_ok { "Ed25519 signature valid" } else { "Ed25519 signature INVALID" });
    let body: Value = match serde_json::from_slice(input.contract_bytes) {
        Ok(b) => b,
        Err(e) => {
            v.add("parse", false, e.to_string());
            return (None, v);
        }
    };
    // canonical encoding check: the signed bytes must be the canonical form of the body
    v.add("canonical", canonical_json(&body) == input.contract_bytes, "contract bytes are canonical JSON");
    v.add("format", body["format"] == CONTRACT_FORMAT, body["format"].to_string());
    let schema_v = &super::schema::schema().version;
    v.add("schema_version", body["schema_version"].as_str() == Some(schema_v), body["schema_version"].to_string());
    // 2. plan hash
    let recomputed = digest(&body["plan"]);
    v.add("plan_hash", body["plan_hash"].as_str() == Some(recomputed.as_str()), recomputed);
    // 3. key id of issuer matches the pinned key
    let kid = key_id(input.trusted_key.as_bytes());
    v.add("issuer", body["issuer"]["key_id"].as_str() == Some(kid.as_str()), format!("pinned key {kid}"));
    // 4. target + platform
    let targeted = body["targets"].as_array().into_iter().flatten().any(|t| {
        t["host"].as_str() == Some(input.host_id) && t["platform"].as_str() == Some(input.platform)
    });
    v.add("target", targeted, format!("{} ({})", input.host_id, input.platform));
    // 5. freshness
    let now_s = now();
    let fresh = match (parse_time(body["issued_at"].as_str().unwrap_or("")), parse_time(body["expires_at"].as_str().unwrap_or(""))) {
        (Ok(iss), Ok(exp)) => {
            let n = parse_time(&now_s).unwrap();
            (iss - n).num_seconds() <= MAX_CLOCK_SKEW_SECS && n <= exp
        }
        _ => false,
    };
    v.add("freshness", fresh, format!("now {now_s}, expires {}", body["expires_at"]));
    // 6. replay protection
    let nonce = body["nonce"].as_str().unwrap_or("").to_string();
    v.add("nonce", !nonce.is_empty() && !input.seen_nonces.contains(&nonce), "contract not previously executed");
    // 7. collectors for this platform
    let lowered = &body["plan"]["platforms"][input.platform]["collectors"];
    let unsupported: Vec<String> = lowered
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["collector"].as_str())
        .filter(|c| !input.supported_collectors.iter().any(|s| s == c))
        .map(String::from)
        .collect();
    v.add("collectors", lowered.is_array() && unsupported.is_empty(),
          if unsupported.is_empty() { "all collectors available".to_string() } else { format!("unsupported: {}", unsupported.join(", ")) });
    // 8. capabilities: recomputed ⊆ declared ⊆ local allowlist
    match plan_capabilities(&body["plan"]) {
        Ok(needed) => {
            let declared: BTreeSet<String> = body["required_capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str().map(String::from))
                .collect();
            let undeclared: Vec<&String> = needed.difference(&declared).collect();
            v.add("capabilities_declared", undeclared.is_empty(),
                  if undeclared.is_empty() { "plan reads only declared capabilities".to_string() }
                  else { format!("plan needs undeclared {:?}", undeclared) });
            let denied: Vec<&String> = declared
                .iter()
                .filter(|c| !input.allow.iter().any(|p| match_pattern(p, c)))
                .collect();
            v.add("capabilities_policy", denied.is_empty(),
                  if denied.is_empty() { "all capabilities allowed by local policy".to_string() }
                  else { format!("denied by local policy: {:?}", denied) });
            v.required_capabilities = declared.into_iter().collect();
        }
        Err(e) => v.add("capabilities_declared", false, e.to_string()),
    }
    (Some(body), v)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}
