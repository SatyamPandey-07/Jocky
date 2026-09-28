//! Endpoint stream execution — mirrors `compiler/jocky/runtime/endpoint.py`:
//! collect -> time bound -> predicate -> de-duplicate -> reduce -> project -> seal.

use super::canonical::{canonical_json, digest, shift_time};
use super::evidence::{get_field, rec_str, seal, Record};
use super::predicate::evaluate;
use super::schema::entity;
use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Instant;

#[derive(Debug, Default, Serialize, Clone)]
pub struct StreamStats {
    pub scanned: u64,
    pub normalize_errors: u64,
    pub collected: u64,
    pub after_time: u64,
    pub after_predicate: u64,
    pub after_dedupe: u64,
    pub after_reduce: u64,
    pub emitted: u64,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// collector-level work avoided (e.g. files outside the time bound not attributed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Bounds<'a> {
    pub lo: Option<&'a str>,
    pub hi: Option<&'a str>,
}

/// A source of normalized (unprojected, unhashed) evidence records.
pub trait Collector {
    fn platform(&self) -> &'static str;
    fn collectors(&self) -> Vec<String>;
    /// Called once per contract before any stream is collected.
    fn prepare(&mut self, _body: &Value) {}
    fn collect(&mut self, entity: &str, stream: &Value, bounds: Bounds, stats: &mut StreamStats) -> Result<Vec<Record>>;
    /// Optional enrichment after reduction (e.g. hash only the files that survived).
    fn enrich(&mut self, _entity: &str, _stream: &Value, _records: &mut [Record], _stats: &mut StreamStats, _limits: &Value) {}
}

pub struct ExecOutput {
    pub streams: BTreeMap<String, Vec<Record>>,
    pub stats: Value,
}

pub fn time_bounds(stream: &Value, window: &Value) -> Result<(Option<String>, Option<String>)> {
    let t = &stream["time"];
    if t.is_null() || window.is_null() {
        return Ok((None, None));
    }
    let (mut lo, mut hi) = if t["window"].as_bool() == Some(true) {
        (window["from"].as_str().map(String::from), window["to"].as_str().map(String::from))
    } else {
        (None, None)
    };
    if let Some(w) = t["within_seconds"].as_i64().filter(|w| *w != 0) {
        let to = window["to"].as_str().ok_or_else(|| anyhow!("window.to missing"))?;
        let w_lo = shift_time(to, -w)?;
        lo = Some(match lo {
            Some(l) if l > w_lo => l,
            _ => w_lo,
        });
        if hi.is_none() {
            hi = Some(to.to_string());
        }
    }
    Ok((lo, hi))
}

fn key_of(r: &Record, keys: &[String]) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        let v = get_field(r, k);
        if v.is_null() {
            return None;
        }
        out.push(String::from_utf8(canonical_json(&v)).unwrap());
    }
    Some(out)
}

pub fn contract_hash(body: &Value) -> String {
    digest(body)
}

pub fn execute(body: &Value, collector: &mut dyn Collector) -> Result<ExecOutput> {
    let wall = Instant::now();
    let cpu = cpu_time::ProcessTime::try_now().ok();
    let plan = &body["plan"];
    let window = &body["window"];
    let limits = &body["limits"];
    let execution_id = body["execution_id"].as_str().unwrap_or("");
    let chash = contract_hash(body);
    let streams = plan["streams"].as_array().ok_or_else(|| anyhow!("plan.streams missing"))?;
    collector.prepare(body);

    let mut staged: BTreeMap<String, Vec<Record>> = BTreeMap::new();
    let mut stats: BTreeMap<String, StreamStats> = BTreeMap::new();
    for s in streams {
        let sid = s["id"].as_str().unwrap_or("").to_string();
        let ent = s["entity"].as_str().unwrap_or("");
        let (lo, hi) = time_bounds(s, window)?;
        let mut st = StreamStats::default();
        let recs = collector.collect(ent, s, Bounds { lo: lo.as_deref(), hi: hi.as_deref() }, &mut st)?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for r in recs {
            st.collected += 1;
            let t = rec_str(&r, "time");
            if lo.as_deref().map_or(false, |l| t < l) || hi.as_deref().map_or(false, |h| t > h) {
                continue;
            }
            st.after_time += 1;
            if !evaluate(&s["predicate"], &|name| get_field(&r, name)) {
                continue;
            }
            st.after_predicate += 1;
            let id = rec_str(&r, "evidence_id").to_string();
            if !seen.insert(id) {
                continue;
            }
            out.push(r);
        }
        st.after_dedupe = out.len() as u64;
        staged.insert(sid.clone(), out);
        stats.insert(sid, st);
    }

    for g in plan["reduce_groups"].as_array().into_iter().flatten() {
        let keys: Vec<String> = g["keys"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(String::from)).collect();
        let sids: Vec<String> = g["streams"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(String::from)).collect();
        let mut common: Option<BTreeSet<Vec<String>>> = None;
        for sid in &sids {
            let ks: BTreeSet<Vec<String>> = staged[sid].iter().filter_map(|r| key_of(r, &keys)).collect();
            common = Some(match common {
                None => ks,
                Some(c) => c.intersection(&ks).cloned().collect(),
            });
        }
        let common = common.unwrap_or_default();
        for sid in &sids {
            let v = staged.remove(sid).unwrap_or_default();
            staged.insert(sid.clone(), v.into_iter().filter(|r| key_of(r, &keys).map_or(false, |k| common.contains(&k))).collect());
        }
    }

    let max_records = limits["max_records_per_stream"].as_u64().unwrap_or(u64::MAX) as usize;
    let max_bytes = limits["max_bytes"].as_u64().unwrap_or(u64::MAX);
    let mut result = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut truncated = false;
    for s in streams {
        let sid = s["id"].as_str().unwrap_or("").to_string();
        let ent = entity(s["entity"].as_str().unwrap_or(""))?;
        let mut recs = staged.remove(&sid).unwrap_or_default();
        recs.sort_by(|a, b| (rec_str(a, "time"), rec_str(a, "evidence_id")).cmp(&(rec_str(b, "time"), rec_str(b, "evidence_id"))));
        let st = stats.get_mut(&sid).unwrap();
        st.after_reduce = recs.len() as u64;
        if recs.len() > max_records {
            recs.truncate(max_records);
            st.truncated = Some(true);
            truncated = true;
        }
        collector.enrich(ent.name.as_str(), s, &mut recs, st, limits);
        let keep: Vec<String> = match s["fields"].as_array() {
            Some(fs) => fs.iter().filter_map(|f| f.as_str().map(String::from)).collect(),
            None => ent.payload_fields().map(|(n, _)| n.clone()).collect(),
        };
        let mut sealed = Vec::with_capacity(recs.len());
        let mut nbytes = 0u64;
        for mut r in recs {
            let fields = r.get("fields").and_then(|f| f.as_object()).cloned().unwrap_or_default();
            let mut projected = Map::new();
            for k in &keep {
                projected.insert(k.clone(), fields.get(k).cloned().unwrap_or(Value::Null));
            }
            r.insert("fields".into(), Value::Object(projected));
            let r = seal(r, execution_id, &chash);
            nbytes += canonical_json(&Value::Object(r.clone())).len() as u64 + 1;
            sealed.push(r);
        }
        st.emitted = sealed.len() as u64;
        st.bytes = nbytes;
        total_bytes += nbytes;
        result.insert(sid, sealed);
    }
    if total_bytes > max_bytes {
        truncated = true;
    }
    let cpu_ms = cpu.map(|c| c.elapsed().as_secs_f64() * 1000.0).unwrap_or(0.0);
    let records: usize = result.values().map(|v: &Vec<Record>| v.len()).sum();
    Ok(ExecOutput {
        streams: result,
        stats: json!({
            "streams": serde_json::to_value(&stats)?,
            "records": records,
            "bytes": total_bytes,
            "wall_ms": (wall.elapsed().as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0,
            "cpu_ms": (cpu_ms * 1000.0).round() / 1000.0,
            "truncated": truncated,
        }),
    })
}

pub fn encode_jsonl(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.extend_from_slice(&canonical_json(&Value::Object(r.clone())));
        out.push(b'\n');
    }
    out
}
