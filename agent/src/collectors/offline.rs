//! Offline evidence collector: JSON / JSONL / CSV datasets described by a
//! `dataset.json` manifest (same rules as runtime/offline.py).

use crate::core::evidence::{coerce, make_record, Record, RecordMeta};
use crate::core::executor::{Bounds, Collector, StreamStats};
use crate::core::schema::{entity, schema};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

pub const OFFLINE_COLLECTOR_VERSION: &str = "0.1.0";

pub struct OfflineCollector {
    dir: PathBuf,
    manifest: Value,
}

impl OfflineCollector {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let text = std::fs::read_to_string(dir.join("dataset.json"))
            .with_context(|| format!("reading {}/dataset.json", dir.display()))?;
        Ok(Self { dir, manifest: serde_json::from_str(&text)? })
    }
}

fn lookup<'a>(row: &'a Map<String, Value>, path: &str) -> Value {
    if let Some(v) = row.get(path) {
        return v.clone();
    }
    if !path.contains('.') {
        return Value::Null;
    }
    let mut cur: Option<&Value> = None;
    for (i, part) in path.split('.').enumerate() {
        let next = if i == 0 { row.get(part) } else { cur.and_then(|c| c.as_object()).and_then(|o| o.get(part)) };
        match next {
            Some(n) => cur = Some(n),
            None => return Value::Null,
        }
    }
    cur.cloned().unwrap_or(Value::Null)
}

fn rows(path: &Path, fmt: &str) -> Result<Vec<Map<String, Value>>> {
    let mut out = Vec::new();
    match fmt {
        "jsonl" => {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            for line in text.lines() {
                let l = line.trim();
                if l.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(l)? {
                    Value::Object(m) => out.push(m),
                    _ => bail!("{}: jsonl rows must be objects", path.display()),
                }
            }
        }
        "json" => {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            match serde_json::from_str::<Value>(&text)? {
                Value::Array(items) => {
                    for it in items {
                        match it {
                            Value::Object(m) => out.push(m),
                            _ => bail!("{}: json rows must be objects", path.display()),
                        }
                    }
                }
                _ => bail!("{}: json source must be an array of objects", path.display()),
            }
        }
        "csv" => {
            let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(path)?;
            let headers = rdr.headers()?.clone();
            for rec in rdr.records() {
                let rec = rec?;
                let mut m = Map::new();
                for (i, h) in headers.iter().enumerate() {
                    m.insert(h.to_string(), rec.get(i).map(|s| Value::String(s.to_string())).unwrap_or(Value::Null));
                }
                out.push(m);
            }
        }
        other => bail!("unknown source format {other:?}"),
    }
    Ok(out)
}

impl Collector for OfflineCollector {
    fn platform(&self) -> &'static str {
        "offline"
    }

    fn collectors(&self) -> Vec<String> {
        schema().entities.keys().map(|e| format!("Offline{e}Collector")).collect()
    }

    fn collect(&mut self, entity_name: &str, _stream: &Value, _bounds: Bounds, stats: &mut StreamStats) -> Result<Vec<Record>> {
        let spec = entity(entity_name)?;
        let name = self.manifest["name"].as_str().ok_or_else(|| anyhow!("manifest name missing"))?.to_string();
        let default_host = self.manifest["default_host"].as_str().unwrap_or("OFFLINE").to_string();
        let mut out = Vec::new();
        let empty = Map::new();
        for src in self.manifest["sources"].as_array().into_iter().flatten() {
            if src["entity"].as_str() != Some(entity_name) {
                continue;
            }
            let mapping = src["fields"].as_object().unwrap_or(&empty);
            let map = |f: &str| -> String { mapping.get(f).and_then(|v| v.as_str()).unwrap_or(f).to_string() };
            let time_format = src["time_format"].as_str().unwrap_or("iso");
            let rel = src["path"].as_str().unwrap_or("");
            let label = format!("offline:{name}/{rel}");
            let collector = format!("Offline{entity_name}Collector");
            let time_source = src["time_source"].as_str().unwrap_or("event");
            for row in rows(&self.dir.join(rel), src["format"].as_str().unwrap_or("jsonl"))? {
                stats.scanned += 1;
                let t = match coerce(&lookup(&row, &map("time")), "time", time_format) {
                    Ok(Value::String(s)) => s,
                    _ => {
                        stats.normalize_errors += 1;
                        continue;
                    }
                };
                let host = match lookup(&row, &map("host")) {
                    Value::String(h) if !h.is_empty() => h,
                    _ => default_host.clone(),
                };
                let mut values = Map::new();
                for (fname, fspec) in spec.payload_fields() {
                    let v = match coerce(&lookup(&row, &map(fname)), &fspec.ty, time_format) {
                        Ok(v) => v,
                        Err(_) => {
                            stats.normalize_errors += 1;
                            Value::Null
                        }
                    };
                    values.insert(fname.clone(), v);
                }
                let observed = match coerce(&lookup(&row, &map("observed_at")), "time", time_format) {
                    Ok(Value::String(s)) => s,
                    _ => t.clone(),
                };
                out.push(make_record(
                    RecordMeta {
                        entity: entity_name,
                        host: &host,
                        time: &t,
                        time_source,
                        observed_at: &observed,
                        collector: &collector,
                        collector_version: OFFLINE_COLLECTOR_VERSION,
                        source: &label,
                    },
                    values,
                )?);
            }
        }
        Ok(out)
    }
}
