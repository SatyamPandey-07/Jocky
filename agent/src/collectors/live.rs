//! Live endpoint collector: dispatches to the Windows or Linux implementations.
//! Everything here is read-only: no process control, no writes, no injection.

use crate::core::canonical::{now, sha256_hex};
use crate::core::evidence::{make_record, Record, RecordMeta};
use crate::core::executor::{Bounds, Collector, StreamStats};
use anyhow::Result;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const AGENT_COLLECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
pub struct FileScanConfig {
    pub roots: Vec<PathBuf>,
    pub max_depth: usize,
    pub max_files: usize,
}

pub struct LiveCollector {
    pub host_id: String,
    pub files: FileScanConfig,
    params: HashMap<String, Value>,
    cache: HashMap<String, Vec<Record>>,
}

/// One raw observation produced by a platform module.
pub struct Raw {
    pub time: String,
    pub time_source: &'static str,
    pub source: String,
    pub values: Map<String, Value>,
}

pub struct FileCandidate {
    pub path: PathBuf,
    pub time: String,
    pub time_source: &'static str,
    pub size: u64,
}

impl LiveCollector {
    pub fn new(host_id: String, files: FileScanConfig) -> Self {
        Self { host_id, files, params: HashMap::new(), cache: HashMap::new() }
    }

    fn collector_name(entity: &str) -> String {
        #[cfg(windows)]
        let p = "Windows";
        #[cfg(not(windows))]
        let p = "Linux";
        format!("{p}{entity}Collector")
    }

    fn build(&self, entity: &str, raws: Vec<Raw>, observed: &str) -> Result<Vec<Record>> {
        let collector = Self::collector_name(entity);
        raws.into_iter()
            .map(|r| {
                make_record(
                    RecordMeta {
                        entity,
                        host: &self.host_id,
                        time: &r.time,
                        time_source: r.time_source,
                        observed_at: observed,
                        collector: &collector,
                        collector_version: AGENT_COLLECTOR_VERSION,
                        source: &r.source,
                    },
                    r.values,
                )
            })
            .collect()
    }

    fn hash_mode(&self, stream: &Value) -> String {
        self.params
            .get(stream["id"].as_str().unwrap_or(""))
            .and_then(|p| p["hash"].as_str())
            .unwrap_or("after-filter")
            .to_string()
    }

    fn wants_hash(stream: &Value) -> bool {
        match stream["fields"].as_array() {
            None => true,
            Some(f) => f.iter().any(|x| x == "sha256"),
        }
    }
}

pub fn walk_files(cfg: &FileScanConfig, bounds: Bounds, stats: &mut StreamStats) -> Vec<FileCandidate> {
    let mut out = Vec::new();
    let mut pruned = 0u64;
    let mut stack: Vec<(PathBuf, usize)> = cfg.roots.iter().filter(|r| r.exists()).map(|r| (r.clone(), 0)).collect();
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if depth + 1 < cfg.max_depth {
                    stack.push((entry.path(), depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            seen += 1;
            if seen > cfg.max_files {
                stats.note = Some(format!("file scan capped at {} files", cfg.max_files));
                stats.pruned = Some(pruned);
                return out;
            }
            let Ok(md) = entry.metadata() else { continue };
            let (t, src) = match md.created() {
                Ok(c) => (c, "birth"),
                Err(_) => match md.modified() {
                    Ok(m) => (m, "mtime"),
                    Err(_) => continue,
                },
            };
            let time = crate::core::canonical::format_time(&chrono::DateTime::<chrono::Utc>::from(t));
            // collector-level temporal pushdown: skip before (expensive) attribution
            if bounds.lo.map_or(false, |l| time.as_str() < l) || bounds.hi.map_or(false, |h| time.as_str() > h) {
                pruned += 1;
                continue;
            }
            out.push(FileCandidate { path: entry.path(), time, time_source: src, size: md.len() });
        }
    }
    stats.pruned = Some(pruned);
    out
}

pub fn file_values(path: &Path, size: u64, pid: Option<u32>, attribution: &str) -> Map<String, Value> {
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e.to_string(),
        None => String::new(),
    };
    let mut v = Map::new();
    v.insert("pid".into(), pid.map(|p| json!(p)).unwrap_or(Value::Null));
    v.insert("path".into(), json!(path.to_string_lossy()));
    v.insert("name".into(), json!(name));
    v.insert("extension".into(), json!(ext));
    v.insert("size".into(), json!(size));
    v.insert("action".into(), json!("create"));
    v.insert("attribution".into(), json!(attribution));
    v.insert("sha256".into(), Value::Null);
    v
}

pub fn hash_file(path: &str, max: u64) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    if f.metadata().ok()?.len() > max {
        return None;
    }
    let mut h = Sha256::new();
    let mut r = std::io::BufReader::new(f);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

impl Collector for LiveCollector {
    fn platform(&self) -> &'static str {
        #[cfg(windows)]
        return "windows";
        #[cfg(not(windows))]
        return "linux";
    }

    fn collectors(&self) -> Vec<String> {
        ["Process", "File", "NetworkConnection", "User", "Event"].iter().map(|e| Self::collector_name(e)).collect()
    }

    /// Pick up per-stream collector params for this platform from the contract plan.
    fn prepare(&mut self, body: &Value) {
        self.cache.clear();
        self.params.clear();
        let platform = self.platform();
        for c in body["plan"]["platforms"][platform]["collectors"].as_array().into_iter().flatten() {
            if let Some(sid) = c["stream"].as_str() {
                self.params.insert(sid.to_string(), c["params"].clone());
            }
        }
    }

    fn collect(&mut self, entity: &str, stream: &Value, bounds: Bounds, stats: &mut StreamStats) -> Result<Vec<Record>> {
        let cache_key = format!("{entity}|{:?}|{:?}", bounds.lo, bounds.hi);
        if let Some(c) = self.cache.get(&cache_key) {
            stats.scanned = c.len() as u64;
            return Ok(c.clone());
        }
        let observed = now();
        let raws = match entity {
            "Process" => platform::processes()?,
            "NetworkConnection" => platform::network(&observed)?,
            "User" => platform::users(&observed)?,
            "Event" => platform::events(bounds, stats)?,
            "File" => {
                let cands = walk_files(&self.files, bounds, stats);
                let mut raws = platform::attribute_files(cands)?;
                if self.hash_mode(stream) == "before-filter" && Self::wants_hash(stream) {
                    let mut n = 0;
                    for r in raws.iter_mut() {
                        let p = r.values["path"].as_str().unwrap_or("").to_string();
                        if let Some(h) = hash_file(&p, 64 * 1024 * 1024) {
                            r.values.insert("sha256".into(), json!(h));
                            n += 1;
                        }
                    }
                    stats.hashed = Some(n);
                }
                raws
            }
            other => anyhow::bail!("no live collector for {other}"),
        };
        stats.scanned = raws.len() as u64;
        let recs = self.build(entity, raws, &observed)?;
        self.cache.insert(cache_key, recs.clone());
        Ok(recs)
    }

    fn enrich(&mut self, entity: &str, stream: &Value, records: &mut [Record], stats: &mut StreamStats, limits: &Value) {
        if entity != "File" || !Self::wants_hash(stream) || self.hash_mode(stream) != "after-filter" {
            return;
        }
        let max = limits["max_hash_bytes"].as_u64().unwrap_or(64 * 1024 * 1024);
        let mut n = 0;
        for r in records.iter_mut() {
            let Some(Value::Object(f)) = r.get_mut("fields") else { continue };
            let path = f.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string();
            if let Some(h) = hash_file(&path, max) {
                f.insert("sha256".into(), json!(h));
                n += 1;
            }
        }
        stats.hashed = Some(n);
    }
}

#[cfg(windows)]
use crate::windows as platform;
#[cfg(not(windows))]
use crate::linux as platform;

pub fn source_label(api: &str) -> String {
    format!("live:{api}")
}

pub fn stable_id(parts: &[&str]) -> String {
    sha256_hex(parts.join("|").as_bytes())[..16].to_string()
}
