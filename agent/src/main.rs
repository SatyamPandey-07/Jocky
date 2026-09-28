//! JOCKY endpoint agent.
//!
//!   jocky-agent run      connect to the control plane and execute signed contracts
//!   jocky-agent exec     verify + execute one signed contract file locally (air-gapped / conformance)
//!   jocky-agent collect  print what a live collector observes (diagnostics)
//!   jocky-agent id       print this agent's identity key id

mod collectors;
mod core;
mod transport;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

use crate::collectors::live::{FileScanConfig, LiveCollector};
use crate::core::canonical::{canonical_json, digest};
use crate::core::contract::{self, decode_b64, VerifyInput};
use crate::core::executor::{self, Bounds, Collector, StreamStats};
use crate::core::identity::State;
use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "jocky-agent", version, about = "JOCKY read-only forensic endpoint agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// Endpoint identity used in evidence (e.g. WIN-01)
    #[arg(long, env = "JOCKY_HOST_ID")]
    host_id: String,
    /// windows | linux | offline (default: this OS)
    #[arg(long, env = "JOCKY_PLATFORM")]
    platform: Option<String>,
    /// Offline evidence dataset directory (platform=offline)
    #[arg(long, env = "JOCKY_DATASET")]
    dataset: Option<PathBuf>,
    /// Local capability allowlist (comma separated; `*` suffix = prefix match)
    #[arg(long, env = "JOCKY_ALLOW", value_delimiter = ',',
          default_value = "collect:process,collect:file,collect:network,collect:user,collect:event,preserve:records")]
    allow: Vec<String>,
    /// Roots scanned by the live File collector (separated by ';')
    #[arg(long, env = "JOCKY_FILE_ROOTS", value_delimiter = ';')]
    file_roots: Vec<String>,
    #[arg(long, env = "JOCKY_FILE_MAX_DEPTH", default_value_t = 6)]
    file_max_depth: usize,
    #[arg(long, env = "JOCKY_FILE_MAX_FILES", default_value_t = 50_000)]
    file_max_files: usize,
}

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[command(flatten)]
        common: Common,
        #[arg(long, env = "JOCKY_CONTROL_PLANE", default_value = "https://localhost:50051")]
        control_plane: String,
        #[arg(long, env = "JOCKY_CA")]
        ca: Option<PathBuf>,
        #[arg(long, env = "JOCKY_TLS_DOMAIN")]
        tls_domain: Option<String>,
        #[arg(long, env = "JOCKY_CLIENT_CERT")]
        client_cert: Option<PathBuf>,
        #[arg(long, env = "JOCKY_CLIENT_KEY")]
        client_key: Option<PathBuf>,
        #[arg(long, env = "JOCKY_ENROLLMENT_TOKEN", default_value = "")]
        enrollment_token: String,
        #[arg(long, env = "JOCKY_STATE_DIR", default_value = ".jocky-agent")]
        state_dir: PathBuf,
        /// Pin the control-plane signing key (hex); otherwise trust-on-first-use over verified TLS
        #[arg(long, env = "JOCKY_CP_PUBKEY")]
        cp_pubkey: Option<String>,
    },
    Exec {
        #[command(flatten)]
        common: Common,
        /// Signed contract envelope: {"contract": {...}, "signature": {...}}
        #[arg(long)]
        contract: PathBuf,
        /// Trusted issuer key (base64 raw Ed25519); defaults to the issuer key in the envelope
        #[arg(long)]
        issuer_key: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Collect {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        entity: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Only records newer than this many seconds
        #[arg(long)]
        since: Option<i64>,
    },
    Id {
        #[arg(long, env = "JOCKY_STATE_DIR", default_value = ".jocky-agent")]
        state_dir: PathBuf,
    },
}

fn default_roots() -> Vec<String> {
    #[cfg(windows)]
    {
        let mut v = Vec::new();
        if let Ok(t) = std::env::var("TEMP") {
            v.push(t);
        }
        if let Ok(h) = std::env::var("USERPROFILE") {
            v.push(format!("{h}\\Downloads"));
        }
        v
    }
    #[cfg(not(windows))]
    {
        vec!["/tmp".into(), "/var/tmp".into(), "/dev/shm".into(), "/home".into(), "/root".into()]
    }
}

fn expand(root: &str) -> String {
    let mut out = root.to_string();
    for (k, v) in std::env::vars() {
        out = out.replace(&format!("%{k}%"), &v).replace(&format!("${{{k}}}"), &v);
    }
    out
}

fn platform_of(c: &Common) -> String {
    c.platform.clone().unwrap_or_else(|| if cfg!(windows) { "windows".into() } else { "linux".into() })
}

fn files_of(c: &Common) -> FileScanConfig {
    let roots = if c.file_roots.is_empty() { default_roots() } else { c.file_roots.clone() };
    FileScanConfig {
        roots: roots.iter().filter(|r| !r.is_empty()).map(|r| PathBuf::from(expand(r))).collect(),
        max_depth: c.file_max_depth,
        max_files: c.file_max_files,
    }
}

fn config(c: &Common) -> transport::AgentConfig {
    transport::AgentConfig {
        host_id: c.host_id.clone(),
        platform: platform_of(c),
        dataset: c.dataset.clone(),
        control_plane: String::new(),
        ca: None,
        tls_domain: None,
        client_cert: None,
        client_key: None,
        enrollment_token: String::new(),
        state_dir: PathBuf::from(".jocky-agent"),
        allow: c.allow.clone(),
        cp_pubkey: None,
        files: files_of(c),
    }
}

fn exec_local(common: Common, contract_path: PathBuf, issuer_key: Option<String>, out: Option<PathBuf>) -> Result<()> {
    let env: Value = serde_json::from_str(&std::fs::read_to_string(&contract_path)?)?;
    let body = &env["contract"];
    let bytes = canonical_json(body);
    let sig = decode_b64(env["signature"]["value"].as_str().ok_or_else(|| anyhow!("signature missing"))?)?;
    let key_b64 = issuer_key.unwrap_or_else(|| body["issuer"]["public_key"].as_str().unwrap_or("").to_string());
    let key_raw: [u8; 32] = decode_b64(&key_b64)?.as_slice().try_into().map_err(|_| anyhow!("issuer key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_raw)?;
    let cfg = config(&common);
    let mut collector = transport::make_collector(&cfg)?;
    let supported = collector.collectors();
    let (parsed, ver) = contract::verify(VerifyInput {
        contract_bytes: &bytes,
        signature: &sig,
        trusted_key: &key,
        host_id: &cfg.host_id,
        platform: &cfg.platform,
        allow: &cfg.allow,
        seen_nonces: &Default::default(),
        supported_collectors: &supported,
    });
    if !ver.ok || parsed.is_none() {
        let report = json!({"verification": ver});
        println!("{}", serde_json::to_string_pretty(&report)?);
        anyhow::bail!("contract rejected: {}", ver.failures().join("; "));
    }
    let body = parsed.unwrap();
    let res = executor::execute(&body, collector.as_mut())?;
    let result = json!({
        "verification": ver,
        "contract_hash": digest(&body),
        "stats": res.stats,
        "streams": res.streams,
    });
    let text = serde_json::to_string(&result)?;
    match out {
        Some(p) => std::fs::write(p, text)?,
        None => println!("{text}"),
    }
    Ok(())
}

fn collect_debug(common: Common, entity: String, limit: usize, since: Option<i64>) -> Result<()> {
    let cfg = config(&common);
    let mut c = LiveCollector::new(cfg.host_id.clone(), cfg.files.clone());
    let lo = since.map(|s| crate::core::canonical::shift_time(&crate::core::canonical::now(), -s)).transpose()?;
    let mut st = StreamStats::default();
    let stream = json!({"id": "debug", "entity": entity, "fields": null});
    let recs = c.collect(&entity, &stream, Bounds { lo: lo.as_deref(), hi: None }, &mut st)?;
    let mut recs: Vec<_> = recs.into_iter().filter(|r| lo.as_deref().map_or(true, |l| r["time"].as_str().unwrap_or("") >= l)).collect();
    recs.sort_by(|a, b| b["time"].as_str().cmp(&a["time"].as_str()));
    eprintln!("{} {} records (stats: {})", recs.len(), entity, serde_json::to_string(&st)?);
    for r in recs.iter().take(limit) {
        println!("{}", serde_json::to_string(r)?);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { common, control_plane, ca, tls_domain, client_cert, client_key, enrollment_token, state_dir, cp_pubkey } => {
            let mut cfg = config(&common);
            cfg.control_plane = control_plane;
            cfg.ca = ca;
            cfg.tls_domain = tls_domain;
            cfg.client_cert = client_cert;
            cfg.client_key = client_key;
            cfg.enrollment_token = enrollment_token;
            cfg.state_dir = state_dir;
            cfg.cp_pubkey = cp_pubkey;
            transport::log!("jocky-agent {} starting: host={} platform={} allow={:?}",
                            env!("CARGO_PKG_VERSION"), cfg.host_id, cfg.platform, cfg.allow);
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(transport::run(cfg))
        }
        Cmd::Exec { common, contract, issuer_key, out } => exec_local(common, contract, issuer_key, out),
        Cmd::Collect { common, entity, limit, since } => collect_debug(common, entity, limit, since),
        Cmd::Id { state_dir } => {
            let s = State::open(state_dir)?;
            let pk = s.public_key().to_bytes();
            println!("public_key={} key_id={}", hex::encode(pk), contract::key_id(&pk));
            Ok(())
        }
    }
}
