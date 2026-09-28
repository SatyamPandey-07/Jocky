//! gRPC client loop: register, poll for tasks, verify, execute, upload evidence.

use crate::collectors::live::{FileScanConfig, LiveCollector};
use crate::collectors::offline::OfflineCollector;
use crate::core::canonical::sha256_hex;
use crate::core::contract::{self, VerifyInput};
use crate::core::executor::{self, Collector};
use crate::core::identity::State;
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::VerifyingKey;
use prost::Message;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

pub mod pb {
    tonic::include_proto!("jocky.agent.v1");
}
use pb::agent_service_client::AgentServiceClient;

pub const BATCH_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub host_id: String,
    pub platform: String,
    pub dataset: Option<PathBuf>,
    pub control_plane: String,
    pub ca: Option<PathBuf>,
    pub tls_domain: Option<String>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    pub enrollment_token: String,
    pub state_dir: PathBuf,
    pub allow: Vec<String>,
    pub cp_pubkey: Option<String>,
    pub files: FileScanConfig,
}

macro_rules! log {
    ($($arg:tt)*) => { eprintln!("{} {}", crate::core::canonical::now(), format!($($arg)*)) };
}
pub(crate) use log;

pub fn make_collector(cfg: &AgentConfig) -> Result<Box<dyn Collector + Send>> {
    Ok(match cfg.platform.as_str() {
        "offline" => Box::new(OfflineCollector::open(cfg.dataset.as_ref().ok_or_else(|| anyhow!("--dataset required for offline"))?)?),
        _ => Box::new(LiveCollector::new(cfg.host_id.clone(), cfg.files.clone())),
    })
}

async fn connect(cfg: &AgentConfig) -> Result<Channel> {
    let mut ep = Channel::from_shared(cfg.control_plane.clone())?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120));
    if cfg.control_plane.starts_with("https://") {
        let ca = std::fs::read(cfg.ca.as_ref().ok_or_else(|| anyhow!("--ca is required for https"))?)
            .context("reading CA certificate")?;
        let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
        if let Some(d) = &cfg.tls_domain {
            tls = tls.domain_name(d.clone());
        }
        if let (Some(c), Some(k)) = (&cfg.client_cert, &cfg.client_key) {
            tls = tls.identity(Identity::from_pem(std::fs::read(c)?, std::fs::read(k)?));
        }
        ep = ep.tls_config(tls)?;
    } else {
        log!("WARNING: plaintext transport to {} (development only)", cfg.control_plane);
    }
    Ok(ep.connect().await?)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

struct Session {
    client: AgentServiceClient<Channel>,
    state: State,
    agent_id: String,
    cp_key: VerifyingKey,
    cfg: AgentConfig,
}

impl Session {
    fn auth(&self, method: &str, payload_sha: &str) -> pb::Auth {
        let ts = now_ms();
        let msg = format!("{method}|{}|{ts}|{payload_sha}", self.agent_id);
        pb::Auth { agent_id: self.agent_id.clone(), timestamp_ms: ts, signature: self.state.sign(msg.as_bytes()) }
    }

    async fn update(&mut self, task_id: &str, state: &str, message: &str, detail: &Value) -> Result<()> {
        let detail_json = serde_json::to_vec(detail)?;
        let mut pre = format!("{task_id}\n{state}\n{message}\n").into_bytes();
        pre.extend_from_slice(&detail_json);
        let auth = self.auth("UpdateTask", &sha256_hex(&pre));
        self.client
            .update_task(pb::TaskUpdate { auth: Some(auth), task_id: task_id.into(), state: state.into(), message: message.into(), detail_json })
            .await?;
        log!("task {task_id}: {state} {message}");
        Ok(())
    }

    async fn handle(&mut self, task: pb::Task) -> Result<()> {
        let tid = task.task_id.clone();
        self.update(&tid, "RECEIVED", "", &json!({})).await?;
        let mut collector = make_collector(&self.cfg)?;
        let supported = collector.collectors();
        let (body, ver) = contract::verify(VerifyInput {
            contract_bytes: &task.contract,
            signature: &task.contract_signature,
            trusted_key: &self.cp_key,
            host_id: &self.cfg.host_id,
            platform: &self.cfg.platform,
            allow: &self.cfg.allow,
            seen_nonces: &self.state.nonces,
            supported_collectors: &supported,
        });
        let ver_json = serde_json::to_value(&ver)?;
        let Some(body) = body.filter(|_| ver.ok) else {
            let msg = ver.failures().join("; ");
            return self.update(&tid, "REJECTED", &msg, &json!({"verification": ver_json})).await;
        };
        self.state.remember_nonce(body["nonce"].as_str().unwrap_or(""))?;
        self.update(&tid, "VERIFIED", "contract verified", &json!({"verification": ver_json})).await?;
        self.update(&tid, "RUNNING", "collecting", &json!({})).await?;
        let timeout = body["limits"]["timeout_seconds"].as_u64().unwrap_or(300);
        let exec_body = body.clone();
        let job = tokio::task::spawn_blocking(move || executor::execute(&exec_body, collector.as_mut()));
        let out = match tokio::time::timeout(Duration::from_secs(timeout), job).await {
            Err(_) => return self.update(&tid, "FAILED", &format!("timeout after {timeout}s"), &json!({})).await,
            Ok(Err(e)) => return self.update(&tid, "FAILED", &format!("executor panicked: {e}"), &json!({})).await,
            Ok(Ok(Err(e))) => return self.update(&tid, "FAILED", &format!("{e:#}"), &json!({})).await,
            Ok(Ok(Ok(o))) => o,
        };
        self.update(&tid, "UPLOADING", "", &json!({"records": out.stats["records"]})).await?;
        let (mut batches, mut payload, mut wire) = (0u64, 0u64, 0u64);
        for (sid, recs) in &out.streams {
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            let mut cur = Vec::new();
            let mut counts = Vec::new();
            let mut n = 0u32;
            for r in recs {
                let line = executor::encode_jsonl(std::slice::from_ref(r));
                if !cur.is_empty() && cur.len() + line.len() > BATCH_BYTES {
                    chunks.push(std::mem::take(&mut cur));
                    counts.push(n);
                    n = 0;
                }
                cur.extend_from_slice(&line);
                n += 1;
            }
            chunks.push(cur);
            counts.push(n);
            let total = chunks.len();
            for (seq, (chunk, count)) in chunks.into_iter().zip(counts).enumerate() {
                let last = seq + 1 == total;
                let rsha = sha256_hex(&chunk);
                let pre = format!("{tid}\n{sid}\n{seq}\n{rsha}\n{last}");
                let msg = pb::EvidenceBatch {
                    auth: Some(self.auth("SubmitEvidence", &sha256_hex(pre.as_bytes()))),
                    task_id: tid.clone(),
                    stream_id: sid.clone(),
                    seq: seq as u32,
                    records_sha256: rsha,
                    record_count: count,
                    last,
                    records_jsonl: chunk,
                };
                payload += msg.records_jsonl.len() as u64;
                wire += msg.encoded_len() as u64;
                batches += 1;
                let ack = self.client.submit_evidence(msg).await?.into_inner();
                if !ack.ok {
                    return self.update(&tid, "FAILED", &format!("evidence rejected: {}", ack.message), &json!({})).await;
                }
            }
        }
        let detail = json!({
            "stats": out.stats,
            "verification": ver_json,
            "transfer": {"batches": batches, "payload_bytes": payload, "wire_bytes": wire},
            "agent": {"version": env!("CARGO_PKG_VERSION"), "platform": self.cfg.platform},
        });
        self.update(&tid, "COMPLETED", &format!("{} records", out.stats["records"]), &detail).await
    }
}

pub async fn run(cfg: AgentConfig) -> Result<()> {
    let mut backoff = 1u64;
    loop {
        let state = State::open(&cfg.state_dir)?;
        let pubkey = state.public_key().to_bytes();
        match connect(&cfg).await {
            Ok(channel) => {
                let mut client = AgentServiceClient::new(channel)
                    .max_decoding_message_size(64 * 1024 * 1024)
                    .max_encoding_message_size(64 * 1024 * 1024);
                let ts = now_ms();
                let sig = state.sign(format!("Register|{}|{ts}|{}", cfg.host_id, hex::encode(pubkey)).as_bytes());
                let collectors = make_collector(&cfg)?.collectors();
                let reg = client
                    .register(pb::RegisterRequest {
                        host_id: cfg.host_id.clone(),
                        platform: cfg.platform.clone(),
                        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
                        agent_version: env!("CARGO_PKG_VERSION").into(),
                        public_key: pubkey.to_vec(),
                        enrollment_token: cfg.enrollment_token.clone(),
                        collectors,
                        capabilities: cfg.allow.clone(),
                        hostname: hostname(),
                        timestamp_ms: ts,
                        signature: sig,
                    })
                    .await;
                let reg = match reg {
                    Ok(r) => r.into_inner(),
                    Err(e) => {
                        log!("register failed: {}", e.message());
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(30);
                        continue;
                    }
                };
                let cp_key = state.pin_control_plane(&reg.control_plane_public_key, cfg.cp_pubkey.as_deref())?;
                log!("registered {} as {} (control-plane key {})", cfg.host_id, reg.agent_id, reg.control_plane_key_id);
                backoff = 1;
                let mut s = Session { client, state, agent_id: reg.agent_id, cp_key, cfg: cfg.clone() };
                let mut interval = reg.poll_interval_ms.max(250) as u64;
                loop {
                    let auth = s.auth("Poll", &sha256_hex(b""));
                    match s.client.poll(pb::PollRequest { auth: Some(auth) }).await {
                        Ok(r) => {
                            let r = r.into_inner();
                            if r.poll_interval_ms > 0 {
                                interval = r.poll_interval_ms as u64;
                            }
                            for t in r.tasks {
                                let tid = t.task_id.clone();
                                if let Err(e) = s.handle(t).await {
                                    log!("task {tid} error: {e:#}");
                                    let _ = s.update(&tid, "FAILED", &format!("{e:#}"), &json!({})).await;
                                }
                            }
                        }
                        Err(e) => {
                            log!("poll failed: {}; reconnecting", e.message());
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(interval)).await;
                }
                tokio::time::sleep(Duration::from_secs(backoff)).await;
            }
            Err(e) => {
                log!("cannot reach control plane {}: {e:#}", cfg.control_plane);
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        }
    }
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".into())
}
