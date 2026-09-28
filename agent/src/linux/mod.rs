//! Linux collectors (procfs + filesystem metadata).  Read-only.

use crate::collectors::direction;
use crate::collectors::live::{file_values, source_label, FileCandidate, Raw};
use crate::core::canonical::{canonical_time, format_time, from_unix_micros};
use crate::core::executor::{Bounds, StreamStats};
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn passwd() -> HashMap<u32, (String, String)> {
    let mut m = HashMap::new();
    for line in read("/etc/passwd").unwrap_or_default().lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 6 {
            if let Ok(uid) = f[2].parse::<u32>() {
                m.insert(uid, (f[0].to_string(), f[5].to_string()));
            }
        }
    }
    m
}

fn boot_time() -> Option<i64> {
    read("/proc/stat")?.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse().ok()))
}

fn clk_tck() -> i64 {
    // SAFETY: sysconf is always safe to call.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v } else { 100 }
}

fn pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok())).collect())
        .unwrap_or_default()
}

pub fn processes() -> Result<Vec<Raw>> {
    let users = passwd();
    let btime = boot_time().unwrap_or(0);
    let tck = clk_tck();
    let mut out = Vec::new();
    for pid in pids() {
        let Some(stat) = read(&format!("/proc/{pid}/stat")) else { continue };
        // comm is parenthesised and may contain spaces: split after the last ')'
        let (Some(l), Some(r)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = stat[l + 1..r].to_string();
        let rest: Vec<&str> = stat[r + 2..].split_whitespace().collect();
        if rest.len() < 20 {
            continue;
        }
        let ppid: i64 = rest[1].parse().unwrap_or(0);
        let start_ticks: i64 = rest[19].parse().unwrap_or(0);
        let start_us = btime * 1_000_000 + start_ticks * 1_000_000 / tck;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().to_string());
        let name = exe
            .as_ref()
            .and_then(|e| e.rsplit('/').next().map(|s| s.trim_end_matches(" (deleted)").to_string()))
            .unwrap_or_else(|| comm.clone());
        let cmdline = read(&format!("/proc/{pid}/cmdline"))
            .map(|c| c.split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "));
        let uid = read(&format!("/proc/{pid}/status")).and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("Uid:").and_then(|v| v.split_whitespace().next().and_then(|x| x.parse::<u32>().ok())))
        });
        let user = uid.map(|u| users.get(&u).map(|x| x.0.clone()).unwrap_or_else(|| u.to_string()));
        let mut v = Map::new();
        v.insert("pid".into(), json!(pid));
        v.insert("ppid".into(), json!(ppid));
        v.insert("name".into(), json!(name));
        v.insert("path".into(), exe.map(Value::String).unwrap_or(Value::Null));
        v.insert("cmdline".into(), cmdline.filter(|c| !c.is_empty()).map(Value::String).unwrap_or(Value::Null));
        v.insert("user".into(), user.map(Value::String).unwrap_or(Value::Null));
        out.push(Raw { time: from_unix_micros(start_us), time_source: "start", source: source_label("procfs"), values: v });
    }
    Ok(out)
}

fn socket_inodes() -> HashMap<u64, u32> {
    let mut m = HashMap::new();
    for pid in pids() {
        let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for e in rd.flatten() {
            if let Ok(t) = std::fs::read_link(e.path()) {
                let t = t.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(inode) = n.parse() {
                        m.entry(inode).or_insert(pid);
                    }
                }
            }
        }
    }
    m
}

fn parse_addr(hex: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = hex.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(u32::from_str_radix(ip, 16).ok()?.to_le_bytes())),
        32 => {
            let mut b = [0u8; 16];
            for w in 0..4 {
                let word = u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16).ok()?;
                b[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some((ip, port))
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED", "02" => "SYN_SENT", "03" => "SYN_RECV", "04" => "FIN_WAIT1", "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT", "07" => "CLOSE", "08" => "CLOSE_WAIT", "09" => "LAST_ACK", "0A" => "LISTEN",
        "0B" => "CLOSING", _ => "UNKNOWN",
    }
}

pub fn network(observed: &str) -> Result<Vec<Raw>> {
    let inodes = socket_inodes();
    struct Row { proto: &'static str, state: String, local: (IpAddr, u16), remote: (IpAddr, u16), inode: u64 }
    let mut rows = Vec::new();
    for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp")] {
        for line in read(file).unwrap_or_default().lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                continue;
            }
            let (Some(local), Some(remote)) = (parse_addr(f[1]), parse_addr(f[2])) else { continue };
            let state = if proto == "tcp" { tcp_state(f[3]).to_string() } else if f[3] == "01" { "CONNECTED".into() } else { "UNCONN".into() };
            rows.push(Row { proto, state, local, remote, inode: f[9].parse().unwrap_or(0) });
        }
    }
    let listening: HashSet<u16> = rows.iter().filter(|r| r.state == "LISTEN").map(|r| r.local.1).collect();
    let mut out = Vec::new();
    for r in rows {
        let remote_ip = if r.remote.0.is_unspecified() && r.remote.1 == 0 { None } else { Some(r.remote.0) };
        let dir = direction(&r.state, Some(r.local.1), remote_ip, &listening);
        let mut v = Map::new();
        v.insert("pid".into(), inodes.get(&r.inode).filter(|_| r.inode != 0).map(|p| json!(p)).unwrap_or(Value::Null));
        v.insert("protocol".into(), json!(r.proto));
        v.insert("direction".into(), json!(dir));
        v.insert("state".into(), json!(r.state));
        v.insert("local_ip".into(), json!(r.local.0.to_string()));
        v.insert("local_port".into(), json!(r.local.1));
        v.insert("remote_ip".into(), remote_ip.map(|i| json!(i.to_string())).unwrap_or(Value::Null));
        v.insert("remote_port".into(), remote_ip.map(|_| json!(r.remote.1)).unwrap_or(Value::Null));
        out.push(Raw { time: observed.to_string(), time_source: "observed", source: source_label("procfs-net"), values: v });
    }
    Ok(out)
}

pub fn users(observed: &str) -> Result<Vec<Raw>> {
    let mut out = Vec::new();
    for (uid, (name, home)) in passwd() {
        let mut v = Map::new();
        v.insert("name".into(), json!(name));
        v.insert("uid".into(), json!(uid.to_string()));
        v.insert("domain".into(), Value::Null);
        v.insert("home".into(), json!(home));
        out.push(Raw { time: observed.to_string(), time_source: "observed", source: source_label("passwd"), values: v });
    }
    Ok(out)
}

/// Open-handle attribution: which processes hold each candidate file open.
pub fn attribute_files(cands: Vec<FileCandidate>) -> Result<Vec<Raw>> {
    let mut holders: HashMap<PathBuf, Vec<u32>> = HashMap::new();
    if !cands.is_empty() {
        let wanted: HashSet<&PathBuf> = cands.iter().map(|c| &c.path).collect();
        for pid in pids() {
            let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for e in rd.flatten() {
                if let Ok(t) = std::fs::read_link(e.path()) {
                    if wanted.contains(&t) {
                        let v = holders.entry(t).or_default();
                        if !v.contains(&pid) {
                            v.push(pid);
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for c in cands {
        let src = source_label(if c.time_source == "birth" { "statx+procfs-fd" } else { "stat+procfs-fd" });
        match holders.get(&c.path) {
            Some(pids) => {
                for pid in pids {
                    out.push(Raw { time: c.time.clone(), time_source: c.time_source, source: src.clone(),
                                   values: file_values(&c.path, c.size, Some(*pid), "open-handle") });
                }
            }
            None => out.push(Raw { time: c.time.clone(), time_source: c.time_source, source: src,
                                   values: file_values(&c.path, c.size, None, "none") }),
        }
    }
    Ok(out)
}

/// syslog-style files; absent in minimal containers (reported, not fabricated).
pub fn events(bounds: Bounds, stats: &mut StreamStats) -> Result<Vec<Raw>> {
    let year = chrono::Utc::now().format("%Y").to_string();
    let mut out = Vec::new();
    let mut found = Vec::new();
    for file in ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log"] {
        let Some(text) = read(file) else { continue };
        found.push(file);
        for (n, line) in text.lines().enumerate() {
            let (time, rest) = if line.len() > 32 && line.as_bytes()[4] == b'-' {
                // RFC 3339 (rsyslog high precision): "2026-09-28T10:00:00.123456+00:00 host prog[pid]: msg"
                let (ts, rest) = line.split_once(' ').unwrap_or((line, ""));
                (canonical_time(ts).ok(), rest)
            } else if line.len() > 16 {
                // RFC 3164: "Sep 28 10:00:00 host prog[pid]: msg" (year inferred)
                let ts = format!("{year} {}", &line[..15]);
                (chrono::NaiveDateTime::parse_from_str(&ts, "%Y %b %e %H:%M:%S").ok()
                    .map(|d| format_time(&d.and_utc())), &line[16..])
            } else {
                (None, "")
            };
            let Some(time) = time else { continue };
            if bounds.lo.map_or(false, |l| time.as_str() < l) || bounds.hi.map_or(false, |h| time.as_str() > h) {
                continue;
            }
            let mut parts = rest.splitn(2, ' ');
            let _host = parts.next();
            let body = parts.next().unwrap_or("");
            let (tag, msg) = body.split_once(": ").unwrap_or(("", body));
            let (prog, pid) = match tag.split_once('[') {
                Some((p, x)) => (p.to_string(), x.trim_end_matches(']').parse::<u32>().ok()),
                None => (tag.to_string(), None),
            };
            let mut v = Map::new();
            v.insert("channel".into(), json!(file));
            v.insert("provider".into(), json!(prog));
            v.insert("event_id".into(), Value::Null);
            v.insert("record_id".into(), json!(n as u64 + 1));
            v.insert("level".into(), Value::Null);
            v.insert("pid".into(), pid.map(|p| json!(p)).unwrap_or(Value::Null));
            v.insert("message".into(), json!(msg.chars().take(512).collect::<String>()));
            out.push(Raw { time, time_source: "event", source: source_label("syslog"), values: v });
        }
    }
    if found.is_empty() {
        stats.note = Some("no syslog files present on this endpoint".into());
    }
    Ok(out)
}
