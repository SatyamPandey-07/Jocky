//! Windows collectors.  Read-only APIs only:
//!  * processes    — sysinfo (Toolhelp / NtQuerySystemInformation)
//!  * network      — GetExtendedTcpTable / GetExtendedUdpTable (owner-module rows,
//!                   which carry the socket creation timestamp)
//!  * files        — directory walk + creation time, attributed with the
//!                   Restart Manager (which processes hold a file open)
//!  * events       — EvtQuery with an XPath time filter (temporal pushdown)

use crate::collectors::direction;
use crate::collectors::live::{file_values, source_label, FileCandidate, Raw};
use crate::core::canonical::{canonical_time, from_unix_micros};
use crate::core::executor::{Bounds, StreamStats};
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use sysinfo::{System, Users};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_MODULE, MIB_TCPROW_OWNER_MODULE,
    MIB_UDP6ROW_OWNER_MODULE, MIB_UDPROW_OWNER_MODULE, TCP_TABLE_OWNER_MODULE_ALL, UDP_TABLE_OWNER_MODULE,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender, EvtRenderEventXml,
};
use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY, RM_PROCESS_INFO,
};

const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn filetime_to_time(ft: i64) -> Option<String> {
    if ft <= FILETIME_UNIX_EPOCH {
        return None;
    }
    Some(from_unix_micros((ft - FILETIME_UNIX_EPOCH) / 10))
}

pub fn processes() -> Result<Vec<Raw>> {
    let sys = System::new_all();
    let users = Users::new_with_refreshed_list();
    let mut out = Vec::new();
    for (pid, p) in sys.processes() {
        let user = p.user_id().and_then(|u| users.get_user_by_id(u)).map(|u| u.name().to_string());
        let cmd = p.cmd().join(" ");
        let mut v = Map::new();
        v.insert("pid".into(), json!(pid.as_u32()));
        v.insert("ppid".into(), p.parent().map(|pp| json!(pp.as_u32())).unwrap_or(Value::Null));
        v.insert("name".into(), json!(p.name()));
        v.insert("path".into(), p.exe().map(|e| json!(e.to_string_lossy())).unwrap_or(Value::Null));
        v.insert("cmdline".into(), if cmd.is_empty() { Value::Null } else { json!(cmd) });
        v.insert("user".into(), user.map(Value::String).unwrap_or(Value::Null));
        out.push(Raw {
            time: from_unix_micros(p.start_time() as i64 * 1_000_000),
            time_source: "start",
            source: source_label("sysinfo"),
            values: v,
        });
    }
    Ok(out)
}

fn port(dw: u32) -> u16 {
    u16::from_be((dw & 0xffff) as u16)
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RECV", 5 => "ESTABLISHED", 6 => "FIN_WAIT1",
        7 => "FIN_WAIT2", 8 => "CLOSE_WAIT", 9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT",
        12 => "DELETE_TCB", _ => "UNKNOWN",
    }
}

/// Fetch an IP Helper table into an 8-byte-aligned buffer.
fn fetch(f: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size: u32 = 0;
    let r = f(std::ptr::null_mut(), &mut size);
    if r != ERROR_INSUFFICIENT_BUFFER && r != 0 {
        return None;
    }
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize + 7) / 8 + 1];
        let r = f(buf.as_mut_ptr() as *mut _, &mut size);
        if r == 0 {
            return Some(buf);
        }
        if r != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
    }
    None
}

unsafe fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let base = buf.as_ptr() as *const u8;
    let n = *(base as *const u32) as usize;
    // rows start at the first T-aligned offset after dwNumEntries
    let first = base.add(std::mem::align_of::<T>().max(4));
    (0..n).map(|i| std::ptr::read_unaligned(first.add(i * std::mem::size_of::<T>()) as *const T)).collect()
}

struct Sock {
    proto: &'static str,
    state: String,
    local: (IpAddr, u16),
    remote: Option<(IpAddr, u16)>,
    pid: u32,
    created: i64,
}

pub fn network(observed: &str) -> Result<Vec<Raw>> {
    let mut socks = Vec::new();
    unsafe {
        if let Some(b) = fetch(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)) {
            for r in rows::<MIB_TCPROW_OWNER_MODULE>(&b) {
                socks.push(Sock {
                    proto: "tcp",
                    state: tcp_state(r.dwState).into(),
                    local: (IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes())), port(r.dwLocalPort)),
                    remote: Some((IpAddr::V4(Ipv4Addr::from(r.dwRemoteAddr.to_le_bytes())), port(r.dwRemotePort))),
                    pid: r.dwOwningPid,
                    created: r.liCreateTimestamp,
                });
            }
        }
        if let Some(b) = fetch(|p, s| GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_MODULE_ALL, 0)) {
            for r in rows::<MIB_TCP6ROW_OWNER_MODULE>(&b) {
                socks.push(Sock {
                    proto: "tcp",
                    state: tcp_state(r.dwState).into(),
                    local: (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
                    remote: Some((IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)), port(r.dwRemotePort))),
                    pid: r.dwOwningPid,
                    created: r.liCreateTimestamp,
                });
            }
        }
        if let Some(b) = fetch(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_MODULE, 0)) {
            for r in rows::<MIB_UDPROW_OWNER_MODULE>(&b) {
                socks.push(Sock {
                    proto: "udp",
                    state: "UNCONN".into(),
                    local: (IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes())), port(r.dwLocalPort)),
                    remote: None,
                    pid: r.dwOwningPid,
                    created: r.liCreateTimestamp,
                });
            }
        }
        if let Some(b) = fetch(|p, s| GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_MODULE, 0)) {
            for r in rows::<MIB_UDP6ROW_OWNER_MODULE>(&b) {
                socks.push(Sock {
                    proto: "udp",
                    state: "UNCONN".into(),
                    local: (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), port(r.dwLocalPort)),
                    remote: None,
                    pid: r.dwOwningPid,
                    created: r.liCreateTimestamp,
                });
            }
        }
    }
    let listening: HashSet<u16> = socks.iter().filter(|s| s.state == "LISTEN").map(|s| s.local.1).collect();
    let mut out = Vec::new();
    for s in socks {
        let remote = s.remote.filter(|(ip, p)| !(ip.is_unspecified() && *p == 0));
        let norm = |ip: IpAddr| match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let dir = direction(&s.state, Some(s.local.1), remote.map(|r| r.0), &listening);
        let mut v = Map::new();
        v.insert("pid".into(), if s.pid == 0 { Value::Null } else { json!(s.pid) });
        v.insert("protocol".into(), json!(s.proto));
        v.insert("direction".into(), json!(dir));
        v.insert("state".into(), json!(s.state));
        v.insert("local_ip".into(), json!(norm(s.local.0).to_string()));
        v.insert("local_port".into(), json!(s.local.1));
        v.insert("remote_ip".into(), remote.map(|r| json!(norm(r.0).to_string())).unwrap_or(Value::Null));
        v.insert("remote_port".into(), remote.map(|r| json!(r.1)).unwrap_or(Value::Null));
        let (time, ts) = match filetime_to_time(s.created) {
            Some(t) => (t, "event"),
            None => (observed.to_string(), "observed"),
        };
        out.push(Raw { time, time_source: ts, source: source_label("iphlpapi"), values: v });
    }
    Ok(out)
}

pub fn users(observed: &str) -> Result<Vec<Raw>> {
    let users = Users::new_with_refreshed_list();
    let mut out = Vec::new();
    for u in users.list() {
        let mut v = Map::new();
        v.insert("name".into(), json!(u.name()));
        v.insert("uid".into(), json!(u.id().to_string()));
        v.insert("domain".into(), Value::Null);
        v.insert("home".into(), Value::Null);
        out.push(Raw { time: observed.to_string(), time_source: "observed", source: source_label("sysinfo-users"), values: v });
    }
    Ok(out)
}

/// Processes currently holding `path` open, via the Restart Manager.
fn holders(path: &std::path::Path) -> Vec<u32> {
    unsafe {
        let mut session: u32 = 0;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        if RmStartSession(&mut session, 0, key.as_mut_ptr()) != 0 {
            return vec![];
        }
        let w = wide(path.as_os_str());
        let files = [w.as_ptr()];
        let mut pids = Vec::new();
        if RmRegisterResources(session, 1, files.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) == 0 {
            let mut needed: u32 = 0;
            let mut count: u32 = 0;
            let mut reasons: u32 = 0;
            let r = RmGetList(session, &mut needed, &mut count, std::ptr::null_mut(), &mut reasons);
            if r == ERROR_MORE_DATA && needed > 0 {
                let mut infos: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); needed as usize];
                count = needed;
                if RmGetList(session, &mut needed, &mut count, infos.as_mut_ptr(), &mut reasons) == 0 {
                    for info in &infos[..count as usize] {
                        let pid = info.Process.dwProcessId;
                        if !pids.contains(&pid) {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
        RmEndSession(session);
        pids
    }
}

pub fn attribute_files(cands: Vec<FileCandidate>) -> Result<Vec<Raw>> {
    let mut out = Vec::new();
    for c in cands {
        let pids = holders(&c.path);
        let src = source_label("ntfs-metadata+restart-manager");
        if pids.is_empty() {
            out.push(Raw { time: c.time.clone(), time_source: c.time_source, source: src,
                           values: file_values(&c.path, c.size, None, "none") });
        }
        for pid in pids {
            out.push(Raw { time: c.time.clone(), time_source: c.time_source, source: src.clone(),
                           values: file_values(&c.path, c.size, Some(pid), "open-handle") });
        }
    }
    Ok(out)
}

fn xml_attr<'a>(xml: &'a str, tag: &str, attr: &str) -> Option<&'a str> {
    let at = xml.find(&format!("<{tag} "))?;
    let seg = &xml[at..at + xml[at..].find('>')?];
    for q in ['\'', '"'] {
        if let Some(i) = seg.find(&format!("{attr}={q}")) {
            let v = &seg[i + attr.len() + 2..];
            return v.find(q).map(|e| &v[..e]);
        }
    }
    None
}

fn xml_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let at = xml.find(&format!("<{tag}"))?;
    let open_end = at + xml[at..].find('>')?;
    if xml[..open_end].ends_with('/') {
        return None;
    }
    let body = &xml[open_end + 1..];
    body.find(&format!("</{tag}>")).map(|e| &body[..e])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn event_data(xml: &str) -> String {
    let mut parts = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data") {
        rest = &rest[i..];
        let Some(close) = rest.find('>') else { break };
        let head = &rest[..close];
        if head.ends_with('/') {
            rest = &rest[close..];
            continue;
        }
        let name = xml_attr(head, "Data", "Name").or_else(|| xml_attr(&format!("{head} "), "Data", "Name"));
        let body = &rest[close + 1..];
        let Some(end) = body.find("</Data>") else { break };
        let val = unescape(&body[..end]);
        parts.push(match name {
            Some(n) => format!("{n}={val}"),
            None => val,
        });
        rest = &body[end..];
    }
    parts.join("; ")
}

fn level_name(l: &str) -> &'static str {
    match l {
        "1" => "Critical", "2" => "Error", "3" => "Warning", "4" | "0" => "Information", "5" => "Verbose", _ => "Unknown",
    }
}

const MAX_EVENTS_PER_CHANNEL: usize = 20_000;

pub fn events(bounds: Bounds, stats: &mut StreamStats) -> Result<Vec<Raw>> {
    // Temporal pushdown into the Event Log service itself.
    let mut conds = Vec::new();
    if let Some(lo) = bounds.lo {
        conds.push(format!("@SystemTime>='{lo}'"));
    }
    if let Some(hi) = bounds.hi {
        conds.push(format!("@SystemTime<='{hi}'"));
    }
    let query = if conds.is_empty() { "*".to_string() } else { format!("*[System[TimeCreated[{}]]]", conds.join(" and ")) };
    let mut out = Vec::new();
    let mut capped = false;
    for channel in ["System", "Application"] {
        unsafe {
            let ch = wide(std::ffi::OsStr::new(channel));
            let q = wide(std::ffi::OsStr::new(&query));
            let h = EvtQuery(0, ch.as_ptr(), q.as_ptr(), (EvtQueryChannelPath | EvtQueryForwardDirection) as u32);
            if h == 0 {
                continue;
            }
            let mut buf: Vec<u16> = vec![0; 16 * 1024];
            'outer: loop {
                let mut evts = [0isize; 64];
                let mut returned: u32 = 0;
                if EvtNext(h, evts.len() as u32, evts.as_mut_ptr(), 1000, 0, &mut returned) == 0 {
                    break;
                }
                for &e in &evts[..returned as usize] {
                    let mut used: u32 = 0;
                    let mut props: u32 = 0;
                    let mut ok = EvtRender(0, e, EvtRenderEventXml as u32, (buf.len() * 2) as u32,
                                           buf.as_mut_ptr() as *mut _, &mut used, &mut props);
                    if ok == 0 && used as usize > buf.len() * 2 {
                        buf = vec![0; used as usize / 2 + 1];
                        ok = EvtRender(0, e, EvtRenderEventXml as u32, (buf.len() * 2) as u32,
                                       buf.as_mut_ptr() as *mut _, &mut used, &mut props);
                    }
                    EvtClose(e);
                    if ok == 0 {
                        continue;
                    }
                    let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).saturating_sub(1)]);
                    let Some(t) = xml_attr(&xml, "TimeCreated", "SystemTime").and_then(|t| canonical_time(t).ok()) else { continue };
                    let mut v = Map::new();
                    v.insert("channel".into(), json!(xml_text(&xml, "Channel").unwrap_or(channel)));
                    v.insert("provider".into(), xml_attr(&xml, "Provider", "Name").map(|p| json!(p)).unwrap_or(Value::Null));
                    v.insert("event_id".into(), xml_text(&xml, "EventID").and_then(|x| x.trim().parse::<i64>().ok()).map(|x| json!(x)).unwrap_or(Value::Null));
                    v.insert("record_id".into(), xml_text(&xml, "EventRecordID").and_then(|x| x.trim().parse::<i64>().ok()).map(|x| json!(x)).unwrap_or(Value::Null));
                    v.insert("level".into(), xml_text(&xml, "Level").map(|l| json!(level_name(l.trim()))).unwrap_or(Value::Null));
                    v.insert("pid".into(), xml_attr(&xml, "Execution", "ProcessID").and_then(|x| x.parse::<i64>().ok()).map(|x| json!(x)).unwrap_or(Value::Null));
                    let msg: String = event_data(&xml).chars().take(512).collect();
                    v.insert("message".into(), if msg.is_empty() { Value::Null } else { json!(msg) });
                    out.push(Raw { time: t, time_source: "event", source: source_label(&format!("evtquery:{channel}")), values: v });
                    if out.len() >= MAX_EVENTS_PER_CHANNEL * 2 {
                        capped = true;
                        break 'outer;
                    }
                }
            }
            EvtClose(h);
        }
    }
    stats.note = Some(if capped { format!("event query capped; xpath: {query}") } else { format!("xpath: {query}") });
    Ok(out)
}
