//! Canonical JSON, hashing and time encoding — byte-identical to
//! `compiler/jocky/canonical.py` (sorted keys, no whitespace, UTF-8, only
//! `"`/`\\`/control characters escaped, integers only).

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_value(value, &mut out);
    out
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(x, out);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(k, out);
                out.push(b':');
                write_value(&m[*k], out);
            }
            out.push(b'}');
        }
    }
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x00..=0x1f => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xf) as usize]);
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn digest(value: &Value) -> String {
    sha256_hex(&canonical_json(value))
}

// ---- time ----------------------------------------------------------------------

pub fn format_time(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

pub fn now() -> String {
    format_time(&Utc::now())
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse ISO-8601 / RFC 3339 exactly like `canonical.parse_time` in Python.
pub fn parse_time(text: &str) -> Result<DateTime<Utc>> {
    let t = text.trim();
    let b = t.as_bytes();
    if b.len() < 19 || !t.is_ascii() {
        bail!("not an ISO-8601 timestamp: {t:?}");
    }
    let (date, rest) = t.split_at(10);
    let sep = rest.as_bytes()[0];
    if sep != b'T' && sep != b' ' {
        bail!("not an ISO-8601 timestamp: {t:?}");
    }
    let rest = &rest[1..];
    let dp: Vec<&str> = date.split('-').collect();
    if dp.len() != 3 || dp[0].len() != 4 || dp[1].len() != 2 || dp[2].len() != 2 || !dp.iter().all(|x| digits(x)) {
        bail!("not an ISO-8601 timestamp: {t:?}");
    }
    if rest.len() < 8 {
        bail!("not an ISO-8601 timestamp: {t:?}");
    }
    let (clock, mut tail) = rest.split_at(8);
    let cp: Vec<&str> = clock.split(':').collect();
    if cp.len() != 3 || !cp.iter().all(|x| x.len() == 2 && digits(x)) {
        bail!("not an ISO-8601 timestamp: {t:?}");
    }
    let mut micros: u32 = 0;
    if let Some(stripped) = tail.strip_prefix('.') {
        let n = stripped.bytes().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > 9 {
            bail!("not an ISO-8601 timestamp: {t:?}");
        }
        let frac = &stripped[..n];
        let six: String = frac.chars().take(6).collect();
        micros = format!("{six:0<6}").parse()?;
        tail = &stripped[n..];
    }
    let mut offset_secs: i64 = 0;
    if !tail.is_empty() {
        if tail == "Z" || tail == "z" {
        } else {
            let sign = match tail.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => bail!("not an ISO-8601 timestamp: {t:?}"),
            };
            let d: String = tail[1..].chars().filter(|c| *c != ':').collect();
            let colon_ok = tail.len() == 5 && !tail[1..].contains(':') || tail.len() == 6 && tail.as_bytes()[3] == b':';
            if d.len() != 4 || !digits(&d) || !colon_ok {
                bail!("not an ISO-8601 timestamp: {t:?}");
            }
            let hh: i64 = d[..2].parse()?;
            let mm: i64 = d[2..].parse()?;
            offset_secs = sign * (hh * 3600 + mm * 60);
        }
    }
    let nd = NaiveDate::from_ymd_opt(dp[0].parse()?, dp[1].parse()?, dp[2].parse()?)
        .ok_or_else(|| anyhow!("invalid date in {t:?}"))?;
    let nt = NaiveTime::from_hms_micro_opt(cp[0].parse()?, cp[1].parse()?, cp[2].parse()?, micros)
        .ok_or_else(|| anyhow!("invalid time in {t:?}"))?;
    let naive = NaiveDateTime::new(nd, nt) - Duration::seconds(offset_secs);
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

pub fn canonical_time(text: &str) -> Result<String> {
    Ok(format_time(&parse_time(text)?))
}

pub fn time_from_epoch(value: i64, millis: bool) -> Result<String> {
    let dt = if millis {
        let secs = value.div_euclid(1000);
        let ms = value.rem_euclid(1000);
        DateTime::<Utc>::from_timestamp(secs, (ms * 1_000_000) as u32)
    } else {
        DateTime::<Utc>::from_timestamp(value, 0)
    };
    dt.map(|d| format_time(&d)).ok_or_else(|| anyhow!("epoch out of range: {value}"))
}

pub fn shift_time(text: &str, seconds: i64) -> Result<String> {
    Ok(format_time(&(parse_time(text)? + Duration::seconds(seconds))))
}

pub fn micros(text: &str) -> Result<i64> {
    Ok(parse_time(text)?.timestamp_micros())
}

pub fn from_unix_micros(us: i64) -> String {
    let dt = DateTime::<Utc>::from_timestamp(us.div_euclid(1_000_000), (us.rem_euclid(1_000_000) * 1000) as u32)
        .unwrap_or_default();
    format_time(&dt)
}

/// Canonical textual IP; IPv4-mapped IPv6 collapses to IPv4 (as in Python).
pub fn canonical_ip(text: &str) -> Option<String> {
    let t = text.trim().trim_matches(|c| c == '[' || c == ']');
    let ip: IpAddr = t.parse().ok()?;
    Some(match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_matches_python() {
        let v = json!({"b": 1, "a": [true, null, "x\"\\\n\u{1}é"], "c": {"z": -5, "y": "t"}});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            "{\"a\":[true,null,\"x\\\"\\\\\\n\\u0001é\"],\"b\":1,\"c\":{\"y\":\"t\",\"z\":-5}}"
        );
    }

    #[test]
    fn times() {
        assert_eq!(canonical_time("2026-09-28 09:00:00.123").unwrap(), "2026-09-28T09:00:00.123000Z");
        assert_eq!(canonical_time("2026-09-28T10:00:00+05:30").unwrap(), "2026-09-28T04:30:00.000000Z");
        assert_eq!(canonical_time("2026-09-28T10:00:00.1234567891Z").is_err(), true);
        assert_eq!(canonical_time("2026-09-28T10:00:00.123456789Z").unwrap(), "2026-09-28T10:00:00.123456Z");
        assert!(canonical_time("2026-13-01T00:00:00Z").is_err());
        assert_eq!(time_from_epoch(1_790_000_000_123, true).unwrap(), "2026-09-21T14:13:20.123000Z");
    }

    #[test]
    fn ips() {
        assert_eq!(canonical_ip("::ffff:10.1.2.3").unwrap(), "10.1.2.3");
        assert_eq!(canonical_ip("2001:DB8::1").unwrap(), "2001:db8::1");
        assert!(canonical_ip("999.1.1.1").is_none());
    }
}
