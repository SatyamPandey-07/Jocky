//! Predicate evaluation — mirrors `compiler/jocky/runtime/predicate.py` exactly.

use serde_json::Value;
use std::net::IpAddr;

fn is_int(v: &Value) -> bool {
    matches!(v, Value::Number(n) if n.is_i64() || n.is_u64())
}

fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Bool(_), _) | (_, Value::Bool(_)) => false,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Number(_), Value::Number(_)) if is_int(a) && is_int(b) => a.as_i64() == b.as_i64(),
        _ => false,
    }
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn in_cidr(value: &Value, cidr: &str) -> bool {
    let Value::String(s) = value else { return false };
    let Ok(addr) = s.parse::<IpAddr>() else { return false };
    let Some((net, bits)) = cidr.split_once('/') else { return false };
    let (Ok(net), Ok(bits)) = (net.parse::<IpAddr>(), bits.parse::<u32>()) else { return false };
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

pub fn evaluate(pred: &Value, get: &dyn Fn(&str) -> Value) -> bool {
    if pred.is_null() {
        return true;
    }
    match pred["op"].as_str().unwrap_or("") {
        "and" => pred["args"].as_array().map(|a| a.iter().all(|p| evaluate(p, get))).unwrap_or(true),
        "or" => pred["args"].as_array().map(|a| a.iter().any(|p| evaluate(p, get))).unwrap_or(false),
        "not" => !evaluate(&pred["arg"], get),
        "cmp" => {
            let cmp = pred["cmp"].as_str().unwrap_or("");
            let value = &pred["value"];
            let v = get(pred["field"].as_str().unwrap_or(""));
            if cmp == "==" || cmp == "!=" {
                if value.is_null() {
                    return if cmp == "==" { v.is_null() } else { !v.is_null() };
                }
                if v.is_null() {
                    return false;
                }
                let e = eq(&v, value);
                return if cmp == "==" { e } else { !e };
            }
            if v.is_null() {
                return false;
            }
            match cmp {
                "<" | "<=" | ">" | ">=" => {
                    let ord = if is_int(&v) && is_int(value) {
                        v.as_i64().cmp(&value.as_i64())
                    } else if let (Value::String(a), Value::String(b)) = (&v, value) {
                        a.as_str().cmp(b.as_str())
                    } else {
                        return false;
                    };
                    match cmp {
                        "<" => ord.is_lt(),
                        "<=" => ord.is_le(),
                        ">" => ord.is_gt(),
                        _ => ord.is_ge(),
                    }
                }
                "in" => value.as_array().map(|xs| xs.iter().any(|x| eq(&v, x))).unwrap_or(false),
                "cidr" => in_cidr(&v, value.as_str().unwrap_or("")),
                "contains" | "startswith" | "endswith" | "like" => {
                    let (Value::String(s), Value::String(p)) = (&v, value) else { return false };
                    let (s, p) = (s.to_ascii_lowercase(), p.to_ascii_lowercase());
                    match cmp {
                        "contains" => s.contains(&p),
                        "startswith" => s.starts_with(&p),
                        "endswith" => s.ends_with(&p),
                        _ => glob_match(&p, &s),
                    }
                }
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(name: &str) -> Value {
        let r = json!({"name": "PowerShell.EXE", "pid": 42, "ip": "10.1.2.3", "none": null, "flag": true});
        r.get(name).cloned().unwrap_or(Value::Null)
    }

    fn c(op: &str, f: &str, v: Value) -> Value {
        json!({"op": "cmp", "cmp": op, "field": f, "value": v})
    }

    #[test]
    fn semantics_match_python() {
        let cases = [
            (c("==", "pid", json!(42)), true),
            (c("==", "pid", json!("42")), false),
            (c("!=", "missing", json!(1)), false),
            (json!({"op": "not", "arg": c("==", "missing", json!(1))}), true),
            (c("==", "none", Value::Null), true),
            (c("!=", "pid", Value::Null), true),
            (c("<", "pid", json!(43)), true),
            (c(">=", "name", json!("A")), true),
            (c("<", "pid", json!("43")), false),
            (c("in", "pid", json!([1, 42])), true),
            (c("contains", "name", json!("shell")), true),
            (c("startswith", "name", json!("POWER")), true),
            (c("endswith", "name", json!(".exe")), true),
            (c("like", "name", json!("power*.e?e")), true),
            (c("like", "name", json!("pwsh*")), false),
            (c("cidr", "ip", json!("10.0.0.0/8")), true),
            (c("cidr", "ip", json!("fd00::/8")), false),
            (c("cidr", "name", json!("10.0.0.0/8")), false),
            (c("==", "flag", json!(1)), false),
        ];
        for (p, want) in cases {
            assert_eq!(evaluate(&p, &rec), want, "{p}");
        }
    }

    #[test]
    fn glob() {
        for (p, t, ok) in [("*", "", true), ("a*b", "ab", true), ("a*b", "axxb", true), ("a*b", "axxc", false),
                           ("?", "", false), ("*.ps1", "c:\\t\\x.ps1", true), ("**a", "bba", true)] {
            assert_eq!(glob_match(p, t), ok, "{p} {t}");
        }
    }
}
