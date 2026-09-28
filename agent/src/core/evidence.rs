//! Evidence records: normalization, identity and integrity (mirrors runtime/evidence.py).

use super::canonical::{canonical_ip, canonical_json, canonical_time, digest, sha256_hex, time_from_epoch};
use super::schema::entity;
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Map, Value};

pub type Record = Map<String, Value>;

fn int_str(s: &str) -> Option<i64> {
    let t = s.trim();
    let body = t.strip_prefix('-').unwrap_or(t);
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// Coerce a raw value to a schema type.  Ok(Null) for null/empty, Err on bad input.
pub fn coerce(value: &Value, ty: &str, time_format: &str) -> Result<Value> {
    if value.is_null() || value.as_str() == Some("") {
        return Ok(Value::Null);
    }
    match ty {
        "int" => match value {
            Value::Number(n) if n.is_i64() => Ok(value.clone()),
            Value::String(s) => int_str(s).map(|i| json!(i)).ok_or_else(|| anyhow!("not an int: {s:?}")),
            _ => bail!("not an int: {value}"),
        },
        "str" => match value {
            Value::Bool(b) => Ok(json!(if *b { "true" } else { "false" })),
            Value::Number(n) if n.is_i64() => Ok(json!(n.to_string())),
            Value::String(_) => Ok(value.clone()),
            _ => bail!("not a string: {value}"),
        },
        "time" => {
            if time_format == "epoch_s" || time_format == "epoch_ms" {
                let ms = time_format == "epoch_ms";
                match value {
                    Value::Number(n) if n.is_i64() => Ok(json!(time_from_epoch(n.as_i64().unwrap(), ms)?)),
                    Value::String(s) => match int_str(s) {
                        Some(i) => Ok(json!(time_from_epoch(i, ms)?)),
                        None => bail!("not an epoch: {s:?}"),
                    },
                    _ => bail!("not an epoch: {value}"),
                }
            } else {
                match value {
                    Value::String(s) => Ok(json!(canonical_time(s)?)),
                    _ => bail!("not a timestamp: {value}"),
                }
            }
        }
        "ip" => match value {
            Value::String(s) => canonical_ip(s).map(Value::String).ok_or_else(|| anyhow!("not an ip: {s:?}")),
            _ => bail!("not an ip: {value}"),
        },
        "bool" => match value {
            Value::Bool(_) => Ok(value.clone()),
            Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(json!(true)),
            Value::String(s) if s.eq_ignore_ascii_case("false") => Ok(json!(false)),
            _ => bail!("not a bool: {value}"),
        },
        other => bail!("unknown type {other}"),
    }
}

pub fn evidence_id(entity_name: &str, host: &str, time: &str, fields: &Record) -> Result<String> {
    let spec = entity(entity_name)?;
    let key: Vec<Value> = spec
        .natural_key
        .iter()
        .map(|k| match k.as_str() {
            "host" => json!(host),
            "time" => json!(time),
            other => fields.get(other).cloned().unwrap_or(Value::Null),
        })
        .collect();
    let d = digest(&json!({"entity": entity_name, "key": key}));
    Ok(format!("ev_{}", &d[..32]))
}

pub struct RecordMeta<'a> {
    pub entity: &'a str,
    pub host: &'a str,
    pub time: &'a str,
    pub time_source: &'a str,
    pub observed_at: &'a str,
    pub collector: &'a str,
    pub collector_version: &'a str,
    pub source: &'a str,
}

/// Build an unprojected, unhashed record with every payload field present.
pub fn make_record(meta: RecordMeta, mut values: Record) -> Result<Record> {
    let spec = entity(meta.entity)?;
    let mut payload = Map::new();
    for (name, _) in spec.payload_fields() {
        payload.insert(name.clone(), values.remove(name).unwrap_or(Value::Null));
    }
    let mut r = Map::new();
    r.insert("evidence_id".into(), json!(evidence_id(meta.entity, meta.host, meta.time, &payload)?));
    r.insert("entity".into(), json!(meta.entity));
    r.insert("host".into(), json!(meta.host));
    r.insert("time".into(), json!(meta.time));
    r.insert("time_source".into(), json!(meta.time_source));
    r.insert("observed_at".into(), json!(meta.observed_at));
    r.insert("collector".into(), json!(meta.collector));
    r.insert("collector_version".into(), json!(meta.collector_version));
    r.insert("source".into(), json!(meta.source));
    r.insert("fields".into(), Value::Object(payload));
    Ok(r)
}

/// Stamp execution references and compute the integrity hash.
pub fn seal(mut r: Record, execution_id: &str, contract_hash: &str) -> Record {
    r.insert("execution_id".into(), json!(execution_id));
    r.insert("contract_hash".into(), json!(contract_hash));
    r.remove("sha256");
    let h = sha256_hex(&canonical_json(&Value::Object(r.clone())));
    r.insert("sha256".into(), json!(h));
    r
}

/// Field access used by predicates and reduction keys.
pub fn get_field(r: &Record, name: &str) -> Value {
    if name == "host" || name == "time" {
        return r.get(name).cloned().unwrap_or(Value::Null);
    }
    r.get("fields").and_then(|f| f.get(name)).cloned().unwrap_or(Value::Null)
}

pub fn rec_str<'a>(r: &'a Record, key: &str) -> &'a str {
    r.get(key).and_then(|v| v.as_str()).unwrap_or("")
}
