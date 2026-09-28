//! The shared five-entity schema, compiled into the agent from `schemas/entities.json`.

use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const SCHEMA_JSON: &str = include_str!("../../../schemas/entities.json");

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub ty: String,
    pub capability: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EntitySpec {
    pub name: String,
    pub capability: String,
    /// field name -> spec (sorted by name; order is irrelevant to canonical JSON)
    pub fields: BTreeMap<String, FieldSpec>,
    pub natural_key: Vec<String>,
}

impl EntitySpec {
    /// Fields stored under `fields` (everything except the envelope's host/time).
    pub fn payload_fields(&self) -> impl Iterator<Item = (&String, &FieldSpec)> {
        self.fields.iter().filter(|(n, _)| n.as_str() != "host" && n.as_str() != "time")
    }
}

pub struct Schema {
    pub version: String,
    pub entities: BTreeMap<String, EntitySpec>,
}

pub fn schema() -> &'static Schema {
    static S: OnceLock<Schema> = OnceLock::new();
    S.get_or_init(|| {
        let raw: Value = serde_json::from_str(SCHEMA_JSON).expect("valid entities.json");
        let mut entities = BTreeMap::new();
        for (name, spec) in raw["entities"].as_object().expect("entities") {
            let fields = spec["fields"]
                .as_object()
                .expect("fields")
                .iter()
                .map(|(f, fs)| {
                    (
                        f.clone(),
                        FieldSpec {
                            ty: fs["type"].as_str().unwrap().to_string(),
                            capability: fs.get("capability").and_then(|c| c.as_str()).map(String::from),
                        },
                    )
                })
                .collect();
            entities.insert(
                name.clone(),
                EntitySpec {
                    name: name.clone(),
                    capability: spec["capability"].as_str().unwrap().to_string(),
                    fields,
                    natural_key: spec["natural_key"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect(),
                },
            );
        }
        Schema { version: raw["schema_version"].as_str().unwrap().to_string(), entities }
    })
}

pub fn entity(name: &str) -> anyhow::Result<&'static EntitySpec> {
    schema().entities.get(name).ok_or_else(|| anyhow::anyhow!("unknown entity {name}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn loads_five_entities() {
        let s = super::schema();
        assert_eq!(s.entities.len(), 5);
        let p = super::entity("Process").unwrap();
        assert_eq!(p.payload_fields().count(), 6);
        assert_eq!(p.fields["cmdline"].capability.as_deref(), Some("collect:process.cmdline"));
        assert_eq!(p.natural_key, ["host", "pid", "time"]);
    }
}
