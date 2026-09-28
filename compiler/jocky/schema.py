"""Loader for the shared entity schema (`schemas/entities.json`)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ENVELOPE_FIELDS = ("host", "time")  # addressable from expressions, stored in the envelope


@dataclass(frozen=True)
class FieldSpec:
    name: str
    type: str
    capability: str | None
    doc: str


@dataclass(frozen=True)
class EntitySpec:
    name: str
    capability: str
    fields: dict[str, FieldSpec]
    natural_key: tuple[str, ...]
    doc: str

    @property
    def payload_fields(self) -> list[str]:
        """Fields stored under `fields` (everything except envelope fields)."""
        return [f for f in self.fields if f not in ENVELOPE_FIELDS]


@dataclass(frozen=True)
class Schema:
    version: str
    entities: dict[str, EntitySpec]


def schemas_dir() -> Path:
    env = os.environ.get("JOCKY_SCHEMAS_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "schemas"


@lru_cache(maxsize=1)
def load_schema() -> Schema:
    raw = json.loads((schemas_dir() / "entities.json").read_text(encoding="utf-8"))
    entities: dict[str, EntitySpec] = {}
    for name, spec in raw["entities"].items():
        fields = {
            fname: FieldSpec(fname, f["type"], f.get("capability"), f.get("doc", ""))
            for fname, f in spec["fields"].items()
        }
        entities[name] = EntitySpec(
            name=name,
            capability=spec["capability"],
            fields=fields,
            natural_key=tuple(spec["natural_key"]),
            doc=spec.get("doc", ""),
        )
    return Schema(version=raw["schema_version"], entities=entities)
