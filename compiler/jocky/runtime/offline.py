"""Offline evidence source: JSON / JSONL / CSV datasets described by a manifest.

`dataset.json`::

    {
      "format": "jocky.dataset/0.1",
      "name": "incident42-lab",
      "default_host": "OFFLINE-01",
      "sources": [
        {"entity": "Process", "path": "process.jsonl", "format": "jsonl",
         "time_format": "iso", "time_source": "start",
         "fields": {"time": "start_time", "pid": "ProcessId"}}
      ]
    }

`fields` maps schema field -> source column (dotted paths reach into nested
JSON).  Unmapped schema fields are looked up under their own name.
The Rust agent's offline collector implements the same rules.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterator

from ..schema import load_schema
from .evidence import NormalizeError, coerce, make_record

OFFLINE_COLLECTOR_VERSION = "0.1.0"


def lookup(row: dict, path: str) -> Any:
    if path in row:
        return row[path]
    if "." not in path:
        return None
    cur: Any = row
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def load_manifest(dataset_dir: str | Path) -> dict:
    return json.loads((Path(dataset_dir) / "dataset.json").read_text(encoding="utf-8"))


def iter_rows(path: Path, fmt: str) -> Iterator[dict]:
    if fmt == "jsonl":
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
    elif fmt == "json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError(f"{path}: json source must be an array of objects")
        yield from data
    elif fmt == "csv":
        with path.open(encoding="utf-8", newline="") as fh:
            yield from csv.DictReader(fh)
    else:
        raise ValueError(f"unknown source format {fmt!r}")


class OfflineSource:
    def __init__(self, dataset_dir: str | Path):
        self.dir = Path(dataset_dir)
        self.manifest = load_manifest(self.dir)
        self.name = self.manifest["name"]

    def collect(self, entity: str, stats: dict) -> Iterator[dict]:
        """Yield normalized (unprojected) records for `entity` from every matching source."""
        spec = load_schema().entities[entity]
        default_host = self.manifest.get("default_host", "OFFLINE")
        for src in self.manifest["sources"]:
            if src["entity"] != entity:
                continue
            mapping = src.get("fields", {})
            time_format = src.get("time_format", "iso")
            path = self.dir / src["path"]
            label = f"offline:{self.name}/{src['path']}"
            for row in iter_rows(path, src.get("format", "jsonl")):
                stats["scanned"] = stats.get("scanned", 0) + 1
                values: dict[str, Any] = {}
                try:
                    t = coerce(lookup(row, mapping.get("time", "time")), "time", time_format)
                except NormalizeError:
                    t = None
                if t is None:
                    stats["normalize_errors"] = stats.get("normalize_errors", 0) + 1
                    continue
                host = lookup(row, mapping.get("host", "host"))
                host = host if isinstance(host, str) and host else default_host
                for fname in spec.payload_fields:
                    try:
                        values[fname] = coerce(lookup(row, mapping.get(fname, fname)),
                                               spec.fields[fname].type, time_format)
                    except NormalizeError:
                        values[fname] = None
                        stats["normalize_errors"] = stats.get("normalize_errors", 0) + 1
                observed_raw = lookup(row, mapping.get("observed_at", "observed_at"))
                try:
                    observed = coerce(observed_raw, "time", time_format) or t
                except NormalizeError:
                    observed = t
                yield make_record(
                    entity=entity,
                    host=host,
                    time=t,
                    fields=values,
                    time_source=src.get("time_source", "event"),
                    observed_at=observed,
                    collector=f"Offline{entity}Collector",
                    collector_version=OFFLINE_COLLECTOR_VERSION,
                    source=label,
                )
