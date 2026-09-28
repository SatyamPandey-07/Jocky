"""Endpoint-side execution of a contract's streams (reference implementation).

Per stream: collect -> normalize -> time bound -> predicate -> de-duplicate
-> (reduce group) -> project -> seal (hash).  The Rust agent implements the
identical pipeline; `tests/agent/test_conformance.py` compares them
byte-for-byte on the same contract and dataset.
"""
from __future__ import annotations

import time as _time
from typing import Callable, Iterable

from ..canonical import canonical_json, shift_time
from ..contract import contract_hash
from ..schema import load_schema
from .evidence import seal
from .predicate import evaluate, record_getter

Collect = Callable[[str, dict, dict], Iterable[dict]]  # (entity, stream, stats) -> records


def time_bounds(stream: dict, window: dict | None) -> tuple[str | None, str | None]:
    t = stream.get("time")
    if not t or window is None:
        return None, None
    lo, hi = (window["from"], window["to"]) if t.get("window") else (None, None)
    if t.get("within_seconds"):
        w_lo = shift_time(window["to"], -int(t["within_seconds"]))
        lo = w_lo if lo is None or w_lo > lo else lo
        hi = window["to"] if hi is None else hi
    return lo, hi


def key_of(record: dict, keys: list[str]):
    get = record_getter(record)
    vals = tuple(get(k) for k in keys)
    return None if any(v is None for v in vals) else vals


def execute_streams(contract: dict, collect: Collect) -> dict:
    """Run every stream of the contract plan.  Returns {"streams": {sid: [records]}, "stats": {...}}."""
    plan = contract["plan"]
    window = contract.get("window")
    limits = contract["limits"]
    chash = contract_hash(contract)
    wall0, cpu0 = _time.perf_counter(), _time.process_time()
    schema = load_schema()

    staged: dict[str, list[dict]] = {}
    stats: dict[str, dict] = {}
    for stream in plan["streams"]:
        st: dict = {"scanned": 0, "normalize_errors": 0}
        lo, hi = time_bounds(stream, window)
        out: list[dict] = []
        seen: set[str] = set()
        collected = after_time = after_pred = 0
        for rec in collect(stream["entity"], stream, st):
            collected += 1
            if lo is not None and rec["time"] < lo:
                continue
            if hi is not None and rec["time"] > hi:
                continue
            after_time += 1
            if not evaluate(stream.get("predicate"), record_getter(rec)):
                continue
            after_pred += 1
            if rec["evidence_id"] in seen:
                continue
            seen.add(rec["evidence_id"])
            out.append(rec)
        st.update({"collected": collected, "after_time": after_time, "after_predicate": after_pred,
                   "after_dedupe": len(out)})
        staged[stream["id"]] = out
        stats[stream["id"]] = st

    for group in plan.get("reduce_groups", []):
        keysets = []
        for sid in group["streams"]:
            keysets.append({k for k in (key_of(r, group["keys"]) for r in staged[sid]) if k is not None})
        common = set.intersection(*keysets) if keysets else set()
        for sid in group["streams"]:
            staged[sid] = [r for r in staged[sid] if key_of(r, group["keys"]) in common]

    result: dict[str, list[dict]] = {}
    total_bytes = 0
    truncated = False
    for stream in plan["streams"]:
        sid = stream["id"]
        spec = schema.entities[stream["entity"]]
        keep = stream.get("fields")
        recs = sorted(staged[sid], key=lambda r: (r["time"], r["evidence_id"]))
        if len(recs) > limits["max_records_per_stream"]:
            recs = recs[: limits["max_records_per_stream"]]
            stats[sid]["truncated"] = True
            truncated = True
        sealed = []
        nbytes = 0
        for r in recs:
            r = dict(r)
            r["fields"] = {f: r["fields"].get(f) for f in (keep if keep is not None else spec.payload_fields)}
            s = seal(r, contract["execution_id"], chash)
            nbytes += len(canonical_json(s)) + 1
            sealed.append(s)
        stats[sid]["after_reduce"] = len(staged[sid])
        stats[sid]["emitted"] = len(sealed)
        stats[sid]["bytes"] = nbytes
        total_bytes += nbytes
        result[sid] = sealed
    if total_bytes > limits["max_bytes"]:
        truncated = True
    return {
        "streams": result,
        "stats": {
            "streams": stats,
            "records": sum(len(v) for v in result.values()),
            "bytes": total_bytes,
            "wall_ms": round((_time.perf_counter() - wall0) * 1000, 3),
            "cpu_ms": round((_time.process_time() - cpu0) * 1000, 3),
            "truncated": truncated,
        },
    }


def encode_jsonl(records: list[dict]) -> bytes:
    return b"".join(canonical_json(r) + b"\n" for r in records)
