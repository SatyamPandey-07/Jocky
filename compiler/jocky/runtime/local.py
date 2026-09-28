"""Single-process offline execution (Milestone 3): source + dataset -> findings.

Runs the exact same artifacts as the distributed system — compiled plan,
signed contract, endpoint stream execution, central correlation — without a
control plane or agents, and writes a replayable run directory.
"""
from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..canonical import utc_now
from ..compiler import compile_source
from ..contract import build_contract, resolve_window
from ..correlation import build_provenance, correlate
from .endpoint import encode_jsonl, execute_streams
from .offline import OfflineSource, load_manifest


def run_offline(
    source: str,
    dataset_dir: str | Path,
    *,
    key: Ed25519PrivateKey,
    mode: str = "optimized",
    host: str = "OFFLINE-01",
    anchor: str | None = None,
    out_dir: str | Path | None = None,
) -> dict:
    comp = compile_source(source)
    plan = comp.plan(mode)
    manifest = load_manifest(dataset_dir)
    anchor = anchor or manifest.get("reference_time") or utc_now()
    envelope = build_contract(
        plan=plan,
        ir=comp.ir,
        targets=[{"host": host, "platform": "offline"}],
        signing_key=key,
        investigation_id=f"local:{comp.ir['investigation']['name']}",
        window=resolve_window(comp.ir["investigation"]["window"], anchor),
    )
    body = envelope["contract"]
    src = OfflineSource(dataset_dir)
    endpoint = execute_streams(body, lambda entity, stream, stats: src.collect(entity, stats))
    result = correlate(body["plan"], body["window"], endpoint["streams"])
    records = {r["evidence_id"]: r for recs in endpoint["streams"].values() for r in recs}
    provenance = {f["finding_id"]: build_provenance(f, records, envelope) for f in result["findings"]}
    summary = {
        "investigation": comp.ir["investigation"]["name"],
        "mode": mode,
        "window": body["window"],
        "execution_id": body["execution_id"],
        "findings": len(result["findings"]),
        "digest": result["digest"],
        "preserved": result["preserved"],
        "notes": result["notes"],
        "endpoint_stats": endpoint["stats"],
    }
    if out_dir is not None:
        out = Path(out_dir)
        (out / "evidence").mkdir(parents=True, exist_ok=True)
        (out / "provenance").mkdir(exist_ok=True)
        (out / "contract.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        for sid, recs in endpoint["streams"].items():
            (out / "evidence" / f"{sid}.jsonl").write_bytes(encode_jsonl(recs))
        (out / "findings.json").write_text(json.dumps(result["findings"], indent=2), encoding="utf-8")
        for fid, prov in provenance.items():
            (out / "provenance" / f"{fid}.json").write_text(json.dumps(prov, indent=2), encoding="utf-8")
        (out / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return {"summary": summary, "findings": result["findings"], "provenance": provenance,
            "contract": envelope, "streams": endpoint["streams"]}
