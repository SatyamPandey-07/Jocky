"""Provenance: Finding -> derived tuples -> raw evidence -> collector -> host -> contract."""
from __future__ import annotations


def build_provenance(finding: dict, records: dict[str, dict], contract_envelope: dict,
                     agents: dict[str, dict] | None = None) -> dict:
    """`records` maps evidence_id -> sealed evidence record (full envelope).
    `agents` optionally maps host -> agent/task metadata."""
    body = contract_envelope["contract"]
    comps = [c["alias"] for c in finding["components"]]
    derived = [
        {"chain": i, "links": [{"alias": a, "evidence_id": e} for a, e in zip(comps, chain)]}
        for i, chain in enumerate(finding["chains"])
    ]
    raw = []
    for eid in sorted(finding["evidence"]):
        r = records.get(eid)
        if r is None:
            raw.append({"evidence_id": eid, "missing": True})
            continue
        raw.append({
            "evidence_id": eid,
            "entity": r["entity"],
            "time": r["time"],
            "time_source": r["time_source"],
            "observed_at": r["observed_at"],
            "sha256": r["sha256"],
            "collector": {"name": r["collector"], "version": r["collector_version"], "source": r["source"]},
            "host": {"id": r["host"], **((agents or {}).get(r["host"], {}))},
            "execution_id": r["execution_id"],
            "contract_hash": r["contract_hash"],
        })
    return {
        "finding": {"finding_id": finding["finding_id"], "digest": finding["digest"],
                    "title": finding["title"], "severity": finding["severity"]},
        "derived": derived,
        "evidence": raw,
        "contract": {
            "contract_id": body["contract_id"],
            "execution_id": body["execution_id"],
            "investigation": body["investigation"],
            "compiler_version": body["compiler_version"],
            "mode": body["mode"],
            "ir_sha256": body["ir_sha256"],
            "plan_hash": body["plan_hash"],
            "issued_at": body["issued_at"],
            "signature": contract_envelope["signature"],
        },
    }
