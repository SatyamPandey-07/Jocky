"""Replay: frozen evidence + the same signed contract -> the same finding digest."""
from __future__ import annotations

import json
from pathlib import Path

from .contract import public_key_from_b64, verify
from .correlation import correlate
from .runtime.evidence import verify_record


def replay_streams(envelope: dict, streams: dict[str, list[dict]], original_digest: str,
                   trusted_key_b64: str | None = None) -> dict:
    body = envelope["contract"]
    key = public_key_from_b64(trusted_key_b64 or body["issuer"]["public_key"])
    # Expiry is irrelevant for replay: the contract is historical.
    ver = verify(envelope, key, now=body["issued_at"])
    tampered = [r["evidence_id"] for recs in streams.values() for r in recs if not verify_record(r)]
    result = correlate(body["plan"], body["window"], streams)
    return {
        "contract_verified": ver.ok,
        "contract_checks": ver.checks,
        "records_checked": sum(len(v) for v in streams.values()),
        "tampered_records": tampered,
        "original_digest": original_digest,
        "replay_digest": result["digest"],
        "match": ver.ok and not tampered and result["digest"] == original_digest,
        "findings": len(result["findings"]),
    }


def replay_run_dir(run_dir: str | Path, trusted_key_b64: str | None = None) -> dict:
    d = Path(run_dir)
    envelope = json.loads((d / "contract.json").read_text(encoding="utf-8"))
    original = json.loads((d / "result.json").read_text(encoding="utf-8"))["digest"]
    streams: dict[str, list[dict]] = {}
    for s in envelope["contract"]["plan"]["streams"]:
        path = d / "evidence" / f"{s['id']}.jsonl"
        streams[s["id"]] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return replay_streams(envelope, streams, original, trusted_key_b64)
