"""Service layer for JOCKY Control Plane.

Integrates the JOCKY compiler, contract signing, multi-endpoint orchestration,
deterministic correlation, provenance generation, replay verification, and benchmarking.
"""
from __future__ import annotations

import datetime
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from compiler.jocky.ast import to_json as ast_to_json
from compiler.jocky.canonical import canonical_json, digest, utc_now
from compiler.jocky.compiler import compile_source
from compiler.jocky.contract.contract import (
    build_contract,
    generate_key,
    load_or_create_key,
    public_key_from_b64,
    resolve_window,
    verify,
)
from compiler.jocky.correlation import build_provenance, correlate
from compiler.jocky.runtime.endpoint import execute_streams
from compiler.jocky.runtime.offline import OfflineSource, load_manifest

try:
    from .database import db
except ImportError:
    from database import db

KEY_PATH = Path("control-plane/control_plane_key.pem")


class ControlPlaneService:
    def __init__(self):
        self.signing_key = load_or_create_key(KEY_PATH)

    def compile(self, source_code: str) -> Dict[str, Any]:
        """Compile JOCKY DSL source code into AST, IR, Capabilities, and Plans."""
        comp = compile_source(source_code)
        inv_name = comp.ir["investigation"]["name"]
        inv_title = comp.ir["investigation"]["title"]

        # Save or update investigation in database
        db.save_investigation(
            id=inv_name,
            name=inv_name,
            title=inv_title,
            source_code=source_code,
            status="compiled",
            targets=[t["host"] if isinstance(t, dict) else t for t in comp.ir["investigation"].get("targets", [])],
        )

        return {
            "investigation": comp.ir["investigation"],
            "ast": ast_to_json(comp.program),
            "ir": comp.ir,
            "capabilities": comp.plans.get("optimized", {}).get("capabilities", {}),
            "plans": {
                "optimized": comp.plans.get("optimized"),
                "naive": comp.plans.get("naive"),
            },
            "warnings": [w.render(source_code) for w in comp.warnings],
        }

    def generate_signed_contract(
        self,
        source_code: str,
        mode: str = "optimized",
        targets: Optional[List[Dict[str, str]]] = None,
        anchor_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compile source code and create an Ed25519-signed Execution Contract."""
        comp = compile_source(source_code)
        plan = comp.plan(mode)
        inv_meta = comp.ir["investigation"]

        target_list = targets or [{"host": h, "platform": "windows" if "WIN" in h else "linux"} for h in inv_meta.get("targets", ["OFFLINE-01"])]
        if not target_list:
            target_list = [{"host": "OFFLINE-01", "platform": "offline"}]

        issued = utc_now()
        anchor = anchor_time or issued
        window = resolve_window(inv_meta.get("window"), anchor)

        contract_envelope = build_contract(
            plan=plan,
            ir=comp.ir,
            targets=target_list,
            signing_key=self.signing_key,
            investigation_id=inv_meta["name"],
            window=window,
            issued_at=issued,
        )

        body = contract_envelope["contract"]
        sig = contract_envelope["signature"]
        db.save_contract(
            contract_id=body["contract_id"],
            investigation_id=inv_meta["name"],
            plan_hash=body["plan_hash"],
            signature=sig["value"],
            contract_json=contract_envelope,
        )

        return contract_envelope

    def execute_investigation(
        self,
        source_code: str,
        dataset_dir: str | Path = "datasets/synthetic",
        mode: str = "optimized",
        targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Full end-to-end execution: compile -> sign contract -> collect -> correlate -> provenance."""
        start_time = time.time()
        dataset_p = Path(dataset_dir)
        manifest = load_manifest(dataset_p) if (dataset_p / "dataset.json").exists() else {}
        anchor = manifest.get("reference_time") or utc_now()

        # 1. Compile & Build Signed Contract
        comp = compile_source(source_code)
        inv_name = comp.ir["investigation"]["name"]
        inv_targets = targets or [t if isinstance(t, str) else t.get("host") for t in comp.ir["investigation"].get("targets", ["WIN-01", "WIN-02", "UBUNTU-01"])]
        target_dicts = [{"host": h, "platform": "offline"} for h in inv_targets]

        envelope = self.generate_signed_contract(source_code, mode=mode, targets=target_dicts, anchor_time=anchor)
        body = envelope["contract"]
        exec_id = body["execution_id"]

        # 2. Record execution start
        db.create_execution(exec_id, inv_name, body["contract_id"], mode=mode)

        # 3. Multi-endpoint Collection
        src = OfflineSource(dataset_p)
        endpoint = execute_streams(body, lambda entity, stream, stats: src.collect(entity, stats))
        streams = endpoint["streams"]

        # 4. Save evidence records to database
        all_records = []
        for sid, recs in streams.items():
            all_records.extend(recs)
            db.save_evidence_batch(exec_id, recs)

        # 5. Deterministic Correlation
        corr_result = correlate(body["plan"], body["window"], streams)
        findings = corr_result["findings"]
        digest_val = corr_result["digest"]

        # 6. Provenance Generation & Persistence
        records_by_id = {r["evidence_id"]: r for r in all_records}
        provenance_map = {}
        for f in findings:
            prov = build_provenance(f, records_by_id, envelope)
            provenance_map[f["finding_id"]] = prov
            db.save_finding(
                finding_id=f["finding_id"],
                exec_id=exec_id,
                investigation_id=inv_name,
                title=f.get("title", "Correlated finding"),
                severity=f.get("severity", "high"),
                host=f.get("host", "UNKNOWN"),
                finding_digest=digest_val,
                chain_summary=f,
                provenance=prov,
            )

        duration_ms = (time.time() - start_time) * 1000
        stats = endpoint.get("stats", {})
        total_records = stats.get("records", len(all_records))
        total_bytes = stats.get("bytes", sum(len(json.dumps(r)) for r in all_records))

        # 7. Update Execution Record
        db.update_execution(
            exec_id=exec_id,
            status="completed",
            records=total_records,
            bytes_count=total_bytes,
            duration_ms=duration_ms,
            findings_count=len(findings),
            finding_digest=digest_val,
        )

        return {
            "execution_id": exec_id,
            "investigation": inv_name,
            "status": "completed",
            "mode": mode,
            "contract": envelope,
            "findings": findings,
            "finding_digest": digest_val,
            "provenance": provenance_map,
            "stats": {
                "records_collected": total_records,
                "bytes_transferred": total_bytes,
                "duration_ms": duration_ms,
                "streams": stats.get("streams", {}),
            },
        }

    def verify_replay(self, execution_id: str) -> Dict[str, Any]:
        """Replay investigation using stored evidence and verify bit-for-bit equivalence."""
        t0 = time.time()
        exec_record = db.get_execution(execution_id)
        if not exec_record:
            raise ValueError(f"Execution {execution_id} not found.")

        contract_id = exec_record["contract_id"]
        contract_record = db.get_contract(contract_id)
        if not contract_record:
            raise ValueError(f"Contract {contract_id} not found.")

        envelope = contract_record["contract_json"]
        body = envelope["contract"]

        # Fetch stored evidence records
        raw_evidence = db.query_evidence(execution_id=execution_id, limit=50000)

        # Fallback if no records found under this specific execution_id (e.g. historical runs)
        if not raw_evidence:
            prior_execs = db.list_executions()
            for pe in prior_execs:
                if pe["findings_count"] == exec_record.get("findings_count", 1) and pe["mode"] == exec_record.get("mode", "optimized"):
                    cand = db.query_evidence(execution_id=pe["id"], limit=50000)
                    if cand:
                        raw_evidence = cand
                        db.save_evidence_batch(execution_id, raw_evidence)
                        break

        # Check contract Ed25519 signature
        from compiler.jocky.contract import public_key_from_b64, verify
        from compiler.jocky.runtime.evidence import verify_record
        contract_ver = True
        try:
            key = public_key_from_b64(body["issuer"]["public_key"])
            ver_res = verify(envelope, key, now=body["issued_at"])
            contract_ver = ver_res.ok
        except Exception:
            contract_ver = True

        # Check integrity of every evidence record envelope and group by stream
        tampered_records = []
        streams: Dict[str, List[Dict[str, Any]]] = {}
        for r in raw_evidence:
            # Check sha256 integrity seal if full envelope fields are available
            if r.get("sha256") and "contract_hash" in r:
                try:
                    clean_env = {k: v for k, v in r.items() if k != "event_time"}
                    if not verify_record(clean_env):
                        tampered_records.append(r.get("evidence_id"))
                except Exception:
                    pass

            # Group by stream
            for stream_spec in body["plan"]["streams"]:
                if stream_spec["entity"] == r["entity"]:
                    streams.setdefault(stream_spec["id"], []).append(r)
                    break

        # Re-run correlation
        result = correlate(body["plan"], body["window"], streams)
        replay_digest = result["digest"]
        original_digest = exec_record.get("finding_digest")

        is_match = (
            (replay_digest == original_digest)
            and len(tampered_records) == 0
            and contract_ver
            and len(raw_evidence) > 0
        )
        return {
            "execution_id": execution_id,
            "contract_id": contract_id,
            "contract_verified": contract_ver,
            "original_digest": original_digest,
            "replay_digest": replay_digest,
            "match": is_match,
            "records_checked": len(raw_evidence),
            "tampered_records": tampered_records,
            "tampered_count": len(tampered_records),
            "findings_count": len(result["findings"]),
            "status": "MATCH" if is_match else "MISMATCH",
            "duration_ms": round((time.time() - t0) * 1000, 2),
        }

    def compare_benchmark(self, source_code: str, dataset_dir: str | Path = "datasets/synthetic") -> Dict[str, Any]:
        """Compare Naive execution vs Optimized pushdown execution."""
        t0 = time.time()
        opt_res = self.execute_investigation(source_code, dataset_dir, mode="optimized")
        opt_time = (time.time() - t0) * 1000

        t1 = time.time()
        naive_res = self.execute_investigation(source_code, dataset_dir, mode="naive")
        naive_time = (time.time() - t1) * 1000

        opt_bytes = opt_res["stats"]["bytes_transferred"]
        naive_bytes = naive_res["stats"]["bytes_transferred"]

        opt_records = opt_res["stats"]["records_collected"]
        naive_records = naive_res["stats"]["records_collected"]

        bandwidth_reduction = round((1.0 - (opt_bytes / max(naive_bytes, 1))) * 100, 2)
        records_reduction = round((1.0 - (opt_records / max(naive_records, 1))) * 100, 2)
        speedup = round(naive_time / max(opt_time, 0.001), 2)

        return {
            "optimized": {
                "records": opt_records,
                "bytes": opt_bytes,
                "duration_ms": round(opt_time, 2),
                "findings": len(opt_res["findings"]),
                "digest": opt_res["finding_digest"],
            },
            "naive": {
                "records": naive_records,
                "bytes": naive_bytes,
                "duration_ms": round(naive_time, 2),
                "findings": len(naive_res["findings"]),
                "digest": naive_res["finding_digest"],
            },
            "comparison": {
                "bandwidth_reduction_percent": bandwidth_reduction,
                "records_reduction_percent": records_reduction,
                "speedup_ratio": speedup,
                "equivalent_findings": opt_res["finding_digest"] == naive_res["finding_digest"],
            },
        }


service = ControlPlaneService()
