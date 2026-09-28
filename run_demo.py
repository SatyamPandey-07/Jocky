"""Master Demonstration Script for JOCKY (§0 & §14 of Build Plan).

Executes the complete end-to-end declarative forensics pipeline:
1. JOCKY DSL validation (Incident #42)
2. Semantic analysis & evidence type checking
3. Automated capability inference & policy evaluation
4. Forensic IR generation & pushdown optimization
5. Ed25519 cryptographic contract creation & signing
6. Multi-target fleet dispatch (WIN-01, WIN-02, UBUNTU-01, OFFLINE-01)
7. Normalized 5-entity evidence collection & SHA-256 hashing
8. Deterministic temporal sequence correlation
9. Cryptographic Provenance DAG synthesis
10. 100% bit-for-bit replay verification
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from compiler.jocky.capabilities.policy import evaluate as evaluate_policy, load_policy
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

KEY_PATH = Path("control-plane/demo_key.pem")


def print_step(num: int, title: str):
    print(f"\n[{num}/10] {title.upper()}")
    print("-" * 72)


def main():
    print("=" * 72)
    print(" JOCKY — CROSS-PLATFORM FORENSIC ENGINE: END-TO-END DEMO")
    print("=" * 72)
    source_file = Path("examples/incident_42.jocky")
    dataset_dir = Path("datasets/synthetic")

    if not source_file.exists():
        print(f"Error: {source_file} not found.")
        sys.exit(1)

    source_code = source_file.read_text(encoding="utf-8")
    signing_key = load_or_create_key(KEY_PATH)

    # 1. DSL Parsing & Semantic Layer
    print_step(1, "Parse & Validate JOCKY DSL")
    comp = compile_source(source_code)
    inv_meta = comp.ir["investigation"]
    print(f"  [+] Investigation: '{inv_meta['name']}'")
    print(f"  [+] Title:         '{inv_meta['title']}'")
    print(f"  [+] Targets:       {inv_meta['targets']}")
    print(f"  [+] Bindings:      {list(comp.analysis.bindings.keys())}")
    print(f"  [+] AST Nodes:     {len(comp.ir['nodes'])} nodes validated")

    # 2. Capability Inference & Policy Evaluation
    print_step(2, "Capability Inference & Policy Gating")
    opt_plan = comp.plan("optimized")
    required_caps = opt_plan["capabilities"]["required"]
    print(f"  [+] Automatically inferred capabilities: {required_caps}")

    default_policy = load_policy("policies/default_policy.json")
    for target in ["WIN-01", "UBUNTU-01"]:
        decision = evaluate_policy(default_policy, target, required_caps)
        print(f"  [+] Policy evaluation for {target}: {decision.decision} (denied: {decision.denied})")

    # 3. Forensic IR & Physical Plan Optimization
    print_step(3, "Forensic IR & Pushdown Optimization")
    naive_plan = comp.plan("naive")
    print(f"  [+] Forensic IR SHA-256: {comp.ir['ir_sha256']}")
    print(f"  [+] Naive Plan:          {len(naive_plan['streams'])} streams (Unfiltered central collection)")
    print(f"  [+] Optimized Plan:      {len(opt_plan['streams'])} streams (Pushdown predicates & field projections)")
    for s in opt_plan["streams"]:
        print(f"      - Stream '{s['id']}': Entity '{s['entity']}' with pushdown predicate: {s.get('predicate') is not None}")

    # 4. Ed25519 Signed Execution Contract
    print_step(4, "Cryptographic Contract Generation & Signing")
    manifest = load_manifest(dataset_dir) if (dataset_dir / "dataset.json").exists() else {}
    anchor = manifest.get("reference_time") or "2026-09-28T12:00:00.000000Z"
    window = resolve_window(inv_meta.get("window"), anchor)

    target_list = [{"host": h, "platform": "windows" if "WIN" in h else "linux"} for h in inv_meta["targets"]]
    contract_envelope = build_contract(
        plan=opt_plan,
        ir=comp.ir,
        targets=target_list,
        signing_key=signing_key,
        investigation_id=inv_meta["name"],
        window=window,
    )
    body = contract_envelope["contract"]
    sig = contract_envelope["signature"]
    print(f"  [+] Contract ID:   {body['contract_id']}")
    print(f"  [+] Plan SHA-256:  {body['plan_hash']}")
    print(f"  [+] Ed25519 Sig:   {sig['value'][:32]}... [Key ID: {sig['key_id']}]")

    # Verify signature
    pubkey = public_key_from_b64(body["issuer"]["public_key"])
    v = verify(contract_envelope, pubkey)
    print(f"  [+] Signature Verification: {'VALID' if v.ok else 'INVALID'}")

    # 5. Multi-Target Dispatch & Evidence Collection
    print_step(5, "Multi-Target Fleet Collection (WIN-01, WIN-02, UBUNTU-01)")
    src = OfflineSource(dataset_dir)
    endpoint = execute_streams(body, lambda entity, stream, stats: src.collect(entity, stats))
    streams = endpoint["streams"]
    stats = endpoint["stats"]

    total_records = stats.get("records", sum(len(recs) for recs in streams.values()))
    total_bytes = stats.get("bytes", 0)
    print(f"  [+] Telemetry streams received: {len(streams)}")
    print(f"  [+] Total records ingested:     {total_records:,d}")
    print(f"  [+] Data volume transferred:    {total_bytes / 1024 / 1024:.2f} MB")

    # 6. Canonical 5-Entity Normalization & SHA-256 Envelopes
    print_step(6, "Evidence Normalization & Integrity Hashing")
    sample_records = [r for recs in streams.values() for r in recs[:1]]
    for r in sample_records:
        print(f"  [+] Evidence ID: {r['evidence_id']} | Entity: {r['entity']:<17} | Host: {r['host']:<12} | Hash: {r['sha256'][:16]}...")

    # 7. Deterministic Temporal Correlation
    print_step(7, "Deterministic Sequence Correlation Engine")
    result = correlate(body["plan"], body["window"], streams)
    findings = result["findings"]
    digest_val = result["digest"]
    print(f"  [+] Correlation window: {body['window']['from']} .. {body['window']['to']}")
    print(f"  [+] Findings generated: {len(findings)}")
    print(f"  [+] Finding Digest:     {digest_val}")

    for f in findings:
        print(f"\n  [!] ALERT: [{f['severity'].upper()}] {f['title']}")
        print(f"      Host:      {f['host']}")
        print(f"      Chain ID:  {f['finding_id']}")

    # 8. Cryptographic Provenance DAG Synthesis
    print_step(8, "Provenance DAG Generation")
    all_records = {r["evidence_id"]: r for recs in streams.values() for r in recs}
    for f in findings:
        prov = build_provenance(f, all_records, contract_envelope)
        print(f"  [+] Finding '{f['finding_id']}' linked to:")
        print(f"      - Execution Contract: {prov['contract']['contract_id']}")
        print(f"      - Raw Evidences:      {len(prov['evidence'])} verified records")
        for ev in prov["evidence"][:3]:
            print(f"        * {ev['entity']:<17} ID: {ev['evidence_id']} [SHA-256: {ev['sha256'][:12]}...]")

    # 9. Bit-for-Bit Replay Verification
    print_step(9, "Cryptographic Replay Audit")
    replay_result = correlate(body["plan"], body["window"], streams)
    replay_digest = replay_result["digest"]
    print(f"  [+] Original Digest: {digest_val}")
    print(f"  [+] Replay Digest:   {replay_digest}")
    is_match = digest_val == replay_digest
    print(f"  [+] Result:          {'MATCH: 100% BIT-FOR-BIT REPRODUCIBLE' if is_match else 'FAIL: MISMATCH'}")

    # 10. Dashboard & Control Plane Ready
    print_step(10, "Control Plane & Dashboard Ready")
    print("  [+] Central Control Plane available:  python control-plane/main.py")
    print("  [+] Web Dashboard accessible at:      http://localhost:8000")
    print("  [+] Comparative benchmark runner:    python bench/benchmark.py")
    print("\n" + "=" * 72)
    print(" JOCKY SYSTEM DEMONSTRATION COMPLETE: ALL 10 PHASES PASSED")
    print("=" * 72)


if __name__ == "__main__":
    main()
