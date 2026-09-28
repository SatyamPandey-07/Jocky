"""End-to-end integration tests for JOCKY system."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from compiler.jocky.capabilities.policy import evaluate as evaluate_policy, load_policy
from compiler.jocky.compiler import compile_source
from compiler.jocky.contract.contract import (
    build_contract,
    load_or_create_key,
    public_key_from_b64,
    resolve_window,
    verify,
)
from compiler.jocky.correlation import correlate
from compiler.jocky.runtime.local import run_offline


@pytest.fixture
def source_code():
    return Path("examples/incident_42.jocky").read_text(encoding="utf-8")


@pytest.fixture
def dataset_dir():
    return Path("datasets/synthetic")


@pytest.fixture
def signing_key(tmp_path):
    return load_or_create_key(tmp_path / "test_key.pem")


def test_compiler_end_to_end(source_code, dataset_dir, signing_key):
    """Test full execution from DSL to finding."""
    res = run_offline(source_code, dataset_dir, key=signing_key, mode="optimized")
    assert res["summary"]["findings"] == 1
    assert res["findings"][0]["severity"] == "high"
    assert "PowerShell" in res["findings"][0]["title"]
    assert res["summary"]["digest"] is not None


def test_pushdown_equivalence(source_code, dataset_dir, signing_key):
    """Verify optimized and naive plans produce identical finding digests."""
    opt_run = run_offline(source_code, dataset_dir, key=signing_key, mode="optimized")
    naive_run = run_offline(source_code, dataset_dir, key=signing_key, mode="naive")

    # Finding digests must match bit-for-bit
    assert opt_run["summary"]["digest"] == naive_run["summary"]["digest"]

    # Bandwidth reduction must be substantial (>80%)
    opt_bytes = opt_run["summary"]["endpoint_stats"]["bytes"]
    naive_bytes = naive_run["summary"]["endpoint_stats"]["bytes"]
    reduction = (1.0 - (opt_bytes / naive_bytes)) * 100
    assert reduction > 80.0


def test_contract_verification_and_tampering(source_code, signing_key):
    """Test Ed25519 contract verification and tampering detection."""
    comp = compile_source(source_code)
    plan = comp.plan("optimized")
    envelope = build_contract(
        plan=plan,
        ir=comp.ir,
        targets=[{"host": "WIN-01", "platform": "windows"}],
        signing_key=signing_key,
        investigation_id="incident_42",
    )
    pubkey = public_key_from_b64(envelope["contract"]["issuer"]["public_key"])

    # Valid contract verifies cleanly
    v = verify(envelope, pubkey)
    assert v.ok is True

    # Tampered plan hash must be caught
    tampered = json.loads(json.dumps(envelope))
    tampered["contract"]["plan"]["mode"] = "tampered"
    v_tampered = verify(tampered, pubkey)
    assert v_tampered.ok is False


def test_capability_policy_enforcement(source_code):
    """Test capability inference against default and strict policies."""
    comp = compile_source(source_code)
    plan = comp.plan("optimized")
    caps = plan["capabilities"]["required"]

    default_policy = load_policy("policies/default_policy.json")
    dec_win = evaluate_policy(default_policy, "WIN-01", caps)
    assert dec_win.allowed is True

    # Test forbidden capability rejection
    forbidden_caps = list(caps) + ["exec:powershell.exe"]
    dec_forbidden = evaluate_policy(default_policy, "WIN-01", forbidden_caps)
    assert dec_forbidden.allowed is False
    assert any("forbidden" in r for r in dec_forbidden.reasons)
