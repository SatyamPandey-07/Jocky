import copy

from jocky.canonical import shift_time
from jocky.compiler import compile_source
from jocky.contract import build_contract, generate_key, verify


def make(incident42_source, key):
    comp = compile_source(incident42_source)
    return build_contract(plan=comp.plans["optimized"], ir=comp.ir, signing_key=key,
                          targets=[{"host": "WIN-01", "platform": "windows"}], investigation_id="inv_test")


def test_contract_has_required_fields(incident42_source, signing_key):
    env = make(incident42_source, signing_key)
    body = env["contract"]
    for field in ("investigation", "compiler_version", "plan", "targets", "required_capabilities",
                  "limits", "schema_version", "plan_hash", "nonce", "expires_at"):
        assert field in body
    assert env["signature"]["algorithm"] == "Ed25519"


def test_valid_contract_verifies(incident42_source, signing_key):
    env = make(incident42_source, signing_key)
    v = verify(env, signing_key.public_key(), host="WIN-01")
    assert v.ok, v.checks


def test_tampered_plan_is_rejected(incident42_source, signing_key):
    env = make(incident42_source, signing_key)
    bad = copy.deepcopy(env)
    bad["contract"]["plan"]["streams"][0]["predicate"] = None  # widen collection
    v = verify(bad, signing_key.public_key())
    failed = {c["check"] for c in v.checks if not c["passed"]}
    assert {"signature", "plan_hash"} <= failed


def test_wrong_key_wrong_target_and_expiry(incident42_source, signing_key):
    env = make(incident42_source, signing_key)
    assert not verify(env, generate_key().public_key()).ok
    assert not verify(env, signing_key.public_key(), host="WIN-99").ok
    later = shift_time(env["contract"]["expires_at"], 1)
    assert not verify(env, signing_key.public_key(), now=later).ok
