from jocky.capabilities import evaluate, stream_capabilities
from jocky.compiler import compile_source

POLICY = {
    "name": "test",
    "default": {"allow": ["collect:process", "collect:file", "collect:network", "preserve:records"]},
    "targets": {
        "TRUSTED": {"allow": ["collect:*", "preserve:records", "acquire:file.content"]},
        "LOCKED": {"deny": ["collect:network"]},
    },
}


def test_optimized_needs_less_privilege_than_naive(incident42_source):
    comp = compile_source(incident42_source)
    opt = set(comp.plans["optimized"]["capabilities"]["required"])
    naive = set(comp.plans["naive"]["capabilities"]["required"])
    assert opt == {"collect:process", "collect:file", "collect:network", "preserve:records"}
    assert naive - opt == {"collect:process.cmdline", "collect:file.hash"}


def test_policy_allow_and_reject(incident42_source):
    comp = compile_source(incident42_source)
    opt = comp.plans["optimized"]["capabilities"]["required"]
    naive = comp.plans["naive"]["capabilities"]["required"]
    assert evaluate(POLICY, "WIN-01", opt).decision == "ALLOW"
    d = evaluate(POLICY, "WIN-01", naive)
    assert d.decision == "REJECT" and set(d.denied) == {"collect:process.cmdline", "collect:file.hash"}
    assert evaluate(POLICY, "TRUSTED", naive).decision == "ALLOW"
    locked = evaluate(POLICY, "LOCKED", opt)
    assert locked.decision == "REJECT" and locked.denied == ["collect:network"]


def test_forbidden_families_never_granted():
    d = evaluate({"name": "p", "default": {"allow": ["*"]}}, "H", ["exec:process", "collect:process"])
    assert d.decision == "REJECT" and d.denied == ["exec:process"]
    assert "read-only" in d.reasons[0]


def test_predicate_on_sensitive_field_requires_capability():
    stream = {"entity": "Process", "fields": ["pid"],
              "predicate": {"op": "cmp", "cmp": "contains", "field": "cmdline", "value": "-enc"}}
    assert "collect:process.cmdline" in stream_capabilities(stream)


def test_content_acquisition_capability():
    src = """investigation t { targets ["H"] window last 1h
      let f = observe File | filter extension == "ps1"
      preserve f with content }"""
    comp = compile_source(src)
    assert "acquire:file.content" in comp.plans["optimized"]["capabilities"]["required"]
    assert "naive" in comp.plan_errors  # naive would acquire every file
