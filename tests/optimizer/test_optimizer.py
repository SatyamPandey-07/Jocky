"""Optimizer: rewrites fire where expected, and optimized == naive findings (Milestone 4)."""
import json

import pytest

from jocky.compiler import compile_source
from jocky.runtime.local import run_offline


def rules(plan):
    return [r["rule"] for r in plan["rewrites"]]


def test_all_rewrites_fire_on_running_example(incident42_source):
    plan = compile_source(incident42_source).plans["optimized"]
    assert {"predicate-pushdown", "temporal-pushdown", "projection-pushdown", "semi-join-reduction"} <= set(rules(plan))
    assert [c["op"] for c in plan["central"]] == ["sequence", "preserve", "emit"]
    assert plan["reduce_groups"][0]["keys"] == ["host", "pid"]
    naive = compile_source(incident42_source).plans["naive"]
    assert naive["rewrites"] == [] and all(s["predicate"] is None and s["fields"] is None for s in naive["streams"])


def test_predicate_pushdown_through_join():
    src = """investigation t { targets ["H"] window last 24h
      let p = observe Process | select pid, name
      let n = observe NetworkConnection | select pid, remote_port
      let j = join p, n on host, pid within 10m | filter n.remote_port == 443 and p.name == "x" or p.pid == 1
      let k = join p, n on host, pid | filter n.remote_port == 8443 and p.name like "power*"
      emit finding j
      emit finding k }"""
    comp = compile_source(src)
    plan = comp.plans["optimized"]
    # `j`'s filter is a disjunction and `p`/`n` are shared: nothing may be pushed
    assert any(c["op"] == "filter" for c in plan["central"])
    assert all(s["reduce_group"] is None for s in plan["streams"])


def test_pushdown_through_join_when_safe():
    src = """investigation t { targets ["H"] window last 24h
      let p = observe Process | select pid, name
      let n = observe NetworkConnection | select pid, remote_port
      let j = join p, n on host, pid within 10m | filter n.remote_port == 443 and p.name like "power*"
      emit finding j }"""
    plan = compile_source(src).plans["optimized"]
    assert not any(c["op"] == "filter" for c in plan["central"])
    by = {s["binding"]: s for s in plan["streams"]}
    assert by["n"]["predicate"] == {"op": "cmp", "cmp": "==", "field": "remote_port", "value": 443}
    assert by["p"]["predicate"]["cmp"] == "like"


def test_dead_stream_elimination():
    src = """investigation t { targets ["H"] window last 24h
      let p = observe Process
      let u = observe User
      emit finding p }"""
    plan = compile_source(src).plans["optimized"]
    assert [s["entity"] for s in plan["streams"]] == ["Process"]
    assert "dead-stream-elimination" in rules(plan)


VARIANTS = {
    "running_example": None,
    "join_within": """investigation v { window last 24h
        let p = observe Process | filter name in ["powershell.exe", "pwsh"]
        let f = observe File | filter action == "create" | select pid, path
        let j = join p, f on host, pid within 5m
        emit finding j severity low }""",
    "no_host_key": """investigation v { window last 24h
        let p = observe Process | filter name like "p*sh*"
        let n = observe NetworkConnection | filter remote_port == 443
        let s = sequence p -> n on pid within 30m
        emit finding s }""",
    "derived_filter_and_select": """investigation v { window last 24h
        let p = observe Process
        let n = observe NetworkConnection
        let j = join p, n on host, pid within 20m | filter n.remote_port == 443 and p.name endswith ".exe" | select p.pid, p.name, n.remote_ip
        preserve j
        emit finding j }""",
    "within_stage": """investigation v { window last 24h
        let n = observe NetworkConnection | within 4h | filter direction == "outbound"
        emit finding n severity info }""",
    "shared_stream": """investigation v { window last 24h
        let p = observe Process | filter name in ["powershell.exe", "pwsh"]
        let f = observe File
        let n = observe NetworkConnection
        let a = join p, f on host, pid within 20m
        let b = join p, n on host, pid within 20m
        emit finding a
        emit finding b }""",
}


@pytest.mark.parametrize("name", list(VARIANTS))
def test_optimized_and_naive_findings_are_identical(name, incident42_source, lab_dataset, signing_key):
    src = VARIANTS[name] or incident42_source
    opt = run_offline(src, lab_dataset, key=signing_key, mode="optimized")
    naive = run_offline(src, lab_dataset, key=signing_key, mode="naive")
    assert opt["summary"]["digest"] == naive["summary"]["digest"], name
    assert json.dumps(opt["findings"], sort_keys=True).count("finding_id") == \
        json.dumps(naive["findings"], sort_keys=True).count("finding_id")
    assert opt["summary"]["endpoint_stats"]["bytes"] <= naive["summary"]["endpoint_stats"]["bytes"]


def test_running_example_matches_ground_truth(incident42_source, lab_dataset, signing_key):
    truth = json.loads((lab_dataset / "ground_truth.json").read_text())
    res = run_offline(incident42_source, lab_dataset, key=signing_key)
    found = set()
    for f in res["findings"]:
        anchor = f["evidence"][f["anchor"]]
        found.add((anchor["host"], anchor["fields"]["pid"]))
    assert found == {(e["host"], e["pid"]) for e in truth["expected_findings"]}
