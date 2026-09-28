import pytest

from jocky.runtime.predicate import evaluate, glob_match


def cmp(op, field, value):
    return {"op": "cmp", "cmp": op, "field": field, "value": value}


REC = {"name": "PowerShell.EXE", "pid": 42, "ip": "10.1.2.3", "none": None, "flag": True}
get = REC.get


@pytest.mark.parametrize("pred,expected", [
    (cmp("==", "pid", 42), True),
    (cmp("==", "pid", "42"), False),  # type-strict
    (cmp("!=", "missing", 1), False),  # null never compares
    ({"op": "not", "arg": cmp("==", "missing", 1)}, True),
    (cmp("==", "none", None), True),
    (cmp("!=", "pid", None), True),
    (cmp("<", "pid", 43), True),
    (cmp(">=", "name", "A"), True),
    (cmp("<", "pid", "43"), False),
    (cmp("in", "pid", [1, 42]), True),
    (cmp("contains", "name", "shell"), True),  # ASCII case-insensitive
    (cmp("startswith", "name", "POWER"), True),
    (cmp("endswith", "name", ".exe"), True),
    (cmp("like", "name", "power*.e?e"), True),
    (cmp("like", "name", "pwsh*"), False),
    (cmp("cidr", "ip", "10.0.0.0/8"), True),
    (cmp("cidr", "ip", "fd00::/8"), False),
    (cmp("cidr", "name", "10.0.0.0/8"), False),
    (cmp("==", "flag", 1), False),  # bool is not int
    ({"op": "or", "args": [cmp("==", "pid", 1), cmp("==", "pid", 42)]}, True),
    ({"op": "and", "args": [cmp("==", "pid", 42), cmp("==", "pid", 1)]}, False),
])
def test_semantics(pred, expected):
    assert evaluate(pred, get) is expected


@pytest.mark.parametrize("pat,text,ok", [
    ("*", "", True), ("a*b", "ab", True), ("a*b", "axxb", True), ("a*b", "axxc", False),
    ("?", "", False), ("*.ps1", "c:\\t\\x.ps1", True), ("**a", "bba", True), ("a?c", "abc", True),
])
def test_glob(pat, text, ok):
    assert glob_match(pat, text) is ok
