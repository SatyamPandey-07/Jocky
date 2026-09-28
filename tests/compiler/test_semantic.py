import pytest

from jocky.compiler import compile_source
from jocky.errors import CompileError


def errors(src):
    with pytest.raises(CompileError) as e:
        compile_source(src)
    return [d for d in e.value.diagnostics if d.severity == "error"]


def wrap(body, window="window last 24h"):
    return f"investigation t {{ targets [\"H1\"] {window}\n{body}\n}}"


def test_example_types_and_lineage(incident42_source):
    comp = compile_source(incident42_source)
    b = comp.analysis.bindings
    assert b["shells"].render() == "Evidence<Process>"
    assert b["chain"].render() == "Derived<Sequence<Process, File, NetworkConnection>>"
    emit = next(n for n in comp.ir["nodes"] if n["op"] == "emit")
    assert emit["type"] == "Finding<Sequence<Process, File, NetworkConnection>>"
    observes = [n["id"] for n in comp.ir["nodes"] if n["op"] == "observe"]
    assert emit["evidence"]["lineage"] == observes  # finding traceable to all raw inputs
    assert comp.warnings == []


@pytest.mark.parametrize("body,code,fragment", [
    ("let a = observe Proc\nemit finding a", "E0200", "unknown entity"),
    ("emit finding nope", "E0201", "unknown binding"),
    ("let a = observe Process\nlet a = observe File\nemit finding a", "E0202", "already defined"),
    ("let a = observe Process | filter nme == \"x\"\nemit finding a", "E0203", "unknown field"),
    ("let a = observe Process | filter pid == \"4\"\nemit finding a", "E0204", "int"),
    ("let a = observe Process | filter pid like \"4*\"\nemit finding a", "E0205", "str field"),
    ("let a = observe Process | filter name in cidr(\"10.0.0.0/8\")\nemit finding a", "E0205", "ip field"),
    ("let a = observe NetworkConnection | filter remote_ip in cidr(\"10.0.0.0/33\")\nemit finding a", "E0214", "CIDR"),
    ("let a = observe NetworkConnection | filter remote_ip == \"999.1.1.1\"\nemit finding a", "E0214", "IP"),
    ("let a = observe Process | filter time > \"yesterday\"\nemit finding a", "E0214", "timestamp"),
    ("let a = observe Process\nlet b = observe User\nlet j = join a, b on host, pid\nemit finding j", "E0207", "not a field"),
    ("let a = observe Process\nlet b = observe File\nlet j = join a, b on host, pid\nlet s = sequence j -> a on host, pid within 5m\nemit finding s",
     "E0206", "evidence streams"),
    ("let a = observe Process\npreserve a with content", "E0210", "Evidence<File>"),
    ("let a = observe Process", "E0211", "produces nothing"),
    ("let a = observe Process\nlet b = observe File\nlet j = join a, b on host, pid | filter pid == 3\nemit finding j", "E0212", "ambiguous"),
])
def test_semantic_errors(body, code, fragment):
    errs = errors(wrap(body))
    assert any(e.code == code and fragment.lower() in (e.message + (e.hint or "")).lower() for e in errs), errs


def test_within_stage_requires_window():
    errs = errors(wrap("let a = observe Process | within 1h\nemit finding a", window=""))
    assert errs[0].code == "E0209"


def test_warnings_host_key_and_unused():
    comp = compile_source(wrap(
        "let a = observe Process\nlet b = observe File\nlet u = observe User\n"
        "let j = join a, b on pid\nemit finding j"))
    codes = {w.code for w in comp.warnings}
    assert {"W0001", "W0002"} <= codes


def test_time_and_ip_literals_are_canonicalized():
    comp = compile_source(wrap(
        'let a = observe NetworkConnection | filter time >= "2026-09-28T10:00:00+05:30" and remote_ip == "::ffff:10.1.2.3"\n'
        "emit finding a"))
    pred = next(n for n in comp.ir["nodes"] if n["op"] == "filter")["predicate"]
    assert pred["args"][0]["value"] == "2026-09-28T04:30:00.000000Z"
    assert pred["args"][1]["value"] == "10.1.2.3"


def test_select_keeps_implicit_host_and_time():
    comp = compile_source(wrap("let a = observe Process | select pid\nemit finding a"))
    assert set(comp.analysis.bindings["a"].schema) == {"pid", "host", "time"}
