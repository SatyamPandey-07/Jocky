import pytest

from jocky.ast import nodes as A
from jocky.errors import CompileError
from jocky.parser import parse


def diag_codes(src):
    with pytest.raises(CompileError) as e:
        parse(src)
    return e.value.diagnostics


def test_parses_running_example(incident42_source):
    inv = parse(incident42_source)
    assert inv.name == "incident_42"
    assert inv.targets == ["WIN-01", "WIN-02", "UBUNTU-01", "OFFLINE-01"]
    assert inv.window.kind == "last" and inv.window.last.seconds == 86400
    lets = [s for s in inv.statements if isinstance(s, A.Let)]
    assert [l.name for l in lets] == ["shells", "drops", "beacons", "chain"]
    seq = lets[3].pipeline.source
    assert isinstance(seq, A.Sequence)
    assert [r.name for r in seq.steps] == ["shells", "drops", "beacons"]
    assert [k.text for k in seq.keys] == ["host", "pid"]
    assert seq.within.seconds == 1200
    emit = [s for s in inv.statements if isinstance(s, A.Emit)][0]
    assert emit.severity == "high" and emit.title.startswith("PowerShell")


def test_all_eight_primitives_parse():
    src = """
    investigation all_ops {
      window from "2026-09-01T00:00:00Z" to "2026-09-02T00:00:00Z"
      let p = observe Process | filter name like "power*" and not (pid in [4, 8]) | select pid, name | within 2h
      let f = observe File | filter path endswith ".ps1"
      let j = join p, f on host, pid within 5m
      let s = sequence p -> f on host, pid within 10m
      preserve j
      emit finding s as "t" severity critical
    }"""
    inv = parse(src)
    kinds = {type(x).__name__ for s in inv.statements if isinstance(s, A.Let)
             for x in [s.pipeline.source, *s.pipeline.stages]}
    assert {"Observe", "Filter", "Select", "Within", "Join", "Sequence"} <= kinds
    assert any(isinstance(s, A.Preserve) for s in inv.statements)
    assert any(isinstance(s, A.Emit) for s in inv.statements)


def test_sequence_requires_within_with_hint():
    d = diag_codes("investigation x { let a = observe Process\n let s = sequence a -> a on pid\n emit finding s }")
    assert d[0].code == "E0100"
    assert "within" in d[0].message and "within 20m" in d[0].hint
    assert d[0].span.line == 3


def test_single_equals_gets_hint():
    d = diag_codes('investigation x { let a = observe Process | filter name = "x" emit finding a }')
    assert "use '=='" in d[0].hint


def test_bad_duration_unit():
    d = diag_codes("investigation x { window last 20x }")
    assert d[0].code == "E0001" and "duration unit" in d[0].message


def test_unterminated_string():
    d = diag_codes('investigation x { title "abc\n }')
    assert "unterminated" in d[0].message


def test_recovery_reports_multiple_errors():
    src = """investigation x {
      let a = observe
      let b = observe File | filter
      emit finding b severity extreme
    }"""
    d = diag_codes(src)
    assert len(d) == 3
    assert [x.span.line for x in d] == [3, 4, 4]


def test_error_rendering_has_caret():
    src = 'investigation x { let a = observe Process | filter pid ~ 3 }'
    with pytest.raises(CompileError) as e:
        parse(src)
    text = e.value.render(src, "x.jocky")
    assert "x.jocky:1:" in text and "^" in text
