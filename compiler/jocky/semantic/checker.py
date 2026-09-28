"""Semantic + evidence-type analysis (compiler layers C2 and C3).

Checks name resolution, entity/field existence, operator/type compatibility,
join/sequence key validity, temporal expressions, and emitted/preserved
values.  Produces an `Analysis`: the evidence type of every binding plus
normalized predicates (time/IP/CIDR literals canonicalized) for lowering.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..ast import nodes as A
from ..canonical import canonical_ip, canonical_time, parse_time
from ..errors import CompileError, Diagnostic, Span
from ..evidence.types import EvidenceType, derived, evidence
from ..schema import load_schema

STRING_OPS = {"contains", "startswith", "endswith", "like"}
ORDER_OPS = {"<", "<=", ">", ">="}


@dataclass
class Analysis:
    program: A.Investigation
    bindings: dict[str, EvidenceType] = field(default_factory=dict)
    binding_order: list[str] = field(default_factory=list)
    # id(Filter) -> normalized predicate (IR JSON form)
    predicates: dict[int, dict] = field(default_factory=dict)
    window: dict | None = None
    warnings: list[Diagnostic] = field(default_factory=list)
    # binding -> evidence type after the source and after each stage
    stage_types: dict[str, list[EvidenceType]] = field(default_factory=dict)
    finding_types: dict[str, EvidenceType] = field(default_factory=dict)


class Checker:
    def __init__(self, program: A.Investigation):
        self.p = program
        self.schema = load_schema()
        self.errors: list[Diagnostic] = []
        self.an = Analysis(program=program)
        self.used: set[str] = set()
        self.binding_spans: dict[str, Span] = {}

    # ---- helpers ------------------------------------------------------------
    def error(self, code: str, msg: str, span: Span | None, hint: str | None = None) -> None:
        self.errors.append(Diagnostic("error", code, msg, span, hint))

    def warn(self, code: str, msg: str, span: Span | None, hint: str | None = None) -> None:
        self.an.warnings.append(Diagnostic("warning", code, msg, span, hint))

    def lookup(self, ref: A.Ref) -> EvidenceType | None:
        t = self.an.bindings.get(ref.name)
        if t is None:
            known = ", ".join(self.an.binding_order) or "none defined yet"
            self.error("E0201", f"unknown binding '{ref.name}'", ref.span,
                       f"bindings must be defined with `let` before use (known: {known})")
            return None
        self.used.add(ref.name)
        return t

    # ---- entry ---------------------------------------------------------------
    def run(self) -> Analysis:
        p = self.p
        self.check_header()
        for st in p.statements:
            if isinstance(st, A.Let):
                self.check_let(st)
        outputs = 0
        for st in p.statements:
            if isinstance(st, A.Preserve):
                outputs += 1
                t = self.lookup(st.target)
                if t is not None and st.with_content and not (t.is_evidence and t.entity == "File"):
                    self.error("E0210", f"`preserve ... with content` needs Evidence<File>, but "
                               f"'{st.target.name}' is {t.render()}", st.span,
                               "content acquisition applies to file evidence streams")
            elif isinstance(st, A.Emit):
                outputs += 1
                t = self.lookup(st.target)
                if t is not None:
                    self.an.finding_types[st.target.name] = t.as_finding()
        if outputs == 0:
            self.error("E0211", "investigation produces nothing: add `emit finding <binding>` or "
                       "`preserve <binding>`", p.span)
        for name in self.an.binding_order:
            if name not in self.used:
                self.warn("W0001", f"binding '{name}' is never used", self.binding_spans.get(name))
        if self.errors:
            raise CompileError(self.errors + self.an.warnings)
        return self.an

    def check_header(self) -> None:
        p = self.p
        if p.targets is not None:
            seen: set[str] = set()
            for t in p.targets:
                if t in seen:
                    self.error("E0213", f"duplicate target '{t}'", p.span)
                seen.add(t)
            if not p.targets:
                self.error("E0213", "targets list is empty", p.span)
        else:
            self.warn("W0004", "no `targets`: endpoints must be chosen at dispatch time", p.span)
        w = p.window
        if w is None:
            self.warn("W0003", "no `window`: collection is unbounded in time (no temporal pushdown)",
                      p.span, "add e.g. `window last 24h`")
            return
        if w.kind == "last":
            if w.last.seconds <= 0:
                self.error("E0208", "window duration must be positive", w.span)
            self.an.window = {"last_seconds": w.last.seconds}
        else:
            try:
                start, end = parse_time(w.start), parse_time(w.end)
            except ValueError as e:
                self.error("E0209", f"invalid window timestamp: {e}", w.span,
                           'use RFC 3339, e.g. "2026-09-28T00:00:00Z"')
                return
            if start >= end:
                self.error("E0209", "window start must be before window end", w.span)
            self.an.window = {"from": canonical_time(w.start), "to": canonical_time(w.end)}

    # ---- bindings ------------------------------------------------------------
    def check_let(self, st: A.Let) -> None:
        if st.name in self.an.bindings:
            self.error("E0202", f"binding '{st.name}' is already defined", st.name_span)
            return
        if st.name in self.schema.entities:
            self.error("E0202", f"binding name '{st.name}' shadows an entity type", st.name_span)
            return
        t = self.check_source(st.pipeline.source, st.name)
        if t is None:
            return
        progression = [t]
        for stage in st.pipeline.stages:
            t = self.check_stage(stage, t)
            if t is None:
                return
            progression.append(t)
        self.an.stage_types[st.name] = progression
        self.an.bindings[st.name] = t
        self.an.binding_order.append(st.name)
        self.binding_spans[st.name] = st.name_span

    def check_source(self, src, binding: str) -> EvidenceType | None:
        if isinstance(src, A.Observe):
            ent = self.schema.entities.get(src.entity)
            if ent is None:
                self.error("E0200", f"unknown entity type '{src.entity}'", src.span,
                           "entities: " + ", ".join(self.schema.entities))
                return None
            return evidence(src.entity, {n: f.type for n, f in ent.fields.items()}, binding)
        if isinstance(src, A.Ref):
            t = self.lookup(src)
            if t is None:
                return None
            return EvidenceType(kind=t.kind, entity=t.entity, shape=t.shape,
                                components=list(t.components), schema=dict(t.schema),
                                lineage=list(t.lineage))
        if isinstance(src, A.Join):
            return self.check_correlation("Join", [src.left, src.right], src.keys, src.within, src.span)
        if isinstance(src, A.Sequence):
            return self.check_correlation("Sequence", src.steps, src.keys, src.within, src.span)
        raise AssertionError(src)

    def check_correlation(self, shape: str, refs: list[A.Ref], keys: list[A.FieldRef],
                          within: A.Duration | None, span: Span) -> EvidenceType | None:
        ok = True
        inputs: list[tuple[str, EvidenceType]] = []
        names = [r.name for r in refs]
        for r in refs:
            if names.count(r.name) > 1:
                self.error("E0206", f"'{r.name}' appears more than once in {shape.lower()}", r.span,
                           "define a second binding over the same stream if a self-correlation is intended")
                ok = False
                continue
            t = self.lookup(r)
            if t is None:
                ok = False
                continue
            if not t.is_evidence:
                self.error("E0206", f"{shape.lower()} inputs must be evidence streams, but '{r.name}' "
                           f"is {t.render()}", r.span, "nested correlation is deferred beyond the MVP")
                ok = False
                continue
            inputs.append((r.name, t))
        if within is not None and within.seconds <= 0:
            self.error("E0208", "within duration must be positive", within.span)
            ok = False
        key_names: list[str] = []
        for k in keys:
            if len(k.parts) != 1:
                self.error("E0207", f"join key '{k.text}' must be an unqualified field name", k.span)
                ok = False
                continue
            if k.text in key_names:
                self.error("E0207", f"duplicate key '{k.text}'", k.span)
                ok = False
                continue
            key_names.append(k.text)
            types = set()
            for name, t in inputs:
                ft = t.schema.get(k.text)
                if ft is None:
                    self.error("E0207", f"key '{k.text}' is not a field of '{name}' ({t.render()})", k.span,
                               "available: " + ", ".join(sorted(t.schema)))
                    ok = False
                else:
                    types.add(ft)
            if len(types) > 1:
                self.error("E0207", f"key '{k.text}' has incompatible types across inputs: "
                           + ", ".join(sorted(types)), k.span)
                ok = False
        if ok and "host" not in key_names:
            self.warn("W0002", f"{shape.lower()} keys do not include 'host': records from different "
                      "endpoints may be correlated (and endpoint-side semi-join reduction is disabled)", span,
                      "use e.g. `on host, pid`")
        if not ok:
            return None
        return derived(shape, inputs)

    def check_stage(self, stage, t: EvidenceType) -> EvidenceType | None:
        if isinstance(stage, A.Filter):
            pred = self.check_expr(stage.expr, t)
            if pred is None:
                return None
            self.an.predicates[id(stage)] = pred
            return t
        if isinstance(stage, A.Select):
            keep: dict[str, str] = {}
            ok = True
            for f in stage.fields:
                name = self.resolve_field(f, t)
                if name is None:
                    ok = False
                    continue
                if name in keep:
                    self.error("E0203", f"field '{f.text}' selected twice", f.span)
                    ok = False
                keep[name] = t.schema[name]
            if not ok:
                return None
            implicit = ["host", "time"] if t.is_evidence else [
                f"{c.alias}.{x}" for c in t.components for x in ("host", "time")]
            for name in implicit:
                keep.setdefault(name, t.schema[name])
            return EvidenceType(kind=t.kind, entity=t.entity, shape=t.shape,
                                components=list(t.components), schema=keep, lineage=list(t.lineage))
        if isinstance(stage, A.Within):
            if not t.is_evidence:
                self.error("E0205", "`| within` applies to evidence streams", stage.span,
                           "for correlations use the `within` clause of join/sequence")
                return None
            if stage.duration.seconds <= 0:
                self.error("E0208", "within duration must be positive", stage.span)
                return None
            if self.p.window is None:
                self.error("E0209", "`| within` is relative to the investigation window, but no "
                           "window is declared", stage.span, "add e.g. `window last 24h`")
                return None
            return t
        raise AssertionError(stage)

    # ---- expressions -----------------------------------------------------------
    def resolve_field(self, f: A.FieldRef, t: EvidenceType) -> str | None:
        name = f.text
        if t.is_evidence:
            if len(f.parts) != 1:
                self.error("E0203", f"'{name}' is not a field of {t.render()}", f.span,
                           "fields of an evidence stream are unqualified, e.g. `pid`")
                return None
        else:
            if len(f.parts) == 1:
                matches = [k for k in t.schema if k.endswith("." + name)]
                self.error("E0212", f"field '{name}' is ambiguous on {t.render()}", f.span,
                           "qualify it with a component: " + ", ".join(matches[:4]) if matches else None)
                return None
        if name not in t.schema:
            self.error("E0203", f"unknown field '{name}' on {t.render()}", f.span,
                       "available: " + ", ".join(sorted(t.schema)))
            return None
        return name

    def coerce(self, lit: A.Literal, ftype: str, op: str, fname: str):
        """Return (ok, normalized value)."""
        if lit.kind == "null":
            if op not in ("==", "!="):
                self.error("E0204", f"null can only be compared with == or !=", lit.span)
                return False, None
            return True, None
        if ftype == "int":
            if lit.kind != "int":
                self.error("E0204", f"'{fname}' is int but the literal is {lit.kind}", lit.span)
                return False, None
            return True, lit.value
        if ftype == "bool":
            if lit.kind != "bool":
                self.error("E0204", f"'{fname}' is bool but the literal is {lit.kind}", lit.span)
                return False, None
            return True, lit.value
        if lit.kind != "str":
            self.error("E0204", f"'{fname}' is {ftype} but the literal is {lit.kind}", lit.span)
            return False, None
        if ftype == "time":
            try:
                return True, canonical_time(lit.value)
            except ValueError:
                self.error("E0214", f"'{lit.value}' is not a valid timestamp for time field '{fname}'",
                           lit.span, 'use RFC 3339, e.g. "2026-09-28T10:00:00Z"')
                return False, None
        if ftype == "ip":
            ip = canonical_ip(lit.value)
            if ip is None:
                self.error("E0214", f"'{lit.value}' is not a valid IP address for '{fname}'", lit.span,
                           'for ranges use `in cidr("10.0.0.0/8")`')
                return False, None
            return True, ip
        return True, lit.value

    def check_expr(self, e, t: EvidenceType) -> dict | None:
        if isinstance(e, A.BoolOp):
            args = [self.check_expr(a, t) for a in e.args]
            if any(a is None for a in args):
                return None
            return {"op": e.op, "args": args}
        if isinstance(e, A.Not):
            a = self.check_expr(e.arg, t)
            return None if a is None else {"op": "not", "arg": a}
        if isinstance(e, A.Compare):
            name = self.resolve_field(e.field, t)
            if name is None:
                return None
            ftype = t.schema[name]
            if e.op in STRING_OPS and ftype != "str":
                self.error("E0205", f"'{e.op}' needs a str field, '{name}' is {ftype}", e.span)
                return None
            if e.op in ORDER_OPS and ftype not in ("int", "time", "str"):
                self.error("E0205", f"'{e.op}' is not defined for {ftype} field '{name}'", e.span,
                           'for IP ranges use `in cidr("...")`')
                return None
            ok, value = self.coerce(e.value, ftype, e.op, name)
            if not ok:
                return None
            return {"op": "cmp", "cmp": e.op, "field": name, "value": value}
        if isinstance(e, A.InList):
            name = self.resolve_field(e.field, t)
            if name is None:
                return None
            ftype = t.schema[name]
            values = []
            for lit in e.values:
                if lit.kind == "null":
                    self.error("E0204", "null is not allowed inside `in [...]`", lit.span,
                               "use `field == null`")
                    return None
                ok, v = self.coerce(lit, ftype, "==", name)
                if not ok:
                    return None
                values.append(v)
            return {"op": "cmp", "cmp": "in", "field": name, "value": values}
        if isinstance(e, A.InCidr):
            name = self.resolve_field(e.field, t)
            if name is None:
                return None
            if t.schema[name] != "ip":
                self.error("E0205", f"`in cidr(...)` needs an ip field, '{name}' is {t.schema[name]}", e.span)
                return None
            try:
                net = ipaddress.ip_network(e.cidr.value, strict=False)
            except ValueError:
                self.error("E0214", f"'{e.cidr.value}' is not a valid CIDR block", e.cidr.span)
                return None
            return {"op": "cmp", "cmp": "cidr", "field": name, "value": str(net)}
        raise AssertionError(e)


def check(program: A.Investigation) -> Analysis:
    return Checker(program).run()
