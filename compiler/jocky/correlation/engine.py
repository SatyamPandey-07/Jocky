"""Central correlation engine: executes a plan's central fragment.

Deterministic: identical input evidence always yields identical findings
(and therefore identical digests), which is what makes replay meaningful.

Values flowing between nodes are either
* evidence collections: lists of evidence records, or
* derived collections:  lists of tuples  {alias: record}.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field

from ..canonical import digest, parse_time, shift_time
from ..version import FINDING_FORMAT
from ..runtime.predicate import evaluate, record_getter

MAX_CHAINS_PER_ANCHOR = 100


@dataclass
class Value:
    kind: str  # "evidence" | "derived"
    items: list
    aliases: list[str] = field(default_factory=list)
    components: list[dict] = field(default_factory=list)


def _micros(t: str) -> int:
    dt = parse_time(t)
    return int(dt.timestamp()) * 1_000_000 + dt.microsecond


def _tuple_getter(tup: dict):
    def get(name: str):
        alias, _, fname = name.partition(".")
        rec = tup.get(alias)
        if rec is None:
            return None
        return record_getter(rec)(fname)
    return get


def _project(record: dict, keep: list[str]) -> dict:
    r = dict(record)
    r["fields"] = {f: record["fields"].get(f) for f in keep if f not in ("host", "time")}
    return r


def _key(record: dict, keys: list[str]):
    get = record_getter(record)
    vals = tuple(get(k) for k in keys)
    return None if any(v is None for v in vals) else vals


class Engine:
    def __init__(self, plan: dict, window: dict | None):
        self.plan = plan
        self.window = window
        self.values: dict[str, Value] = {}
        self.findings: list[dict] = []
        self.preserved: list[dict] = []
        self.notes: list[str] = []

    def load_streams(self, streams: dict[str, list[dict]]) -> None:
        for s in self.plan["streams"]:
            recs = {}
            for r in streams.get(s["id"], []):
                recs.setdefault(r["evidence_id"], r)
            items = sorted(recs.values(), key=lambda r: (r["time"], r["evidence_id"]))
            self.values[s["id"]] = Value("evidence", items)

    def run(self, streams: dict[str, list[dict]]) -> dict:
        self.load_streams(streams)
        for node in self.plan["central"]:
            self.values[node["id"]] = self.exec(node)
        findings = sorted(self.findings, key=lambda f: (f["first_seen"], f["digest"]))
        return {
            "findings": findings,
            "preserved": self.preserved,
            "digest": digest(sorted(f["digest"] for f in findings)),
            "notes": self.notes,
        }

    # ---- operators ------------------------------------------------------------
    def exec(self, n: dict) -> Value | None:
        op = n["op"]
        inp = self.values[n["inputs"][0]] if n["inputs"] else None
        if op == "timerange":
            lo, hi = self.window["from"], self.window["to"]
            return Value("evidence", [r for r in inp.items if lo <= r["time"] <= hi])
        if op == "within":
            lo, hi = shift_time(self.window["to"], -int(n["seconds"])), self.window["to"]
            return Value("evidence", [r for r in inp.items if lo <= r["time"] <= hi])
        if op == "filter":
            if inp.kind == "evidence":
                return Value("evidence", [r for r in inp.items if evaluate(n["predicate"], record_getter(r))])
            return Value("derived", [t for t in inp.items if evaluate(n["predicate"], _tuple_getter(t))],
                         inp.aliases, inp.components)
        if op == "select":
            if inp.kind == "evidence":
                return Value("evidence", [_project(r, n["fields"]) for r in inp.items])
            per_alias: dict[str, list[str]] = defaultdict(list)
            for f in n["fields"]:
                alias, _, fname = f.partition(".")
                per_alias[alias].append(fname)
            items = [{a: _project(r, per_alias.get(a, [])) for a, r in t.items()} for t in inp.items]
            return Value("derived", items, inp.aliases, inp.components)
        if op == "join":
            return self.join(n)
        if op == "sequence":
            return self.sequence(n)
        if op == "preserve":
            self.preserve(n, inp)
            return None
        if op == "emit":
            self.emit(n, inp)
            return None
        raise ValueError(f"unknown central op {op!r}")

    def _components(self, n: dict) -> list[dict]:
        ent = {c["alias"]: c["entity"] for c in n["evidence"].get("components", [])}
        return [{"alias": a, "entity": ent.get(a)} for a in n["aliases"]]

    def join(self, n: dict) -> Value:
        left, right = (self.values[i].items for i in n["inputs"])
        la, ra = n["aliases"]
        keys, within = n["keys"], n.get("within_seconds")
        index: dict[tuple, list[dict]] = defaultdict(list)
        for r in right:
            k = _key(r, keys)
            if k is not None:
                index[k].append(r)
        out = []
        for l in left:
            k = _key(l, keys)
            if k is None:
                continue
            for r in index.get(k, []):
                if within is not None and abs(_micros(l["time"]) - _micros(r["time"])) > within * 1_000_000:
                    continue
                out.append({la: l, ra: r})
        out.sort(key=lambda t: tuple((t[a]["time"], t[a]["evidence_id"]) for a in (la, ra)))
        return Value("derived", out, [la, ra], self._components(n))

    def sequence(self, n: dict) -> Value:
        aliases, keys = n["aliases"], n["keys"]
        within_us = int(n["within_seconds"]) * 1_000_000
        groups: list[dict[tuple, list[tuple[int, dict]]]] = []
        for i in n["inputs"]:
            g: dict[tuple, list[tuple[int, dict]]] = defaultdict(list)
            for r in self.values[i].items:
                k = _key(r, keys)
                if k is not None:
                    g[k].append((_micros(r["time"]), r))
            for lst in g.values():
                lst.sort(key=lambda x: (x[0], x[1]["evidence_id"]))
            groups.append(g)
        out: list[dict] = []
        truncated = 0
        for k, anchors in sorted(groups[0].items(), key=lambda kv: repr(kv[0])):
            rest = [g.get(k, []) for g in groups[1:]]
            if any(not lst for lst in rest):
                continue
            rest_times = [[t for t, _ in lst] for lst in rest]
            for t0, a in anchors:
                chains: list[list[dict]] = []

                def extend(step: int, prev_t: int, chain: list[dict]) -> None:
                    if len(chains) >= MAX_CHAINS_PER_ANCHOR:
                        return
                    if step == len(rest):
                        chains.append(chain)
                        return
                    lst, times = rest[step], rest_times[step]
                    j = bisect.bisect_left(times, prev_t)
                    while j < len(lst) and times[j] - t0 <= within_us:
                        extend(step + 1, times[j], chain + [lst[j][1]])
                        j += 1

                extend(0, t0, [a])
                if len(chains) >= MAX_CHAINS_PER_ANCHOR:
                    truncated += 1
                out.extend({alias: rec for alias, rec in zip(aliases, c)} for c in chains)
        if truncated:
            self.notes.append(f"sequence {n['id']}: {truncated} anchor(s) hit the {MAX_CHAINS_PER_ANCHOR}-chain cap")
        out.sort(key=lambda t: tuple((t[a]["time"], t[a]["evidence_id"]) for a in aliases))
        return Value("derived", out, list(aliases), self._components(n))

    # ---- outputs ------------------------------------------------------------------
    @staticmethod
    def _records(v: Value) -> list[dict]:
        if v.kind == "evidence":
            return list(v.items)
        return [r for t in v.items for r in t.values()]

    def preserve(self, n: dict, v: Value) -> None:
        ids = sorted({r["evidence_id"] for r in self._records(v)})
        self.preserved.append({
            "node": n["id"],
            "binding": n["binding"],
            "with_content": n.get("with_content", False),
            "evidence_ids": ids,
            "digest": digest(ids),
        })

    @staticmethod
    def _evidence_view(r: dict) -> dict:
        return {"entity": r["entity"], "host": r["host"], "time": r["time"],
                "time_source": r["time_source"], "fields": r["fields"]}

    def emit(self, n: dict, v: Value) -> None:
        if v.kind == "evidence":
            for r in v.items:
                self._finding(n, "Evidence", [{"alias": n["binding"], "entity": r["entity"]}],
                              r, [[r]])
            return
        by_anchor: dict[str, list[list[dict]]] = defaultdict(list)
        anchors: dict[str, dict] = {}
        first = v.aliases[0]
        for t in v.items:
            a = t[first]
            anchors[a["evidence_id"]] = a
            by_anchor[a["evidence_id"]].append([t[al] for al in v.aliases])
        shape = n["evidence"].get("shape") or "Derived"
        for aid in sorted(by_anchor):
            self._finding(n, shape, v.components, anchors[aid], by_anchor[aid])

    def _finding(self, n: dict, shape: str, components: list[dict], anchor: dict,
                 chains: list[list[dict]]) -> None:
        evidence: dict[str, dict] = {}
        for chain in chains:
            for r in chain:
                evidence[r["evidence_id"]] = self._evidence_view(r)
        times = [e["time"] for e in evidence.values()]
        content = {
            "format": FINDING_FORMAT,
            "binding": n["binding"],
            "title": n["title"],
            "severity": n["severity"],
            "shape": shape,
            "components": components,
            "anchor": anchor["evidence_id"],
            "host": anchor["host"],
            "chains": sorted([[r["evidence_id"] for r in c] for c in chains]),
            "evidence": evidence,
            "first_seen": min(times),
            "last_seen": max(times),
        }
        d = digest(content)
        content["digest"] = d
        content["finding_id"] = "fd_" + d[:24]
        content["node"] = n["id"]
        self.findings.append(content)


def correlate(plan: dict, window: dict | None, streams: dict[str, list[dict]]) -> dict:
    return Engine(plan, window).run(streams)
