"""Plan optimizer (the rewrite rules demonstrated by the MVP).

Given the logical IR, split it into *endpoint streams* (work executed on the
agent next to the evidence) and a *central* fragment (correlation executed
by the control plane), applying:

1. predicate pushdown          — filters move into the endpoint stream;
                                 single-component conjuncts of a filter over
                                 a correlation move through the join.
2. temporal pushdown           — the investigation window and `| within`
                                 become collector time bounds.
3. projection pushdown         — streams ship only the fields that central
                                 operators and outputs actually use.
4. semi-join reduction         — host-local equi-correlations reduce every
                                 input stream to the key intersection on the
                                 endpoint before transfer.
5. dead-stream elimination     — observations that feed no output are not
                                 collected at all.

`naive` mode performs none of these: collect everything, transfer, then
filter and correlate centrally.  Both modes must yield identical findings.
"""
from __future__ import annotations

import copy

from ..ir.builder import consumers

LOCAL_OPS = ("filter", "select", "within")
CORRELATION_OPS = ("join", "sequence")


def conjuncts(pred: dict | None) -> list[dict]:
    if pred is None:
        return []
    if pred["op"] == "and":
        out: list[dict] = []
        for a in pred["args"]:
            out.extend(conjuncts(a))
        return out
    return [pred]


def conjoin(preds: list[dict]) -> dict | None:
    preds = [p for p in preds if p is not None]
    flat: list[dict] = []
    for p in preds:
        flat.extend(conjuncts(p))
    if not flat:
        return None
    if len(flat) == 1:
        return flat[0]
    return {"op": "and", "args": flat}


def predicate_fields(pred: dict | None) -> set[str]:
    if pred is None:
        return set()
    if pred["op"] in ("and", "or"):
        out: set[str] = set()
        for a in pred["args"]:
            out |= predicate_fields(a)
        return out
    if pred["op"] == "not":
        return predicate_fields(pred["arg"])
    return {pred["field"]}


def rename_fields(pred: dict, fn) -> dict:
    if pred["op"] in ("and", "or"):
        return {"op": pred["op"], "args": [rename_fields(a, fn) for a in pred["args"]]}
    if pred["op"] == "not":
        return {"op": "not", "arg": rename_fields(pred["arg"], fn)}
    out = dict(pred)
    out["field"] = fn(pred["field"])
    return out


def required_fields(nodes: list[dict], stream_schemas: dict[str, dict]) -> dict[str, set[str]]:
    """Backward analysis: which output fields of each node/stream are used."""
    by_id = {n["id"]: n for n in nodes}
    need: dict[str, set[str]] = {n["id"]: set() for n in nodes}
    for sid in stream_schemas:
        need[sid] = set()

    def schema_of(ref: str) -> dict:
        return stream_schemas[ref] if ref in stream_schemas else by_id[ref]["schema"]

    for n in reversed(nodes):
        op, out = n["op"], need[n["id"]]
        ins = n["inputs"]
        if op in ("emit", "preserve"):
            need[ins[0]] |= set(schema_of(ins[0]))
        elif op == "filter":
            need[ins[0]] |= out | predicate_fields(n["predicate"])
        elif op == "select":
            need[ins[0]] |= out
        elif op in ("within", "timerange"):
            need[ins[0]] |= out | {"time"}
        elif op in CORRELATION_OPS:
            for alias, ref in zip(n["aliases"], ins):
                prefix = alias + "."
                need[ref] |= {f[len(prefix):] for f in out if f.startswith(prefix)}
                need[ref] |= set(n["keys"]) | {"host", "time"}
    return need


def optimize(ir: dict, mode: str = "optimized") -> dict:
    """Return {streams, reduce_groups, central, rewrites} for `mode`."""
    if mode not in ("optimized", "naive"):
        raise ValueError(f"unknown plan mode {mode!r}")
    nodes = copy.deepcopy(ir["nodes"])
    by_id = {n["id"]: n for n in nodes}
    cons = consumers(nodes)
    rewrites: list[dict] = []
    window = ir["investigation"].get("window")

    # ---- reachability (dead-stream elimination) -------------------------------
    reachable: set[str] = set()
    stack = list(ir["outputs"]["emit"]) + list(ir["outputs"]["preserve"])
    while stack:
        nid = stack.pop()
        if nid in reachable:
            continue
        reachable.add(nid)
        stack.extend(by_id[nid]["inputs"])
    observes = [n for n in nodes if n["op"] == "observe"]
    if mode == "optimized":
        dead = [n for n in observes if n["id"] not in reachable]
        for n in dead:
            rewrites.append({"rule": "dead-stream-elimination",
                             "detail": f"observe {n['entity']} ({n.get('binding', n['id'])}) feeds no output; not collected"})
        nodes = [n for n in nodes if n["id"] in reachable]
        observes = [n for n in observes if n["id"] in reachable]
        cons = consumers(nodes)

    streams: list[dict] = []
    absorbed: set[str] = set()
    stream_of_output: dict[str, str] = {}

    def label(o: dict) -> str:
        """Name a stream after the first binding along its linear chain."""
        cur = o
        while "binding" not in cur and len(cons[cur["id"]]) == 1 and by_id[cons[cur["id"]][0]]["op"] in LOCAL_OPS:
            cur = by_id[cons[cur["id"]][0]]
        return cur.get("binding", o["id"])

    for o in observes:
        sid = f"s_{label(o)}"
        stream = {
            "id": sid,
            "root": o["id"],
            "entity": o["entity"],
            "binding": o.get("binding"),
            "predicate": None,
            "time": None,
            "fields": None,
            "reduce_group": None,
            "acquire_content": False,
        }
        absorbed.add(o["id"])
        cur = o
        if mode == "optimized":
            preds: list[dict] = []
            within: int | None = None
            while len(cons[cur["id"]]) == 1 and by_id[cons[cur["id"]][0]]["op"] in LOCAL_OPS:
                nxt = by_id[cons[cur["id"]][0]]
                if nxt["op"] == "filter":
                    preds.append(nxt["predicate"])
                    rewrites.append({"rule": "predicate-pushdown",
                                     "detail": f"filter {nxt['id']} on {o['entity']} evaluated on the endpoint"})
                elif nxt["op"] == "within":
                    within = nxt["seconds"] if within is None else min(within, nxt["seconds"])
                    rewrites.append({"rule": "temporal-pushdown",
                                     "detail": f"within {nxt['seconds']}s on {o['entity']} becomes a collector time bound"})
                absorbed.add(nxt["id"])
                cur = nxt
            stream["predicate"] = conjoin(preds)
            if window is not None or within is not None:
                stream["time"] = {"window": window is not None, "within_seconds": within}
                if window is not None:
                    rewrites.append({"rule": "temporal-pushdown",
                                     "detail": f"investigation window bounds {o['entity']} collection on the endpoint"})
        stream["output"] = cur["id"]
        stream["binding"] = cur.get("binding", stream["binding"])
        stream["schema"] = dict(cur["schema"])
        streams.append(stream)
        stream_of_output[cur["id"]] = sid

    # ---- central fragment ------------------------------------------------------
    central: list[dict] = []
    for n in nodes:
        if n["id"] in absorbed:
            continue
        c = copy.deepcopy(n)
        c["inputs"] = [stream_of_output.get(i, i) for i in n["inputs"]]
        central.append(c)
    if mode == "naive":
        # The naive plan transfers raw observations; the window is applied centrally.
        prepended: list[dict] = []
        for s in streams:
            if window is None:
                continue
            tid = f"t_{s['id']}"
            prepended.append({"id": tid, "op": "timerange", "inputs": [s["id"]], "window": True,
                              "schema": dict(s["schema"]), "type": by_id[s["root"]]["type"]})
            for c in central:
                c["inputs"] = [tid if i == s["id"] else i for i in c["inputs"]]
        central = prepended + central

    streams_by_id = {s["id"]: s for s in streams}

    if mode == "optimized":
        # ---- predicate pushdown through correlations ---------------------------
        central_cons = consumers(central + [{"id": s["id"], "inputs": []} for s in streams])
        cby = {c["id"]: c for c in central}
        for f in list(central):
            if f["op"] != "filter":
                continue
            src = cby.get(f["inputs"][0])
            if src is None or src["op"] not in CORRELATION_OPS or central_cons[src["id"]] != [f["id"]]:
                continue
            remaining: list[dict] = []
            for conj in conjuncts(f["predicate"]):
                flds = predicate_fields(conj)
                aliases = {x.split(".", 1)[0] for x in flds}
                target = None
                if len(aliases) == 1:
                    alias = next(iter(aliases))
                    idx = src["aliases"].index(alias)
                    inp = src["inputs"][idx]
                    if inp in streams_by_id and central_cons[inp] == [src["id"]]:
                        target = streams_by_id[inp]
                if target is None:
                    remaining.append(conj)
                    continue
                prefix = alias + "."
                local = rename_fields(conj, lambda x: x[len(prefix):])
                target["predicate"] = conjoin([target["predicate"], local])
                rewrites.append({"rule": "predicate-pushdown",
                                 "detail": f"conjunct on '{alias}' moved through {src['op']} {src['id']} to the endpoint"})
            if remaining:
                f["predicate"] = conjoin(remaining)
            else:
                # filter fully pushed: splice it out of the central graph
                central.remove(f)
                for c in central:
                    c["inputs"] = [src["id"] if i == f["id"] else i for i in c["inputs"]]
                rewrites.append({"rule": "predicate-pushdown",
                                 "detail": f"filter {f['id']} eliminated (all conjuncts pushed to endpoints)"})

        # ---- projection pushdown -------------------------------------------------
        need = required_fields(central, {s["id"]: s["schema"] for s in streams})
        for s in streams:
            payload_all = sorted(k for k in s["schema"] if k not in ("host", "time"))
            used = sorted(k for k in need[s["id"]] if k not in ("host", "time"))
            s["fields"] = used
            if len(used) < len(payload_all) or s["schema"] != by_id[s["root"]]["schema"]:
                total = len([k for k in by_id[s["root"]]["schema"] if k not in ("host", "time")])
                rewrites.append({"rule": "projection-pushdown",
                                 "detail": f"{s['id']} ships {len(used)}/{total} payload fields: {', '.join(used)}"})

        # ---- semi-join reduction -------------------------------------------------
        central_cons = consumers(central + [{"id": s["id"], "inputs": []} for s in streams])
        groups: list[dict] = []
        for c in central:
            if c["op"] not in CORRELATION_OPS or "host" not in c["keys"]:
                continue
            if not all(i in streams_by_id and central_cons[i] == [c["id"]] for i in c["inputs"]):
                continue
            gid = f"g{len(groups) + 1}"
            groups.append({"id": gid, "for": c["id"], "streams": list(c["inputs"]), "keys": list(c["keys"])})
            for i in c["inputs"]:
                streams_by_id[i]["reduce_group"] = gid
            rewrites.append({"rule": "semi-join-reduction",
                             "detail": f"{c['op']} {c['id']} is host-local on ({', '.join(c['keys'])}); endpoints "
                                       f"reduce {', '.join(c['inputs'])} to the key intersection before transfer"})
    else:
        groups = []

    # content acquisition for `preserve <File stream> with content`
    for c in central:
        if c["op"] == "preserve" and c.get("with_content"):
            src = c["inputs"][0]
            if src not in streams_by_id:
                raise ValueError(
                    f"`preserve {c['binding']} with content` needs the file stream to reach the endpoint "
                    f"unchanged; in {mode} mode it is transformed centrally"
                )
            if mode == "naive":
                raise ValueError("content acquisition requires the optimized plan "
                                 "(the naive plan would acquire every file on every endpoint)")
            streams_by_id[src]["acquire_content"] = True

    for s in streams:
        s["schema"] = dict(sorted(s["schema"].items()))
    return {"streams": streams, "reduce_groups": groups, "central": central, "rewrites": rewrites}
