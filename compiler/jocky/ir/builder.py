"""Forensic IR (compiler layer C5): a JSON logical plan.

The IR is a DAG of nodes in topological order.  Every node records its op
(one of the eight primitives), inputs, output schema, evidence type and
lineage (the observe roots it depends on), which makes every derived value
and finding traceable to the evidence that produced it.
"""
from __future__ import annotations

from ..ast import nodes as A
from ..canonical import digest, sha256_hex
from ..evidence.types import EvidenceType
from ..schema import load_schema
from ..semantic.checker import Analysis
from ..version import COMPILER_VERSION, IR_FORMAT


class IRBuilder:
    def __init__(self, analysis: Analysis, source: str):
        self.an = analysis
        self.source = source
        self.nodes: list[dict] = []
        self.by_id: dict[str, dict] = {}
        self.bindings: dict[str, str] = {}

    def new(self, op: str, inputs: list[str], **params) -> dict:
        node = {"id": f"n{len(self.nodes) + 1}", "op": op, "inputs": inputs, **params}
        self.nodes.append(node)
        self.by_id[node["id"]] = node
        return node

    @staticmethod
    def annotate(node: dict, etype: EvidenceType, lineage: list[str]) -> None:
        t = etype.to_json()
        t["lineage"] = lineage
        node["type"] = t["render"]
        node["evidence"] = t
        node["schema"] = dict(sorted(etype.schema.items()))

    def lineage_of(self, node_ids: list[str]) -> list[str]:
        out: list[str] = []
        for nid in node_ids:
            for root in self.by_id[nid]["evidence"]["lineage"]:
                if root not in out:
                    out.append(root)
        return out

    def lower_let(self, st: A.Let) -> None:
        src = st.pipeline.source
        types = self.an.stage_types[st.name]
        if isinstance(src, A.Observe):
            cur = self.new("observe", [], entity=src.entity)
            lineage = [cur["id"]]
            self.annotate(cur, types[0], lineage)
        elif isinstance(src, A.Ref):
            cur = self.by_id[self.bindings[src.name]]
            lineage = list(cur["evidence"]["lineage"])
        else:
            refs = [src.left, src.right] if isinstance(src, A.Join) else src.steps
            inputs = [self.bindings[r.name] for r in refs]
            cur = self.new(
                "join" if isinstance(src, A.Join) else "sequence",
                inputs,
                aliases=[r.name for r in refs],
                keys=[k.text for k in src.keys],
                within_seconds=src.within.seconds if src.within else None,
            )
            lineage = self.lineage_of(inputs)
            self.annotate(cur, types[0], lineage)
        for stage, t in zip(st.pipeline.stages, types[1:]):
            if isinstance(stage, A.Filter):
                cur = self.new("filter", [cur["id"]], predicate=self.an.predicates[id(stage)])
            elif isinstance(stage, A.Select):
                cur = self.new("select", [cur["id"]], fields=[f.text for f in stage.fields])
            elif isinstance(stage, A.Within):
                cur = self.new("within", [cur["id"]], seconds=stage.duration.seconds)
            self.annotate(cur, t, lineage)
        cur.setdefault("binding", st.name)
        self.bindings[st.name] = cur["id"]

    def build(self) -> dict:
        p = self.an.program
        for st in p.statements:
            if isinstance(st, A.Let):
                self.lower_let(st)
        outputs: dict[str, list[str]] = {"emit": [], "preserve": []}
        for st in p.statements:
            if isinstance(st, A.Preserve):
                src = self.by_id[self.bindings[st.target.name]]
                n = self.new("preserve", [src["id"]], binding=st.target.name, with_content=st.with_content)
                n["type"] = f"Preserved<{src['type']}>"
                n["evidence"] = {"kind": "Preserved", "render": n["type"],
                                 "lineage": src["evidence"]["lineage"]}
                n["schema"] = src["schema"]
                outputs["preserve"].append(n["id"])
            elif isinstance(st, A.Emit):
                src = self.by_id[self.bindings[st.target.name]]
                n = self.new("emit", [src["id"]], binding=st.target.name, severity=st.severity,
                             title=st.title or st.target.name)
                self.annotate(n, self.an.finding_types[st.target.name], src["evidence"]["lineage"])
                outputs["emit"].append(n["id"])
        ir = {
            "format": IR_FORMAT,
            "compiler": COMPILER_VERSION,
            "schema_version": load_schema().version,
            "source_sha256": sha256_hex(self.source.encode("utf-8")),
            "investigation": {
                "name": p.name,
                "title": p.title or p.name,
                "targets": p.targets,
                "window": self.an.window,
            },
            "nodes": self.nodes,
            "bindings": self.bindings,
            "outputs": outputs,
        }
        ir["ir_sha256"] = digest(ir)
        return ir


def build_ir(analysis: Analysis, source: str) -> dict:
    return IRBuilder(analysis, source).build()


def consumers(ir_nodes: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {n["id"]: [] for n in ir_nodes}
    for n in ir_nodes:
        for i in n["inputs"]:
            out[i].append(n["id"])
    return out
