"""Capability inference (compiler layer C4).

A capability names an endpoint-side privilege: which entity may be
observed, which sensitive fields may be read, whether file content may be
acquired.  Capabilities are inferred from the *physical* plan — i.e. from
what the agent will actually read — so a naive plan (collect every field)
requires more privilege than the optimized plan for the same investigation.
"""
from __future__ import annotations

from ..optimizer.rules import predicate_fields
from ..schema import load_schema

PRESERVE_RECORDS = "preserve:records"
ACQUIRE_CONTENT = "acquire:file.content"


def stream_capabilities(stream: dict) -> set[str]:
    ent = load_schema().entities[stream["entity"]]
    caps = {ent.capability}
    if stream.get("fields") is None:
        read = set(ent.fields)
    else:
        read = set(stream["fields"]) | predicate_fields(stream.get("predicate"))
    for f in read:
        spec = ent.fields.get(f)
        if spec is not None and spec.capability:
            caps.add(spec.capability)
    if stream.get("acquire_content"):
        caps.add(ACQUIRE_CONTENT)
    return caps


def plan_capabilities(streams: list[dict], central: list[dict]) -> dict:
    by_stream = {s["id"]: sorted(stream_capabilities(s)) for s in streams}
    required: set[str] = set()
    for caps in by_stream.values():
        required.update(caps)
    if any(c["op"] == "preserve" for c in central):
        required.add(PRESERVE_RECORDS)
    return {"required": sorted(required), "by_stream": by_stream}


def capability_catalog() -> list[dict]:
    """Every capability the MVP knows about, with a description."""
    schema = load_schema()
    out = []
    for name, ent in schema.entities.items():
        out.append({"capability": ent.capability, "doc": f"observe {name} evidence"})
        for f in ent.fields.values():
            if f.capability:
                out.append({"capability": f.capability, "doc": f"read {name}.{f.name} ({f.doc})"})
    out.append({"capability": PRESERVE_RECORDS, "doc": "seal evidence records into the preservation store"})
    out.append({"capability": ACQUIRE_CONTENT, "doc": "read and upload file content from the endpoint"})
    return out
