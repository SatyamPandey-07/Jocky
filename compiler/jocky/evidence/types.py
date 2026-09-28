"""Evidence-aware type system: Evidence<T>, Derived<T>, Finding<T>.

* `observe E`                      : Evidence<E>
* filter / select / within on Evidence<E> : Evidence<E>   (records stay original
  observations; projection never fabricates values)
* join a, b                        : Derived<Join<A, B>>
* sequence a -> b -> c             : Derived<Sequence<A, B, C>>
* filter / select on Derived<T>    : Derived<T>
* emit finding x                   : Finding<T> where x : Evidence<T> | Derived<T>
* preserve x                       : seals the evidence lineage of x

Every type carries its *lineage*: the set of observe roots it was computed
from.  Lineage is what lets a finding be traced back to raw evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Component:
    alias: str  # binding name of the component inside a derived tuple
    entity: str


@dataclass
class EvidenceType:
    kind: str  # "Evidence" | "Derived" | "Finding"
    entity: str | None = None  # for Evidence
    shape: str | None = None  # "Join" | "Sequence" for Derived/Finding over derived
    components: list[Component] = field(default_factory=list)
    # field name -> type.  For Derived the names are qualified ("alias.field").
    schema: dict[str, str] = field(default_factory=dict)
    lineage: list[str] = field(default_factory=list)  # IR ids of observe roots

    def render(self) -> str:
        if self.kind == "Evidence":
            return f"Evidence<{self.entity}>"
        inner = (
            f"{self.shape}<{', '.join(c.entity for c in self.components)}>"
            if self.shape
            else f"{self.entity}"
        )
        return f"{self.kind}<{inner}>"

    @property
    def is_evidence(self) -> bool:
        return self.kind == "Evidence"

    @property
    def is_derived(self) -> bool:
        return self.kind == "Derived"

    def as_finding(self) -> "EvidenceType":
        return EvidenceType(
            kind="Finding",
            entity=self.entity,
            shape=self.shape,
            components=list(self.components),
            schema=dict(self.schema),
            lineage=list(self.lineage),
        )

    def to_json(self) -> dict:
        out: dict = {"kind": self.kind, "render": self.render(), "lineage": self.lineage}
        if self.entity:
            out["entity"] = self.entity
        if self.shape:
            out["shape"] = self.shape
            out["components"] = [{"alias": c.alias, "entity": c.entity} for c in self.components]
        return out


def evidence(entity: str, schema: dict[str, str], root: str) -> EvidenceType:
    return EvidenceType(kind="Evidence", entity=entity, schema=dict(schema), lineage=[root])


def derived(shape: str, inputs: list[tuple[str, EvidenceType]]) -> EvidenceType:
    schema: dict[str, str] = {}
    comps: list[Component] = []
    lineage: list[str] = []
    for alias, t in inputs:
        comps.append(Component(alias, t.entity or "?"))
        for fname, ftype in t.schema.items():
            schema[f"{alias}.{fname}"] = ftype
        for root in t.lineage:
            if root not in lineage:
                lineage.append(root)
    return EvidenceType(kind="Derived", shape=shape, components=comps, schema=schema, lineage=lineage)
