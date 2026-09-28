"""JOCKY abstract syntax tree.

The eight MVP primitives appear as: `observe` (Observe), `filter` (Filter),
`select` (Select), `join` (Join), `within` (Within stage and the `within`
clause of Join/Sequence), `sequence` (Sequence), `preserve` (Preserve) and
`emit` (Emit).
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Union

from ..errors import Span


@dataclass
class Duration:
    text: str
    seconds: int
    span: Span


@dataclass
class FieldRef:
    parts: list[str]
    span: Span

    @property
    def text(self) -> str:
        return ".".join(self.parts)


@dataclass
class Literal:
    value: Any  # str | int | bool | None
    kind: str  # "str" | "int" | "bool" | "null"
    span: Span


# ---- expressions -----------------------------------------------------------

@dataclass
class BoolOp:
    op: str  # "and" | "or"
    args: list["Expr"]
    span: Span


@dataclass
class Not:
    arg: "Expr"
    span: Span


@dataclass
class Compare:
    field: FieldRef
    op: str  # == != < <= > >= contains startswith endswith like
    value: Literal
    span: Span


@dataclass
class InList:
    field: FieldRef
    values: list[Literal]
    span: Span


@dataclass
class InCidr:
    field: FieldRef
    cidr: Literal
    span: Span


Expr = Union[BoolOp, Not, Compare, InList, InCidr]


# ---- pipeline sources and stages --------------------------------------------

@dataclass
class Observe:
    entity: str
    span: Span


@dataclass
class Ref:
    name: str
    span: Span


@dataclass
class Join:
    left: Ref
    right: Ref
    keys: list[FieldRef]
    within: Duration | None
    span: Span


@dataclass
class Sequence:
    steps: list[Ref]
    keys: list[FieldRef]
    within: Duration
    span: Span


Source = Union[Observe, Ref, Join, Sequence]


@dataclass
class Filter:
    expr: Expr
    span: Span


@dataclass
class Select:
    fields: list[FieldRef]
    span: Span


@dataclass
class Within:
    duration: Duration
    span: Span


Stage = Union[Filter, Select, Within]


@dataclass
class Pipeline:
    source: Source
    stages: list[Stage]
    span: Span


# ---- statements --------------------------------------------------------------

@dataclass
class Let:
    name: str
    pipeline: Pipeline
    span: Span
    name_span: Span


@dataclass
class Preserve:
    target: Ref
    with_content: bool
    span: Span


@dataclass
class Emit:
    target: Ref
    severity: str
    title: str | None
    span: Span


Statement = Union[Let, Preserve, Emit]


@dataclass
class Window:
    kind: str  # "last" | "range"
    last: Duration | None
    start: str | None
    end: str | None
    span: Span


@dataclass
class Investigation:
    name: str
    title: str | None
    targets: list[str] | None
    window: Window | None
    statements: list[Statement] = field(default_factory=list)
    span: Span | None = None


def to_json(node: Any) -> Any:
    """Serialize an AST (dataclasses) into plain JSON with a `node` tag."""
    if is_dataclass(node):
        out: dict[str, Any] = {"node": type(node).__name__}
        for f in fields(node):
            value = getattr(node, f.name)
            if f.name == "span" or f.name == "name_span":
                out[f.name] = value.to_json() if value else None
            else:
                out[f.name] = to_json(value)
        return out
    if isinstance(node, list):
        return [to_json(v) for v in node]
    return node
