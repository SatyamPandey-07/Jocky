"""Diagnostics with source spans and caret rendering."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Span:
    line: int
    col: int
    end_line: int
    end_col: int

    def to_json(self) -> dict:
        return {"line": self.line, "col": self.col, "end_line": self.end_line, "end_col": self.end_col}

    @staticmethod
    def join(a: "Span", b: "Span") -> "Span":
        return Span(a.line, a.col, b.end_line, b.end_col)


@dataclass
class Diagnostic:
    severity: str  # "error" | "warning"
    code: str
    message: str
    span: Span | None = None
    hint: str | None = None

    def to_json(self) -> dict:
        out = {"severity": self.severity, "code": self.code, "message": self.message}
        if self.span:
            out["span"] = self.span.to_json()
        if self.hint:
            out["hint"] = self.hint
        return out

    def render(self, source: str | None = None, filename: str = "<source>") -> str:
        loc = f"{filename}:{self.span.line}:{self.span.col}" if self.span else filename
        text = f"{loc}: {self.severity}[{self.code}]: {self.message}"
        if source is not None and self.span is not None:
            lines = source.splitlines()
            if 0 < self.span.line <= len(lines):
                src_line = lines[self.span.line - 1]
                width = (
                    self.span.end_col - self.span.col
                    if self.span.end_line == self.span.line and self.span.end_col > self.span.col
                    else 1
                )
                gutter = f"{self.span.line:>4} | "
                text += f"\n{gutter}{src_line}\n{' ' * (len(gutter) + self.span.col - 1)}{'^' * width}"
        if self.hint:
            text += f"\n     = hint: {self.hint}"
        return text


@dataclass
class CompileError(Exception):
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def __str__(self) -> str:
        return "; ".join(d.message for d in self.diagnostics)

    def render(self, source: str | None = None, filename: str = "<source>") -> str:
        return "\n\n".join(d.render(source, filename) for d in self.diagnostics)
