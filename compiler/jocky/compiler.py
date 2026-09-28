"""Compiler driver: source -> AST -> semantic/evidence checks -> IR -> physical plans."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ast as A
from .ast import to_json
from .errors import CompileError, Diagnostic
from .ir import build_ir
from .parser import parse
from .planner import physical_plan
from .semantic import Analysis, check
from .version import COMPILER_VERSION


@dataclass
class Compilation:
    source: str
    program: A.Investigation
    analysis: Analysis
    ir: dict
    plans: dict[str, dict] = field(default_factory=dict)
    plan_errors: dict[str, str] = field(default_factory=dict)

    @property
    def warnings(self) -> list[Diagnostic]:
        return self.analysis.warnings

    def plan(self, mode: str) -> dict:
        if mode not in self.plans:
            raise CompileError([Diagnostic("error", "E0300", self.plan_errors.get(mode, f"no {mode} plan"))])
        return self.plans[mode]

    def artifacts(self) -> dict:
        """JSON artifacts for storage and the dashboard's compiler view."""
        return {
            "compiler": COMPILER_VERSION,
            "ast": to_json(self.program),
            "diagnostics": [d.to_json() for d in self.warnings],
            "types": {name: t.to_json() for name, t in self.analysis.bindings.items()},
            "ir": self.ir,
            "plans": self.plans,
            "plan_errors": self.plan_errors,
            "capabilities": {mode: p["capabilities"] for mode, p in self.plans.items()},
        }


def compile_source(source: str) -> Compilation:
    program = parse(source)
    analysis = check(program)
    ir = build_ir(analysis, source)
    comp = Compilation(source=source, program=program, analysis=analysis, ir=ir)
    for mode in ("optimized", "naive"):
        try:
            comp.plans[mode] = physical_plan(ir, mode)
        except ValueError as e:
            comp.plan_errors[mode] = str(e)
    if "optimized" not in comp.plans:
        raise CompileError([Diagnostic("error", "E0300", comp.plan_errors["optimized"])])
    return comp
