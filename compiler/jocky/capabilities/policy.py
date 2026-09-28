"""Capability policy evaluation: required capabilities -> ALLOW / REJECT.

Policy document::

    {
      "name": "default",
      "version": 1,
      "default": {"allow": ["collect:*", "preserve:records"], "deny": []},
      "targets": {"UBUNTU-01": {"deny": ["collect:process.cmdline"]}}
    }

Patterns ending in `*` match by prefix.  Capabilities in the FORBIDDEN
families can never be granted: JOCKY is a read-only forensic platform
(no execution, modification, injection or process control on endpoints).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

FORBIDDEN_FAMILIES = ("exec:", "write:", "delete:", "modify:", "inject:", "kill:", "network.block:")


def _match(pattern: str, cap: str) -> bool:
    if pattern.endswith("*"):
        return cap.startswith(pattern[:-1])
    return pattern == cap


@dataclass
class Decision:
    target: str
    decision: str  # "ALLOW" | "REJECT"
    required: list[str]
    denied: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_json(self) -> dict:
        return {"target": self.target, "decision": self.decision, "required": self.required,
                "denied": self.denied, "reasons": self.reasons}


def load_policy(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evaluate(policy: dict, target: str, required: list[str]) -> Decision:
    default = policy.get("default", {})
    override = policy.get("targets", {}).get(target, {})
    allow = override.get("allow", default.get("allow", []))
    deny = list(default.get("deny", [])) + list(override.get("deny", []))
    denied, reasons = [], []
    for cap in required:
        if cap.startswith(FORBIDDEN_FAMILIES):
            denied.append(cap)
            reasons.append(f"{cap}: forbidden by design (JOCKY endpoints are read-only)")
        elif any(_match(p, cap) for p in deny):
            denied.append(cap)
            reasons.append(f"{cap}: denied for {target} by policy '{policy.get('name', '?')}'")
        elif not any(_match(p, cap) for p in allow):
            denied.append(cap)
            reasons.append(f"{cap}: not granted to {target} by policy '{policy.get('name', '?')}'")
    return Decision(target, "REJECT" if denied else "ALLOW", sorted(required), denied, reasons)


def evaluate_all(policy: dict, targets: list[str], required: list[str]) -> list[Decision]:
    return [evaluate(policy, t, required) for t in targets]
