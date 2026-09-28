"""Predicate evaluation (reference semantics; mirrored by agent/src/core/predicate.rs).

* A comparison against a null/missing field is false — except `== null`
  (true when missing) and `!= null` (true when present).
* Equality is type-strict (no int/str/bool coercion).
* contains / startswith / endswith / like are ASCII case-insensitive;
  `like` is a glob with `*` (any run) and `?` (one character).
* `cidr` parses the field as an IP address; unparsable values never match.
* Time values are canonical fixed-width UTC strings, so ordering operators
  compare them lexicographically.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any, Callable

from ..canonical import ascii_lower

Getter = Callable[[str], Any]


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_int(a) and _is_int(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def glob_match(pattern: str, text: str) -> bool:
    """Iterative wildcard match; `*` = any run, `?` = exactly one character."""
    p, t = 0, 0
    star, mark = -1, 0
    while t < len(text):
        if p < len(pattern) and (pattern[p] == "?" or pattern[p] == text[t]):
            p += 1
            t += 1
        elif p < len(pattern) and pattern[p] == "*":
            star, mark = p, t
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


@lru_cache(maxsize=256)
def _network(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def _in_cidr(value: Any, cidr: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    net = _network(cidr)
    if addr.version != net.version:
        return False
    return addr in net


def evaluate(pred: dict | None, get: Getter) -> bool:
    if pred is None:
        return True
    op = pred["op"]
    if op == "and":
        return all(evaluate(a, get) for a in pred["args"])
    if op == "or":
        return any(evaluate(a, get) for a in pred["args"])
    if op == "not":
        return not evaluate(pred["arg"], get)
    cmp, value = pred["cmp"], pred["value"]
    v = get(pred["field"])
    if cmp in ("==", "!="):
        if value is None:
            return (v is None) if cmp == "==" else (v is not None)
        if v is None:
            return False
        eq = _eq(v, value)
        return eq if cmp == "==" else not eq
    if v is None:
        return False
    if cmp in ("<", "<=", ">", ">="):
        if not ((_is_int(v) and _is_int(value)) or (isinstance(v, str) and isinstance(value, str))):
            return False
        if cmp == "<":
            return v < value
        if cmp == "<=":
            return v <= value
        if cmp == ">":
            return v > value
        return v >= value
    if cmp == "in":
        return any(_eq(v, x) for x in value)
    if cmp == "cidr":
        return _in_cidr(v, value)
    if not isinstance(v, str):
        return False
    lv, lp = ascii_lower(v), ascii_lower(value)
    if cmp == "contains":
        return lp in lv
    if cmp == "startswith":
        return lv.startswith(lp)
    if cmp == "endswith":
        return lv.endswith(lp)
    if cmp == "like":
        return glob_match(lp, lv)
    raise ValueError(f"unknown comparison {cmp!r}")


def record_getter(record: dict) -> Getter:
    """Field access on a normalized evidence record (host/time live in the envelope)."""
    fields = record["fields"]

    def get(name: str) -> Any:
        if name == "host" or name == "time":
            return record[name]
        return fields.get(name)

    return get
