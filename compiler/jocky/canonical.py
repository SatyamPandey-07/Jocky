"""Canonical encodings shared by the compiler, runtime, control plane and agent.

Everything that is hashed or signed in JOCKY goes through `canonical_json`.
The Rust agent implements the byte-identical encoding (sorted keys, no
insignificant whitespace, UTF-8, no ASCII escaping); `tests/agent` checks
parity between the two implementations.

Times are always UTC, rendered with a fixed width
(``YYYY-MM-DDTHH:MM:SS.ffffffZ``) so that lexicographic order equals
chronological order.  The evaluators rely on that property.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|z|[+-]\d{2}:?\d{2})?$"
)


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding used for hashing and signing."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """SHA-256 of the canonical JSON encoding of `value`."""
    return sha256_hex(canonical_json(value))


def format_time(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(TIME_FORMAT)


def parse_time(text: str) -> datetime:
    """Parse an ISO-8601 / RFC 3339 timestamp.  Naive timestamps are UTC.

    Fractions beyond microseconds are truncated (not rounded) — the Rust
    agent does the same.
    """
    m = _ISO_RE.match(text.strip())
    if not m:
        raise ValueError(f"not an ISO-8601 timestamp: {text!r}")
    y, mo, d, h, mi, s, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=timezone.utc)
    if tz and tz not in ("Z", "z"):
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
        dt = dt - sign * offset
    return dt


def canonical_time(text: str) -> str:
    return format_time(parse_time(text))


def time_from_epoch(value: int, unit: str = "s") -> str:
    if unit == "ms":
        seconds, millis = divmod(int(value), 1000)
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc) + timedelta(milliseconds=millis)
    else:
        dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
    return format_time(dt)


def shift_time(text: str, seconds: int) -> str:
    return format_time(parse_time(text) + timedelta(seconds=seconds))


def utc_now() -> str:
    return format_time(datetime.now(timezone.utc))


def canonical_ip(text: str) -> str | None:
    """Canonical textual IP (RFC 5952 for v6; IPv4-mapped v6 collapses to v4)."""
    try:
        addr = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def ascii_lower(text: str) -> str:
    """Case folding restricted to ASCII so Python and Rust agree exactly."""
    return text.translate(_ASCII_LOWER)


_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}
