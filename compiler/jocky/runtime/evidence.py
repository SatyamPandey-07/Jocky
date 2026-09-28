"""Evidence normalization: raw values -> typed, identified, hashed evidence records."""
from __future__ import annotations

import re
from typing import Any

from ..canonical import canonical_ip, canonical_json, canonical_time, digest, sha256_hex, time_from_epoch
from ..schema import ENVELOPE_FIELDS, EntitySpec, load_schema

_INT_RE = re.compile(r"^-?\d+$")


class NormalizeError(ValueError):
    pass


def coerce(value: Any, ftype: str, time_format: str = "iso") -> Any:
    """Coerce a raw value to a schema type.  Returns None for null/empty; raises on bad input."""
    if value is None or value == "":
        return None
    if ftype == "int":
        if isinstance(value, bool):
            raise NormalizeError(f"bool is not int: {value!r}")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and _INT_RE.match(value.strip()):
            return int(value.strip())
        raise NormalizeError(f"not an int: {value!r}")
    if ftype == "str":
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            return value
        raise NormalizeError(f"not a string: {value!r}")
    if ftype == "time":
        if time_format in ("epoch_s", "epoch_ms"):
            if isinstance(value, bool):
                raise NormalizeError(f"not an epoch: {value!r}")
            if isinstance(value, int):
                return time_from_epoch(value, "ms" if time_format == "epoch_ms" else "s")
            if isinstance(value, str) and _INT_RE.match(value.strip()):
                return time_from_epoch(int(value.strip()), "ms" if time_format == "epoch_ms" else "s")
            raise NormalizeError(f"not an epoch: {value!r}")
        if isinstance(value, str):
            try:
                return canonical_time(value)
            except ValueError as e:
                raise NormalizeError(str(e)) from None
        raise NormalizeError(f"not a timestamp: {value!r}")
    if ftype == "ip":
        if not isinstance(value, str):
            raise NormalizeError(f"not an ip: {value!r}")
        ip = canonical_ip(value)
        if ip is None:
            raise NormalizeError(f"not an ip: {value!r}")
        return ip
    if ftype == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.lower() in ("true", "false"):
            return value.lower() == "true"
        raise NormalizeError(f"not a bool: {value!r}")
    raise NormalizeError(f"unknown type {ftype}")


def evidence_id(entity: EntitySpec, host: str, time: str, fields: dict) -> str:
    key = []
    for k in entity.natural_key:
        key.append(host if k == "host" else time if k == "time" else fields.get(k))
    return "ev_" + digest({"entity": entity.name, "key": key})[:32]


def make_record(
    *,
    entity: str,
    host: str,
    time: str,
    fields: dict,
    time_source: str,
    observed_at: str,
    collector: str,
    collector_version: str,
    source: str,
) -> dict:
    """Build an (unprojected, unhashed) evidence record with every payload field present."""
    spec = load_schema().entities[entity]
    payload = {f: fields.get(f) for f in spec.payload_fields}
    return {
        "evidence_id": evidence_id(spec, host, time, payload),
        "entity": entity,
        "host": host,
        "time": time,
        "time_source": time_source,
        "observed_at": observed_at,
        "collector": collector,
        "collector_version": collector_version,
        "source": source,
        "fields": payload,
    }


def seal(record: dict, execution_id: str, contract_hash: str) -> dict:
    """Stamp execution references and compute the integrity hash."""
    out = dict(record)
    out["execution_id"] = execution_id
    out["contract_hash"] = contract_hash
    out.pop("sha256", None)
    out["sha256"] = sha256_hex(canonical_json(out))
    return out


def verify_record(record: dict) -> bool:
    body = {k: v for k, v in record.items() if k != "sha256"}
    return sha256_hex(canonical_json(body)) == record.get("sha256")


__all__ = ["coerce", "evidence_id", "make_record", "seal", "verify_record", "NormalizeError", "ENVELOPE_FIELDS"]
