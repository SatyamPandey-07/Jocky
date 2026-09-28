"""Forensic execution contracts: build, hash, sign (Ed25519), verify.

The signed bytes are exactly `canonical_json(contract)`; the transport sends
those bytes verbatim, so verifiers check the signature over what they
received and never need to re-encode before verifying.
"""
from __future__ import annotations

import base64
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..canonical import canonical_json, digest, parse_time, sha256_hex, shift_time, utc_now
from ..version import COMPILER_VERSION, CONTRACT_FORMAT

DEFAULT_LIMITS = {
    "max_records_per_stream": 500_000,
    "max_bytes": 256 * 1024 * 1024,
    "timeout_seconds": 300,
    "max_hash_bytes": 64 * 1024 * 1024,
    "max_content_bytes": 16 * 1024 * 1024,
}


# ---- keys ----------------------------------------------------------------------

def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    Path(path).write_bytes(pem)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_or_create_key(path: str | Path) -> Ed25519PrivateKey:
    p = Path(path)
    if p.exists():
        return load_private_key(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    key = generate_key()
    save_private_key(key, p)
    return key


def raw_public_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(key: Ed25519PrivateKey | Ed25519PublicKey | bytes) -> str:
    raw = key if isinstance(key, bytes) else raw_public_key(key)
    return sha256_hex(raw)[:16]


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(text))


# ---- contracts ------------------------------------------------------------------

def resolve_window(window: dict | None, issued_at: str) -> dict | None:
    if window is None:
        return None
    if "last_seconds" in window:
        return {"from": shift_time(issued_at, -int(window["last_seconds"])), "to": issued_at}
    return {"from": window["from"], "to": window["to"]}


def build_contract(
    *,
    plan: dict,
    ir: dict,
    targets: list[dict],
    signing_key: Ed25519PrivateKey,
    investigation_id: str,
    execution_id: str | None = None,
    limits: dict | None = None,
    issued_at: str | None = None,
    ttl_seconds: int = 3600,
    window: dict | None = None,
) -> dict:
    """Create and sign a contract.  Returns {"contract": body, "signature": {...}}."""
    issued = issued_at or utc_now()
    body = {
        "format": CONTRACT_FORMAT,
        "contract_id": f"ctr_{uuid.uuid4().hex}",
        "execution_id": execution_id or f"exe_{uuid.uuid4().hex}",
        "investigation": {
            "id": investigation_id,
            "name": ir["investigation"]["name"],
            "title": ir["investigation"]["title"],
        },
        "compiler_version": COMPILER_VERSION,
        "schema_version": ir["schema_version"],
        "source_sha256": ir["source_sha256"],
        "ir_sha256": ir["ir_sha256"],
        "mode": plan["mode"],
        "window": window if window is not None else resolve_window(ir["investigation"]["window"], issued),
        "targets": sorted(targets, key=lambda t: t["host"]),
        "required_capabilities": plan["capabilities"]["required"],
        "limits": {**DEFAULT_LIMITS, **(limits or {})},
        "plan": plan,
        "plan_hash": digest(plan),
        "issued_at": issued,
        "expires_at": shift_time(issued, ttl_seconds),
        "nonce": secrets.token_hex(16),
        "issuer": {
            "algorithm": "Ed25519",
            "key_id": key_id(signing_key),
            "public_key": base64.b64encode(raw_public_key(signing_key)).decode(),
        },
    }
    return sign(body, signing_key)


def sign(body: dict, key: Ed25519PrivateKey) -> dict:
    sig = key.sign(canonical_json(body))
    return {
        "contract": body,
        "signature": {"algorithm": "Ed25519", "key_id": key_id(key), "value": base64.b64encode(sig).decode()},
    }


def contract_hash(body: dict) -> str:
    return digest(body)


@dataclass
class Verification:
    ok: bool
    checks: list[dict] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "passed": passed, "detail": detail})
        if not passed:
            self.ok = False


def verify(envelope: dict, trusted_key: Ed25519PublicKey, now: str | None = None,
           host: str | None = None) -> Verification:
    body, sig = envelope["contract"], envelope["signature"]
    v = Verification(ok=True)
    v.add("format", body.get("format") == CONTRACT_FORMAT, body.get("format", ""))
    v.add("key_id", sig.get("key_id") == key_id(trusted_key), sig.get("key_id", ""))
    try:
        trusted_key.verify(base64.b64decode(sig["value"]), canonical_json(body))
        v.add("signature", True, "Ed25519 signature valid")
    except (InvalidSignature, ValueError, KeyError) as e:
        v.add("signature", False, f"invalid signature: {type(e).__name__}")
    recomputed = digest(body["plan"])
    v.add("plan_hash", recomputed == body.get("plan_hash"), recomputed)
    now_t = parse_time(now or utc_now())
    v.add("not_expired", now_t <= parse_time(body["expires_at"]), body["expires_at"])
    if host is not None:
        v.add("target", any(t["host"] == host for t in body["targets"]), host)
    return v
