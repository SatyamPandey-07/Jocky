"""JOCKY Cross-Platform Endpoint Agent.

Implements §VI of the JOCKY research specification:
- Cryptographic contract verification (Ed25519 signature + SHA-256 plan hash).
- Capability policy enforcement (ALLOW / REJECT before execution).
- Local predicate & projection pushdown evaluation.
- Canonical 5-entity evidence normalization (schemas/entities.json).
- SHA-256 envelope hashing and provenance attribution.
- Supports Windows (live Win32/psutil), Linux (/proc), and Offline forensic datasets.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil

# Import compiler utilities
from compiler.jocky.capabilities.policy import evaluate as evaluate_policy, load_policy
from compiler.jocky.contract.contract import public_key_from_b64, verify, Verification
from compiler.jocky.runtime.predicate import evaluate as eval_pred

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("jocky-agent")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def calculate_sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class ContractVerificationError(Exception):
    """Raised when a contract fails cryptographic or capability checks."""
    pass


class EndpointAgent:
    def __init__(
        self,
        agent_id: str,
        hostname: Optional[str] = None,
        policy_path: str | Path = "policies/default_policy.json",
        dataset_dir: Optional[str | Path] = None,
    ):
        self.agent_id = agent_id
        self.hostname = hostname or socket.gethostname().upper()
        self.os_type = platform.system().lower()
        self.policy_path = Path(policy_path)
        self.dataset_dir = Path(dataset_dir) if dataset_dir else None
        self.policy = load_policy(self.policy_path) if self.policy_path.exists() else {
            "name": "default", "default": {"allow": ["collect:*", "preserve:records"], "deny": []}
        }
        self.running = False
        logger.info(f"Initialized JOCKY Agent: id={self.agent_id}, host={self.hostname}, OS={self.os_type}")

    def verify_contract(self, contract_envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Verify Ed25519 signature and plan hash of the incoming contract."""
        body = contract_envelope.get("contract")
        sig_info = contract_envelope.get("signature")

        if not body or not sig_info:
            raise ContractVerificationError("Invalid contract envelope: missing body or signature.")

        # 1. Verify Ed25519 signature & hash via canonical verifier
        pubkey_b64 = body.get("issuer", {}).get("public_key")
        if not pubkey_b64:
            raise ContractVerificationError("Contract missing issuer public_key.")

        pubkey = public_key_from_b64(pubkey_b64)
        v = verify(contract_envelope, pubkey)
        if not v.ok:
            failed_checks = [c["check"] for c in v.checks if not c["passed"]]
            raise ContractVerificationError(f"Contract verification failed: {failed_checks}")

        # 2. Check Capabilities against Local Policy
        required_caps = body.get("required_capabilities", [])
        decision = evaluate_policy(self.policy, self.hostname, required_caps)
        if not decision.allowed:
            raise ContractVerificationError(
                f"Contract requires unauthorized capabilities on {self.hostname}: {decision.denied}. Reasons: {decision.reasons}"
            )

        logger.info(f"Contract '{body.get('investigation_id')}' verified successfully (signature valid, capabilities granted).")
        return body

    def collect_live_processes(self, filter_fn: Callable, projection: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Live Process collector on Windows / Linux via psutil."""
        results = []
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            try:
                info = p.info
                name = info.get("name") or ""
                create_dt = datetime.datetime.fromtimestamp(info.get("create_time", time.time()), tz=datetime.timezone.utc)
                record = {
                    "host": self.hostname,
                    "time": create_dt.isoformat(),
                    "pid": info.get("pid") or 0,
                    "ppid": info.get("ppid") or 0,
                    "name": name,
                    "path": info.get("exe") or "",
                    "cmdline": " ".join(info.get("cmdline") or []) if info.get("cmdline") else "",
                    "user": info.get("username") or "",
                }
                if filter_fn(record):
                    if projection:
                        record = {k: v for k, v in record.items() if k in projection or k in ("host", "time", "pid")}
                    results.append(record)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return results

    def collect_live_network(self, filter_fn: Callable, projection: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Live Network connection collector via psutil."""
        results = []
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.warning(f"Could not read live network connections: {e}")
            return []

        now_str = utc_now()
        for conn in connections:
            try:
                laddr = conn.laddr
                raddr = conn.raddr
                direction = "outbound" if raddr else ("listen" if conn.status == "LISTEN" else "inbound")
                record = {
                    "host": self.hostname,
                    "time": now_str,
                    "pid": conn.pid or 0,
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "direction": direction,
                    "state": conn.status.lower() if conn.status else "unknown",
                    "local_ip": laddr.ip if laddr else "0.0.0.0",
                    "local_port": laddr.port if laddr else 0,
                    "remote_ip": raddr.ip if raddr else "0.0.0.0",
                    "remote_port": raddr.port if raddr else 0,
                }
                if filter_fn(record):
                    if projection:
                        record = {k: v for k, v in record.items() if k in projection or k in ("host", "time", "pid")}
                    results.append(record)
            except Exception:
                continue
        return results

    def collect_offline(self, entity: str, filter_fn: Callable, projection: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Collect from offline forensic dataset directory using OfflineSource."""
        if not self.dataset_dir or not self.dataset_dir.exists():
            return []

        try:
            from compiler.jocky.runtime.offline import OfflineSource
            src = OfflineSource(self.dataset_dir)
            stats = {"scanned": 0}
            raw_records = src.collect(entity, stats)
            
            results = []
            for r in raw_records:
                # r is a normalized evidence record with "host", "time", "fields"
                rec_dict = {**r["fields"], "host": r["host"], "time": r["time"]}
                if filter_fn(rec_dict):
                    results.append(r)
            return results
        except Exception as e:
            logger.error(f"Error during offline collection for {entity}: {e}")
            return []

    def build_envelope(self, entity: str, record: Dict[str, Any], contract_body: Dict[str, Any]) -> Dict[str, Any]:
        """Wrap record into canonical 5-entity envelope with SHA-256."""
        ev_id = f"ev_{calculate_sha256(json.dumps(record, sort_keys=True))[:16]}"
        now = utc_now()
        payload = {k: v for k, v in record.items() if k not in ("host", "time")}
        env = {
            "evidence_id": ev_id,
            "entity": entity,
            "host": record.get("host", self.hostname),
            "time": record.get("time", now),
            "time_source": "agent_collector",
            "observed_at": now,
            "collector": f"jocky-agent-{self.os_type}",
            "collector_version": "0.1.0",
            "source": f"{self.os_type}:{entity.lower()}",
            "execution_id": contract_body.get("execution_id", "local"),
            "contract_hash": contract_body.get("plan_hash", ""),
            "fields": payload,
        }
        # Compute integrity hash of the envelope content
        content_bytes = json.dumps(env, sort_keys=True, separators=(",", ":")).encode("utf-8")
        env["sha256"] = calculate_sha256(content_bytes)
        return env

    def execute_contract(self, contract_envelope: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Execute physical plan streams on this endpoint."""
        body = self.verify_contract(contract_envelope)
        plan = body.get("plan", {})
        streams = plan.get("streams", [])

        collected_streams: Dict[str, List[Dict[str, Any]]] = {}

        def make_filter(pred):
            if not pred:
                return lambda rec: True
            return lambda rec: eval_pred(pred, lambda k: rec.get(k))

        for spec in streams:
            stream_id = spec.get("id")
            entity = spec.get("entity")
            filt = spec.get("predicate")
            proj = spec.get("fields")

            filter_fn = make_filter(filt)
            logger.info(f"Executing stream {stream_id} for entity '{entity}' with pushdown filter...")

            # Collect telemetry based on configuration
            if self.dataset_dir and self.dataset_dir.exists():
                records = self.collect_offline(entity, filter_fn, proj)
            else:
                if entity == "Process":
                    records = self.collect_live_processes(filter_fn, proj)
                elif entity == "NetworkConnection":
                    records = self.collect_live_network(filter_fn, proj)
                else:
                    records = []

            # Envelope each record if not already enveloped
            enveloped_records = [
                r if "evidence_id" in r else self.build_envelope(entity, r, body)
                for r in records
            ]
            collected_streams[stream_id] = enveloped_records
            logger.info(f"Stream {stream_id} collected {len(enveloped_records)} records.")

        return collected_streams


def main():
    parser = argparse.ArgumentParser(description="JOCKY Cross-Platform Endpoint Agent")
    parser.add_argument("--id", default="WIN-01", help="Agent identifier")
    parser.add_argument("--host", default=None, help="Host name override")
    parser.add_argument("--policy", default="policies/default_policy.json", help="Path to policy JSON")
    parser.add_argument("--dataset", default=None, help="Optional offline dataset directory")
    parser.add_argument("--contract", default=None, help="Path to contract JSON file to execute")
    parser.add_argument("--out", default=None, help="Output directory for collected evidence")
    args = parser.parse_args()

    agent = EndpointAgent(
        agent_id=args.id,
        hostname=args.host,
        policy_path=args.policy,
        dataset_dir=args.dataset,
    )

    if args.contract:
        contract_data = json.loads(Path(args.contract).read_text(encoding="utf-8"))
        results = agent.execute_contract(contract_data)
        total_records = sum(len(recs) for recs in results.values())
        print(f"Execution complete: {len(results)} streams, {total_records} records collected.")
        if args.out:
            out_p = Path(args.out)
            out_p.mkdir(parents=True, exist_ok=True)
            for sid, recs in results.items():
                (out_p / f"{sid}.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
            print(f"Evidence saved to {args.out}")


if __name__ == "__main__":
    main()
