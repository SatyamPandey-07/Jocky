"""Database layer for JOCKY Control Plane.

Stores investigations, contracts, agents, executions, evidence records, findings,
and audit logs. Uses SQLite for zero-config persistence (or PostgreSQL via DATABASE_URL).
"""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path("control-plane/jocky.db")


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_code TEXT NOT NULL,
                    status TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS contracts (
                    contract_id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    plan_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os TEXT NOT NULL,
                    status TEXT NOT NULL,
                    capabilities TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS executions (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    contract_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    records_collected INTEGER DEFAULT 0,
                    bytes_transferred INTEGER DEFAULT 0,
                    duration_ms REAL DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    finding_digest TEXT,
                    started_at TEXT,
                    finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    investigation_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    finding_digest TEXT NOT NULL,
                    chain_summary TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

    # --- Investigations ---
    def save_investigation(self, id: str, name: str, title: str, source_code: str, status: str = "draft", targets: List[str] = None):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO investigations (id, name, title, source_code, status, targets, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    title=excluded.title,
                    source_code=excluded.source_code,
                    status=excluded.status,
                    targets=excluded.targets,
                    updated_at=excluded.updated_at
                """,
                (id, name, title, source_code, status, json.dumps(targets or []), utc_now(), utc_now()),
            )

    def get_investigation(self, id: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as conn:
            row = conn.execute("SELECT * FROM investigations WHERE id = ?", (id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            res["targets"] = json.loads(res["targets"])
            return res

    def list_investigations(self) -> List[Dict[str, Any]]:
        with self.get_conn() as conn:
            rows = conn.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["targets"] = json.loads(item["targets"])
                results.append(item)
            return results

    # --- Contracts ---
    def save_contract(self, contract_id: str, investigation_id: str, plan_hash: str, signature: str, contract_json: dict):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO contracts (contract_id, investigation_id, plan_hash, signature, contract_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (contract_id, investigation_id, plan_hash, signature, json.dumps(contract_json), utc_now()),
            )

    def get_contract(self, contract_id: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as conn:
            row = conn.execute("SELECT * FROM contracts WHERE contract_id = ?", (contract_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            res["contract_json"] = json.loads(res["contract_json"])
            return res

    # --- Agents ---
    def register_agent(self, agent_id: str, hostname: str, os_name: str, capabilities: List[str], status: str = "online"):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO agents (agent_id, hostname, os, status, capabilities, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    os=excluded.os,
                    status=excluded.status,
                    capabilities=excluded.capabilities,
                    last_seen=excluded.last_seen
                """,
                (agent_id, hostname, os_name, status, json.dumps(capabilities), utc_now()),
            )

    def list_agents(self) -> List[Dict[str, Any]]:
        with self.get_conn() as conn:
            rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["capabilities"] = json.loads(item["capabilities"])
                results.append(item)
            return results

    # --- Executions ---
    def create_execution(self, exec_id: str, investigation_id: str, contract_id: str, mode: str = "optimized") -> Dict[str, Any]:
        now = utc_now()
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO executions (id, investigation_id, contract_id, status, mode, started_at)
                VALUES (?, ?, ?, 'running', ?, ?)
                """,
                (exec_id, investigation_id, contract_id, mode, now),
            )
        return {"id": exec_id, "investigation_id": investigation_id, "contract_id": contract_id, "status": "running", "mode": mode, "started_at": now}

    def update_execution(self, exec_id: str, status: str, records: int, bytes_count: int, duration_ms: float, findings_count: int, finding_digest: str):
        now = utc_now()
        with self.get_conn() as conn:
            conn.execute(
                """
                UPDATE executions SET
                    status=?, records_collected=?, bytes_transferred=?, duration_ms=?,
                    findings_count=?, finding_digest=?, finished_at=?
                WHERE id=?
                """,
                (status, records, bytes_count, duration_ms, findings_count, finding_digest, now, exec_id),
            )

    def get_execution(self, exec_id: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as conn:
            row = conn.execute("SELECT * FROM executions WHERE id = ?", (exec_id,)).fetchone()
            return dict(row) if row else None

    def list_executions(self) -> List[Dict[str, Any]]:
        with self.get_conn() as conn:
            rows = conn.execute("SELECT * FROM executions ORDER BY started_at DESC").fetchall()
            return [dict(r) for r in rows]

    # --- Evidence Records ---
    def save_evidence_batch(self, exec_id: str, records: List[Dict[str, Any]]):
        with self.get_conn() as conn:
            data = [
                (
                    r.get("evidence_id"),
                    exec_id,
                    r.get("entity"),
                    r.get("host"),
                    r.get("time"),
                    r.get("observed_at", utc_now()),
                    r.get("collector", "unknown"),
                    r.get("sha256", ""),
                    json.dumps(r.get("fields", {})),
                )
                for r in records
            ]
            conn.executemany(
                """
                INSERT OR IGNORE INTO evidence_records (evidence_id, execution_id, entity, host, event_time, observed_at, collector, sha256, payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                data,
            )

    def query_evidence(self, execution_id: Optional[str] = None, entity: Optional[str] = None, host: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_conn() as conn:
            query = "SELECT * FROM evidence_records WHERE 1=1"
            params = []
            if execution_id:
                query += " AND execution_id = ?"
                params.append(execution_id)
            if entity:
                query += " AND entity = ?"
                params.append(entity)
            if host:
                query += " AND host = ?"
                params.append(host)
            query += " ORDER BY event_time ASC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["fields"] = json.loads(item["payload"])
                results.append(item)
            return results

    # --- Findings ---
    def save_finding(self, finding_id: str, exec_id: str, investigation_id: str, title: str, severity: str, host: str, finding_digest: str, chain_summary: dict, provenance: dict):
        with self.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (id, execution_id, investigation_id, title, severity, host, finding_digest, chain_summary, provenance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (finding_id, exec_id, investigation_id, title, severity, host, finding_digest, json.dumps(chain_summary), json.dumps(provenance), utc_now()),
            )

    def list_findings(self, execution_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_conn() as conn:
            if execution_id:
                rows = conn.execute("SELECT * FROM findings WHERE execution_id = ? ORDER BY created_at DESC", (execution_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["chain_summary"] = json.loads(item["chain_summary"])
                item["provenance"] = json.loads(item["provenance"])
                results.append(item)
            return results

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self.get_conn() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            res["chain_summary"] = json.loads(res["chain_summary"])
            res["provenance"] = json.loads(res["provenance"])
            return res


db = Database()
