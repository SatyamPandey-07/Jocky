"""API routes for JOCKY Control Plane."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from .database import db
    from .services import service
except ImportError:
    from database import db
    from services import service

router = APIRouter(prefix="/api")


# --- Request & Response Schemas ---
class CompileRequest(BaseModel):
    source: str = Field(..., description="JOCKY investigation source code")


class RunRequest(BaseModel):
    source: str = Field(..., description="JOCKY investigation source code")
    dataset: str = Field("datasets/synthetic", description="Path to dataset directory")
    mode: str = Field("optimized", description="optimized or naive")
    targets: Optional[List[str]] = Field(None, description="Target host list")


class RegisterAgentRequest(BaseModel):
    agent_id: str
    hostname: str
    os: str
    capabilities: List[str]


class BenchmarkRequest(BaseModel):
    source: str
    dataset: str = "datasets/synthetic"


# --- Investigations Endpoints ---
@router.post("/investigations/compile")
def compile_investigation(req: CompileRequest):
    try:
        return service.compile(req.source)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/investigations")
def list_investigations():
    return db.list_investigations()


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: str):
    inv = db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.post("/investigations/run")
def run_investigation(req: RunRequest):
    try:
        return service.execute_investigation(
            source_code=req.source,
            dataset_dir=req.dataset,
            mode=req.mode,
            targets=req.targets,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- Contracts Endpoints ---
@router.get("/contracts/{contract_id}")
def get_contract(contract_id: str):
    ctr = db.get_contract(contract_id)
    if not ctr:
        raise HTTPException(status_code=404, detail="Contract not found")
    return ctr


# --- Agents Endpoints ---
@router.get("/agents")
def list_agents():
    # If no agents registered yet, pre-populate default demo fleet
    agents = db.list_agents()
    if not agents:
        default_fleet = [
            ("WIN-01", "WIN-01.corp.internal", "windows", ["collect:process", "collect:file", "collect:network", "collect:event", "preserve:records"]),
            ("WIN-02", "WIN-02.corp.internal", "windows", ["collect:process", "collect:file", "collect:network", "preserve:records"]),
            ("UBUNTU-01", "ubuntu-srv-01", "linux", ["collect:process", "collect:file", "collect:network", "preserve:records"]),
            ("OFFLINE-01", "forensic-lab-vault", "offline", ["collect:*", "preserve:records"]),
        ]
        for aid, h, o, caps in default_fleet:
            db.register_agent(aid, h, o, caps, "online")
        agents = db.list_agents()
    return agents


@router.post("/agents/register")
def register_agent(req: RegisterAgentRequest):
    db.register_agent(req.agent_id, req.hostname, req.os, req.capabilities)
    return {"status": "ok", "agent_id": req.agent_id}


# --- Executions Endpoints ---
@router.get("/executions")
def list_executions():
    return db.list_executions()


@router.get("/executions/{exec_id}")
def get_execution(exec_id: str):
    res = db.get_execution(exec_id)
    if not res:
        raise HTTPException(status_code=404, detail="Execution not found")
    return res


# --- Evidence Endpoints ---
@router.get("/evidence")
def query_evidence(
    execution_id: Optional[str] = Query(None),
    entity: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    return db.query_evidence(execution_id=execution_id, entity=entity, host=host, limit=limit)


# --- Findings Endpoints ---
@router.get("/findings")
def list_findings(execution_id: Optional[str] = Query(None)):
    return db.list_findings(execution_id=execution_id)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    res = db.get_finding(finding_id)
    if not res:
        raise HTTPException(status_code=404, detail="Finding not found")
    return res


@router.get("/findings/{finding_id}/provenance")
def get_finding_provenance(finding_id: str):
    res = db.get_finding(finding_id)
    if not res:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "finding_id": finding_id,
        "title": res["title"],
        "provenance": res["provenance"],
    }


# --- Replay & Audit Endpoints ---
@router.post("/replay/{execution_id}")
def verify_replay(execution_id: str):
    try:
        return service.verify_replay(execution_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Benchmarks Endpoints ---
@router.post("/benchmark")
def run_benchmark(req: BenchmarkRequest):
    try:
        return service.compare_benchmark(req.source, req.dataset)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
