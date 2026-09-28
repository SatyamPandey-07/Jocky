<div align="center">

# ⚡ JOCKY
### *Declarative Forensic Engine • Cryptographic Contracts • Bit-for-Bit Replay*

[![Tests](https://img.shields.io/badge/tests-83%20passed-10b981.svg?style=for-the-badge&logo=pytest)](file:///d:/SIH_SOFTWARE/tests)
[![Bandwidth](https://img.shields.io/badge/bandwidth%20saved-92.5%25-0ea5e9.svg?style=for-the-badge)](file:///d:/SIH_SOFTWARE/bench)
[![Replay](https://img.shields.io/badge/replay%20guarantee-100%25%20deterministic-8b5cf6.svg?style=for-the-badge)](file:///d:/SIH_SOFTWARE/run_demo.py)
[![Custody](https://img.shields.io/badge/custody-Ed25519%20%2B%20SHA--256-ef4444.svg?style=for-the-badge)](file:///d:/SIH_SOFTWARE/compiler/jocky/contract)

<p align="center">
  <b>Write once, hunt anywhere.</b><br>
  A declarative forensic query language, query-optimizing compiler, and Ed25519-signed runtime<br>
  for cross-platform threat hunting with 100% bit-for-bit verifiable replay.
</p>

</div>

---

> Practical implementation of the academic research paper:  
> **"JOCKY: A Declarative Framework for Cross-Platform Forensic Investigations"**

JOCKY allows investigators to write platform-agnostic forensic investigations once in a high-level query language, compile them into cryptographically signed and capability-constrained **Forensic Execution Contracts**, evaluate them across heterogeneous endpoints (Windows, Linux, offline datasets) with zero code modifications, and correlate normalized forensic evidence into provenance-backed, bit-for-bit replayable findings.

---

## Quickstart (Try it in 30 seconds)

### 1. Run the Full End-to-End Demonstration
Executes the complete 10-phase pipeline (Incident #42: PowerShell $\to$ Dropper $\to$ C2 Beacon within 20m):
```bash
python run_demo.py
```

### 2. Start Central Control Plane & Forensic Dashboard
Launches the FastAPI backend and dark-mode interactive console on port 8000:
```bash
python control-plane/main.py
```
Open **`http://localhost:8000`** in your browser to access all 6 forensic console screens:
- **① Investigations**: Interactive JOCKY code editor and live diagnostics.
- **② Compiler & Forensic IR**: AST viewer, capability inference, and Forensic IR JSON.
- **③ Fleet Status**: Heterogeneous endpoint matrix (`WIN-01`, `WIN-02`, `UBUNTU-01`, `OFFLINE-01`).
- **④ Evidence Stream**: Real-time 5-entity normalized telemetry envelopes with SHA-256 integrity hashes.
- **⑤ Correlated Findings**: Attack chain correlation cards.
- **⑥ Provenance & Replay**: Interactive Directed Acyclic Graph (DAG) and one-click bit-for-bit replay verification.

### 3. Run Comparative Pushdown Benchmark
Measures bandwidth and latency gains of Predicate & Projection Pushdown vs Naive Collection:
```bash
python bench/benchmark.py
```
*Results: Over **92% bandwidth reduction**, **91% records reduction**, and **1.9x latency speedup** while producing bit-for-bit identical finding digests.*

### 4. Run Test Suite
Runs all 83 automated unit, property, and integration tests:
```bash
pytest
```

---

## System Architecture

```
                               INVESTIGATOR
                                    │
                                    │ (Writes JOCKY DSL)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          JOCKY COMPILER                                │
│   Source Code ──► Parser ──► AST ──► Semantic & Evidence Analysis      │
│   Physical Plan ◄── Optimizer ◄── Forensic IR ◄┘                       │
│         │                                                              │
│         ▼                                                              │
│   Execution Contract Generator ──► Ed25519 Signer ──► Signed Contract  │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CENTRAL CONTROL PLANE                           │
│   FastAPI REST API ─── WebSocket Hub ─── SQLite/PostgreSQL Database    │
└───────────┬──────────────────────────┬─────────────────────────────────┘
            │                          │
            ▼                          ▼
┌────────────────────────┐  ┌────────────────────────┐  ┌───────────────┐
│     ENDPOINT: WIN-01   │  │   ENDPOINT: UBUNTU-01  │  │  OFFLINE-01   │
│  (Cross-Platform Agent)│  │  (Cross-Platform Agent)│  │  (Disk Dumps) │
│  ├── Contract Verifier │  │  ├── Contract Verifier │  │  ├── JSON     │
│  ├── Policy Enforcer   │  │  ├── Policy Enforcer   │  │  └── CSV      │
│  ├── Win32 Collectors  │  │  ├── /proc Collectors  │  │  Collectors   │
│  └── Evidence Hasher   │  │  └── Evidence Hasher   │  │               │
└───────────┬────────────┘  └──────────┬─────────────┘  └───────┬───────┘
            │                          │                        │
            └──────────────────────────┼────────────────────────┘
                                       │ (5-Entity Normalized Envelopes)
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     CORRELATION & PROVENANCE ENGINE                    │
│   Deterministic Temporal Join ──► Provenance Graph DAG Builder        │
│                                           │                            │
│                                           ▼                            │
│                                Provenance-Backed Finding               │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    CENTRAL DASHBOARD CONSOLE (6 SCREENS)               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Five-Entity Schema Envelopes

Every record observed on an endpoint is normalized into one of 5 canonical entities under a uniform cryptographic envelope (`schemas/entities.json`):
1. **`Process`**: Process executions, start time, PID, PPID, image name, path, command line, user.
2. **`File`**: File creations, modifications, deletions, file hashes, attributed PID.
3. **`NetworkConnection`**: TCP/UDP socket connections, direction, local/remote IP and ports.
4. **`User`**: Account observations, UID/SID, domain, home directory.
5. **`Event`**: OS event log entries, event IDs, providers, channels.

---

## Directory Layout

```
SIH_SOFTWARE/
├── agent/                # Endpoint Agent (Rust & Python cross-platform)
│   ├── jocky_agent.py    # Cross-platform runner with Ed25519 & pushdown filters
│   └── src/              # Rust agent implementation
├── bench/                # Benchmarking suite (Pushdown vs Naive)
├── compiler/             # Compiler core (Parser, AST, IR, Optimizer, Contract)
├── control-plane/        # FastAPI backend, SQLite database, and WebSocket hub
├── dashboard/            # Modern 6-screen web investigation console
├── datasets/             # Synthetic telemetry generator & test data
├── examples/             # Incident #42 and sample investigations
├── policies/             # Agent capability policies (default & strict)
├── scenario/             # Multi-host scenario orchestrator
├── schemas/              # Canonical 5-entity schema (entities.json)
├── tests/                # 83 passing automated unit & integration tests
├── run_demo.py           # Master end-to-end demonstration runner
├── docker-compose.yml    # Container orchestration
└── plan.md               # Master engineering specification
```

---

## Core Principles & Guarantees

1. **Read-Only Non-Invasive Forensics**: Zero endpoint modification, zero driver injection, zero process tampering.
2. **Capability-Gated Privilege**: Endpoints refuse execution if required privileges are not explicitly granted by local policy.
3. **Cryptographic Chain-of-Custody**:
   - Ed25519 signed contract envelope
   - SHA-256 hashed evidence envelopes
   - Direct provenance linking Finding $\to$ Derived $\to$ Raw Evidences $\to$ Contract
4. **Deterministic Replay Guarantee**: Any investigation produces the exact same bit-for-bit SHA-256 finding digest when re-executed over frozen evidence.
