# JOCKY MVP Master Implementation Plan

> **System:** JOCKY — Cross-Platform Declarative Forensic Investigation Engine  
> **Source of Truth:** Academic Research Paper ("JOCKY: A Declarative Framework for Cross-Platform Forensic Investigations")  
> **Scope:** Practical engineering blueprint to realize the demonstrable MVP from research concepts to operational software.  
> **Status:** Active Execution  

---

## 0. Executive Summary & MVP North Star

JOCKY is a declarative forensic framework that enables investigators to write platform-agnostic forensic investigations once in a high-level query language, compile them into cryptographically signed and capability-constrained **Forensic Execution Contracts**, evaluate them across heterogeneous endpoints (Windows, Linux, offline datasets) with zero code modifications, and correlate normalized forensic evidence into provenance-backed, bit-for-bit replayable findings.

### The Single North Star Flow

The entire MVP proves one uninterrupted end-to-end execution path:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Write Investigation in JOCKY DSL (e.g. Incident #42)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Compile: Parser ➔ AST ➔ Semantic & Evidence Checks       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Capability Analysis & Policy Verification (RBAC/Gating)  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Forensic IR Generation ➔ Physical Optimization           │
│    (Predicate & Projection Pushdown, Join Reduction)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Create Cryptographically Signed Execution Contract       │
│    (Ed25519 Signature, SHA-256 Plan Hash, Capability Claims)│
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Multi-Target Dispatch (Control Plane / Agents / Offline) │
│    - WIN-01 (Windows 10/11 ETW + Win32 APIs)                │
│    - UBUNTU-01 (Linux /proc + netlink/auditd)               │
│    - OFFLINE-01 (Cold forensic JSON/CSV disks)              │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Normalize Telemetry to 5 Canonical Entities              │
│    (Process, File, NetworkConnection, User, Event)          │
│    Hashed with SHA-256 envelope and chain-of-custody        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 8. Deterministic Temporal Correlation                       │
│    (shells ➔ drops ➔ beacons within 20m window)             │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 9. Synthesize Provenance-Backed Finding                     │
│    (Complete DAG from Raw Evidence ➔ Contract ➔ Finding)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 10. Central Dashboard Visualization & Replay Verification   │
│     (Replay over frozen evidence produces identical digest) │
└─────────────────────────────────────────────────────────────┘
```

The MVP is deemed successful when the **identical logical investigation** executes across Windows, Linux, and offline evidence without changing a single line of source code.

---

## 1. Academic Paper Alignment & Specification Map

The original research paper defines the foundational theory, formal semantics, and algorithms. The implementation adheres directly to the sections below:

| Paper Section | Topic | Concrete Implementation Responsibility |
|:---|:---|:---|
| **§IV — The JOCKY Language** | DSL Semantics & Types | Grammar, 8 core primitives, evidence-aware type system (`Evidence<T>`, `Derived<T>`, `Finding<T>`). |
| **§V — Compiler Architecture** | Lowering & Optimization | AST, semantic resolution, Forensic IR (canonical JSON), capability inference pass, logical-to-physical optimization. |
| **§VI — Execution Contract & Runtime** | Custody & Enforcement | Ed25519 signed contract envelope, resource bounding, capability attestation, cross-platform agent execution, evidence hashing. |
| **§VII — Evaluation** | Methodology & Metrics | Benchmarking: bytes transferred, wall-clock latency, naive vs optimized plan speedup, auditability proofs. |
| **§IX — Future Work** | Scope Boundaries | Explicit list of features deferred beyond the MVP (MLIR/LLVM dialects, eBPF kernel probes, AI copilot). |

---

## 2. Current Implementation Status & Codebase Audit

As of today, the repository contains a fully validated compiler core with 79 passing automated tests, schema definitions, and a synthetic forensic telemetry generator.

### Current Component Maturity Matrix

| Component | Directory / File | Status | Test Coverage | Key Capabilities |
|:---|:---|:---:|:---:|:---|
| **JOCKY Grammar & Parser** | `compiler/jocky/parser/` | **COMPLETE** | 8 tests | Full recursive-descent/LALR parser for 8 primitives, bindings, filters, and temporal windows. |
| **Semantic Analysis** | `compiler/jocky/semantic/` | **COMPLETE** | 20 tests | Scope checking, natural key checks, type validation, temporal range checks. |
| **Evidence Type System** | `compiler/jocky/evidence/` | **COMPLETE** | Integrated | Strong tracking of `Evidence<T>`, `Derived<T>`, `Finding<T>`, and taint/provenance. |
| **Capability Inference** | `compiler/jocky/capabilities/` | **COMPLETE** | 5 tests | Automated deduction of required endpoint capabilities (`collect:process`, `collect:process.cmdline`, etc.). |
| **Forensic IR** | `compiler/jocky/ir/` | **COMPLETE** | Integrated | Canonical JSON-based intermediate representation with topological sorting. |
| **Plan Optimizer** | `compiler/jocky/optimizer/` | **COMPLETE** | 11 tests | Predicate pushdown, projection pushdown, temporal window bounding, join reduction. |
| **Physical Planner** | `compiler/jocky/planner/` | **COMPLETE** | Integrated | Physical task lowered to target-specific operators (Windows, Linux, Offline). |
| **Execution Contract** | `compiler/jocky/contract/` | **COMPLETE** | 4 tests | Ed25519 asymmetric signing, public key attestation, plan SHA-256 digest validation. |
| **Correlation Engine** | `compiler/jocky/correlation/` | **COMPLETE** | Integrated | Deterministic temporal join engine (`within <duration>`, `on host, pid`). |
| **Replay Subsystem** | `compiler/jocky/replay.py` | **COMPLETE** | 2 tests | Deterministic execution from frozen evidence bundles, digest matching. |
| **CLI Tools** | `compiler/jocky/cli.py` | **COMPLETE** | Operational | `check`, `compile`, `run`, `replay`, `keygen`, `verify-contract`. |
| **Schemas** | `schemas/entities.json` | **COMPLETE** | Operational | 5 core canonical entity envelopes (Process, File, NetworkConnection, User, Event). |
| **Dataset Generator** | `datasets/generate.py` | **COMPLETE** | Operational | Multi-host synthetic timeline generator with configurable noise and Incident #42 injection. |
| **Rust Agent Core** | `agent/` | **IN PROGRESS** | Scaffolding | Cargo crate, Proto transport, contract verification, Windows & Linux collectors. |
| **Control Plane API** | `control-plane/` | **PENDING** | - | FastAPI backend, PostgreSQL database, WebSocket orchestrator, agent registration. |
| **Dashboard UI** | `dashboard/` | **PENDING** | - | Modern React/Next.js dashboard (investigations, IR visualizer, timeline, provenance DAG). |

---

## 3. System Architecture & Component Specification

```
                               INVESTIGATOR
                                    │
                                    │ (Writes JOCKY DSL)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          JOCKY COMPILER                                │
│                                                                        │
│   Source Code ──► Parser ──► AST ──► Semantic & Evidence Analysis      │
│                                                │                       │
│   Physical Plan ◄── Optimizer ◄── Forensic IR ◄┘                       │
│         │                                                              │
│         ▼                                                              │
│   Execution Contract Generator ──► Ed25519 Signer ──► Signed Contract  │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CENTRAL CONTROL PLANE                           │
│                                                                        │
│   FastAPI REST API ─── WebSocket Hub ─── PostgreSQL (State & Metadata) │
│           │                                      │                     │
│           ├── Contract Dispatch                  ├── Evidence Ingest   │
│           │                                      └── Finding Records   │
│           ▼                                                            │
│   MinIO / S3 Store (Frozen Evidence & Artifact Tarballs)               │
└───────────┬──────────────────────────┬─────────────────────────────────┘
            │                          │
            ▼                          ▼
┌────────────────────────┐  ┌────────────────────────┐  ┌───────────────┐
│     ENDPOINT: WIN-01   │  │   ENDPOINT: UBUNTU-01  │  │  OFFLINE-01   │
│  (Rust Agent)          │  │  (Rust Agent)          │  │  (Local Run)  │
│  ├── Verifier          │  │  ├── Verifier          │  │  ├── JSON     │
│  ├── Policy Enforcer   │  │  ├── Policy Enforcer   │  │  └── CSV      │
│  ├── Win Collectors    │  │  ├── Linux Collectors  │  │  Collectors   │
│  └── Evidence Hasher   │  │  └── Evidence Hasher   │  │               │
└───────────┬────────────┘  └──────────┬─────────────┘  └───────┬───────┘
            │                          │                        │
            └──────────────────────────┼────────────────────────┘
                                       │ (Normalized Evidence Records)
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     CORRELATION & PROVENANCE ENGINE                    │
│                                                                        │
│   Deterministic Temporal Join ──► Provenance Graph DAG Builder        │
│                                           │                            │
│                                           ▼                            │
│                                Provenance-Backed Finding               │
└──────────────────────────────────────┬─────────────────────────────────┘
                                       │
                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          CENTRAL DASHBOARD                             │
│                                                                        │
│  [1. Investigations] [2. Compiler & IR] [3. Fleet Status]              │
│  [4. Evidence Stream] [5. Findings]    [6. Provenance & Replay]        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Deep-Dive Component Blueprints

### 4.1 JOCKY Domain-Specific Language & Compiler Pipeline

#### Primitive Set (8 Primitives)
1. `observe <Entity>`: Collects telemetry stream for an entity type (`Process`, `File`, `NetworkConnection`, `User`, `Event`).
2. `filter <Predicate>`: Restricts records using boolean expressions, CIDR matches, set membership, regex.
3. `select <Field1>, <Field2>, ...`: Projections to reduce data volume early.
4. `join <Stream1>, <Stream2>`: Equi-join on specified keys.
5. `within <Duration>`: Temporal bounding window (e.g. `within 20m`, `within 1h`).
6. `sequence <A> -> <B> -> <C>`: Ordered temporal sequence matching across common natural keys.
7. `preserve <Binding>`: Designates an intermediate evidence stream as mandatory for forensic retention.
8. `emit finding <Binding>`: Declares a corroborated finding with title, description, and severity level.

#### Concrete Running Scenario: `Incident #42`
```jocky
investigation incident_42 {
    title   "PowerShell dropped a file, then connected out"
    targets ["WIN-01", "WIN-02", "UBUNTU-01", "OFFLINE-01"]
    window  last 24h

    let shells = observe Process
        | filter name in ["powershell.exe", "pwsh.exe", "pwsh"]
        | select pid, ppid, name, path, user

    let drops = observe File
        | filter action == "create"
        | select pid, path, name, extension, size

    let beacons = observe NetworkConnection
        | filter direction == "outbound" and not remote_ip in cidr("127.0.0.0/8")
        | select pid, protocol, remote_ip, remote_port, state

    let chain = sequence shells -> drops -> beacons
        on host, pid
        within 20m

    preserve chain

    emit finding chain
        as "PowerShell -> file creation -> network connection within 20m"
        severity high
}
```

#### Compiler Phases
- **Parser (`compiler/jocky/parser/`)**: Converts concrete syntax to strongly-typed AST nodes (`ProgramNode`, `InvestigationNode`, `LetBindingNode`, `SequenceNode`, etc.).
- **Semantic Validator (`compiler/jocky/semantic/`)**: Verifies variable scopes, field existence against schema, type compatibility, and valid sequence joins.
- **Evidence Type Checker (`compiler/jocky/evidence/`)**: Wraps types in provenance containers (`Evidence<T>`, `Derived<T>`, `Finding<T>`).
- **Capability Inference Engine (`compiler/jocky/capabilities/`)**: Analyzes referenced entities and fields to generate the capability set required to execute the investigation (e.g., `collect:process`, `collect:process.cmdline`, `collect:file`, `collect:network`).
- **Forensic IR Generator (`compiler/jocky/ir/`)**: Compiles the AST into a deterministic, JSON-serializable DAG of operations.
- **Physical Optimizer (`compiler/jocky/optimizer/`)**:
  - *Predicate Pushdown*: Pushes filters down into host collectors to prevent massive event transfers.
  - *Projection Pushdown*: Restricts extracted attributes to only requested columns.
  - *Temporal Pushdown*: Computes exact timestamps bounds before dispatch.
  - *Join Pruning*: Reduces cardinality before central correlation.

---

### 4.2 Forensic Execution Contract Specification

The Execution Contract is the immutable, cryptographically verifiable unit of execution dispatched to endpoints.

```json
{
  "contract_id": "cnt_01J8K3M90A...",
  "investigation_id": "incident_42",
  "compiler_version": "jocky-0.1.0",
  "created_at": "2026-09-29T01:00:00Z",
  "expires_at": "2026-09-29T02:00:00Z",
  "plan_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "target_endpoints": ["WIN-01", "WIN-02", "UBUNTU-01"],
  "required_capabilities": [
    "collect:process",
    "collect:file",
    "collect:network"
  ],
  "resource_limits": {
    "max_memory_mb": 256,
    "max_cpu_percent": 15,
    "max_duration_seconds": 300,
    "max_records": 50000
  },
  "physical_plan": {
    "nodes": [ ... ]
  },
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "MCowBQYDK2VwAyEA...",
    "key_id": "key_investigator_satyam",
    "sig_bytes": "3b4f...a891"
  }
}
```

#### Contract Verification Rules on Agent:
1. Decode public key and verify signature over the canonical JSON serialization of the contract fields.
2. Calculate SHA-256 of `physical_plan` and verify match with `plan_hash`.
3. Check `expires_at` against local synchronized UTC clock.
4. Check `required_capabilities` against host agent policy (`policies/agent_policy.json`). If any capability is denied, reject contract with specific capability error code.
5. Apply OS cgroups / Windows Job Objects for `resource_limits`.

---

### 4.3 Five-Entity Evidence Schema & Normalization

All endpoint telemetry is normalized into 5 canonical entities under a uniform forensic envelope defined in `schemas/entities.json`:

```json
{
  "envelope": {
    "evidence_id": "ev_01J8K...",
    "entity": "Process | File | NetworkConnection | User | Event",
    "host": "WIN-01",
    "time": "2026-09-29T00:45:12.345678Z",
    "time_source": "kernel_event | file_birth | netlink_socket",
    "observed_at": "2026-09-29T00:45:13.001000Z",
    "collector": "jocky-windows-collector",
    "collector_version": "0.1.0",
    "source": "etw:Microsoft-Windows-Kernel-Process",
    "execution_id": "exec_42_01",
    "contract_hash": "e3b0c442...",
    "sha256": "8f4a...129c"
  },
  "fields": { ... }
}
```

#### The 5 Entities:
1. **`Process`**:
   - Fields: `pid`, `ppid`, `name`, `path`, `cmdline`, `user`, `host`, `time`.
   - Natural Key: `["host", "pid", "time"]`.
2. **`File`**:
   - Fields: `pid`, `path`, `name`, `extension`, `size`, `action` (`create|modify|delete|open`), `attribution`, `sha256`, `host`, `time`.
   - Natural Key: `["host", "path", "time", "pid"]`.
3. **`NetworkConnection`**:
   - Fields: `pid`, `protocol` (`tcp|udp`), `direction` (`inbound|outbound|listen`), `state`, `local_ip`, `local_port`, `remote_ip`, `remote_port`, `host`, `time`.
   - Natural Key: `["host", "pid", "protocol", "local_ip", "local_port", "remote_ip", "remote_port", "time"]`.
4. **`User`**:
   - Fields: `name`, `uid` (UID/SID), `domain`, `home`, `host`, `time`.
   - Natural Key: `["host", "name", "uid"]`.
5. **`Event`**:
   - Fields: `channel`, `provider`, `event_id`, `record_id`, `level`, `pid`, `message`, `host`, `time`.
   - Natural Key: `["host", "channel", "provider", "event_id", "record_id", "time"]`.

---

### 4.4 Cross-Platform Endpoint Agent (Rust)

Location: `agent/`

```
agent/
├── Cargo.toml
├── build.rs
└── src/
    ├── main.rs                  // CLI entrypoint, contract loader, daemon mode
    ├── transport.rs             // gRPC / WebSocket / HTTPS upload transport
    ├── core/
    │   ├── contract.rs          // Contract validation & signature verification
    │   ├── policy.rs            // Local capability policy evaluator
    │   ├── normalizer.rs        // Telemetry-to-Envelope canonicalizer
    │   ├── limits.rs            // Resource bounds watchdog (CPU/RAM/Timeout)
    │   └── storage.rs           // Local disk ring buffer
    ├── collectors/
    │   ├── traits.rs            // Collector interface (collect, filter, poll)
    │   └── offline.rs           // Offline JSON/CSV reader for test & forensics
    ├── windows/
    │   ├── process.rs           // Win32 Toolhelp32Snapshot / ETW Process
    │   ├── file.rs              // USN Journal / Directory change watcher
    │   └── network.rs           // GetExtendedTcpTable / GetExtendedUdpTable
    └── linux/
        ├── process.rs           // /proc/[pid]/stat, cmdline, status
        ├── file.rs              // fanotify / inotify
        └── network.rs           // /proc/net/tcp, netlink sock_diag
```

#### Collector Execution Characteristics:
- **Read-Only**: Strictly forensic extraction; zero system modification, zero DLL injection, zero driver loading.
- **Pushdown Execution**: Receives the physical plan node; applies filtering immediately during scan (e.g. skips processes whose `name` doesn't match filter).
- **Integrity**: Every record envelope is hashed immediately at the collector level.

---

### 4.5 Central Control Plane (FastAPI + PostgreSQL)

Location: `control-plane/`

#### Tech Stack:
- **Language**: Python 3.10+ / FastAPI
- **Database**: PostgreSQL 15+ (asyncpg + SQLAlchemy Core/Alembic)
- **Object Storage**: MinIO or local filesystem evidence vault
- **Messaging**: WebSockets for low-latency agent push & dashboard live telemetry

#### API Endpoints Architecture:
```
/api/v1/
├── investigations/
│   ├── POST   /                       # Create new investigation
│   ├── GET    /                       # List investigations
│   ├── GET    /{id}                   # Get details & status
│   └── POST   /{id}/compile           # Trigger compiler -> outputs IR & Contract
├── contracts/
│   ├── GET    /{id}                   # Get contract JSON & signature
│   └── POST   /{id}/dispatch          # Dispatch contract to agents
├── agents/
│   ├── GET    /                       # List connected agents & capabilities
│   ├── POST   /register               # Agent handshake & public key registration
│   └── WS     /ws/{agent_id}          # Bidirectional streaming (dispatch & ingest)
├── evidence/
│   ├── GET    /                       # Query normalized evidence records
│   ├── GET    /{id}                   # Retrieve raw evidence envelope
│   └── POST   /ingest                 # Bulk upload evidence packets
├── findings/
│   ├── GET    /                       # Query correlated findings
│   ├── GET    /{id}                   # Get finding detail
│   └── GET    /{id}/provenance        # Get full provenance graph (nodes & edges)
├── replay/
│   └── POST   /execute                # Replay investigation against frozen run
└── metrics/
    └── GET    /benchmark              # Optimizer vs Naive comparative statistics
```

#### PostgreSQL Relational Model:
```sql
CREATE TABLE investigations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    source_code TEXT NOT NULL,
    status VARCHAR(32) NOT NULL, -- draft, compiled, running, completed, failed
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE contracts (
    contract_id VARCHAR(64) PRIMARY KEY,
    investigation_id VARCHAR(64) REFERENCES investigations(id),
    plan_hash VARCHAR(64) NOT NULL,
    signature TEXT NOT NULL,
    contract_json JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    os VARCHAR(32) NOT NULL, -- windows, linux, offline
    ip_address VARCHAR(45) NOT NULL,
    capabilities JSONB NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE executions (
    id VARCHAR(64) PRIMARY KEY,
    investigation_id VARCHAR(64) REFERENCES investigations(id),
    contract_id VARCHAR(64) REFERENCES contracts(contract_id),
    target_host VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    records_collected INTEGER DEFAULT 0,
    bytes_transferred BIGINT DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE evidence_records (
    evidence_id VARCHAR(64) PRIMARY KEY,
    execution_id VARCHAR(64) REFERENCES executions(id),
    entity VARCHAR(32) NOT NULL,
    host VARCHAR(64) NOT NULL,
    event_time TIMESTAMP WITH TIME ZONE NOT NULL,
    observed_time TIMESTAMP WITH TIME ZONE NOT NULL,
    collector VARCHAR(64) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE findings (
    id VARCHAR(64) PRIMARY KEY,
    investigation_id VARCHAR(64) REFERENCES investigations(id),
    title TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,
    finding_digest VARCHAR(64) NOT NULL,
    chain_summary JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE provenance_links (
    id BIGSERIAL PRIMARY KEY,
    finding_id VARCHAR(64) REFERENCES findings(id),
    parent_id VARCHAR(64) NOT NULL, -- evidence_id or contract_id
    child_id VARCHAR(64) NOT NULL,
    relationship VARCHAR(32) NOT NULL -- collected_by, derived_from, correlated_in
);
```

---

### 4.6 Correlation & Provenance Engine

Location: `compiler/jocky/correlation/`

#### Deterministic Sequence Algorithm
For rules of the form:
`let chain = sequence shells -> drops -> beacons on host, pid within 20m`

1. Partition all evidence by the join keys (`host`, `pid`).
2. Sort chronological records within each partition by `event_time`.
3. For each candidate starting event in `shells`:
   - Seek forward in `drops` where $T_{drop} \ge T_{shell}$ and $T_{drop} - T_{shell} \le 20\text{ minutes}$.
   - For each matching drop, seek forward in `beacons` where $T_{beacon} \ge T_{drop}$ and $T_{beacon} - T_{shell} \le 20\text{ minutes}$.
   - If a complete match $\{E_{shell}, E_{drop}, E_{beacon}\}$ is formed, instantiate a `Derived<Sequence>` record.
4. Generate cryptographic Provenance DAG:
   - Root: `Finding`
   - Intermediate: `Derived<Sequence>`
   - Leaves: `Evidence<Process>`, `Evidence<File>`, `Evidence<NetworkConnection>`
   - Attestation: Linked to `ExecutionContract` (hash of plan) and `Collector` signatures.

---

### 4.7 Central Dashboard UI (6 Screens)

Location: `dashboard/`  
Stack: Next.js 14 (App Router) + TypeScript + Tailwind CSS + Lucide Icons + React Flow (DAG)

#### Screen Specifications:
1. **Screen 1 — Investigation Studio**:
   - Code editor with JOCKY DSL syntax highlighting.
   - Run compilation button, real-time syntax/semantic diagnostics overlay.
   - Target host selector (`WIN-01`, `WIN-02`, `UBUNTU-01`, `OFFLINE-01`).
2. **Screen 2 — Compiler & Forensic IR Visualizer**:
   - Side-by-side view: High-level DSL ➔ Abstract Syntax Tree ➔ Forensic IR JSON.
   - Physical Plan tab showing Naive vs Optimized operators and Pushdown diffs.
   - Cryptographic Contract card: Ed25519 signature badge, SHA-256 plan fingerprint.
3. **Screen 3 — Fleet Status & Orchestration**:
   - Endpoint grid with live connection health and platform tags (Windows, Linux, Offline).
   - Capability policy matrix per endpoint (e.g. `collect:process.cmdline` Allowed / Gated).
   - Active execution progress bars, CPU/RAM utilization gauges.
4. **Screen 4 — Forensic Evidence Stream**:
   - Interactive timeline of ingested evidence envelopes.
   - Filter by entity type, host, timestamp, collector.
   - Detail drawer inspecting raw envelope, payload, and SHA-256 hash.
5. **Screen 5 — Correlated Findings**:
   - Cards showing high-severity findings (Incident #42).
   - Sequence chain summary: PowerShell (PID 4812) ➔ `dropper.ps1` ➔ `198.51.100.24:443`.
   - Direct links to raw evidence items.
6. **Screen 6 — Provenance Graph & Replay Studio**:
   - Interactive DAG visualization using React Flow:
     `Finding` ➔ `Derived Sequence` ➔ `Raw Evidences` ➔ `Contract` ➔ `Endpoints`.
   - One-click Replay verification trigger: executes exact query against frozen snapshot; renders bit-for-bit SHA-256 digest match badge (`MATCH: 100% REPRODUCIBLE`).

---

## 5. Directory Structure & Layout

```
D:/SIH_SOFTWARE/
├── agent/                         # Rust Endpoint Agent
│   ├── Cargo.toml                 # Rust dependencies (tokio, ed25519-dalek, serde, tonic)
│   ├── build.rs                   # Protobuf codegen
│   └── src/
│       ├── main.rs                # Entrypoint & CLI execution
│       ├── transport.rs           # Communication to control plane
│       ├── core/                  # Contract verification, policy check, limits
│       ├── collectors/            # Trait definitions & offline collector
│       ├── windows/               # Windows ETW & Win32 APIs
│       └── linux/                 # Linux /proc & netlink collectors
│
├── compiler/                      # JOCKY Compiler (Python)
│   ├── pyproject.toml             # Packaging config
│   └── jocky/
│       ├── ast/                   # AST node hierarchy & JSON serialization
│       ├── parser/                # Recursive descent parser
│       ├── semantic/              # Scopes, symbols, type check
│       ├── evidence/              # Evidence<T> type tracking
│       ├── capabilities/          # Capability inference engine
│       ├── ir/                    # Forensic IR builder
│       ├── optimizer/             # Pushdown & join reduction passes
│       ├── planner/               # Physical task generation
│       ├── contract/              # Ed25519 contract creation & verification
│       ├── correlation/           # Temporal join & sequence engine
│       ├── runtime/               # Local offline execution driver
│       ├── replay.py              # Cryptographic replay validator
│       ├── cli.py                 # `jocky` command line utility
│       └── compiler.py            # High-level compilation pipeline coordinator
│
├── control-plane/                 # Central Orchestration Backend (FastAPI)
│   ├── requirements.txt           # fastapi, uvicorn, asyncpg, sqlalchemy, pydantic
│   ├── main.py                    # Application bootstrap
│   ├── api/                       # API route controllers
│   │   ├── investigations.py
│   │   ├── contracts.py
│   │   ├── agents.py
│   │   ├── evidence.py
│   │   ├── findings.py
│   │   └── replay.py
│   ├── services/                  # Business logic & compiler bridge
│   ├── models/                    # SQLAlchemy ORM models & Pydantic schemas
│   └── database/                  # Connection pool & migrations
│
├── dashboard/                     # Web UI (Next.js / TypeScript / Tailwind)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── app/                   # App Router pages (routes 1..6)
│   │   ├── components/            # UI components (DAG, code editor, charts)
│   │   ├── lib/                   # API client & WebSocket listener
│   │   └── types/                 # Shared TypeScript models
│
├── datasets/                      # Telemetry Generators & Scenarios
│   ├── generate.py                # Synthetic realistic timeline generator
│   └── synthetic/                 # Generated test datasets
│
├── examples/                      # Canonical JOCKY investigations
│   ├── incident_42.jocky          # Primary demonstration scenario
│   └── evidence/                  # Sample test evidence
│
├── policies/                      # Agent capability policies
│   ├── default_policy.json        # Baseline permitted capabilities
│   └── strict_policy.json         # High-security constrained policy
│
├── schemas/                       # Canonical Schema Definitions
│   ├── entities.json              # 5-entity forensic schema & envelopes
│   └── proto/                     # Protocol Buffer definitions for gRPC
│       ├── contract.proto
│       └── evidence.proto
│
├── tests/                         # Comprehensive Automated Test Suites
│   ├── compiler/                  # Parser, AST, semantic, contract tests
│   ├── optimizer/                 # Pushdown, join, and equivalence tests
│   ├── agent/                     # Collector and contract verification tests
│   └── integration/               # End-to-end integration tests
│
├── docker-compose.yml             # Orchestration: Control Plane, PostgreSQL, MinIO
└── README.md                      # Quickstart and run instructions
```

---

## 6. Build Order & Implementation Milestones

```
  M1: Language & Parser           [COMPLETED]
            │
            ▼
  M2: Compiler Core & IR          [COMPLETED]
            │
            ▼
  M3: Offline Telemetry Runtime   [COMPLETED]
            │
            ▼
  M4: Physical Plan Optimizer     [COMPLETED]
            │
            ▼
  M5: Rust Agent (Offline/Core)   [IN PROGRESS - NEXT]
            │
            ▼
  M6: Cross-Platform Collectors   [SCHEDULED]
            │
            ▼
  M7: Central Control Plane API   [SCHEDULED]
            │
            ▼
  M8: Central Dashboard Frontend  [SCHEDULED]
            │
            ▼
  M9: Cryptographic Replay Audit  [SCHEDULED]
            │
            ▼
  M10: End-to-End Demo Hardening  [SCHEDULED]
```

### Milestone Breakdown

#### Milestone 1: Language & Parser (`compiler/jocky/parser/`) — [COMPLETED]
- [x] Grammar design for all 8 primitives (`observe`, `filter`, `select`, `join`, `within`, `sequence`, `preserve`, `emit`).
- [x] Recursive-descent AST parser.
- [x] Syntax error reporting with line/column source mapping.
- **Verification**: `pytest tests/compiler/test_parser.py` (8 passed).

#### Milestone 2: Compiler Core & Forensic IR (`compiler/jocky/`) — [COMPLETED]
- [x] Semantic analysis & scope verification.
- [x] Evidence type inference (`Evidence<T>`, `Derived<T>`).
- [x] Capability deduction engine (`capabilities.py`).
- [x] Forensic IR canonical JSON generation (`ir/`).
- **Verification**: `pytest tests/compiler/test_semantic.py tests/compiler/test_capabilities.py` (25 passed).

#### Milestone 3: Offline Telemetry Runtime (`compiler/jocky/runtime/`) — [COMPLETED]
- [x] Schema definition in `schemas/entities.json`.
- [x] Synthetic dataset generator in `datasets/generate.py`.
- [x] Local JSON/CSV evidence reader.
- [x] Deterministic correlation engine for sequence chains.
- **Verification**: `python -m compiler.jocky.cli run examples/incident_42.jocky --dataset datasets/synthetic`.

#### Milestone 4: Physical Plan Optimizer (`compiler/jocky/optimizer/`) — [COMPLETED]
- [x] Predicate pushdown implementation.
- [x] Projection pushdown implementation.
- [x] Temporal bounding pushdown.
- [x] Equivalence test ensuring Naive and Optimized plans produce identical findings.
- **Verification**: `pytest tests/optimizer/test_optimizer.py` (11 passed).

#### Milestone 5: Rust Agent Core & Contract Verifier (`agent/`) — [IN PROGRESS]
- [ ] Implement Ed25519 contract verification in Rust using `ed25519-dalek`.
- [ ] Implement capability checker against `policies/default_policy.json`.
- [ ] Implement resource watchdog (cgroups on Linux, Job Object on Windows).
- [ ] Port offline dataset runner to Rust to guarantee cross-language execution equivalence.
- **Acceptance Criteria**: `cargo test` in `agent/` succeeds; agent validates and executes a signed contract.

#### Milestone 6: Cross-Platform Endpoint Collectors (`agent/src/`) — [SCHEDULED]
- [ ] Windows Process Collector: `Toolhelp32Snapshot` / `EnumProcesses` + start time.
- [ ] Windows Network Collector: `GetExtendedTcpTable` / `GetExtendedUdpTable`.
- [ ] Linux Process Collector: `/proc/[pid]/stat`, `/proc/[pid]/cmdline`.
- [ ] Linux Network Collector: `/proc/net/tcp`, `/proc/net/tcp6`.
- [ ] Normalizer module producing valid envelopes matching `schemas/entities.json`.
- **Acceptance Criteria**: Agent collects live process and network states on Windows and Linux and normalizes them into identical schemas.

#### Milestone 7: Central Control Plane (`control-plane/`) — [SCHEDULED]
- [ ] FastAPI application setup with async endpoints for investigations, contracts, and evidence.
- [ ] PostgreSQL schema definition and migrations via SQLAlchemy.
- [ ] Compiler invocation service (compiling submitted JOCKY code, signing contracts).
- [ ] WebSocket hub for agent registration, heartbeat monitoring, and contract dispatch.
- **Acceptance Criteria**: Complete API tests passing; agents can register and receive contracts over WebSockets.

#### Milestone 8: Central Dashboard Frontend (`dashboard/`) — [SCHEDULED]
- [ ] Next.js app scaffolding with Tailwind CSS and dark-mode forensic styling.
- [ ] Screen 1: Investigation Studio (DSL editor with live diagnostics).
- [ ] Screen 2: Compiler & IR Visualizer (DAG & optimization diff).
- [ ] Screen 3: Fleet Status (Endpoint health & capability matrix).
- [ ] Screen 4: Forensic Evidence Stream (Real-time telemetry table & timeline).
- [ ] Screen 5: Correlated Findings (Incident #42 finding card).
- [ ] Screen 6: Provenance & Replay Studio (Interactive React Flow DAG and Replay button).
- **Acceptance Criteria**: Dashboard runs on `localhost:3000`, communicates with FastAPI backend, and renders all 6 screens seamlessly.

#### Milestone 9: Cryptographic Replay Engine & Auditability (`compiler/jocky/replay.py`) — [SCHEDULED]
- [ ] Bundle execution evidence into an immutable, hashed archive.
- [ ] Central replay controller that accepts an investigation and a frozen evidence bundle.
- [ ] Compute Finding Digest over results and verify bit-for-bit equivalence.
- **Acceptance Criteria**: Replay of `Incident #42` outputs the identical SHA-256 finding digest with audit proof.

#### Milestone 10: End-to-End Demo Hardening & Video Target — [SCHEDULED]
- [ ] Docker Compose environment orchestrating Control Plane, Database, and Dashboard.
- [ ] End-to-end automated script demonstrating multi-target execution (`WIN-01`, `WIN-02`, `UBUNTU-01`).
- [ ] Benchmark comparison report: Naive vs Optimized data transfer metrics.
- [ ] Video demonstration rehearsal following Section 7 storyboard.

---

## 7. Prototype Video Storyboard & Demonstration Scenario

The prototype demonstration tells one cohesive, continuous forensic story:

```
[00:00 - 00:30] THE PROBLEM & JOCKY DSL
  - Show incident alert: Suspicious outbound beacon detected.
  - Investigator opens JOCKY Dashboard -> Investigation Studio.
  - Write Incident #42 in JOCKY DSL:
    "PowerShell dropped file, then connected out within 20m".

[00:30 - 01:15] COMPILATION & OPTIMIZATION
  - Click "Compile".
  - Show Compiler Visualizer:
    1. AST generation.
    2. Capability Analysis: Automatically infers collect:process, collect:file, collect:network.
    3. Forensic IR generation.
    4. Optimization Pass: Displays Predicate Pushdown badge
       (Filters powershell.exe locally on agent instead of sending all 100,000 OS processes).
    5. Ed25519 cryptographic signing of the contract.

[01:15 - 02:00] MULTI-ENDPOINT DISPATCH
  - Targets selected: WIN-01, WIN-02, UBUNTU-01.
  - Show Fleet View:
    - Contract dispatched simultaneously across Windows and Linux endpoints.
    - Agents verify signature, check local policy, and start pushdown collectors.

[02:00 - 02:45] EVIDENCE STREAM & NORMALIZATION
  - Real-time stream shows incoming normalized envelopes.
  - Highlight: Schema is identical whether from Windows ETW or Linux /proc.
  - Show Metrics widget: Optimized plan reduced network transfer by >90%.

[02:45 - 03:30] FINDING & PROVENANCE GRAPH
  - Incident #42 correlates in real-time.
  - High-severity alert triggers: "Finding Found on WIN-01".
  - Investigator opens Provenance Studio:
    - Causal graph links: powershell.exe (PID 4812) ➔ dropper.ps1 ➔ 198.51.100.24:443.
    - Trace node down to raw evidence hash and collector signature.

[03:30 - 04:00] BIT-FOR-BIT CRYPTOGRAPHIC REPLAY
  - Click "Freeze Evidence & Verify Replay".
  - System executes same JOCKY source against frozen evidence bundle.
  - Green banner: "Replay Digest MATCH (100% Deterministic & Legally Defensible)".
```

---

## 8. Explicitly Deferred Features (Post-MVP Backlog)

In strict accordance with the paper's §IX (Future Work), the following capabilities are explicitly deferred from the MVP to prevent scope expansion:

1. **MLIR / LLVM Lowering Dialects**: The MVP uses canonical JSON IR. Native binary compilation via MLIR is deferred.
2. **Kernel Probing / Custom eBPF JIT**: Collectors utilize standard OS userland interfaces (`/proc`, Netlink, Win32 APIs, ETW).
3. **Plaso / Volatility / KAPE Custom Adapters**: Ingestion is standardized on canonical JSON/CSV; external forensic framework plugins will be integrated post-MVP.
4. **Distributed Cost-Based Optimizer**: The MVP uses deterministic rule-based pushdown optimization; dynamic cost modeling across 10,000+ nodes is deferred.
5. **AI / LLM Query Generation**: The focus is 100% on the formal declarative language and verifiable engine.
6. **Blockchain / Hardware HSM Custody**: Standard Ed25519 asymmetric cryptography and SHA-256 Merkle chains are used for MVP custody.

---

## 9. Security Model & Forensic Integrity Principles

1. **Read-Only Non-Invasive Forensics**: JOCKY agents never alter system state, inject code, or terminate processes.
2. **Strict Capability Gating**: Capabilities like `collect:process.cmdline` (which may expose command-line credentials) or memory reads require explicit administrator policy approval; the compiler detects and enforces this prior to execution.
3. **Cryptographic Chain of Custody**:
   - Contract signed with Ed25519.
   - Every raw evidence record hashed with SHA-256 upon observation.
   - Derived findings linked immutably to parent evidence IDs.
4. **Deterministic Replay Guarantee**: Any finding must be reproducibly verifiable from its preserved evidence bundle at any future date in a courtroom or peer review setting.

---

## 10. Master Verification Protocol (Definition of Done)

To verify the complete JOCKY system, run the following commands sequentially:

```powershell
# 1. Run all unit and integration tests (Must be 100% passing)
pytest

# 2. Generate multi-host synthetic forensic telemetry
python datasets/generate.py synthetic --out datasets/synthetic --hosts "WIN-01,WIN-02,UBUNTU-01" --incidents 1

# 3. Check JOCKY investigation source code
python -m compiler.jocky.cli check examples/incident_42.jocky

# 4. Compile investigation and inspect Forensic IR & Optimized Plan
python -m compiler.jocky.cli compile examples/incident_42.jocky --out build/

# 5. Execute investigation against forensic telemetry dataset
python -m compiler.jocky.cli run examples/incident_42.jocky --dataset datasets/synthetic --mode optimized --out runs/run_01

# 6. Verify bit-for-bit replayability of the run
python -m compiler.jocky.cli replay runs/run_01

# 7. Compare performance metrics: Naive vs Optimized
python -m compiler.jocky.cli run examples/incident_42.jocky --dataset datasets/synthetic --mode naive --out runs/run_naive
```

> **Core Axiom:** *The paper defines the research. The MVP proves the research works as a robust, reproducible, and verifiable system.*
