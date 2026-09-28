# JOCKY MVP Build Plan

> **Purpose:** Build a demonstrable JOCKY MVP from the research paper,
> while adding only the engineering needed to turn the research
> architecture into a usable prototype.
>
> **Rule:** The paper is the source of truth for research concepts. This
> file does not duplicate the paper. When a capability is already
> defined there, this plan references the relevant section instead of
> redefining it.

------------------------------------------------------------------------

## 0. MVP North Star

Prove one complete path:

``` text
Write one investigation
        ↓
Compile
        ↓
Validate evidence + capabilities
        ↓
Generate Forensic IR
        ↓
Optimize the plan
        ↓
Create execution contract
        ↓
Run on endpoints / offline evidence
        ↓
Collect normalized evidence
        ↓
Correlate
        ↓
Produce provenance-backed finding
        ↓
View / replay centrally
```

The MVP is successful when one JOCKY investigation can run against
Windows, Linux, and an offline/synthetic evidence source without
changing its logical source.

------------------------------------------------------------------------

## 1. Paper as the Source of Truth

Do not reimplement the research design from scratch.

  -----------------------------------------------------------------------
  Paper section                       Use it as the specification for
  ----------------------------------- -----------------------------------
  §IV --- The JOCKY Language          DSL semantics, running example,
                                      evidence-aware types

  §V --- Compiler Architecture        frontend, Forensic IR, capability
                                      inference, physical
                                      planning/optimization

  §VI --- Forensic Execution Contract contract, execution, preservation,
  / runtime                           provenance, replay

  §VII --- Evaluation                 evaluation methodology and metrics

  §IX --- Future Work                 features explicitly deferred from
                                      the MVP
  -----------------------------------------------------------------------

The paper already defines the conceptual architecture, eight MVP
primitives, five-entity schema, Windows/Linux collectors, and offline
JSON/CSV direction. This file only turns those ideas into an engineering
sequence.

------------------------------------------------------------------------

## 2. MVP Scope

### Must Have

**JOCKY DSL**

Implement the paper's MVP primitive set:

``` text
observe
filter
select
join
within
sequence
preserve
emit
```

Start with the paper's running scenario:

``` text
Process
  ↓
File creation
  ↓
Network connection
  ↓
Temporal correlation
  ↓
Preserve + emit
```

**Compiler**

``` text
Source
  ↓
Parser
  ↓
AST
  ↓
Semantic validation
  ↓
Evidence validation
  ↓
Capability inference
  ↓
Forensic IR
  ↓
Physical plan
```

**Execution**

Support three source types:

``` text
Windows
Linux
Offline JSON/CSV
```

Collectors can initially be small and read-only.

**Evidence**

Retain enough metadata to demonstrate:

-   source
-   host
-   collector/version
-   event/observation time
-   integrity hash
-   investigation/execution reference

**Central Control Plane**

Provide:

-   investigation creation
-   compilation
-   endpoint registration
-   execution dispatch
-   task status
-   evidence metadata
-   findings
-   audit history

**Dashboard**

Minimum screens:

1.  Investigations
2.  Compiler / IR
3.  Execution status
4.  Evidence / timeline
5.  Finding
6.  Provenance

------------------------------------------------------------------------

## 3. Engineering Additions

These are the practical components added around the paper's research
architecture.

### 3.1 Control Plane

**Recommended:**

-   FastAPI
-   PostgreSQL
-   WebSocket
-   Docker Compose

Responsibilities:

``` text
API
├── investigations
├── compilation
├── agents
├── execution
├── evidence
├── findings
└── audit
```

### 3.2 Endpoint Agent

**Recommended:** Rust.

``` text
JOCKY Agent
├── contract verifier
├── capability enforcement
├── task runner
├── evidence normalizer
├── Windows collectors
└── Linux collectors
```

The initial agent should be read-only.

### 3.3 Multi-Endpoint Orchestration

``` text
Investigation
    ↓
Control Plane
    ↓
Execution Contract
    ↓
Target selection
    ↓
Agent dispatch
    ↓
Results
```

Initial demo targets:

``` text
WIN-01
WIN-02
UBUNTU-01
```

### 3.4 Evidence Store

Use:

-   PostgreSQL for metadata, relationships and state
-   MinIO/S3-compatible storage for larger evidence objects

Do not add a graph database initially.

### 3.5 Authentication and Transport

Initial stack:

``` text
TLS
+
agent identity
+
signed execution contract
+
SHA-256 evidence hashes
+
capability policy
```

Add mTLS after basic agent communication works.

------------------------------------------------------------------------

## 4. Compiler Implementation Order

### C1 --- Parser

``` text
JOCKY source
    ↓
AST
```

Done when valid investigations parse and malformed syntax produces
useful errors.

### C2 --- Semantic Layer

Validate:

-   referenced variables exist
-   entity types are compatible
-   joins use valid keys
-   temporal expressions are valid
-   emitted values are valid

### C3 --- Evidence Layer

Follow the paper's evidence model:

``` text
Evidence<T>
Derived<T>
Finding<T>
```

Done when derived values and findings can be traced to their inputs.

### C4 --- Capability Inference

``` text
JOCKY Program
      ↓
Required capabilities
      ↓
Policy
      ↓
ALLOW / REJECT
```

Done when disallowed capabilities are rejected before execution.

### C5 --- Forensic IR

Use JSON initially.

``` json
{
  "op": "observe",
  "entity": "Process",
  "filter": {
    "image.name": "powershell.exe"
  }
}
```

Follow §V of the paper for IR semantics.

**Do not build MLIR/LLVM for the MVP.**

### C6 --- Physical Plan

Lower logical operations into collector-specific operations:

``` text
Logical:
observe Process

Windows:
WindowsProcessCollector

Linux:
LinuxProcessCollector

Offline:
JSONProcessCollector
```

------------------------------------------------------------------------

## 5. Optimizer

Only implement the optimizer behavior needed to demonstrate the paper's
idea.

Start with:

``` text
1. Predicate pushdown
2. Temporal pushdown
3. Projection pushdown
4. Basic join/semi-join reduction
```

Do not build a full distributed database optimizer initially.

Compare:

``` text
Naive:
collect → transfer → filter → correlate
```

against:

``` text
Optimized:
filter locally → reduce → transfer → correlate
```

Measure actual:

-   bytes transferred
-   execution time
-   CPU
-   records transferred
-   findings

Never present the paper's reported performance number as our own
measurement.

------------------------------------------------------------------------

## 6. Execution Contract

Minimum contract:

``` text
investigation ID
compiler version
IR/plan
target endpoints
required capabilities
resource limits
schema/version
plan hash
signature
```

Flow:

``` text
Compiler
   ↓
Physical plan
   ↓
Contract
   ↓
Hash
   ↓
Sign
   ↓
Dispatch
```

Agent:

``` text
Receive
  ↓
Verify
  ↓
Check policy
  ↓
Check capabilities
  ↓
Execute
```

------------------------------------------------------------------------

## 7. Evidence Pipeline

``` text
Collector
   ↓
Raw event
   ↓
Normalize
   ↓
Evidence object
   ↓
Hash
   ↓
Store
   ↓
Provenance link
```

Minimum entity types:

``` text
Process
File
NetworkConnection
User
Event
```

Use the paper's model as the semantic reference.

------------------------------------------------------------------------

## 8. Correlation Engine

Start with deterministic correlation.

Demo rule:

``` text
Process
  └── same PID
       ├── File creation
       └── Network connection

AND

events occur within N minutes
```

Output:

``` text
Finding
```

Every finding must point back to the evidence that produced it.

No AI is required for MVP.

------------------------------------------------------------------------

## 9. Dashboard

### Screen 1 --- Investigations

``` text
Incident #42
Status: Running
Targets: 3
Findings: 1
```

### Screen 2 --- Compiler

Show:

``` text
Source
AST
Capabilities
IR
Optimization
Contract
```

### Screen 3 --- Fleet

``` text
WIN-01      RUNNING
WIN-02      COMPLETE
UBUNTU-01   RUNNING
```

### Screen 4 --- Evidence

Show:

-   timeline
-   host
-   event type
-   collector
-   hash

### Screen 5 --- Finding

Show:

``` text
Process → File → Network
```

### Screen 6 --- Provenance

Show:

``` text
Finding
 ↓
Derived evidence
 ↓
Raw evidence
 ↓
Collector
 ↓
Host
 ↓
Execution Contract
```

------------------------------------------------------------------------

## 10. Replay

Implement after the basic execution loop works.

``` text
Frozen evidence
      ↓
Same investigation
      ↓
Same correlation
      ↓
Finding digest
```

Compare:

``` text
Original digest
Replay digest
```

Expected:

``` text
MATCH
```

------------------------------------------------------------------------

## 11. Recommended Stack

``` text
Language
    Custom JOCKY DSL

Compiler
    Python
    Tree-sitter

IR
    JSON

Backend / Control Plane
    FastAPI
    PostgreSQL
    MinIO

Endpoint Agent
    Rust

Agent Protocol
    gRPC + Protobuf

Frontend
    Next.js
    TypeScript
    Tailwind
    shadcn/ui

Realtime
    WebSocket

Security
    SHA-256
    Ed25519 signatures
    TLS / mTLS
    Capability policies

Deployment
    Docker Compose

CI
    GitHub Actions
```

------------------------------------------------------------------------

## 12. Repository Structure

``` text
jocky/
│
├── compiler/
│   ├── parser/
│   ├── ast/
│   ├── semantic/
│   ├── evidence/
│   ├── capabilities/
│   ├── ir/
│   ├── optimizer/
│   ├── planner/
│   └── contract/
│
├── agent/
│   ├── core/
│   ├── collectors/
│   ├── windows/
│   └── linux/
│
├── control-plane/
│   ├── api/
│   ├── services/
│   ├── models/
│   └── database/
│
├── dashboard/
│
├── schemas/
│
├── examples/
│   └── incident_42.jocky
│
├── tests/
│   ├── compiler/
│   ├── optimizer/
│   ├── agent/
│   └── integration/
│
├── docker-compose.yml
└── README.md
```

------------------------------------------------------------------------

## 13. Build Order

Do not build the frontend first.

### Milestone 1 --- Language

``` text
JOCKY source
    ↓
Parser
    ↓
AST
```

### Milestone 2 --- Compiler Core

``` text
AST
 ↓
Semantic checks
 ↓
Capabilities
 ↓
IR JSON
```

### Milestone 3 --- Offline Runtime

``` text
IR
 ↓
JSON/CSV evidence
 ↓
Execution
 ↓
Finding
```

This is the first real end-to-end milestone.

### Milestone 4 --- Optimizer

``` text
Logical IR
 ↓
Optimization
 ↓
Physical plan
```

Optimized and naive plans must produce equivalent findings.

### Milestone 5 --- Agent

``` text
Contract
 ↓
Rust agent
 ↓
Collector
 ↓
Evidence
```

Start with one platform.

### Milestone 6 --- Cross-platform

Add:

``` text
Windows
+
Ubuntu
```

using the same JOCKY source.

### Milestone 7 --- Control Plane

Add:

``` text
API
Database
Agent registration
Task dispatch
Evidence storage
```

### Milestone 8 --- Dashboard

Build the polished UI around the working pipeline.

### Milestone 9 --- Replay + Audit

Add:

``` text
hashes
provenance
contract verification
replay
```

### Milestone 10 --- Demo Hardening

Test:

``` text
JOCKY source
 ↓
Compile
 ↓
IR
 ↓
Optimize
 ↓
Contract
 ↓
3 endpoints
 ↓
Evidence
 ↓
Correlation
 ↓
Finding
 ↓
Provenance
 ↓
Replay
```

------------------------------------------------------------------------

## 14. Prototype Video Target

The final prototype should demonstrate one continuous scenario:

``` text
Investigator writes:

PowerShell
   ↓
File creation
   ↓
Network connection
   ↓
within 20 minutes

            ↓

JOCKY Compiler
            ↓
Capability Analysis
            ↓
Forensic IR
            ↓
Optimizer
            ↓
Signed Execution Contract
            ↓
WIN-01 ──┐
WIN-02 ──┼── Evidence
Linux ───┘
            ↓
Correlation
            ↓
Finding
            ↓
Provenance
            ↓
Replay
            ↓
Same Finding
```

The video should prove the **system flow**, not every research feature.

------------------------------------------------------------------------

## 15. Explicitly Deferred

Do not put these into the MVP backlog unless the core system is already
working:

-   MLIR dialect
-   LLVM backend
-   full WebAssembly backend
-   advanced cost-based distributed optimizer
-   Plaso/Volatility/KAPE adapters
-   Sigma import
-   Timesketch/STIX integrations
-   registry/ledger custody
-   AI investigation assistant
-   large-scale fleet infrastructure
-   advanced plugin ecosystem

These are already identified as longer-term directions in the paper's
future-work section.

------------------------------------------------------------------------

## 16. Security Boundary

JOCKY MVP is a **forensic investigation platform**, not an
endpoint-evasion framework.

Out of scope:

``` text
process injection
API unhooking
vulnerable-driver exploitation
EDR disabling
covert command-and-control
stealth/polymorphic malware execution
```

The paper explicitly places these outside its design and adopts
security-control cooperation instead.

------------------------------------------------------------------------

## 17. Definition of Done

The MVP is complete when:

``` text
1. Write JOCKY investigation
          ↓
2. Compiler validates it
          ↓
3. Capabilities are inferred
          ↓
4. Forensic IR is generated
          ↓
5. Physical plan is optimized
          ↓
6. Execution contract is created
          ↓
7. Endpoint/offline runtime executes
          ↓
8. Evidence is normalized + hashed
          ↓
9. Finding is correlated
          ↓
10. Finding has provenance
          ↓
11. Same investigation can be replayed
```

## Core principle

> **The paper defines the research. The MVP proves the research works as
> a system.**

When a component is already specified academically, return to the paper
section rather than creating a second competing specification.
