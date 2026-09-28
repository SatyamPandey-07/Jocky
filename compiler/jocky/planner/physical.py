"""Physical planning (compiler layer C6).

Lowers each logical endpoint stream into a collector-specific operation for
every platform:

    observe Process  ->  windows: WindowsProcessCollector
                         linux:   LinuxProcessCollector
                         offline: OfflineProcessCollector   (JSON / JSONL / CSV)

The endpoint operators (time bound, predicate, reduction, projection) are
platform-independent and executed by the agent runtime after collection; the
collector params below describe collector-level work each platform can
avoid (e.g. skipping files outside the time bound before attribution, or
hashing only the files that survive the predicate).
"""
from __future__ import annotations

from ..canonical import digest
from ..capabilities.infer import plan_capabilities
from ..optimizer.rules import optimize, predicate_fields
from ..version import PLAN_FORMAT

PLATFORMS = ("windows", "linux", "offline")

COLLECTORS: dict[str, dict[str, tuple[str, dict]]] = {
    "windows": {
        "Process": ("WindowsProcessCollector", {"api": "process snapshot (sysinfo / NtQuerySystemInformation)"}),
        "File": ("WindowsFileCollector", {"api": "directory walk + creation time", "attribution": "restart-manager"}),
        "NetworkConnection": ("WindowsNetworkCollector",
                              {"api": "GetExtendedTcpTable/GetExtendedUdpTable (owner-module)",
                               "time_source": "socket create timestamp"}),
        "User": ("WindowsUserCollector", {"api": "local accounts (sysinfo)"}),
        "Event": ("WindowsEventCollector", {"api": "EvtQuery", "channels": ["System", "Application"]}),
    },
    "linux": {
        "Process": ("LinuxProcessCollector", {"api": "procfs"}),
        "File": ("LinuxFileCollector", {"api": "directory walk + statx birth time", "attribution": "procfs-fd"}),
        "NetworkConnection": ("LinuxNetworkCollector",
                              {"api": "/proc/net/{tcp,tcp6,udp,udp6} + fd inode map", "time_source": "observed"}),
        "User": ("LinuxUserCollector", {"api": "/etc/passwd"}),
        "Event": ("LinuxEventCollector", {"api": "syslog files"}),
    },
    "offline": {
        e: (f"Offline{e}Collector", {"api": "dataset manifest (json | jsonl | csv)"})
        for e in ("Process", "File", "NetworkConnection", "User", "Event")
    },
}


def lower_stream(platform: str, stream: dict) -> dict:
    name, base = COLLECTORS[platform][stream["entity"]]
    params = dict(base)
    if stream.get("time"):
        params["time_prune"] = True
    if stream["entity"] == "File":
        wants_hash = stream.get("fields") is None or "sha256" in (stream.get("fields") or [])
        pred_uses_hash = "sha256" in predicate_fields(stream.get("predicate"))
        params["hash"] = "none" if not wants_hash and not pred_uses_hash else (
            "before-filter" if pred_uses_hash else "after-filter")
    return {"stream": stream["id"], "collector": name, "params": params}


def physical_plan(ir: dict, mode: str = "optimized") -> dict:
    opt = optimize(ir, mode)
    platforms = {p: {"collectors": [lower_stream(p, s) for s in opt["streams"]]} for p in PLATFORMS}
    plan = {
        "format": PLAN_FORMAT,
        "mode": mode,
        "investigation": ir["investigation"]["name"],
        "ir_sha256": ir["ir_sha256"],
        "schema_version": ir["schema_version"],
        "streams": opt["streams"],
        "reduce_groups": opt["reduce_groups"],
        "central": opt["central"],
        "outputs": {
            "emit": [c["id"] for c in opt["central"] if c["op"] == "emit"],
            "preserve": [c["id"] for c in opt["central"] if c["op"] == "preserve"],
        },
        "platforms": platforms,
        "rewrites": opt["rewrites"],
    }
    plan["capabilities"] = plan_capabilities(opt["streams"], opt["central"])
    plan["plan_sha256"] = digest(plan)
    return plan
