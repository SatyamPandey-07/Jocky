"""Comparative evaluation benchmark (Section 5 & 14 of JOCKY build plan).

Measures and compares:
1. Naive execution: transfer full streams -> central filter -> correlate
2. Optimized execution: predicate pushdown + projection pushdown -> local reduce -> transfer -> correlate

Outputs:
- Total records scanned & transferred
- Total bytes transferred across the network
- CPU time & wall-clock latency
- Finding equivalence proof (verifying finding digests match 100%)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Add workspace root to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from compiler.jocky.canonical import utc_now
from compiler.jocky.contract.contract import load_or_create_key
from compiler.jocky.runtime.local import run_offline

KEY_PATH = Path("control-plane/benchmark_key.pem")


def run_benchmark(source_file: str, dataset_dir: str):
    source_p = Path(source_file)
    dataset_p = Path(dataset_dir)
    source_code = source_p.read_text(encoding="utf-8")
    signing_key = load_or_create_key(KEY_PATH)

    print("=" * 72)
    print(" JOCKY PERFORMANCE EVALUATION: PUSHDOWN OPTIMIZATION VS NAIVE")
    print("=" * 72)
    print(f"Investigation: {source_file}")
    print(f"Dataset:       {dataset_dir}")
    print("-" * 72)

    # 1. Run Optimized Plan
    print("[*] Running OPTIMIZED plan (predicate & projection pushdown)...")
    t0 = time.perf_counter()
    opt_run = run_offline(source_code, dataset_p, key=signing_key, mode="optimized")
    opt_time = (time.perf_counter() - t0) * 1000

    # 2. Run Naive Plan
    print("[*] Running NAIVE plan (unfiltered stream collection & central transfer)...")
    t1 = time.perf_counter()
    naive_run = run_offline(source_code, dataset_p, key=signing_key, mode="naive")
    naive_time = (time.perf_counter() - t1) * 1000

    opt_stats = opt_run["summary"]["endpoint_stats"]
    naive_stats = naive_run["summary"]["endpoint_stats"]

    opt_records = opt_stats.get("records", 0)
    naive_records = naive_stats.get("records", 0)

    opt_bytes = opt_stats.get("bytes", 0)
    naive_bytes = naive_stats.get("bytes", 0)

    bandwidth_saved_pct = (1.0 - (opt_bytes / max(naive_bytes, 1))) * 100
    records_saved_pct = (1.0 - (opt_records / max(naive_records, 1))) * 100
    speedup = naive_time / max(opt_time, 0.001)

    print("\n" + "=" * 72)
    print(" BENCHMARK RESULTS MATRIX")
    print("=" * 72)
    print(f"{'Metric':<30} | {'Naive Plan':<18} | {'Optimized Plan':<18}")
    print("-" * 72)
    print(f"{'Records Transferred':<30} | {naive_records:<18,d} | {opt_records:<18,d}")
    print(f"{'Data Volume Transferred':<30} | {f'{naive_bytes / 1024 / 1024:.2f} MB':<18} | {f'{opt_bytes / 1024 / 1024:.2f} MB':<18}")
    print(f"{'Wall-clock Latency':<30} | {f'{naive_time:.2f} ms':<18} | {f'{opt_time:.2f} ms':<18}")
    print(f"{'Findings Correlated':<30} | {len(naive_run['findings']):<18} | {len(opt_run['findings']):<18}")
    print("-" * 72)
    print(f"[*] Bandwidth Reduction:     {bandwidth_saved_pct:.2f}%")
    print(f"[*] Records Reduction:       {records_saved_pct:.2f}%")
    print(f"[*] Execution Speedup:       {speedup:.2f}x")
    
    equivalent = opt_run["summary"]["digest"] == naive_run["summary"]["digest"]
    print(f"[+] Finding Equivalence:     {'PASSED: 100% MATCH (Digest Validated)' if equivalent else 'FAILED: MISMATCH'}")
    print("=" * 72)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JOCKY Benchmark Runner")
    parser.add_argument("--source", default="examples/incident_42.jocky", help="JOCKY source file")
    parser.add_argument("--dataset", default="datasets/synthetic", help="Telemetry dataset")
    args = parser.parse_args()
    run_benchmark(args.source, args.dataset)
