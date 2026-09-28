"""Multi-endpoint scenario setup for JOCKY.

Generates telemetry across multiple heterogeneous endpoints:
- WIN-01: Primary workstation (PowerShell drop + beacon attack path)
- WIN-02: Secondary workstation (Benign background administrative activity)
- UBUNTU-01: Linux application server (Web server + bash activity)
- OFFLINE-01: Forensic disk dump image
"""
from __future__ import annotations

import argparse
from pathlib import Path
from datasets.generate import generate_dataset


def setup_enterprise_scenario(out_dir: str | Path = "datasets/synthetic", seed: int = 42):
    out = Path(out_dir)
    print(f"[*] Setting up JOCKY multi-endpoint scenario in {out}...")
    
    generate_dataset(
        out_dir=out,
        reference_time="2026-09-28T12:00:00.000000Z",
        hosts=3,
        noise=1000,
        incidents=1,
        mode="synthetic",
        seed=seed,
    )
    print(f"[+] Enterprise scenario created successfully with WIN-01, WIN-02, and UBUNTU-01 telemetry.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate JOCKY enterprise investigation scenario")
    parser.add_argument("--out", default="datasets/synthetic", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()
    setup_enterprise_scenario(args.out, args.seed)
