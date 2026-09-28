"""`jocky` command-line interface.

    jocky check    FILE                      validate (syntax, semantics, evidence types)
    jocky compile  FILE [--emit ...] [--out DIR] [--policy P --targets A,B]
    jocky run      FILE --dataset DIR [--mode optimized|naive] [--out DIR] [--at TIME]
    jocky replay   RUN_DIR
    jocky keygen   --out KEY.pem
    jocky verify-contract CONTRACT.json [--pubkey B64]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ast import to_json
from .capabilities import evaluate_all, load_policy
from .compiler import compile_source
from .contract import generate_key, key_id, load_or_create_key, public_key_from_b64, save_private_key, verify
from .errors import CompileError


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def cmd_check(args) -> int:
    src = _read(args.file)
    try:
        comp = compile_source(src)
    except CompileError as e:
        print(e.render(src, args.file), file=sys.stderr)
        return 1
    for w in comp.warnings:
        print(w.render(src, args.file), file=sys.stderr)
    print(f"ok: {comp.ir['investigation']['name']} - {len(comp.ir['nodes'])} IR nodes, "
          f"{len(comp.analysis.bindings)} bindings")
    for name, t in comp.analysis.bindings.items():
        print(f"  {name}: {t.render()}")
    return 0


def cmd_compile(args) -> int:
    src = _read(args.file)
    try:
        comp = compile_source(src)
    except CompileError as e:
        print(e.render(src, args.file), file=sys.stderr)
        return 1
    for w in comp.warnings:
        print(w.render(src, args.file), file=sys.stderr)
    outputs = {
        "ast": to_json(comp.program),
        "ir": comp.ir,
        "plan": comp.plans.get("optimized"),
        "naive": comp.plans.get("naive"),
        "caps": {m: p["capabilities"] for m, p in comp.plans.items()},
    }
    if args.policy:
        targets = args.targets.split(",") if args.targets else (comp.ir["investigation"]["targets"] or [])
        policy = load_policy(args.policy)
        outputs["policy"] = {
            m: [d.to_json() for d in evaluate_all(policy, targets, p["capabilities"]["required"])]
            for m, p in comp.plans.items()
        }
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for name, value in outputs.items():
            (out / f"{name}.json").write_text(_dump(value), encoding="utf-8")
        print(f"wrote {', '.join(outputs)} to {out}")
    emit = args.emit.split(",") if args.emit else ["caps"] + (["policy"] if args.policy else [])
    for name in emit:
        print(f"== {name}")
        print(_dump(outputs[name]))
    if args.policy and any(d["decision"] == "REJECT" for d in outputs["policy"]["optimized"]):
        return 3
    return 0


def cmd_run(args) -> int:
    from .runtime.local import run_offline

    key = load_or_create_key(args.key) if args.key else generate_key()
    src = _read(args.file)
    try:
        res = run_offline(src, args.dataset, key=key, mode=args.mode, host=args.host,
                          anchor=args.at, out_dir=args.out)
    except CompileError as e:
        print(e.render(src, args.file), file=sys.stderr)
        return 1
    s = res["summary"]
    print(f"{s['investigation']} [{s['mode']}] window {s['window']['from']} .. {s['window']['to']}"
          if s["window"] else f"{s['investigation']} [{s['mode']}] (no window)")
    st = s["endpoint_stats"]
    print(f"endpoint: {st['records']} records, {st['bytes']} bytes, {st['wall_ms']} ms wall, {st['cpu_ms']} ms cpu")
    for sid, x in st["streams"].items():
        print(f"  {sid:<14} scanned={x['scanned']:<7} time={x['after_time']:<7} pred={x['after_predicate']:<7} "
              f"reduced={x['after_reduce']:<6} emitted={x['emitted']:<6} bytes={x['bytes']}")
    print(f"findings: {s['findings']}   digest: {s['digest']}")
    for f in res["findings"]:
        print(f"  [{f['severity']}] {f['finding_id']} host={f['host']} chains={len(f['chains'])} {f['title']}")
    if args.out:
        print(f"run written to {args.out}")
    return 0


def cmd_replay(args) -> int:
    from .replay import replay_run_dir

    res = replay_run_dir(args.run_dir, args.pubkey)
    print(_dump(res) if args.json else
          f"contract verified: {res['contract_verified']}\n"
          f"records checked:   {res['records_checked']} (tampered: {len(res['tampered_records'])})\n"
          f"original digest:   {res['original_digest']}\n"
          f"replay digest:     {res['replay_digest']}\n"
          f"result:            {'MATCH' if res['match'] else 'MISMATCH'}")
    return 0 if res["match"] else 4


def cmd_keygen(args) -> int:
    key = generate_key()
    save_private_key(key, args.out)
    print(f"wrote Ed25519 key {key_id(key)} to {args.out}")
    return 0


def cmd_verify_contract(args) -> int:
    env = json.loads(_read(args.contract))
    key = public_key_from_b64(args.pubkey or env["contract"]["issuer"]["public_key"])
    v = verify(env, key, host=args.host)
    for c in v.checks:
        print(f"  [{'ok' if c['passed'] else 'FAIL'}] {c['check']}: {c['detail']}")
    print("VALID" if v.ok else "INVALID")
    return 0 if v.ok else 5


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="jocky", description="JOCKY forensic investigation compiler")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check")
    p.add_argument("file")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("compile")
    p.add_argument("file")
    p.add_argument("--emit", help="comma list of: ast, ir, plan, naive, caps, policy")
    p.add_argument("--out")
    p.add_argument("--policy")
    p.add_argument("--targets")
    p.set_defaults(fn=cmd_compile)

    p = sub.add_parser("run")
    p.add_argument("file")
    p.add_argument("--dataset", required=True)
    p.add_argument("--mode", default="optimized", choices=["optimized", "naive"])
    p.add_argument("--host", default="OFFLINE-01")
    p.add_argument("--at", help="anchor time for relative windows (default: dataset reference_time)")
    p.add_argument("--key", help="Ed25519 signing key (created if missing); ephemeral if omitted")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("replay")
    p.add_argument("run_dir")
    p.add_argument("--pubkey")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_replay)

    p = sub.add_parser("keygen")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("verify-contract")
    p.add_argument("contract")
    p.add_argument("--pubkey")
    p.add_argument("--host")
    p.set_defaults(fn=cmd_verify_contract)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
