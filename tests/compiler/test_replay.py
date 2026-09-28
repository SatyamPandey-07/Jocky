import json

from jocky.replay import replay_run_dir
from jocky.runtime.local import run_offline


def test_replay_matches_and_detects_tampering(incident42_source, lab_dataset, signing_key, tmp_path):
    run = tmp_path / "run"
    res = run_offline(incident42_source, lab_dataset, key=signing_key, out_dir=run)
    assert res["summary"]["findings"] == 2

    ok = replay_run_dir(run)
    assert ok["match"] and ok["contract_verified"] and not ok["tampered_records"]

    # Alter one frozen evidence record: its hash no longer verifies -> MISMATCH
    path = run / "evidence" / "s_beacons.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["fields"]["remote_port"] = 80
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    bad = replay_run_dir(run)
    assert not bad["match"] and bad["tampered_records"] == [rec["evidence_id"]]


def test_provenance_reaches_contract(incident42_source, lab_dataset, signing_key):
    res = run_offline(incident42_source, lab_dataset, key=signing_key)
    f = res["findings"][0]
    prov = res["provenance"][f["finding_id"]]
    assert prov["derived"][0]["links"][0]["alias"] == "shells"
    assert {e["collector"]["name"] for e in prov["evidence"]} == {
        "OfflineProcessCollector", "OfflineFileCollector", "OfflineNetworkConnectionCollector"}
    assert all(len(e["sha256"]) == 64 for e in prov["evidence"])
    assert prov["contract"]["plan_hash"] == res["contract"]["contract"]["plan_hash"]
    assert prov["contract"]["signature"]["algorithm"] == "Ed25519"
