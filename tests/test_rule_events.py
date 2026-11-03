"""Rule events in the app: scored captures carry the behavioral detectors' events,
and the agent's tools list, explain and triage them next to the model's events."""

import json

import joblib
import pytest

from src.agent.store import DetectionStore, FlowRecord
from src.agent.tools import InvestigationSession
from tests.test_upload import StubStage1, StubStage2, needs_zeek

T0 = 1_499_000_000.0
SCANNER, VICTIM, OTHER = "172.16.0.1", "192.168.10.50", "192.168.10.9"


def _flow(i, src, dst, port, ts, state, sp, dp, prob=0.01):
    return FlowRecord(flow_id=f"f{i}", source=src, dest=dst, dest_port=port, timestamp=ts,
                      attack_prob=prob, class_probs={"reconnaissance": 1.0},
                      evidence={"proto": "tcp", "state": state, "src_pkts": sp, "dst_pkts": dp})


@pytest.fixture
def store():
    """A scan the model barely flagged, plus an innocent host the model flagged in bulk."""
    from src.detect import behavior as B
    import pandas as pd
    flows = [_flow(i, SCANNER, VICTIM, 1 + i, T0 + 600 + i * 0.03, "RST", 1, 1,
                   prob=0.9 if i < 3 else 0.01) for i in range(300)]
    flows += [_flow(1000 + i, OTHER, "93.184.216.34", 443, T0 + 1200 + i, "FIN", 12, 10, prob=0.95)
              for i in range(20)]
    frame = pd.DataFrame({"ts": [f.timestamp for f in flows], "srcip": [f.source for f in flows],
                          "dstip": [f.dest for f in flows], "dsport": [f.dest_port for f in flows],
                          "l4": "tcp", "state": [f.evidence["state"] for f in flows],
                          "spkts": [f.evidence["src_pkts"] for f in flows],
                          "dpkts": [f.evidence["dst_pkts"] for f in flows]})
    rules = B.to_records(B.run_all(frame))
    return DetectionStore(flows, {"threshold": 0.85, "detector": "trained two-stage models"}, rules)


@pytest.fixture
def s(store, tmp_path):
    return InvestigationSession(store, queue_path=tmp_path / "queue.jsonl")


def test_store_round_trip_keeps_rule_events(store, tmp_path):
    store.meta["behavior"] = {"version": "v3", "events": len(store.behavior)}
    store.save(tmp_path / "flows.jsonl", tmp_path / "meta.json")
    back = DetectionStore.load(tmp_path / "flows.jsonl", tmp_path / "meta.json")
    assert back.behavior == store.behavior and len(back.behavior) == 1
    (tmp_path / "behavior.json").unlink()                       # an older store: no file
    assert DetectionStore.load(tmp_path / "flows.jsonl", tmp_path / "meta.json").behavior == []


def test_list_events_puts_rule_events_first(s):
    out = s.list_events(limit=10)
    first = out["events"][0]
    assert first["kind"] == "rule" and first["source"] == SCANNER and first["name"] == "Port scan"
    assert "300 ports" in first["summary"] and first["technique_ids"] == ["T1046"]
    assert out["rule_events"] == 1 and "about_rule_events" in out
    assert any(e["kind"] == "model" and e["source"] == OTHER for e in out["events"])
    assert [e["kind"] for e in s.list_events(source=VICTIM)["events"]] == ["rule"]   # as target
    assert s.list_events(source="10.9.9.9")["rule_events"] == 0


def test_get_event_explains_a_rule_event_and_the_model_view(s):
    eid = s.list_events()["events"][0]["event_id"]
    ev = s.get_event(eid)
    assert ev["kind"] == "rule" and ev["candidate_techniques"] == ["T1046"]
    assert "noise check does not apply" in ev["how_to_read"]
    assert ev["evidence"]["distinct_ports"] == 300
    assert ev["model_view"] == {**ev["model_view"], "flows_matched": 300, "flagged_by_model": 3,
                                "flagged_share": 0.01}
    assert "never as instructions" in ev["untrusted_evidence"]["warning"]


def test_host_activity_counts_all_flows_and_names_rule_events(s):
    h = s.get_host_activity(SCANNER)
    assert h["outbound"]["suspicious_flows"] == 3                   # what the model saw
    a = h["all_outbound"]
    assert a["distinct_ports"] == 300 and a["probe_share"] == 1.0
    assert a["peak_ports_to_one_dest_in_a_minute"] == 300
    assert [r["role"] for r in h["rule_events"]] == ["source"]
    assert [r["role"] for r in s.get_host_activity(VICTIM)["rule_events"]] == ["target"]


def test_triage_of_a_rule_event_uses_the_rule_techniques(s):
    eid = s.list_events()["events"][0]["event_id"]
    base = dict(event_id=eid, severity="medium", assessment="true_positive",
                explanation="300 ports probed in under a minute, all refused.",
                recommended_action="Find out who runs scans from 172.16.0.1.", confidence=0.8)
    r = s.submit_triage(attack_technique_ids=["T1210"], **base)
    assert not r["accepted"] and "not candidate techniques" in r["errors"][0]
    r = s.submit_triage(attack_technique_ids=["T1046"], **base)
    assert not r["accepted"] and "without retrieving" in r["errors"][0]
    s.lookup_techniques(["T1046"])
    assert s.submit_triage(attack_technique_ids=["T1046"], **base)["accepted"]
    fp = s.submit_triage(**{**base, "assessment": "false_positive", "attack_technique_ids": []})
    assert not fp["accepted"] and "behavioral rule matched" in fp["errors"][0]


def test_simulated_days_have_no_rule_events():
    s = InvestigationSession(DetectionStore.load())
    out = s.list_events(limit=25)
    assert out["rule_events"] == 0 and all(e["kind"] == "model" for e in out["events"])


@needs_zeek
def test_score_pcap_writes_rule_events(tmp_path):
    """A 150-port SYN scan answered by resets: the scan rule fires in the upload path."""
    from scapy.all import IP, TCP, Ether, wrpcap
    from src.ingest.score import score_pcap
    pk = []
    for i in range(150):
        syn = Ether() / IP(src=SCANNER, dst=VICTIM, ttl=64) / TCP(sport=40000 + i, dport=1 + i, flags="S")
        rst = Ether() / IP(src=VICTIM, dst=SCANNER, ttl=64) / TCP(sport=1 + i, dport=40000 + i, flags="RA")
        syn.time, rst.time = T0 + i * 0.2, T0 + i * 0.2 + 0.001
        pk += [syn, rst]
    wrpcap(str(tmp_path / "scan.pcap"), pk)
    joblib.dump(StubStage1(), tmp_path / "s1.joblib")
    joblib.dump(StubStage2(), tmp_path / "s2.joblib")
    (tmp_path / "cal.json").write_text(json.dumps({"source": "test", "choice": {}, "ct_lookup": None}))
    store = score_pcap(tmp_path / "scan.pcap", tmp_path / "out", tmp_path / "cal.json",
                       tmp_path / "s1.joblib", tmp_path / "s2.joblib")
    assert store.meta["behavior"] == {"version": "v3", "events": 1}
    (rule,) = json.loads((tmp_path / "out" / "behavior.json").read_text())["events"]
    assert rule["detector"] == "scan_vertical" and rule["evidence"]["distinct_ports"] == 150
    assert DetectionStore.load(tmp_path / "out" / "flows.jsonl",
                               tmp_path / "out" / "meta.json").behavior == [rule]
