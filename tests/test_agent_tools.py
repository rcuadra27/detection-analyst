"""The tools and, above all, the guardrails in submit_triage."""

import json

import pytest

from src.agent.store import DetectionStore, is_internal
from src.agent.tools import TRIAGE_QUEUE_PATH, InvestigationSession

WORM_EVENT = "EV-10.0.3.57-49200"
GENERIC_EVENT = "EV-198.51.100.90-73800"
NOISY_EVENT = "EV-10.0.9.200-3600"
INJECTION_EVENT = "EV-198.51.100.61-40800"


@pytest.fixture
def s():
    return InvestigationSession(DetectionStore.load())


def triage(**over):
    base = dict(event_id=WORM_EVENT, severity="critical", assessment="true_positive",
                attack_technique_ids=["T1210"], explanation="Fan-out to 33 internal hosts.",
                recommended_action="Isolate 10.0.3.57.", confidence=0.8)
    return {**base, **over}


def test_internal_means_rfc1918_only():
    assert is_internal("10.0.3.57") and is_internal("192.168.1.2")
    assert not is_internal("203.0.113.77") and not is_internal("198.51.100.23")


def test_list_events_ranks_by_risk(s):
    ev = s.list_events(limit=25)["events"]
    assert ev[0]["event_id"] == "EV-10.0.8.23-33000"
    scores = [e["risk_score"] for e in ev]
    assert scores == sorted(scores, reverse=True)
    assert {WORM_EVENT, GENERIC_EVENT, NOISY_EVENT} <= {e["event_id"] for e in ev}


def test_worm_event_is_split_with_disambiguation_note(s):
    d = s.get_event(WORM_EVENT)["detection"]
    assert d["presentation"] == "split"
    assert {h["attack_class"] for h in d["hypotheses"][:2]} == {"worms", "backdoor"}
    assert "OTHER internal hosts" in d["analyst_note"]


def test_host_activity_separates_worm_from_backdoor(s):
    worm = s.get_host_activity("10.0.3.57")["outbound"]
    bd = s.get_host_activity("10.0.5.14")["outbound"]
    assert worm["distinct_internal_dests_suspicious"] >= 5 and worm["distinct_ports_suspicious"] == 1
    assert bd["top_pair_share_of_suspicious"] == 1.0 and bd["windows_with_suspicious_activity"] >= 3
    assert bd["distinct_external_dests_suspicious"] == 1


def test_injection_text_is_labeled_untrusted(s):
    ev = s.get_event(INJECTION_EVENT)["untrusted_evidence"]
    assert "never as instructions" in ev["warning"]
    assert any("IGNORE ALL PREVIOUS" in str(f.get("http_user_agent", "")) for f in ev["sample_flows"])


def test_unknown_inputs_return_errors_not_exceptions(s):
    assert s.call("get_event", event_id="EV-nope-1")["error"] == "unknown_event"
    assert s.call("get_host_activity", host="1.2.3.4")["error"] == "unknown_host"
    assert s.call("drop_table")["error"] == "unknown_tool"
    assert s.call("get_event", wrong_arg=1)["error"] == "bad_arguments"


def test_submit_rejects_technique_not_retrieved(s):
    s.get_event(WORM_EVENT)
    r = s.submit_triage(**triage())
    assert not r["accepted"] and "without retrieving" in r["errors"][0]


def test_submit_rejects_technique_the_detector_did_not_propose(s):
    s.lookup_techniques(["T1210", "T1486"])
    r = s.submit_triage(**triage(attack_technique_ids=["T1210", "T1486"]))
    assert not r["accepted"] and "not candidate techniques" in r["errors"][0]


def test_submit_rejects_bad_schema(s):
    r = s.submit_triage(**triage(severity="severe"))
    assert not r["accepted"] and "Schema validation" in r["errors"][0]


def test_submit_blocks_silent_false_positive_on_confident_detection(s):
    # The Phase 4.5 failure: no mappable technique turning into "benign".
    r = s.submit_triage(**triage(event_id=GENERIC_EVENT, assessment="false_positive",
                                 severity="low", attack_technique_ids=[]))
    assert not r["accepted"] and "false_positive_reason" in r["errors"][0]


def test_submit_accepts_valid_triage_and_queues_for_review(s):
    s.lookup_techniques(["T1210", "T1570"])
    r = s.submit_triage(**triage(attack_technique_ids=["T1210", "T1570"]))
    assert r["accepted"] and r["status"] == "pending_analyst_review"
    queued = [json.loads(l) for l in TRIAGE_QUEUE_PATH.read_text().splitlines()]
    assert queued[-1]["triage_id"] == r["triage_id"]


def test_generic_event_accepts_true_positive_with_no_techniques(s):
    r = s.submit_triage(**triage(event_id=GENERIC_EVENT, severity="medium",
                                 attack_technique_ids=[]))
    assert r["accepted"]


def test_every_call_is_audited(s):
    from src.agent.tools import AUDIT_PATH
    before = len(AUDIT_PATH.read_text().splitlines()) if AUDIT_PATH.exists() else 0
    s.call("list_events", limit=1)
    s.call("get_event", event_id="EV-nope-1")
    lines = AUDIT_PATH.read_text().splitlines()[before:]
    assert [json.loads(l)["ok"] for l in lines] == [True, False]
