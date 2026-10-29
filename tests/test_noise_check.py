"""The fix for the held-out v1 failures: a noise check, and list_events that says
when it is truncated and can filter by host.

The noise check is data, not a verdict: the rule that uses it lives in
.claude/skills/disambiguate-hypotheses/pairs.md. These tests check the signal
separates attack hosts from benign noise on all three stub days. That is a check
on the signal, not on the agent; the agent is measured by the live eval.
"""

import pytest

from src.agent.store import SCENARIO_DIRS, DetectionStore
from src.agent.tools import DETECTOR_FALSE_POSITIVE_RATE, MAX_EVENTS_LISTED, InvestigationSession

NOISE_MULTIPLE = 3    # pairs.md, Step 0: under 3x the false-positive rate is noise

ATTACK_HOSTS = {"dev": ["10.0.3.57", "10.0.5.14", "10.0.8.23"],
                "heldout": ["172.16.12.40", "172.16.30.8", "172.16.22.9"],
                "heldout2": ["172.24.8.15", "172.24.12.30", "172.24.30.7"]}
BENIGN_HOSTS = {"dev": ["10.0.9.200"],
                "heldout": ["192.168.40.15", "192.168.20.5"],
                "heldout2": ["192.168.205.20", "192.168.201.53"]}


def session(name: str) -> InvestigationSession:
    d = SCENARIO_DIRS[name]
    return InvestigationSession(DetectionStore.load(d / "flows.jsonl", d / "meta.json"))


def frac(s: InvestigationSession, host: str) -> float:
    return s.get_host_activity(host)["noise_check"]["suspicious_fraction_in_active_windows"]


def times_rate(s: InvestigationSession, host: str) -> float:
    return s.get_host_activity(host)["noise_check"]["times_false_positive_rate"]


@pytest.mark.parametrize("name", ["dev", "heldout", "heldout2"])
def test_noise_check_separates_attacks_from_benign_noise(name):
    s = session(name)
    for h in ATTACK_HOSTS[name]:
        assert times_rate(s, h) >= NOISE_MULTIPLE, h
    for h in BENIGN_HOSTS[name]:
        assert times_rate(s, h) < NOISE_MULTIPLE, h


def test_busy_worm_stays_on_the_attack_side():
    # the case most likely to be wrongly dismissed by the noise rule
    s = session("heldout2")
    assert times_rate(s, "172.24.8.15") >= NOISE_MULTIPLE and frac(s, "172.24.8.15") < 0.8


def test_noise_check_reports_the_reference_rate():
    n = session("dev").get_host_activity("10.0.9.200")["noise_check"]
    assert n["detector_false_positive_rate"] == DETECTOR_FALSE_POSITIVE_RATE
    assert n["times_false_positive_rate"] == pytest.approx(
        n["suspicious_fraction_in_active_windows"] / DETECTOR_FALSE_POSITIVE_RATE, abs=0.1)


def test_a_store_with_its_own_baseline_uses_it():
    """An uploaded capture carries its own false-positive estimate; the same flagged
    share is then read against that rate, not UNSW's 6.9%."""
    from src.agent.store import FlowRecord
    flows = [FlowRecord(f"f{i}", "10.1.1.1", "10.1.1.2", 80, 100.0 + i,
                        0.95 if i < 3 else 0.01, {"exploits": 1.0}) for i in range(30)]
    shared = {"threshold": 0.85}
    default = InvestigationSession(DetectionStore(flows, dict(shared)))
    own = InvestigationSession(DetectionStore(flows, {**shared, "false_positive_rate": 0.002,
                                                      "false_positive_rate_source": "estimated"}))
    a = default.get_host_activity("10.1.1.1")["noise_check"]
    b = own.get_host_activity("10.1.1.1")["noise_check"]
    assert a["suspicious_fraction_in_active_windows"] == b["suspicious_fraction_in_active_windows"] == 0.1
    assert a["times_false_positive_rate"] < NOISE_MULTIPLE          # 10% vs 6.9%: noise
    assert b["times_false_positive_rate"] >= NOISE_MULTIPLE         # 10% vs 0.2%: not noise
    assert b["false_positive_rate_source"] == "estimated" and b["flagged_expected_by_chance"] == 0.1
    assert "0.20%" in b["how_to_read"]


def test_list_events_says_when_it_is_truncated():
    s = session("heldout")
    out = s.list_events(limit=200, min_suspicious=1)
    assert out["returned"] == min(out["total_events"], MAX_EVENTS_LISTED)
    assert out["truncated"] == (out["total_events"] > MAX_EVENTS_LISTED)
    small = s.list_events(limit=3)
    assert small["truncated"] and "source=" in small["note"]


def test_list_events_filters_by_source():
    out = session("heldout").list_events(limit=25, min_suspicious=1, source="192.168.20.5")
    assert out["events"] and {e["source"] for e in out["events"]} == {"192.168.20.5"}
    assert not out["truncated"]
