"""The per-capture false-positive baseline (src/ingest/baseline.py).

Synthetic hosts with a known benign flag rate: the estimator should recover it
with attack sources present, not trim ordinary benign hosts, and stay finite
when nothing is flagged."""

import numpy as np
import pandas as pd
import pytest

from src.ingest.baseline import estimate_baseline, host_noise_calls


def _hosts(rng, n_benign=50, flows=500, rate=0.002, attackers=((300, 0.6),)):
    src, alert = [], []
    for i in range(n_benign):
        src += [f"10.0.0.{i}"] * flows
        alert += list(rng.random(flows) < rate)
    for j, (n, share) in enumerate(attackers):
        src += [f"175.45.176.{j}"] * n
        alert += list(rng.random(n) < share)
    return src, alert


def test_recovers_the_benign_rate_with_attackers_present():
    rng = np.random.default_rng(0)
    src, alert = _hosts(rng, attackers=((300, 0.6), (1000, 0.3), (200, 0.9)))
    est = estimate_baseline(src, alert)
    assert est["rate"] == pytest.approx(0.002, rel=0.5)
    assert est["hosts_trimmed"] == 3
    assert {h["host"] for h in est["top_trimmed"]} == {"175.45.176.0", "175.45.176.1", "175.45.176.2"}
    assert est["ci95"][0] < est["rate"] < est["ci95"][1]
    pooled = np.mean(alert)
    assert pooled > 5 * est["rate"]          # the attackers would have inflated a pooled rate


def test_does_not_trim_ordinary_benign_hosts():
    rng = np.random.default_rng(1)
    src, alert = _hosts(rng, rate=0.05, attackers=())
    est = estimate_baseline(src, alert)
    assert est["hosts_trimmed"] <= 1             # at alpha=1e-3, ~0.05 false trims expected
    assert est["rate"] == pytest.approx(0.05, rel=0.15)


def test_nothing_flagged_gives_a_small_positive_rate():
    est = estimate_baseline(["a"] * 100 + ["b"] * 100, [False] * 200)
    assert 0 < est["rate"] < 0.01


def test_small_capture_falls_back_to_all_hosts():
    est = estimate_baseline(["a", "a", "b"], [True, False, False])
    assert est["hosts_used"] + est["hosts_trimmed"] == 2 and est["rate"] > 0


def test_host_noise_calls_follow_step_0():
    # one host with a burst of 6 flagged flows among 10 in a window, one benign host
    df = pd.DataFrame({
        "source": ["atk"] * 10 + ["ok"] * 100,
        "ts": [100.0 + i for i in range(10)] + [100.0 + i for i in range(100)],
        "alert": [True] * 6 + [False] * 4 + [True] * 5 + [False] * 95})
    calls = host_noise_calls(df, rate=0.069)
    assert calls.loc["atk", "noise"] == False      # 60% vs 6.9%: about 8.7x
    assert calls.loc["ok", "noise"] == True        # 5% vs 6.9%
    strict = host_noise_calls(df, rate=0.002)
    assert strict.loc["ok", "noise"] == False      # the same 5% is 25x a 0.2% baseline


def test_truth_separates_innocent_hosts_from_attackers_normal_flows():
    """The first validation counted every normal-labelled flow. Attack hosts also
    send normal-labelled flows, and on the 17-2-2015 captures those carried every
    flagged 'benign' flow; the noise check needs innocent hosts only."""
    from src.ingest.baseline import truth_rates
    m = pd.DataFrame({
        "srcip":   ["atk"] * 10 + ["ok1"] * 50 + ["ok2"] * 50,
        "u_label": [1] * 6 + [0] * 4 + [0] * 100,          # atk: 6 attack + 4 normal-labelled
        "alert":   [True] * 6 + [True, True, False, False] + [False] * 99 + [True]})
    t = truth_rates(m)
    assert t["attack_hosts"] == ["atk"]
    assert t["innocent_flows"] == 100 and t["innocent_flagged"] == 1 and t["innocent_rate"] == 0.01
    assert t["benign_from_attack_hosts_rate"] == 0.5
    assert t["benign_labelled_rate"] == pytest.approx(3 / 104, abs=1e-6)   # the old reference


@pytest.mark.parametrize("true,upper,a,b", [
    (0.0, 0.00007, True, True),      # nothing flagged, small upper bound: pass
    (0.001, 0.0018, True, True),     # within 2x
    (0.001, 0.0005, False, True),    # upper below truth: too strict
    (0.001, 0.0030, True, False),    # 3x and beyond the 0.05-point slack: too lenient
    (0.0, 0.0006, True, False),      # slack is 0.05 points, not more
])
def test_rule_v2_edges(true, upper, a, b):
    from src.ingest.baseline import rule_v2
    r = rule_v2(true, upper)
    assert (r["a_not_too_strict"], r["b_not_too_lenient"], r["pass"]) == (a, b, a and b)


def test_upper_bound_is_reported_and_conservative():
    est = estimate_baseline(["a"] * 30000 + ["b"] * 5000, [False] * 35000)
    assert est["rate"] < est["rate_upper"] < 0.0002           # 0 of 35k: at most ~0.007%
    assert est["rate_upper"] == est["ci95"][1]
