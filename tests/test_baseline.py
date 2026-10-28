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
