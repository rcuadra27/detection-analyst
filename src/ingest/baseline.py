"""
Phase A — the detector's false-positive rate, estimated from the capture itself.

WHY: the agent's noise check asks whether a host's flagged share is more than
the detector flags on benign traffic by chance. Until now that rate was 6.9%,
measured on UNSW's official test split. On real captures scored through Zeek
the benign rate came out at 0.1-0.3% (parity runs 1-3). With 6.9% as the
reference, a host flagging 15% of its traffic would look like noise when it is
about a hundred times the real rate. So each uploaded capture gets its own
baseline.

HOW, without labels: most hosts in a capture are benign, and their flagged
share sits near the noise floor; attack sources concentrate flags. Starting
from the pooled flag rate over hosts with enough flows, drop every host whose
flag count is improbable under that rate (one-sided binomial test), recompute
the rate from the hosts that remain, and repeat until the kept set stops
changing. The result is the flag rate of hosts that look like chance.

Known ways this can be wrong (and why the validation below exists):
  - a capture where most active hosts are attackers (the trimmed set is then
    not benign)
  - benign services that the detector flags heavily (they are trimmed as if
    they were attackers, so the estimate comes out low and the noise check
    becomes stricter, never more lenient)

Usage (validation on labelled UNSW captures):
    python -m src.ingest.baseline --eval data/processed/ingest/1 data/processed/ingest/10 \
        data/processed/ingest/feb15 data/processed/ingest/feb20 \
        --unsw-csv data/raw/UNSW-NB15_[1-4].csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

MIN_FLOWS_PER_HOST = 20      # hosts with fewer flows say little about the rate
TRIM_ALPHA = 1e-3            # a host is trimmed when P(>= its flags | rate) < this
MAX_ITERATIONS = 25
NOISE_MULTIPLE = 3.0         # the skill's Step 0: under 3x the rate is consistent with noise
WINDOW_SECONDS = 300.0       # matches the correlation window and the noise check


def _rate(k: float, n: float) -> float:
    """Jeffreys estimate: never exactly 0, so ratios against it stay finite."""
    return (k + 0.5) / (n + 1.0)


def estimate_baseline(sources, alerts, min_flows: int = MIN_FLOWS_PER_HOST,
                      alpha: float = TRIM_ALPHA) -> dict:
    """Benign flag rate from per-flow (source host, flagged?) pairs, no labels."""
    from scipy.stats import beta, binom

    df = pd.DataFrame({"source": np.asarray(sources), "alert": np.asarray(alerts, dtype=bool)})
    if df.empty:
        return {"rate": None, "method": "no flows"}
    g = df.groupby("source")["alert"].agg(n="size", k="sum")
    hosts = g[g["n"] >= min_flows]
    if hosts.empty:          # small capture: use every host rather than nothing
        hosts = g
    n, k = hosts["n"].to_numpy(float), hosts["k"].to_numpy(float)
    keep = np.ones(len(hosts), dtype=bool)
    p = _rate(k.sum(), n.sum())
    iterations = 0
    for iterations in range(1, MAX_ITERATIONS + 1):
        p = _rate(k[keep].sum(), n[keep].sum())
        tail = binom.sf(k - 1, n, p)             # P(X >= k) for each host at rate p
        new_keep = tail >= alpha
        if not new_keep.any():                   # everything looks anomalous: stop trimming
            break
        if (new_keep == keep).all():
            break
        keep = new_keep
    kk, nn = k[keep].sum(), n[keep].sum()
    lo, hi = beta.ppf([0.025, 0.975], kk + 0.5, nn - kk + 0.5)
    trimmed = hosts[~keep].assign(share=lambda d: d["k"] / d["n"]).sort_values("k", ascending=False)
    return {
        "rate": round(float(p), 6),
        "ci95": [round(float(lo), 6), round(float(hi), 6)],
        "method": (f"flag rate of hosts consistent with chance: hosts with >= {min_flows} "
                   f"flows, hosts with improbable flag counts (binomial p < {alpha}) "
                   "trimmed iteratively"),
        "hosts_used": int(keep.sum()),
        "hosts_trimmed": int((~keep).sum()),
        "flows_used": int(nn),
        "flagged_in_used": int(kk),
        "iterations": iterations,
        "top_trimmed": [{"host": str(h), "flows": int(r["n"]), "flagged": int(r["k"]),
                         "share": round(float(r["share"]), 4)}
                        for h, r in trimmed.head(5).iterrows()],
    }


# ---------------------------------------------------------------- noise check

def host_noise_calls(df: pd.DataFrame, rate: float, min_suspicious: int = 5) -> pd.DataFrame:
    """The agent's Step 0 for every host that would raise an event.

    `df` has source, ts, alert. A host raises an event when some 5-minute window
    holds >= min_suspicious flagged flows (the correlation gate). Its noise share
    is flagged / all flows over the windows where it had flagged flows, as in
    get_host_activity. Noise when share < NOISE_MULTIPLE x rate.
    """
    d = df.assign(w=(df["ts"] // WINDOW_SECONDS).astype(int))
    per_w = d.groupby(["source", "w"])["alert"].agg(n="size", k="sum").reset_index()
    eventful = set(per_w.loc[per_w["k"] >= min_suspicious, "source"])
    active = per_w[(per_w["k"] > 0) & per_w["source"].isin(eventful)]
    h = active.groupby("source")[["n", "k"]].sum()
    h["share"] = h["k"] / h["n"]
    h["times_rate"] = h["share"] / rate
    h["noise"] = h["times_rate"] < NOISE_MULTIPLE
    return h


# ---------------------------------------------------------------- validation

def evaluate(capture_dirs: list[Path], unsw_csvs: list[str], calibration: Path,
             stage1: Path, threshold: float = 0.85, fixed_rate: float = 0.069) -> list[dict]:
    """Estimate vs truth on labelled UNSW captures (features.py output dirs)."""
    import joblib

    from src.ingest.features import UNSW_FEATURES, select
    from src.ingest.other import combine
    from src.ingest.parity import join, load_unsw_full
    from src.ingest.score import load_calibration

    cal = load_calibration(calibration)
    unsw = load_unsw_full(unsw_csvs)
    s1 = joblib.load(stage1)
    out = []
    for d in capture_dirs:
        base = pd.read_csv(d / "base.csv.gz", low_memory=False)
        pk = d / "other_packets.csv.gz"
        if pk.exists():
            base = combine(base, pd.read_csv(pk), cal["choice"]["other"])
        z = select(base, cal["choice"], cal["ct_lookup"])
        z["alert"] = s1.predict_proba(z[UNSW_FEATURES])[:, 1] >= threshold
        est = estimate_baseline(z["srcip"], z["alert"])

        m = join(z, unsw)
        benign = m[m["u_label"] == 0]
        true_rate = float(benign["alert"].mean()) if len(benign) else float("nan")

        # host truth: majority label of the host's matched flagged flows
        lab = m[m["alert"]].groupby("srcip")["u_label"].mean()
        res = {"capture": str(d), "flows": int(len(z)), "matched": int(len(m)),
               "true_benign_rate": round(true_rate, 6), "estimate": est,
               "ratio_to_true": round(est["rate"] / true_rate, 3) if true_rate > 0 else None,
               "noise_calls": {}}
        for name, rate in (("fixed_0.069", fixed_rate), ("estimated", est["rate"])):
            h = host_noise_calls(z.rename(columns={"srcip": "source"}), rate)
            h["attack"] = h.index.map(lambda s: bool(lab.get(s, 0) >= 0.5))
            res["noise_calls"][name] = {
                "event_hosts": int(len(h)),
                "attack_hosts_called_noise": int((h["attack"] & h["noise"]).sum()),
                "benign_hosts_called_not_noise": int((~h["attack"] & ~h["noise"]).sum()),
                "attack_hosts": int(h["attack"].sum()),
            }
            nc = res["noise_calls"][name]
            nc["misclassified"] = nc["attack_hosts_called_noise"] + nc["benign_hosts_called_not_noise"]
        out.append(res)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate the noise baseline estimator")
    ap.add_argument("--eval", nargs="+", type=Path, required=True,
                    help="features.py output dirs of labelled UNSW captures")
    ap.add_argument("--unsw-csv", nargs="+", required=True)
    ap.add_argument("--calibration", type=Path, default=Path("src/ingest/calibration.json"))
    ap.add_argument("--stage1", type=Path, default=Path("data/processed/stage1_binary.joblib"))
    ap.add_argument("--out", type=Path, default=Path("data/processed/baseline_eval.json"))
    a = ap.parse_args()
    res = evaluate(a.eval, a.unsw_csv, a.calibration, a.stage1)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=2))
    print(f"{'capture':<32} {'true':>8} {'estimate':>9} {'ratio':>6}   misclassified hosts (6.9% / estimated)")
    for r in res:
        f, e = r["noise_calls"]["fixed_0.069"], r["noise_calls"]["estimated"]
        print(f"{r['capture']:<32} {r['true_benign_rate']:>8.4f} {r['estimate']['rate']:>9.4f} "
              f"{r['ratio_to_true'] or float('nan'):>6.2f}   {f['misclassified']} / {e['misclassified']}"
              f"  (of {e['event_hosts']} event hosts, {e['attack_hosts']} attack)")
    print(f"[baseline] details: {a.out}")


if __name__ == "__main__":
    main()
