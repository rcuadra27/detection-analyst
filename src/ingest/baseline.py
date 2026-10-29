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
        # The highest rate consistent with what the kept hosts showed. Used as the
        # noise reference: with few or no flags a point estimate is falsely
        # precise, and erring high only makes the noise check more lenient.
        "rate_upper": round(float(hi), 6),
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


# ---------------------------------------------------------------- truth, rule v2

RULE_V2_ABS_SLACK = 0.0005     # 0.05 percentage points


def truth_rates(m: pd.DataFrame) -> dict:
    """True false-positive rates on a joined capture (Zeek rows + UNSW labels).

    `innocent` is the rate the noise check needs: flows from hosts that sent no
    attack-labelled flow in the capture, i.e. hosts that are innocent. The first
    validation used `benign_labelled` (every normal-labelled flow), which mixes in
    normal-labelled flows sent by attack hosts; on the 17-2-2015 captures those
    carried every flagged "benign" flow while innocent hosts flagged 0-0.003%.
    Attack hosts are found from the labels, not from an address range.
    """
    attack_hosts = set(m.loc[m["u_label"] == 1, "srcip"])
    benign = m[m["u_label"] == 0]
    innocent = benign[~benign["srcip"].isin(attack_hosts)]
    from_attackers = benign[benign["srcip"].isin(attack_hosts)]

    def rate(df):
        return round(float(df["alert"].mean()), 6) if len(df) else None

    return {"attack_hosts": sorted(attack_hosts),
            "innocent_rate": rate(innocent), "innocent_flows": int(len(innocent)),
            "innocent_flagged": int(innocent["alert"].sum()),
            "benign_labelled_rate": rate(benign),
            "benign_from_attack_hosts_rate": rate(from_attackers),
            "benign_from_attack_hosts_flows": int(len(from_attackers))}


def rule_v2(true_innocent: float, upper: float) -> dict:
    """Decision rule v2 for the per-capture baseline (docs/upload.md):
    (a) not too strict: the true innocent-host rate is at or below the upper bound
    (b) not too lenient: the upper bound is at most 2x the true rate, or the true
        rate plus 0.05 percentage points, whichever is larger"""
    a = true_innocent <= upper
    b = upper <= max(2 * true_innocent, true_innocent + RULE_V2_ABS_SLACK)
    return {"a_not_too_strict": bool(a), "b_not_too_lenient": bool(b), "pass": bool(a and b)}


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
        truth = truth_rates(m)
        true_rate = truth["benign_labelled_rate"] if truth["benign_labelled_rate"] is not None \
            else float("nan")

        # host truth: majority label of the host's matched flagged flows
        lab = m[m["alert"]].groupby("srcip")["u_label"].mean()
        res = {"capture": str(d), "flows": int(len(z)), "matched": int(len(m)),
               "true_benign_rate": round(true_rate, 6), "estimate": est,
               "ratio_to_true": round(est["rate"] / true_rate, 3) if true_rate > 0 else None,
               "truth": truth,
               "rule_v2": (rule_v2(truth["innocent_rate"], est["rate_upper"])
                           if truth["innocent_rate"] is not None else None),
               "noise_calls": {}}
        for name, rate in (("fixed_0.069", fixed_rate), ("estimated", est["rate"]),
                           ("estimated_upper", est["rate_upper"])):
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
    print("Rule v2 (docs/upload.md): true innocent-host rate vs the estimate's upper bound")
    print(f"{'capture':<32} {'innocent flagged':>18} {'true':>9} {'upper':>9}  (a) (b)  verdict"
          f"   misclassified hosts 6.9% / upper")
    for r in res:
        t, v = r["truth"], r["rule_v2"]
        f, e = r["noise_calls"]["fixed_0.069"], r["noise_calls"]["estimated_upper"]
        ok = lambda x: "ok " if x else "NO "
        print(f"{r['capture']:<32} {t['innocent_flagged']:>7} / {t['innocent_flows']:<8} "
              f"{t['innocent_rate']:>8.4%} {r['estimate']['rate_upper']:>8.4%}  "
              f"{ok(v['a_not_too_strict'])} {ok(v['b_not_too_lenient'])} {'PASS' if v['pass'] else 'FAIL'}"
              f"   {f['misclassified']} / {e['misclassified']} (of {e['event_hosts']} event hosts)")
    print("(the first validation's reference, all benign-labelled flows, is kept in the json as "
          "truth.benign_labelled_rate)")
    print(f"[baseline] details: {a.out}")


if __name__ == "__main__":
    main()
