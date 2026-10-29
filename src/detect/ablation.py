"""
Feature ablation: retrain the two-stage detector without a group of features and
compare it with the production models on UNSW's test split.

WHY: the TTL swap test (docs/cic_eval.md) showed the production stage 1 keys on
source TTL. Setting every normal UNSW test flow's sttl to 31 flags 0% of them; to
64 or 128 (Linux, Windows) 10.2%; to 254, 30%. Attacks set to sttl 31 are caught
0.2% of the time instead of 93%. TTL is set by the sender's operating system and
its distance, so the model learned where hosts sat in the UNSW lab, and an
attacker who sends with a TTL arriving at 31 is invisible to it.

The ablated models keep the full 42-column interface (a DropColumns step inside
the pipeline), so score_pcap and cic_eval can use them unchanged. They are saved
under data/processed/ablation/<variant>/ and never replace the production models
here; switching is a separate, reviewed step.

Usage:
    python -m src.detect.ablation --variant no_ttl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.detect.classifier import TEST_CSV, TRAIN_CSV, load_split
from src.detect.two_stage import STAGE1_PATH, STAGE2_PATH, _pipeline

VARIANTS = {
    "no_ttl": ["sttl", "dttl", "ct_state_ttl"],
}
OUT_ROOT = Path("data/processed/ablation")
THRESHOLDS = (0.5, 0.85)
SWAP_TTLS = (31, 62, 64, 128, 254)


def evaluate(s1, s2, X: pd.DataFrame, y: pd.Series) -> dict:
    """Stage-1 rates at each threshold, recall per attack type at 0.85, stage-2
    accuracy on attacks, and the TTL swap test."""
    atk = (y != "normal").to_numpy()
    p = s1.predict_proba(X)[:, 1]
    out = {"stage1": {}}
    for t in THRESHOLDS:
        flag = p >= t
        out["stage1"][str(t)] = {
            "normal_false_positive_rate": round(float(flag[~atk].mean()), 4),
            "attack_recall": round(float(flag[atk].mean()), 4),
            "attack_precision": round(float(atk[flag].mean()), 4) if flag.any() else None}
    flag = p >= 0.85
    out["recall_by_type_0.85"] = (pd.Series(flag[atk], index=y[atk].values)
                                  .groupby(level=0).mean().round(3).to_dict())
    pred2 = s2.predict(X[atk])
    out["stage2_accuracy_given_attack"] = round(float((pred2 == y[atk].values).mean()), 4)
    normal, attack = X[~atk], X[atk]
    out["ttl_swap_0.85"] = {
        str(ttl): {"normal_flagged": round(float((s1.predict_proba(normal.assign(sttl=ttl))[:, 1]
                                                  >= 0.85).mean()), 4),
                   "attacks_caught": round(float((s1.predict_proba(attack.assign(sttl=ttl))[:, 1]
                                                  >= 0.85).mean()), 4)}
        for ttl in SWAP_TTLS}
    return out


def train_variant(variant: str, train_csv=TRAIN_CSV, test_csv=TEST_CSV,
                  out_root: Path = OUT_ROOT, save: bool = True) -> dict:
    import joblib

    drop = VARIANTS[variant]
    X_tr, y_tr = load_split(train_csv)
    X_te, y_te = load_split(test_csv)
    print(f"[ablation] {variant}: dropping {drop}; train={len(X_tr)} test={len(X_te)}")
    s1 = _pipeline(class_weight=None, max_iter=300, drop=drop)
    s1.fit(X_tr, (y_tr != "normal").astype(int))
    atk = y_tr != "normal"
    s2 = _pipeline(class_weight="balanced", max_iter=300, drop=drop)
    s2.fit(X_tr[atk], y_tr[atk])

    res = {"variant": variant, "dropped": drop, "ablated": evaluate(s1, s2, X_te, y_te)}
    if STAGE1_PATH.exists() and STAGE2_PATH.exists():
        res["production"] = evaluate(joblib.load(STAGE1_PATH), joblib.load(STAGE2_PATH), X_te, y_te)
    if save:
        d = out_root / variant
        d.mkdir(parents=True, exist_ok=True)
        joblib.dump(s1, d / "stage1_binary.joblib")
        joblib.dump(s2, d / "stage2_multiclass.joblib")
        (d / "metrics.json").write_text(json.dumps(res, indent=1))
        (d / "compare.md").write_text(compare_table(res))
        print(f"[ablation] saved -> {d}")
    print(compare_table(res))
    return res


def compare_table(res: dict) -> str:
    a, p = res["ablated"], res.get("production")
    cols = ["production", res["variant"]] if p else [res["variant"]]
    runs = [p, a] if p else [a]
    L = [f"# Ablation: {res['variant']} (dropped {', '.join(res['dropped'])})", "",
         "UNSW test split.", "", "| | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for t in THRESHOLDS:
        for key, name in (("normal_false_positive_rate", "normal flagged"),
                          ("attack_recall", "attacks caught")):
            L.append(f"| {name} @ {t} | " + " | ".join(f"{r['stage1'][str(t)][key]:.2%}" for r in runs) + " |")
    L.append("| stage 2 accuracy on attacks | " +
             " | ".join(f"{r['stage2_accuracy_given_attack']:.2%}" for r in runs) + " |")
    L += ["", "**Recall per attack type @ 0.85**", "", "| type | " + " | ".join(cols) + " |",
          "|---" * (len(cols) + 1) + "|"]
    for c in a["recall_by_type_0.85"]:
        L.append(f"| {c} | " + " | ".join(f"{r['recall_by_type_0.85'].get(c, float('nan')):.1%}"
                                          for r in runs) + " |")
    L += ["", "**TTL swap @ 0.85** (every row's sttl set to the value; normal flagged / attacks caught)",
          "", "| sttl | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for ttl in SWAP_TTLS:
        L.append(f"| {ttl} | " + " | ".join(
            f"{r['ttl_swap_0.85'][str(ttl)]['normal_flagged']:.1%} / "
            f"{r['ttl_swap_0.85'][str(ttl)]['attacks_caught']:.1%}" for r in runs) + " |")
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Retrain without a feature group and compare")
    ap.add_argument("--variant", choices=sorted(VARIANTS), default="no_ttl")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv", default=TEST_CSV)
    a = ap.parse_args()
    train_variant(a.variant, a.train_csv, a.test_csv)


if __name__ == "__main__":
    main()
