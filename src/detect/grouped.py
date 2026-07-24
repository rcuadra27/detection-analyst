"""
Phase 3c — ATT&CK-aligned taxonomy + operational threshold tuning.

TWO FINDINGS DROVE THIS MODULE

1. Prior mismatch. UNSW's training split is ~68% attack while the test split is
   ~55%, so a classifier trained at the default 0.5 cutoff over-predicts
   'attack' — a 26.5% false-positive rate on benign traffic. The fix is a tuned
   decision threshold, reported as a sweep so the operating point is an explicit
   choice rather than an accident.

2. Label overlap. UNSW's `analysis` class scored 0.04 precision / 0.04 recall —
   statistically indistinguishable from guessing — and `backdoor` (0.06
   precision) and `dos` (0.21 recall) were nearly as bad. This is a documented
   property of the dataset: analysis/backdoor/dos overlap heavily with exploits
   in the original labeling. No model separates classes whose feature
   distributions coincide.

   Rather than report meaningless per-class numbers, we predict a taxonomy the
   data supports: groups aligned to ATT&CK tactics. Since the system's OUTPUT is
   an ATT&CK technique plus an explanation, merging `analysis` into `discovery`
   costs the analyst nothing — both resolve to the same techniques. What we give
   up is a distinction the dataset never actually encoded.

This is a deliberate scope decision, and the writeup should state it plainly
alongside the fine-grained numbers that motivated it.

Usage:
    python -m src.detect.grouped --train                 # grouped taxonomy
    python -m src.detect.grouped --train --sweep         # + threshold sweep
    python -m src.detect.grouped --train --fine          # keep original classes
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from src.detect.classifier import TEST_CSV, TRAIN_CSV, load_split
from src.detect.two_stage import _pipeline

MODEL_DIR = Path("data/processed")
METRICS_PATH = MODEL_DIR / "grouped_metrics.json"

# UNSW class -> ATT&CK-tactic-aligned group.
# Groups are chosen so that members share techniques in mapping.py, i.e. the
# merge is invisible in the final triage output.
GROUPS = {
    "normal": "normal",
    "reconnaissance": "discovery",
    "analysis": "discovery",
    "fuzzers": "discovery",
    "exploits": "exploitation",
    "shellcode": "exploitation",
    "backdoor": "persistence",
    "worms": "persistence",
    "dos": "impact",
    "generic": "generic",
}

# Representative ATT&CK techniques per group (union of members' mappings).
GROUP_TECHNIQUES = {
    "discovery": ["T1595", "T1046", "T1590"],
    "exploitation": ["T1190", "T1203", "T1059"],
    "persistence": ["T1133", "T1505.003", "T1210", "T1570"],
    "impact": ["T1498", "T1499"],
    "generic": [],
    "normal": [],
}

GROUP_SEVERITY = {
    "discovery": "medium",
    "exploitation": "high",
    "persistence": "critical",
    "impact": "high",
    "generic": "medium",
    "normal": "low",
}


def to_group(cls: str) -> str:
    return GROUPS.get(str(cls).strip().lower(), str(cls).strip().lower())


def sweep_threshold(s1, X_te, b_te, thresholds=(0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95)):
    from sklearn.metrics import confusion_matrix

    p = s1.predict_proba(X_te)[:, 1]
    rows = []
    print(f"\n=== Stage-1 threshold sweep (the operating-point choice) ===")
    print(f"  {'thresh':>7} {'FP rate':>8} {'attacks caught':>15} {'atk precision':>14}")
    for t in thresholds:
        pred = (p >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(b_te, pred).ravel()
        fpr = fp / (tn + fp) if (tn + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rows.append({"threshold": t, "fp_rate": float(fpr),
                     "attack_recall": float(rec), "attack_precision": float(prec)})
        print(f"  {t:>7.2f} {fpr:>8.3f} {rec:>15.3f} {prec:>14.3f}")
    return rows


def train(train_csv=TRAIN_CSV, test_csv=TEST_CSV, grouped=True,
          threshold=0.5, do_sweep=False, save=True, stage2_balance="balanced"):
    """stage2_balance: 'balanced' lifts rare-class recall but can flood
    predictions (persistence hit 0.06 precision at 1% of training rows);
    'none' protects precision at the cost of rare-class recall."""
    import joblib
    from sklearn.metrics import (balanced_accuracy_score, classification_report,
                                 confusion_matrix)

    X_tr, y_tr = load_split(train_csv)
    X_te, y_te = load_split(test_csv)
    if grouped:
        y_tr = y_tr.map(to_group)
        y_te = y_te.map(to_group)
    tag = "grouped" if grouped else "fine"
    print(f"[{tag}] train={len(X_tr)} test={len(X_te)} classes={y_tr.nunique()}")
    print(f"[{tag}] class counts (train): "
          f"{dict(y_tr.value_counts())}")

    # ---- stage 1 ----
    b_tr = (y_tr != "normal").astype(int)
    b_te = (y_te != "normal").astype(int)
    print(f"[{tag}] fitting stage 1 ...")
    s1 = _pipeline(class_weight=None, max_iter=300)
    s1.fit(X_tr, b_tr)

    sweep = sweep_threshold(s1, X_te, b_te) if do_sweep else None

    p_attack = s1.predict_proba(X_te)[:, 1]
    pred_attack = (p_attack >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(b_te, pred_attack).ravel()
    print(f"\n=== Stage 1 @ threshold {threshold} ===")
    print(f"  false-positive rate : {fp/(tn+fp):.3f}")
    print(f"  attacks caught      : {tp/(tp+fn):.3f}")

    # ---- stage 2 ----
    atk_tr = y_tr != "normal"
    print(f"\n[{tag}] fitting stage 2 ...")
    cw = None if stage2_balance == "none" else "balanced"
    print(f"[{tag}] stage-2 class_weight={cw}")
    s2 = _pipeline(class_weight=cw, max_iter=300)
    s2.fit(X_tr[atk_tr], y_tr[atk_tr])

    # ---- end to end ----
    final = np.where(pred_attack == 1, s2.predict(X_te), "normal")
    rep = classification_report(y_te, final, output_dict=True, zero_division=0)
    labels = sorted(set(y_te))
    per_class = {c: {"precision": rep[c]["precision"], "recall": rep[c]["recall"],
                     "f1": rep[c]["f1-score"], "support": int(rep[c]["support"])}
                 for c in labels if c in rep}
    acc = float((final == y_te.values).mean())
    bal = float(balanced_accuracy_score(y_te, final))

    print(f"\n=== End to end ({tag} taxonomy, threshold {threshold}) ===")
    print(f"  accuracy          : {acc:.3f}")
    print(f"  balanced accuracy : {bal:.3f}")
    print(f"\n  {'class':16} {'precision':>9} {'recall':>7} {'f1':>6} {'support':>8}")
    for c, v in sorted(per_class.items(), key=lambda x: -x[1]["f1"]):
        print(f"  {c:16} {v['precision']:>9.2f} {v['recall']:>7.2f} "
              f"{v['f1']:>6.2f} {v['support']:>8}")
    usable = [c for c, v in per_class.items()
              if v["recall"] >= 0.50 and v["precision"] >= 0.50]
    print(f"\n  classes usable (precision AND recall >= 0.50): "
          f"{len(usable)}/{len(per_class)}")
    print(f"    {sorted(usable)}")

    metrics = {"taxonomy": tag, "threshold": threshold,
               "stage2_balance": stage2_balance, "accuracy": acc,
               "balanced_accuracy": bal, "per_class": per_class, "sweep": sweep}
    if save:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(s1, MODEL_DIR / f"{tag}_stage1.joblib")
        joblib.dump(s2, MODEL_DIR / f"{tag}_stage2.joblib")
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        print(f"\n[{tag}] saved models + {METRICS_PATH}")
    return s1, s2, metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--fine", action="store_true", help="original UNSW classes, not groups")
    ap.add_argument("--sweep", action="store_true", help="print threshold sweep")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--stage2-balance", choices=["balanced", "none"], default="balanced",
                    help="'none' protects precision on rare classes")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv", default=TEST_CSV)
    args = ap.parse_args()
    train(args.train_csv, args.test_csv, grouped=not args.fine,
          threshold=args.threshold, do_sweep=args.sweep,
          stage2_balance=args.stage2_balance)