"""
Phase 3b — two-stage detection.

WHY: a single 10-way classifier forced one model to answer two very different
questions at once, and the first attempt showed the cost. Aggressive class
weighting (needed to see worms/shellcode at all) collapsed precision on rare
classes to 0.04-0.20 and dropped `normal` recall to 0.59 — a 41% false-positive
rate on benign traffic, which is operationally unusable.

Splitting the job fixes the conflict:

  Stage 1 — BINARY: attack vs normal, tuned for high precision on `normal`.
            This is the easy, high-signal question and it protects the analyst
            from false positives. A tunable threshold trades FP rate vs missed
            attacks explicitly, which is the knob a SOC actually wants.

  Stage 2 — MULTICLASS: which attack type, trained ONLY on attack rows. With
            the dominant `normal` class removed, moderate class weighting can
            lift rare classes without flooding the whole prediction space.

Reported honestly: stage-1 confusion (the FP/FN tradeoff) and stage-2 per-class
recall *conditional on the row being an attack*, plus end-to-end numbers.

Usage:
    python -m src.detect.two_stage --train
    python -m src.detect.two_stage --train --threshold 0.5
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.detect.classifier import (CATEGORICAL, DROP_COLS, TEST_CSV, TRAIN_CSV,
                                   load_split, normalize_class)

STAGE1_PATH = Path("data/processed/stage1_binary.joblib")
STAGE2_PATH = Path("data/processed/stage2_multiclass.joblib")
METRICS_PATH = Path("data/processed/two_stage_metrics.json")


def _pipeline(class_weight=None, max_iter=300):
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OrdinalEncoder

    pre = ColumnTransformer(
        [("cat", OrdinalEncoder(handle_unknown="use_encoded_value",
                                unknown_value=-1), CATEGORICAL)],
        remainder="passthrough", verbose_feature_names_out=False,
    )
    clf = HistGradientBoostingClassifier(
        max_iter=max_iter, learning_rate=0.1, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.1, random_state=13,
        class_weight=class_weight,
    )
    return Pipeline([("pre", pre), ("clf", clf)])


def train_two_stage(train_csv=TRAIN_CSV, test_csv=TEST_CSV, threshold=0.5, save=True):
    import joblib
    from sklearn.metrics import (balanced_accuracy_score, classification_report,
                                 confusion_matrix)

    X_tr, y_tr = load_split(train_csv)
    X_te, y_te = load_split(test_csv)
    print(f"[2stage] train={len(X_tr)} test={len(X_te)} features={X_tr.shape[1]}")

    # ---------------- Stage 1: attack vs normal ----------------
    b_tr = (y_tr != "normal").astype(int)
    b_te = (y_te != "normal").astype(int)
    print("[2stage] fitting stage 1 (binary attack detection) ...")
    s1 = _pipeline(class_weight=None, max_iter=300)   # NO balancing: protect precision
    s1.fit(X_tr, b_tr)

    p_attack = s1.predict_proba(X_te)[:, 1]
    pred_attack = (p_attack >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(b_te, pred_attack).ravel()
    stage1 = {
        "threshold": threshold,
        "normal_recall": float(tn / (tn + fp)) if (tn + fp) else 0.0,   # 1 - FP rate
        "attack_recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "attack_precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
        "false_positive_rate": float(fp / (tn + fp)) if (tn + fp) else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }
    print(f"\n=== Stage 1: attack vs normal (threshold={threshold}) ===")
    print(f"  normal correctly cleared : {stage1['normal_recall']:.3f}  "
          f"(false-positive rate {stage1['false_positive_rate']:.3f})")
    print(f"  attacks caught           : {stage1['attack_recall']:.3f}")
    print(f"  attack precision         : {stage1['attack_precision']:.3f}")

    # ---------------- Stage 2: which attack (attacks only) ----------------
    atk_tr = y_tr != "normal"
    print("\n[2stage] fitting stage 2 (attack-type classification) ...")
    # moderate balancing only — 'normal' is gone, so rare classes need less lift
    s2 = _pipeline(class_weight="balanced", max_iter=300)
    s2.fit(X_tr[atk_tr], y_tr[atk_tr])

    atk_te = b_te == 1
    y_true_atk = y_te[atk_te]
    y_pred_atk = s2.predict(X_te[atk_te])
    rep = classification_report(y_true_atk, y_pred_atk, output_dict=True, zero_division=0)
    labels = sorted(set(y_true_atk))
    stage2 = {
        "accuracy_given_attack": float((y_pred_atk == y_true_atk).mean()),
        "balanced_accuracy_given_attack": float(balanced_accuracy_score(y_true_atk, y_pred_atk)),
        "per_class": {c: {"precision": rep[c]["precision"], "recall": rep[c]["recall"],
                          "f1": rep[c]["f1-score"], "support": int(rep[c]["support"])}
                      for c in labels if c in rep},
    }
    print(f"\n=== Stage 2: attack type (given the row IS an attack) ===")
    print(f"  accuracy          : {stage2['accuracy_given_attack']:.3f}")
    print(f"  balanced accuracy : {stage2['balanced_accuracy_given_attack']:.3f}")
    print(f"\n  {'class':16} {'precision':>9} {'recall':>7} {'f1':>6} {'support':>8}")
    for c, v in sorted(stage2["per_class"].items(), key=lambda x: -x[1]["recall"]):
        print(f"  {c:16} {v['precision']:>9.2f} {v['recall']:>7.2f} "
              f"{v['f1']:>6.2f} {v['support']:>8}")

    # ---------------- End to end ----------------
    final = np.where(pred_attack == 1, s2.predict(X_te), "normal")
    e2e = {
        "accuracy": float((final == y_te.values).mean()),
        "balanced_accuracy": float(balanced_accuracy_score(y_te, final)),
    }
    rep_e = classification_report(y_te, final, output_dict=True, zero_division=0)
    e2e["per_class"] = {c: {"precision": rep_e[c]["precision"], "recall": rep_e[c]["recall"],
                            "f1": rep_e[c]["f1-score"], "support": int(rep_e[c]["support"])}
                        for c in sorted(set(y_te)) if c in rep_e}
    print(f"\n=== End to end (both stages) ===")
    print(f"  accuracy          : {e2e['accuracy']:.3f}")
    print(f"  balanced accuracy : {e2e['balanced_accuracy']:.3f}")
    print(f"\n  {'class':16} {'precision':>9} {'recall':>7} {'f1':>6} {'support':>8}")
    for c, v in sorted(e2e["per_class"].items(), key=lambda x: -x[1]["recall"]):
        print(f"  {c:16} {v['precision']:>9.2f} {v['recall']:>7.2f} "
              f"{v['f1']:>6.2f} {v['support']:>8}")
    usable = [c for c, v in e2e["per_class"].items()
              if v["recall"] >= 0.30 and v["precision"] >= 0.30]
    print(f"\n  classes usable (recall>=0.30 AND precision>=0.30): "
          f"{len(usable)}/{len(e2e['per_class'])}")
    print(f"    {sorted(usable)}")

    metrics = {"stage1": stage1, "stage2": stage2, "end_to_end": e2e}
    if save:
        STAGE1_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(s1, STAGE1_PATH)
        joblib.dump(s2, STAGE2_PATH)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        print(f"\n[2stage] saved -> {STAGE1_PATH}, {STAGE2_PATH}, {METRICS_PATH}")
    return s1, s2, metrics


def predict(X: pd.DataFrame, threshold: float = 0.5):
    """Full detection: returns (class, attack_probability)."""
    import joblib
    s1 = joblib.load(STAGE1_PATH)
    s2 = joblib.load(STAGE2_PATH)
    p = s1.predict_proba(X)[:, 1]
    out = np.where(p >= threshold, s2.predict(X), "normal")
    return out, p


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="stage-1 attack probability cutoff; raise it to cut false positives")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv", default=TEST_CSV)
    args = ap.parse_args()
    train_two_stage(args.train_csv, args.test_csv, threshold=args.threshold)