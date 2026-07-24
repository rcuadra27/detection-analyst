"""
Phase 3 — the detection stage: a supervised flow classifier.

WHY THIS EXISTS
The Phase 2 evaluation established that mapping raw telemetry onto ATT&CK prose
by embedding similarity has a hard ceiling (hit@10 ~= 0.3), and a controlled
ablation showed payload extraction does not lift it on UNSW. The cause is
modality mismatch: ATT&CK narrates adversary intent, a flow record reports
packet counts. Semantic similarity is the wrong instrument for DETECTION.

So we split the job the way production SOC platforms do:
    detection   -> supervised classifier over flow features (this module)
    grounding   -> deterministic class -> ATT&CK lookup via mapping.py
    explanation -> retrieval-augmented generation (the existing RAG stack)

The classifier learns from labels rather than semantic proximity, so classes
that are invisible to an embedding model (exploits, generic) become separable.

HONEST EVALUATION
Trained on UNSW_NB15_training-set.csv, evaluated on the official held-out
UNSW_NB15_testing-set.csv. No tuning against the test split. Per-class recall is
reported because aggregate accuracy hides the classes that matter — UNSW's
analysis/backdoor/dos are well documented as confusable with exploits, and the
report should show that rather than bury it.

Usage:
    python -m src.detect.classifier --train                # train + evaluate + save
    python -m src.detect.classifier --report               # evaluate saved model
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

MODEL_PATH = Path("data/processed/flow_classifier.joblib")
METRICS_PATH = Path("data/processed/classifier_metrics.json")

TRAIN_CSV = "data/raw/UNSW_NB15_training-set.csv"
TEST_CSV = "data/raw/UNSW_NB15_testing-set.csv"

CATEGORICAL = ["proto", "service", "state"]
DROP_COLS = ["id", "label", "attack_cat", "_class"]

# UNSW attack_cat spellings -> our mapping.py keys
_ALIASES = {"backdoors": "backdoor"}


def normalize_class(raw) -> str:
    key = str(raw).strip().lower()
    return _ALIASES.get(key, key)


def load_split(csv_path: str) -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(csv_path)
    if "attack_cat" not in df.columns:
        raise ValueError(f"'attack_cat' not in {csv_path}; found {list(df.columns)[:8]}")
    y = df["attack_cat"].map(normalize_class)
    X = df.drop(columns=[c for c in DROP_COLS if c in df.columns])
    return X, y


def build_pipeline():
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OrdinalEncoder

    # Ordinal encoding + a tree model: trees split on categories fine, and this
    # avoids the high-dimensional sparsity that one-hot creates for 'service'.
    pre = ColumnTransformer(
        transformers=[
            ("cat", OrdinalEncoder(handle_unknown="use_encoded_value",
                                   unknown_value=-1), CATEGORICAL),
        ],
        remainder="passthrough",
        verbose_feature_names_out=False,
    )
    clf = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.1,
        max_depth=None,
        l2_regularization=1.0,
        early_stopping=True,
        validation_fraction=0.1,
        random_state=13,
        # UNSW is heavily imbalanced (Generic/Normal dominate); this keeps rare
        # classes like worms/shellcode from being ignored entirely.
        class_weight="balanced",
    )
    return Pipeline([("pre", pre), ("clf", clf)])


def evaluate(pipe, X_test, y_test) -> dict:
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 balanced_accuracy_score)

    y_pred = pipe.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    labels = sorted(set(y_test) | set(y_pred))
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    return {
        "accuracy": float((y_pred == y_test).mean()),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "per_class": {
            c: {"precision": report[c]["precision"], "recall": report[c]["recall"],
                "f1": report[c]["f1-score"], "support": int(report[c]["support"])}
            for c in labels if c in report
        },
        "labels": labels,
        "confusion_matrix": cm.tolist(),
    }


def print_report(m: dict) -> None:
    print(f"\n=== Flow classifier — held-out test set ===")
    print(f"  accuracy          : {m['accuracy']:.3f}")
    print(f"  balanced accuracy : {m['balanced_accuracy']:.3f}   "
          f"(mean per-class recall — the number that matters here)")
    print(f"\n  {'class':16} {'precision':>9} {'recall':>7} {'f1':>6} {'support':>8}")
    for c, v in sorted(m["per_class"].items(), key=lambda x: -x[1]["recall"]):
        print(f"  {c:16} {v['precision']:>9.2f} {v['recall']:>7.2f} "
              f"{v['f1']:>6.2f} {v['support']:>8}")
    detected = [c for c, v in m["per_class"].items() if v["recall"] >= 0.30]
    print(f"\n  classes detected at recall >= 0.30: {len(detected)}/{len(m['per_class'])}")
    print(f"    {sorted(detected)}")


def predict_with_confidence(pipe, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return (predicted_class, confidence). Confidence feeds the triage output."""
    proba = pipe.predict_proba(X)
    idx = proba.argmax(axis=1)
    classes = pipe.named_steps["clf"].classes_
    return classes[idx], proba[np.arange(len(idx)), idx]


def train_and_eval(train_csv: str = TRAIN_CSV, test_csv: str = TEST_CSV, save: bool = True):
    import joblib

    print(f"[clf] loading {train_csv}")
    X_tr, y_tr = load_split(train_csv)
    print(f"[clf] loading {test_csv}")
    X_te, y_te = load_split(test_csv)
    print(f"[clf] train={len(X_tr)} rows, test={len(X_te)} rows, "
          f"{X_tr.shape[1]} features, {y_tr.nunique()} classes")

    pipe = build_pipeline()
    print("[clf] fitting ...")
    pipe.fit(X_tr, y_tr)

    metrics = evaluate(pipe, X_te, y_te)
    print_report(metrics)

    if save:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipe, MODEL_PATH)
        METRICS_PATH.write_text(json.dumps(metrics, indent=2))
        print(f"\n[clf] saved model -> {MODEL_PATH}")
        print(f"[clf] saved metrics -> {METRICS_PATH}")
    return pipe, metrics


def load_model():
    import joblib
    return joblib.load(MODEL_PATH)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true", help="train, evaluate, save")
    ap.add_argument("--report", action="store_true", help="evaluate the saved model")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv", default=TEST_CSV)
    args = ap.parse_args()

    if args.report and not args.train:
        pipe = load_model()
        X_te, y_te = load_split(args.test_csv)
        print_report(evaluate(pipe, X_te, y_te))
    else:
        train_and_eval(args.train_csv, args.test_csv)