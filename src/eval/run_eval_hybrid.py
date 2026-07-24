"""
Evaluation of the HYBRID pipeline (classifier -> mapping -> retrieval -> generation).

Why a separate runner from src/eval/run_eval.py: that harness reads pre-rendered
alert text and selects ATT&CK techniques by embedding similarity, which is the
architecture this project replaced. To measure what the system actually does now,
evaluation must start from raw flow rows and run the real path:

    flow row -> two-stage detector -> ranked hypotheses
             -> deterministic ATT&CK lookup (mapping.py)
             -> retrieve those techniques by ID
             -> Claude writes the triage
             -> score severity / technique / faithfulness

Evaluated on the HELD-OUT UNSW_NB15_testing-set.csv. The classifier was trained
only on the training split, so no row here was seen during fitting.

Metric notes:
  - technique scoring is family-aware (T1110 matches T1110.003), as in the
    retrieval harness.
  - faithfulness now measures whether the model stayed within the techniques the
    mapping supplied. It is a check on the generator, not on the detector: a
    correct-but-ungrounded citation still scores 0.
  - `normal` rows are scored too — a benign flow should yield no technique.

Usage:
    python -m src.eval.run_eval_hybrid --per-class 8
    python -m src.eval.run_eval_hybrid --per-class 8 --from-cache
"""

from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

import pandas as pd

from src.detect.predict import detect
from src.eval.answer import AnswerEval, print_report
from src.mapping import GROUND_TRUTH, get as get_mapping
from src.pipeline import DEFAULT_THRESHOLD, _alert_text, chunks_for_techniques, flow_evidence
from src.rag.index import VectorIndex
from src.schema import TriageResult

CACHE_PATH = Path("data/processed/hybrid_predictions.jsonl")
METRICS_PATH = Path("data/processed/hybrid_metrics.json")
TEST_CSV = "data/raw/UNSW_NB15_testing-set.csv"

_ALIASES = {"backdoors": "backdoor"}


def _norm(c: str) -> str:
    k = str(c).strip().lower()
    return _ALIASES.get(k, k)


def sample_balanced(csv_path: str, per_class: int, seed: int = 13) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df["_class"] = df["attack_cat"].map(_norm)
    known = set(GROUND_TRUTH)
    rng = random.Random(seed)
    picks = []
    for cls in sorted(set(df["_class"]) & known):
        idxs = list(df[df["_class"] == cls].index)
        rng.shuffle(idxs)
        picks.extend(idxs[:per_class])
    out = df.loc[picks].reset_index(drop=True)
    missing = sorted(set(df["_class"]) - known)
    if missing:
        print(f"[hybrid-eval] WARNING — unmapped classes skipped: {missing}")
    return out


class _LabeledRow:
    """Minimal stand-in for LabeledAlert so AnswerEval can score these rows."""
    def __init__(self, alert_id, attack_class, true_severity, true_technique_ids):
        self.alert_id = alert_id
        self.attack_class = attack_class
        self.true_severity = true_severity
        self.true_technique_ids = true_technique_ids


def run(per_class: int = 8, threshold: float = DEFAULT_THRESHOLD,
        csv_path: str = TEST_CSV, use_cache: bool = False,
        model: str = "claude-sonnet-5", seed: int = 13):
    sample = sample_balanced(csv_path, per_class, seed)
    print(f"[hybrid-eval] {len(sample)} rows across "
          f"{sample['_class'].nunique()} classes from {csv_path}")

    feature_df = sample.drop(columns=[c for c in ("id", "label", "attack_cat", "_class")
                                      if c in sample.columns])
    detections = detect(feature_df, attack_threshold=threshold)

    index = VectorIndex.load()
    cache: dict[str, dict] = {}
    if CACHE_PATH.exists():
        for line in CACHE_PATH.read_text().splitlines():
            if line.strip():
                r = json.loads(line)
                cache[r["alert_id"]] = r

    client = None
    if not use_cache:
        from anthropic import Anthropic
        client = Anthropic()

    ev = AnswerEval()
    detection_correct = []
    new_lines = []

    for i, det in enumerate(detections):
        row = sample.iloc[i]
        cls = row["_class"]
        entry = get_mapping(cls)
        alert_id = f"{cls}-{i:03d}"
        labeled = _LabeledRow(alert_id, cls, entry.severity, entry.technique_ids)

        # detector-level correctness, tracked separately from triage quality
        if cls == "normal":
            detection_correct.append(0 if det.is_attack else 1)
        else:
            top = det.hypotheses[0].attack_class if det.hypotheses else None
            detection_correct.append(1 if (det.is_attack and top == cls) else 0)

        context_ids = det.candidate_techniques
        rec = cache.get(alert_id)
        if rec is not None:
            pred = TriageResult.model_validate(rec["pred"])
            context_ids = rec.get("context_ids", context_ids)
        elif use_cache:
            continue
        else:
            if not det.is_attack:
                # benign: the system's answer is "no technique, low severity"
                pred = TriageResult(
                    severity="low", assessment="false_positive",
                    attack_technique_ids=[], explanation="Detector cleared as benign.",
                    recommended_action="No action required.",
                    confidence=1.0 - det.attack_probability, alert_id=alert_id,
                )
            else:
                from src.rag.generator import generate_triage
                chunks = chunks_for_techniques(index, det.candidate_techniques)
                context_ids = [c.chunk.technique_id for c in chunks]
                try:
                    pred = generate_triage(_alert_text(row, det), chunks, client,
                                           model=model, alert_id=alert_id)
                except Exception as e:
                    print(f"  [warn] generation failed {alert_id}: {e}")
                    continue
            new_lines.append(json.dumps({
                "alert_id": alert_id, "pred": pred.model_dump(mode="json"),
                "context_ids": context_ids}))
            print(f"  [{i+1}/{len(sample)}] {alert_id:20} "
                  f"det={det.presentation:10} sev={pred.severity.value:8} "
                  f"tech={pred.attack_technique_ids}")

        ev.add(labeled, pred, context_ids)

    if new_lines:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_PATH, "a") as f:
            f.write("\n".join(new_lines) + "\n")

    summary = ev.summary()
    det_acc = sum(detection_correct) / len(detection_correct) if detection_correct else 0.0
    print(f"\n=== Detector (class-level, held-out) ===")
    print(f"  exact class accuracy : {det_acc:.3f}")
    print_report(summary)
    summary["detector_class_accuracy"] = det_acc
    summary["threshold"] = threshold
    METRICS_PATH.write_text(json.dumps(summary, indent=2))
    print(f"\n[hybrid-eval] wrote {METRICS_PATH}")
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=8)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--csv", default=TEST_CSV)
    ap.add_argument("--from-cache", action="store_true")
    ap.add_argument("--model", default="claude-sonnet-5")
    args = ap.parse_args()

    if not args.from_cache and not os.getenv("ANTHROPIC_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()
    run(per_class=args.per_class, threshold=args.threshold, csv_path=args.csv,
        use_cache=args.from_cache, model=args.model)