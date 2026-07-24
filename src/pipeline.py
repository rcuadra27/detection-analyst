"""
The end-to-end pipeline: flow telemetry in, analyst-facing triage out.

This is the module that makes the parts a system:

    flow -> two-stage detector -> ranked hypotheses + confidence
         -> deterministic ATT&CK lookup (mapping.py, not similarity search)
         -> retrieve those techniques' documentation from the FAISS corpus
         -> Claude writes the triage, validated against TriageResult

ARCHITECTURAL NOTE
Earlier versions selected ATT&CK techniques by embedding similarity between the
alert text and technique descriptions. That was measured at hit@10 ~= 0.31 and
replaced: telemetry and ATT&CK prose are different modalities, and cosine
similarity across them is weak. Here the classifier decides WHAT the attack is
and the hand-authored mapping decides which techniques that implies. Retrieval
is then a lookup by technique ID — used to fetch documentation for grounding,
not to guess the answer.

Consequence: technique selection is now as accurate as the classifier, and the
language model's job is narrowed to what it is good at — explaining evidence in
analyst-facing language, grounded in retrieved documentation.

Usage:
    python -m src.pipeline --demo
    python -m src.pipeline --csv data/raw/UNSW_NB15_testing-set.csv --n 5
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field

import pandas as pd

from src.detect.predict import Detection, detect
from src.rag.index import RetrievedChunk, VectorIndex
from src.schema import TriageResult

DEFAULT_THRESHOLD = 0.85


@dataclass
class TriageReport:
    """Everything an analyst sees for one flow."""
    detection: Detection
    triage: TriageResult | None
    evidence: dict = field(default_factory=dict)
    context_technique_ids: list[str] = field(default_factory=list)

    def render(self) -> str:
        d = self.detection
        lines = [f"DETECTION: {d.summary()}"]
        if d.note:
            lines.append(f"  note: {d.note}")
        if self.evidence:
            ev = ", ".join(f"{k}={v}" for k, v in self.evidence.items())
            lines.append(f"  evidence: {ev}")
        if self.triage:
            t = self.triage
            lines += [
                f"\nTRIAGE",
                f"  severity   : {t.severity.value}",
                f"  assessment : {t.assessment.value}",
                f"  techniques : {', '.join(t.attack_technique_ids) or '(none)'}",
                f"  confidence : {t.confidence:.2f}",
                f"\n  {t.explanation}",
                f"\n  RECOMMENDED: {t.recommended_action}",
            ]
        return "\n".join(lines)


def chunks_for_techniques(index: VectorIndex, technique_ids: list[str],
                          per_technique: int = 2) -> list[RetrievedChunk]:
    """Fetch documentation chunks BY TECHNIQUE ID rather than by similarity.

    Family-aware: requesting T1110 also accepts T1110.003, since the mapping may
    name a parent while the corpus carries sub-technique detail.
    """
    wanted = {t.split(".", 1)[0] for t in technique_ids}
    picked: list[RetrievedChunk] = []
    seen: dict[str, int] = {}
    for chunk in index.chunks:
        base = chunk.technique_id.split(".", 1)[0]
        if base not in wanted:
            continue
        if seen.get(chunk.technique_id, 0) >= per_technique:
            continue
        seen[chunk.technique_id] = seen.get(chunk.technique_id, 0) + 1
        # score is 1.0: these were selected deterministically, not ranked
        picked.append(RetrievedChunk(chunk=chunk, score=1.0))
    return picked


def flow_evidence(row: pd.Series) -> dict:
    """Human-readable evidence fields to show alongside the verdict."""
    out = {}
    for col, label in (("proto", "proto"), ("service", "service"), ("state", "state"),
                       ("dur", "duration"), ("spkts", "src_pkts"), ("dpkts", "dst_pkts"),
                       ("sbytes", "src_bytes"), ("rate", "rate")):
        if col in row and pd.notna(row[col]):
            v = row[col]
            out[label] = f"{v:.2f}" if isinstance(v, float) else v
    return out


def triage_flows(df: pd.DataFrame, threshold: float = DEFAULT_THRESHOLD,
                 explain: bool = True, model: str = "claude-sonnet-5",
                 index: VectorIndex | None = None, client=None) -> list[TriageReport]:
    """Run detection on every row, then explain the ones that are attacks."""
    feature_df = df.drop(columns=[c for c in ("id", "label", "attack_cat")
                                  if c in df.columns])
    detections = detect(feature_df, attack_threshold=threshold)

    if index is None:
        index = VectorIndex.load()
    if explain and client is None:
        from anthropic import Anthropic
        client = Anthropic()

    reports: list[TriageReport] = []
    for i, det in enumerate(detections):
        row = df.iloc[i]
        report = TriageReport(detection=det, triage=None,
                              evidence=flow_evidence(row))
        if det.is_attack and explain and det.candidate_techniques:
            from src.rag.generator import generate_triage

            chunks = chunks_for_techniques(index, det.candidate_techniques)
            report.context_technique_ids = [c.chunk.technique_id for c in chunks]
            alert_text = _alert_text(row, det)
            try:
                report.triage = generate_triage(
                    alert_text, chunks, client, model=model,
                    alert_id=str(row.get("id", i)),
                )
            except Exception as e:  # generation failure is reported, not swallowed
                print(f"  [warn] generation failed for row {i}: {e}")
        reports.append(report)
    return reports


def _alert_text(row: pd.Series, det: Detection) -> str:
    """Compose the alert the model sees: observed evidence + detector output.

    The detector's hypotheses are included deliberately — the model's job here is
    to explain and contextualise a detection, not to re-derive it. Ground-truth
    labels are never included.
    """
    ev = ", ".join(f"{k} {v}" for k, v in flow_evidence(row).items())
    hyps = "; ".join(f"{h.attack_class} {h.probability:.0%}" for h in det.hypotheses)
    parts = [
        f"Network flow observed: {ev}.",
        f"Detector output: attack probability {det.attack_probability:.2f}; "
        f"candidate classifications: {hyps}.",
    ]
    if det.note:
        parts.append(f"Detector note: {det.note}")
    return " ".join(parts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="data/raw/UNSW_NB15_testing-set.csv")
    ap.add_argument("--n", type=int, default=5, help="number of flows to triage")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--no-explain", action="store_true",
                    help="detection only, skip the API call")
    ap.add_argument("--demo", action="store_true",
                    help="sample a mix of attack and benign flows")
    args = ap.parse_args()

    if not args.no_explain and not os.getenv("ANTHROPIC_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()

    df = pd.read_csv(args.csv)
    if args.demo and "attack_cat" in df.columns:
        # a readable mix: a few attacks and a few benign
        atk = df[df["attack_cat"].str.lower() != "normal"].sample(
            min(args.n - 1, 4), random_state=13)
        ben = df[df["attack_cat"].str.lower() == "normal"].sample(1, random_state=13)
        sample = pd.concat([atk, ben]).sample(frac=1, random_state=13)
    else:
        sample = df.head(args.n)

    truth = (sample["attack_cat"].tolist() if "attack_cat" in sample.columns
             else [None] * len(sample))
    reports = triage_flows(sample.reset_index(drop=True),
                           threshold=args.threshold, explain=not args.no_explain)

    for i, rep in enumerate(reports):
        print("\n" + "=" * 72)
        if truth[i] is not None:
            print(f"[ground truth: {truth[i]}]")
        print(rep.render())