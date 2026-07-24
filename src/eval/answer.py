"""
Phase 2 — answer-quality metrics. The generator goes on trial.

Retrieval asked "did the right technique reach context?". This asks "given
whatever context it got, was the final triage correct — and honest?".

Three things, measured separately because they fail for different reasons:

  1. severity accuracy  — did predicted severity match ground truth? We report
     exact accuracy AND off-by-one (low<med<high<critical are ordinal, so
     predicting 'high' for a 'critical' is a smaller error than 'low').

  2. technique accuracy — did the predicted ATT&CK IDs overlap the ground-truth
     set (family-matched, same rule as retrieval)? Reported as hit (any overlap)
     and Jaccard (set similarity).

  3. faithfulness       — is every technique the model CITED actually present in
     the retrieved context it was given? This catches the failure that matters
     most for a grounded system: inventing a technique that sounds right but was
     never retrieved. A confident hallucination scores 0 here even if it happens
     to match ground truth, because it wasn't grounded.

faithfulness vs technique-accuracy is the key distinction: accuracy asks "right
answer?", faithfulness asks "right answer FOR THE RIGHT REASON (from context)?".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.eval.dataset import LabeledAlert
from src.eval.retrieval import base_id, ranked_technique_ids
from src.rag.index import RetrievedChunk
from src.schema import Severity, TriageResult

_SEV_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _fam_overlap(a: list[str], b: list[str]) -> set[str]:
    """Family-aware intersection: T1110 matches T1110.003."""
    bbase = {base_id(x) for x in b}
    return {x for x in a if base_id(x) in bbase}


def severity_scores(pred: Severity, truth: Severity) -> tuple[int, int]:
    """(exact 0/1, off_by_one 0/1)."""
    dist = abs(_SEV_ORDER[pred] - _SEV_ORDER[truth])
    return (1 if dist == 0 else 0, 1 if dist <= 1 else 0)


def technique_scores(pred_ids: list[str], truth_ids: list[str]) -> tuple[int, float]:
    """(hit 0/1 = any family overlap, jaccard). truth empty (normal) handled."""
    if not truth_ids:
        # 'normal': correct iff the model also claimed no technique
        return (1 if not pred_ids else 0, 1.0 if not pred_ids else 0.0)
    overlap = _fam_overlap(pred_ids, truth_ids)
    hit = 1 if overlap else 0
    union = {base_id(x) for x in pred_ids} | {base_id(x) for x in truth_ids}
    jac = len({base_id(x) for x in overlap}) / len(union) if union else 0.0
    return (hit, jac)


def faithfulness_score(pred_ids: list[str], context_ids: list[str]) -> float:
    """Fraction of cited techniques that were actually in the retrieved context.
    1.0 if the model cited nothing (nothing to hallucinate)."""
    if not pred_ids:
        return 1.0
    grounded = _fam_overlap(pred_ids, context_ids)
    return len(grounded) / len(pred_ids)


@dataclass
class AnswerEval:
    n: int = 0
    sev_exact: list = field(default_factory=list)
    sev_off1: list = field(default_factory=list)
    tech_hit: list = field(default_factory=list)
    tech_jac: list = field(default_factory=list)
    faith: list = field(default_factory=list)
    per_class: dict = field(default_factory=dict)
    rows: list = field(default_factory=list)  # per-alert detail for inspection

    def add(self, alert: LabeledAlert, pred: TriageResult, context_ids: list[str]):
        se, so = severity_scores(pred.severity, alert.true_severity)
        th, tj = technique_scores(pred.attack_technique_ids, alert.true_technique_ids)
        fa = faithfulness_score(pred.attack_technique_ids, context_ids)
        self.n += 1
        self.sev_exact.append(se); self.sev_off1.append(so)
        self.tech_hit.append(th); self.tech_jac.append(tj); self.faith.append(fa)
        pc = self.per_class.setdefault(alert.attack_class,
                                       {"sev": [], "tech": [], "faith": []})
        pc["sev"].append(se); pc["tech"].append(th); pc["faith"].append(fa)
        self.rows.append({
            "alert_id": alert.alert_id, "class": alert.attack_class,
            "true_sev": alert.true_severity.value, "pred_sev": pred.severity.value,
            "true_tech": alert.true_technique_ids, "pred_tech": pred.attack_technique_ids,
            "faith": fa, "assessment": pred.assessment.value,
        })

    def summary(self) -> dict:
        m = lambda xs: sum(xs) / len(xs) if xs else 0.0
        return {
            "n": self.n,
            "severity_accuracy": m(self.sev_exact),
            "severity_off_by_one": m(self.sev_off1),
            "technique_hit_rate": m(self.tech_hit),
            "technique_jaccard": m(self.tech_jac),
            "faithfulness": m(self.faith),
            "per_class": {
                c: {"severity": m(v["sev"]), "technique": m(v["tech"]),
                    "faithfulness": m(v["faith"])}
                for c, v in sorted(self.per_class.items())
            },
        }


def print_report(summary: dict) -> None:
    print(f"\n=== Answer-quality metrics (n={summary['n']}) ===")
    print(f"  severity accuracy      : {summary['severity_accuracy']:.3f}"
          f"   (off-by-one: {summary['severity_off_by_one']:.3f})")
    print(f"  technique hit-rate     : {summary['technique_hit_rate']:.3f}"
          f"   (jaccard: {summary['technique_jaccard']:.3f})")
    print(f"  faithfulness           : {summary['faithfulness']:.3f}")
    print(f"\n  {'class':16} {'sev':>5} {'tech':>5} {'faith':>6}")
    for c, v in summary["per_class"].items():
        print(f"  {c:16} {v['severity']:>5.2f} {v['technique']:>5.2f} {v['faithfulness']:>6.2f}")


if __name__ == "__main__":
    # Wired end to end in run_eval.py; this block is a self-test of the math.
    from src.schema import Assessment

    def mk(sev, assess, tech):
        return TriageResult(severity=sev, assessment=assess, attack_technique_ids=tech,
                            explanation="x", recommended_action="y", confidence=0.5)

    # severity: exact, off-by-one, far
    assert severity_scores(Severity.HIGH, Severity.HIGH) == (1, 1)
    assert severity_scores(Severity.HIGH, Severity.CRITICAL) == (0, 1)
    assert severity_scores(Severity.LOW, Severity.CRITICAL) == (0, 0)
    # technique family overlap
    assert technique_scores(["T1110.003"], ["T1110"]) == (1, 1.0)
    assert technique_scores(["T1046"], ["T1595", "T1046"])[0] == 1
    assert technique_scores([], [])[0] == 1              # normal, correctly empty
    assert technique_scores(["T1071"], [])[0] == 0       # normal, wrongly cited
    # faithfulness: cited a technique NOT in context -> penalized even if 'right'
    assert faithfulness_score(["T1110", "T1499"], ["T1110"]) == 0.5
    assert faithfulness_score(["T1110.003"], ["T1110"]) == 1.0  # family-grounded
    assert faithfulness_score([], ["T1110"]) == 1.0
    print("ALL ANSWER-METRIC UNIT TESTS PASSED")