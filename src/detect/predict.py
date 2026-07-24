"""
Phase 3d — the detection OUTPUT layer: ranked hypotheses, not a forced label.

WHY NOT A SINGLE CLASS
Fine-grained evaluation showed some UNSW classes are hard to separate from flow
features (analysis 0.04 F1; backdoor 0.06 precision; dos 0.21 recall). Two bad
responses to that:

  - Force a single label anyway -> confident-looking output that is frequently
    wrong, which is how analysts learn to distrust a tool.
  - Merge the confusable classes -> destroys distinctions the analyst acts on.
    A worm (contain spread now) and a backdoor (hunt the implant) have different
    playbooks; collapsing them into "persistence" costs real information.

INSTEAD: report what the model actually believes.
  - confident      -> the specific class
  - split          -> the top candidates, with the note that flow features
                      cannot separate them and what evidence would
  - diffuse        -> back off to the ATT&CK-tactic family

Uncertainty becomes actionable guidance rather than hidden error. The candidate
techniques passed downstream are the union over surviving hypotheses, so the RAG
layer retrieves documentation for everything still in play.

Usage:
    python -m src.detect.predict --demo
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from src.detect.grouped import GROUPS, GROUP_SEVERITY, GROUP_TECHNIQUES
from src.mapping import GROUND_TRUTH

MODEL_DIR = Path("data/processed")

# Decision bands for how to present the result.
CONFIDENT = 0.60          # top-1 this high -> report the specific class
CANDIDATE_FLOOR = 0.15    # candidates below this are dropped
MAX_CANDIDATES = 3


@dataclass
class Hypothesis:
    attack_class: str
    probability: float
    technique_ids: list[str] = field(default_factory=list)
    severity: str = "medium"


@dataclass
class Detection:
    is_attack: bool
    attack_probability: float
    hypotheses: list[Hypothesis]
    presentation: str           # "confident" | "split" | "diffuse" | "benign"
    group: str | None           # ATT&CK-tactic family when backing off
    candidate_techniques: list[str]
    note: str = ""

    def summary(self) -> str:
        if not self.is_attack:
            return f"benign (attack probability {self.attack_probability:.2f})"
        top = self.hypotheses[0]
        # Always report the full candidate technique set: when a secondary
        # hypothesis survives the floor, its techniques are retrieved too and
        # the model may legitimately cite them. Showing only the top
        # hypothesis's techniques under-reports what was actually in context.
        techs = ", ".join(self.candidate_techniques) or "(none)"
        if self.presentation == "confident":
            secondary = self.hypotheses[1:]
            alt = ("; also " + ", ".join(f"{h.attack_class} {h.probability:.0%}"
                                         for h in secondary)) if secondary else ""
            return (f"{top.attack_class} ({top.probability:.0%} confidence{alt}), "
                    f"techniques in context: {techs}")
        if self.presentation == "split":
            alts = ", ".join(f"{h.attack_class} {h.probability:.0%}"
                             for h in self.hypotheses)
            return f"ambiguous between: {alts} | techniques in context: {techs}"
        return (f"{self.group}-family activity, specific type undetermined "
                f"| techniques in context: {techs}")


# Pairs known to be hard to separate from flow features, with the evidence that
# would actually disambiguate them. Derived from the fine-grained confusion
# results, and stated in the output so the analyst knows where to look next.
_DISAMBIGUATION = {
    frozenset({"exploits", "analysis"}):
        "Flow statistics do not separate exploitation from analysis probes. "
        "Check application/web server logs for malformed requests or error responses.",
    frozenset({"exploits", "backdoor"}):
        "Check for persistence indicators — outbound beaconing, unexpected listening "
        "ports, or new scheduled tasks on the destination host.",
    frozenset({"exploits", "shellcode"}):
        "Shellcode is commonly the payload of an exploit; inspect packet payload or "
        "endpoint telemetry for injected code execution.",
    frozenset({"reconnaissance", "analysis"}):
        "Both indicate pre-attack information gathering; the practical response is "
        "the same — verify exposure of the probed service.",
    frozenset({"dos", "generic"}):
        "Check request-rate metrics and service availability on the destination.",
    frozenset({"backdoor", "worms"}):
        "Critical distinction: check whether the same pattern appears toward OTHER "
        "internal hosts. Fan-out indicates self-propagation (worm); a single "
        "persistent channel indicates a backdoor.",
}


def _techniques_for(cls: str) -> tuple[list[str], str]:
    entry = GROUND_TRUTH.get(cls)
    if entry:
        return list(entry.technique_ids), entry.severity.value
    grp = GROUPS.get(cls, cls)
    return list(GROUP_TECHNIQUES.get(grp, [])), GROUP_SEVERITY.get(grp, "medium")


def interpret(class_probs: dict[str, float], attack_prob: float,
              attack_threshold: float = 0.5) -> Detection:
    """Turn a probability distribution into an analyst-facing detection."""
    if attack_prob < attack_threshold:
        return Detection(is_attack=False, attack_probability=attack_prob,
                         hypotheses=[], presentation="benign", group=None,
                         candidate_techniques=[],
                         note="Traffic consistent with normal activity.")

    ranked = sorted(class_probs.items(), key=lambda x: -x[1])
    kept = [(c, p) for c, p in ranked if p >= CANDIDATE_FLOOR][:MAX_CANDIDATES]
    if not kept:
        kept = ranked[:1]

    hyps = []
    for c, p in kept:
        tids, sev = _techniques_for(c)
        hyps.append(Hypothesis(attack_class=c, probability=float(p),
                               technique_ids=tids, severity=sev))

    top_p = hyps[0].probability
    groups = {GROUPS.get(h.attack_class, h.attack_class) for h in hyps}
    pair_key = frozenset(h.attack_class for h in hyps[:2])
    specific_note = _DISAMBIGUATION.get(pair_key)

    if top_p >= CONFIDENT:
        presentation, group, note = "confident", None, ""
    elif specific_note:
        # A known-confusable pair with concrete disambiguating evidence. Report
        # the candidates explicitly even if they share an ATT&CK family —
        # backdoor vs worms sit in the same family but have different response
        # playbooks, so collapsing them would hide what the analyst must decide.
        presentation, group, note = "split", None, specific_note
    elif len(hyps) >= 2 and len(groups) == 1:
        # spread within one ATT&CK family and no specific guidance -> back off
        presentation = "diffuse"
        group = next(iter(groups))
        note = (f"Model is uncertain among {', '.join(h.attack_class for h in hyps)}, "
                f"all within the {group} family. Reporting at family level.")
    else:
        presentation, group = "split", None
        note = ("Flow features are insufficient to separate these; corroborate "
                "with host or application telemetry.")

    # union of techniques across surviving hypotheses -> RAG retrieves them all
    cand: list[str] = []
    for h in hyps:
        for t in h.technique_ids:
            if t not in cand:
                cand.append(t)

    return Detection(is_attack=True, attack_probability=attack_prob,
                     hypotheses=hyps, presentation=presentation, group=group,
                     candidate_techniques=cand, note=note)


def detect(X: pd.DataFrame, attack_threshold: float = 0.5,
           stage1_path: Path | None = None, stage2_path: Path | None = None
           ) -> list[Detection]:
    """Run the two-stage detector and interpret each row."""
    import joblib
    s1 = joblib.load(stage1_path or MODEL_DIR / "stage1_binary.joblib")
    s2 = joblib.load(stage2_path or MODEL_DIR / "stage2_multiclass.joblib")

    p_atk = s1.predict_proba(X)[:, 1]
    proba = s2.predict_proba(X)
    classes = s2.named_steps["clf"].classes_

    out = []
    for i in range(len(X)):
        dist = {classes[j]: float(proba[i, j]) for j in range(len(classes))}
        out.append(interpret(dist, float(p_atk[i]), attack_threshold))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="show the three presentation modes")
    args = ap.parse_args()

    if args.demo:
        cases = {
            "confident detection": (0.97, {"generic": 0.91, "exploits": 0.05, "dos": 0.02}),
            "split between families": (0.88, {"exploits": 0.41, "analysis": 0.33, "dos": 0.10}),
            "diffuse within a family": (0.84, {"exploits": 0.34, "shellcode": 0.31,
                                               "fuzzers": 0.06}),
            "worm vs backdoor (playbooks differ)": (0.91, {"backdoor": 0.44, "worms": 0.39}),
            "benign": (0.08, {"generic": 0.5, "exploits": 0.3}),
        }
        for name, (ap_, dist) in cases.items():
            d = interpret(dist, ap_)
            print(f"\n[{name}]")
            print(f"  -> {d.summary()}")
            print(f"     presentation: {d.presentation}")
            if d.candidate_techniques:
                print(f"     techniques to retrieve: {d.candidate_techniques}")
            if d.note:
                print(f"     analyst note: {d.note}")