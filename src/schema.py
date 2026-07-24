"""
Phase 0 — the output contract.

Every component downstream (the RAG generator in Phase 1, the eval harness in
Phase 2, the fine-tuned model in Phase 3) must emit or validate against this
schema. If the model returns something that doesn't parse here, we treat it as a
failure, not as a "best effort" answer. That strictness is the point.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Assessment(str, Enum):
    """The real-vs-false-positive call."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"  # not enough signal to commit either way


# ATT&CK technique IDs look like T1059 or, for sub-techniques, T1059.001
_ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class TriageResult(BaseModel):
    """The structured triage an analyst (or the model standing in for one) produces."""

    severity: Severity = Field(
        ..., description="Overall severity of the alert: low, medium, high, or critical."
    )
    assessment: Assessment = Field(
        ...,
        description="Whether this is a genuine detection, a false positive, or inconclusive.",
    )
    attack_technique_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Mapped MITRE ATT&CK technique IDs (e.g. ['T1110', 'T1046']). "
            "Empty list is allowed only when the assessment is false_positive."
        ),
    )
    explanation: str = Field(
        ...,
        min_length=1,
        description="Plain-English reasoning, grounded in the retrieved ATT&CK/CVE context.",
    )
    recommended_action: str = Field(
        ..., min_length=1, description="The next step a responder should take."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence in this triage, from 0.0 to 1.0."
    )
    # Optional traceability so Phase 2 can join predictions back to the labeled alert.
    alert_id: str | None = Field(
        default=None, description="Identifier of the source alert, if available."
    )

    @field_validator("attack_technique_ids")
    @classmethod
    def _validate_attack_ids(cls, ids: list[str]) -> list[str]:
        bad = [i for i in ids if not _ATTACK_ID_RE.match(i)]
        if bad:
            raise ValueError(
                f"Malformed ATT&CK technique IDs: {bad}. Expected 'Tdddd' or 'Tdddd.ddd'."
            )
        return ids


if __name__ == "__main__":
    # Sanity checks — a valid triage parses, garbage is rejected.
    good = TriageResult(
        severity="high",
        assessment="true_positive",
        attack_technique_ids=["T1110", "T1110.001"],
        explanation="Repeated failed logins from a single source matches brute-force behavior.",
        recommended_action="Lock the targeted account and block the source IP.",
        confidence=0.82,
        alert_id="unsw-00417",
    )
    print("VALID:", good.model_dump_json(indent=2))

    for label, payload in {
        "bad technique id": dict(
            severity="low", assessment="inconclusive",
            attack_technique_ids=["1110"], explanation="x",
            recommended_action="y", confidence=0.1,
        ),
        "confidence out of range": dict(
            severity="low", assessment="true_positive",
            attack_technique_ids=[], explanation="x",
            recommended_action="y", confidence=1.4,
        ),
        "bad severity": dict(
            severity="severe", assessment="true_positive",
            attack_technique_ids=[], explanation="x",
            recommended_action="y", confidence=0.5,
        ),
    }.items():
        try:
            TriageResult(**payload)
            print(f"FAIL: {label} should have raised")
        except Exception as e:
            print(f"OK   rejected ({label}): {type(e).__name__}")
