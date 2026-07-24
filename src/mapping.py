"""
Phase 0 — the ground-truth mapping. THE load-bearing artifact.

Maps each NIDS attack class (UNSW-NB15 and ToN-IoT) to:
  - the correct MITRE ATT&CK technique ID(s),
  - the correct severity,
  - a mapping-confidence flag, so we know which rows are solid and which are
    judgment calls worth revisiting.

This table is hand-authored. Every accuracy number reported later in Phase 2 is
measured against it, so a wrong row here silently corrupts the whole eval. The
mappings below are a defensible v1; the ones marked LOW/MEDIUM confidence are
where domain review matters most.

NOTE: the technique IDs here are asserted from knowledge of ATT&CK. Once the
STIX corpus is downloaded (next Phase 0 task), run validate_against_attack() to
confirm every ID actually exists in the catalog.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, field_validator

from .schema import Severity, _ATTACK_ID_RE


class MapConfidence(str, Enum):
    HIGH = "high"        # clean, well-established mapping
    MEDIUM = "medium"    # reasonable but the class is broad or the fit is loose
    LOW = "low"          # ATT&CK has no clean equivalent; revisit


class GroundTruthEntry(BaseModel):
    attack_class: str
    datasets: list[str]          # which dataset(s) this class appears in
    technique_ids: list[str]
    technique_names: list[str]   # human-readable, for sanity-checking the IDs
    severity: Severity
    confidence: MapConfidence
    notes: str = ""

    @field_validator("technique_ids")
    @classmethod
    def _validate_ids(cls, ids: list[str]) -> list[str]:
        bad = [i for i in ids if not _ATTACK_ID_RE.match(i)]
        if bad:
            raise ValueError(f"Malformed ATT&CK IDs in mapping: {bad}")
        return ids


UNSW = "UNSW-NB15"
TON = "ToN-IoT"


_ENTRIES: list[GroundTruthEntry] = [
    # --- benign baseline ---------------------------------------------------
    GroundTruthEntry(
        attack_class="normal",
        datasets=[UNSW, TON],
        technique_ids=[],
        technique_names=[],
        severity=Severity.LOW,
        confidence=MapConfidence.HIGH,
        notes="Benign traffic. Correct triage is assessment=false_positive, no technique.",
    ),
    # --- UNSW-NB15 classes -------------------------------------------------
    GroundTruthEntry(
        attack_class="fuzzers",
        datasets=[UNSW],
        technique_ids=["T1595.002", "T1499"],
        technique_names=["Active Scanning: Vulnerability Scanning", "Endpoint Denial of Service"],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.MEDIUM,
        notes="Feeding malformed/random input to find faults; can crash services. Discovery + possible DoS.",
    ),
    GroundTruthEntry(
        attack_class="analysis",
        datasets=[UNSW],
        technique_ids=["T1595", "T1046"],
        technique_names=["Active Scanning", "Network Service Discovery"],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.LOW,
        notes="UNSW's 'Analysis' is a grab-bag (port scan, spam, HTML penetration). No single clean ATT&CK fit.",
    ),
    GroundTruthEntry(
        attack_class="backdoor",
        datasets=[UNSW, TON],
        technique_ids=["T1133", "T1505.003", "T1071"],
        technique_names=["External Remote Services", "Server Software Component: Web Shell",
                         "Application Layer Protocol"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Persistent unauthorized remote access channel.",
    ),
    GroundTruthEntry(
        attack_class="dos",
        datasets=[UNSW, TON],
        technique_ids=["T1499", "T1498"],
        technique_names=["Endpoint Denial of Service", "Network Denial of Service"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Single-source denial of service.",
    ),
    GroundTruthEntry(
        attack_class="exploits",
        datasets=[UNSW],
        technique_ids=["T1190", "T1210", "T1203"],
        technique_names=["Exploit Public-Facing Application", "Exploitation of Remote Services",
                         "Exploitation for Client Execution"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Exploitation of a known vulnerability; severity can rise to critical given RCE + exposure.",
    ),
    GroundTruthEntry(
        attack_class="generic",
        datasets=[UNSW],
        technique_ids=[],
        technique_names=[],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.LOW,
        notes=(
            "UNSW 'Generic' = cryptanalytic attacks against block ciphers. "
            "ATT&CK has no equivalent technique, so the correct behavior is to cite no technique."
        ),
    ),
    GroundTruthEntry(
        attack_class="reconnaissance",
        datasets=[UNSW],
        technique_ids=["T1595", "T1046", "T1590"],
        technique_names=["Active Scanning", "Network Service Discovery",
                         "Gather Victim Network Information"],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.HIGH,
        notes="Pre-attack info gathering. Severity is defensible as LOW (low impact) vs MEDIUM (intent signal).",
    ),
    GroundTruthEntry(
        attack_class="shellcode",
        datasets=[UNSW],
        technique_ids=["T1203", "T1059"],
        technique_names=["Exploitation for Client Execution", "Command and Scripting Interpreter"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Payload that achieves code execution.",
    ),
    GroundTruthEntry(
        attack_class="worms",
        datasets=[UNSW],
        technique_ids=["T1210", "T1570", "T1021"],
        technique_names=["Exploitation of Remote Services", "Lateral Tool Transfer", "Remote Services"],
        severity=Severity.CRITICAL,
        confidence=MapConfidence.HIGH,
        notes="Self-propagating across hosts; fast blast radius justifies critical.",
    ),
    # --- ToN-IoT classes (excluding overlaps above) ------------------------
    GroundTruthEntry(
        attack_class="ddos",
        datasets=[TON],
        technique_ids=["T1498", "T1499"],
        technique_names=["Network Denial of Service", "Endpoint Denial of Service"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Distributed DoS; arguably critical at scale.",
    ),
    GroundTruthEntry(
        attack_class="injection",
        datasets=[TON],
        technique_ids=["T1190", "T1059"],
        technique_names=["Exploit Public-Facing Application", "Command and Scripting Interpreter"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="SQL/command injection against an app.",
    ),
    GroundTruthEntry(
        attack_class="mitm",
        datasets=[TON],
        technique_ids=["T1557", "T1557.002"],
        technique_names=["Adversary-in-the-Middle", "Adversary-in-the-Middle: ARP Cache Poisoning"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Interception/relay of traffic.",
    ),
    GroundTruthEntry(
        attack_class="password",
        datasets=[TON],
        technique_ids=["T1110", "T1110.001"],
        technique_names=["Brute Force", "Brute Force: Password Guessing"],
        severity=Severity.HIGH,
        confidence=MapConfidence.HIGH,
        notes="Credential attack. Defensible as MEDIUM if it's slow guessing with no success signal.",
    ),
    GroundTruthEntry(
        attack_class="ransomware",
        datasets=[TON],
        technique_ids=["T1486", "T1490", "T1489"],
        technique_names=["Data Encrypted for Impact", "Inhibit System Recovery", "Service Stop"],
        severity=Severity.CRITICAL,
        confidence=MapConfidence.HIGH,
        notes="Destructive impact.",
    ),
    GroundTruthEntry(
        attack_class="scanning",
        datasets=[TON],
        technique_ids=["T1595", "T1046"],
        technique_names=["Active Scanning", "Network Service Discovery"],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.HIGH,
        notes="Overlaps conceptually with UNSW 'reconnaissance'.",
    ),
    GroundTruthEntry(
        attack_class="xss",
        datasets=[TON],
        technique_ids=["T1059.007", "T1539"],
        technique_names=["Command and Scripting Interpreter: JavaScript", "Steal Web Session Cookie"],
        severity=Severity.MEDIUM,
        confidence=MapConfidence.LOW,
        notes="Web-app attack; ATT&CK (host/enterprise-centric) maps it only loosely. Flagged for review.",
    ),
]

GROUND_TRUTH: dict[str, GroundTruthEntry] = {e.attack_class: e for e in _ENTRIES}


def get(attack_class: str) -> GroundTruthEntry:
    """Look up a class label, case-insensitively."""
    key = attack_class.strip().lower()
    if key not in GROUND_TRUTH:
        raise KeyError(f"Unknown attack class '{attack_class}'. Known: {sorted(GROUND_TRUTH)}")
    return GROUND_TRUTH[key]


def validate_against_attack(known_ids: set[str]) -> list[str]:
    """Given the set of real technique IDs from the ATT&CK STIX corpus,
    return any IDs in this mapping that aren't in the catalog. Run this once
    the corpus is downloaded."""
    used = {tid for e in _ENTRIES for tid in e.technique_ids}
    return sorted(used - known_ids)


if __name__ == "__main__":
    print(f"{len(GROUND_TRUTH)} classes mapped (all IDs format-valid).\n")
    flagged = [e for e in _ENTRIES if e.confidence != MapConfidence.HIGH]
    print("Rows worth domain review:")
    for e in flagged:
        ids = ", ".join(e.technique_ids) or "(none)"
        print(f"  [{e.confidence.value:6}] {e.attack_class:15} sev={e.severity.value:8} {ids}")