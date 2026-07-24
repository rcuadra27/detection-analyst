"""
Phase 0 — reference corpus acquisition and mapping validation.

Downloads the MITRE ATT&CK Enterprise corpus (STIX 2.1 JSON from MITRE's
official attack-stix-data repo), extracts every technique into a clean list of
records, and cross-checks the ground-truth mapping in src/mapping.py against
the real catalog.

The extracted technique records (id, name, description, tactics) are exactly
what Phase 1 will chunk and embed, so this module is reused there.

Usage (from the project root, venv active):
    python -m src.corpus            # download if missing, extract, validate
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import requests

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
RAW_DIR = Path("data/raw")
ATTACK_PATH = RAW_DIR / "enterprise-attack.json"


@dataclass
class AttackTechnique:
    technique_id: str          # e.g. "T1110" or "T1110.001"
    name: str
    description: str
    tactics: list[str] = field(default_factory=list)  # kill-chain phases
    is_subtechnique: bool = False
    deprecated: bool = False


def download_attack(force: bool = False) -> Path:
    """Fetch the enterprise ATT&CK STIX bundle if not already present."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    if ATTACK_PATH.exists() and not force:
        print(f"[corpus] already present: {ATTACK_PATH}")
        return ATTACK_PATH
    print(f"[corpus] downloading ATT&CK enterprise bundle ...")
    resp = requests.get(ATTACK_URL, timeout=120)
    resp.raise_for_status()
    ATTACK_PATH.write_bytes(resp.content)
    print(f"[corpus] saved {ATTACK_PATH} ({ATTACK_PATH.stat().st_size / 1e6:.1f} MB)")
    return ATTACK_PATH


def load_attack_techniques(path: Path = ATTACK_PATH,
                           include_deprecated: bool = False) -> list[AttackTechnique]:
    """Parse the STIX bundle into technique records.

    In STIX, techniques are 'attack-pattern' objects; the human-facing Txxxx ID
    lives in external_references under source_name == 'mitre-attack'.
    """
    bundle = json.loads(path.read_text())
    techniques: list[AttackTechnique] = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = next(
            (r.get("external_id") for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id or not ext_id.startswith("T"):
            continue
        deprecated = obj.get("x_mitre_deprecated", False) or obj.get("revoked", False)
        if deprecated and not include_deprecated:
            continue
        techniques.append(AttackTechnique(
            technique_id=ext_id,
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=[p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])],
            is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
            deprecated=deprecated,
        ))
    return techniques


def attack_id_set(techniques: list[AttackTechnique]) -> set[str]:
    return {t.technique_id for t in techniques}


if __name__ == "__main__":
    from src.mapping import GROUND_TRUTH, validate_against_attack

    download_attack()
    techniques = load_attack_techniques()
    ids = attack_id_set(techniques)
    n_sub = sum(t.is_subtechnique for t in techniques)
    print(f"[corpus] {len(techniques)} active techniques "
          f"({len(techniques) - n_sub} parents, {n_sub} sub-techniques)")

    missing = validate_against_attack(ids)
    if missing:
        print(f"[VALIDATE] FAIL — these mapped IDs are NOT in the ATT&CK catalog: {missing}")
        raise SystemExit(1)

    # Also confirm none of the mapped IDs point at deprecated/revoked techniques.
    all_techs = {t.technique_id: t for t in load_attack_techniques(include_deprecated=True)}
    used = {tid for e in GROUND_TRUTH.values() for tid in e.technique_ids}
    dep = sorted(t for t in used if all_techs[t].deprecated)
    if dep:
        print(f"[VALIDATE] WARNING — mapped IDs are deprecated/revoked in ATT&CK: {dep}")
    else:
        print("[VALIDATE] OK — every mapped technique ID exists and is active. Sample:")
        for tid in sorted(used)[:5]:
            print(f"    {tid:10} {all_techs[tid].name}")
        print(f"    ... ({len(used)} mapped IDs total)")