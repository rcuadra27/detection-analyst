"""
Phase 2 — labeled test-set builder.

Turns real UNSW-NB15 flows into a labeled eval set: each item is a terse alert
string plus its ground-truth severity and ATT&CK technique IDs (from mapping.py).

Two rules that protect the integrity of every later metric:
  1. The alert text is rendered from NETWORK FEATURES ONLY. attack_cat and label
     never appear in it — otherwise retrieval/generation would be reading the
     answer off the input and the scores would be meaningless.
  2. Sampling is balanced across attack classes, so the eval isn't dominated by
     whichever class happens to be most frequent in the raw data.

Usage:
    python -m src.eval.dataset --csv data/raw/UNSW_NB15_training-set.csv \
        --per-class 8 --out data/processed/eval_set.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import pandas as pd
from pydantic import BaseModel

from src.schema import Severity
from src.mapping import GROUND_TRUTH, get as get_mapping
from src.eval.enrich import enrich_alert

# attack_cat spellings in the wild -> our lowercase mapping keys
_CLASS_ALIASES = {
    "backdoors": "backdoor",
    "dos": "dos",
    "ddos": "ddos",
}

# Network-feature columns we render into the alert. All optional: the renderer
# uses whatever is present, so minor schema differences degrade gracefully.
_RENDER_COLS = [
    "proto", "service", "state", "dur",
    "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl",
]


class LabeledAlert(BaseModel):
    alert_id: str
    alert_text: str
    attack_class: str            # normalized mapping key
    true_severity: Severity
    true_technique_ids: list[str]


def normalize_class(raw: str) -> str:
    key = str(raw).strip().lower()
    return _CLASS_ALIASES.get(key, key)


def render_alert(row: pd.Series) -> str:
    """Render a flow row as a terse, analyst-style alert line. Features only."""
    def val(c):
        return row[c] if c in row and pd.notna(row[c]) else None

    proto = str(val("proto") or "?").upper()
    service = val("service")
    service = None if service in (None, "-", "") else str(service)
    state = val("state")

    head = f"{proto} flow" + (f", service {service}" if service else "")
    if state:
        head += f", state {state}"

    parts = []
    if val("dur") is not None:
        parts.append(f"duration {float(val('dur')):.2f}s")
    if val("spkts") is not None or val("dpkts") is not None:
        parts.append(f"{int(val('spkts') or 0)} src pkts / {int(val('dpkts') or 0)} dst pkts")
    if val("sbytes") is not None or val("dbytes") is not None:
        parts.append(f"{int(val('sbytes') or 0)} src bytes / {int(val('dbytes') or 0)} dst bytes")
    if val("rate") is not None:
        parts.append(f"rate {float(val('rate')):.0f} pkts/s")
    if val("sttl") is not None:
        parts.append(f"src TTL {int(val('sttl'))}")

    return head + (". " + ", ".join(parts) + "." if parts else ".")


def build_eval_set(
    csv_path: str,
    per_class: int = 8,
    seed: int = 13,
    include_normal: bool = True,
    enrich: bool = True,
) -> list[LabeledAlert]:
    df = pd.read_csv(csv_path)
    if "attack_cat" not in df.columns:
        raise ValueError(
            f"'attack_cat' column not found. Columns present: {list(df.columns)[:10]}..."
        )
    df["_class"] = df["attack_cat"].map(normalize_class)

    # Report any class that doesn't resolve against the mapping (integrity check).
    present = set(df["_class"].unique())
    known = set(GROUND_TRUTH)
    unknown = sorted(present - known)
    if unknown:
        print(f"[dataset] WARNING — attack_cat values with no mapping entry, skipped: {unknown}")

    rng = random.Random(seed)
    alerts: list[LabeledAlert] = []
    for cls in sorted(present & known):
        if cls == "normal" and not include_normal:
            continue
        rows = df[df["_class"] == cls]
        idxs = list(rows.index)
        rng.shuffle(idxs)
        picked = idxs[:per_class]
        entry = get_mapping(cls)
        for j, ridx in enumerate(picked):
            row = df.loc[ridx]
            base = render_alert(row)
            text = enrich_alert(base, row) if enrich else base
            alerts.append(LabeledAlert(
                alert_id=f"{cls}-{j:03d}",
                alert_text=text,
                attack_class=cls,  # noqa
                true_severity=entry.severity,
                true_technique_ids=entry.technique_ids,
            ))
    rng.shuffle(alerts)
    return alerts


def save_jsonl(alerts: list[LabeledAlert], out_path: str) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for a in alerts:
            f.write(a.model_dump_json() + "\n")
    print(f"[dataset] wrote {len(alerts)} labeled alerts -> {out_path}")


def load_jsonl(path: str) -> list[LabeledAlert]:
    with open(path) as f:
        return [LabeledAlert.model_validate_json(line) for line in f if line.strip()]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="data/raw/UNSW_NB15_training-set.csv")
    ap.add_argument("--per-class", type=int, default=8)
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--out", default="data/processed/eval_set.jsonl")
    ap.add_argument("--no-enrich", action="store_true",
                    help="render raw flow lines only (baseline, no behavioral descriptors)")
    args = ap.parse_args()

    alerts = build_eval_set(args.csv, per_class=args.per_class, seed=args.seed,
                            enrich=not args.no_enrich)
    print(f"[dataset] built {len(alerts)} alerts across "
          f"{len(set(a.attack_class for a in alerts))} classes")
    print("\n--- 3 sample alerts ---")
    for a in alerts[:3]:
        print(f"[{a.attack_class}] sev={a.true_severity.value} {a.true_technique_ids}")
        print(f"    {a.alert_text}")
    save_jsonl(alerts, args.out)