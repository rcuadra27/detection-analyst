"""
Phase 2.5 — label extracted flows using the UNSW ground-truth table.

UNSW-NB15_GT.csv columns:
    Start time, Last time, Attack category, Attack subcategory, Protocol,
    Source IP, Source Port, Destination IP, Destination Port,
    Attack Name, Attack Reference

Matching follows the method UNB used to build CIC-UNSW-NB15: match on the
5-tuple, and when several GT rows share a 5-tuple, disambiguate with the
timestamp window. Flows that match nothing are labelled 'normal'.

LEAK DISCIPLINE: 'Attack Name' and 'Attack Reference' are extremely descriptive
("Solaris rwalld Format String Vulnerability", "CVE 2002-0573"). They are the
ANSWER, not the input. They are kept ONLY as evaluation metadata under keys
prefixed with '_gt_' and must never be rendered into alert text.

Usage:
    python -m src.pcap.label --flows data/processed/flows.jsonl \
        --gt data/raw/UNSW-NB15_GT.csv --out data/processed/flows_labeled.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

# GT header names vary slightly across distributions; normalize loosely.
def _norm(h: str) -> str:
    return h.strip().lower().replace(" ", "_").replace("-", "_")


_WANT = {
    "start_time": ["start_time", "starttime"],
    "last_time": ["last_time", "lasttime", "end_time"],
    "category": ["attack_category", "attack_cat", "category"],
    "subcategory": ["attack_subcategory", "attack_subcat", "subcategory"],
    "proto": ["protocol", "proto"],
    "sip": ["source_ip", "srcip", "src_ip"],
    "sport": ["source_port", "sport", "src_port"],
    "dip": ["destination_ip", "dstip", "dst_ip"],
    "dport": ["destination_port", "dsport", "dport", "dst_port"],
    "name": ["attack_name", "name"],
    "ref": ["attack_reference", "reference"],
}


def _resolve_columns(fieldnames: list[str]) -> dict[str, str]:
    have = {_norm(f): f for f in fieldnames}
    out = {}
    for key, cands in _WANT.items():
        for c in cands:
            if c in have:
                out[key] = have[c]
                break
    missing = [k for k in ("category", "sip", "dip", "dport") if k not in out]
    if missing:
        raise ValueError(f"GT file missing required columns {missing}. Found: {fieldnames}")
    return out


def load_gt(gt_path: str):
    """Index GT rows by (sip, dip, dport, proto) -> list of intervals."""
    idx = defaultdict(list)
    n = 0
    with open(gt_path, newline="", encoding="utf-8", errors="replace") as f:
        rdr = csv.DictReader(f)
        cols = _resolve_columns(rdr.fieldnames or [])
        for row in rdr:
            def g(k, default=""):
                c = cols.get(k)
                return (row.get(c) or default).strip() if c else default
            try:
                t0 = float(g("start_time", "0") or 0)
                t1 = float(g("last_time", "0") or 0)
            except ValueError:
                t0 = t1 = 0.0
            proto = g("proto").lower()
            try:
                dport = int(float(g("dport", "0") or 0))
            except ValueError:
                dport = 0
            key = (g("sip"), g("dip"), dport, proto)
            idx[key].append({
                "t0": t0, "t1": t1,
                "category": g("category").strip().lower(),
                "subcategory": g("subcategory"),
                "name": g("name"), "ref": g("ref"),
            })
            n += 1
    print(f"[label] loaded {n} ground-truth rows, {len(idx)} distinct 5-tuple keys")
    return idx


def label_flow(rec: dict, gt_idx, time_slack: float = 2.0):
    """Return (category, meta) for a flow; 'normal' if no GT match.

    Flows are keyed bidirectionally during extraction, so whichever packet
    arrived first determines the stored src/dst. That may be the RESPONSE
    direction, which would be reversed relative to the ground-truth table.
    We therefore try both orientations before concluding 'normal'.
    """
    sip, dip = rec.get("_src_ip", ""), rec.get("_dst_ip", "")
    proto = rec.get("proto", "")
    dport = int(rec.get("dst_port", 0))
    sport = int(rec.get("src_port", 0))

    cands = []
    for key in (
        (sip, dip, dport, proto),      # as captured
        (sip, dip, dport, ""),         # proto missing in GT
        (dip, sip, sport, proto),      # reversed orientation
        (dip, sip, sport, ""),
    ):
        found = gt_idx.get(key)
        if found:
            cands = found
            break
    if not cands:
        return "normal", {}
    if len(cands) == 1:
        c = cands[0]
        return c["category"] or "normal", c
    # disambiguate by time overlap
    f0, f1 = float(rec.get("first_ts", 0)), float(rec.get("last_ts", 0))
    best, best_ov = None, -1.0
    for c in cands:
        ov = min(f1, c["t1"] + time_slack) - max(f0, c["t0"] - time_slack)
        if ov > best_ov:
            best, best_ov = c, ov
    if best is None or best_ov < 0:
        return "normal", {}
    return best["category"] or "normal", best


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", default="data/processed/flows.jsonl")
    ap.add_argument("--gt", default="data/raw/UNSW-NB15_GT.csv")
    ap.add_argument("--out", default="data/processed/flows_labeled.jsonl")
    args = ap.parse_args()

    gt = load_gt(args.gt)
    counts = defaultdict(int)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.flows) as fin, open(args.out, "w") as fout:
        for line in fin:
            if not line.strip():
                continue
            rec = json.loads(line)
            cat, meta = label_flow(rec, gt)
            rec["attack_class"] = cat
            # evaluation-only metadata; NEVER rendered into alert text
            rec["_gt_subcategory"] = meta.get("subcategory", "")
            rec["_gt_name"] = meta.get("name", "")
            rec["_gt_reference"] = meta.get("ref", "")
            counts[cat] += 1
            fout.write(json.dumps(rec) + "\n")

    print(f"[label] wrote {args.out}")
    print("[label] class distribution:")
    for c, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {c:18} {n}")