"""
Phase A — score any pcap: Zeek features -> the trained detector -> a store the
agent reads.

This is the upload path without the web page. It needs no UNSW data at run
time: the definitions chosen by calibration and the ct_state_ttl table are
read from a calibration file committed with the code (src/ingest/calibration.json,
exported once from a parity run with --export-calibration).

Output is the same pair of files the simulated scenario days use
(flows.jsonl, meta.json), so every agent tool works on it unchanged. There is
no truth.json: an uploaded capture has no answer key. meta.json carries the
capture's own false-positive baseline (baseline.py), which the noise check
uses instead of the 6.9% measured on UNSW's test split.

Usage:
    # once, after a parity run whose choices you accept
    python -m src.ingest.score --export-calibration data/processed/parity_validation3
    # then, for any pcap
    python -m src.ingest.score --pcap capture.pcap --out data/uploads/capture
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

CALIBRATION_PATH = Path(__file__).parent / "calibration.json"
MODEL_DIR = Path("data/processed")
THRESHOLD = 0.85
FALLBACK_FALSE_POSITIVE_RATE = 0.069    # UNSW test split
# The per-capture estimate (baseline.py) failed its first validation, which turned
# out to use the wrong reference (docs/upload.md). It stays off until it passes
# rule v2 on fresh captures; until then uploads use the stated default. The
# estimate is still computed and stored in meta["baseline"].
USE_CAPTURE_ESTIMATE = False
FALLBACK_SOURCE = ("UNSW test split; on UNSW captures scored through Zeek, innocent hosts "
                   "were flagged at 0-0.003%, so this reference is very lenient "
                   "(per-capture estimate disabled until it passes validation)")

# Columns copied into each flow's evidence, under the names the scenario uses.
_EVIDENCE = (("proto", "proto"), ("service", "service"), ("state", "state"),
             ("dur", "duration"), ("spkts", "src_pkts"), ("dpkts", "dst_pkts"),
             ("sbytes", "src_bytes"), ("rate", "rate"))
# HTTP fields are attacker-controlled text. The tools already label evidence as
# untrusted and truncate it; these keys start with http_ so they are counted.
_HTTP = (("method", "http_method"), ("host", "http_host"), ("uri", "http_uri"),
         ("user_agent", "http_user_agent"))


# ---------------------------------------------------------------- calibration

def export_calibration(parity_dir: Path, out: Path = CALIBRATION_PATH) -> dict:
    """Freeze a parity run's chosen definitions and ct_state_ttl table."""
    choice = json.loads((parity_dir / "choice.json").read_text())["choice"]
    lookup = json.loads((parity_dir / "ct_state_ttl_lookup.json").read_text())
    cal = {"source": str(parity_dir), "exported_at": dt.date.today().isoformat(),
           "choice": choice, "ct_lookup": lookup}
    out.write_text(json.dumps(cal, indent=1))
    return cal


def load_calibration(path: Path = CALIBRATION_PATH) -> dict:
    if not Path(path).exists():
        raise FileNotFoundError(
            f"No calibration at {path}. Export one from a parity run: "
            "python -m src.ingest.score --export-calibration data/processed/parity_validation3")
    return json.loads(Path(path).read_text())


# ---------------------------------------------------------------- scoring

def _clean(v):
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (float, np.floating)):
        return round(float(v), 2) if np.isfinite(v) else None
    return v


def _http_by_uid(workdir: Path) -> dict[str, dict]:
    from src.ingest.zeek_run import read_log
    h = read_log(workdir, "http")
    if h.empty or "uid" not in h.columns:
        return {}
    first = h.drop_duplicates("uid").set_index("uid")
    out = {}
    for uid, r in first.iterrows():
        ev = {key: str(r[col]) for col, key in _HTTP
              if col in r and isinstance(r[col], str) and r[col] not in ("", "-")}
        if ev:
            out[uid] = ev
    return out


def score_features(feats: pd.DataFrame, stage1, stage2, threshold: float = THRESHOLD,
                   http: dict[str, dict] | None = None):
    """42-feature frame (+ META columns) -> FlowRecords, per-flow alerts, classes."""
    from src.agent.store import FlowRecord
    from src.ingest.features import UNSW_FEATURES

    classes = [str(c) for c in stage2.named_steps["clf"].classes_]
    if feats.empty:
        return [], np.array([], dtype=bool), classes
    X = feats[UNSW_FEATURES]
    p_atk = stage1.predict_proba(X)[:, 1]
    proba = stage2.predict_proba(X)
    http = http or {}
    flows = []
    for i, r in enumerate(feats.itertuples(index=False)):
        row = r._asdict()
        ev = {key: _clean(row[col]) for col, key in _EVIDENCE if col in row}
        ev.update(http.get(row["uid"], {}))
        flows.append(FlowRecord(
            flow_id=str(row["uid"]), source=str(row["srcip"]), dest=str(row["dstip"]),
            dest_port=int(row["dsport"]), timestamp=round(float(row["ts"]), 6),
            attack_prob=round(float(p_atk[i]), 4),
            class_probs={classes[j]: round(float(proba[i, j]), 4) for j in range(len(classes))},
            evidence=ev))
    return flows, p_atk >= threshold, classes


def score_pcap(pcap: Path, out_dir: Path, calibration: Path = CALIBRATION_PATH,
               stage1: Path | None = None, stage2: Path | None = None,
               threshold: float = THRESHOLD, name: str | None = None):
    """pcap -> out_dir/flows.jsonl + meta.json. Returns the DetectionStore."""
    import joblib

    from src.agent.store import DetectionStore
    from src.ingest.baseline import estimate_baseline
    from src.ingest.features import features_from_pcap

    cal = load_calibration(calibration)
    s1 = joblib.load(stage1 or MODEL_DIR / "stage1_binary.joblib")
    s2 = joblib.load(stage2 or MODEL_DIR / "stage2_multiclass.joblib")
    out_dir = Path(out_dir)
    workdir = out_dir / "zeek"
    _, feats, _ = features_from_pcap(pcap, workdir, cal["choice"], cal["ct_lookup"])
    flows, alerts, classes = score_features(feats, s1, s2, threshold, _http_by_uid(workdir))

    est = estimate_baseline([f.source for f in flows], alerts) if flows else {"rate": None}
    rate = est.get("rate_upper")         # conservative: see baseline.estimate_baseline
    digest = hashlib.sha256(Path(pcap).read_bytes()).hexdigest()
    meta = {
        "scenario": name or Path(pcap).name,
        "mode": "pcap",
        "detector": "trained two-stage models",
        "flow_source": Path(pcap).name,
        "classifier_classes": classes,
        "threshold": threshold,
        "layout": "real traffic from an uploaded pcap, flows built by Zeek",
        "false_positive_rate": (rate if USE_CAPTURE_ESTIMATE and rate is not None
                                else FALLBACK_FALSE_POSITIVE_RATE),
        "false_positive_rate_source": ("estimated from this capture (upper bound of the "
                                       "rate on hosts consistent with chance)"
                                       if USE_CAPTURE_ESTIMATE and rate is not None
                                       else FALLBACK_SOURCE),
        "baseline": {**est, "used": bool(USE_CAPTURE_ESTIMATE and rate is not None)},
        "n_flows": len(flows),
        "n_flagged": int(alerts.sum()) if len(alerts) else 0,
        "pcap_sha256": digest,
        "calibration": cal.get("source"),
        "built_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    store = DetectionStore(flows, meta)
    store.save(out_dir / "flows.jsonl", out_dir / "meta.json")
    return store


def main() -> None:
    ap = argparse.ArgumentParser(description="Score a pcap into an agent-readable store")
    ap.add_argument("--pcap", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--calibration", type=Path, default=CALIBRATION_PATH)
    ap.add_argument("--export-calibration", type=Path, metavar="PARITY_DIR",
                    help="write calibration.json from a parity output dir and exit")
    a = ap.parse_args()
    if a.export_calibration:
        cal = export_calibration(a.export_calibration, a.calibration)
        print(f"[score] calibration from {cal['source']} -> {a.calibration}")
        return
    if not (a.pcap and a.out):
        ap.error("--pcap and --out are required")
    st = score_pcap(a.pcap, a.out, a.calibration)
    m = st.meta
    print(f"[score] {m['n_flows']} flows, {m['n_flagged']} flagged at {m['threshold']}; "
          f"baseline {m['false_positive_rate']:.4%} ({m['false_positive_rate_source']}) "
          f"-> {a.out}")


if __name__ == "__main__":
    main()
