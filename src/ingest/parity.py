"""
Phase A — parity experiment: can Zeek reproduce the features the detector was
trained on, and does the detector behave the same when it can't?

QUESTION: score UNSW's own pcaps two ways, through UNSW's published features and
through features rebuilt by Zeek (features.py), for the SAME flows. If the
detector's decisions agree, uploads of new pcaps can be scored with this model.
If not, this shows which features break it and by how much.

DESIGN
  1. Join each Zeek connection to its UNSW record (UNSW-NB15_1..4.csv carry the
     5-tuple and start time; the training/testing CSVs do not).
  2. CALIBRATE on capture A: for each ambiguous definition (first or last TTL,
     IP or payload bytes, ...), pick the variant that agrees best with UNSW.
  3. VALIDATE on capture B with those choices frozen. Every number in the report
     comes from B, so the calibration cannot inflate it.
  4. Report coverage (UNSW flows Zeek never produced), per-feature agreement,
     state confusion, and detector agreement at the 0.85 operating point.
  5. Swap-one attribution: start from UNSW's features and replace ONE feature
     with Zeek's value. The drop in agreement says which mismatches matter to
     the model, which is not the same as which features differ most.

`rate` is not in the full CSVs, so its formula is checked against the training
CSV instead, which carries rate next to spkts, dpkts and dur.

Usage:
    python -m src.ingest.features --pcap data/raw/pcap/1.pcap --out data/processed/ingest/1
    python -m src.ingest.features --pcap data/raw/pcap/2.pcap --out data/processed/ingest/2
    python -m src.ingest.parity --calib data/processed/ingest/1 --valid data/processed/ingest/2 \
        --unsw-csv data/raw/UNSW-NB15_1.csv --out data/processed/parity
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.ingest.features import (DEFAULT_CHOICE, UNSW_FEATURES, VARIANTS,
                                 apply_ct_state_ttl, learn_ct_state_ttl, select)

FULL_COLS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smean", "dmean",
    "trans_depth", "response_body_len", "sjit", "djit", "stime", "ltime",
    "sinpkt", "dinpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]
CATEGORICAL = ["proto", "service", "state"]
THRESHOLD = 0.85
JOIN_TOLERANCE_S = 1.5    # UNSW stime is whole seconds

# Which features decide each variant group during calibration.
GROUP_FEATURES = {
    "bytes": ["sbytes", "dbytes"],
    "ttl": ["sttl", "dttl"],
    "win": ["swin", "dwin"],
    "jit": ["sjit", "djit"],
    "service": ["service"],
    "body": ["response_body_len"],
    "mthd": ["ct_flw_http_mthd"],
    "loss": ["sloss", "dloss"],
    "window": ["ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
               "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm"],
}


# ---------------------------------------------------------------- loading

def _port(x) -> int:
    try:
        return int(str(x).strip(), 0)     # some rows carry hex ports ('0x000b')
    except ValueError:
        try:
            return int(float(x))
        except (TypeError, ValueError):
            return -1


def load_unsw_full(paths: list[str | Path]) -> pd.DataFrame:
    """Load UNSW-NB15_1..4.csv (headerless, 49 columns) into one frame."""
    frames = []
    for p in paths:
        df = pd.read_csv(p, header=None, low_memory=False, encoding="latin-1")
        if str(df.iloc[0, 0]).strip().lower() == "srcip":   # tolerate a header row
            df = df.iloc[1:]
        if df.shape[1] != len(FULL_COLS):
            raise ValueError(f"{p}: expected {len(FULL_COLS)} columns, got {df.shape[1]}")
        df.columns = FULL_COLS
        frames.append(df)
    u = pd.concat(frames, ignore_index=True)
    for c in ("srcip", "dstip", "proto", "state", "service"):
        u[c] = u[c].astype(str).str.strip()
    u["proto"] = u["proto"].str.lower()
    u["sport"] = u["sport"].map(_port)
    u["dsport"] = u["dsport"].map(_port)
    num = [c for c in FULL_COLS if c not in ("srcip", "dstip", "proto", "state",
                                             "service", "attack_cat")]
    for c in num:
        u[c] = pd.to_numeric(u[c], errors="coerce").fillna(0)
    u["attack_cat"] = (u["attack_cat"].fillna("normal").astype(str).str.strip().str.lower()
                       .replace({"": "normal", "backdoors": "backdoor", "nan": "normal"}))
    u["label"] = u["label"].astype(int)
    return u


def check_rate_formula(train_csv: str | Path) -> dict:
    """Which candidate formula reproduces the training CSV's `rate` column."""
    t = pd.read_csv(train_csv, usecols=["dur", "spkts", "dpkts", "rate"])
    t = t[t["dur"] > 0]
    out = {}
    for v in VARIANTS["rate"]:
        pk = t["spkts"] + t["dpkts"] - (1 if v == "pkts_minus1" else 0)
        cand = pk / t["dur"]
        out[v] = float(np.mean(np.isclose(cand, t["rate"], rtol=1e-3, atol=1e-6)))
    return {"agreement": out, "best": max(out, key=out.get), "rows": int(len(t))}


# ---------------------------------------------------------------- join

def join(zeek: pd.DataFrame, unsw: pd.DataFrame,
         tol: float = JOIN_TOLERANCE_S) -> pd.DataFrame:
    """Match Zeek connections to UNSW records: same 5-tuple, nearest start time.

    Each UNSW record and each Zeek connection is used at most once. Returns one
    row per match with Zeek columns plain and UNSW columns prefixed `u_`.
    """
    z = zeek.copy()
    z["_zi"] = np.arange(len(z))
    u = unsw.add_prefix("u_")
    u["_ui"] = np.arange(len(u))
    m = z.merge(u, left_on=["srcip", "sport", "dstip", "dsport", "l4"],
                right_on=["u_srcip", "u_sport", "u_dstip", "u_dsport", "u_proto"])
    m["_dt"] = (m["ts"] - m["u_stime"]).abs()
    m = m[m["_dt"] <= tol].sort_values("_dt", kind="stable")
    m = m.drop_duplicates("_zi").drop_duplicates("_ui")
    return m.sort_values("_zi").reset_index(drop=True)


def coverage(zeek: pd.DataFrame, unsw: pd.DataFrame, matched: pd.DataFrame) -> dict:
    """Share of UNSW records inside the capture's time span that Zeek produced."""
    lo, hi = zeek["ts"].min() - JOIN_TOLERANCE_S, zeek["end_ts"].max() + JOIN_TOLERANCE_S
    span = unsw[(unsw["stime"] >= lo) & (unsw["stime"] <= hi)].copy()
    span["_ui"] = span.index
    hit = set(matched["_ui"]) if len(matched) else set()
    span["matched"] = span["_ui"].map(lambda i: i in hit)
    def table(col):
        g = span.groupby(col)["matched"].agg(["sum", "count"])
        g["share"] = g["sum"] / g["count"]
        return {k: {"matched": int(r["sum"]), "total": int(r["count"]),
                    "share": round(float(r["share"]), 4)}
                for k, r in g.sort_values("count", ascending=False).iterrows()}
    return {"unsw_in_span": int(len(span)), "matched": int(span["matched"].sum()),
            "share": round(float(span["matched"].mean()) if len(span) else 0.0, 4),
            "by_class": table("attack_cat"), "by_proto": table("proto"),
            "zeek_connections": int(len(zeek)),
            "zeek_unmatched": int(len(zeek) - len(matched))}


# ---------------------------------------------------------------- agreement

def agree(z: pd.Series, u: pd.Series, rel: float = 0.01) -> dict:
    """Exact-ish agreement between a Zeek column and the UNSW column."""
    if not (pd.api.types.is_numeric_dtype(z) and pd.api.types.is_numeric_dtype(u)):
        eq = z.astype(str).str.upper() == u.astype(str).str.upper()
        return {"match": round(float(eq.mean()), 4), "kind": "categorical"}
    zf, uf = z.astype(float).to_numpy(), u.astype(float).to_numpy()
    close = np.abs(zf - uf) <= np.maximum(1e-6, rel * np.abs(uf))
    denom = np.maximum(np.abs(uf), 1e-9)
    relerr = np.abs(zf - uf) / denom
    rho = pd.Series(zf).corr(pd.Series(uf), method="spearman")
    return {"match": round(float(close.mean()), 4),
            "median_rel_err": round(float(np.median(relerr)), 4),
            "spearman": None if pd.isna(rho) else round(float(rho), 4),
            "kind": "numeric"}


def feature_agreement(m: pd.DataFrame) -> dict:
    return {f: agree(m[f], m[f"u_{f}"]) for f in UNSW_FEATURES
            if f != "rate" and f"u_{f}" in m.columns}


def calibrate(base: pd.DataFrame, unsw: pd.DataFrame, ct_lookup: dict | None,
              rate_variant: str) -> dict:
    """Choose each variant group's definition by agreement on this capture.

    Groups are chosen one at a time with the others held at their defaults;
    they touch disjoint features (window counts depend on `service`, so the
    service group is settled first).
    """
    choice = {**DEFAULT_CHOICE, "rate": rate_variant}
    scores: dict[str, dict] = {}
    order = ["service"] + [g for g in GROUP_FEATURES if g != "service"]
    for group in order:
        scores[group] = {}
        for v in VARIANTS[group]:
            trial = {**choice, group: v}
            m = join(select(base, trial, ct_lookup), unsw)
            if not len(m):
                scores[group][v] = 0.0
                continue
            s = [agree(m[f], m[f"u_{f}"])["match"] for f in GROUP_FEATURES[group]]
            scores[group][v] = round(float(np.mean(s)), 4)
        choice[group] = max(scores[group], key=scores[group].get)
    return {"choice": choice, "scores": scores}


# ---------------------------------------------------------------- detector

def unsw_feature_frame(m: pd.DataFrame, rate_variant: str) -> pd.DataFrame:
    """UNSW's own 42 features for the matched rows, in training column order."""
    X = pd.DataFrame({f: m[f"u_{f}"] for f in UNSW_FEATURES if f != "rate"})
    dur = m["u_dur"].to_numpy(float)
    pk = (m["u_spkts"] + m["u_dpkts"]).to_numpy(float) - (1 if rate_variant == "pkts_minus1" else 0)
    X["rate"] = np.where(dur > 0, pk / np.where(dur > 0, dur, 1), 0.0)
    return X[UNSW_FEATURES]


def _rates(pred: np.ndarray, y: np.ndarray) -> dict:
    atk, ben = y == 1, y == 0
    return {"recall": round(float(pred[atk].mean()), 4) if atk.any() else None,
            "fpr": round(float(pred[ben].mean()), 4) if ben.any() else None}


def detector_parity(Xu: pd.DataFrame, Xz: pd.DataFrame, y: np.ndarray,
                    stage1, stage2=None, threshold: float = THRESHOLD) -> dict:
    pu = stage1.predict_proba(Xu)[:, 1]
    pz = stage1.predict_proba(Xz)[:, 1]
    du, dz = pu >= threshold, pz >= threshold
    out = {
        "n": int(len(y)), "attacks": int(y.sum()), "threshold": threshold,
        "decision_agreement": round(float((du == dz).mean()), 4),
        "unsw_features": _rates(du, y), "zeek_features": _rates(dz, y),
        "prob_spearman": round(float(pd.Series(pu).corr(pd.Series(pz), method="spearman")), 4)
                         if len(y) > 1 else None,
        "flips": {"attack_to_normal": int((du & ~dz).sum()),
                  "normal_to_attack": int((~du & dz).sum())},
    }
    if stage2 is not None and (du & dz).any():
        both = du & dz
        cu = stage2.predict(Xu[both])
        cz = stage2.predict(Xz[both])
        out["class_agreement_on_shared_alerts"] = round(float((cu == cz).mean()), 4)
    # swap-one attribution
    base_dec = du
    swaps = []
    for f in UNSW_FEATURES:
        Xs = Xu.copy()
        Xs[f] = Xz[f].to_numpy()
        ds = stage1.predict_proba(Xs)[:, 1] >= threshold
        r = _rates(ds, y)
        swaps.append({"feature": f,
                      "decision_agreement": round(float((ds == base_dec).mean()), 4),
                      "recall": r["recall"], "fpr": r["fpr"]})
    swaps.sort(key=lambda s: s["decision_agreement"])
    out["swap_one"] = swaps
    return out


# ---------------------------------------------------------------- report

def state_confusion(m: pd.DataFrame, top: int = 12) -> list[dict]:
    c = (m.groupby(["u_state", "state"]).size().sort_values(ascending=False).head(top))
    return [{"unsw": a, "zeek": b, "n": int(n)} for (a, b), n in c.items()]


def write_report(res: dict, out: Path) -> None:
    lines = ["# Zeek feature parity", ""]
    cov = res["coverage"]
    lines += [f"Validation capture: {res['valid']}. Variants chosen on: {res['calib']}.", "",
              "## Coverage", "",
              f"UNSW records in the capture's time span: {cov['unsw_in_span']}. "
              f"Matched to a Zeek connection: {cov['matched']} ({cov['share']:.1%}).", "",
              "| class | matched | total | share |", "|---|---|---|---|"]
    for k, r in cov["by_class"].items():
        lines.append(f"| {k} | {r['matched']} | {r['total']} | {r['share']:.1%} |")
    lines += ["", "| proto (top 10) | matched | total | share |", "|---|---|---|---|"]
    for k, r in list(cov["by_proto"].items())[:10]:
        lines.append(f"| {k} | {r['matched']} | {r['total']} | {r['share']:.1%} |")
    lines += ["", "## Per-feature agreement (matched flows)", "",
              "| feature | source | match | median rel err | spearman |", "|---|---|---|---|---|"]
    for f, a in sorted(res["features"].items(), key=lambda kv: kv[1]["match"]):
        lines.append(f"| {f} | {res['provenance'].get(f, '')} | {a['match']:.1%} | "
                     f"{a.get('median_rel_err', '')} | {a.get('spearman', '')} |")
    d = res.get("detector")
    if d:
        lines += ["", "## Detector at the operating point", "",
                  f"Threshold {d['threshold']}, {d['n']} matched flows, {d['attacks']} attacks.", "",
                  "| features | attack recall | false-positive rate |", "|---|---|---|",
                  f"| UNSW's | {d['unsw_features']['recall']} | {d['unsw_features']['fpr']} |",
                  f"| Zeek's | {d['zeek_features']['recall']} | {d['zeek_features']['fpr']} |", "",
                  f"Decision agreement: {d['decision_agreement']:.1%}. "
                  f"Flips: {d['flips']['attack_to_normal']} attack->normal, "
                  f"{d['flips']['normal_to_attack']} normal->attack.", "",
                  "### Swap-one: features whose Zeek value moves the detector most", "",
                  "| feature | decision agreement | recall | FPR |", "|---|---|---|---|"]
        for s in d["swap_one"][:12]:
            lines.append(f"| {s['feature']} | {s['decision_agreement']:.1%} | {s['recall']} | {s['fpr']} |")
    lines += ["", "## Calibration choices", "", "```json",
              json.dumps(res["calibration"], indent=2), "```"]
    (out / "parity_report.md").write_text("\n".join(lines) + "\n")


def run(calib_dir: Path, valid_dir: Path, unsw_csvs: list[str], out: Path,
        train_csv: str | None, stage1_path: Path | None, stage2_path: Path | None) -> dict:
    from src.ingest.features import PROVENANCE
    out.mkdir(parents=True, exist_ok=True)
    unsw = load_unsw_full(unsw_csvs)
    ct_lookup, rate_check = None, None
    rate_variant = DEFAULT_CHOICE["rate"]
    if train_csv:
        ct_lookup = learn_ct_state_ttl(train_csv)
        (out / "ct_state_ttl_lookup.json").write_text(json.dumps(ct_lookup))
        rate_check = check_rate_formula(train_csv)
        rate_variant = rate_check["best"]

    calib_base = pd.read_csv(calib_dir / "base.csv.gz", low_memory=False)
    cal = calibrate(calib_base, unsw, ct_lookup, rate_variant)
    (out / "choice.json").write_text(json.dumps(cal, indent=2))

    valid_base = pd.read_csv(valid_dir / "base.csv.gz", low_memory=False)
    vz = select(valid_base, cal["choice"], ct_lookup)
    m = join(vz, unsw)
    res = {"calib": str(calib_dir), "valid": str(valid_dir),
           "calibration": cal, "rate_check": rate_check, "provenance": PROVENANCE,
           "ct_state_ttl_purity": ct_lookup["purity"] if ct_lookup else None,
           "coverage": coverage(vz, unsw, m),
           "features": feature_agreement(m) if len(m) else {},
           "state_confusion": state_confusion(m) if len(m) else []}
    if ct_lookup and len(m):
        # Isolate the lookup from TTL/state errors: apply it to UNSW's own inputs.
        own = apply_ct_state_ttl(m["u_state"], m["u_sttl"], m["u_dttl"], ct_lookup)
        res["ct_state_ttl_lookup_on_unsw_inputs"] = round(float((own == m["u_ct_state_ttl"]).mean()), 4)

    if stage1_path and stage1_path.exists() and len(m):
        import joblib
        s1 = joblib.load(stage1_path)
        s2 = joblib.load(stage2_path) if stage2_path and stage2_path.exists() else None
        Xu = unsw_feature_frame(m, rate_variant)
        Xz = m[UNSW_FEATURES].copy()
        res["detector"] = detector_parity(Xu, Xz, m["u_label"].to_numpy(), s1, s2)

    (out / "parity.json").write_text(json.dumps(res, indent=2, default=str))
    write_report(res, out)
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description="Zeek vs UNSW feature parity")
    ap.add_argument("--calib", required=True, type=Path, help="features.py output dir, capture A")
    ap.add_argument("--valid", required=True, type=Path, help="features.py output dir, capture B")
    ap.add_argument("--unsw-csv", required=True, nargs="+", help="UNSW-NB15_[1-4].csv")
    ap.add_argument("--train-csv", default="data/raw/UNSW_NB15_training-set.csv")
    ap.add_argument("--stage1", type=Path, default=Path("data/processed/stage1_binary.joblib"))
    ap.add_argument("--stage2", type=Path, default=Path("data/processed/stage2_multiclass.joblib"))
    ap.add_argument("--out", type=Path, default=Path("data/processed/parity"))
    a = ap.parse_args()
    train = a.train_csv if a.train_csv and Path(a.train_csv).exists() else None
    res = run(a.calib, a.valid, a.unsw_csv, a.out, train, a.stage1, a.stage2)
    cov = res["coverage"]
    print(f"[parity] coverage {cov['matched']}/{cov['unsw_in_span']} ({cov['share']:.1%})")
    if "detector" in res:
        d = res["detector"]
        print(f"[parity] decision agreement {d['decision_agreement']:.1%}; "
              f"recall {d['unsw_features']['recall']} -> {d['zeek_features']['recall']}, "
              f"FPR {d['unsw_features']['fpr']} -> {d['zeek_features']['fpr']}")
    print(f"[parity] report: {a.out / 'parity_report.md'}")


if __name__ == "__main__":
    main()
