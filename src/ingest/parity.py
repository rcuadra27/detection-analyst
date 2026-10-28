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

CONN_PROTOS = ("tcp", "udp", "icmp")
_KEY = ["srcip", "sport", "dstip", "dsport", "_fam"]
# Two UNSW rows with all of these equal are the same flow written twice.
DUP_COLS = ["srcip", "sport", "dstip", "dsport", "proto", "stime", "ltime",
            "sbytes", "dbytes", "spkts", "dpkts"]


def _family(s: pd.Series) -> pd.Series:
    """tcp/udp/icmp stay as they are; every other protocol (and ARP) is 'other'.

    Flows on the other-protocol path are matched by addresses and time, and the
    protocol name is compared as a feature, so a naming difference shows up in
    the report instead of as a missing flow."""
    s = s.astype(str)
    return s.where(s.isin(CONN_PROTOS), "other")


def join(zeek: pd.DataFrame, unsw: pd.DataFrame,
         tol: float = JOIN_TOLERANCE_S) -> pd.DataFrame:
    """Match Zeek connections to UNSW records: same 5-tuple, nearest start time.

    Each UNSW record and each Zeek connection is used at most once. Returns one
    row per match with Zeek columns plain and UNSW columns prefixed `u_`.
    """
    z = zeek.copy()
    z["_zi"] = np.arange(len(z))
    z["_fam"] = _family(z["l4"])
    u = unsw.add_prefix("u_")
    u["_ui"] = np.arange(len(u))
    u["u__fam"] = _family(u["u_proto"])
    m = z.merge(u, left_on=_KEY, right_on=[f"u_{k}" for k in _KEY])
    m["_dt"] = (m["ts"] - m["u_stime"]).abs()
    # prefer a same-name match (matters on the other-protocol path, where
    # several protocols can share addresses and time)
    m["_name_diff"] = (m["proto"].astype(str) != m["u_proto"].astype(str)).astype(int) \
        if "proto" in m.columns else 0
    m = m[m["_dt"] <= tol].sort_values(["_name_diff", "_dt"], kind="stable")
    m = m.drop_duplicates("_zi").drop_duplicates("_ui")
    return m.sort_values("_zi").reset_index(drop=True)


def _in_span(zeek: pd.DataFrame, unsw: pd.DataFrame) -> pd.DataFrame:
    lo, hi = zeek["ts"].min() - JOIN_TOLERANCE_S, zeek["end_ts"].max() + JOIN_TOLERANCE_S
    return unsw[(unsw["stime"] >= lo) & (unsw["stime"] <= hi)].copy()


def covered_rows(zeek: pd.DataFrame, span: pd.DataFrame, tol: float = JOIN_TOLERANCE_S,
                 require_name: bool = True) -> pd.Series:
    """True for each UNSW row that some Zeek flow matches (same key, start time
    within tolerance). Unlike `join`, several UNSW rows may share one Zeek flow:
    UNSW writes some flows several times, once per attack label.

    For other-protocol flows the protocol name must also agree. A protocol
    sweep sends many protocols to one host in the same second, so matching on
    addresses and time alone lets a 'pim' flow cover a 'mobile' record.
    `require_name=False` gives the name-agnostic count for comparison."""
    z = zeek[["srcip", "sport", "dstip", "dsport", "l4", "ts"]].copy()
    z["proto"] = zeek["proto"] if "proto" in zeek.columns else zeek["l4"]
    z["_fam"] = _family(z["l4"])
    z = z.rename(columns={"proto": "_zproto"})
    s = span[["srcip", "sport", "dstip", "dsport", "proto", "stime"]].copy()
    s["_fam"] = _family(s["proto"])
    s["_row"] = span.index
    mm = s.merge(z[_KEY + ["ts", "_zproto"]], on=_KEY)
    ok = (mm["ts"] - mm["stime"]).abs() <= tol
    if require_name:
        ok &= (mm["_fam"] != "other") | (mm["_zproto"].astype(str) == mm["proto"].astype(str))
    hit = set(mm.loc[ok, "_row"])
    return pd.Series(span.index.isin(list(hit)), index=span.index)


def _dup_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in DUP_COLS if c in df.columns]


def duplicates(span: pd.DataFrame) -> dict:
    """How often UNSW writes the same flow more than once, and with which labels."""
    g = span.groupby(_dup_cols(span), dropna=False)
    size = g.size()
    labels = g["attack_cat"].nunique()
    return {"rows": int(len(span)), "distinct_flows": int(len(size)),
            "rows_in_duplicated_flows": int(size[size > 1].sum()),
            "duplicated_flows": int((size > 1).sum()),
            "flows_with_conflicting_labels": int((labels > 1).sum()),
            "rows_in_conflicting_flows": int(size[labels > 1].sum())}


def coverage(zeek: pd.DataFrame, unsw: pd.DataFrame, matched: pd.DataFrame) -> dict:
    """Share of UNSW records inside the capture's time span that Zeek produced."""
    span = _in_span(zeek, unsw)
    span["matched"] = covered_rows(zeek, span)
    any_name = covered_rows(zeek, span, require_name=False)
    dup = duplicates(span)
    flows = span.groupby(_dup_cols(span), dropna=False)["matched"].any()
    dup["distinct_flows_covered"] = round(float(flows.mean()) if len(flows) else 0.0, 4)
    def table(col):
        g = span.groupby(col)["matched"].agg(["sum", "count"])
        g["share"] = g["sum"] / g["count"]
        return {k: {"matched": int(r["sum"]), "total": int(r["count"]),
                    "share": round(float(r["share"]), 4)}
                for k, r in g.sort_values("count", ascending=False).iterrows()}
    return {"unsw_in_span": int(len(span)), "matched": int(span["matched"].sum()),
            "share": round(float(span["matched"].mean()) if len(span) else 0.0, 4),
            "duplicates": dup,
            "share_ignoring_protocol_name": round(float(any_name.mean()) if len(span) else 0.0, 4),
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


def _other_rule_score(base: pd.DataFrame, unsw: pd.DataFrame, choice: dict,
                      ct_lookup: dict | None) -> float:
    """Share of UNSW's other-protocol flows (distinct, in span) that a Zeek-side
    flow matches with the same packet count. Rewards getting both the flow
    boundaries and the start times right."""
    sel = select(base, choice, ct_lookup)
    span = _in_span(sel, unsw)
    span = span[_family(span["proto"]) == "other"].drop_duplicates(_dup_cols(span))
    if not len(span):
        return 0.0
    m = join(sel[sel["l4"] == "other"], span)
    return round(float((m["spkts"] == m["u_spkts"]).sum() / len(span)), 4)


def calibrate(base: pd.DataFrame, unsw: pd.DataFrame, ct_lookup: dict | None,
              rate_variant: str, packets: pd.DataFrame | None = None) -> dict:
    """Choose each variant group's definition by agreement on this capture.

    Groups are chosen one at a time with the others held at their defaults;
    they touch disjoint features (window counts depend on `service`, so the
    service group is settled first). The other-protocol grouping rule changes
    which rows exist, so it is settled before everything else.
    """
    from src.ingest.other import combine
    choice = {**DEFAULT_CHOICE, "rate": rate_variant}
    scores: dict[str, dict] = {}
    if packets is not None and len(packets):
        scores["other"] = {v: _other_rule_score(combine(base, packets, v), unsw,
                                                {**choice, "other": v}, ct_lookup)
                           for v in VARIANTS["other"]}
        choice["other"] = max(scores["other"], key=scores["other"].get)
        base = combine(base, packets, choice["other"])
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
              ]
    dup = cov.get("duplicates")
    if dup:
        lines += [f"UNSW writes some flows more than once: {dup['rows']} records are "
                  f"{dup['distinct_flows']} distinct flows. {dup['rows_in_duplicated_flows']} "
                  f"records belong to duplicated flows; {dup['flows_with_conflicting_labels']} "
                  f"flows ({dup['rows_in_conflicting_flows']} records) carry conflicting attack "
                  f"labels. Distinct flows covered: {dup['distinct_flows_covered']:.1%}.", ""]
    if "share_ignoring_protocol_name" in cov:
        lines += [f"Other-protocol flows must match on protocol name. Ignoring the name, "
                  f"coverage would be {cov['share_ignoring_protocol_name']:.1%}.", ""]
    lines += ["| class | matched | total | share |", "|---|---|---|---|"]
    for k, r in cov["by_class"].items():
        lines.append(f"| {k} | {r['matched']} | {r['total']} | {r['share']:.1%} |")
    lines += ["", "| proto (top 10) | matched | total | share |", "|---|---|---|---|"]
    for k, r in list(cov["by_proto"].items())[:10]:
        lines.append(f"| {k} | {r['matched']} | {r['total']} | {r['share']:.1%} |")
    if res.get("other_proto_confusion"):
        lines += ["", "Protocol names on the other-protocol path (top 15):", "",
                  "| UNSW | this pipeline | flows |", "|---|---|---|"]
        for r in res["other_proto_confusion"]:
            lines.append(f"| {r['unsw']} | {r['zeek']} | {r['n']} |")
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


def _packets(d: Path) -> pd.DataFrame | None:
    p = d / "other_packets.csv.gz"
    return pd.read_csv(p) if p.exists() else None


def other_proto_confusion(m: pd.DataFrame, top: int = 15) -> list[dict]:
    """Protocol names on the other-protocol path: UNSW's vs this pipeline's."""
    o = m[m["l4"] == "other"]
    c = o.groupby(["u_proto", "proto"]).size().sort_values(ascending=False).head(top)
    return [{"unsw": a, "zeek": b, "n": int(n)} for (a, b), n in c.items()]


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

    from src.ingest.other import combine
    calib_base = pd.read_csv(calib_dir / "base.csv.gz", low_memory=False)
    cal = calibrate(calib_base, unsw, ct_lookup, rate_variant, _packets(calib_dir))
    (out / "choice.json").write_text(json.dumps(cal, indent=2))

    valid_base = pd.read_csv(valid_dir / "base.csv.gz", low_memory=False)
    vp = _packets(valid_dir)
    if vp is not None:
        valid_base = combine(valid_base, vp, cal["choice"]["other"])
    vz = select(valid_base, cal["choice"], ct_lookup)
    m = join(vz, unsw)
    res = {"calib": str(calib_dir), "valid": str(valid_dir),
           "calibration": cal, "rate_check": rate_check, "provenance": PROVENANCE,
           "ct_state_ttl_purity": ct_lookup["purity"] if ct_lookup else None,
           "coverage": coverage(vz, unsw, m),
           "features": feature_agreement(m) if len(m) else {},
           "state_confusion": state_confusion(m) if len(m) else [],
           "other_proto_confusion": other_proto_confusion(m) if len(m) else []}
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
