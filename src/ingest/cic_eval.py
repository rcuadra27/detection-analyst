"""
Cross-dataset check: the UNSW-trained detector on CIC-IDS2017.

WHY: every capture tested so far came from the UNSW testbed, the same network the
model was trained on. That proves the pcap -> Zeek -> features pipeline is
faithful, not that the detector works elsewhere. CIC-IDS2017 is a different lab,
different hosts and different attack tools, with labels. The rules this run is
judged by, and the predictions made before it, are frozen in docs/cic_eval.md.

WHAT it runs: the exact upload path (score.score_pcap), so the numbers describe
what a user of the app would get. Only the comparison with CIC's labels is new.

HOW labels are attached: CIC's labelled flow CSVs (TrafficLabelling, built by
CICFlowMeter) are matched to Zeek flows on the unordered endpoint pair, ports and
protocol, and time. Unordered, because CICFlowMeter's direction is unreliable
(the first row of Monday's file has the server as source). The CSV clock is the
lab's local time, written without a zone and, in some files, on a 12-hour clock
with no AM/PM; the offset to UTC is measured from the data, not assumed: the
whole-hour offset that matches the most rows wins.

Usage:
    python -m src.ingest.cic_eval --day Monday \\
        --pcap data/raw/cic2017/pcap/Monday-WorkingHours.pcap \\
        --csv-dir "data/raw/cic2017/csv/TrafficLabelling " \\
        --out data/processed/cic2017/monday
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path

import numpy as np
import pandas as pd

BENIGN = "BENIGN"
FIRST_WORK_HOUR = 8            # the captures cover working hours: "3:30" means 15:30
OFFSET_CANDIDATES = range(-12, 13)
CALIBRATION_SAMPLE = 20000
MIN_MATCHED_SHARE = 0.90       # rule 0: below this, the labels are not attached well enough
MIN_OFFSET_MARGIN = 2.0        # rule 0: best offset matches at least 2x the runner-up
BANDS = ((0.001, "usable"), (0.01, "degraded"))   # rule 1, on the innocent-host flag rate
_PROTO = {6: "tcp", 17: "udp"}
_CSV_COLS = {"Source IP": "a_ip", "Source Port": "a_port", "Destination IP": "b_ip",
             "Destination Port": "b_port", "Protocol": "proto", "Timestamp": "stamp",
             "Label": "label"}


# ---------------------------------------------------------------- labels

def day_csvs(csv_dir: Path, day: str) -> list[Path]:
    files = sorted(p for p in Path(csv_dir).glob("*.csv") if p.name.lower().startswith(day.lower()))
    if not files:
        raise FileNotFoundError(f"no CSV for {day} in {csv_dir!s}")
    return files


def clean_label(s: pd.Series) -> pd.Series:
    """'Web Attack \\x96 Brute Force' (latin-1 dash) -> 'Web Attack - Brute Force'."""
    return s.astype(str).str.strip().str.replace(r"[^\x20-\x7e]+", "-", regex=True)


def parse_times(stamp: pd.Series) -> tuple[pd.Series, pd.Series]:
    """CIC timestamps -> (naive local datetime, precision in seconds).

    Day first. Some files carry seconds, some only minutes; minute-only rows get
    a 60 s matching tolerance. Hours before FIRST_WORK_HOUR are afternoon hours
    written on a 12-hour clock."""
    s = stamp.astype(str).str.strip()
    with_s = pd.to_datetime(s, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    no_s = pd.to_datetime(s, format="%d/%m/%Y %H:%M", errors="coerce")
    t = with_s.fillna(no_s)
    precision = pd.Series(np.where(with_s.notna(), 1.0, 60.0), index=s.index)
    pm = t.dt.hour < FIRST_WORK_HOUR
    t = t.where(~pm, t + pd.Timedelta(hours=12))
    return t, precision


def load_labels(files: list[Path]) -> pd.DataFrame:
    frames = []
    for f in files:
        head = pd.read_csv(f, nrows=0, encoding="latin-1")
        raw = {c.strip(): c for c in head.columns}
        missing = [c for c in _CSV_COLS if c not in raw]
        if missing:
            raise ValueError(f"{f.name}: missing columns {missing}")
        d = pd.read_csv(f, usecols=[raw[c] for c in _CSV_COLS], encoding="latin-1",
                        low_memory=False)
        d.columns = [_CSV_COLS[c.strip()] for c in d.columns]
        d = d.dropna(subset=["a_ip", "b_ip", "stamp"]).assign(file=f.name)
        frames.append(d)
    d = pd.concat(frames, ignore_index=True)
    d["label"] = clean_label(d["label"])
    d["proto"] = pd.to_numeric(d["proto"], errors="coerce").map(_PROTO)
    for c in ("a_port", "b_port"):
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(-1).astype(int)
    d["local"], d["tol"] = parse_times(d["stamp"])
    bad = d["local"].isna()
    if bad.any():
        print(f"[cic] {int(bad.sum())} rows with unreadable timestamps dropped")
    return d[~bad].reset_index(drop=True)


# ---------------------------------------------------------------- matching

def pair_key(ip1, port1, ip2, port2, proto) -> pd.Series:
    """Direction-free flow key: the two endpoints sorted, plus the protocol."""
    e1 = ip1.astype(str) + "/" + port1.astype(str)
    e2 = ip2.astype(str) + "/" + port2.astype(str)
    lo = np.where(e1 <= e2, e1, e2)
    hi = np.where(e1 <= e2, e2, e1)
    return pd.Series(lo, index=ip1.index) + "|" + pd.Series(hi, index=ip1.index) + "|" + proto.astype(str)


def zeek_keys(feats: pd.DataFrame) -> pd.DataFrame:
    z = feats[feats["l4"].isin(["tcp", "udp"])]
    out = pd.DataFrame({"uid": z["uid"].values,
                        "key": pair_key(z["srcip"], z["sport"].astype(int), z["dstip"],
                                        z["dsport"].astype(int), z["l4"]).values,
                        "zts": z["ts"].astype(float).values,
                        "zend": z["end_ts"].fillna(z["ts"]).astype(float).values})
    return out.sort_values("zts", kind="stable").reset_index(drop=True)


def match(cic: pd.DataFrame, z: pd.DataFrame, offset_hours: float) -> pd.Series:
    """For each CIC row (TCP/UDP), the uid of the Zeek flow it falls in, else NaN.

    A row matches the latest Zeek flow on the same key that started no later than
    the row (plus tolerance) and was still running at the row's start (minus
    tolerance). CICFlowMeter cuts long connections into several rows; each lands
    in the one Zeek flow."""
    c = cic[cic["proto"].notna()]
    t = (c["local"] - pd.Timestamp("1970-01-01")).dt.total_seconds() + offset_hours * 3600.0
    left = pd.DataFrame({"row": c.index, "key": pair_key(c["a_ip"], c["a_port"], c["b_ip"],
                                                         c["b_port"], c["proto"]).values,
                         "t": t.values, "tol": c["tol"].values})
    left["probe"] = left["t"] + left["tol"]
    left = left.sort_values("probe", kind="stable")
    m = pd.merge_asof(left, z, left_on="probe", right_on="zts", by="key", direction="backward")
    ok = m["zend"].notna() & (m["t"] - m["tol"] <= m["zend"])
    return pd.Series(np.where(ok, m["uid"], None), index=m["row"].values).reindex(cic.index)


def calibrate_offset(cic: pd.DataFrame, z: pd.DataFrame, seed: int = 0) -> dict:
    """Whole-hour local -> UTC offset that matches the most rows of a sample."""
    pool = cic[cic["proto"].notna()]
    sample = pool.sample(min(CALIBRATION_SAMPLE, len(pool)), random_state=seed)
    shares = {h: float(match(sample, z, h).notna().mean()) for h in OFFSET_CANDIDATES}
    ranked = sorted(shares.items(), key=lambda kv: kv[1], reverse=True)
    (best, s1), (_, s2) = ranked[0], ranked[1]
    return {"offset_hours": best, "sample_share": round(s1, 4),
            "runner_up_share": round(s2, 4),
            "margin": round(s1 / s2, 2) if s2 > 0 else None,
            "all": {str(h): round(v, 4) for h, v in shares.items()}}


def label_flows(feats: pd.DataFrame, cic: pd.DataFrame, uid: pd.Series) -> pd.Series:
    """Per Zeek flow: the most common attack label among its CIC rows, BENIGN if
    they are all benign, None if no row landed in it."""
    m = pd.DataFrame({"uid": uid, "label": cic["label"]}).dropna(subset=["uid"])
    atk = m[m["label"] != BENIGN]
    top = atk.groupby("uid")["label"].agg(lambda s: s.value_counts().index[0])
    out = pd.Series(None, index=feats["uid"].values, dtype=object)
    out[out.index.isin(m["uid"])] = BENIGN
    out.loc[top.index] = top.values
    return pd.Series(out.values, index=feats.index)


# ---------------------------------------------------------------- rules

def band(rate: float) -> str:
    for limit, name in BANDS:
        if rate <= limit:
            return name
    return "fail"


def per_attack(f: pd.DataFrame, cic: pd.DataFrame, uid: pd.Series) -> list[dict]:
    rows = []
    for lab, g in cic[cic["label"] != BENIGN].groupby("label"):
        flows = f[f["label"] == lab]
        flagged = flows[flows["alert"]]
        rows.append({
            "label": lab, "cic_rows": int(len(g)),
            "cic_rows_matched": round(float(uid.loc[g.index].notna().mean()), 4),
            "zeek_flows": int(len(flows)), "flagged": int(len(flagged)),
            "flow_recall": round(float(flows["alert"].mean()), 4) if len(flows) else None,
            "detected": bool(len(flagged)),
            "median_attack_prob": round(float(flows["attack_prob"].median()), 4) if len(flows) else None,
            "flagged_as": flagged["pred_class"].value_counts().head(3).to_dict(),
            "attack_sources": sorted(flows["srcip"].unique().tolist())[:5]})
    return rows


def diagnostics(innocent: pd.DataFrame) -> dict:
    """Where the false alarms on innocent hosts come from."""
    def by(col, top=10):
        g = innocent.groupby(col)["alert"].agg(flows="size", flagged="sum")
        g["rate"] = (g["flagged"] / g["flows"]).round(5)
        return g.sort_values("flows", ascending=False).head(top).reset_index().to_dict("records")

    fl = innocent[innocent["alert"]]
    hosts = innocent.groupby("srcip").agg(flows=("alert", "size"), flagged=("alert", "sum"))
    hosts["share"] = (hosts["flagged"] / hosts["flows"]).round(4)
    top_hosts = hosts.sort_values("flagged", ascending=False).head(10)
    top_hosts["top_ports"] = [fl.loc[fl["srcip"] == h, "dsport"].value_counts().head(3).index.tolist()
                              for h in top_hosts.index]
    return {"by_sttl": by("sttl"), "by_proto": by("l4"), "by_service": by("service"),
            "flagged_as": fl["pred_class"].value_counts().to_dict(),
            "top_hosts": top_hosts.reset_index().to_dict("records"),
            "hosts_with_flags": int((hosts["flagged"] > 0).sum()), "hosts": int(len(hosts))}


def incidents(f: pd.DataFrame, rate: float, attack_hosts: set) -> dict:
    """What would reach an analyst: hosts that pass the correlation gate (>= 5
    flagged flows in a 5-minute window) and that the noise check does not dismiss."""
    from src.ingest.baseline import host_noise_calls
    h = host_noise_calls(f.rename(columns={"srcip": "source"})[["source", "ts", "alert"]], rate)
    h["attacker"] = h.index.isin(attack_hosts)
    shown = h[~h["noise"]]
    return {"hosts_raising_events": int(len(h)),
            "innocent_shown": int((~shown["attacker"]).sum()),
            "innocent_dismissed_as_noise": int((h["noise"] & ~h["attacker"]).sum()),
            "attackers_shown": int(shown["attacker"].sum()),
            "attackers_dismissed_as_noise": int((h["noise"] & h["attacker"]).sum()),
            "innocent_shown_hosts": shown.index[~shown["attacker"]].tolist()[:20]}


def attach_labels(feats: pd.DataFrame, cic: pd.DataFrame) -> tuple[pd.DataFrame, dict, pd.Series]:
    """Zeek flows + CIC rows -> (flows with label/u_label, rule 0 result, CIC row -> uid)."""
    z = zeek_keys(feats)
    off = calibrate_offset(cic, z)
    uid = match(cic, z, off["offset_hours"])
    tcpudp = cic["proto"].notna()
    matched_share = float(uid[tcpudp].notna().mean())
    rule0 = {"matched_share": round(matched_share, 4), "offset": off,
             "zeek_tcp_udp_matched": round(float(z["uid"].isin(set(uid.dropna())).mean()), 4),
             "pass": bool(matched_share >= MIN_MATCHED_SHARE
                          and (off["margin"] is None or off["margin"] >= MIN_OFFSET_MARGIN))}

    f = feats.copy()
    if "alert" in f.columns:
        f["alert"] = f["alert"].astype(bool)
    f["label"] = label_flows(f, cic, uid)
    f["u_label"] = (f["label"].notna() & (f["label"] != BENIGN)).astype(int)
    return f, rule0, uid


def evaluate(feats: pd.DataFrame, meta: dict, cic: pd.DataFrame) -> dict:
    from src.ingest.baseline import rule_v2, truth_rates

    f, rule0, uid = attach_labels(feats, cic)
    truth = truth_rates(f)
    attack_hosts = set(truth["attack_hosts"])
    innocent = f[~f["srcip"].isin(attack_hosts) & (f["u_label"] == 0)]
    inn_matched = innocent[innocent["label"].notna()]

    rate = truth["innocent_rate"] or 0.0
    rule1 = {"innocent_rate": rate, "innocent_flows": truth["innocent_flows"],
             "innocent_flagged": truth["innocent_flagged"], "band": band(rate),
             "innocent_rate_matched_only": round(float(inn_matched["alert"].mean()), 6)
             if len(inn_matched) else None}

    upper = (meta.get("baseline") or {}).get("rate_upper")
    rule2 = ({"true": rate, "upper": upper, **rule_v2(rate, upper)} if upper is not None
             else {"true": rate, "upper": None, "pass": False, "note": "no baseline estimate"})

    return {"rule0_labels_attached": rule0, "rule1_false_alarms": rule1,
            "rule2_baseline": rule2, "rule3_detection": per_attack(f, cic, uid),
            "truth": {k: v for k, v in truth.items() if k != "attack_hosts"},
            "attack_hosts": sorted(attack_hosts)[:50],
            "incidents": incidents(f, upper if upper else rate or 1e-6, attack_hosts),
            "diagnostics": diagnostics(innocent),
            "n_flows": int(len(f)), "n_flagged": int(f["alert"].sum()),
            "cic_rows": int(len(cic)), "cic_labels": cic["label"].value_counts().to_dict()}


# ---------------------------------------------------------------- report

def _pct(x):
    return "n/a" if x is None else f"{x:.4%}"


def write_report(res: dict, day: str, out: Path, name: str = "report.md") -> None:
    r0, r1, r2 = res["rule0_labels_attached"], res["rule1_false_alarms"], res["rule2_baseline"]
    inc = res["incidents"]
    L = [f"# CIC-IDS2017 {day}: UNSW-trained detector", "",
         f"{res['n_flows']:,} Zeek flows, {res['n_flagged']:,} flagged. "
         f"{res['cic_rows']:,} CIC rows: " + ", ".join(f"{k} {v:,}" for k, v in res["cic_labels"].items()),
         "", "Rules frozen in docs/cic_eval.md before this run.", "",
         "| Rule | Result | Verdict |", "|---|---|---|",
         f"| 0 labels attached | {r0['matched_share']:.1%} of CIC TCP/UDP rows matched; offset "
         f"{r0['offset']['offset_hours']:+d} h (margin {r0['offset']['margin']}) | "
         f"{'PASS' if r0['pass'] else 'FAIL: do not read the rules below'} |",
         f"| 1 false alarms | innocent hosts flagged {_pct(r1['innocent_rate'])} "
         f"({r1['innocent_flagged']:,} of {r1['innocent_flows']:,}) | {r1['band'].upper()} |",
         f"| 2 noise baseline | true {_pct(r2['true'])}, estimated upper {_pct(r2['upper'])} | "
         f"{'PASS' if r2['pass'] else 'FAIL'} |", "",
         "## What an analyst would see", "",
         f"- hosts raising events: {inc['hosts_raising_events']}",
         f"- innocent hosts shown as incidents: **{inc['innocent_shown']}** "
         f"(dismissed as noise: {inc['innocent_dismissed_as_noise']})",
         f"- attackers shown: {inc['attackers_shown']} (dismissed as noise: "
         f"{inc['attackers_dismissed_as_noise']})", ""]
    if res["rule3_detection"]:
        L += ["## Rule 3: detection per attack (reported, no pass/fail)", "",
              "| Attack | CIC rows | matched | Zeek flows | flagged | recall | detected | flagged as |",
              "|---|---|---|---|---|---|---|---|"]
        for a in res["rule3_detection"]:
            recall = "n/a" if a["flow_recall"] is None else f"{a['flow_recall']:.1%}"
            L.append(f"| {a['label']} | {a['cic_rows']:,} | {a['cic_rows_matched']:.0%} | "
                     f"{a['zeek_flows']:,} | {a['flagged']:,} | {recall} | "
                     f"{'yes' if a['detected'] else 'no'} | {a['flagged_as']} |")
        L.append("")
    d = res["diagnostics"]
    L += ["## Where the innocent-host alarms come from", "",
          f"{d['hosts_with_flags']} of {d['hosts']} innocent hosts have at least one flagged flow. "
          f"Flagged as: {d['flagged_as']}", ""]
    for title, key in (("Source TTL (sttl)", "by_sttl"), ("Protocol", "by_proto"),
                       ("Service", "by_service")):
        rows = d[key]
        if not rows:
            continue
        col = list(rows[0].keys())[0]
        L += [f"**{title}**", "", f"| {col} | flows | flagged | rate |", "|---|---|---|---|"]
        L += [f"| {r[col]} | {r['flows']:,} | {r['flagged']:,} | {r['rate']:.3%} |" for r in rows]
        L.append("")
    L += ["**Top innocent hosts by flagged flows**", "",
          "| host | flows | flagged | share | top ports |", "|---|---|---|---|---|"]
    L += [f"| {h['srcip']} | {h['flows']:,} | {h['flagged']:,} | {h['share']:.2%} | {h['top_ports']} |"
          for h in d["top_hosts"]]
    (out / name).write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------- other models

def rescore(feats: pd.DataFrame, models_dir: Path, threshold: float = 0.85) -> tuple[pd.DataFrame, dict]:
    """Score the saved features with other models (an ablation), without Zeek.

    Returns the frame with attack_prob, pred_class and alert replaced, and a
    meta dict holding that model's own per-capture baseline."""
    import joblib

    from src.ingest.baseline import estimate_baseline
    from src.ingest.features import UNSW_FEATURES
    s1 = joblib.load(Path(models_dir) / "stage1_binary.joblib")
    s2 = joblib.load(Path(models_dir) / "stage2_multiclass.joblib")
    X = feats[UNSW_FEATURES]
    p = s1.predict_proba(X)[:, 1]
    classes = np.array([str(c) for c in s2.named_steps["clf"].classes_])
    f = feats.assign(attack_prob=p.round(4),
                     pred_class=classes[s2.predict_proba(X).argmax(axis=1)],
                     alert=p >= threshold)
    meta = {"baseline": estimate_baseline(f["srcip"].to_numpy(), f["alert"].to_numpy()),
            "models": str(models_dir)}
    return f, meta


# ---------------------------------------------------------------- behavioral detectors

B1_MAX_FALSE_EVENTS = 1          # per detector per day (docs/behavior.md)
B2_MIN_COVERAGE = 0.90


def behavior_eval(f: pd.DataFrame, det) -> dict:
    """Behavioral events against CIC labels. `f` comes from attach_labels."""
    from src.detect.behavior import DETECTORS, INFORMATIONAL
    ev = det.events.copy()
    mem = det.members.merge(f[["label", "u_label"]], left_on="flow", right_index=True)
    if len(ev):
        lab = mem.groupby("event_id").agg(attack_flows=("u_label", "sum"))
        top = (mem[mem["u_label"] == 1].groupby("event_id")["label"]
               .agg(lambda s: s.value_counts().index[0]))
        ev = ev.merge(lab, left_on="event_id", right_index=True, how="left")
        ev["label"] = ev["event_id"].map(top)
        ev["true"] = ev["attack_flows"].fillna(0) > 0
    per_detector = {}
    for name in DETECTORS:
        d = ev[ev["detector"] == name] if len(ev) else ev
        false = int((~d["true"]).sum()) if len(d) else 0
        per_detector[name] = {"events": int(len(d)), "true_events": int(len(d) - false),
                              "false_events": false,
                              "b1": ("informational" if name in INFORMATIONAL
                                     else "usable" if false <= B1_MAX_FALSE_EVENTS else "fail")}
    true_ids = set(ev.loc[ev["true"], "event_id"]) if len(ev) else set()
    covered = set(mem.loc[mem["event_id"].isin(true_ids), "flow"])
    attacks = []
    for lab_, g in f[f["u_label"] == 1].groupby("label"):
        by = {name: round(float(g.index.isin(set(mem.loc[mem["event_id"].isin(
                  {e for e in true_ids if e.startswith(name + "-")}), "flow"])).mean()), 4)
              for name in DETECTORS}
        cov = float(g.index.isin(covered).mean())
        attacks.append({"label": lab_, "flows": int(len(g)), "coverage": round(cov, 4),
                        "detected": bool(cov > 0), "by_detector": by,
                        "b2": "pass" if cov >= B2_MIN_COVERAGE else "fail"})
    cols = ["event_id", "detector", "technique", "source", "target", "start", "end", "flows",
            "true", "label", "evidence"]
    return {"per_detector": per_detector, "per_attack": attacks,
            "events": ev[[c for c in cols if c in ev.columns]].to_dict("records") if len(ev) else []}


def write_behavior_report(res: dict, day: str, out: Path) -> None:
    from src.detect.behavior import VERSION as _V
    L = [f"# CIC-IDS2017 {day}: behavioral detectors {_V}", "",
         "Rules frozen in docs/behavior.md before any attack day was run.", "",
         "## B1: false events (events with no attack-labelled flow)", "",
         "| Detector | events | true | false | B1 |", "|---|---|---|---|---|"]
    for name, d in res["per_detector"].items():
        L.append(f"| {name} | {d['events']} | {d['true_events']} | {d['false_events']} | "
                 f"{d['b1'].upper()} |")
    if res["per_attack"]:
        L += ["", "## B2: attack flows inside a true event", "",
              "| Attack | flows | covered | by detector | B2 |", "|---|---|---|---|---|"]
        for a in res["per_attack"]:
            by = ", ".join(f"{k} {v:.0%}" for k, v in a["by_detector"].items() if v)
            L.append(f"| {a['label']} | {a['flows']:,} | {a['coverage']:.1%} | {by or '-'} | "
                     f"{a['b2'].upper()} |")
    L += ["", "## Events", "", "| event | source | target | minutes | flows | label | evidence |",
          "|---|---|---|---|---|---|---|"]
    for e in res["events"][:40]:
        lab = e.get("label") if e.get("true") else "none (false)"
        L.append(f"| {e['event_id']} | {e['source']} | {e['target']} | "
                 f"{(e['end'] - e['start']) / 60:.1f} | {e['flows']:,} | {lab} | {e['evidence']} |")
    if len(res["events"]) > 40:
        L.append(f"| ... {len(res['events']) - 40} more in results_behavior.json | | | | | | |")
    from src.detect.behavior import VERSION
    (out / f"report_behavior_{VERSION}.md").write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description="UNSW-trained detector on a CIC-IDS2017 day")
    ap.add_argument("--day", required=True, help="Monday ... Friday (matches the CSV names)")
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--csv-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rescore", action="store_true", help="run Zeek and the detector again")
    ap.add_argument("--keep-zeek", action="store_true",
                    help="keep the raw Zeek logs (several GB) after scoring")
    ap.add_argument("--models", type=Path,
                    help="re-score the saved features with these models (e.g. "
                         "data/processed/ablation/no_ttl) instead of production; no Zeek")
    ap.add_argument("--threshold", type=float,
                    help="stage-1 cutoff for re-scoring (default 0.85); with no --models, "
                         "re-scores with the production models")
    ap.add_argument("--behavior", action="store_true",
                    help="run the behavioral detectors (src/detect/behavior.py) instead of "
                         "the model, on the saved features")
    ap.add_argument("--tag", help="suffix for the report and results files (default: the "
                                  "models folder name)")
    a = ap.parse_args()

    out = a.out
    if a.rescore or not (out / "features.csv.gz").exists():
        from src.ingest.score import score_pcap
        print(f"[cic] scoring {a.pcap} (Zeek on a 10 GB capture takes a while)")
        score_pcap(a.pcap, out, name=f"CIC-IDS2017 {a.day}", keep_features=True)
        if not a.keep_zeek:
            shutil.rmtree(out / "zeek", ignore_errors=True)
    feats = pd.read_csv(out / "features.csv.gz", low_memory=False)
    meta = json.loads((out / "meta.json").read_text())
    if a.behavior:
        from src.detect.behavior import run_all
        cic = load_labels(day_csvs(a.csv_dir, a.day))
        f, rule0, _ = attach_labels(feats, cic)
        det = run_all(f)
        res = {"rule0_labels_attached": rule0, **behavior_eval(f, det)}
        from src.detect.behavior import VERSION
        (out / f"results_behavior_{VERSION}.json").write_text(json.dumps(res, indent=1, default=str))
        write_behavior_report(res, a.day, out)
        summary = "; ".join(f"{k} {v['true_events']} true / {v['false_events']} false"
                            for k, v in res["per_detector"].items())
        cover = "; ".join(f"{x['label']} {x['coverage']:.1%}" for x in res["per_attack"])
        print(f"[behavior] rule 0 {'PASS' if rule0['pass'] else 'FAIL'}; {summary}"
              + (f"; coverage: {cover}" if cover else "")
              + f" -> {out / f'report_behavior_{VERSION}.md'}")
        return
    suffix = ""
    if a.models or a.threshold is not None:
        models = a.models or Path("data/processed")
        t = 0.85 if a.threshold is None else a.threshold
        feats, meta = rescore(feats, models, t)
        name = a.models.name if a.models else "production"
        suffix = "_" + (a.tag or (name if a.threshold is None else f"{name}_t{t:g}"))
        print(f"[cic] re-scored with {models} at {t:g}: {int(feats['alert'].sum()):,} flagged")
    cic = load_labels(day_csvs(a.csv_dir, a.day))
    print(f"[cic] {len(feats):,} Zeek flows, {len(cic):,} CIC rows; matching")
    res = evaluate(feats, meta, cic)
    res["models"] = str(a.models) if a.models else "production"
    res["threshold"] = 0.85 if a.threshold is None else a.threshold
    (out / f"results{suffix}.json").write_text(json.dumps(res, indent=1, default=str))
    write_report(res, a.day + (f" ({suffix[1:]})" if suffix else ""), out, f"report{suffix}.md")
    r0, r1, r2 = res["rule0_labels_attached"], res["rule1_false_alarms"], res["rule2_baseline"]
    print(f"[cic] rule 0 {'PASS' if r0['pass'] else 'FAIL'} ({r0['matched_share']:.1%} matched, "
          f"offset {r0['offset']['offset_hours']:+d} h); rule 1 {r1['band']} "
          f"({_pct(r1['innocent_rate'])}); rule 2 {'PASS' if r2['pass'] else 'FAIL'} "
          f"-> {out / f'report{suffix}.md'}")


if __name__ == "__main__":
    main()
