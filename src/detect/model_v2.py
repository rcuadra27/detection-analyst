"""
Model v2, first cut: train and test the per-flow model across two networks.

Plan, classes, label correction, metrics and decision rules: docs/model_v2.md
(frozen before any run of this module).

Data:
  UNSW-NB15   the official training and testing CSVs (features from Argus; Phase A
              parity showed our Zeek features reproduce them)
  CIC-IDS2017 the five days scored by our pipeline
              (data/processed/cic2017/<day>/features.csv.gz), labels attached
              with cic_eval.attach_labels, plus the Thursday correction

Experiments (stage 1, attack vs normal):
  E1  UNSW train      -> each CIC day          new network
  E2  all CIC days    -> UNSW test             new network, the other way
  E3  UNSW + 4 days   -> the fifth CIC day     a new day of a seen network
  E4  UNSW train      -> UNSW test             in-lab reference
  D   dataset check: can the features tell UNSW normal rows from CIC normal rows?

Usage:
    python -m src.detect.model_v2 \\
        --unsw-train data/raw/UNSW_NB15_training-set.csv \\
        --unsw-test data/raw/UNSW_NB15_testing-set.csv \\
        --cic-dir data/processed/cic2017 \\
        --csv-dir "data/raw/cic2017/csv/TrafficLabelling " \\
        --out data/processed/model_v2
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import numpy as np
import pandas as pd

from src.detect.two_stage import PRODUCTION_DROP, _pipeline
from src.ingest.features import UNSW_FEATURES

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
CALIBRATION_SHARE = 0.10       # of training normal rows, held out to set the threshold
TARGET_FALSE_ALARM = 0.001     # threshold: 0.1% of those rows flagged
MAX_NORMAL_PER_DAY = 200_000   # CIC normal rows kept per day (all attack rows are kept)
SEED = 13

# docs/model_v2.md, "Common classes"
UNSW_CLASSES = {"normal": "normal", "reconnaissance": "scan", "analysis": "scan", "dos": "dos",
                "backdoor": "botnet", "backdoors": "botnet", "exploits": "exploit",
                "shellcode": "exploit", "worms": "exploit", "fuzzers": "other", "generic": "other"}
CIC_CLASSES = {"BENIGN": "normal", "PortScan": "scan", "DDoS": "dos", "DoS Hulk": "dos",
               "DoS GoldenEye": "dos", "DoS slowloris": "dos", "DoS Slowhttptest": "dos",
               "FTP-Patator": "brute_force", "SSH-Patator": "brute_force",
               "Web Attack - Brute Force": "web_attack", "Web Attack - XSS": "web_attack",
               "Web Attack - Sql Injection": "web_attack", "Bot": "botnet",
               "Infiltration": "exploit", "Heartbleed": "exploit"}

# The Thursday correction (docs/model_v2.md, "Label correction"): the compromised
# host's internal scan, which CIC labels BENIGN. Lab time is UTC-3.
CORRECTION = {"day": "thursday", "source": "192.168.10.8", "subnet": "192.168.10.",
              "start": dt.datetime(2017, 7, 6, 14, 33), "end": dt.datetime(2017, 7, 6, 15, 45),
              "lab_utc_offset_hours": -3, "cls": "scan"}

# Feature sets (docs/model_v2.md). "no_rtt" also drops the handshake timings,
# which measure how far the connecting machine is from the sensor: in CIC every
# attack connects from outside the firewall.
VARIANTS = {"base": list(PRODUCTION_DROP),
            "no_rtt": list(PRODUCTION_DROP) + ["tcprtt", "synack", "ackdat"]}

# docs/model_v2.md, "Decision rules"
M1_MIN_AUC = 0.80
M1_MAX_FALSE_ALARM = 0.01
BANDS = ((0.001, "usable"), (0.01, "degraded"))


# ---------------------------------------------------------------- data

def load_unsw(csv_path: str | Path, split: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    cls = df["attack_cat"].astype(str).str.strip().str.lower().map(UNSW_CLASSES)
    out = df[[c for c in UNSW_FEATURES]].copy()
    out["cls"] = cls.fillna("other")
    out["dataset"], out["part"], out["srcip"] = "unsw", split, None
    return out


def correct_thursday(f: pd.DataFrame) -> pd.Series:
    """Rows to relabel as the compromised host's scan."""
    from src.detect.behavior import is_probe
    c = CORRECTION
    off = dt.timedelta(hours=-c["lab_utc_offset_hours"])
    t0 = (c["start"] + off).replace(tzinfo=dt.timezone.utc).timestamp()
    t1 = (c["end"] + off).replace(tzinfo=dt.timezone.utc).timestamp()
    return ((f["srcip"] == c["source"]) & f["dstip"].astype(str).str.startswith(c["subnet"])
            & (f["dstip"] != c["source"]) & f["ts"].between(t0, t1) & is_probe(f))


def load_cic_day(day_dir: Path, csv_dir: Path, day: str,
                 max_normal: int = MAX_NORMAL_PER_DAY) -> tuple[pd.DataFrame, dict]:
    from src.ingest.cic_eval import attach_labels, day_csvs, load_labels
    feats = pd.read_csv(Path(day_dir) / "features.csv.gz", low_memory=False)
    f, rule0, _ = attach_labels(feats, load_labels(day_csvs(csv_dir, day)))
    f = f[f["label"].notna()].copy()                  # TCP/UDP flows CIC labelled
    f["cls"] = f["label"].map(CIC_CLASSES).fillna("other")
    corrected = 0
    if day == CORRECTION["day"]:
        m = correct_thursday(f) & (f["cls"] == "normal")
        f.loc[m, "cls"] = CORRECTION["cls"]
        corrected = int(m.sum())
    normal = f[f["cls"] == "normal"]
    if len(normal) > max_normal:
        f = pd.concat([f[f["cls"] != "normal"], normal.sample(max_normal, random_state=SEED)])
    out = f[UNSW_FEATURES + ["srcip"]].copy()
    out["cls"], out["dataset"], out["part"] = f["cls"].values, "cic", day
    info = {"rows": int(len(out)), "matched_share": rule0["matched_share"],
            "classes": out["cls"].value_counts().to_dict(), "corrected_to_scan": corrected}
    return out.reset_index(drop=True), info


def build_table(unsw_train, unsw_test, cic_dir, csv_dir, cache: Path | None = None,
                rebuild: bool = False) -> tuple[pd.DataFrame, dict]:
    if cache and cache.exists() and not rebuild:
        t = pd.read_pickle(cache)
        return t, json.loads(cache.with_suffix(".json").read_text())
    parts, info = [load_unsw(unsw_train, "train"), load_unsw(unsw_test, "test")], {}
    for day in DAYS:
        d = Path(cic_dir) / day
        if not (d / "features.csv.gz").exists():
            info[day] = "missing"
            continue
        frame, info[day] = load_cic_day(d, csv_dir, day)
        parts.append(frame)
        print(f"[model_v2] {day}: {info[day]}")
    t = pd.concat(parts, ignore_index=True)
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        t.to_pickle(cache)
        cache.with_suffix(".json").write_text(json.dumps(info, indent=1))
    return t, info


# ---------------------------------------------------------------- one experiment

def _weights(train: pd.DataFrame) -> np.ndarray:
    """Each dataset carries equal total weight, so 2 million CIC rows do not drown
    175,000 UNSW rows."""
    n = train["dataset"].map(train["dataset"].value_counts())
    return (1.0 / n).to_numpy() * len(train) / train["dataset"].nunique()


def fit(train: pd.DataFrame, drop=tuple(PRODUCTION_DROP)):
    rng = np.random.default_rng(SEED)
    normal = train.index[train["cls"] == "normal"]
    calib = rng.choice(normal, size=max(1, int(len(normal) * CALIBRATION_SHARE)), replace=False)
    fit_rows = train.drop(index=calib)
    model = _pipeline(class_weight=None, max_iter=300, drop=list(drop))
    model.fit(fit_rows[UNSW_FEATURES], (fit_rows["cls"] != "normal").astype(int),
              clf__sample_weight=_weights(fit_rows))
    s = model.predict_proba(train.loc[calib, UNSW_FEATURES])[:, 1]
    threshold = float(np.quantile(s, 1 - TARGET_FALSE_ALARM))
    return model, threshold


def band(rate: float) -> str:
    for limit, name in BANDS:
        if rate <= limit:
            return name
    return "fail"


def score(model, threshold: float, test: pd.DataFrame) -> dict:
    from sklearn.metrics import roc_auc_score
    p = model.predict_proba(test[UNSW_FEATURES])[:, 1]
    attack = (test["cls"] != "normal").to_numpy()
    flag = p >= threshold
    # Innocent: normal rows from sources that sent no attack row (UNSW's CSVs carry
    # no addresses, so there every normal row counts).
    atk_src = set(test.loc[attack & test["srcip"].notna().to_numpy(), "srcip"])
    innocent = ~attack & ~test["srcip"].isin(atk_src).to_numpy()
    fa = float(flag[innocent].mean()) if innocent.any() else None
    auc = float(roc_auc_score(attack, p)) if 0 < attack.sum() < len(attack) else None
    recall = {c: round(float(flag[(test["cls"] == c).to_numpy()].mean()), 4)
              for c in sorted(set(test["cls"]) - {"normal"})}
    return {"rows": int(len(test)), "attack_rows": int(attack.sum()),
            "auc": None if auc is None else round(auc, 4),
            "false_alarm": None if fa is None else round(fa, 6),
            "band": None if fa is None else band(fa),
            "recall": recall, "threshold": round(threshold, 6)}


def m1(r: dict) -> bool | None:
    if r["auc"] is None or r["false_alarm"] is None:
        return None
    return bool(r["auc"] >= M1_MIN_AUC and r["false_alarm"] <= M1_MAX_FALSE_ALARM)


# ---------------------------------------------------------------- the experiments

def run_all(t: pd.DataFrame, drop=tuple(PRODUCTION_DROP), importances: bool = False) -> dict:
    unsw_tr = t[(t["dataset"] == "unsw") & (t["part"] == "train")]
    unsw_te = t[(t["dataset"] == "unsw") & (t["part"] == "test")]
    cic = t[t["dataset"] == "cic"]
    days = [d for d in DAYS if (cic["part"] == d).any()]
    res: dict = {}

    model, thr = fit(unsw_tr, drop)
    res["E4"] = {"train": "unsw", "test": "unsw test", **score(model, thr, unsw_te)}
    res["E1"] = {d: {"train": "unsw", "test": d, **score(model, thr, cic[cic["part"] == d])}
                 for d in days}
    print(f"[model_v2] E4 auc {res['E4']['auc']}; E1 done")

    if len(days):
        model, thr = fit(cic, drop)
        res["E2"] = {"train": "cic (all days)", "test": "unsw test", **score(model, thr, unsw_te)}
        print(f"[model_v2] E2 auc {res['E2']['auc']}")

    res["E3"] = {}
    for d in days:
        train = pd.concat([unsw_tr, cic[cic["part"] != d]])
        model, thr = fit(train, drop)
        test = cic[cic["part"] == d]
        res["E3"][d] = {"train": "unsw + other days", "test": d, **score(model, thr, test)}
        if importances and res["E3"][d]["auc"] is not None:
            res["E3"][d]["top_features"] = _top_features(
                model, test[UNSW_FEATURES], (test["cls"] != "normal").astype(int), k=5)
        print(f"[model_v2] E3 {d} auc {res['E3'][d]['auc']}")

    res["D"] = dataset_check(t, drop)
    res["M1"] = {"E1": {d: m1(r) for d, r in res["E1"].items()},
                 "E2": m1(res["E2"]) if "E2" in res else None}
    return res


def dataset_check(t: pd.DataFrame, drop=tuple(PRODUCTION_DROP)) -> dict:
    """Train a classifier to tell UNSW normal rows from CIC normal rows."""
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split
    n = t[t["cls"] == "normal"]
    if n["dataset"].nunique() < 2:
        return {"note": "needs both datasets"}
    per = pd.concat([g.sample(min(len(g), 100_000), random_state=SEED)
                     for _, g in n.groupby("dataset")])
    y = (per["dataset"] == "cic").astype(int)
    Xtr, Xte, ytr, yte = train_test_split(per[UNSW_FEATURES], y, test_size=0.3,
                                          random_state=SEED, stratify=y)
    m = _pipeline(class_weight=None, max_iter=200, drop=list(drop))
    m.fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    imp = _top_features(m, Xte, yte)
    return {"accuracy": round(float(((p >= 0.5) == yte.to_numpy()).mean()), 4),
            "auc": round(float(roc_auc_score(yte, p)), 4), "most_telling_features": imp}


def _top_features(model, X, y, k: int = 8) -> list:
    from sklearn.inspection import permutation_importance
    sample = X.sample(min(len(X), 5000), random_state=SEED)
    r = permutation_importance(model, sample, y.loc[sample.index], n_repeats=3,
                               random_state=SEED, scoring="roc_auc")
    order = np.argsort(r.importances_mean)[::-1][:k]
    return [[X.columns[i], round(float(r.importances_mean[i]), 4)] for i in order]


# ---------------------------------------------------------------- report

def _pct(x):
    return "n/a" if x is None else f"{x:.3%}"


def write_report(res: dict, info: dict, out: Path, variant: str = "base") -> None:
    def row(name, r, verdict=""):
        rec = ", ".join(f"{c} {v:.0%}" for c, v in r["recall"].items())
        return (f"| {name} | {r['test']} | {r['auc']} | {_pct(r['false_alarm'])} ({r['band']}) | "
                f"{rec} | {verdict} |")
    L = [f"# Model v2, first cut ({variant}: dropped {', '.join(VARIANTS[variant])})", "",
         "Rules frozen in docs/model_v2.md before this run.", "",
         "| Exp | Test | AUC | False alarms | Recall at the training threshold | M1 |",
         "|---|---|---|---|---|---|",
         row("E4", res["E4"])]
    for d, r in res["E1"].items():
        v = res["M1"]["E1"][d]
        L.append(row("E1", r, "pass" if v else "fail"))
    if "E2" in res:
        L.append(row("E2", res["E2"], "pass" if res["M1"]["E2"] else "fail"))
    for d, r in res["E3"].items():
        L.append(row("E3", r))
    tops = {d: r["top_features"] for d, r in res["E3"].items() if r.get("top_features")}
    if tops:
        L += ["", "## E3: features each held-out model leaned on", ""]
        L += [f"- {d}: {v}" for d, v in tops.items()]
    D = res["D"]
    L += ["", "## Dataset check (normal rows only)", "",
          f"Accuracy {D.get('accuracy')}, AUC {D.get('auc')}. Most telling features: "
          f"{D.get('most_telling_features')}", "",
          "## Data", "", "```", json.dumps(info, indent=1), "```"]
    name = "report.md" if variant == "base" else f"report_{variant}.md"
    (out / name).write_text("\n".join(L) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Model v2 first cut: UNSW + CIC-IDS2017")
    ap.add_argument("--unsw-train", default="data/raw/UNSW_NB15_training-set.csv")
    ap.add_argument("--unsw-test", default="data/raw/UNSW_NB15_testing-set.csv")
    ap.add_argument("--cic-dir", type=Path, default=Path("data/processed/cic2017"))
    ap.add_argument("--csv-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("data/processed/model_v2"))
    ap.add_argument("--rebuild", action="store_true", help="rebuild the cached training table")
    ap.add_argument("--variant", choices=sorted(VARIANTS), default="base",
                    help="feature set; no_rtt also drops the handshake timings")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    t, info = build_table(a.unsw_train, a.unsw_test, a.cic_dir, a.csv_dir,
                          cache=a.out / "table.pkl", rebuild=a.rebuild)
    print(f"[model_v2] table: {len(t):,} rows; {t.groupby(['dataset', 'cls']).size().to_dict()}")
    res = run_all(t, VARIANTS[a.variant], importances=True)
    res["variant"] = a.variant
    suffix = "" if a.variant == "base" else f"_{a.variant}"
    (a.out / f"results{suffix}.json").write_text(json.dumps(res, indent=1))
    write_report(res, info, a.out, a.variant)
    print(f"[model_v2] -> {a.out / ('report.md' if a.variant == 'base' else f'report_{a.variant}.md')}")


if __name__ == "__main__":
    main()
