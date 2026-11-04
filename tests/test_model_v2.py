"""Model v2 first cut on synthetic data: the data plumbing, the label
correction, thresholds from training data only, and the experiment loop."""

import datetime as dt

import numpy as np
import pandas as pd

from src.detect import model_v2 as M
from src.ingest.features import UNSW_FEATURES


def _rows(n, seed, attack_share, attack_signal, normal_shift, dataset, part, classes):
    """Attacks separate on sbytes; each dataset's normal traffic sits at its own
    smean (a 'which network' signal for the dataset check)."""
    rng = np.random.default_rng(seed)
    atk = rng.random(n) < attack_share
    df = pd.DataFrame({c: rng.random(n) for c in UNSW_FEATURES})
    df["proto"], df["service"], df["state"] = "tcp", "-", "FIN"
    df["sbytes"] = np.where(atk, attack_signal, 500) + rng.normal(0, 300, n)
    df["smean"] = normal_shift + rng.normal(0, 5, n)
    df["cls"] = np.where(atk, rng.choice(classes, n), "normal")
    df["dataset"], df["part"] = dataset, part
    df["srcip"] = None if dataset == "unsw" else np.where(atk, "172.16.0.1", "192.168.10.5")
    return df


def table():
    parts = [_rows(3000, 1, .4, 5000, 50, "unsw", "train", ["dos", "exploit"]),
             _rows(1500, 2, .4, 5000, 50, "unsw", "test", ["dos", "exploit"])]
    for i, d in enumerate(("monday", "friday", "wednesday")):
        parts.append(_rows(2000, 10 + i, 0 if d == "monday" else .3, 5000, 400, "cic", d,
                           ["dos", "scan"]))
    return pd.concat(parts, ignore_index=True)


def test_load_unsw_maps_classes(tmp_path):
    df = pd.DataFrame({c: [1.0, 2.0, 3.0] for c in UNSW_FEATURES})
    df["attack_cat"], df["label"], df["id"] = ["Normal", "Reconnaissance", " Backdoors"], [0, 1, 1], [1, 2, 3]
    df.to_csv(tmp_path / "u.csv", index=False)
    u = M.load_unsw(tmp_path / "u.csv", "train")
    assert u["cls"].tolist() == ["normal", "scan", "botnet"] and set(u["dataset"]) == {"unsw"}


def test_thursday_correction_takes_only_the_infected_hosts_internal_probes():
    t_lab = dt.datetime(2017, 7, 6, 15, 0, tzinfo=dt.timezone(dt.timedelta(hours=-3))).timestamp()
    f = pd.DataFrame({
        "srcip": ["192.168.10.8", "192.168.10.8", "192.168.10.8", "192.168.10.9", "192.168.10.8"],
        "dstip": ["192.168.10.12", "8.8.8.8", "192.168.10.12", "192.168.10.12", "192.168.10.14"],
        "ts": [t_lab, t_lab, t_lab, t_lab, t_lab - 4 * 3600],
        "state": ["RST", "RST", "FIN", "RST", "RST"], "spkts": [1, 1, 30, 1, 1], "dpkts": [1, 1, 30, 1, 1]})
    assert M.correct_thursday(f).tolist() == [True, False, False, False, False]


def test_threshold_comes_from_training_normal_only():
    t = table()
    tr = t[(t["dataset"] == "unsw") & (t["part"] == "train")]
    model, thr = M.fit(tr)
    p = model.predict_proba(tr.loc[tr["cls"] == "normal", UNSW_FEATURES])[:, 1]
    assert (p >= thr).mean() < 0.02
    r = M.score(model, thr, t[(t["dataset"] == "unsw") & (t["part"] == "test")])
    assert r["auc"] > 0.95 and set(r["recall"]) == {"dos", "exploit"}


def test_run_all_produces_every_experiment_and_the_dataset_check():
    res = M.run_all(table())
    assert set(res) >= {"E1", "E2", "E3", "E4", "D", "M1"}
    assert set(res["E1"]) == set(res["E3"]) == {"monday", "friday", "wednesday"}
    assert res["E1"]["monday"]["auc"] is None            # no attacks that day: no AUC
    assert res["D"]["accuracy"] > 0.95                    # smean gives the network away
    assert res["D"]["most_telling_features"][0][0] == "smean"
    assert res["E4"]["auc"] > 0.95


def test_weights_balance_datasets():
    t = table()
    w = M._weights(t)
    tot = pd.Series(w).groupby(t["dataset"].values).sum()
    assert abs(tot["unsw"] - tot["cic"]) < 1e-6 * tot.sum()


def test_report_names_the_m1_verdicts(tmp_path):
    res = M.run_all(table())
    M.write_report(res, {"monday": {"rows": 2000}}, tmp_path)
    text = (tmp_path / "report.md").read_text()
    assert "| E1 | friday |" in text and "| E2 | unsw test |" in text and "Dataset check" in text


def test_no_rtt_variant_drops_the_handshake_timings(tmp_path):
    from src.detect.two_stage import PRODUCTION_DROP
    assert set(M.VARIANTS["no_rtt"]) == set(PRODUCTION_DROP) | {"tcprtt", "synack", "ackdat"}
    t = table()
    model, _ = M.fit(t[t["dataset"] == "unsw"], M.VARIANTS["no_rtt"])
    assert set(model.named_steps["drop"].columns) >= {"tcprtt", "synack", "ackdat"}
    res = M.run_all(t, M.VARIANTS["no_rtt"], importances=True)
    assert "top_features" in res["E3"]["friday"]
    M.write_report(res, {}, tmp_path, "no_rtt")
    assert "no_rtt: dropped" in (tmp_path / "report_no_rtt.md").read_text()
