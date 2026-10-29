"""The CIC-IDS2017 comparison: CIC's labelled CSVs attached to Zeek flows.

Unit tests use small frames. The end-to-end test scores the upload tests' scan
capture with the stub detector, writes a CIC-style CSV for it (reversed
directions, a 12-hour clock, a zone offset), and checks the rules come out as
they should."""

import json

import joblib
import numpy as np
import pandas as pd
import pytest

from src.ingest import cic_eval as C
from tests.test_upload import (SCANNER, StubStage1, StubStage2, needs_zeek,
                               write_scan_pcap)


def test_parse_times_day_first_12_hour_clock_and_precision():
    t, prec = C.parse_times(pd.Series(["03/07/2017 08:55:58", "7/7/2017 3:30", "05/07/2017 1:02:03"]))
    assert list(t) == [pd.Timestamp("2017-07-03 08:55:58"), pd.Timestamp("2017-07-07 15:30"),
                       pd.Timestamp("2017-07-05 13:02:03")]
    assert list(prec) == [1.0, 60.0, 1.0]


def test_clean_label_replaces_the_latin1_dash():
    assert C.clean_label(pd.Series(["Web Attack \x96 Brute Force", " BENIGN"])).tolist() == \
        ["Web Attack - Brute Force", "BENIGN"]


def test_pair_key_ignores_direction():
    a = C.pair_key(pd.Series(["10.0.0.1"]), pd.Series([1234]), pd.Series(["10.0.0.2"]),
                   pd.Series([80]), pd.Series(["tcp"]))
    b = C.pair_key(pd.Series(["10.0.0.2"]), pd.Series([80]), pd.Series(["10.0.0.1"]),
                   pd.Series([1234]), pd.Series(["tcp"]))
    assert a[0] == b[0]


def _feats(rows):
    return pd.DataFrame(rows, columns=["uid", "ts", "end_ts", "srcip", "sport", "dstip", "dsport", "l4"])


def _cic(rows):
    d = pd.DataFrame(rows, columns=["a_ip", "a_port", "b_ip", "b_port", "proto", "local", "tol", "label"])
    d["local"] = pd.to_datetime(d["local"])
    return d


def test_match_splits_reversal_and_time():
    t0 = pd.Timestamp("2017-07-03 12:00:00").timestamp()
    f = _feats([["u1", t0, t0 + 300, "10.0.0.1", 1234, "10.0.0.2", 80, "tcp"],
                ["u2", t0 + 1000, t0 + 1001, "10.0.0.1", 1234, "10.0.0.2", 80, "tcp"]])
    z = C.zeek_keys(f)
    # local clock 3 h behind UTC; the second row is CICFlowMeter's cut of the same connection
    cic = _cic([["10.0.0.2", 80, "10.0.0.1", 1234, "tcp", "2017-07-03 09:00:00", 1.0, "BENIGN"],
                ["10.0.0.1", 1234, "10.0.0.2", 80, "tcp", "2017-07-03 09:02:00", 1.0, "DoS Hulk"],
                ["10.0.0.1", 1234, "10.0.0.2", 80, "tcp", "2017-07-03 09:16:40", 1.0, "BENIGN"],
                ["10.0.0.1", 1234, "10.0.0.2", 80, "tcp", "2017-07-03 09:10:00", 1.0, "BENIGN"],
                ["10.0.0.9", 1, "10.0.0.2", 80, None, "2017-07-03 09:00:00", 1.0, "BENIGN"]])
    uid = C.match(cic, z, 3)
    assert uid.tolist()[:3] == ["u1", "u1", "u2"]
    assert pd.isna(uid.iloc[3])                                 # 09:10 falls between the two flows
    assert pd.isna(uid.iloc[4])                                 # not TCP/UDP: not matched
    off = C.calibrate_offset(cic, z)
    assert off["offset_hours"] == 3
    labels = C.label_flows(f, cic, uid)
    assert labels.tolist() == ["DoS Hulk", "BENIGN"]           # any attack row labels the flow


def test_bands():
    assert [C.band(x) for x in (0.0, 0.001, 0.005, 0.02)] == ["usable", "usable", "degraded", "fail"]


@pytest.fixture(scope="module")
def scored(tmp_path_factory):
    from src.ingest.score import score_pcap
    d = tmp_path_factory.mktemp("cic")
    joblib.dump(StubStage1(), d / "s1.joblib")
    joblib.dump(StubStage2(), d / "s2.joblib")
    (d / "cal.json").write_text(json.dumps({"source": "test", "choice": {}, "ct_lookup": None}))
    pcap = write_scan_pcap(d / "scan.pcap")
    score_pcap(pcap, d / "out", d / "cal.json", d / "s1.joblib", d / "s2.joblib",
               keep_features=True)
    return d


@needs_zeek
def test_end_to_end_on_the_scan_capture(scored):
    out = scored / "out"
    feats = pd.read_csv(out / "features.csv.gz")
    assert {"attack_prob", "pred_class", "alert", "sttl"} <= set(feats.columns)
    meta = json.loads((out / "meta.json").read_text())

    # CIC-style CSV: local clock 5 h ahead of UTC on a 12-hour clock (09:00 UTC
    # is written 02:00), every other row reversed, scanner rows labelled.
    rows = []
    for i, r in enumerate(feats[feats["l4"].isin(["tcp", "udp"])].itertuples()):
        local = pd.Timestamp(r.ts, unit="s") + pd.Timedelta(hours=5) - pd.Timedelta(hours=12)
        a, b = (r.srcip, r.sport), (r.dstip, r.dsport)
        if i % 2:
            a, b = b, a
        rows.append({"Flow ID": "x", " Source IP": a[0], " Source Port": a[1],
                     " Destination IP": b[0], " Destination Port": b[1],
                     " Protocol": 6 if r.l4 == "tcp" else 17,
                     " Timestamp": local.strftime("%d/%m/%Y ") + f"{local.hour}:{local:%M:%S}",
                     " Flow Duration": 1, " Label": "PortScan" if r.srcip == SCANNER else "BENIGN"})
    csv_dir = scored / "csv"
    csv_dir.mkdir()
    pd.DataFrame(rows).to_csv(csv_dir / "Monday-WorkingHours.pcap_ISCX.csv", index=False)

    cic = C.load_labels(C.day_csvs(csv_dir, "monday"))
    res = C.evaluate(feats, meta, cic)
    r0 = res["rule0_labels_attached"]
    assert r0["pass"] and r0["matched_share"] == 1.0 and r0["offset"]["offset_hours"] == -5
    assert res["attack_hosts"] == [SCANNER]
    assert res["rule1_false_alarms"]["innocent_rate"] == 0.0
    assert res["rule1_false_alarms"]["band"] == "usable"
    (scan,) = res["rule3_detection"]
    assert scan["label"] == "PortScan" and scan["detected"] and scan["flow_recall"] == 1.0
    assert res["incidents"]["attackers_shown"] == 1 and res["incidents"]["innocent_shown"] == 0
    C.write_report(res, "Monday", out)
    assert "PortScan" in (out / "report.md").read_text()
