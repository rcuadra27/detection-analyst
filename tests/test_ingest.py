"""Phase A ingest: Zeek feature extraction and the parity experiment.

Two groups:
  - pure tests (no Zeek): state mapping, window counts, join, calibration
    helpers, detector parity on a toy model
  - Zeek tests: a synthetic pcap with known values goes through Zeek and the
    adapter. Skipped when Zeek is not installed.
"""

from __future__ import annotations

import json
import shutil

import numpy as np
import pandas as pd
import pytest

from src.ingest import features as F
from src.ingest import parity as P
from src.ingest.zeek_run import ZeekNotFound, zeek_bin

try:
    zeek_bin()
    HAVE_ZEEK = True
except ZeekNotFound:
    HAVE_ZEEK = False
needs_zeek = pytest.mark.skipif(not HAVE_ZEEK, reason="zeek not installed")


# ---------------------------------------------------------------- pure

@pytest.mark.parametrize("l4,state,resp,expected", [
    ("tcp", "SF", 3, "FIN"), ("tcp", "S0", 0, "REQ"), ("tcp", "REJ", 1, "RST"),
    ("tcp", "RSTO", 2, "RST"), ("tcp", "S1", 2, "CON"), ("tcp", "SHR", 1, "ACC"),
    ("tcp", "OTH", 0, "INT"), ("udp", "S0", 0, "INT"), ("udp", "SF", 1, "CON"),
    ("icmp", "OTH", 1, "ECO"),
])
def test_argus_state(l4, state, resp, expected):
    assert F.argus_state(l4, state, resp) == expected


def test_normalize_service_variants():
    assert F.normalize_service("ssl,http", 443, "zeek") == "ssl"
    assert F.normalize_service(None, 80, "zeek") == "-"
    assert F.normalize_service(None, 80, "zeek_port") == "http"
    assert F.normalize_service("ftp-data", 20, "zeek") == "ftp-data"
    assert F.normalize_service("krb", 88, "zeek_port") == "-"


def _ct_frame():
    # four connections, one of them ends late
    return pd.DataFrame({
        "ts":     [0.0, 1.0, 2.0, 3.0],
        "end_ts": [0.5, 9.0, 2.5, 3.5],
        "srcip":  ["a", "a", "b", "a"], "dstip": ["x", "x", "x", "y"],
        "sport":  [1, 2, 3, 4], "dsport": [80, 80, 80, 22],
        "service": ["http", "http", "http", "ssh"],
    })


def test_window_counts_start_order_with_self():
    ct = F.window_counts(_ct_frame(), "start_self", window=100)
    assert ct["ct_src_ltm"].tolist() == [1, 2, 1, 3]
    assert ct["ct_dst_ltm"].tolist() == [1, 2, 3, 1]
    assert ct["ct_srv_src"].tolist() == [1, 2, 1, 1]
    assert ct["ct_src_dport_ltm"].tolist() == [1, 2, 1, 1]


def test_window_counts_end_order_without_self():
    # end order: 0, 2, 3, 1
    ct = F.window_counts(_ct_frame(), "end_noself", window=100)
    assert ct["ct_src_ltm"].tolist() == [0, 2, 0, 1]


def test_window_counts_respects_window_size():
    df = pd.DataFrame({"ts": np.arange(6.0), "end_ts": np.arange(6.0),
                       "srcip": ["a"] * 6, "dstip": ["x"] * 6, "sport": range(6),
                       "dsport": [80] * 6, "service": ["-"] * 6})
    assert F.window_counts(df, "start_self", window=3)["ct_src_ltm"].tolist() == [1, 2, 3, 3, 3, 3]
    assert F.window_counts(df, "start_noself", window=3)["ct_src_ltm"].tolist() == [0, 1, 2, 3, 3, 3]


def _zeek_rows():
    return pd.DataFrame({
        "uid": ["C1", "C2"], "ts": [100.2, 200.0], "end_ts": [101.0, 200.5],
        "srcip": ["1.1.1.1", "1.1.1.1"], "sport": [1000, 1000],
        "dstip": ["2.2.2.2", "2.2.2.2"], "dsport": [80, 80], "l4": ["tcp", "tcp"],
        "sbytes": [10, 20],
    })


def _unsw_rows():
    return pd.DataFrame({
        "srcip": ["1.1.1.1"] * 3, "sport": [1000] * 3, "dstip": ["2.2.2.2"] * 3,
        "dsport": [80] * 3, "proto": ["tcp"] * 3,
        "stime": [100.0, 103.0, 200.0], "sbytes": [10, 99, 21],
        "attack_cat": ["normal", "normal", "exploits"], "label": [0, 0, 1],
    })


def test_join_nearest_time_one_to_one():
    m = P.join(_zeek_rows(), _unsw_rows())
    assert m["uid"].tolist() == ["C1", "C2"]
    assert m["u_sbytes"].tolist() == [10, 21]       # 103.0 is outside tolerance


def test_coverage_counts_unmatched_unsw_rows():
    z, u = _zeek_rows(), _unsw_rows()
    cov = P.coverage(z, u, P.join(z, u))
    assert cov["unsw_in_span"] == 3 and cov["matched"] == 2
    assert cov["by_class"]["normal"] == {"matched": 1, "total": 2, "share": 0.5}


def test_agree_numeric_and_categorical():
    a = P.agree(pd.Series([100, 200, 0]), pd.Series([100.5, 300, 0]))
    assert a["match"] == pytest.approx(2 / 3, abs=1e-3)
    c = P.agree(pd.Series(["FIN", "int"]), pd.Series(["FIN", "INT"]))
    assert c["match"] == 1.0


def test_load_unsw_full_hex_ports_and_labels(tmp_path):
    row = ["1.1.1.1", "0x000b", "2.2.2.2", "80", "TCP", "FIN"] + ["1"] * 41 + [" Backdoors ", "1"]
    hdr = ",".join(P.FULL_COLS)
    (tmp_path / "u.csv").write_text(hdr + "\n" + ",".join(row) + "\n")
    u = P.load_unsw_full([tmp_path / "u.csv"])
    assert u.loc[0, "sport"] == 11 and u.loc[0, "proto"] == "tcp"
    assert u.loc[0, "attack_cat"] == "backdoor" and u.loc[0, "label"] == 1


def test_learn_ct_state_ttl_and_rate_formula(tmp_path):
    df = pd.DataFrame({"state": ["FIN", "FIN", "FIN", "INT"], "sttl": [62, 62, 62, 254],
                       "dttl": [252, 252, 252, 0], "ct_state_ttl": [1, 1, 0, 2],
                       "dur": [1.0, 2.0, 0.5, 1.0], "spkts": [3, 4, 2, 1], "dpkts": [2, 2, 1, 0]})
    df["rate"] = (df["spkts"] + df["dpkts"] - 1) / df["dur"]
    df.to_csv(tmp_path / "train.csv", index=False)
    lk = F.learn_ct_state_ttl(tmp_path / "train.csv")
    assert lk["table"]["FIN|62|252"] == 1 and lk["table"]["INT|254|0"] == 2
    assert lk["purity"] == pytest.approx(0.75)
    r = P.check_rate_formula(tmp_path / "train.csv")
    assert r["best"] == "pkts_minus1" and r["agreement"]["pkts_minus1"] == 1.0


def _toy_model(X: pd.DataFrame, y: np.ndarray):
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OrdinalEncoder
    pre = ColumnTransformer([("cat", OrdinalEncoder(handle_unknown="use_encoded_value",
                                                    unknown_value=-1), P.CATEGORICAL)],
                            remainder="passthrough")
    return Pipeline([("pre", pre), ("clf", HistGradientBoostingClassifier(max_iter=50,
                                                                          random_state=0))]).fit(X, y)


def _toy_frame(n=400, seed=0):
    rng = np.random.default_rng(seed)
    X = pd.DataFrame({f: rng.random(n) for f in F.UNSW_FEATURES})
    X["proto"] = rng.choice(["tcp", "udp"], n)
    X["service"] = rng.choice(["-", "http"], n)
    X["state"] = rng.choice(["FIN", "INT"], n)
    y = (X["sttl"] > 0.5).astype(int).to_numpy()   # the model keys on sttl
    return X, y


def test_detector_parity_identical_and_swap_one():
    X, y = _toy_frame()
    m = _toy_model(X, y)
    same = P.detector_parity(X, X.copy(), y, m, threshold=0.5)
    assert same["decision_agreement"] == 1.0
    assert all(s["decision_agreement"] == 1.0 for s in same["swap_one"])

    Xz = X.copy()
    Xz["sttl"] = 1.0 - Xz["sttl"]                   # Zeek gets sttl badly wrong
    Xz["dload"] = Xz["dload"] * 1.5                 # and dload, which the model ignores
    res = P.detector_parity(X, Xz, y, m, threshold=0.5)
    assert res["decision_agreement"] < 0.2
    assert res["swap_one"][0]["feature"] == "sttl"
    dload = next(s for s in res["swap_one"] if s["feature"] == "dload")
    assert dload["decision_agreement"] > 0.95


# ---------------------------------------------------------------- Zeek

@pytest.fixture(scope="module")
def zeek_features(tmp_path_factory):
    from tests.pcap_fixtures import write_fixture
    d = tmp_path_factory.mktemp("ingest")
    pcap = write_fixture(d / "fixture.pcap")
    base, feats = F.features_from_pcap(pcap, d / "zeek")
    return d, base, feats


def _row(feats, dport, l4="tcp"):
    r = feats[(feats["dsport"] == dport) & (feats["l4"] == l4)]
    assert len(r) == 1, f"expected one {l4}/{dport} connection, got {len(r)}"
    return r.iloc[0]


@needs_zeek
def test_zeek_sees_all_five_connections(zeek_features):
    _, _, feats = zeek_features
    assert len(feats) == 5
    assert list(feats.columns) == F.META + F.UNSW_FEATURES


@needs_zeek
def test_zeek_http_flow_packet_features(zeek_features):
    from tests.pcap_fixtures import HTTP, HTTP_REQ, HTTP_RESP
    _, base, feats = zeek_features
    r = _row(feats, 80)
    assert (r["proto"], r["service"], r["state"]) == ("tcp", "http", "FIN")
    assert (r["spkts"], r["dpkts"]) == (7, 3)
    # Zeek stops the duration clock at the second FIN (0.110) and ignores the
    # trailing ACK, although it counts that packet in spkts. Argus likely runs to
    # the last packet (0.120). Recorded in docs/parity.md as a known difference.
    assert r["dur"] == pytest.approx(0.110, abs=1e-6)
    assert r["sbytes"] == 7 * 40 + 2 * len(HTTP_REQ)          # IP bytes, retransmission included
    assert r["dbytes"] == 3 * 40 + len(HTTP_RESP)
    assert r["smean"] == r["sbytes"] // 7
    assert (r["sttl"], r["dttl"]) == (HTTP["c_ttl_first"], HTTP["s_ttl"])
    assert (r["swin"], r["dwin"]) == (HTTP["c_win_first"], HTTP["s_win"])
    assert (r["stcpb"], r["dtcpb"]) == (HTTP["c_isn"], HTTP["s_isn"])
    assert r["synack"] == pytest.approx(HTTP["synack"], abs=1e-6)
    assert r["ackdat"] == pytest.approx(HTTP["ackdat"], abs=1e-6)
    assert r["tcprtt"] == pytest.approx(HTTP["synack"] + HTTP["ackdat"], abs=1e-6)
    assert (r["sloss"], r["dloss"]) == (1, 0)
    assert r["sinpkt"] == pytest.approx(20.0, abs=1e-3)       # gaps 15,5,40,10,30,20 ms
    assert r["dinpkt"] == pytest.approx(50.0, abs=1e-3)
    assert r["sjit"] == pytest.approx(11.902, abs=1e-3)       # population std of the gaps
    assert r["rate"] == pytest.approx((7 + 3 - 1) / r["dur"], rel=1e-6)
    assert r["sload"] == pytest.approx(r["sbytes"] * 8 / r["dur"], rel=1e-6)
    assert (r["trans_depth"], r["response_body_len"], r["ct_flw_http_mthd"]) == (1, 5, 1)
    # candidate variants carry the alternatives
    b = base[base["dsport"] == 80].iloc[0]
    assert b["sttl@last"] == HTTP["c_ttl_last"] and b["swin@last"] == HTTP["c_win_last"]
    assert b["sjit@mad"] == pytest.approx(21.0, abs=1e-3)
    assert b["sbytes@payload"] == len(HTTP_REQ)


@needs_zeek
def test_zeek_udp_oneway_and_syn_scan_states(zeek_features):
    _, _, feats = zeek_features
    dns = _row(feats, 53, "udp")
    assert (dns["proto"], dns["service"], dns["state"], dns["dpkts"]) == ("udp", "dns", "INT", 0)
    assert (dns["sttl"], dns["dttl"], dns["swin"]) == (64, 0, 0)
    syn = _row(feats, 22)
    assert (syn["state"], syn["spkts"], syn["dpkts"], syn["sttl"]) == ("REQ", 1, 0, 254)
    assert syn["stcpb"] == 777


@needs_zeek
def test_zeek_ftp_login_and_commands(zeek_features):
    _, _, feats = zeek_features
    ftp = _row(feats, 21)
    assert ftp["service"] == "ftp"
    assert (ftp["is_ftp_login"], ftp["ct_ftp_cmd"]) == (1, 3)   # USER, PASS, QUIT


@needs_zeek
def test_zeek_loss_candidates(zeek_features):
    from tests.pcap_fixtures import LOSSY
    _, base, feats = zeek_features
    b = base[base["dsport"] == LOSSY["dport"]].iloc[0]
    assert b["sloss@retrans"] == 1
    assert b["sloss@retrans_gaps"] == 2
    assert b["sloss@retrans_zero"] == 2
    assert b["sloss@all"] == 3
    assert b["sloss@retrans_plus1"] == 2
    assert b["dloss@all"] == 0
    # the HTTP flow has one retransmission and no hole or repeated SYN/FIN
    h = base[base["dsport"] == 80].iloc[0]
    assert (h["sloss@retrans"], h["sloss@all"], h["sloss@retrans_plus1"]) == (1, 1, 2)
    assert F.select(base, {"loss": "all"}).set_index("dsport").loc[LOSSY["dport"], "sloss"] == 3


@needs_zeek
def test_zeek_window_counts_over_capture(zeek_features):
    _, _, feats = zeek_features
    # default variant: ordered by end time, self included
    r = _row(feats, 21)
    assert r["ct_src_ltm"] == 3          # http, dns, then ftp from 10.0.0.5
    assert r["ct_dst_src_ltm"] == 1


@needs_zeek
def test_parity_end_to_end_on_fixture(zeek_features, tmp_path):
    """UNSW rows built from the fixture's own features must give perfect parity."""
    d, base, feats = zeek_features
    sel = F.select(base)
    u = sel.rename(columns={"l4": "proto_l4"}).copy()
    u["stime"] = np.floor(sel["ts"])
    u["ltime"] = np.floor(sel["end_ts"])
    u["attack_cat"] = ["exploits" if p == 22 else "normal" for p in sel["dsport"]]
    u["label"] = (u["attack_cat"] != "normal").astype(int)
    rows = u[[c for c in P.FULL_COLS]]
    rows.to_csv(tmp_path / "UNSW-NB15_x.csv", header=False, index=False)
    feats_dir = tmp_path / "cap"
    feats_dir.mkdir()
    base.to_csv(feats_dir / "base.csv.gz", index=False)

    X = sel[F.UNSW_FEATURES]
    model = _toy_model(X, rows["label"].to_numpy())
    import joblib
    joblib.dump(model, tmp_path / "s1.joblib")

    res = P.run(feats_dir, feats_dir, [str(tmp_path / "UNSW-NB15_x.csv")], tmp_path / "out",
                None, tmp_path / "s1.joblib", None)
    assert res["coverage"]["share"] == 1.0
    assert all(a["match"] == 1.0 for a in res["features"].values()), res["features"]
    assert res["detector"]["decision_agreement"] == 1.0
    assert (tmp_path / "out" / "parity_report.md").exists()
    assert json.loads((tmp_path / "out" / "choice.json").read_text())["choice"]
