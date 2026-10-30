"""Behavioral detectors on synthetic flows: each fires on its pattern and stays
quiet on the busy-but-normal traffic that looks closest to it."""

import numpy as np
import pandas as pd

from src.detect import behavior as B

T0 = 1_499_000_000.0


def _flows(rows):
    return pd.DataFrame(rows, columns=["ts", "srcip", "dstip", "dsport", "l4", "state",
                                       "spkts", "dpkts"])


def background(minutes=20, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for m in range(minutes):
        for i in range(1200):        # a steady, very busy DNS server: 1,200 a minute
            rows.append([T0 + m * 60 + i * 0.05, f"10.0.0.{rng.integers(2, 200)}",
                         "10.0.0.1", 53, "udp", "CON", 1, 1])
        for i in range(40):           # browsing
            rows.append([T0 + m * 60 + i, f"10.0.0.{rng.integers(2, 200)}",
                         "93.184.216.34", 443, "tcp", "FIN", 12, 10])
    for i in range(150):              # passive FTP data: many ports, all real transfers
        rows.append([T0 + 300 + i * 0.3, "10.0.0.7", "10.0.0.9", 40000 + i, "tcp", "FIN", 20, 30])
    return rows


def test_quiet_on_busy_normal_traffic():
    det = B.run_all(_flows(background()))
    assert det.events.empty


def test_vertical_scan():
    rows = background() + [[T0 + 600 + i * 0.03, "172.16.0.1", "10.0.0.50", 1 + i, "tcp",
                            "RST" if i % 10 else "REQ", 1, 1] for i in range(1000)]
    det = B.run_all(_flows(rows))
    (ev,) = det.events.to_dict("records")
    assert (ev["detector"], ev["source"], ev["target"]) == ("scan_vertical", "172.16.0.1", "10.0.0.50")
    assert ev["evidence"]["distinct_ports"] == 1000 and ev["evidence"]["probe_share"] == 1.0
    assert len(det.members) == 1000


def test_horizontal_scan():
    rows = background() + [[T0 + 700 + i * 0.2, "10.0.0.66", f"10.0.1.{i}", 445, "tcp", "REQ", 2, 0]
                           for i in range(80)]
    det = B.run_all(_flows(rows))
    (ev,) = det.events.to_dict("records")
    assert (ev["detector"], ev["target"]) == ("scan_horizontal", "port 445/tcp")
    assert ev["evidence"]["distinct_targets"] == 80


def test_flood_against_its_own_normal():
    rows = background()
    for m in range(12, 15):           # 3 minutes at 3,000/min to a web server that saw 40/min
        rows += [[T0 + m * 60 + i * 0.02, "172.16.0.1", "93.184.216.34", 443, "tcp", "REQ", 2, 1]
                 for i in range(3000)]
    det = B.run_all(_flows(rows))
    (ev,) = det.events.to_dict("records")
    assert (ev["detector"], ev["target"]) == ("flood", "93.184.216.34:443/tcp")
    assert ev["evidence"]["minutes"] in (3, 4)      # 3 minutes of traffic across 60 s windows
    assert ev["evidence"]["peak_per_minute"] >= 2000 and len(det.members) >= 9000   # plus normal browsing in those minutes
    assert ev["source"].startswith("172.16.0.1")


def test_no_flood_before_history_exists():
    rows = [[T0 + i * 0.01, "1.1.1.1", "10.0.0.5", 80, "tcp", "FIN", 5, 5] for i in range(5000)]
    assert B.run_all(_flows(rows)).events.empty     # first minutes of a capture: no baseline yet


def test_behavior_eval_counts_true_and_false_events():
    from src.ingest.cic_eval import behavior_eval
    rows = background() + [[T0 + 600 + i * 0.03, "172.16.0.1", "10.0.0.50", 1 + i, "tcp", "RST", 1, 1]
                           for i in range(1000)] \
        + [[T0 + 900 + i * 0.03, "10.0.0.8", "10.0.0.51", 1 + i, "tcp", "RST", 1, 1] for i in range(200)]
    f = _flows(rows)
    f["label"] = np.where(f["srcip"] == "172.16.0.1", "PortScan", "BENIGN")
    f["u_label"] = (f["label"] != "BENIGN").astype(int)
    res = behavior_eval(f, B.run_all(f))
    assert res["per_detector"]["scan_vertical"] == {"events": 2, "true_events": 1, "false_events": 1,
                                                    "b1": "usable"}
    (scan,) = res["per_attack"]
    assert scan["label"] == "PortScan" and scan["coverage"] == 1.0 and scan["b2"] == "pass"
