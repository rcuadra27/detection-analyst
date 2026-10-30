"""
Behavioral detectors: attacks described by what they must do across many flows.

WHY: the per-flow model judges one connection at a time, and on CIC-IDS2017 it
ranked attacks below normal traffic (docs/cic_eval.md). One port-scan probe is
one refused connection; one DDoS request is one HTTP request. What gives them
away is the pattern: thousands of refused connections from one source, or a
service suddenly receiving many times its own normal load. These detectors
count that pattern directly. They learn nothing from a dataset, so no lab's
quirks leak in, and they say why they fired.

Input: the scored flow frame (features.csv.gz from score_pcap(keep_features=True)
or any frame with the same columns): ts, srcip, dstip, dsport, l4, state, spkts,
dpkts. `state` is the Argus vocabulary from features.argus_state.

Detectors (thresholds frozen in docs/behavior.md before any attack day was run):

  scan_vertical    one source -> one target, within a 60 s window: at least 100
                   distinct destination ports, at least half of them probes
  scan_horizontal  one source -> one port, within a 60 s window: at least 50
                   distinct targets, at least half probes
  flood            one target service (address, port, protocol), per 60 s: at
                   least 1,000 connections and at least 10x the service's own
                   median over the previous 30 minutes

A probe is a connection that never carried an exchange: no reply, refused or
reset (REQ, RST, INT), or at most two packets each way.

Each detector returns events (one per run of consecutive firing windows) and the
flows that belong to them, so evaluations can check events against labels and
the app can show the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

WINDOW_S = 60.0
FAILED_STATES = ("REQ", "RST", "INT")
PROBE_MAX_PKTS = 2

SCAN_MIN_PORTS = 100
SCAN_MIN_TARGETS = 50
SCAN_MIN_PROBE_SHARE = 0.5

FLOOD_MIN_CONNS = 1000
FLOOD_MULTIPLE = 10.0
FLOOD_HISTORY_WINDOWS = 30
FLOOD_MIN_HISTORY = 5          # windows since capture start before a flood can fire

TECHNIQUES = {"scan_vertical": "T1046", "scan_horizontal": "T1046",
              "flood": "T1498/T1499"}


@dataclass
class Detections:
    events: pd.DataFrame      # one row per event
    members: pd.DataFrame     # event_id, flow (index into the input frame)


def _empty() -> Detections:
    return Detections(pd.DataFrame(columns=["event_id", "detector", "technique", "source",
                                            "target", "start", "end", "flows", "evidence"]),
                      pd.DataFrame(columns=["event_id", "flow"]))


def is_probe(f: pd.DataFrame) -> pd.Series:
    small = (pd.to_numeric(f["spkts"], errors="coerce").fillna(0) <= PROBE_MAX_PKTS) & \
            (pd.to_numeric(f["dpkts"], errors="coerce").fillna(0) <= PROBE_MAX_PKTS)
    return f["state"].isin(FAILED_STATES) | small


def _window(ts: pd.Series) -> pd.Series:
    return (ts.astype(float) // WINDOW_S).astype(np.int64)


def _runs(fired: pd.DataFrame, keys: list[str]) -> pd.DataFrame:
    """Give consecutive firing windows of the same key one run id."""
    fired = fired.sort_values(keys + ["w"])
    new = (fired[keys].ne(fired[keys].shift()).any(axis=1)) | (fired["w"].diff() != 1)
    return fired.assign(run=new.cumsum())


def _collect(name: str, f: pd.DataFrame, fired: pd.DataFrame, keys: list[str],
             source_of, target_of, evidence_of) -> Detections:
    if fired.empty:
        return _empty()
    fired = _runs(fired, keys)
    member = f[keys + ["w"]].reset_index().merge(fired[keys + ["w", "run"]], on=keys + ["w"])
    events, members = [], []
    for run, m in member.groupby("run"):
        rows = f.loc[m["index"]]
        eid = f"{name}-{len(events) + 1}"
        events.append({"event_id": eid, "detector": name, "technique": TECHNIQUES[name],
                       "source": source_of(rows), "target": target_of(rows),
                       "start": float(rows["ts"].min()), "end": float(rows["ts"].max()),
                       "flows": int(len(rows)),
                       "evidence": evidence_of(rows, fired[fired["run"] == run])})
        members.append(pd.DataFrame({"event_id": eid, "flow": m["index"].values}))
    return Detections(pd.DataFrame(events), pd.concat(members, ignore_index=True))


def _top(s: pd.Series, n: int = 3) -> dict:
    return {str(k): int(v) for k, v in s.value_counts().head(n).items()}


def scan_vertical(f: pd.DataFrame) -> Detections:
    f = f.assign(w=_window(f["ts"]), probe=is_probe(f))
    g = f.groupby(["srcip", "dstip", "w"]).agg(ports=("dsport", "nunique"), probes=("probe", "mean"))
    fired = g[(g["ports"] >= SCAN_MIN_PORTS) & (g["probes"] >= SCAN_MIN_PROBE_SHARE)].reset_index()
    return _collect(
        "scan_vertical", f, fired, ["srcip", "dstip"],
        lambda r: str(r["srcip"].iloc[0]), lambda r: str(r["dstip"].iloc[0]),
        lambda r, w: {"distinct_ports": int(r["dsport"].nunique()),
                      "peak_ports_per_minute": int(w["ports"].max()),
                      "probe_share": round(float(r["probe"].mean()), 3),
                      "states": _top(r["state"]), "minutes": int(len(w))})


def scan_horizontal(f: pd.DataFrame) -> Detections:
    f = f.assign(w=_window(f["ts"]), probe=is_probe(f))
    g = f.groupby(["srcip", "dsport", "l4", "w"]).agg(targets=("dstip", "nunique"),
                                                      probes=("probe", "mean"))
    fired = g[(g["targets"] >= SCAN_MIN_TARGETS) & (g["probes"] >= SCAN_MIN_PROBE_SHARE)].reset_index()
    return _collect(
        "scan_horizontal", f, fired, ["srcip", "dsport", "l4"],
        lambda r: str(r["srcip"].iloc[0]),
        lambda r: f"port {int(r['dsport'].iloc[0])}/{r['l4'].iloc[0]}",
        lambda r, w: {"distinct_targets": int(r["dstip"].nunique()),
                      "peak_targets_per_minute": int(w["targets"].max()),
                      "probe_share": round(float(r["probe"].mean()), 3), "minutes": int(len(w))})


def flood(f: pd.DataFrame) -> Detections:
    f = f.assign(w=_window(f["ts"]))
    counts = f.groupby(["dstip", "dsport", "l4", "w"]).size().rename("n").reset_index()
    busy = counts.groupby(["dstip", "dsport", "l4"])["n"].transform("max") >= FLOOD_MIN_CONNS
    counts = counts[busy]
    if counts.empty:
        return _empty()
    w0, w1 = int(f["w"].min()), int(f["w"].max())
    frames = []
    for key, g in counts.groupby(["dstip", "dsport", "l4"]):
        s = g.set_index("w")["n"].reindex(range(w0, w1 + 1), fill_value=0)
        past = s.shift(1).rolling(FLOOD_HISTORY_WINDOWS, min_periods=1).median().fillna(0)
        elapsed = pd.Series(np.arange(len(s)), index=s.index)
        fire = (s >= FLOOD_MIN_CONNS) & (s >= FLOOD_MULTIPLE * past.clip(lower=1)) & \
               (elapsed >= FLOOD_MIN_HISTORY)
        if fire.any():
            frames.append(pd.DataFrame({"dstip": key[0], "dsport": key[1], "l4": key[2],
                                        "w": s.index[fire], "n": s[fire].values,
                                        "past_median": past[fire].values}))
    if not frames:
        return _empty()
    fired = pd.concat(frames, ignore_index=True)
    return _collect(
        "flood", f, fired, ["dstip", "dsport", "l4"],
        lambda r: ", ".join(_top(r["srcip"]).keys()),
        lambda r: f"{r['dstip'].iloc[0]}:{int(r['dsport'].iloc[0])}/{r['l4'].iloc[0]}",
        lambda r, w: {"peak_per_minute": int(w["n"].max()),
                      "normal_per_minute": float(w["past_median"].iloc[0]),
                      "distinct_sources": int(r["srcip"].nunique()),
                      "top_sources": _top(r["srcip"]), "minutes": int(len(w))})


DETECTORS = {"scan_vertical": scan_vertical, "scan_horizontal": scan_horizontal, "flood": flood}


def run_all(flows: pd.DataFrame) -> Detections:
    """All detectors over TCP/UDP flows. Member indexes refer to `flows`."""
    f = flows[flows["l4"].isin(["tcp", "udp"])]
    if f.empty:
        return _empty()
    out = [DETECTORS[name](f) for name in DETECTORS]
    return Detections(pd.concat([d.events for d in out if len(d.events)], ignore_index=True)
                      if any(len(d.events) for d in out) else _empty().events,
                      pd.concat([d.members for d in out], ignore_index=True))
