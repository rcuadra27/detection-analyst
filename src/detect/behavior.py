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
  scan_horizontal  one source -> one port, within a 60 s window, at least half
                   probes, and either at least 50 targets inside one subnet
                   (/24, or /64 for IPv6) or at least 500 targets anywhere
  brute_force      (v4) one source -> one target, one login service (ssh, ftp,
                   telnet, rdp, vnc, pop3, imap), per 60 s: at least 20 sessions
                   that exchanged data
  flood            one target service (address, port, protocol), per 60 s: at
                   least 1,000 connections and at least 10x the service's own
                   median over the previous 30 minutes

A probe is a connection that never carried an exchange: no reply (REQ, INT),
or at most two packets each way (a refused SYN is one each way). A reset
connection that exchanged more than that is a normal close, not a probe.

Version 2 (docs/behavior.md): v1 counted every reset as a probe, so browsers
closing HTTPS sessions with a reset looked like a sweep; and v1's flood baseline
took in the flood itself, so a 21-minute DDoS stopped firing after 15 minutes.
v2 counts resets only when tiny, and freezes a service's baseline while it is
in alarm.

Version 3: v2's horizontal rule counted targets anywhere, and a Mac browsing
reached 50+ web servers in 87 different minutes of CIC Monday, with one-off
unanswered SYNs making two of them look like a sweep. A sweep walks a subnet;
browsing scatters across the internet. v3 counts targets per subnet, with a
much higher bar for targets spread across networks.

Each detector returns events (one per run of consecutive firing windows) and the
flows that belong to them, so evaluations can check events against labels and
the app can show the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

VERSION = "v5"
WINDOW_S = 60.0
NO_REPLY_STATES = ("REQ", "INT")
PROBE_MAX_PKTS = 2

SCAN_MIN_PORTS = 100
SCAN_MIN_SUBNET_TARGETS = 50     # in one /24 (IPv4) or /64 (IPv6)
SCAN_MIN_TARGETS_ANYWHERE = 500
SCAN_MIN_PROBE_SHARE = 0.5

FLOOD_MIN_CONNS = 1000
FLOOD_MULTIPLE = 10.0
FLOOD_HISTORY_WINDOWS = 30
FLOOD_MIN_HISTORY = 5          # windows since capture start before a flood can fire

# v4: login services a password-guessing tool targets. SMB (445) is left out:
# Windows clients open many SMB sessions to domain controllers and file servers.
AUTH_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 3389: "rdp", 5900: "vnc",
              110: "pop3", 143: "imap"}
BRUTE_MIN_SESSIONS = 20        # per minute, one source -> one target, one login service

# v5: one internal client hammering the DNS server is not a denial of service. It
# recurred on every CIC day (1,000-1,900 queries in a minute, labelled benign) and
# is reported by dns_burst instead, at low severity: it is also what DNS tunneling
# and domain-generating malware look like.
DNS_PORT = 53
DNS_BURST_MIN_QUERIES = 1000   # per minute, one source
DNS_SINGLE_CLIENT_SHARE = 0.5  # flood windows on port 53 where one private client sent this much
INFORMATIONAL = {"dns_burst"}  # reported, not judged as attacks (docs/behavior.md, v5)

TECHNIQUES = {"scan_vertical": "T1046", "scan_horizontal": "T1046",
              "flood": "T1498/T1499", "brute_force": "T1110", "dns_burst": "T1071.004"}


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
    return f["state"].isin(NO_REPLY_STATES) | small


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
                       "target_host": str(rows["dstip"].iloc[0]) if "dstip" in keys else None,
                       "target_port": int(rows["dsport"].iloc[0]) if "dsport" in keys else None,
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


def subnet(ip: pd.Series) -> pd.Series:
    """/24 for IPv4 (first three octets), /64 for IPv6 (first four groups)."""
    import ipaddress

    def net(a: str) -> str:
        try:
            addr = ipaddress.ip_address(a)
        except ValueError:
            return a
        bits = 24 if addr.version == 4 else 64
        return str(ipaddress.ip_network(f"{a}/{bits}", strict=False))

    s = ip.astype(str)
    uniq = {a: net(a) for a in s.unique()}      # few distinct addresses, many flows
    return s.map(uniq)


def scan_horizontal(f: pd.DataFrame) -> Detections:
    f = f.assign(w=_window(f["ts"]), probe=is_probe(f), net=subnet(f["dstip"]))
    keys = ["srcip", "dsport", "l4", "w"]
    g = f.groupby(keys).agg(targets=("dstip", "nunique"), probes=("probe", "mean"))
    g["subnet_targets"] = f.groupby(keys + ["net"])["dstip"].nunique().groupby(level=keys).max()
    fired = g[(g["probes"] >= SCAN_MIN_PROBE_SHARE)
              & ((g["subnet_targets"] >= SCAN_MIN_SUBNET_TARGETS)
                 | (g["targets"] >= SCAN_MIN_TARGETS_ANYWHERE))].reset_index()
    return _collect(
        "scan_horizontal", f, fired, ["srcip", "dsport", "l4"],
        lambda r: str(r["srcip"].iloc[0]),
        lambda r: f"port {int(r['dsport'].iloc[0])}/{r['l4'].iloc[0]}",
        lambda r, w: {"distinct_targets": int(r["dstip"].nunique()),
                      "peak_targets_per_minute": int(w["targets"].max()),
                      "peak_targets_in_one_subnet": int(w["subnet_targets"].max()),
                      "busiest_subnet": str(r["net"].value_counts().index[0]),
                      "probe_share": round(float(r["probe"].mean()), 3), "minutes": int(len(w))})


def _flood_windows(s: pd.Series) -> tuple[list, list, list]:
    """Walk a service's per-minute counts. The baseline is the median of the last
    FLOOD_HISTORY_WINDOWS minutes that were *not* in alarm, so a long flood does
    not become its own normal (v1 let it in, and stopped firing mid-attack)."""
    from collections import deque
    history: deque = deque(maxlen=FLOOD_HISTORY_WINDOWS)
    out_w, out_n, out_b = [], [], []
    for i, (w, n) in enumerate(s.items()):
        base = float(np.median(history)) if history else 0.0
        if i >= FLOOD_MIN_HISTORY and n >= FLOOD_MIN_CONNS and n >= FLOOD_MULTIPLE * max(base, 1.0):
            out_w.append(w)
            out_n.append(int(n))
            out_b.append(base)
        else:
            history.append(n)
    return out_w, out_n, out_b


def _private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _drop_single_dns_client(fired: pd.DataFrame, f: pd.DataFrame) -> pd.DataFrame:
    """v5: remove DNS flood windows that are one private client's burst (dns_burst
    reports those). Floods of a DNS server by many sources, or from outside, stay."""
    dns = fired[fired["dsport"] == DNS_PORT]
    if dns.empty:
        return fired
    sub = f[(f["dsport"] == DNS_PORT) & f["w"].isin(dns["w"]) & f["dstip"].isin(dns["dstip"])]
    per = sub.groupby(["dstip", "l4", "w", "srcip"]).size().rename("k").reset_index()
    top = per.sort_values("k").groupby(["dstip", "l4", "w"]).tail(1)
    tot = per.groupby(["dstip", "l4", "w"])["k"].sum().rename("total").reset_index()
    top = top.merge(tot, on=["dstip", "l4", "w"])
    one = top[(top["k"] >= DNS_SINGLE_CLIENT_SHARE * top["total"]) & top["srcip"].map(_private)]
    key = fired[["dstip", "dsport", "l4", "w"]].merge(
        one[["dstip", "l4", "w"]].assign(_x=1), on=["dstip", "l4", "w"], how="left")
    return fired[~((fired["dsport"] == DNS_PORT).values & key["_x"].notna().values)].reset_index(drop=True)


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
        fired_w, fired_n, fired_base = _flood_windows(s)
        if fired_w:
            frames.append(pd.DataFrame({"dstip": key[0], "dsport": key[1], "l4": key[2],
                                        "w": fired_w, "n": fired_n, "past_median": fired_base}))
    if not frames:
        return _empty()
    fired = _drop_single_dns_client(pd.concat(frames, ignore_index=True), f)
    if fired.empty:
        return _empty()
    return _collect(
        "flood", f, fired, ["dstip", "dsport", "l4"],
        lambda r: ", ".join(_top(r["srcip"]).keys()),
        lambda r: f"{r['dstip'].iloc[0]}:{int(r['dsport'].iloc[0])}/{r['l4'].iloc[0]}",
        lambda r, w: {"peak_per_minute": int(w["n"].max()),
                      "normal_per_minute": float(w["past_median"].iloc[0]),
                      "distinct_sources": int(r["srcip"].nunique()),
                      "top_sources": _top(r["srcip"]), "minutes": int(len(w))})


def brute_force(f: pd.DataFrame) -> Detections:
    """One source opening at least 20 real sessions a minute to one login service on
    one target. A person logs in a few times an hour; a guessing tool connects, tries,
    disconnects and repeats. Sessions only: probes (refused or unanswered) belong to
    the scan rules. The rule cannot see whether logins failed (SSH is encrypted), so
    automation that logs in in a tight loop is a benign look-alike."""
    f = f.assign(w=_window(f["ts"]), probe=is_probe(f))
    s = f[f["dsport"].isin(list(AUTH_PORTS)) & ~f["probe"]]
    if s.empty:
        return _empty()
    g = s.groupby(["srcip", "dstip", "dsport", "w"]).size().rename("n").reset_index()
    fired = g[g["n"] >= BRUTE_MIN_SESSIONS]
    has_dur = "dur" in s.columns
    return _collect(
        "brute_force", s, fired, ["srcip", "dstip", "dsport"],
        lambda r: str(r["srcip"].iloc[0]),
        lambda r: f"{r['dstip'].iloc[0]}:{int(r['dsport'].iloc[0])} "
                  f"({AUTH_PORTS[int(r['dsport'].iloc[0])]})",
        lambda r, w: {"sessions": int(len(r)), "peak_sessions_per_minute": int(w["n"].max()),
                      "service": AUTH_PORTS[int(r["dsport"].iloc[0])],
                      "median_session_seconds": (round(float(pd.to_numeric(r["dur"], errors="coerce")
                                                                .median()), 2) if has_dur else None),
                      "minutes": int(len(w))})


def dns_burst(f: pd.DataFrame) -> Detections:
    """v5: one source sending at least 1,000 DNS queries in a minute. Low severity and
    informational: in test data it was always software on an office machine, and it
    is also the shape of DNS tunneling and domain-generating malware."""
    f = f.assign(w=_window(f["ts"]))
    s = f[f["dsport"] == DNS_PORT]
    if s.empty:
        return _empty()
    g = s.groupby(["srcip", "w"]).agg(n=("dstip", "size"), servers=("dstip", "nunique")).reset_index()
    fired = g[g["n"] >= DNS_BURST_MIN_QUERIES]
    return _collect(
        "dns_burst", s, fired, ["srcip"],
        lambda r: str(r["srcip"].iloc[0]),
        lambda r: "DNS (" + ", ".join(_top(r["dstip"], 2).keys()) + ")",
        lambda r, w: {"queries": int(len(r)), "peak_queries_per_minute": int(w["n"].max()),
                      "dns_servers": int(r["dstip"].nunique()), "minutes": int(len(w))})


DETECTORS = {"scan_vertical": scan_vertical, "scan_horizontal": scan_horizontal, "flood": flood,
             "brute_force": brute_force, "dns_burst": dns_burst}


def run_all(flows: pd.DataFrame) -> Detections:
    """All detectors over TCP/UDP flows. Member indexes refer to `flows`."""
    f = flows[flows["l4"].isin(["tcp", "udp"])]
    if f.empty:
        return _empty()
    out = [DETECTORS[name](f) for name in DETECTORS]
    return Detections(pd.concat([d.events for d in out if len(d.events)], ignore_index=True)
                      if any(len(d.events) for d in out) else _empty().events,
                      pd.concat([d.members for d in out], ignore_index=True))


# ---------------------------------------------------------------- for the app

_NAMES = {"scan_vertical": "Port scan", "scan_horizontal": "Network sweep", "flood": "Flood",
          "brute_force": "Brute force", "dns_burst": "DNS burst"}


def _summary(e: dict) -> str:
    ev, d = e["evidence"], e["detector"]
    if d == "scan_vertical":
        return (f"Port scan: {e['source']} probed {ev['distinct_ports']} ports on {e['target']} "
                f"({ev['probe_share']:.0%} unanswered or refused), {ev['minutes']} min")
    if d == "scan_horizontal":
        return (f"Network sweep: {e['source']} probed {ev['distinct_targets']} hosts on "
                f"{e['target']} (up to {ev['peak_targets_in_one_subnet']} in "
                f"{ev['busiest_subnet']} in a minute), {ev['minutes']} min")
    if d == "dns_burst":
        return (f"DNS burst: {e['source']} sent {ev['queries']:,} DNS queries (up to "
                f"{ev['peak_queries_per_minute']:,} a minute) to {ev['dns_servers']} server(s), "
                f"{ev['minutes']} min")
    if d == "brute_force":
        return (f"Brute force: {e['source']} opened {ev['sessions']:,} {ev['service']} sessions to "
                f"{e['target'].split(' ')[0]} (up to {ev['peak_sessions_per_minute']} a minute), "
                f"{ev['minutes']} min")
    top = next(iter(ev["top_sources"]), "?")
    return (f"Flood: {e['target']} received up to {ev['peak_per_minute']:,} connections a "
            f"minute (normal {ev['normal_per_minute']:g}), {ev['minutes']} min, mostly from {top}")


def to_records(det: Detections) -> list[dict]:
    """Events as JSON-ready dicts for the store (behavior.json) and the agent's tools.

    `source` is the host the event is about: the scanner, or a flood's main sender.
    `sources` lists the senders behind at least 10% of a flood's connections (an
    event also holds the target's normal traffic in those minutes)."""
    out = []
    for e in det.events.to_dict("records"):
        if e["detector"] == "flood":
            top = e["evidence"]["top_sources"]
            srcs = [s for s, n in top.items() if n >= 0.1 * e["flows"]] or list(top)[:1]
        else:
            srcs = [e["source"]]
        rec = {"event_id": f"RULE-{e['event_id']}", "detector": e["detector"],
               "name": _NAMES[e["detector"]],
               "technique_ids": e["technique"].split("/"),
               "source": srcs[0], "sources": srcs, "target": e["target"],
               "target_host": e.get("target_host"), "target_port": e.get("target_port"),
               "start": float(e["start"]), "end": float(e["end"]), "flows": int(e["flows"]),
               "evidence": e["evidence"], "version": VERSION}
        rec["summary"] = _summary({**rec, "source": srcs[0]})
        out.append(rec)
    return out
