"""
Phase A — rebuild UNSW-NB15's 42 flow features from a raw pcap with Zeek.

WHY: the detector was trained on UNSW's published feature CSVs. To score a pcap
someone uploads, the same 42 features have to be recomputed from packets. If any
of them is computed differently, the model sees shifted inputs and nothing
errors. This module does the recomputation and records, per feature, how
faithful it is, so the parity experiment (parity.py) can measure the cost.

UNSW-NB15 generated its features with Argus (packet-level flow statistics) and
Bro, Zeek's predecessor (service and HTTP/FTP fields), plus its own counting
features over the last 100 connections. Some definitions are not documented
precisely (first or last TTL? which jitter formula?). Where that is the case the
adapter emits every reasonable candidate as `feature@variant`, and the parity
experiment picks one per feature on a CALIBRATION capture and reports results on
a different VALIDATION capture. Choosing and scoring on the same capture would
make the agreement look better than it is.

PROVENANCE (also exported as PROVENANCE for the report):
    zeek       taken from a standard Zeek log
    script     computed by zeek/unsw_features.zeek
    derived    arithmetic on other features
    window     counted over the previous 100 connections
    lookup     learned from the UNSW training CSV (ct_state_ttl)
    mapped     Zeek's value translated to Argus's vocabulary (state)

Usage:
    python -m src.ingest.features --pcap capture.pcap --out data/processed/ingest/capture
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, deque
from pathlib import Path

import numpy as np
import pandas as pd

from src.ingest.zeek_run import read_logs, run_zeek

# The 42 model inputs, in UNSW_NB15_training-set.csv column order
# (minus id, attack_cat, label).
UNSW_FEATURES = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt",
    "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
]

# Columns carried alongside the features to join and correlate, never scored.
META = ["uid", "ts", "end_ts", "srcip", "sport", "dstip", "dsport", "l4"]

PROVENANCE = {
    "dur": "zeek", "proto": "zeek", "service": "zeek", "state": "mapped",
    "spkts": "zeek", "dpkts": "zeek", "sbytes": "zeek", "dbytes": "zeek",
    "rate": "derived", "sttl": "script", "dttl": "script",
    "sload": "derived", "dload": "derived", "sloss": "script", "dloss": "script",
    "sinpkt": "script", "dinpkt": "script", "sjit": "script", "djit": "script",
    "swin": "script", "stcpb": "script", "dtcpb": "script", "dwin": "script",
    "tcprtt": "derived", "synack": "script", "ackdat": "script",
    "smean": "derived", "dmean": "derived", "trans_depth": "zeek",
    "response_body_len": "zeek", "ct_srv_src": "window", "ct_state_ttl": "lookup",
    "ct_dst_ltm": "window", "ct_src_dport_ltm": "window",
    "ct_dst_sport_ltm": "window", "ct_dst_src_ltm": "window",
    "is_ftp_login": "script", "ct_ftp_cmd": "script", "ct_flw_http_mthd": "zeek",
    "ct_src_ltm": "window", "ct_srv_dst": "window", "is_sm_ips_ports": "derived",
}

# Candidate definitions for features whose UNSW definition is ambiguous.
# The first entry is the default when no calibration has been run.
VARIANTS = {
    "bytes":  ["ip", "payload"],          # sbytes/dbytes: IP bytes or payload bytes
    "ttl":    ["first", "last"],
    "win":    ["first", "last", "max"],
    "jit":    ["std", "mad"],
    "service": ["zeek", "zeek_port"],     # zeek_port: fall back to well-known port
    "rate":   ["pkts_minus1", "pkts"],    # (spkts+dpkts-1)/dur or (spkts+dpkts)/dur
    "body":   ["sum", "max"],             # response_body_len over transactions
    "mthd":   ["getpost", "any"],         # ct_flw_http_mthd
    "window": ["end_self", "end_noself", "start_self", "start_noself"],
}
DEFAULT_CHOICE = {k: v[0] for k, v in VARIANTS.items()}

# Port fallback for the zeek_port service variant: UNSW's service values.
PORT_SERVICE = {
    80: "http", 8080: "http", 21: "ftp", 20: "ftp-data", 25: "smtp", 110: "pop3",
    53: "dns", 161: "snmp", 443: "ssl", 67: "dhcp", 68: "dhcp", 6667: "irc",
    1812: "radius", 1813: "radius", 22: "ssh",
}
UNSW_SERVICES = {"http", "ftp", "ftp-data", "smtp", "pop3", "dns", "snmp", "ssl",
                 "dhcp", "irc", "radius", "ssh"}
_ZEEK_SERVICE_ALIASES = {"ftp_data": "ftp-data", "ftp-data": "ftp-data"}

CT_WINDOW = 100


# ---------------------------------------------------------------- state mapping

def argus_state(l4: str, conn_state: str | None, resp_pkts: int) -> str:
    """Translate Zeek's conn_state into Argus's state vocabulary.

    This is an approximation: Argus tracks state differently, and the parity
    experiment reports the confusion between the two. UDP and ICMP have no
    handshake, so they are CON/INT (and ECO for ICMP echo) by whether a reply
    came back.
    """
    replied = (resp_pkts or 0) > 0
    if l4 == "udp":
        return "CON" if replied else "INT"
    if l4 == "icmp":
        return "ECO" if replied else "INT"
    s = (conn_state or "").upper()
    if s == "SF" or s in ("S2", "S3"):
        return "FIN"
    if s == "S0" or s == "SH":
        return "REQ"
    if s == "S1":
        return "CON"
    if s == "REJ" or s.startswith("RST"):
        return "RST"
    if s == "SHR":
        return "ACC"
    return "CON" if replied else "INT"   # OTH: midstream


def normalize_service(svc, dport: int, variant: str) -> str:
    """Zeek service -> UNSW's service vocabulary ('-' when none)."""
    out = "-"
    if isinstance(svc, str) and svc:
        for part in svc.split(","):
            part = _ZEEK_SERVICE_ALIASES.get(part.strip().lower(), part.strip().lower())
            if part in UNSW_SERVICES:
                out = part
                break
    if out == "-" and variant == "zeek_port":
        out = PORT_SERVICE.get(int(dport), "-")
    return out


# ---------------------------------------------------------------- base table

def _num(df: pd.DataFrame, col: str, default=0.0) -> pd.Series:
    if col not in df.columns:
        return pd.Series(default, index=df.index, dtype="float64")
    return pd.to_numeric(df[col], errors="coerce").fillna(default)


def build_base(logs: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """One row per Zeek connection with every candidate column.

    Columns are META plus raw/candidate fields; `select` turns this into the 42
    model features for a given choice of variants.
    """
    conn = logs["conn"]
    if conn.empty:
        return pd.DataFrame(columns=META)
    conn = conn[conn["proto"].isin(["tcp", "udp", "icmp"])].copy()

    b = pd.DataFrame(index=conn.index)
    b["uid"] = conn["uid"]
    b["ts"] = _num(conn, "ts")
    b["dur"] = _num(conn, "duration")
    b["end_ts"] = b["ts"] + b["dur"]
    b["srcip"] = conn["id.orig_h"]
    b["sport"] = _num(conn, "id.orig_p").astype(int)
    b["dstip"] = conn["id.resp_h"]
    b["dsport"] = _num(conn, "id.resp_p").astype(int)
    b["l4"] = conn["proto"]
    b["proto"] = conn["proto"]
    b["zeek_service"] = conn.get("service", pd.Series(None, index=conn.index))
    b["conn_state"] = conn.get("conn_state", pd.Series(None, index=conn.index))
    b["spkts"] = _num(conn, "orig_pkts").astype(int)
    b["dpkts"] = _num(conn, "resp_pkts").astype(int)
    b["sbytes@ip"] = _num(conn, "orig_ip_bytes").astype(int)
    b["dbytes@ip"] = _num(conn, "resp_ip_bytes").astype(int)
    b["sbytes@payload"] = _num(conn, "orig_bytes").astype(int)
    b["dbytes@payload"] = _num(conn, "resp_bytes").astype(int)

    # unsw.log, joined on uid
    u = logs["unsw"]
    if not u.empty:
        u = u.drop_duplicates("uid").set_index("uid")
        j = u.reindex(b["uid"]).reset_index(drop=True)
        j.index = b.index
    else:
        j = pd.DataFrame(index=b.index)
    for side in ("s", "d"):
        for v in VARIANTS["ttl"]:
            b[f"{side}ttl@{v}"] = _num(j, f"{side}_ttl_{v}").astype(int)
        for v in VARIANTS["win"]:
            b[f"{side}win@{v}"] = _num(j, f"{side}_win_{v}").astype(int)
        b[f"{side}tcpb"] = _num(j, f"{side}_isn").astype("int64")
        b[f"{side}inpkt"] = _num(j, f"{side}_ipt_mean_ms")
        b[f"{side}jit@std"] = _num(j, f"{side}_ipt_std_ms")
        b[f"{side}jit@mad"] = _num(j, f"{side}_ipt_mad_ms")
        b[f"{side}loss"] = _num(j, f"{side}_retrans").astype(int)
    b["synack"] = _num(j, "synack")
    b["ackdat"] = _num(j, "ackdat")
    b["ct_ftp_cmd"] = _num(j, "ftp_cmds").astype(int)
    login = j["ftp_login"] if "ftp_login" in j.columns else pd.Series(False, index=b.index)
    b["is_ftp_login"] = login.fillna(False).astype(bool).astype(int)

    # http.log aggregates per uid
    h = logs["http"]
    for col in ("trans_depth", "response_body_len@sum", "response_body_len@max",
                "ct_flw_http_mthd@getpost", "ct_flw_http_mthd@any"):
        b[col] = 0
    if not h.empty and "uid" in h.columns:
        h = h.copy()
        h["trans_depth"] = _num(h, "trans_depth")
        h["response_body_len"] = _num(h, "response_body_len")
        method = h.get("method", pd.Series("", index=h.index)).fillna("").str.upper()
        h["_getpost"] = method.isin(["GET", "POST"]).astype(int)
        h["_any"] = (method != "").astype(int)
        agg = h.groupby("uid").agg(
            td=("trans_depth", "max"), bsum=("response_body_len", "sum"),
            bmax=("response_body_len", "max"), gp=("_getpost", "sum"), anym=("_any", "sum"))
        a = agg.reindex(b["uid"]).fillna(0)
        a.index = b.index
        b["trans_depth"] = a["td"].astype(int)
        b["response_body_len@sum"] = a["bsum"].astype(int)
        b["response_body_len@max"] = a["bmax"].astype(int)
        b["ct_flw_http_mthd@getpost"] = a["gp"].astype(int)
        b["ct_flw_http_mthd@any"] = a["anym"].astype(int)

    b["is_sm_ips_ports"] = ((b["srcip"] == b["dstip"]) & (b["sport"] == b["dsport"])).astype(int)
    b["state"] = [argus_state(l, s, r) for l, s, r in zip(b["l4"], b["conn_state"], b["dpkts"])]
    return b.reset_index(drop=True)


# ---------------------------------------------------------------- windows

_CT_KEYS = {
    "ct_srv_src": ("service", "srcip"),
    "ct_srv_dst": ("service", "dstip"),
    "ct_dst_ltm": ("dstip",),
    "ct_src_ltm": ("srcip",),
    "ct_src_dport_ltm": ("srcip", "dsport"),
    "ct_dst_sport_ltm": ("dstip", "sport"),
    "ct_dst_src_ltm": ("srcip", "dstip"),
}


def window_counts(df: pd.DataFrame, variant: str = "end_self",
                  window: int = CT_WINDOW) -> pd.DataFrame:
    """UNSW's 'number of connections with the same X in the last 100 connections'.

    Connections are ordered by end time (Argus's 'last time') or start time; the
    count includes or excludes the connection itself. `df` must already have a
    `service` column.
    """
    order_col = "end_ts" if variant.startswith("end") else "ts"
    include_self = variant.endswith("_self")
    order = np.argsort(df[order_col].to_numpy(), kind="stable")
    keys = {name: list(zip(*(df[c].to_numpy() for c in cols)))
            for name, cols in _CT_KEYS.items()}
    out = {name: np.zeros(len(df), dtype=int) for name in _CT_KEYS}
    counters = {name: Counter() for name in _CT_KEYS}
    recent: deque[int] = deque()
    for i in order:
        for name in _CT_KEYS:
            k = keys[name][i]
            out[name][i] = counters[name][k] + (1 if include_self else 0)
        recent.append(i)
        for name in _CT_KEYS:
            counters[name][keys[name][i]] += 1
        if len(recent) > window - (1 if include_self else 0):
            old = recent.popleft()
            for name in _CT_KEYS:
                counters[name][keys[name][old]] -= 1
    return pd.DataFrame(out, index=df.index)


# ---------------------------------------------------------------- ct_state_ttl

def learn_ct_state_ttl(train_csv: str | Path) -> dict:
    """Learn UNSW's (state, sttl, dttl) -> ct_state_ttl table from the training CSV.

    UNSW documents ct_state_ttl only as 'a number for each state according to a
    range of TTL values'. Rather than guess the ranges, read the mapping off the
    training data and record how deterministic it is.
    """
    df = pd.read_csv(train_csv, usecols=["state", "sttl", "dttl", "ct_state_ttl"])
    g = df.groupby(["state", "sttl", "dttl"])["ct_state_ttl"]
    mode = g.agg(lambda s: s.value_counts().idxmax())
    purity = float((g.agg(lambda s: s.value_counts().iloc[0]).sum()) / len(df))
    table = {f"{s}|{a}|{b}": int(v) for (s, a, b), v in mode.items()}
    return {"table": table, "purity": purity, "rows": int(len(df))}


def apply_ct_state_ttl(state: pd.Series, sttl: pd.Series, dttl: pd.Series,
                       lookup: dict | None) -> pd.Series:
    if not lookup:
        return pd.Series(0, index=state.index, dtype=int)
    t = lookup["table"]
    return pd.Series([t.get(f"{s}|{a}|{b}", 0) for s, a, b in zip(state, sttl, dttl)],
                     index=state.index, dtype=int)


# ---------------------------------------------------------------- select

def select(base: pd.DataFrame, choice: dict | None = None,
           ct_lookup: dict | None = None) -> pd.DataFrame:
    """Pick one variant per ambiguous feature and compute the derived ones.

    Returns META + the 42 UNSW_FEATURES, in training column order.
    """
    c = {**DEFAULT_CHOICE, **(choice or {})}
    f = pd.DataFrame(index=base.index)
    for m in META:
        f[m] = base[m]
    f["dur"] = base["dur"]
    f["proto"] = base["proto"]
    f["service"] = [normalize_service(s, p, c["service"])
                    for s, p in zip(base["zeek_service"], base["dsport"])]
    f["state"] = base["state"]
    f["spkts"], f["dpkts"] = base["spkts"], base["dpkts"]
    f["sbytes"] = base[f"sbytes@{c['bytes']}"]
    f["dbytes"] = base[f"dbytes@{c['bytes']}"]

    dur = base["dur"].to_numpy(dtype=float)
    pk = (base["spkts"] + base["dpkts"]).to_numpy(dtype=float)
    if c["rate"] == "pkts_minus1":
        pk = pk - 1
    with np.errstate(divide="ignore", invalid="ignore"):
        f["rate"] = np.where(dur > 0, pk / dur, 0.0)
        f["sload"] = np.where(dur > 0, f["sbytes"] * 8.0 / dur, 0.0)
        f["dload"] = np.where(dur > 0, f["dbytes"] * 8.0 / dur, 0.0)

    f["sttl"] = base[f"sttl@{c['ttl']}"]
    f["dttl"] = base[f"dttl@{c['ttl']}"]
    f["sloss"], f["dloss"] = base["sloss"], base["dloss"]
    f["sinpkt"], f["dinpkt"] = base["sinpkt"], base["dinpkt"]
    f["sjit"] = base[f"sjit@{c['jit']}"]
    f["djit"] = base[f"djit@{c['jit']}"]
    f["swin"] = base[f"swin@{c['win']}"]
    f["stcpb"], f["dtcpb"] = base["stcpb"], base["dtcpb"]
    f["dwin"] = base[f"dwin@{c['win']}"]
    f["synack"], f["ackdat"] = base["synack"], base["ackdat"]
    f["tcprtt"] = base["synack"] + base["ackdat"]
    with np.errstate(divide="ignore", invalid="ignore"):
        f["smean"] = np.where(f["spkts"] > 0, f["sbytes"] // f["spkts"].clip(lower=1), 0).astype(int)
        f["dmean"] = np.where(f["dpkts"] > 0, f["dbytes"] // f["dpkts"].clip(lower=1), 0).astype(int)
    f["trans_depth"] = base["trans_depth"]
    f["response_body_len"] = base[f"response_body_len@{c['body']}"]
    f["is_ftp_login"] = base["is_ftp_login"]
    f["ct_ftp_cmd"] = base["ct_ftp_cmd"]
    f["ct_flw_http_mthd"] = base[f"ct_flw_http_mthd@{c['mthd']}"]
    f["is_sm_ips_ports"] = base["is_sm_ips_ports"]
    f["ct_state_ttl"] = apply_ct_state_ttl(f["state"], f["sttl"], f["dttl"], ct_lookup)

    ct = window_counts(f, c["window"])
    for col in ct.columns:
        f[col] = ct[col]
    return f[META + UNSW_FEATURES]


def features_from_pcap(pcap: str | Path, workdir: str | Path, choice: dict | None = None,
                       ct_lookup: dict | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """pcap -> (base candidates, selected 42-feature frame)."""
    run_zeek(pcap, workdir)
    base = build_base(read_logs(workdir))
    return base, select(base, choice, ct_lookup)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True, help="directory for Zeek logs and features")
    ap.add_argument("--choice", help="JSON variant choice from parity calibration")
    ap.add_argument("--ct-lookup", help="JSON from learn_ct_state_ttl")
    args = ap.parse_args()
    choice = json.loads(Path(args.choice).read_text())["choice"] if args.choice else None
    lookup = json.loads(Path(args.ct_lookup).read_text()) if args.ct_lookup else None
    out = Path(args.out)
    base, feats = features_from_pcap(args.pcap, out / "zeek", choice, lookup)
    base.to_csv(out / "base.csv.gz", index=False)
    feats.to_csv(out / "features.csv.gz", index=False)
    print(f"[ingest] {len(feats)} connections -> {out / 'features.csv.gz'}")


if __name__ == "__main__":
    main()
