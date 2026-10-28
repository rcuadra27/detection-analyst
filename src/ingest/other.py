"""
Flows for traffic Zeek does not make connections from: IP protocols other than
TCP, UDP and ICMP, and ARP.

WHY: run 1 matched 0% of these UNSW records. They are 12% of UNSW's attacks
(IP protocol sweeps across rare protocol numbers) plus ordinary ARP and OSPF.

UNSW's records for them (from Argus) are keyed by (source, destination,
protocol) with ports 0: CON when packets went both ways, INT otherwise. Packets
are grouped over time, but the grouping rule is not documented (an OSPF record
holds 6 hellos sent 10 s apart over 50 s). So the Zeek script logs one line per
packet (other.log) and this module groups them under several candidate rules;
calibration picks one, like the other ambiguous definitions.

Protocol names follow the IANA keyword list Argus used (older entries such as
sep, swipe and sun-nd); unassigned numbers are 'unas', as in UNSW. Where the
exact Argus name is uncertain the report's protocol table shows the mismatch.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

ARP_PROTO = 256

# IANA protocol keywords as Argus names them (lowercase). Numbers 134-252 are
# unassigned in that list and print as 'unas'.
_NAMES = (
    "ip icmp igmp ggp ipnip st2 tcp cbt egp igp bbn-rcc nvp pup argus emcon xnet "
    "chaos udp mux dcn hmp prm xns-idp trunk-1 trunk-2 leaf-1 leaf-2 rdp irtp "
    "iso-tp4 netblt mfe-nsp merit-inp sep 3pc idpr xtp ddp idpr-cmtp tp++ il ipv6 "
    "sdrp ipv6-route ipv6-frag idrp rsvp gre mhrp bna esp ah i-nlsp swipe narp "
    "mobile tlsp skip ipv6-icmp ipv6-no ipv6-opts any cftp any sat-expak kryptolan "
    "rvd ippc any sat-mon visa ipcv cpnx cphb wsn pvp br-sat-mon sun-nd wb-mon "
    "wb-expak iso-ip vmtp secure-vmtp vines ttp nsfnet-igp dgp tcf eigrp ospf "
    "sprite-rpc larp mtp ax.25 ipip micp aes-sp3-d etherip encap pri-enc gmtp ifmp "
    "pnni pim aris scps qnx a/n ipcomp snp compaq-peer ipx-n-ip vrrp pgm any l2tp "
    "ddx iatp stp srp uti smp sm ptp isis fire crtp crudp sccopmce iplt sps pipe "
    "sctp fc"
).split()
PROTO_NAMES = {i: n for i, n in enumerate(_NAMES)}
PROTO_NAMES[ARP_PROTO] = "arp"


def proto_name(n: int) -> str:
    return PROTO_NAMES.get(int(n), "unas")


# Grouping rules: a flow ends after `idle` seconds without a packet, or once
# it has lasted `max_dur` seconds (None: no cap).
GROUPING = {
    "idle60_max60": (60.0, 60.0),
    "idle60": (60.0, None),
    "idle30_max30": (30.0, 30.0),
    "idle120_max120": (120.0, 120.0),
}
DEFAULT_GROUPING = "idle60_max60"


def _gaps_ms(ts: np.ndarray) -> np.ndarray:
    return np.diff(ts) * 1000.0 if len(ts) > 1 else np.array([])


def _dir_stats(ts: np.ndarray, lens: np.ndarray, ttls: np.ndarray) -> dict:
    g = _gaps_ms(ts)
    jd = np.abs(np.diff(g)) if len(g) > 1 else np.array([])
    return {
        "pkts": len(ts), "bytes": int(lens.sum()),
        "ttl_first": int(ttls[0]) if len(ttls) else 0,
        "ttl_last": int(ttls[-1]) if len(ttls) else 0,
        "ipt_mean": float(g.mean()) if len(g) else 0.0,
        "ipt_std": float(g.std()) if len(g) else 0.0,
        "ipt_mad": float(jd.mean()) if len(jd) else 0.0,
    }


def group_packets(pk: pd.DataFrame, rule: str = DEFAULT_GROUPING) -> pd.DataFrame:
    """Group other.log packets into flows, in the same column schema as
    features.build_base so the rows can be selected and scored together."""
    from src.ingest.features import META
    cols = META + ["dur", "proto", "zeek_service", "conn_state", "state", "spkts", "dpkts"]
    if pk is None or pk.empty:
        return pd.DataFrame(columns=cols)
    idle, max_dur = GROUPING[rule]
    pk = pk.sort_values("ts", kind="stable").reset_index(drop=True)
    a = pk["src"].astype(str).to_numpy()
    b = pk["dst"].astype(str).to_numpy()
    pair = np.where(a <= b, a + "|" + b, b + "|" + a)
    pk["_key"] = pair + "|" + pk["proto"].astype(str)

    flows: list[dict] = []
    open_: dict[str, dict] = {}

    def close(f: dict) -> None:
        flows.append(f)

    for i, (k, ts) in enumerate(zip(pk["_key"].to_numpy(), pk["ts"].to_numpy())):
        f = open_.get(k)
        if f is not None and (ts - f["last"] > idle or
                              (max_dur is not None and ts - f["start"] >= max_dur)):
            close(f)
            f = None
        if f is None:
            f = {"start": ts, "last": ts, "rows": [], "orig": pk.at[i, "src"]}
            open_[k] = f
        f["rows"].append(i)
        f["last"] = ts
    for f in open_.values():
        close(f)

    out = []
    for n, f in enumerate(sorted(flows, key=lambda f: f["start"])):
        r = pk.loc[f["rows"]]
        orig = str(f["orig"])
        fwd = r[r["src"].astype(str) == orig]
        rev = r[r["src"].astype(str) != orig]
        s = _dir_stats(fwd["ts"].to_numpy(float), fwd["len"].to_numpy(int), fwd["ttl"].to_numpy(int))
        d = _dir_stats(rev["ts"].to_numpy(float), rev["len"].to_numpy(int), rev["ttl"].to_numpy(int))
        first = r.iloc[0]
        dst = str(first["dst"]) if str(first["src"]) == orig else str(first["src"])
        row = {
            "uid": f"O{n}", "ts": float(f["start"]), "dur": float(f["last"] - f["start"]),
            "srcip": orig, "sport": 0, "dstip": dst, "dsport": 0, "l4": "other",
            "proto": proto_name(first["proto"]), "zeek_service": None, "conn_state": None,
            "state": "CON" if d["pkts"] else "INT",
            "spkts": s["pkts"], "dpkts": d["pkts"],
            "is_sm_ips_ports": int(orig == dst),     # ports are 0 on both sides
        }
        row["end_ts"] = row["ts"] + row["dur"]
        for side, st in (("s", s), ("d", d)):
            row[f"{side}bytes@ip"] = row[f"{side}bytes@payload"] = st["bytes"]
            row[f"{side}ttl@first"], row[f"{side}ttl@last"] = st["ttl_first"], st["ttl_last"]
            row[f"{side}inpkt"] = st["ipt_mean"]
            row[f"{side}jit@std"], row[f"{side}jit@mad"] = st["ipt_std"], st["ipt_mad"]
        out.append(row)
    return pd.DataFrame(out)


def combine(base: pd.DataFrame, packets: pd.DataFrame | None,
            rule: str = DEFAULT_GROUPING) -> pd.DataFrame:
    """Connection rows from Zeek plus other-protocol flows under `rule`.

    Columns the other path does not produce (TCP, HTTP, FTP fields) are 0.
    """
    conn = base[base["l4"] != "other"] if "l4" in base.columns else base
    oth = group_packets(packets, rule)
    if oth.empty:
        return conn.reset_index(drop=True)
    out = pd.concat([conn, oth], ignore_index=True)
    for c in conn.columns:
        if c in oth.columns:
            continue
        if pd.api.types.is_numeric_dtype(conn[c]):
            out[c] = out[c].fillna(0)
    return out
