"""
Phase 2 — feature-to-language enrichment.

The diagnosis: rendered alerts were almost pure numbers, so the embedder matched
them to ATT&CK techniques that merely mention bytes/packets (T1132 Data Encoding,
T1030 Data Transfer Size Limits) instead of the actual attack behavior. Six
different attack classes even produced byte-identical alert text.

The fix: translate the numeric flow into honest behavioral phrases using
transparent thresholds, so the alert carries language an embedder can align with
ATT&CK's behavioral prose. This mirrors real SOC alerts, which carry a signature
description, not just raw counts.

INTEGRITY RULES (these are what make it not-cheating):
  - Descriptors are computed ONLY from network features. attack_cat / label are
    never read. The identical code would run on unlabeled production traffic.
  - Descriptors DESCRIBE THE FLOW; they never NAME the attack class. We emit
    "very high packet rate, no response" — never "denial of service". Naming the
    class would be leaking the label. Letting the model INFER the class from an
    honest flow description is exactly the reasoning we want to measure.

Thresholds below are deliberately coarse and are documented assumptions, not
tuned against labels. Reasonable people can adjust them; log the choice.
"""

from __future__ import annotations

import pandas as pd

# Well-known-service hints by port-less service string (UNSW gives the service name).
_SERVICE_HINT = {
    "http": "web/HTTP service",
    "dns": "DNS service",
    "ftp": "FTP file-transfer service",
    "ftp-data": "FTP data-transfer service",
    "ssh": "SSH remote-access service",
    "smtp": "SMTP mail service",
    "pop3": "POP3 mail service",
    "snmp": "SNMP management service",
    "ssl": "TLS/SSL encrypted service",
    "irc": "IRC service",
    "radius": "RADIUS auth service",
    "dhcp": "DHCP service",
}

# TCP/flow state hints (UNSW 'state' column).
_STATE_HINT = {
    "FIN": "connection completed and closed",
    "CON": "connection established",
    "INT": "no reply / connection not established",
    "REQ": "request sent, awaiting response",
    "RST": "connection reset",
    "CLO": "connection closed",
    "ECO": "echo/ICMP-style exchange",
    "URN": "urgent/abnormal flags",
    "no": "no state / stateless",
}


def _num(row, col):
    return row[col] if col in row and pd.notna(row[col]) else None


def behavioral_descriptors(row: pd.Series) -> list[str]:
    """Honest, feature-derived phrases. Describes the flow; never names the attack."""
    d: list[str] = []

    dur = _num(row, "dur")
    spkts = _num(row, "spkts"); dpkts = _num(row, "dpkts")
    sbytes = _num(row, "sbytes"); dbytes = _num(row, "dbytes")
    rate = _num(row, "rate")

    no_response = (dpkts is not None and int(dpkts or 0) == 0 and (spkts or 0) > 0)
    tiny = ((spkts or 0) <= 3) and (dur is None or float(dur or 0) <= 0.05)
    high_rate = rate is not None and rate >= 10000

    # --- rate / volume shape: the key split between flooding and probing ---
    if high_rate:
        d.append("very high packet rate consistent with flooding")
    elif rate is not None and rate >= 1000:
        d.append("elevated packet rate")

    # A no-response flow is flood-shaped ONLY at high rate; at low rate a brief
    # unanswered connection to a port is probe/enumeration-shaped, which is the
    # language that aligns with Discovery/Scanning techniques (T1046/T1595).
    if no_response:
        if high_rate:
            d.append("high volume of unanswered packets to the target")
        elif tiny:
            d.append("brief unanswered connection attempt to a port, probe-like")
        else:
            d.append("no response packets returned from destination")

    # --- fan-out across hosts/ports: enumeration / sweep signature ---
    ct_src_dport = _num(row, "ct_src_dport_ltm")
    ct_dst_sport = _num(row, "ct_dst_sport_ltm")
    ct_dst = _num(row, "ct_dst_ltm")
    ct_src = _num(row, "ct_src_ltm")
    ct_srv_dst = _num(row, "ct_srv_dst")
    if (ct_src_dport and int(ct_src_dport) >= 6) or (ct_dst_sport and int(ct_dst_sport) >= 6):
        d.append("repeated connection attempts across multiple ports, sweep-like enumeration")
    elif (ct_dst and int(ct_dst) >= 10) or (ct_src and int(ct_src) >= 10):
        d.append("many short-lived connections to hosts in the network")
    if ct_srv_dst and int(ct_srv_dst) >= 10:
        d.append("repeated probing of the same network service")

    # --- directionality (only when not already covered by no_response) ---
    if not no_response and spkts is not None and dpkts is not None and (dpkts or 0) > 0:
        ratio = (spkts or 0) / max(dpkts, 1)
        if ratio >= 5:
            d.append("highly asymmetric, mostly outbound traffic")

    # --- payload size shape ---
    if sbytes is not None and dbytes is not None:
        tot = int(sbytes or 0) + int(dbytes or 0)
        if tot <= 200:
            d.append("minimal payload transferred")
        elif tot >= 100000:
            d.append("large data transfer")

    # --- connection lifecycle ---
    state = _num(row, "state")
    key = str(state).upper() if state is not None else None
    if key in _STATE_HINT:
        d.append(_STATE_HINT[key])

    return d


def enrich_alert(base_line: str, row: pd.Series) -> str:
    """Append a behavioral summary to the terse flow line."""
    svc = _num(row, "service")
    svc_hint = _SERVICE_HINT.get(str(svc).lower()) if svc not in (None, "-", "") else None

    descriptors = behavioral_descriptors(row)
    if svc_hint:
        descriptors = [svc_hint] + descriptors
    if not descriptors:
        return base_line
    return f"{base_line} Behavior: {'; '.join(descriptors)}."


if __name__ == "__main__":
    # Show that byte-identical raw flows across classes still get honest,
    # non-label descriptors — and that a DoS-shaped flow reads differently
    # from a scan-shaped flow WITHOUT either being named.
    rows = {
        "flood-shaped": dict(proto="udp", service="-", state="INT", dur=0.0,
                             spkts=2, dpkts=0, sbytes=200, dbytes=0, rate=111111),
        "scan-shaped": dict(proto="tcp", service="-", state="INT", dur=0.0,
                            spkts=1, dpkts=0, sbytes=200, dbytes=0, rate=0,
                            ct_dst_ltm=15),
        "exfil-shaped": dict(proto="tcp", service="ssl", state="FIN", dur=30.0,
                             spkts=500, dpkts=20, sbytes=200000, dbytes=1500, rate=50),
    }
    for name, r in rows.items():
        s = pd.Series(r)
        print(f"[{name}]")
        print("  ", enrich_alert("TCP flow, state INT.", s))