"""
Phase 2.5 — payload feature extraction from raw pcap.

WHY: flow statistics alone cannot distinguish exploits/shellcode/backdoor from
benign traffic — the evidence lives in the packet payload, which the cleaned
UNSW CSVs discarded. This module recovers it.

WHAT IT PRODUCES: for each flow, natural-language text derived from the payload
(HTTP request lines, DNS queries, FTP/SMTP commands, TLS SNI, printable strings,
and byte-pattern indicators). That text is what finally gives the retriever real
semantic signal to align with ATT&CK's behavioral prose.

=========================== LEAK DISCIPLINE ===========================
UNSW's testbed uses FIXED addresses: attackers are 175.45.176.x, victims are
149.171.126.x. If IPs reach the alert text, the model learns the subnet instead
of the attack and every metric becomes meaningless.

  - The 5-tuple is used ONLY to key flows and join ground truth.
  - IPs and the GT 'Attack Name'/'Attack Reference' fields NEVER enter alert text.
  - Emitted text is derived exclusively from payload bytes + protocol behavior.
=======================================================================

Streams the pcap (does not load it into memory), so a multi-GB file is fine.

Usage:
    python -m src.pcap.extract --pcap data/raw/pcap/1.pcap --out data/processed/flows.jsonl --max-flows 50000
"""

from __future__ import annotations

import argparse
import json
import re
import string
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from pathlib import Path

MAX_PAYLOAD_PER_DIR = 2048   # bytes kept per direction; enough for headers+payload start
PRINTABLE = set(bytes(string.printable, "ascii"))

# ---------- payload signature patterns (byte-level, protocol-agnostic) ----------
_HTTP_REQ = re.compile(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT|PROPFIND)\s+(\S+)\s+HTTP/(\d\.\d)")
_HTTP_HDR_UA = re.compile(rb"User-Agent:\s*([^\r\n]{1,120})", re.I)
_HTTP_HDR_HOST = re.compile(rb"Host:\s*([^\r\n]{1,80})", re.I)
_HTTP_RESP = re.compile(rb"^HTTP/(\d\.\d)\s+(\d{3})")
_FTP_CMD = re.compile(rb"^(USER|PASS|RETR|STOR|CWD|LIST|SITE|MKD|DELE)\s+([^\r\n]{0,60})", re.I | re.M)
_SMTP_CMD = re.compile(rb"^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|VRFY|EXPN)\b", re.I | re.M)
_SSH_BANNER = re.compile(rb"^SSH-(\d\.\d)-([^\r\n]{0,40})")
_SQLI = re.compile(rb"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s|;\s*drop\s+table|xp_cmdshell)", re.I)
_TRAVERSAL = re.compile(rb"(\.\./|\.\.\\|%2e%2e%2f)", re.I)
_XSS = re.compile(rb"(<script|javascript:|onerror\s*=|alert\s*\()", re.I)
_CMDI = re.compile(rb"(/bin/sh|/bin/bash|cmd\.exe|powershell|;\s*cat\s+/etc/passwd|\|\s*nc\s)", re.I)
_FMTSTR = re.compile(rb"(%s%s%s|%n%n|%x%x%x)")
_NOPSLED = re.compile(rb"(\x90{12,}|\x41{40,})")          # x86 NOP sled / 'A' overflow padding
_SHELLCODE_HINT = re.compile(rb"(\xcd\x80|\x0f\x05|\xeb\xfe|\x31\xc0\x50)")  # int 0x80, syscall, jmp $, xor eax


@dataclass
class FlowRecord:
    flow_key: str                    # hashed 5-tuple, NOT the raw IPs
    proto: str
    dst_port: int
    src_port: int
    n_pkts_fwd: int = 0
    n_pkts_bwd: int = 0
    n_bytes_fwd: int = 0
    n_bytes_bwd: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    payload_text: list[str] = field(default_factory=list)   # derived NL descriptors
    # join keys kept OUT of alert text, used only for GT labeling
    _src_ip: str = ""
    _dst_ip: str = ""


_IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact_addresses(s: str) -> str:
    """Strip IP literals from derived text.

    UNSW's testbed uses fixed attacker (175.45.176.x) / victim (149.171.126.x)
    subnets, and they leak through payload content such as HTTP Host headers.
    Left in, the model would learn the subnet rather than the attack.
    """
    return _IP_IN_TEXT.sub("<ip>", s)


def _printable_strings(buf: bytes, min_len: int = 6, max_out: int = 6) -> list[str]:
    """Extract human-readable strings from payload bytes (like `strings`)."""
    out, cur = [], []
    for b in buf:
        if b in PRINTABLE and b not in (0, 10, 13):
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", "replace"))
            cur = []
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", "replace"))
    # prefer longer, more informative strings
    out.sort(key=len, reverse=True)
    return out[:max_out]


def derive_payload_text(fwd: bytes, bwd: bytes, dst_port: int) -> list[str]:
    """Turn raw payload bytes into natural-language descriptors.

    These describe OBSERVED CONTENT (an HTTP request, a NOP sled, a SQL keyword).
    They never name an attack class — the same rule as flow enrichment.
    """
    d: list[str] = []
    both = fwd + b"\n" + bwd

    # --- application protocol identification from content, not port ---
    m = _HTTP_REQ.search(fwd)
    if m:
        method = m.group(1).decode("ascii", "replace")
        uri = m.group(2).decode("ascii", "replace")[:120]
        d.append(f"HTTP {method} request for path {uri}")
        ua = _HTTP_HDR_UA.search(fwd)
        if ua:
            d.append(f"client user-agent {ua.group(1).decode('ascii','replace')[:80]}")
        host = _HTTP_HDR_HOST.search(fwd)
        if host:
            d.append(f"requested host header {host.group(1).decode('ascii','replace')[:60]}")
    r = _HTTP_RESP.search(bwd)
    if r:
        d.append(f"HTTP response status {r.group(2).decode('ascii','replace')}")

    ftp = _FTP_CMD.findall(fwd)
    if ftp:
        cmds = ", ".join(sorted({c.decode('ascii','replace').upper() for c, _ in ftp})[:6])
        d.append(f"FTP control commands issued: {cmds}")
    if _SMTP_CMD.search(fwd):
        d.append("SMTP mail transaction commands present")
    ssh = _SSH_BANNER.search(fwd) or _SSH_BANNER.search(bwd)
    if ssh:
        d.append(f"SSH protocol banner exchange, version {ssh.group(1).decode('ascii','replace')}")

    # --- content-level indicators (describe what's in the bytes) ---
    if _SQLI.search(both):
        d.append("SQL keywords and boolean tautology present in request parameters")
    if _TRAVERSAL.search(both):
        d.append("directory traversal sequences in requested path")
    if _XSS.search(both):
        d.append("inline script markup embedded in request content")
    if _CMDI.search(both):
        d.append("operating system shell command strings present in payload")
    if _FMTSTR.search(both):
        d.append("repeated format specifier sequences in payload")
    if _NOPSLED.search(both):
        d.append("long run of repeated no-operation bytes, buffer padding pattern")
    if _SHELLCODE_HINT.search(both):
        d.append("raw byte sequences corresponding to system call instructions")

    # --- fallback: readable strings so there is always some content signal ---
    if len(d) <= 1:
        strs = _printable_strings(fwd or bwd)
        if strs:
            joined = "; ".join(s[:60] for s in strs[:3])
            d.append(f"payload contains readable content: {joined}")
        elif fwd or bwd:
            d.append("payload is non-printable binary content")

    return [redact_addresses(x) for x in d]


def _flow_key(sip: str, sport: int, dip: str, dport: int, proto: str) -> tuple:
    """Bidirectional key: canonical ordering so both directions map together."""
    a, b = (sip, sport), (dip, dport)
    return (min(a, b), max(a, b), proto)


def extract_flows(pcap_path: str, max_flows: int = 50000, max_packets: int = 0):
    """Stream a pcap, group packets into flows, derive payload text. Yields FlowRecord."""
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP  # noqa

    flows: "OrderedDict[tuple, dict]" = OrderedDict()
    n = 0
    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            n += 1
            if max_packets and n > max_packets:
                break
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                continue
            l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            if l4 is None:
                continue
            proto = "tcp" if pkt.haslayer(TCP) else "udp"
            sip, dip = str(ip.src), str(ip.dst)
            sport, dport = int(l4.sport), int(l4.dport)
            key = _flow_key(sip, sport, dip, dport, proto)

            payload = bytes(l4.payload) if l4.payload else b""
            ts = float(pkt.time)

            f = flows.get(key)
            if f is None:
                if len(flows) >= max_flows:
                    # emit + evict oldest to bound memory
                    ok, of = flows.popitem(last=False)
                    yield _finalize(ok, of)
                f = flows[key] = {
                    "sip": sip, "dip": dip, "sport": sport, "dport": dport,
                    "proto": proto, "fwd": bytearray(), "bwd": bytearray(),
                    "npf": 0, "npb": 0, "nbf": 0, "nbb": 0,
                    "t0": ts, "t1": ts,
                }
            forward = (sip, sport) == (f["sip"], f["sport"])
            if forward:
                f["npf"] += 1; f["nbf"] += len(payload)
                if len(f["fwd"]) < MAX_PAYLOAD_PER_DIR:
                    f["fwd"] += payload[: MAX_PAYLOAD_PER_DIR - len(f["fwd"])]
            else:
                f["npb"] += 1; f["nbb"] += len(payload)
                if len(f["bwd"]) < MAX_PAYLOAD_PER_DIR:
                    f["bwd"] += payload[: MAX_PAYLOAD_PER_DIR - len(f["bwd"])]
            f["t1"] = ts

    for key, f in flows.items():
        yield _finalize(key, f)


def _finalize(key, f) -> FlowRecord:
    text = derive_payload_text(bytes(f["fwd"]), bytes(f["bwd"]), f["dport"])
    # flow_key is a stable hash — deliberately NOT the raw IPs
    fk = f"{abs(hash(key)) % (10**12):012d}"
    return FlowRecord(
        flow_key=fk, proto=f["proto"], dst_port=f["dport"], src_port=f["sport"],
        n_pkts_fwd=f["npf"], n_pkts_bwd=f["npb"],
        n_bytes_fwd=f["nbf"], n_bytes_bwd=f["nbb"],
        first_ts=f["t0"], last_ts=f["t1"], payload_text=text,
        _src_ip=f["sip"], _dst_ip=f["dip"],
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", default="data/processed/flows.jsonl")
    ap.add_argument("--max-flows", type=int, default=50000)
    ap.add_argument("--max-packets", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.out, "w") as fh:
        for rec in extract_flows(args.pcap, args.max_flows, args.max_packets):
            fh.write(json.dumps(asdict(rec)) + "\n")
            n += 1
            if n % 5000 == 0:
                print(f"  ... {n} flows")
    print(f"[extract] wrote {n} flows -> {args.out}")