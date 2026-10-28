"""Synthetic pcap with hand-set TTLs, windows, ISNs and timings.

Every value the ingest tests assert on is set explicitly here, so a test failure
means the extractor disagrees with a known answer, not with another estimate.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Padding, Raw, wrpcap

T0 = 1_400_000_000.0   # UNSW-era epoch seconds

CLIENT, SERVER, DNS_SRV, SCANNER, FTP_SRV = (
    "10.0.0.5", "10.0.0.80", "10.0.0.53", "10.0.0.9", "10.0.0.21")

HTTP_REQ = b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n"
HTTP_RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

# Expected values for the HTTP flow
HTTP = {
    "sport": 40000, "dport": 80,
    "c_isn": 1000, "s_isn": 5000,
    "c_ttl_first": 64, "c_ttl_last": 63, "s_ttl": 128,
    "c_win_first": 29200, "c_win_last": 1000, "s_win": 65535,
    "synack": 0.010, "ackdat": 0.005,
    # client packets at these offsets (s): SYN, ACK, GET, ACK, GET-retx, FIN, ACK
    "c_times": [0.000, 0.015, 0.020, 0.060, 0.070, 0.100, 0.120],
    # server packets: SYN/ACK, response, FIN/ACK
    "s_times": [0.010, 0.050, 0.110],
}


class _Side:
    def __init__(self, ip, port, isn, ttl, win):
        self.ip, self.port, self.seq, self.ttl, self.win = ip, port, isn, ttl, win


def _seg(src: _Side, dst: _Side, flags: str, t: float, payload: bytes = b"",
         seq: int | None = None, ack: int | None = None, ttl: int | None = None,
         win: int | None = None):
    p = (IP(src=src.ip, dst=dst.ip, ttl=ttl or src.ttl)
         / TCP(sport=src.port, dport=dst.port, flags=flags,
               seq=src.seq if seq is None else seq,
               ack=(dst.seq if ack is None else ack) if "A" in flags else 0,
               window=src.win if win is None else win))
    if payload:
        p = p / Raw(payload)
    p.time = T0 + t
    return p


def _http_flow():
    c = _Side(CLIENT, HTTP["sport"], HTTP["c_isn"], 64, 29200)
    s = _Side(SERVER, HTTP["dport"], HTTP["s_isn"], 128, 65535)
    ct, st = HTTP["c_times"], HTTP["s_times"]
    pk = []
    pk.append(_seg(c, s, "S", ct[0]));                      c.seq += 1
    pk.append(_seg(s, c, "SA", st[0]));                     s.seq += 1
    pk.append(_seg(c, s, "A", ct[1]))
    get_seq = c.seq
    pk.append(_seg(c, s, "PA", ct[2], HTTP_REQ));           c.seq += len(HTTP_REQ)
    pk.append(_seg(s, c, "PA", st[1], HTTP_RESP));          s.seq += len(HTTP_RESP)
    pk.append(_seg(c, s, "A", ct[3]))
    pk.append(_seg(c, s, "PA", ct[4], HTTP_REQ, seq=get_seq))   # retransmission
    pk.append(_seg(c, s, "FA", ct[5]));                     c.seq += 1
    pk.append(_seg(s, c, "FA", st[2]));                     s.seq += 1
    pk.append(_seg(c, s, "A", ct[6], ttl=HTTP["c_ttl_last"], win=HTTP["c_win_last"]))
    return pk


def _dns_oneway():
    p = (IP(src=CLIENT, dst=DNS_SRV, ttl=64) / UDP(sport=5353, dport=53)
         / DNS(rd=1, qd=DNSQR(qname="example.com")))
    p.time = T0 + 1.0
    return [p]


def _syn_noreply():
    p = IP(src=SCANNER, dst=SERVER, ttl=254) / TCP(sport=41000, dport=22, flags="S", seq=777,
                                                   window=1024)
    p.time = T0 + 2.0
    return [p]


def _ftp_login():
    c = _Side(CLIENT, 40100, 9000, 64, 29200)
    s = _Side(FTP_SRV, 21, 20000, 64, 65535)
    t = 3.0
    pk = []
    def add(src, dst, flags, payload=b""):
        nonlocal t
        pk.append(_seg(src, dst, flags, t, payload))
        src.seq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)
        t += 0.01
    add(c, s, "S"); add(s, c, "SA"); add(c, s, "A")
    add(s, c, "PA", b"220 ready\r\n");  add(c, s, "A")
    add(c, s, "PA", b"USER bob\r\n");   add(s, c, "PA", b"331 password\r\n")
    add(c, s, "PA", b"PASS secret\r\n"); add(s, c, "PA", b"230 logged in\r\n")
    add(c, s, "PA", b"QUIT\r\n");       add(s, c, "PA", b"221 bye\r\n")
    add(c, s, "FA"); add(s, c, "FA"); add(c, s, "A")
    return pk


LOSSY = {"sport": 40200, "dport": 9000, "src": "10.0.0.7", "seg": 100}


def _lossy_flow():
    """One data segment never reaches the sensor (a hole), one segment is
    retransmitted, and the client's FIN is sent twice.

    Expected client-side loss evidence: retrans 1, gaps 1, zero_dup 1.
    """
    c = _Side(LOSSY["src"], LOSSY["sport"], 30000, 64, 29200)
    s = _Side(SERVER, LOSSY["dport"], 40000, 64, 65535)
    n = LOSSY["seg"]
    data = b"x" * n
    t = 5.0
    pk = []
    def add(src, dst, flags, payload=b"", seq=None):
        nonlocal t
        pk.append(_seg(src, dst, flags, t, payload, seq=seq))
        t += 0.01
    add(c, s, "S"); c.seq += 1
    add(s, c, "SA"); s.seq += 1
    add(c, s, "A")
    first = c.seq
    add(c, s, "PA", data)                      # segment 1
    add(c, s, "PA", data, seq=first + 2 * n)   # segment 3: segment 2 never seen (gap)
    add(c, s, "PA", data, seq=first + 2 * n)   # segment 3 again (retransmission)
    c.seq = first + 3 * n
    fin = c.seq
    add(c, s, "FA", seq=fin)
    add(c, s, "FA", seq=fin)                   # FIN repeated
    c.seq += 1
    add(s, c, "FA"); s.seq += 1
    add(c, s, "A")
    return pk


# Non-TCP/UDP/ICMP traffic, grouped by the Python side (src/ingest/other.py)
OSPF = {"src": "10.0.0.1", "dst": "224.0.0.5", "times": [10.0, 20.0, 30.0], "len": 64}
SCTP = {"a": "175.45.176.1", "b": "149.171.126.17", "len": 76}
GARP = {"ip": "10.0.0.40"}


def _other_protocols():
    pk = []
    for t in OSPF["times"]:
        p = IP(src=OSPF["src"], dst=OSPF["dst"], proto=89, ttl=1) / Raw(b"o" * (OSPF["len"] - 20))
        p.time = T0 + t
        pk.append(p)
    for i, (src, dst, ttl) in enumerate([(SCTP["a"], SCTP["b"], 254), (SCTP["b"], SCTP["a"], 60),
                                         (SCTP["a"], SCTP["b"], 254), (SCTP["b"], SCTP["a"], 60)]):
        p = IP(src=src, dst=dst, proto=132, ttl=ttl) / Raw(b"s" * (SCTP["len"] - 20))
        p.time = T0 + 40.0 + 0.01 * i
        pk.append(p)
    # gratuitous ARP, padded to the 60-byte Ethernet minimum: 46-byte payload
    arp = (Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:28")
           / ARP(op=1, psrc=GARP["ip"], pdst=GARP["ip"], hwsrc="02:00:00:00:00:28")
           / Padding(b"\x00" * 18))
    arp.time = T0 + 50.0
    pk.append(arp)
    return pk


def _ether(p):
    if p.haslayer(Ether):
        return p
    e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / p
    e.time = p.time
    return e


def write_fixture(path: str | Path) -> Path:
    pkts = (_http_flow() + _dns_oneway() + _syn_noreply() + _ftp_login() + _lossy_flow()
            + _other_protocols())
    pkts = [_ether(p) for p in pkts]
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    return Path(path)
