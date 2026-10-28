# Phase A: Zeek feature parity

## Why this comes before an upload button

The detector was trained on UNSW-NB15's published feature CSVs. Scoring a pcap
someone uploads means recomputing those 42 features from packets. If any feature
is computed differently, the model gets shifted inputs and nothing errors: it
just scores worse, quietly.

So the first question is measurable: **score the same flows through UNSW's
features and through Zeek-rebuilt features, and see whether the detector makes
the same decisions.**

## What was built

| file | role |
|---|---|
| `src/ingest/zeek/unsw_features.zeek` | Zeek script for the packet-level stats `conn.log` lacks: TTL, TCP window, initial sequence number, inter-packet timing, jitter, retransmissions, handshake timing, FTP commands |
| `src/ingest/zeek_run.py` | runs Zeek on a pcap (JSON logs) and loads the logs |
| `src/ingest/features.py` | builds the 42 features, with candidate definitions where UNSW's is ambiguous |
| `src/ingest/parity.py` | joins Zeek rows to UNSW records, calibrates, measures |
| `tests/pcap_fixtures.py` | synthetic pcap where every TTL, window, ISN and timing is set by hand |

### Where each feature comes from

UNSW built its features with Argus (packet statistics) and Bro, Zeek's
predecessor (service, HTTP, FTP). The Bro-side features should transfer almost
directly. The Argus-side ones are recomputed in the Zeek script.

| source | features |
|---|---|
| Zeek `conn.log` | dur, proto, service, spkts, dpkts, sbytes, dbytes |
| Zeek `http.log` | trans_depth, response_body_len, ct_flw_http_mthd |
| Zeek script | sttl, dttl, swin, dwin, stcpb, dtcpb, sinpkt, dinpkt, sjit, djit, sloss, dloss, synack, ackdat, is_ftp_login, ct_ftp_cmd |
| derived | rate, sload, dload, smean, dmean, tcprtt, is_sm_ips_ports |
| mapped | state (Zeek `conn_state` to Argus vocabulary; approximate) |
| window | the seven `ct_*_ltm` / `ct_srv_*` counts over the last 100 connections |
| lookup | ct_state_ttl, read off the training CSV as (state, sttl, dttl) -> value |

### Ambiguous definitions, settled by data

UNSW does not document some definitions precisely. Rather than guess, the
adapter computes each candidate and the experiment picks one:

| group | candidates |
|---|---|
| bytes | IP bytes, payload bytes |
| ttl | first packet, last packet |
| win | first, last, max |
| jit | std of inter-packet gaps, mean abs difference of consecutive gaps |
| service | Zeek only, Zeek with well-known-port fallback |
| body | sum or max of HTTP response bodies |
| mthd | GET/POST requests, any request |
| window | ordered by end or start time, counting the connection itself or not |
| loss | retransmissions; plus sequence holes; plus repeated SYN/FIN; all three; plus one per lossy flow; data resends plus one if anything was resent (added after run 1) |
| rate | (spkts+dpkts-1)/dur or (spkts+dpkts)/dur, checked against the training CSV |

The choice is made on **capture A** and every reported number comes from
**capture B**. Picking and scoring on the same capture would overstate parity.

## Decision rule (set before running on real data)

Measured on the validation capture, at the 0.85 operating threshold:

| outcome | condition | next step |
|---|---|---|
| **Pass** | decision agreement >= 95%, recall within 3 points and FPR within 2 points of the UNSW-feature scores, and >= 90% of attack flows covered | build the upload path on this model |
| **Partial** | agreement 85-95% | fix the top swap-one features, re-run on a third capture |
| **Fail** | agreement < 85%, or coverage < 90% on any major attack class | retrain on Zeek-derived features from UNSW pcaps (labels from the ground-truth join), report new recall/FPR |

A Fail is a useful result, not a dead end: a detector trained on features Zeek
produces natively is the one that can score uploads and, later, live traffic.

## Known gaps going in

- **Coverage.** Zeek builds connections for TCP, UDP and ICMP only. UNSW has
  many rows with other IP protocols, some carrying attacks. Those flows are
  invisible to this path; the coverage table measures how many.
- **Long flows.** Argus can split a long connection into several records; Zeek
  writes one. Expect duration and byte mismatches on long flows.
- **Duration stops at close.** Found while testing on the synthetic pcap: Zeek
  ends a TCP connection's duration at the second FIN and ignores the trailing
  ACK, although that ACK is counted in `spkts`. Argus likely measures to the
  last packet. On short flows this shifts `dur`, and with it `rate`, `sload`
  and `dload`, which all divide by duration.
- **State.** Argus and Zeek track TCP state differently. The report prints the
  state confusion table.
- **Window edges.** UNSW counted over its whole record stream; one pcap starts
  with an empty window.

## Running it

Needs Zeek, the UNSW pcaps, `UNSW-NB15_1..4.csv` (the full CSVs with the
5-tuple and timestamps, not only the training/testing split), and the trained
stage-1/stage-2 models.

```bash
python -m src.ingest.features --pcap data/raw/pcap/1.pcap --out data/processed/ingest/1
python -m src.ingest.features --pcap data/raw/pcap/2.pcap --out data/processed/ingest/2
python -m src.ingest.parity --calib data/processed/ingest/1 --valid data/processed/ingest/2 \
    --unsw-csv data/raw/UNSW-NB15_1.csv data/raw/UNSW-NB15_2.csv \
               data/raw/UNSW-NB15_3.csv data/raw/UNSW-NB15_4.csv \
    --out data/processed/parity
```

Output in `data/processed/parity/`: `parity_report.md`, `parity.json`,
`choice.json` (calibrated variants) and `ct_state_ttl_lookup.json`.

The pcaps must come from the period the CSVs cover; matching uses the 5-tuple
and start time.

## Run 1 results (calibrate on 1.pcap, validate on 10.pcap)

Recorded before any fix. Capture 10 becomes the dev capture from here on; the
post-fix validation runs on a capture not yet looked at.

**Verdict: Fail, on coverage.** The detector criteria pass on the flows Zeek
produced; the coverage criterion does not.

| criterion | threshold | result | |
|---|---|---|---|
| decision agreement | >= 95% | 98.3% | pass |
| recall change | within 3 points | 0.795 -> 0.780 | pass |
| FPR change | within 2 points | 0.0005 -> 0.0148 | pass |
| attack coverage | >= 90%, each major class | 81% overall; exploits 79%, dos 54%, backdoor 48%, fuzzers 87%, generic 86% | **fail** |

**A flaw in the rule.** It names retraining as the remedy for Fail, but no
model can score a flow Zeek never produces. Coverage and feature drift are
separate problems with separate fixes.

### Coverage

UNSW records with an IP protocol other than TCP, UDP or ICMP were 0% matched
(OSPF, ARP, SCTP, and a tail of rare protocols). Across the whole dataset:

| | normal | attack | attack share |
|---|---|---|---|
| TCP/UDP/ICMP | 2,204,099 | 281,934 | 11% |
| other protocols | 14,665 | 39,349 | 73% |

Not an artifact to drop. The normal side is ordinary ARP and OSPF; the attack
side looks like IP protocol sweeps (in capture 10, mobile, pim, sun-nd and
swipe have exactly 22 records each), which is a real reconnaissance technique.
These are 12% of all UNSW attacks. It also means `proto` partly encodes the
label in UNSW, so the detector likely leans on it more than it would on a real
network.

### False positives: one feature

FPR rose about 30x in relative terms. Swap-one puts most of it on `sloss`:
replacing only UNSW's value with Zeek's takes FPR from 0.0005 to 0.0099. No
other single feature moves it past 0.0011.

The cause was a definition error. UNSW defines sloss as packets "retransmitted
or dropped"; the first version counted retransmissions only. Zeek against UNSW
on capture 10 is a diagonal shifted by one wherever UNSW sees loss (Zeek 0 /
UNSW 1: 2,142 flows; 1/2: 2,191; 2/3: 2,943; 3/4: 1,886; 4/5: 484).

### Other observations

- The worst-agreeing features barely move the detector: `swin`/`dwin` agree
  28.5% and `ct_src_ltm` 3.7%, yet each swap keeps decision agreement >= 99.8%.
- `dur` agrees 69.8%, and `sload`/`dload`, which divide by it, 6-9%. This is the
  close-at-FIN difference found on the synthetic pcap.
- Calibration was decisive where it mattered: IP bytes 93.7% vs payload 0.8%,
  last-packet TTL 100% vs first 8.4%. The three window options tied at 23.6%,
  so none of them is UNSW's definition.
- Single swaps add up to less than the full Zeek effect, so features interact.

### Next

1. `sloss`/`dloss` candidates: retransmissions plus sequence holes, repeated
   SYN/FIN, or both. Calibrated on capture 1 like the others.
2. A flow path for other IP protocols, so coverage can be measured again.
3. One validation of both fixes on a capture not yet used, same thresholds.

### Dev check after the loss candidates (capture 10)

Calibration on capture 1 chose `retrans_plus1` (0.944 vs 0.25 for the rest),
and `sloss` agreement on capture 10 rose from 28.6% to 94.3%. FPR did not
move: 0.0148, and the `sloss` swap-one FPR stayed at exactly 0.0099.

- Sequence holes were not UNSW's "dropped": `retrans_gaps` equals `retrans`
  on every flow (no holes in the capture).
- The +1 is the original packet: UNSW counts it along with its resends.
- The 2,142 flows still at Zeek 0 / UNSW 1 all have a repeated SYN or FIN and
  no data resend. UNSW counts those as 1 however many repeats.
- The detector mostly reads `sloss` as zero or not zero. Fixing the ~9,500
  flows that were off by one above zero changed no decisions; the 2,142 flows
  wrong about zero carry the false positives.

Added `plus1_any`: data resends, plus one if anything was resent. Derived on
the dev capture; still chosen by calibration on capture 1 and validated on an
unused capture.

### Coverage: duplicates and the other-protocol path

Looking at UNSW's records for non-TCP/UDP/ICMP traffic turned up two things.

**UNSW writes some flows more than once, with different labels.** One `unas`
flow appears as four identical records (same features, same time) labelled
analysis, backdoor, exploits and dos. The run 1 join was one-to-one, so a single
Zeek flow covered one of the four and the other three counted as missed. That
undercounts coverage wherever UNSW duplicated, TCP and UDP included. Coverage
now counts a UNSW record as covered when any Zeek flow matches it, and the
report says how many records are duplicates and how many carry conflicting
labels. Feature comparison stays one-to-one.

**What those records look like.** Ports are always 0, so Argus keyed them by
(source, destination, protocol): CON when packets went both ways, INT when not.
ARP records carry the IPs from the ARP message, TTL 0 and 46 bytes (Ethernet
payload after padding). Packets are grouped over time: an OSPF record holds 6
hellos sent 10 s apart over 50 s.

**The path.** The Zeek script logs every non-TCP/UDP/ICMP packet and every ARP
message as one line (`other.log`). `src/ingest/other.py` groups them into
flows. The grouping rule is not documented, so four candidates (idle timeout
and maximum flow length of 60/60, 60/none, 30/30, 120/120 s) are scored on the
calibration capture by how many UNSW flows they reproduce with the right packet
count. Protocol names follow the IANA keywords Argus used, with unassigned
numbers as `unas`; the report prints UNSW's name next to this pipeline's, so
naming differences show up rather than hiding as missed flows.

Zeek 8 also writes these protocols to `conn.log` as `unknown_transport`; those
rows are dropped so nothing is counted twice.

### Dev check after the coverage path (capture 10)

| criterion | threshold | run 1 | now |
|---|---|---|---|
| decision agreement | >= 95% | 98.3% | 99.4% |
| recall change | within 3 points | -1.5 | -1.3 |
| FPR change | within 2 points | +1.4 | +0.2 |
| worst class coverage | >= 90% | 48% (backdoor) | 95% (dos) |

- Grouping rule: 60 s idle / 60 s max reproduced 85% of UNSW's other-protocol
  flows with the right packet count; every other rule was at 41% or below.
- Duplicates: 39,295 records are 38,290 distinct flows. 21 flows carry
  conflicting labels and account for 329 records (about 15 copies each).
- ARP coverage is 82% (102 of 125); the rest is unexplained.

These numbers come from the capture the fixes were built on, so they are not
the verdict. One more change before validation: other-protocol coverage now
requires the protocol name to agree. A protocol sweep hits one host with many
protocols in the same second, and the name table showed a `pim` flow paired
with a `mobile` record. Without the name check, sweep coverage could be
counted against the wrong records.

## Validation protocol (set before running)

- Calibrate on capture 1, validate on capture 20. Capture 20 has not been run
  through any part of the pipeline.
- Same decision rule as above, unchanged.
- No code change between seeing the capture 20 result and recording it. The
  result goes into this file and the README whichever way it lands.

## Validation run 1 (calibrate on capture 1, validate on capture 20): inconclusive

Every UNSW record in capture 20's time span is labelled normal: 0 attacks in
21,135 records. Attack recall and per-class attack coverage cannot be
measured, so under the protocol above this run is neither a pass nor a fail.
The capture was chosen without checking its attack content, which the UNSW CSV
alone would have shown. No code was changed after seeing the result.

What it does show, on traffic no fix was built from:

| | result |
|---|---|
| decision agreement | 100% on 20,540 benign flows |
| FPR, UNSW features -> Zeek features | 0.0 -> 0.0 |
| coverage (all normal) | 98.8%; distinct flows 99.4% |
| sloss / sbytes / spkts agreement | 99.4% / 99.6% / 99.8% |
| sttl, dttl, stcpb, dtcpb, state, service | 99.9-100% |

- The weak features are the same, at the same sizes, as on captures 1 and 10
  (window counts 1-41%, swin 28%, sjit 28%): consistent definitional
  differences, not noise.
- OSPF matched 0 of 64 records (100% on capture 10). Likely phase: Argus's
  60 s records began before this capture started, so their boundaries do not
  line up with flows that start at the capture's first packet.
- ARP 81% (120 of 148), as on the dev capture.

**Selection rule for the next validation capture (set before choosing):** it
must contain at least 500 attack records within its time span according to the
UNSW CSV, checked from the CSV only, before the capture goes through any part
of the pipeline. Thresholds and protocol are otherwise unchanged.

**Capture labels.** UNSW-NB15 has two capture days, and both pcap folders
number their files from 1. Captures 1 and 10 above are from the 17-2-2015
folder (timestamps 18 Feb 2015 UTC). The capture 20 of validation run 1 was
from the 22-1-2015 folder; on that day UNSW ran attacks only in the first two
hours, which is why it had none. Validation run 2 uses capture 20 from the
17-2-2015 folder.

## Validation run 2 (calibrate on capture 1, validate on 17-2-2015 capture 20): Fail on coverage

Selection rule: 13,008 attack records in the capture's span by the UNSW CSV
(>= 500 required). The timestamp check was not run beforehand; the count comes
from the CSV alone and does not depend on the pipeline.

| criterion | threshold | result | |
|---|---|---|---|
| decision agreement | >= 95% | 99.5% (40,747 flows, 2,157 attacks) | pass |
| recall change | within 3 points | 0.853 -> 0.846 | pass |
| FPR change | within 2 points | 0.0033 -> 0.0012 | pass |
| coverage, each major attack class | >= 90% | generic 6.7% (403 / 5,983); others 98.4-100% | **fail** |

The rule was written when coverage meant UNSW records, so the verdict uses
records. Distinct-flow coverage is 98.1%; it is reported, not substituted.

**The detector side holds on unseen traffic.** Decisions agree on 99.5% of
flows, recall is within a point, and FPR is lower with Zeek's features than
with UNSW's. The calibrated definitions carried over (sloss 99.9%, sbytes
95.6%, TTLs and ISNs 100%). No single remaining mismatch moves decision
agreement by more than 0.3 points. The model can score Zeek-built features
without retraining.

**The coverage failure is concentrated.** UDP coverage is 47.4% against 99.8%
for TCP. 59,138 records are 41,532 distinct flows; the uncovered records sit in
roughly 800 flows written about 16 times each, nearly all labelled generic.
Hypothesis (not yet checked): repeated UDP bursts on one 5-tuple. Zeek keeps a
UDP connection open until it has been idle for a minute, so the bursts merge
into one connection that starts at the first burst; Argus wrote a record per
burst, and later bursts find no Zeek connection with a matching start time. If
so, the traffic is seen but segmented differently, and the fix is UDP
segmentation, not retraining.

Any fix for this is built and checked on captures already used, and validated
on a new capture chosen by the same selection rule.
