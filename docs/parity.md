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
