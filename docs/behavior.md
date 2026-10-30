# Behavioral detectors

## Why

On CIC-IDS2017 the per-flow model ranked attacks below normal traffic
(docs/cic_eval.md). Its limit is structural, not only TTL: it judges one flow at
a time, and many attacks are invisible in one flow. A port-scan probe is one
refused connection; a DDoS request is one HTTP request. What gives them away is
the pattern across flows. `src/detect/behavior.py` counts that pattern directly,
per host and per minute. Nothing is trained, so no dataset's quirks leak in, and
every event carries the numbers that made it fire.

## Detectors and thresholds (frozen before any attack day was run)

| Detector | Measured per 60 s window | Fires when | MITRE |
|---|---|---|---|
| `scan_vertical` | one source → one target: distinct destination ports, share of probes | ≥ 100 ports and ≥ 50% probes | T1046 |
| `scan_horizontal` | one source → one port: distinct targets, share of probes | ≥ 50 targets and ≥ 50% probes | T1046 |
| `flood` | one target service (address, port, protocol): connections | ≥ 1,000 and ≥ 10× the service's own median over the previous 30 minutes; not in the first 5 minutes of a capture | T1498/T1499 |

A **probe** is a connection with no exchange: no reply, refused or reset
(Argus states REQ, RST, INT), or at most two packets each way.

Where the numbers come from:

- **100 ports / 50 targets in a minute:** a person or an application talks to a
  handful of ports on one server (a Windows client to a domain controller uses a
  few dozen at most). nmap's default scan is 1,000 ports. The 50% probe share
  keeps legitimate many-port traffic out (passive FTP data, RPC), because those
  connections carry data.
- **Flood, 10× its own normal:** relative to the service itself, so a busy DNS
  server at 1,200 a minute does not fire and a quiet web server hit by 3,000 a
  minute does. The 1,000 floor keeps small services' bursts out.

Known blind spots, by design: scans slower than 100 ports a minute; floods that
ramp up over more than 30 minutes; floods in the first 5 minutes of a capture;
ICMP and other protocols (TCP/UDP only). Per-host history (Phase C) is what
covers slow attacks.

## Rules

| # | Rule | Threshold |
|---|---|---|
| B0 | Labels attached | rule 0 of docs/cic_eval.md |
| B1 | False events: events containing no attack-labelled flow | ≤ 1 per detector per day: **usable**; more: **fail**. Judged on Monday and on Friday. |
| B2 | Coverage: share of an attack's flows inside a true event | ≥ 90%: **pass**. Judged for PortScan and DDoS on Friday. |

## Predictions (written before the first run)

- **Monday:** 0 scan events. Flood 0, possibly 1 (a burst at the domain
  controller's DNS or NetBIOS).
- **Friday PortScan:** detected by `scan_vertical`; coverage ≥ 90% but not 100%,
  because some nmap variants send almost nothing (list and ping scans) or run
  slower than the threshold.
- **Friday DDoS:** detected by `flood`; coverage ≥ 90%, minus the ramp-up
  minutes before it reaches 10× normal.
- **Bot:** not covered. It is periodic command-and-control traffic, a job for
  the beaconing detector (not built yet).

## How to run

Uses the features already saved by the CIC runs; no Zeek, seconds per day.

```
for day in Monday Friday; do
  python -m src.ingest.cic_eval --day $day --pcap none \
      --csv-dir "data/raw/cic2017/csv/TrafficLabelling " \
      --out data/processed/cic2017/$(echo $day | tr A-Z a-z) --behavior
done
```

## Results

(none yet)
