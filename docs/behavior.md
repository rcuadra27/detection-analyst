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
for day in Monday Tuesday Wednesday Thursday Friday; do
  python -m src.ingest.cic_eval --day $day --pcap none \
      --csv-dir "data/raw/cic2017/csv/TrafficLabelling " \
      --out data/processed/cic2017/$(echo $day | tr A-Z a-z) --behavior
done
```

## Results, v1

| | Monday | Friday | Verdict |
|---|---|---|---|
| `scan_vertical` false events | 0 | 1 | B1 usable |
| `scan_horizontal` false events | 3 | 2 | **B1 fail** |
| `flood` false events | 1 | 1 | B1 usable |
| PortScan coverage | | **99.8%** (3 events, 998-999 ports a minute, probe share 0.995-1.0) | **B2 pass** |
| DDoS coverage | | 73.2% (1 event, peak 5,085 a minute, 15 minutes) | **B2 fail** |
| Bot coverage | | 0% | expected: needs beaconing |

For comparison, the per-flow model on the same Friday at 0.85: PortScan 0.8%,
DDoS 0.1%, with 74% of innocent flows flagged.

Predictions: right on PortScan, the Monday flood count and Bot; wrong on Monday
scans (3 horizontal events) and DDoS (73%, predicted ≥ 90%).

Causes, checked against the data:

- **Horizontal false events are web browsing.** Office PCs reached 50-59 web
  servers (443 or 80) in a minute, normal for a page that pulls from CDNs and
  ad networks. v1 counted every reset (Argus RST, which merges Zeek's REJ with
  RSTO/RSTR) as a probe, and browsers often close HTTPS sessions with a reset
  after exchanging data: 53-77% of those sessions counted as probes.
- **The DDoS gap is the baseline absorbing the attack.** Per minute, the DDoS
  ran at 1,355, then 4,831-5,085 for 19 minutes, then 1,069: never below the
  1,000 floor (so the guess of "dips below the floor" was wrong). v1's baseline
  was the median of the previous 30 minutes, flood included; after 15 flood
  minutes the median became the flood itself and the 10× condition stopped
  holding. 15 of 21 minutes covered.
- The other false events are borderline: `scan_vertical-4` is the victim's
  backscatter during the scan (394 unanswered ports from 192.168.10.50 back to
  the scanner); both flood false events are one client (192.168.10.14) sending
  ~1,100 DNS queries in a minute to the domain controller, labelled benign.

## v2 (frozen before any held-out day is run)

Two changes, each tied to a cause above; thresholds unchanged.

1. **Probe:** no reply (REQ, INT), or at most two packets each way. A reset
   connection with more traffic is a normal close.
2. **Flood baseline:** the median of the last 30 minutes **not in alarm**; while
   a service is in alarm its baseline is frozen.

Monday and Friday shaped v2, so re-running them is a regression check, not a
test. The tests are days v2 has not seen:

| Day | Judged | Rule |
|---|---|---|
| Tuesday (FTP and SSH brute force) | B1 | ≤ 1 false event per detector |
| Wednesday (DoS Hulk, GoldenEye, slowloris, slowhttptest; Heartbleed) | B1; B2 for **DoS Hulk** and **DoS GoldenEye** | ≥ 90% of their flows in a true flood event |
| Thursday (web attacks; infiltration) | B1 | ≤ 1 false event per detector |

Predictions for v2:

- Monday and Friday: horizontal false events drop to 0-1; DDoS coverage ≥ 95%.
- Wednesday: Hulk and GoldenEye pass B2 (both are HTTP floods). Slowloris and
  slowhttptest are **not** caught: they hold a few hundred slow connections
  open, far under 1,000 a minute. Recorded as a known blind spot (a detector
  for many long, nearly idle connections to one server would be its own rule).
  Heartbleed is a single connection: not caught.
- Tuesday: brute force not detected (not these detectors' job; a brute-force
  detector is next); flood may fire on SSH-Patator if it opens ≥ 1,000
  sessions a minute; if it does, that counts as a true event.
- Thursday: web attacks not detected (single HTTP sessions); B1 usable.
