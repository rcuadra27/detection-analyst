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

## Results, v2 (regression check on Monday and Friday)

| | Monday | Friday |
|---|---|---|
| `scan_vertical` | 0 false | 3 true, 1 false (backscatter) |
| `scan_horizontal` | **2 false** | 0 false (v1: 2) |
| `flood` | 1 false (busy DNS client) | 1 true, 1 false (busy DNS client) |
| PortScan coverage | | 99.8% |
| DDoS coverage | | **100%** (v1: 73.2%): one event, all 21 minutes |

Both v2 changes did what they were for on Friday. Monday kept two horizontal
false events (predicted 0-1): HTTPS from 192.168.10.25 (the Mac) to 62 and 76
web servers in a minute, 54-59% probes. Of that host's probe-like 443 flows in
its busy minutes, 2,050 of 2,333 were one SYN with no answer and no retry
(duration 0). The Mac reached 50 or more web servers in **87 different
minutes** of Monday: the 50-target threshold was wrong, not a first principle.
One-off unanswered SYNs to many servers cannot be told apart from a slow SYN
sweep by any probe definition; where the targets are can.

## v3 (frozen before any held-out day is run)

`scan_horizontal` only. Probe share still ≥ 50%, and either

- **≥ 50 targets inside one subnet** (/24 for IPv4, /64 for IPv6): a sweep of a
  network, the lateral-movement case, or
- **≥ 500 targets anywhere**: wide scanning by an infected host.

Browsing scatters across unrelated networks; a sweep walks one. Blind spot: a
sweep spread over many subnets at fewer than 500 targets a minute.

Held-out tests for v3 (none run yet):

| Day | Judged |
|---|---|
| Wednesday | B1 for all detectors; B2 for DoS Hulk and DoS GoldenEye (flood) |
| Thursday | B1 for all detectors. Infiltration: CIC describes the compromised host scanning the internal network afterwards; if those flows carry an attack label, a scan event covering them is reported (not judged: CIC labels only a few dozen rows as Infiltration) |
| Tuesday | B1 for all detectors |

Predictions for v3: Monday and Friday horizontal false events 0 (regression
check); Wednesday and Tuesday horizontal false events 0; the other v2
predictions stand.

## Results, v3

### Regression check (Monday, Friday)

| | Monday | Friday |
|---|---|---|
| `scan_vertical` | 0 false | 3 true, 1 false (backscatter) |
| `scan_horizontal` | **0 false** (v2: 2) | 0 false |
| `flood` | 1 false (busy DNS client) | 1 true, 1 false (busy DNS client) |
| Coverage | | PortScan 99.8%, DDoS 100%, Bot 0% |

As predicted: the subnet rule removed the Mac's false events and changed nothing
else.

### Held-out: Wednesday

| Rule | Result | Verdict |
|---|---|---|
| B1 `scan_vertical`, `scan_horizontal` | 0 and 0 false events | usable |
| B1 `flood` | 1 false event: 192.168.10.8 sent 1,911 DNS queries in a minute to the domain controller | usable |
| **B2 DoS Hulk** | **99.8%** (one event, 18 minutes, peak 10,374 a minute, normal 7.5) | **pass** |
| **B2 DoS GoldenEye** | **65.4%** (two events, peaks 1,226 and 1,461 a minute) | **fail** |

Reported, not judged: DoS Slowhttptest 85.3% (four one- or two-minute events at
2,400-4,300 connections); DoS slowloris 0%; Heartbleed 0% (one flow). The
per-flow model on the same day flagged 56.8% of innocent flows (rule 1 fail).

Predictions: right on Hulk, slowloris, Heartbleed and B1; wrong on GoldenEye
(predicted pass) and Slowhttptest (predicted missed; the tool opened thousands
of connections a minute in bursts).

- **GoldenEye:** it ran just above the 1,000-a-minute floor; minutes below the
  floor fell outside the events. The binding condition was the floor, not 10×
  normal (the server's normal was 0). A fix (keep a flood in alarm while it
  stays ≥ 10× normal, even under the floor) is not adopted: CIC has no other
  flood day to test it held-out. It needs another dataset (UNSW DoS, CIC-IDS2018).
- **Slowloris:** a few hundred long, nearly idle connections; no rate rule sees
  it. A separate detector (many long idle connections to one server) would.
- **The DNS burst** recurs every day (Monday and Friday 192.168.10.14,
  Wednesday 192.168.10.8, 1,000-1,900 queries a minute). CIC labels it benign;
  it is also what DNS tunneling and domain-generating malware look like. A
  separate, lower-severity "DNS burst" detector would describe it better than
  `flood`.

### Status

`scan_vertical`, `scan_horizontal` (v3) and `flood` are frozen at v3. Known
gaps: floods near the 1,000 floor, slow DoS, beaconing, brute force.

## In the app

Since this change the upload path runs both branches on the same Zeek flows:

```
pcap -> Zeek -> flows -+-> model: per-flow score and class -> model events (EV-...)
                       +-> rules: scan, sweep, flood (v3)  -> rule events (RULE-...)
```

- `score_pcap` runs the detectors after the model and writes `behavior.json`
  next to `flows.jsonl` (`meta.behavior` holds the version and the count; a
  detector failure is recorded there and never loses the model's output). The
  upload job copies the file to the bucket; stores scored earlier have no file
  and load with no rule events.
- The alert rail shows one card per host: its rule events first (name,
  counted evidence, minutes), then the model's windows and risk.
- The agent's tools: `list_events` lists rule events first, with
  `kind: "rule"`; `get_event` on a `RULE-...` ID returns the evidence,
  `how_to_read` (meaning and benign look-alikes), candidate techniques, a
  default severity and `model_view` (what the model said about the same flows);
  `get_host_activity` adds `all_outbound` (ports and probe share over every flow
  the host sent) and the host's rule events; `submit_triage` accepts the rule's
  techniques and still requires a reason to call a rule event a false positive.
- The `investigate-event` skill has a step for rule events, and the noise check
  (Step 0 in `pairs.md`) is limited to model events: a counted pattern is not a
  per-flow score.
- The simulated demo days have no rule events (their flows carry no
  connection state).

## v4: brute force (frozen before any run of it)

One new detector; the scan and flood rules are unchanged from v3.

| Detector | Measured per 60 s window | Fires when | MITRE |
|---|---|---|---|
| `brute_force` | one source → one target, one login service (ssh 22, ftp 21, telnet 23, rdp 3389, vnc 5900, pop3 110, imap 143): sessions that exchanged data | ≥ 20 sessions | T1110 |

- **Why 20 a minute:** a person logs in a few times an hour; a guessing tool
  connects, tries a password or a few, disconnects and repeats. 20 a minute is
  far above any person and far below a guessing tool's usual pace. CIC's
  published totals (a few thousand Patator rows per attack, each over about an
  hour) were known when this was written; the threshold was set from the
  principle, not fitted to them, and is several times below their average rate.
- **Sessions only:** probes (refused, unanswered) are the scan rules' job, so a
  scan of port 22 does not count here.
- **SMB (445) is excluded:** Windows clients open many SMB sessions to domain
  controllers and file servers.
- **Blind spots:** the rule cannot see whether logins failed (SSH is
  encrypted), so automation that logs in in a tight loop (backups,
  configuration tools, monitoring) is a benign look-alike; guessing slower than
  20 a minute; password spraying (one guess against many targets); brute force
  of web logins (HTTP, Thursday), which has no fixed port.

Rules for v4:

| Day | Judged |
|---|---|
| **Tuesday** (held out) | B2: ≥ 90% of **FTP-Patator** and of **SSH-Patator** flows inside a true `brute_force` event. B1 for every detector. |
| Monday, Wednesday, Friday | B1 for `brute_force` (it has never been run on them, so this is held out too); the other detectors as a regression check (expected identical to v3) |
| Thursday | B1 for every detector |

Predictions: Tuesday FTP-Patator and SSH-Patator both pass B2; 0 `brute_force`
false events on Monday, Wednesday, Friday and Thursday (the office's SSH and FTP
use is light: Monday has about 1,000 SSH and 460 FTP flows in the whole day).

## Results, v4

### Held-out: Tuesday (FTP-Patator, SSH-Patator)

| Rule | Result | Verdict |
|---|---|---|
| **B2 FTP-Patator** | **99.6%**: one event, 61 minutes, 3,977 sessions, peak 70 a minute, median session 9 s | **pass** |
| **B2 SSH-Patator** | **99.6%**: two events (58 and 3 minutes, split by a one-minute dip), peak 56 a minute, median session 12 s | **pass** |
| B1 `brute_force`, `scan_vertical`, `scan_horizontal` | 0 false events | usable |
| **B1 `flood`** | **2 false events**: 192.168.10.9 (1,227 DNS queries in a minute) and 192.168.10.8 (1,070) to the domain controller | **fail** |

The per-flow model (now without TTL) flagged 16.4% of Tuesday's innocent flows.

### `brute_force` on the other days (held out for this rule)

| Day | `brute_force` | Other detectors |
|---|---|---|
| Monday | 0 true, 0 false | identical to v3 |
| Wednesday | 0 true, 0 false | identical to v3 |
| Friday | **2 true**, 0 false | identical to v3 |

Predictions held, except that brute force fired twice on Friday, which has no
brute-force attack. The flows carry an attack label (PortScan), so they count as
true events, but the likely cause is nmap's service-version probing, which
connects to open FTP and SSH ports repeatedly and exchanges data: the event then
names the wrong technique (T1110 instead of T1046). Not confirmed against the
event list yet. Not changed: fixing it on the day that showed it would be
tuning on seen data. The agent can tell them apart (same source, same target, a
port-scan event in the same minutes); a later version could suppress
brute force when the same source scans the same target in those minutes.

## v5 (frozen before Thursday is run)

The DNS burst has now appeared on every CIC day (Monday, Wednesday, Friday once
each, Tuesday twice): one office machine sends 1,000-1,900 DNS queries in a
minute to the domain controller. CIC labels it benign. It is not a denial of
service, and the flood rule should not own it.

1. **`flood`** drops a DNS (port 53) window when one private client sent at
   least half of that minute's queries. Floods of a DNS server by many sources,
   or from a public address, still fire. (Those windows still freeze the
   service's baseline, as any window over 10× normal does.)
2. **`dns_burst`** (new, informational): one source sending at least 1,000 DNS
   queries in a minute. Low severity, technique T1071.004. Reported, not judged
   as an attack: on CIC it was always benign software, and it is also the shape
   of DNS tunneling and of malware generating random domains. B1 does not apply
   to it.

Thresholds of the other detectors are unchanged.

| Day | Judged |
|---|---|
| **Thursday** (held out) | B1 for `scan_vertical`, `scan_horizontal`, `flood`, `brute_force`. Reported: `dns_burst` events; coverage of web attacks (brute force, XSS, SQL injection) and infiltration, which no detector is built for |
| Monday, Tuesday, Wednesday, Friday | Regression check: `flood` false events go to 0 on all four; true events and coverage unchanged; the former DNS floods reappear as `dns_burst` events |

Predictions: Thursday B1 usable for all four judged detectors; web attacks
0-10% covered (single HTTP sessions; Thursday's web brute force may trip
nothing, since 20 logins a minute over HTTP is not a fixed-port login
service); infiltration not covered unless the infected host's internal scan
reaches the scan thresholds.
