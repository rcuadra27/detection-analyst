# CIC-IDS2017: does the UNSW-trained detector work on another network?

## Why

Phase A showed the pcap → Zeek → features pipeline reproduces UNSW's features,
so the detector scores a raw UNSW capture the way it scores the official CSVs.
Every capture tested came from the UNSW testbed, the network the model was
trained on, so that says nothing about other networks. UNSW-trained models are
known to lean on testbed artifacts, TTL above all: `sttl` and `ct_state_ttl`
separate attack from normal in UNSW largely because the attack machines sat a
different number of hops away.

CIC-IDS2017 is a different lab (Canadian Institute for Cybersecurity), with
different hosts, operating systems and attack tools, and has labels. Monday is
benign only; Tuesday to Friday carry attacks.

## What runs

`src/ingest/cic_eval.py` calls `score_pcap`, the same function the upload job
uses, so the numbers describe what a user of the app would get. The only new
part is attaching CIC's labels:

- **Labels**: `TrafficLabelling/*.csv` (CICFlowMeter flows with IPs and
  timestamps). `MachineLearningCVE` lacks both and cannot be matched.
- **Matching**: unordered endpoint pair + ports + protocol, and time.
  CICFlowMeter's direction is unreliable, and it cuts long connections into
  several rows; each row lands in the Zeek flow running at its start.
- **Clock**: CIC's timestamps are local time with no zone, day first, some on a
  12-hour clock without AM/PM and some without seconds. Hours before 08:00 are
  read as afternoon; minute-only rows get a 60 s tolerance. The offset to UTC is
  **measured**, not assumed: the whole-hour offset matching the most rows of a
  20,000-row sample wins.
- **Innocent hosts**: Zeek sources that originate no attack-labelled flow, as in
  the UNSW baseline validation (`baseline.truth_rates`).

## Decision rules (frozen before the first run)

| # | Rule | Threshold |
|---|---|---|
| 0 | Labels attached well enough to judge | ≥ 90% of CIC TCP/UDP rows matched, and the best offset matches ≥ 2× the runner-up. If this fails, rules 1-3 are not read: the matching is fixed first. |
| 1 | False alarms on innocent hosts (flow rate) | ≤ 0.1% **usable**; 0.1-1% **degraded**; > 1% **fail** |
| 2 | Noise baseline | rule v2 (docs/upload.md): true innocent rate ≤ estimated upper bound ≤ max(2 × true, true + 0.05 points) |
| 3 | Detection per attack | Reported per CIC label: rows matched, Zeek flows, share flagged, detected at all, classes it was flagged as. No single pass/fail. |

Rule 1 bands, not one cut: an earlier draft said "pass at ≤ 1%". On a busy
network 1% is thousands of false flags a day, so 1% is the point where the
detector stops being useful, not the point where it is good.

Also reported, without a rule: how many innocent hosts would reach an analyst
(pass the 5-flags-in-5-minutes gate and are not dismissed by the noise check),
and where innocent-host alarms concentrate (by source TTL, protocol, service,
host).

## Predictions (written before the first run)

1. **Monday fails or is degraded on rule 1.** CIC's Windows hosts send with TTL
   128 and its Linux hosts with 64; the model learned TTL values from the UNSW
   lab. Expect the alarms to concentrate on a few TTL values.
2. **Rule 2 passes on Monday.** The baseline is estimated from the capture
   itself, so it should track whatever the true rate is, high or low.
3. **Rule 3:** DoS (Hulk, GoldenEye, slowloris, slowhttptest), DDoS and port
   scan mostly detected (closest to UNSW's DoS and reconnaissance). FTP/SSH
   brute force and web attacks (brute force, XSS, SQL injection) mostly missed:
   UNSW has no brute-force class, and the web attacks look like ordinary HTTP
   sessions at the flow level. Botnet and infiltration: no prediction (few rows).

If prediction 1 holds, the next step is the TTL ablation: retrain without the
TTL features and re-run UNSW and CIC.

## Before the Monday run: TTL swap test (UNSW test split, production stage 1, threshold 0.85)

Every row's `sttl` set to one value, nothing else changed (`dttl` and
`ct_state_ttl` left as they were, so this understates the full TTL effect).

| sttl | normal flows flagged | attacks caught |
|---|---|---|
| real values | (normal sttl: 31 ×16,702, 254 ×15,049, 62 ×4,129) | 93.11% |
| 31 | 0.00% | **0.19%** |
| 62 | 13.67% | |
| 64 (Linux) | 10.22% | 90.92% |
| 128 (Windows) | 10.22% | 90.92% |
| 254 | 30.08% | 93.17% |

Reading:

- The model has not learned "254 = attack" (41% of normal test flows are 254).
  It has learned "31 = safe": at 31 it flags nothing, attacks included.
- 64 and 128 fall in the same bin (no split between them): about 10% of normal
  traffic flagged. Prediction 1 sharpens to **fail on Monday**.
- **Evasion:** TTL is chosen by the sender. An attacker whose packets arrive with
  TTL 31 is caught 0.2% of the time. This is a security flaw, not only a
  portability one.

## Ablation: retraining without TTL

`python -m src.detect.ablation --variant no_ttl` retrains both stages without
`sttl`, `dttl` and `ct_state_ttl`, saves them under
`data/processed/ablation/no_ttl/` (production models untouched), and writes
`compare.md` (UNSW test split, production vs ablated, including the swap test).
The ablated models take the same 42 columns, so the CIC days are re-scored from
the saved features without re-running Zeek:

```
python -m src.ingest.cic_eval --day Monday --pcap data/raw/cic2017/pcap/Monday-WorkingHours.pcap \
    --csv-dir "data/raw/cic2017/csv/TrafficLabelling " --out data/processed/cic2017/monday \
    --models data/processed/ablation/no_ttl
```

**Adoption rule (frozen before training):** `no_ttl` replaces production only if

1. on the UNSW test split at 0.85, attack recall drops by at most 5 points and the
   normal false-positive rate rises by at most 2 points, and
2. on CIC Monday, the innocent-host flag rate falls at least 5× or reaches
   "usable" (≤ 0.1%).

Removing TTL can expose the next shortcut (ports, byte counts, services specific
to the lab). The Monday report's breakdown by service and host is where that
would show.

## Order

Monday first (false alarms), then Friday, Wednesday, Tuesday, Thursday. One
pcap at a time; the raw Zeek logs are deleted after scoring unless
`--keep-zeek`, and `features.csv.gz` keeps every flow's 42 features and score
for later analysis without re-running Zeek.

```
caffeinate -i python -m src.ingest.cic_eval --day Monday \
    --pcap data/raw/cic2017/pcap/Monday-WorkingHours.pcap \
    --csv-dir "data/raw/cic2017/csv/TrafficLabelling " \
    --out data/processed/cic2017/monday
```

## Results

### Monday (benign only), threshold 0.85

| | production | no_ttl |
|---|---|---|
| Rule 0: labels attached | PASS: 99.9% matched, offset +3 h (margin 833×) | same |
| Rule 1: innocent flows flagged | **55.5%**: FAIL | **15.2%**: FAIL |
| Rule 2: baseline (true / upper) | FAIL | 15.2% / 8.5%: FAIL (too strict) |
| Innocent hosts an analyst would see | | 8 |

- Prediction 1 held in direction, not size: fail, but 55% instead of the ~10% the
  swap test suggested. With TTL removed it is 15%, spread across ordinary
  traffic (DNS 15%, SSL 14%, HTTP 10%, unidentified services 41%), mostly
  flagged as exploits (30k) or generic (18k). The busiest innocent host is the
  domain controller 192.168.10.3 (DNS, NetBIOS), 22% flagged.
- Prediction 2 failed: the baseline estimate is below the true rate, because no
  host is clean enough to anchor it. Wrong in the strict direction.
- **Ablation adoption rule: not met.** Part 1 (UNSW) passed: attack recall
  93.11% → 92.05%, normal flagged 6.85% → 6.77%, and the swap test is flat (92%
  of attacks caught at sttl 31, was 0.2%). Part 2 (CIC Monday ≥ 5× better or
  ≤ 0.1%) failed: 3.6×. Whether to adopt no_ttl as a security fix (it closes the
  TTL-31 evasion and is no worse anywhere measured) is a separate decision,
  recorded separately, not a pass.

### Monday score distribution, no_ttl

| threshold | Monday flagged |
|---|---|
| 0.85 | 15.228% |
| 0.95 | 6.151% |
| 0.99 | 1.135% |
| 0.995 | 0.445% |
| 0.999 | 0.029% |

Monday's flows score high (median 0.23, 90th percentile 0.91), but the top
0.1% is thin enough that a cutoff of 0.999 would be "usable" on Monday. That is
in-sample: the threshold was read off Monday, so Monday cannot judge it.

## Learning-period threshold (frozen before Friday is scored)

The idea production systems use: learn what normal looks like on this network
first, then alert only above it. Here, the threshold is set from a benign day of
the same network and tested on the other days.

- **Model and threshold:** no_ttl at **0.999**, chosen on Monday, frozen.
- **Rule L1 (false alarms, held out):** innocent-host flag rate on each attack
  day, at 0.999, judged by the rule 1 bands.
- **Rule L2 (detection):** per attack, reported as in rule 3. The approach is
  **viable** if, on Friday, DDoS and PortScan are each detected and at least
  half of their flows are flagged at 0.999; **not viable** otherwise.
- **Prediction:** L1 degraded rather than usable (other days carry traffic
  Monday did not); DDoS detected, PortScan weaker (scan probes are tiny flows
  that look like ordinary failed connections).

```
caffeinate -i python -m src.ingest.cic_eval --day Friday \
    --pcap data/raw/cic2017/pcap/Friday-WorkingHours.pcap \
    --csv-dir "data/raw/cic2017/csv/TrafficLabelling " --out data/processed/cic2017/friday
python -m src.ingest.cic_eval --day Friday --pcap data/raw/cic2017/pcap/Friday-WorkingHours.pcap \
    --csv-dir "data/raw/cic2017/csv/TrafficLabelling " --out data/processed/cic2017/friday \
    --models data/processed/ablation/no_ttl --threshold 0.999
```
