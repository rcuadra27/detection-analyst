# Model v2: a per-flow model trained on more than one network

## Why

The production model was trained on UNSW-NB15 alone. On UNSW's own test split
it catches 92% of attacks with 6.8% false positives; on CIC-IDS2017, a
different lab, it flagged 15-74% of innocent flows on every day and ranked
CIC's attacks *below* normal traffic, so no threshold could separate them
(docs/cic_eval.md). Dropping TTL closed an evasion route but did not fix the
transfer. A model learns one lab's layout when one lab is all it sees.

The behavioral rules now cover the loud attacks on any network (scans, floods,
brute force: docs/behavior.md). The model's job is what the rules cannot see:
attacks inside one connection (exploits, web attacks, implants). It only earns
that job if it works on a network it was not trained on.

## Data

| Dataset | Source of features | Labels | Status |
|---|---|---|---|
| UNSW-NB15 | official training and testing CSVs (Argus) | `attack_cat` | have |
| CIC-IDS2017, five days | **our** pipeline: `data/processed/cic2017/<day>/features.csv.gz` | CIC's TrafficLabelling CSVs, attached by `cic_eval.attach_labels`, with the correction below | have |
| CTU-13 (botnet captures) | our pipeline, from pcaps | per-host labels published with the captures | to download |
| CIC-IDS2018 (a few days) | our pipeline, from pcaps | CIC's CSVs | to download; same lab family as 2017, so a weaker test of "new network" than CTU-13 |

**UNSW from its CSVs.** Phase A showed our Zeek features reproduce UNSW's
(docs/parity.md, rule v2), so the official CSVs stand in for running Zeek over
100 GB of UNSW pcaps. The two sources still differ slightly (the known parity
differences, Argus vs Zeek state mapping). A model could learn "which tool made
this row" instead of "is this an attack"; check 4 below measures that.

**Label correction (decided before any training).** CIC labels the internal
scan by the compromised host 192.168.10.8 on Thursday as BENIGN; CIC's own
description makes it the infiltration's second step (docs/behavior.md, v5
results). Flows from 192.168.10.8 to other 192.168.10.0/24 hosts between 14:33
and 15:45 lab time that are probes are relabelled `scan`. The same rule will
be applied to any corrected labels published for CIC-IDS2017.

## Common classes

| Common class | UNSW-NB15 | CIC-IDS2017 |
|---|---|---|
| normal | Normal | BENIGN |
| scan | Reconnaissance, Analysis | PortScan |
| dos | DoS | DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest |
| brute_force | | FTP-Patator, SSH-Patator |
| web_attack | | Web Attack - Brute Force, Web Attack - XSS, Web Attack - Sql Injection |
| botnet | Backdoor | Bot |
| exploit | Exploits, Shellcode, Worms | Infiltration, Heartbleed |
| other | Fuzzers, Generic | |

`other` is attack traffic with no counterpart elsewhere; it counts as an
attack for stage 1 and is left out of per-class comparisons.

## Features

The 42 UNSW features minus `sttl`, `dttl`, `ct_state_ttl` (the production
decision). The `ct_*` connection counts depend on how busy a network is; they
stay for the first cut and are the next ablation if a dataset-shift check
points at them. Per-host context (distinct ports, probe share) is left for
later: it overlaps with what the rules already count.

## Experiments, first cut (two datasets)

With two datasets there are only two true "new network" tests. Combining them
helps only if it transfers to a third, which needs CTU-13 or CIC-2018.

| # | Train | Test | Answers |
|---|---|---|---|
| E1 | UNSW | each CIC day | the known baseline, re-measured with the new metrics |
| E2 | CIC, all five days | UNSW testing CSV | does a model trained on CIC transfer the other way? |
| E3 | UNSW + four CIC days | the fifth CIC day, rotated | a combined model on a new *day* of a seen network (not a new network) |
| E4 | UNSW | UNSW testing CSV | in-lab reference |

Thresholds are fixed from training data only: the stage-1 score at which 0.1%
of a held-out 10% of the *training* normal flows is flagged. The test set
never picks the threshold.

## Metrics

- **Ranking (AUC)**, attack vs innocent, stage 1. It separates "the model
  cannot tell them apart" from "the threshold is in the wrong place". CIC's
  E1 result predicts an AUC below 0.5.
- **Innocent false-alarm rate** at the training threshold, judged by the
  bands of docs/cic_eval.md (≤ 0.1% usable, ≤ 1% degraded, above that fail).
- **Recall per common class** at the training threshold.
- **Dataset check:** a classifier trained to tell UNSW rows from CIC rows
  using the same features. Accuracy near 100% on *normal* rows means the
  features carry a strong "which network" signal that a combined model can
  learn instead of the attacks.

## Decision rules (frozen before any training run)

- **M1.** A model is worth carrying to the third-dataset test only if, on
  each new-network test it has (E1, E2): AUC ≥ 0.80, and false alarms are not
  "fail" (≤ 1%).
- **M2.** A model replaces production only after a test on a dataset none of
  its training data came from (CTU-13 or CIC-2018): AUC ≥ 0.80, false alarms
  ≤ 1%, and recall ≥ 50% on at least half of the common classes present in
  that dataset.
- **M3.** Nothing in this phase changes the rules or their thresholds.

## Predictions

- E1: AUC below 0.5 on most CIC days (attacks ranked below normal); false
  alarms fail.
- E2: also poor (AUC 0.5-0.7): CIC's attacks are dominated by floods and
  scans, UNSW's by exploits and generic traffic, so little overlaps.
- E3: high on DoS, scan and brute force (seen on other days), weak on classes
  that appear on one day only (web attacks, infiltration).
- Dataset check: well above 90% accuracy on normal rows.

If those hold, two labs are not enough, and the next step is CTU-13 (and a
CIC-2018 slice) before any production decision.

## Running it

```
python -m src.detect.model_v2 --csv-dir "data/raw/cic2017/csv/TrafficLabelling "
```

Defaults: UNSW CSVs in `data/raw/`, CIC features in `data/processed/cic2017/`,
output in `data/processed/model_v2/` (`report.md`, `results.json`, and the
training table cached as `table.pkl`; `--rebuild` rebuilds it). Each fit uses
the production pipeline without TTL; datasets carry equal total weight.

## Results, first cut (base features: the 42 minus TTL)

Training table: UNSW 257,673 rows; CIC 1,495,902 rows (200,000 normal per day
plus every attack row). The Thursday correction relabelled 67,670 flows to
`scan`.

| Exp | Test | AUC | False alarms (training threshold) | Recall | M1 |
|---|---|---|---|---|---|
| E4 | UNSW test | 0.981 | 0.116% (degraded) | botnet 93%, dos 84%, other 75%, exploit 71%, scan 62% | |
| E1 | Monday | n/a | 3.71% (fail) | | fail |
| E1 | Tuesday | **0.315** | 4.07% (fail) | brute_force 0% | fail |
| E1 | Wednesday | **0.182** | 4.10% (fail) | dos 0% | fail |
| E1 | Thursday | **0.243** | 4.23% (fail) | scan 0%, web_attack 0%, exploit 12% | fail |
| E1 | Friday | **0.137** | 6.89% (fail) | botnet 0%, dos 0%, scan 0% | fail |
| E2 | UNSW test | **0.683** | 5.25% (fail) | botnet 0%, dos 2%, exploit 1%, scan 1%, other 3% | fail |
| E3 | Monday | n/a | 0.015% (usable) | | |
| E3 | Tuesday | 0.999 | 0.001% | brute_force 56% | |
| E3 | Wednesday | 0.993 | 0.003% | dos 64% | |
| E3 | Thursday | 0.975 | 0.004% | scan 92%, web_attack 42%, exploit 12% | |
| E3 | Friday | 0.992 | 0.004% | scan 55%, dos 0%, botnet 0% | |

Dataset check (normal rows only): accuracy 99.99%, AUC 1.0. The features tell
UNSW from CIC perfectly.

Predictions: all held. E1 is not merely poor but inverted (AUC 0.14-0.31: the
UNSW model ranks CIC's attacks below its normal traffic); E2 transfers
poorly; both fail M1, so neither model goes to a third-dataset test.

**E3 is suspiciously good.** Tuesday is the only day with brute force, so the
Tuesday-held-out model never saw a brute-force flow, yet ranks them above
normal traffic at AUC 0.999. Two checks on that model:

- Benign flows from the attacker's address (172.16.0.1): only 2 exist, so the
  "does it recognise the attacker's address" test says nothing.
- Permutation importance on Tuesday: `ackdat` 0.163, `synack` 0.023, `state`
  0.012, `ct_srv_dst` 0.008, everything else below 0.001.

`ackdat` and `synack` are TCP handshake timings measured at the sensor: they
grow with the connecting machine's distance from it. In CIC, office machines
connect out (client near, small `ackdat`) and every attack connects in from
the attacker network through the firewall (client far, large `ackdat`). The
likely lesson E3 learned is "connections started from outside the firewall are
attacks": the same family as the TTL shortcut (where a machine sits), through
a different feature. On a real network it would flag every customer of a
public web server and miss attackers already inside.

## Ablation A: without the handshake timings (frozen before the run)

Variant `no_rtt` drops `tcprtt`, `synack` and `ackdat` as well as TTL, and
reruns everything on the cached table (`--variant no_rtt`). E3 runs record each
held-out model's top features.

- **Rule A1.** If E3's AUC falls below 0.90 on at least three of the four
  attack days, E3 was measuring network position and is not evidence about
  attack behaviour. If it stays at or above 0.90 on at least three, the
  handshake timings were not what carried it; the top features are then
  inspected for the next position signal (window sizes, `swin`/`dwin`, are the
  first suspects: they identify operating systems).
- **Rule A2.** M1 is re-judged for E1 and E2 under `no_rtt`; nothing goes to
  a third dataset unless M1 passes.

Predictions: E3 drops on Tuesday and Wednesday (connection-level attacks whose
flows otherwise look ordinary) and holds better on Thursday and Friday (scans,
whose probes differ in state and size anyway), so A1 is borderline; E1 rises
toward 0.5 but still fails M1.

```
caffeinate -i python -m src.detect.model_v2 --csv-dir "data/raw/cic2017/csv/TrafficLabelling " --variant no_rtt
```

## Results, ablation A (`no_rtt`)

| Exp | Test | AUC (base → no_rtt) | False alarms | Recall at the training threshold (base → no_rtt) |
|---|---|---|---|---|
| E4 | UNSW test | 0.981 → 0.981 | 0.068% | about unchanged |
| E1 | CIC days | 0.14-0.31 → **0.11-0.38** | 4.2-4.3% (fail) | 0% everywhere |
| E2 | UNSW test | 0.683 → 0.681 | 7.18% (fail) | 1-2% |
| E3 | Tuesday | 0.999 → **0.790** | 0.001% | brute_force 56% → **0%** |
| E3 | Wednesday | 0.993 → 0.992 | 0.003% | dos 64% → **0%** |
| E3 | Thursday | 0.975 → 0.967 | 0.002% | scan 92% → 73%, web_attack 42% → **0%** |
| E3 | Friday | 0.992 → 0.988 | 0.003% | scan 55% → 48%, dos 0% |

Held-out models' top features without the timings: `state` (0.11-0.24 on
Wednesday, Thursday, Friday) and the `ct_*` connection counts (`ct_src_ltm`,
`ct_dst_src_ltm`, `ct_srv_dst`, `ct_dst_sport_ltm`); on Tuesday `sinpkt`
first. Window sizes barely register.

**Rule A1: not met.** E3 stayed at or above 0.90 on three of the four attack
days, so by the frozen rule the handshake timings were not what carried E3,
except on Tuesday, where AUC fell from 0.999 to 0.790: the brute-force result
did rest on "connected from outside the firewall".

**Rule A2:** E1 and E2 fail M1 again. Nothing goes to a third dataset.

Predictions: right that Tuesday drops and Thursday and Friday hold; wrong on
Wednesday, whose AUC held.

**What AUC hid.** At the operating threshold (0.1% of training normal flows
flagged) recall collapsed: brute force, DoS and web attacks went to 0%. The
ranking separates attacks from the bulk of normal traffic, but not from the
top 0.1% of it, which is where a usable alert threshold has to sit. AUC
answers "can it rank"; the false-alarm budget decides whether that ranking is
any use.

**What the model learns without position.** Connection state and connection
counts: how many connections a source made, to how many services. That is the
pattern the behavioral rules already count directly, with thresholds that
travel across networks and explanations attached. On flow statistics alone the
model rediscovers the rules, less reliably.

## Conclusion of the first cut

1. Each lab encodes its layout in its labels (UNSW: TTL; CIC: connections from
   outside the firewall), and a per-flow model learns the layout first.
2. Mixing two labs teaches both layouts; the features identify the source
   network with 99.99% accuracy.
3. With position features removed, what is left are connection counts and
   states, which the rules already cover.
4. The model's intended job, attacks inside one connection (web attacks,
   exploits), needs **content** it does not have: 0% on web attacks without
   the timings. More flow-statistics data will not supply that.

The model stays as one weak signal. The next model work, when it happens, is
content features (Zeek's HTTP fields: methods, URIs, status codes, body
sizes) for web attacks, not more datasets of the same 42 features. CTU-13 is
deferred until there is a candidate that passes M1.
