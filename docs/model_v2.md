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
