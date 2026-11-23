# The detector: experiments, results and limits

Moved from the README without changes, so section numbers (§2 to §6b) are the ones
older commits and docs refer to. The agent's evaluation is in
[agent.md](agent.md).

## 2. Headline results

**Attack detection** (held-out UNSW-NB15 test set, 82,332 flows)

| metric | value |
|---|---|
| attacks caught | 93.1% |
| false-positive rate | 6.9% |
| operating threshold | 0.85 (tuned, see §5) |

**Attack-type classification**, end to end at threshold 0.85:

| class | precision | recall | F1 | support |
|---|---|---|---|---|
| generic | 1.00 | 0.97 | **0.98** | 18,871 |
| normal | 0.92 | 0.93 | **0.92** | 37,000 |
| exploitation | 0.79 | 0.64 | **0.71** | 11,510 |
| discovery | 0.63 | 0.48 | 0.55 | 10,235 |
| impact | 0.34 | 0.28 | 0.31 | 4,089 |
| persistence | 0.06 | 0.54 | 0.10 | 627 |

Overall accuracy 0.808, balanced accuracy 0.641.

**Explanation quality** — hybrid pipeline, 80 alerts sampled from the held-out
test split:

| metric | value |
|---|---|
| faithfulness | **1.000** |
| technique hit-rate | 0.475 |
| severity accuracy | 0.400 (0.900 within one level) |
| detector class accuracy | 0.562 |

Detector accuracy is reported separately from triage quality so that a poor
result can be attributed to the right component: when the classifier picks the
wrong attack type, the mapping supplies the wrong techniques regardless of how
well the generator reasons.

Faithfulness measures whether every ATT&CK technique the model cited was actually
present in its retrieved context. It held at 1.00 even on classes where retrieval
failed outright — the generator degraded by abstaining rather than by inventing
plausible-sounding techniques from parametric memory. For a grounded system this
is the correct failure mode, and it is the single result this project is most
confident in.

---

## 3. Evaluation design

Retrieval and generation are scored separately because they fail for different
reasons. If the correct technique never reaches the context window, the generator
never had a chance, and that is a retrieval problem rather than a reasoning one.

- **Retrieval:** hit@k, recall@k, MRR, with parent/sub-technique family matching
  (a retrieved T1110.003 counts for a mapped T1110).
- **Answer quality:** severity accuracy (exact and off-by-one, since severity is
  ordinal), technique hit-rate and Jaccard, and faithfulness.
- **Detection:** precision/recall/F1 per class, balanced accuracy, and a
  threshold sweep, all on the official held-out split. The models were never
  trained on it, but the 0.85 threshold was chosen from it (§5).

**Leakage controls.** Alert text is rendered from network features only; the
`attack_cat` label never appears in it. In the pcap pipeline, IP addresses are
redacted everywhere (UNSW's testbed uses fixed attacker/victim subnets, so a
leaked address would let the model learn the subnet instead of the attack), and
the ground-truth table's `Attack Name` / `Attack Reference` fields — which
contain strings like "Solaris rwalld Format String Vulnerability" — are retained
as evaluation metadata only, never rendered into input.

---

## 4. Experiments and findings

### 4.1 Semantic retrieval alone has a ceiling on telemetry

The first architecture embedded alert text and retrieved ATT&CK techniques by
cosine similarity. Measured on 80 balanced alerts:

| configuration | hit@10 | MRR |
|---|---|---|
| raw flow statistics | 0.208 | 0.134 |
| + feature-to-language enrichment | **0.319** | **0.246** |
| + probe/flood rebalance | 0.306 | 0.245 |

Enrichment translates numeric flow features into behavioral phrases ("very high
packet rate consistent with flooding") computed only from network features, never
naming an attack class. It produced a real improvement, and then the metric
plateaued.

The cause is modality mismatch. ATT&CK narrates adversary intent in prose; a flow
record reports packet counts. Diagnostics showed the correct technique typically
ranked beyond position 80, and that six different attack classes produced
byte-identical alert text once reduced to flow statistics.

### 4.2 Payload extraction did not close the gap (negative result)

Hypothesis: the missing signal lives in packet payloads, which the cleaned UNSW
CSVs discard. A full pipeline was built to test it — pcap streaming, flow
reassembly, payload-derived text extraction (HTTP request lines, DNS queries,
FTP/SMTP commands, shellcode byte-pattern signatures), and ground-truth labeling
by 5-tuple and time window against the 174,347-row GT table.

81,217 flows were extracted from two pcaps, yielding 3,413 labeled attack flows
across 8 classes. A controlled ablation on an identical 63-alert set:

| configuration | hit@1 | hit@10 | MRR |
|---|---|---|---|
| flow statistics only | 0.063 | 0.333 | 0.141 |
| + payload text | 0.016 | 0.365 | 0.100 |
| + payload, high-confidence descriptors only | 0.063 | 0.349 | 0.141 |

**No improvement.** Inspection of the extracted payloads explains why: UNSW's
traffic was generated by IXIA PerfectStorm, and for most classes the payloads are
randomized filler rather than real attack content. Only `shellcode` improved
(0.00 → 0.25), and only because genuine byte signatures were present — NOP sleds,
syscall instruction sequences, and the `WS2_32` Windows Sockets import string.

The pipeline works. The dataset does not contain the signal it was built to find.

### 4.3 Supervised classification, and what it revealed about the labels

Replacing semantic retrieval with a supervised classifier for the *detection*
step fixed the ceiling for several classes. It also exposed a labeling problem.

Fine-grained 10-class results included `analysis` at 0.04 precision / 0.04 recall
— statistically indistinguishable from guessing — with `backdoor` at 0.06
precision and `dos` at 0.21 recall. These classes overlap heavily with `exploits`
in UNSW's own labeling, a limitation documented in the literature.

Two weighting schemes were compared to test whether this was a tuning artifact:

| stage-2 weighting | persistence P/R | impact P/R | balanced acc |
|---|---|---|---|
| balanced | 0.06 / 0.54 | 0.34 / 0.28 | 0.641 |
| none | 0.04 / 0.12 | 0.50 / 0.09 | 0.574 |

Both poor. Combined with §4.1 and §4.2, three independent methods — semantic
retrieval, payload extraction, and supervised classification under two
configurations — converge on the same conclusion: **UNSW-NB15 flow features do not
encode enough signal to reliably separate backdoors, worms, and DoS.**

### 4.4 Replacing similarity search with deterministic mapping

Retrieval was removed from the decision path entirely. The classifier determines
the attack type; the hand-authored mapping determines which ATT&CK techniques
that implies; retrieval then fetches those specific techniques' documentation by
ID. Similarity search now only gathers grounding material — it no longer selects
the answer.

Measured on the same 80-alert protocol:

| metric | similarity retrieval | classifier + mapping |
|---|---|---|
| technique hit-rate | 0.175 | **0.475** |
| severity within one level | 0.738 | **0.900** |
| faithfulness | 1.000 | 1.000 |

### 4.5 A false-negative mode the harness caught

Evaluation surfaced a failure worth recording. UNSW's `generic` class was mapped
to T1600 (Weaken Encryption). That mapping is wrong: `generic` denotes
cryptanalytic attacks against block ciphers, while T1600 describes tampering with
cryptography on network devices. The mapping carried a LOW-confidence flag from
Phase 0 with the note "ATT&CK has no good match."

Given irrelevant context, the generator correctly declined to cite T1600 — but it
also returned `assessment=false_positive` and `severity=low`, classifying
confirmed attacks as benign. The detector had identified them at 1.00 precision /
0.97 recall.

The model had conflated "I cannot map this to a technique" with "this is not an
attack." Two fixes followed: `generic` now maps to an empty technique list with a
note that ATT&CK has no equivalent, and the generator prompt states explicitly
that absence of a mappable technique is not evidence of benign traffic.

Missing grounding silently becoming a missed detection is exactly the class of
failure that separates a measured system from a demonstrated one.

### 4.6 Reporting uncertainty rather than hiding it

Given classes the data cannot separate, two tempting responses were rejected:
forcing a confident single label (frequently wrong, teaches analysts to distrust
the tool) and merging confusable classes (destroys distinctions analysts act on —
a worm requires immediate containment, a backdoor requires implant hunting).

The output layer instead reports what the model actually believes:

- **confident** (top class ≥ 0.60) → the specific class and its techniques
- **split** → ranked candidates plus the concrete evidence that would
  disambiguate them
- **diffuse** → back off to the ATT&CK-tactic family

Example output for a genuinely ambiguous case:

```
ambiguous between: backdoor 44%, worms 39%
techniques to retrieve: T1133, T1505.003, T1071, T1210, T1570, T1021
analyst note: Critical distinction — check whether the same pattern appears
toward OTHER internal hosts. Fan-out indicates self-propagation (worm); a
single persistent channel indicates a backdoor.
```

Each disambiguation note derives from a measured confusion in the results above.

---

## 5. Operating point selection

Stage-1 threshold sweep on the held-out set:

| threshold | FP rate | attacks caught | attack precision |
|---|---|---|---|
| 0.30 | 0.376 | 0.996 | 0.764 |
| 0.50 | 0.265 | 0.984 | 0.820 |
| 0.70 | 0.155 | 0.963 | 0.884 |
| **0.85** | **0.069** | **0.931** | — |
| 0.90 | 0.044 | 0.911 | 0.962 |
| 0.95 | 0.018 | 0.879 | 0.984 |

UNSW's training split is ~68% attack while the test split is ~55%, so a default
0.5 cutoff over-predicts attacks. Tuning to 0.85 cut the false-positive rate from
26.5% to 6.9% and raised `normal` F1 from 0.84 to 0.92.

The threshold was picked from this sweep, which runs on the test split, so the
6.9% and 93.1% are slightly optimistic. The clean way is to choose it on a
validation slice of the training split and report the test split once.

---

## 6. Production gap

**This is a measured research prototype, not a deployable IDS.** The reasons are
quantified rather than hand-waved.

**Base rate.** The test set is 55% attack traffic; real networks run 0.1–1%. At
1M flows/day and a 1% attack rate, a 6.9% FPR produces ~68,000 false alarms
against ~9,300 true detections — roughly **12% alert precision**. This is the
base-rate problem that limits deployed NIDS (Axelsson, 2000), and no achievable
per-flow accuracy escapes it: even a 1% FPR yields only ~50% precision at a 1%
base rate.

**Mitigation implemented — correlation.** Attacks concentrate (a scan is hundreds
of flows from one source); false positives scatter. Aggregating detections into
(source, 5-minute window) events and gating on a minimum count exploits that
asymmetry. Simulated at a 1% base rate:

| false-positive distribution | noise gate | events/day | event precision |
|---|---|---|---|
| uniform | 5 | 59 | 1.000 |
| clustered (realistic) | 5 | 4,443 | 0.013 |
| clustered (realistic) | 20 | 56 | 1.000 |

The gate must sit above the noise floor of the environment's noisiest benign
hosts. Below it, clustered false positives pass straight through and correlation
performs *worse* than per-flow alerting. That calibration is environment-specific.

**Remaining gaps, unimplemented:** probability calibration (gradient-boosting
scores are not calibrated, yet thresholds and risk scores assume they are);
per-environment baselining and allowlisting; multi-signal correlation with
endpoint and authentication telemetry; an analyst feedback loop; and drift
monitoring with a retraining cadence. Evaluation is also same-distribution —
train and test come from one testbed, so generalization to a different network is
unmeasured.

---

## 6a. Scoring any pcap: Zeek feature parity (Phase A)

The detector was trained on UNSW's published features, built with Argus and
Bro. To score a pcap someone uploads, those 42 features are rebuilt from raw
packets with Zeek (`src/ingest/`). A wrong definition would shift the model's
inputs without any error, so parity was measured before building on it:
the same flows scored through UNSW's features and through Zeek's, with
ambiguous definitions calibrated on one capture and every result reported on
another. Thresholds were committed before each validation run. Full record:
[docs/parity.md](parity.md).

| run | validation capture | verdict | why |
|---|---|---|---|
| 1 | 22-1-2015 #20 | inconclusive | no attacks in the capture |
| 2 | 17-2-2015 #20 | fail (coverage) | Zeek merged repeated UDP bursts into long flows and oriented some by first packet; traffic present, start-time matching missed it |
| 3 | 17-2-2015 #15 | **pass** (rule v2) | decision agreement 99.6%, recall 0.864 -> 0.852, FPR 0.0019 -> 0.0014, detected attacks 93.4% -> 91.0% |

Found along the way:

- **Loss count.** UNSW counts the original packet with its resends, and counts
  a repeated SYN/FIN as one. Counting resends only raised FPR about 30x; the
  detector reads the feature mostly as zero or not zero.
- **Other protocols.** 12% of UNSW attacks use IP protocols other than
  TCP/UDP/ICMP (protocol sweeps), which Zeek makes no connections for. A
  second path logs those packets and groups them into flows (60 s idle, 60 s
  max, chosen by calibration).
- **Duplicated records.** UNSW writes some flows several times with different
  attack labels (one flow, four records: analysis, backdoor, exploits, dos).
- **Orientation.** On run 2, the detector flagged a flow one way (0.961) and
  scored the same traffic benign oriented the other way (0.003). Direction is
  something an attacker can influence; not yet measured systematically.

**Uploads (Phase A, part 2).** `src/ingest/score.py` turns any pcap into the
store the agent reads, and the web page accepts uploads up to 2 GB: on Cloud Run
the browser puts the file straight into a bucket and a Cloud Run Job scores it.
Each capture gets its own false-positive baseline for the noise check,
estimated without labels. Its first validation failed against the wrong
reference (attack hosts' normal-labelled traffic); against innocent hosts it
then passed a rule set beforehand on two fresh captures (true rate 0%, upper
bound 0.007%). UNSW cannot test the hard case, an innocent host the detector
keeps flagging. Details: [docs/upload.md](upload.md).

## 6b. A different network: CIC-IDS2017, and behavioral rules

Every Phase A capture came from the UNSW lab. On CIC-IDS2017 (another lab,
labelled) the same pipeline showed the per-flow model does not transfer:

| CIC day | Innocent flows flagged (model, 0.85) | Attacks flagged by the model | Behavioral rules |
|---|---|---|---|
| Monday (benign) | 55.5% (15.2% without TTL) | | 0-1 false events per rule |
| Friday | 74.1% | PortScan 0.8%, DDoS 0.1% | PortScan 99.8%, DDoS 100% |
| Wednesday (held out) | 56.8% | | DoS Hulk 99.8%, GoldenEye 65.4% (fail), Slowhttptest 85.3%, slowloris 0% |

- The UNSW model keyed on source TTL, an artifact of the lab's layout and an
  evasion route (attacks arriving at TTL 31 were caught 0.2% of the time).
  Production models now drop the TTL features: about 1 point of recall on UNSW.
- No threshold rescues the model on CIC: it ranks CIC's attacks below normal
  traffic. A threshold learned on Monday (0.999) silenced Friday's attacks.
- Behavioral rules (port scan, network sweep, flood) count patterns across a
  host's flows instead of scoring single flows; nothing is trained. Each version
  was frozen before a held-out day. Uploads now run both branches, and the alert
  rail and the agent's tools show rule events next to model events.

Details: [docs/cic_eval.md](cic_eval.md), [docs/behavior.md](behavior.md).
