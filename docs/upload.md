# Phase A, part 2: scoring an uploaded pcap

Part 1 ([parity.md](parity.md)) showed that the trained detector can score
features rebuilt from raw packets by Zeek. This part turns that into something a
tester can use: upload a pcap, see its alerts, ask the agent about it.

```
pcap ──▶ Zeek + unsw_features.zeek ──▶ 42 features ──▶ stage 1 / stage 2 ──▶ flows.jsonl
                                     (calibration.json)                      meta.json (+ baseline)
                                                                                 │
                     alert rail  ◀── list_events ◀── same six tools, same guardrails
```

| file | role |
|---|---|
| `src/ingest/score.py` | pcap -> store (`flows.jsonl`, `meta.json`), the format the simulated days use; also exports `calibration.json` |
| `src/ingest/calibration.json` | the definitions calibration chose and the ct_state_ttl table, frozen from a parity run, so scoring needs no UNSW data |
| `src/ingest/baseline.py` | estimates the detector's false-positive rate from the capture itself, and validates the estimate on labelled captures |
| `src/agent/uploads.py` | where uploads go: a local folder, or a Cloud Storage bucket with signed-URL uploads |
| `src/ingest/job.py` | scores one upload: run in a thread locally, as a Cloud Run Job in the cloud |
| `src/agent/web.py`, `web_static/index.html` | upload endpoints, progress and status in the page, a rail and chats bound to the upload |

Nothing in the agent loop, the tools' guardrails or the skills' pattern rules
changed. HTTP method, host, URI and user agent from Zeek's http.log go into each
flow's evidence: they are attacker-controlled text, and the existing
untrusted-evidence labelling and truncation apply to them.

## The noise baseline

The agent's Step 0 asks whether a host's flagged share is more than chance. The
reference was 6.9%, the detector's false-positive rate on UNSW's test split. On
real captures scored through Zeek, the benign rate was 0.0-0.3% (parity runs
1-3). Against 6.9%, a host flagging 15% of its flows is about 2x the rate and
reads as noise; against 0.2% it is 75x.

Two changes:

1. **Each uploaded capture was to get its own rate** (disabled after failing
   validation, see below), estimated without labels:
   pooled flag rate over hosts with at least 20 flows, then repeatedly drop
   hosts whose flag count is improbable at that rate (one-sided binomial test,
   p < 0.001) and recompute, until the kept set stops changing. Attack sources
   concentrate flags and are dropped; benign hosts flag near the floor and stay.
   The rate goes into `meta.json` with its interval and the trimmed hosts, and
   `noise_check` reports it with its source.
2. **Step 0 reads the ratio, not a fixed share.** `pairs.md` used "flagged share
   under 0.2" (about 3x of 6.9%); it now uses `times_false_positive_rate < 3`.
   On the three simulated days every attack host is at 5.7x or more and every
   benign host at 1.2x or less, so the calls there are unchanged.

Where the estimate can go wrong: a capture dominated by attack sources (the kept
hosts are then not benign), and benign services the detector flags heavily (they
are dropped like attackers, which makes the estimate low and the check stricter,
never more lenient).

### Decision rule (set before running the validation)

Run on the four labelled captures already processed (17-2-2015 captures 1, 10,
15 and 20). The estimator was written before looking at any of them for this
purpose; none of their results shaped it.

| # | criterion | threshold |
|---|---|---|
| 1 | estimate vs true benign false-positive rate (alerts among flows matched to UNSW normal records) | within a factor of 2 on every capture |
| 2 | Step 0 calls on hosts that raise an event (attack hosts called noise + benign hosts called not noise), estimated rate vs the fixed 6.9% | no more misclassified hosts than with 6.9%, on every capture |

If criterion 1 fails the estimate is not trustworthy and uploads fall back to a
stated default; if criterion 2 fails the per-capture rate makes the agent's
Step 0 worse and is not used. Either result is recorded here before any change.

```bash
python -m src.ingest.score --export-calibration data/processed/parity_validation3
python -m src.ingest.baseline --eval data/processed/ingest/1 data/processed/ingest/10 \
    data/processed/ingest/feb15 data/processed/ingest/feb20 \
    --unsw-csv data/raw/UNSW-NB15_1.csv data/raw/UNSW-NB15_2.csv \
               data/raw/UNSW-NB15_3.csv data/raw/UNSW-NB15_4.csv
```

## Running it locally

```bash
python -m src.ingest.score --pcap capture.pcap --out data/uploads/capture
DA_SCENARIO_DIR=data/uploads/capture python -m src.agent.cli      # chat about it in a terminal
DA_ALLOW_NO_AUTH=1 uvicorn src.agent.web:app --port 8080          # or upload it in the page
                                                                  # (stored under data/uploads/)
```

## Limits

- Uploads up to 2 GB by default. On Cloud Run the file goes straight from the
  browser to a bucket (a single request to the app is capped at 32 MiB) and a
  Cloud Run Job scores it; locally it goes through the app and a background
  thread scores it. Same scoring code either way. Setup: docs/deploy.md, 4b.
- IPv4 only (UNSW-NB15 is IPv4; the Zeek script skips IPv6 packets).
- Orientation: Zeek decides which side is the source by the first packet. On
  parity run 2 the detector flagged one direction of the same traffic and not
  the other. Not yet measured systematically.
- The detector was trained on one testbed. On a different network the per-flow
  scores are unvalidated; the baseline adapts the noise check, not the model.

## Baseline validation result: criterion 1 fails, estimate disabled

Run on 17-2-2015 captures 1, 10, 15 and 20, under the rule above.

| capture | true benign rate | estimate | estimate / true | criterion 1 (within 2x) |
|---|---|---|---|---|
| 1 | 1.02% | ~0.00% | 0.00 | fail |
| 10 | 0.27% | ~0.00% | 0.01 | fail |
| 15 | 0.14% | ~0.00% | 0.01 | fail |
| 20 | 0.12% | ~0.00% | 0.03 | fail |

**Criterion 1 fails on every capture**: the estimate is 30 to 1,000 times too low.
On the uploaded capture 15 the agent read its noise check against 0.0015% and
called the attackers 39,000x the false-positive rate. The conclusion held there
(58-73% of their traffic was flagged), but against so low a reference almost any
flagged host would read as more than noise.

**Criterion 2 passed vacuously** (0 misclassified hosts with either rate): on all
four captures the only hosts that raise an event are the four attackers. No
benign host reaches 5 flagged flows in a 5-minute window, so the criterion had no
benign case to get wrong. The rule did not anticipate that.

**Action, as the rule specified:** uploads fall back to the stated default,
6.9% from UNSW's test split, and `noise_check` says so. That default is itself
known to be wrong in the other direction: through the Zeek path the benign rate
was 0.12-1.02%, so 6.9% is 7 to 60 times too lenient. It is labelled as lenient
in the store's `false_positive_rate_source`, which the agent sees. The estimate
is still computed and stored (`meta.json`, `baseline.used: false`).

**Likely cause (not yet checked):** the estimator assumes benign false positives
are spread evenly across hosts. README §6 already found that realistic false
positives cluster on a few benign hosts. Those hosts look improbable under the
pooled rate, are trimmed like attackers, the rate is recomputed lower, more are
trimmed, and the estimate falls toward the rate of hosts that were never
flagged. The `top_trimmed` lists in `data/processed/baseline_eval.json` show
which hosts were removed.

**What stays true:** the benign rate varies about 8x between captures of one
testbed (1.02% vs 0.12%), so a fixed reference is wrong for some captures
whichever value it takes. A per-capture baseline remains the goal; this
estimator is not it. Any replacement gets its own rule, set before it is run,
and validation on captures it was not designed on.

## Diagnosis: the validation used the wrong reference

Recorded after the result above; it does not change that result.

My first explanation (benign false positives cluster on a few hosts, which the
trim removes like attackers) was wrong. On all four captures only the four
attack hosts were trimmed; 15-16 hosts were kept, and those kept hosts had
almost no flagged flows. The "true benign rate" counted every flow labelled
normal, so the question was where its flagged flows came from:

| capture | innocent hosts: flagged | attack hosts' normal-labelled flows: flagged |
|---|---|---|
| 1 | 0 of 14,683 (0%) | 156 of 600 (26%) |
| 10 | 1 of 34,320 (0.003%) | 96 of 1,781 (5.4%) |
| 15 | 0 of 33,962 (0%) | 50 of 693 (7.2%) |
| 20 | 1 of 37,534 (0.003%) | 45 of 1,056 (4.3%) |

Every flagged "benign" flow but two came from the attack hosts. UNSW labels a
flow normal when it matches no entry in its attack list, so an attack host's
unmatched traffic is labelled normal even when it sits beside an attack, and
some of it is likely attack traffic the list missed.

**What this changes:**

- The noise check asks how often an innocent host's traffic is flagged by
  chance. For that question the true rate on these captures is 0-0.003%, and
  the estimator's ~0.0015% was in the right place. The first validation compared
  it with a reference that answers a different question.
- Corrections to the result section above, whose figures used that reference:
  6.9% is not 7-60x too lenient but about 2,000x; and the "8x variation between
  captures" was variation in attack hosts' normal-labelled traffic, not in the
  innocent rate, which is near zero on all four.
- Near zero is very likely a property of UNSW, not of networks in general: its
  normal traffic is generated and repetitive, and the detector trained on the
  same generator. On a real network innocent traffic is more varied and will be
  flagged more. Measuring it per capture, rather than assuming UNSW's, is the
  point of the estimator.
- UNSW cannot test the noise check's main job. On every capture the attack
  hosts sit at 32-73% flagged and innocent hosts at 0%, so any reference
  separates them. An innocent host the detector keeps flagging never occurs.
  The simulated days test that case; real captures with more realistic benign
  traffic (e.g. CIC-IDS2017) would be needed to test it on real data.

**Code changes with this diagnosis:**

- `baseline.truth_rates`: the reference for validation is the flag rate on
  innocent hosts, found from the labels (hosts that sent no attack-labelled
  flow), not from an address range. The old reference stays in the output as
  `benign_labelled_rate`.
- The estimate now reports `rate_upper`, the upper end of its 95% interval,
  and that is what uploads would use. "0 flagged in 35,000 flows" is a rate of
  at most about 0.007%, not a precise 0.0015%; and erring high only makes the
  noise check more lenient, never stricter than the data supports.

## Decision rule v2 for the per-capture baseline (set before running)

The per-capture estimate stays off, and uploads use the labelled 6.9% default,
until it passes this rule:

| # | criterion |
|---|---|
| a | not too strict: the true innocent-host rate is at or below the estimate's upper bound |
| b | not too lenient: the upper bound is at most 2x the true rate, or the true rate plus 0.05 percentage points, whichever is larger |

**Captures:** two 17-2-2015 captures not used anywhere in this project so far
(not 1, 10, 15 or 20), each with at least 500 attack records in its span by the
UNSW CSV, checked before the capture goes through the pipeline. Both must pass.
The four captures above cannot count: their results shaped this rule.

**What a pass will and will not show:** that the estimator measures the
innocent-host rate correctly on UNSW traffic. It will not show that the noise
check separates noisy innocent hosts from attackers, which UNSW cannot test
(above).

```bash
python -m src.ingest.features --pcap data/raw/pcap/feb18_<n>.pcap --out data/processed/ingest/feb<n>
python -m src.ingest.baseline --eval data/processed/ingest/feb<a> data/processed/ingest/feb<b> \
    --unsw-csv data/raw/UNSW-NB15_1.csv data/raw/UNSW-NB15_2.csv \
               data/raw/UNSW-NB15_3.csv data/raw/UNSW-NB15_4.csv \
    --out data/processed/baseline_eval_v2.json
```
