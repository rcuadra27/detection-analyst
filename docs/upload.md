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
