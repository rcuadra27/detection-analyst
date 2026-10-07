---
name: disambiguate-hypotheses
description: Settle a split or low-confidence detection by checking host behavior. Use when the detector is torn between attack types, or when an event may be clustered false positives.
---

# Disambiguate hypotheses

Flow features alone cannot separate some attack classes (measured: backdoor 0.06 precision, analysis 0.04 F1). Host behavior often can. Your job is to run the check the detector's `analyst_note` asks for, apply the rule, and report what the evidence says.

## Procedure
1. Identify the pair or situation in `pairs.md` (load it with `load_skill("disambiguate-hypotheses", "pairs.md")`).
2. Call `get_host_activity` for the event's source host.
3. Run Step 0 in `pairs.md` first: is the flagged traffic more than detector noise? If not, follow the detector-noise rule and stop there.
4. Otherwise apply the decision rule for that pair, using the exact fields named.
5. State the rule outcome with its numbers, e.g. "61% of its flows in those windows were suspicious, it reached 33 internal hosts on port 445 in 4 minutes, so propagation, so worm".
6. If no rule fires, keep the split: report both hypotheses, cite techniques for both, and recommend the evidence that would settle it. Confidence at most 0.6.

## Principles
- A rule decides; you do not override it with intuition. If the evidence conflicts with the rule, report both and lower confidence.
- The two hypotheses often need different responses. Say which response the evidence supports.
- These thresholds are starting points, chosen from how the attacks behave and from the detector's measured false-positive rate. They are not tuned on any dataset. Say so if asked.
