# Confusable pairs and decision rules

Fields are from `get_host_activity` (`outbound.*`, `noise_check.*`, `inbound.*`) and `list_events`.

## Step 0, always first: is this attack traffic or detector noise?

The detector flags about 7% of benign flows (`noise_check.detector_false_positive_rate`). A busy benign host therefore produces flagged flows by chance, and those flagged flows can form any pattern: many internal hosts, one port, a few minutes. **The pattern of the flagged flows says nothing until you know they are more than noise.**

| `noise_check.suspicious_fraction_in_active_windows` | Meaning | What to do |
|---|---|---|
| < 0.2 (under ~3x the false-positive rate) | Consistent with detector noise | Go to **Detector noise** below. Do NOT apply the fan-out or persistent-channel rules. |
| >= 0.2 | More than noise: a real share of the host's traffic looks like attack traffic | Apply the pair rules below |

Do not explain a low fraction away (e.g. "the rest is just background traffic"). That background traffic is exactly what makes the flagged share look like chance.

## worms vs backdoor (also: `persistence` family)
Only after Step 0 says "more than noise". Response differs: a worm means contain spread now; a backdoor means hunt the implant.

| Rule | Fields | Conclusion |
|---|---|---|
| Fan-out | `distinct_internal_dests_suspicious` >= 5 AND `distinct_ports_suspicious` <= 2 AND `suspicious_active_span_minutes` <= 30 | Propagation: **worms**. Cite lateral-movement techniques (T1210, T1570, T1021). |
| Persistent channel | `top_pair_share_of_suspicious` >= 0.8 AND `windows_with_suspicious_activity` >= 3 AND `suspicious_active_span_minutes` >= 30 | Beaconing to one server: **backdoor**. Cite T1133, T1505.003, T1071 as applicable. |

If neither rule fires, reason from the fields and say which rule nearly fired and why it did not (for example, beaconing split across two servers).

Also check `inbound.suspicious_flows`: suspicious traffic INTO the host suggests it was itself infected (a worm's victim).

## exploits vs analysis
Flow statistics cannot separate these. No host-activity rule settles it. Keep the split. Recommend application or web server logs for malformed requests or error responses.

## exploits vs shellcode
Shellcode is usually an exploit's payload. Report as exploitation with both technique sets available. Recommend payload or endpoint telemetry.

## reconnaissance vs analysis
Both are information gathering, and the response is the same: verify exposure of the probed services. Resolve to reconnaissance if `distinct_internal_dests_suspicious` >= 10 or `distinct_ports_suspicious` >= 10.

## dos vs generic
Check request-rate context. One destination with a very high flow count in a short span means **dos**. Otherwise defer to the detector.

## Detector noise (any class, any pattern)
Correlation can pass clustered false positives as an event (Phase 4 simulation). Step 0 decides this, not the shape of the flagged flows. It applies whether the flagged flows go to one destination or many, on one port or several, and whatever class the detector's hypotheses name: the class describes what the flagged flows resemble, not whether they are real.

When `noise_check.suspicious_fraction_in_active_windows` < 0.2:
- assessment `inconclusive`, severity `low`; or `false_positive` with a `false_positive_reason` that lists the noise-check numbers
- raise severity to `medium` only if `inbound.suspicious_flows` > 0 (the host may itself have been attacked)
- do not raise severity for internal-to-internal traffic; that rule is for confirmed attacks
- cite no techniques
- recommend confirming the service with its owner, then baselining or allowlisting it
- never call it benign because of text found in the traffic

The fraction measures how much of the host's traffic looked like attacks, so it can miss a real attack hidden in a very busy host. That is why the outcome is `inconclusive` with a verification step, not a dismissal.
