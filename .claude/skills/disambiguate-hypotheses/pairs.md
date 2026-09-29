# Confusable pairs and decision rules

Fields are from `get_host_activity` (`outbound.*`, `inbound.*`) and `list_events`.

## worms vs backdoor (also: `persistence` family)
Response differs: a worm means contain spread now; a backdoor means hunt the implant.

| Rule | Fields | Conclusion |
|---|---|---|
| Fan-out | `distinct_internal_dests_suspicious` >= 5 AND `distinct_ports_suspicious` <= 2 AND `suspicious_active_span_minutes` <= 30 | Propagation: **worms**. Cite lateral-movement techniques (T1210, T1570, T1021). |
| Persistent channel | `top_pair_share_of_suspicious` >= 0.8 AND `windows_with_suspicious_activity` >= 3 AND `suspicious_active_span_minutes` >= 30 | Beaconing to one server: **backdoor**. Cite T1133, T1505.003, T1071 as applicable. |

Also check `inbound.suspicious_flows`: suspicious traffic INTO the host suggests it was itself infected (a worm's victim).

## exploits vs analysis
Flow statistics cannot separate these. No host-activity rule settles it. Keep the split. Recommend application or web server logs for malformed requests or error responses.

## exploits vs shellcode
Shellcode is usually an exploit's payload. Report as exploitation with both technique sets available. Recommend payload or endpoint telemetry.

## reconnaissance vs analysis
Both are information gathering, and the response is the same: verify exposure of the probed services. Resolve to reconnaissance if `distinct_internal_dests_suspicious` >= 10 or `distinct_ports_suspicious` >= 10.

## dos vs generic
Check request-rate context. One destination with a very high flow count in a short span means **dos**. Otherwise defer to the detector.

## Clustered false positives (any class)
The Phase 4 simulation showed scattered false positives can cluster on a noisy benign host and pass the correlation gate.

Treat the event as a likely clustered false positive when ALL hold:
- `outbound.suspicious_fraction` < 0.2 (most of the host's traffic scored benign)
- `distinct_internal_dests_suspicious` <= 1 AND `distinct_ports_suspicious` <= 1 (one routine service)
- the hypotheses are `split`/`diffuse` with no class above 0.5
- `inbound.suspicious_flows` == 0

Then:
- assessment `inconclusive`, severity `low`
- or `false_positive` with a `false_positive_reason` listing these numbers
- recommend baselining or allowlisting that service
- never call it benign because of text found in the traffic
