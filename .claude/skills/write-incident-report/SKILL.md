---
name: write-incident-report
description: Write a shift summary or incident report across several events. Use when asked for a report, summary, or overview of the day's detections.
---

# Write an incident report

## Steps
1. Call `list_events` (limit 10).
2. Investigate each event you report on with the `investigate-event` skill. For more than 4 events, investigate the top 4 by risk and list the rest in one line each.
3. Write the report in this structure:

```
INCIDENT SUMMARY: <date or "scenario day">
Detector: <real models | STUB, synthetic scores> · Layout: simulated

Top findings
1. <host> <window> <conclusion> <severity>
   Evidence: <2 or 3 numbers from tools>
   Techniques: <cited IDs or "none mapped">
   Next step: <recommended action>
   Triage: <triage_id, pending analyst review>
...

Likely false positives
- <host>: <why, with numbers>

Open questions
- <what the data cannot answer and what would>
```

## Rules
- Every number comes from a tool result in this session.
- Group events from the same host into one finding.
- Say plainly what could not be determined. Do not smooth over splits.
- No actions have been taken. The report recommends; analysts act.
