"""Phase 5: the investigation agent.

The Phase 1-4 pipeline stops at advice such as "check whether the same pattern
appears toward other internal hosts". This package adds an agent that goes and
checks: it lists correlated events, pulls host activity, resolves ambiguous
hypotheses, and submits a schema-validated triage.

Design rule carried over from the pipeline: the classifier decides what the
attack is and mapping.py decides which ATT&CK techniques that implies. The
agent investigates and explains; it never selects techniques on its own, and
submit_triage enforces that in code.
"""
