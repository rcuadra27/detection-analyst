"""
Phase 4 — the production gap: correlation and risk scoring.

THE PROBLEM
Per-flow alerting is unusable at real base rates. At 6.9% FPR and a 1% attack
rate over 1M flows/day: ~9.3k true detections against ~68k false ones — roughly
12% precision, i.e. ~9 of every 10 alerts wrong. This is the base-rate problem
that limits deployed NIDS (Axelsson, 2000), and no achievable per-flow accuracy
fixes it: even a 1% FPR still yields ~50% precision at a 1% base rate.

THE FIX
Stop treating flows as alerts. Attacks CONCENTRATE — a scan is hundreds of flows
from one source, a worm fans out across destinations. False positives SCATTER —
isolated flows spread across unrelated hosts. Aggregating by (source, time
window) and scoring the aggregate exploits that asymmetry:

    attacker  -> many suspicious flows in one window  -> high aggregate score
    benign host -> a few scattered FPs across a day   -> rarely trips a window

This also matches how analysts work: one ticket saying "host X performed a port
sweep across 40 destinations in 3 minutes, 312 suspicious flows" is actionable.
312 separate tickets are not.

WHAT THIS MODULE PROVIDES
  - windowed aggregation of flow-level detections by source
  - evidence features an analyst cares about (fan-out, volume, consistency)
  - a risk score combining detector confidence with corroborating structure
  - a simulation showing the precision improvement at realistic base rates

Usage:
    python -m src.detect.aggregate --simulate
"""

from __future__ import annotations

import argparse
import math
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class FlowDetection:
    """One scored flow from the detector."""
    source: str
    dest: str
    dest_port: int
    timestamp: float
    attack_prob: float
    predicted_class: str = "unknown"


@dataclass
class CorrelatedEvent:
    source: str
    window_start: float
    window_end: float
    n_flows: int
    n_suspicious: int
    mean_prob: float
    max_prob: float
    distinct_dests: int
    distinct_ports: int
    class_counts: dict = field(default_factory=dict)
    risk_score: float = 0.0

    @property
    def dominant_class(self) -> str:
        if not self.class_counts:
            return "unknown"
        return max(self.class_counts.items(), key=lambda x: x[1])[0]

    def summary(self) -> str:
        return (f"{self.source}: {self.n_suspicious}/{self.n_flows} suspicious flows "
                f"across {self.distinct_dests} hosts / {self.distinct_ports} ports "
                f"-> {self.dominant_class} (risk {self.risk_score:.2f})")


def score_event(ev: CorrelatedEvent) -> float:
    """Combine detector confidence with corroborating structure.

    Rationale for each term:
      - mean_prob     : the detector's own confidence, averaged (not max, which
                        a single fluke flow could dominate)
      - volume        : log-scaled count of suspicious flows. One suspicious flow
                        is noise; 300 in a window is a campaign. Log-scaling
                        prevents a flood from saturating the score.
      - fan-out       : distinct destinations and ports. Scanning and worm
                        propagation both fan out; benign clients do not.
      - consistency   : fraction of the source's flows that are suspicious. A
                        host where 90% of traffic looks hostile is different from
                        one with 3 odd flows among 500 normal ones.
    """
    volume = math.log1p(ev.n_suspicious) / math.log1p(100)          # ~1.0 at 100 flows
    fanout = math.log1p(ev.distinct_dests + ev.distinct_ports) / math.log1p(50)
    consistency = ev.n_suspicious / max(ev.n_flows, 1)

    score = (0.40 * ev.mean_prob
             + 0.25 * min(volume, 1.0)
             + 0.20 * min(fanout, 1.0)
             + 0.15 * consistency)
    return round(min(score, 1.0), 4)


def correlate(detections: list[FlowDetection], window_seconds: float = 300.0,
              flow_threshold: float = 0.85, min_suspicious: int = 5
              ) -> list[CorrelatedEvent]:
    """Group flow detections into (source, time-window) events and score them.

    min_suspicious is the noise gate: a window needs this many suspicious flows
    before it becomes an event at all. This is what filters scattered FPs.
    """
    buckets: dict[tuple, list[FlowDetection]] = defaultdict(list)
    for d in detections:
        w = int(d.timestamp // window_seconds)
        buckets[(d.source, w)].append(d)

    events: list[CorrelatedEvent] = []
    for (src, w), flows in buckets.items():
        suspicious = [f for f in flows if f.attack_prob >= flow_threshold]
        if len(suspicious) < min_suspicious:
            continue
        classes: dict[str, int] = defaultdict(int)
        for f in suspicious:
            classes[f.predicted_class] += 1
        ev = CorrelatedEvent(
            source=src,
            window_start=w * window_seconds,
            window_end=(w + 1) * window_seconds,
            n_flows=len(flows),
            n_suspicious=len(suspicious),
            mean_prob=sum(f.attack_prob for f in suspicious) / len(suspicious),
            max_prob=max(f.attack_prob for f in suspicious),
            distinct_dests=len({f.dest for f in suspicious}),
            distinct_ports=len({f.dest_port for f in suspicious}),
            class_counts=dict(classes),
        )
        ev.risk_score = score_event(ev)
        events.append(ev)

    events.sort(key=lambda e: -e.risk_score)
    return events


def simulate(n_flows: int = 1_000_000, attack_rate: float = 0.01,
             fpr: float = 0.069, tpr: float = 0.931,
             n_benign_hosts: int = 5000, n_attackers: int = 20,
             window_seconds: float = 300.0, min_suspicious: int = 5,
             seed: int = 13):
    """Compare per-flow alerting vs correlated events at a realistic base rate."""
    import random
    rng = random.Random(seed)

    n_attack = int(n_flows * attack_rate)
    n_benign = n_flows - n_attack
    day = 86400.0

    # ---- per-flow view (the naive baseline) ----
    tp = int(n_attack * tpr)
    fp = int(n_benign * fpr)
    flow_precision = tp / (tp + fp) if (tp + fp) else 0.0

    print(f"\n=== Per-flow alerting (base rate {attack_rate:.1%}) ===")
    print(f"  flows/day            : {n_flows:,}")
    print(f"  true detections      : {tp:,}")
    print(f"  false alarms         : {fp:,}")
    print(f"  ALERT PRECISION      : {flow_precision:.3f}   "
          f"({(1-flow_precision)*100:.0f}% of alerts are wrong)")
    print(f"  alerts/analyst/day   : {tp + fp:,}")

    # ---- correlated view ----
    # Attack flows concentrate: a few sources, bursts inside windows.
    dets: list[FlowDetection] = []
    per_attacker = max(1, tp // n_attackers)
    for a in range(n_attackers):
        burst_start = rng.random() * day
        for i in range(per_attacker):
            dets.append(FlowDetection(
                source=f"attacker-{a}", dest=f"victim-{rng.randint(0, 40)}",
                dest_port=rng.choice([22, 80, 139, 443, 445, 3389, rng.randint(1, 65535)]),
                timestamp=burst_start + rng.random() * window_seconds * 2,
                attack_prob=rng.uniform(0.85, 0.99),
                predicted_class=rng.choice(["discovery", "exploitation", "impact"]),
            ))
    # False positives scatter uniformly across hosts and time.
    for _ in range(fp):
        dets.append(FlowDetection(
            source=f"host-{rng.randint(0, n_benign_hosts)}",
            dest=f"svc-{rng.randint(0, 200)}",
            dest_port=rng.choice([80, 443, 53, 123]),
            timestamp=rng.random() * day,
            attack_prob=rng.uniform(0.85, 0.95),
            predicted_class="unknown",
        ))

    events = correlate(dets, window_seconds=window_seconds,
                       flow_threshold=0.85, min_suspicious=min_suspicious)
    true_events = [e for e in events if e.source.startswith("attacker-")]
    false_events = [e for e in events if not e.source.startswith("attacker-")]
    ev_precision = len(true_events) / len(events) if events else 0.0
    attackers_found = len({e.source for e in true_events})

    print(f"\n=== Correlated events ({int(window_seconds)}s windows, "
          f"min {min_suspicious} suspicious flows) ===")
    print(f"  total events         : {len(events):,}")
    print(f"  true events          : {len(true_events):,}")
    print(f"  false events         : {len(false_events):,}")
    print(f"  EVENT PRECISION      : {ev_precision:.3f}")
    print(f"  attackers detected   : {attackers_found}/{n_attackers}")
    print(f"  alert volume cut     : {(tp+fp):,} -> {len(events):,} "
          f"({(1 - len(events)/max(tp+fp,1))*100:.1f}% reduction)")

    if events:
        print(f"\n  top events by risk score:")
        for e in events[:5]:
            print(f"    {e.summary()}")

    return {"flow_precision": flow_precision, "event_precision": ev_precision,
            "alerts_before": tp + fp, "alerts_after": len(events),
            "attackers_found": attackers_found}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--simulate", action="store_true")
    ap.add_argument("--attack-rate", type=float, default=0.01)
    ap.add_argument("--fpr", type=float, default=0.069)
    ap.add_argument("--min-suspicious", type=int, default=5)
    ap.add_argument("--window", type=float, default=300.0)
    args = ap.parse_args()

    if args.simulate:
        simulate(attack_rate=args.attack_rate, fpr=args.fpr,
                 min_suspicious=args.min_suspicious, window_seconds=args.window)