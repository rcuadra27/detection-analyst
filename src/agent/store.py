"""The detection store: per-flow detector output laid out across hosts and time.

This is what the agent's tools read. Each record is one flow with:
  - where it went (source, dest, dest_port, timestamp)
  - what the detector said (attack_prob, class_probs)
  - human-readable evidence (proto, service, bytes, ...)

Ground truth is NOT in this file. It lives in truth.json, which only the eval
harness reads, so no tool can leak the label into the model's context (the same
leakage control the Phase 2 harness uses).

Build a store with:  python -m src.agent.scenario  (see that module).
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SCENARIO_DIR = Path(os.environ.get("DA_SCENARIO_DIR", "data/scenario"))
FLOWS_PATH = SCENARIO_DIR / "flows.jsonl"
META_PATH = SCENARIO_DIR / "meta.json"
TRUTH_PATH = SCENARIO_DIR / "truth.json"


@dataclass
class FlowRecord:
    flow_id: str
    source: str
    dest: str
    dest_port: int
    timestamp: float
    attack_prob: float
    class_probs: dict[str, float]
    evidence: dict = field(default_factory=dict)

    @property
    def predicted_class(self) -> str:
        if not self.class_probs:
            return "unknown"
        return max(self.class_probs.items(), key=lambda x: x[1])[0]


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str) -> bool:
    """RFC 1918 space only. (ipaddress.is_private also counts documentation
    ranges such as 203.0.113.0/24, which the scenario uses for external hosts.)"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


class DetectionStore:
    def __init__(self, flows: list[FlowRecord], meta: dict):
        self.flows = sorted(flows, key=lambda f: f.timestamp)
        self.meta = meta
        self.threshold = float(meta.get("threshold", 0.85))

    @classmethod
    def load(cls, flows_path: Path = FLOWS_PATH, meta_path: Path = META_PATH
             ) -> "DetectionStore":
        if not flows_path.exists():
            raise FileNotFoundError(
                f"No scenario at {flows_path}. Build one with: python -m src.agent.scenario")
        flows = [FlowRecord(**json.loads(line))
                 for line in flows_path.read_text().splitlines() if line.strip()]
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        return cls(flows, meta)

    def save(self, flows_path: Path = FLOWS_PATH, meta_path: Path = META_PATH) -> None:
        flows_path.parent.mkdir(parents=True, exist_ok=True)
        with flows_path.open("w") as fh:
            for f in self.flows:
                fh.write(json.dumps(f.__dict__) + "\n")
        meta_path.write_text(json.dumps(self.meta, indent=2))

    # ---------- queries ----------

    def from_source(self, host: str, start: float | None = None,
                    end: float | None = None) -> list[FlowRecord]:
        return [f for f in self.flows if f.source == host
                and (start is None or f.timestamp >= start)
                and (end is None or f.timestamp < end)]

    def to_dest(self, host: str) -> list[FlowRecord]:
        return [f for f in self.flows if f.dest == host]

    def hosts(self) -> set[str]:
        return {f.source for f in self.flows}
