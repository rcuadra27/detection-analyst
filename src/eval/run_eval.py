"""
Phase 2 — the full eval runner. One command, the whole baseline.

For every labeled alert:
  retrieve top-k  ->  generate triage  ->  score answer quality,
while recording the retrieved technique IDs so faithfulness can check whether
the model only cited what it was actually given.

Caches raw model outputs to JSON so re-scoring (e.g. tweaking a metric) doesn't
re-pay for generation. Costs one generation call per alert on a fresh run.

Usage:
    python -m src.eval.run_eval --k 5 --limit 0          # full run
    python -m src.eval.run_eval --k 5 --limit 8          # quick smoke test
    python -m src.eval.run_eval --from-cache             # re-score, no API calls
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from src.eval.answer import AnswerEval, print_report
from src.eval.dataset import load_jsonl
from src.eval.retrieval import ranked_technique_ids
from src.rag.generator import generate_triage
from src.rag.index import VectorIndex, sentence_transformer_encoder
from src.schema import TriageResult

CACHE_PATH = Path("data/processed/eval_predictions.jsonl")


def run(k: int = 5, limit: int = 0, model: str | None = None,
        eval_path: str = "data/processed/eval_set.jsonl", use_cache: bool = False):
    alerts = load_jsonl(eval_path)
    if limit:
        alerts = alerts[:limit]

    index = VectorIndex.load()
    encoder = sentence_transformer_encoder(index.model_name)

    # cache of {alert_id: {"pred": {...}, "context_ids": [...]}}
    cache: dict[str, dict] = {}
    if CACHE_PATH.exists():
        for line in CACHE_PATH.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                cache[rec["alert_id"]] = rec

    client = None
    if not use_cache:
        from anthropic import Anthropic
        client = Anthropic()

    ev = AnswerEval()
    new_cache_lines: list[str] = []
    for i, a in enumerate(alerts, 1):
        retrieved = index.retrieve(a.alert_text, encoder, k=k)
        context_ids = ranked_technique_ids(retrieved)

        rec = cache.get(a.alert_id)
        if rec is not None:
            pred = TriageResult.model_validate(rec["pred"])
            context_ids = rec.get("context_ids", context_ids)
        elif use_cache:
            print(f"  [skip] no cached prediction for {a.alert_id}")
            continue
        else:
            pred = generate_triage(a.alert_text, retrieved, client,
                                   model=model or "claude-sonnet-5", alert_id=a.alert_id)
            rec = {"alert_id": a.alert_id, "pred": pred.model_dump(mode="json"),
                   "context_ids": context_ids}
            new_cache_lines.append(json.dumps(rec))
            print(f"  [{i}/{len(alerts)}] {a.alert_id:18} "
                  f"pred_sev={pred.severity.value:8} tech={pred.attack_technique_ids}")

        ev.add(a, pred, context_ids)

    # append any newly generated predictions to the cache
    if new_cache_lines:
        with open(CACHE_PATH, "a") as f:
            f.write("\n".join(new_cache_lines) + "\n")

    summary = ev.summary()
    print_report(summary)
    out = Path("data/processed/answer_metrics.json")
    out.write_text(json.dumps(summary, indent=2))
    print(f"\n[run] wrote {out}")
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default=None)
    ap.add_argument("--from-cache", action="store_true",
                    help="score only from cached predictions, no API calls")
    args = ap.parse_args()

    if not args.from_cache and not os.getenv("ANTHROPIC_API_KEY"):
        from dotenv import load_dotenv
        load_dotenv()
    run(k=args.k, limit=args.limit, model=args.model, use_cache=args.from_cache)