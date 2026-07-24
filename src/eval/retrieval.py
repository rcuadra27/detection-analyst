"""
Phase 2 — retrieval metrics. Does the correct ATT&CK technique reach the
context at all?

This is measured independently from answer quality on purpose: if the right
technique never gets retrieved, the generator was set up to fail, and that's a
retriever problem (better embeddings / chunking), not a reasoning problem.

Metrics:
  - hit@k  : fraction of alerts where at least one correct technique appears in
             the top-k retrieved chunks. The headline "did we find it" number.
  - recall@k: average fraction of an alert's correct techniques found in top-k
             (matters because a class can map to several techniques).
  - MRR    : mean reciprocal rank of the FIRST correct technique. Rewards
             ranking the right technique near the top, not just somewhere in k.

Family matching: a retrieved sub-technique (T1110.003) counts as a match for a
mapped parent (T1110) and vice-versa — they're the same technique family, and
an analyst would treat that as correct. Toggle with family_match.
"""

from __future__ import annotations

from collections import defaultdict

from src.eval.dataset import LabeledAlert
from src.rag.index import RetrievedChunk


def base_id(technique_id: str) -> str:
    """T1110.003 -> T1110 ; T1110 -> T1110."""
    return technique_id.split(".", 1)[0]


def _matches(true_id: str, retrieved_id: str, family_match: bool) -> bool:
    if true_id == retrieved_id:
        return True
    return family_match and base_id(true_id) == base_id(retrieved_id)


def ranked_technique_ids(retrieved: list[RetrievedChunk]) -> list[str]:
    """Ordered, de-duplicated technique IDs (best-scoring occurrence wins)."""
    seen: set[str] = set()
    out: list[str] = []
    for r in retrieved:  # assumed already sorted best-first by the index
        tid = r.chunk.technique_id
        if tid not in seen:
            seen.add(tid)
            out.append(tid)
    return out


def first_hit_rank(ranked: list[str], true_ids: list[str], family_match: bool) -> int | None:
    """1-based rank of the first retrieved technique that matches any true id."""
    for pos, tid in enumerate(ranked, 1):
        if any(_matches(t, tid, family_match) for t in true_ids):
            return pos
    return None


def _recall_at_k(ranked: list[str], true_ids: list[str], k: int, family_match: bool) -> float:
    if not true_ids:
        return 1.0  # 'normal' with no technique: retrieving nothing relevant is fine
    topk = ranked[:k]
    found = sum(any(_matches(t, r, family_match) for r in topk) for t in true_ids)
    return found / len(true_ids)


def evaluate_retrieval(
    alerts: list[LabeledAlert],
    index,
    encoder,
    ks: tuple[int, ...] = (1, 3, 5, 10),
    max_k: int | None = None,
    family_match: bool = True,
) -> dict:
    """Run retrieval for every alert and aggregate metrics (overall + per class)."""
    max_k = max_k or max(ks)
    # exclude 'normal' (no technique to retrieve) from technique-retrieval scoring
    scored = [a for a in alerts if a.true_technique_ids]

    per_class_hits: dict[str, list[int]] = defaultdict(list)  # hit@max_k flags
    hit_flags = {k: [] for k in ks}
    recalls = {k: [] for k in ks}
    rr = []

    for a in scored:
        retrieved = index.retrieve(a.alert_text, encoder, k=max_k)
        ranked = ranked_technique_ids(retrieved)
        rank = first_hit_rank(ranked, a.true_technique_ids, family_match)
        rr.append(1.0 / rank if rank else 0.0)
        for k in ks:
            hit = 1 if (rank is not None and rank <= k) else 0
            hit_flags[k].append(hit)
            recalls[k].append(_recall_at_k(ranked, a.true_technique_ids, k, family_match))
        per_class_hits[a.attack_class].append(1 if (rank and rank <= max_k) else 0)

    def mean(xs): return sum(xs) / len(xs) if xs else 0.0

    return {
        "n_scored": len(scored),
        "hit_at_k": {k: mean(hit_flags[k]) for k in ks},
        "recall_at_k": {k: mean(recalls[k]) for k in ks},
        "mrr": mean(rr),
        "per_class_hit_at_maxk": {
            c: mean(v) for c, v in sorted(per_class_hits.items())
        },
        "max_k": max_k,
    }


def print_report(metrics: dict) -> None:
    print(f"\n=== Retrieval metrics (n={metrics['n_scored']} alerts w/ techniques) ===")
    hits = metrics["hit_at_k"]; rec = metrics["recall_at_k"]
    print(f"{'k':>4}  {'hit@k':>7}  {'recall@k':>9}")
    for k in hits:
        print(f"{k:>4}  {hits[k]:>7.3f}  {rec[k]:>9.3f}")
    print(f"MRR: {metrics['mrr']:.3f}")
    print(f"\nper-class hit@{metrics['max_k']}:")
    for c, v in metrics["per_class_hit_at_maxk"].items():
        print(f"  {c:16} {v:.2f}")


if __name__ == "__main__":
    import argparse

    from src.eval.dataset import load_jsonl
    from src.rag.index import VectorIndex, sentence_transformer_encoder

    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default="data/processed/eval_set.jsonl",
                    help="path to the labeled eval set jsonl")
    args = ap.parse_args()

    alerts = load_jsonl(args.eval)
    print(f"[retrieval] scoring {args.eval}")
    index = VectorIndex.load()
    encoder = sentence_transformer_encoder(index.model_name)
    metrics = evaluate_retrieval(alerts, index, encoder)
    print_report(metrics)