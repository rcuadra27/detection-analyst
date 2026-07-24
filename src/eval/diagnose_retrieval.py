"""
Phase 2 diagnostic — WHY does retrieval miss?

For each alert whose correct technique didn't make the top-k, we want to know:
is the right technique ranked just outside k (a reranking / k-tuning problem),
or nowhere near the top (a semantic-gap problem where the alert text simply
doesn't carry the behavioral signal the ATT&CK prose describes)?

Prints, per class: hit-rate, the rank of the correct technique when it IS found
(searched deep), and for misses a sample of what got retrieved instead.
"""

from __future__ import annotations

from collections import defaultdict

from src.eval.dataset import load_jsonl
from src.eval.retrieval import ranked_technique_ids, first_hit_rank
from src.rag.index import VectorIndex, sentence_transformer_encoder

DEEP_K = 100  # search deep so we can see where the true technique really lands


def main():
    alerts = [a for a in load_jsonl("data/processed/eval_set.jsonl") if a.true_technique_ids]
    index = VectorIndex.load()
    encoder = sentence_transformer_encoder(index.model_name)

    by_class = defaultdict(lambda: {"ranks": [], "misses": []})
    for a in alerts:
        retrieved = index.retrieve(a.alert_text, encoder, k=DEEP_K)
        ranked = ranked_technique_ids(retrieved)
        rank = first_hit_rank(ranked, a.true_technique_ids, family_match=True)
        rec = by_class[a.attack_class]
        rec["ranks"].append(rank)  # None if not even in top DEEP_K
        if rank is None or rank > 10:
            rec["misses"].append((a.alert_text[:70], ranked[:3]))

    print(f"\n=== Retrieval diagnosis (deep search k={DEEP_K}) ===")
    print(f"{'class':16} {'hit@10':>7} {'median rank*':>13}  (*rank of correct technique when in top-100; '-' = not found)")
    for cls in sorted(by_class):
        ranks = by_class[cls]["ranks"]
        found = [r for r in ranks if r is not None]
        hit10 = sum(1 for r in ranks if r and r <= 10) / len(ranks)
        med = sorted(found)[len(found)//2] if found else None
        med_s = str(med) if med is not None else "-"
        notfound = sum(1 for r in ranks if r is None)
        print(f"{cls:16} {hit10:>7.2f} {med_s:>13}   in-top100: {len(found)}/{len(ranks)}, never-found: {notfound}")

    print("\n--- sample misses: what got retrieved INSTEAD (top-3) ---")
    for cls in sorted(by_class):
        misses = by_class[cls]["misses"]
        if not misses:
            continue
        print(f"\n[{cls}]  (true techniques should have appeared, but:)")
        for text, top3 in misses[:2]:
            print(f"  alert: {text}")
            print(f"    got: {top3}")


if __name__ == "__main__":
    main()