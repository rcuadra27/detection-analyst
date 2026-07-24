"""
Phase 1 — the vector index. Embed chunks, store in FAISS, retrieve top-k.

Model choice: sentence-transformers/all-MiniLM-L6-v2.
  - small (~80MB), fast on CPU, 384-dim — fine for a 1k-chunk corpus on a laptop
  - a well-understood baseline; if Phase 2 shows retrieval is the bottleneck,
    upgrading the embedder (e.g. bge-small/large) is a measurable experiment,
    which is exactly the kind of lever the eval harness exists to test.

Index choice: IndexFlatIP (exact inner-product search) over normalized
embeddings = exact cosine similarity. With ~1000 vectors there is zero reason
for an approximate index; exact search removes one source of noise from evals.

The encoder is injectable so tests can run without downloading model weights.
"""

from __future__ import annotations

import json
import pickle
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Protocol

import faiss
import numpy as np

from src.rag.chunking import Chunk

PROCESSED_DIR = Path("data/processed")
INDEX_PATH = PROCESSED_DIR / "attack.faiss"
CHUNKS_PATH = PROCESSED_DIR / "attack_chunks.pkl"
META_PATH = PROCESSED_DIR / "index_meta.json"

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Encoder(Protocol):
    def __call__(self, texts: list[str]) -> np.ndarray: ...


def sentence_transformer_encoder(model_name: str = DEFAULT_MODEL) -> Encoder:
    """Real encoder. Imported lazily so the module works without torch installed."""
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_name)

    def encode(texts: list[str]) -> np.ndarray:
        vecs = model.encode(
            texts, batch_size=64, show_progress_bar=len(texts) > 100,
            convert_to_numpy=True, normalize_embeddings=True,
        )
        return vecs.astype(np.float32)

    return encode


@dataclass
class RetrievedChunk:
    chunk: Chunk
    score: float  # cosine similarity


class VectorIndex:
    def __init__(self, index: faiss.Index, chunks: list[Chunk], model_name: str):
        self.index = index
        self.chunks = chunks
        self.model_name = model_name

    # ---------- build / persist ----------

    @classmethod
    def build(cls, chunks: list[Chunk], encoder: Encoder,
              model_name: str = DEFAULT_MODEL) -> "VectorIndex":
        vecs = encoder([c.text for c in chunks])
        faiss.normalize_L2(vecs)  # idempotent if already normalized
        index = faiss.IndexFlatIP(vecs.shape[1])
        index.add(vecs)
        return cls(index, chunks, model_name)

    def save(self) -> None:
        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        faiss.write_index(self.index, str(INDEX_PATH))
        CHUNKS_PATH.write_bytes(pickle.dumps(self.chunks))
        META_PATH.write_text(json.dumps(
            {"model_name": self.model_name, "n_chunks": len(self.chunks),
             "dim": self.index.d}, indent=2))
        print(f"[index] saved {len(self.chunks)} chunks, dim={self.index.d} "
              f"-> {INDEX_PATH}")

    @classmethod
    def load(cls) -> "VectorIndex":
        meta = json.loads(META_PATH.read_text())
        index = faiss.read_index(str(INDEX_PATH))
        chunks = pickle.loads(CHUNKS_PATH.read_bytes())
        return cls(index, chunks, meta["model_name"])

    # ---------- query ----------

    def retrieve(self, query: str, encoder: Encoder, k: int = 5) -> list[RetrievedChunk]:
        q = encoder([query])
        faiss.normalize_L2(q)
        scores, idxs = self.index.search(q, k)
        return [
            RetrievedChunk(chunk=self.chunks[i], score=float(s))
            for s, i in zip(scores[0], idxs[0]) if i != -1
        ]


def build_and_save(model_name: str = DEFAULT_MODEL) -> VectorIndex:
    """One-shot: corpus -> chunks -> embeddings -> saved index."""
    from src.corpus import load_attack_techniques
    from src.rag.chunking import build_chunks

    techniques = load_attack_techniques()
    chunks = build_chunks(techniques)
    print(f"[index] embedding {len(chunks)} chunks with {model_name} ...")
    encoder = sentence_transformer_encoder(model_name)
    vi = VectorIndex.build(chunks, encoder, model_name)
    vi.save()
    return vi


if __name__ == "__main__":
    import sys

    if "--query" in sys.argv:
        # e.g. python -m src.rag.index --query "multiple failed SSH logins from single source"
        q = sys.argv[sys.argv.index("--query") + 1]
        vi = VectorIndex.load()
        encoder = sentence_transformer_encoder(vi.model_name)
        for r in vi.retrieve(q, encoder, k=5):
            print(f"{r.score:.3f}  {r.chunk.technique_id:12} {r.chunk.technique_name}")
    else:
        build_and_save()