"""
Phase 1 — chunking. Turn ATT&CK techniques into retrievable documents.

Design decisions (these matter for retrieval quality, and they're worth being
able to defend in an interview):

1. One-or-more chunks PER TECHNIQUE, never chunks that span techniques. Every
   chunk carries its technique_id in metadata, so retrieval quality in Phase 2
   can be scored as "did any retrieved chunk belong to the right technique?"

2. Every chunk gets a HEADER prefix: technique ID, name, and tactics. Alert
   text is terse and telemetry-flavored ("SYN flood", "port sweep", "failed
   logins"), while ATT&CK descriptions are long prose. The header injects the
   technique's name and kill-chain position into every chunk's embedding,
   which is often what actually matches the alert phrasing.

3. Long descriptions are split into overlapping windows (default ~1200 chars,
   200 overlap) on paragraph boundaries where possible. Most embedding models
   truncate long inputs (e.g. MiniLM at 256 tokens), so a single giant chunk
   would silently throw away most of the description.

4. Citation markup and URLs in ATT&CK descriptions are stripped — they're
   noise to an embedding model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.corpus import AttackTechnique

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")   # [text](url) -> text
_CODE_TICKS_RE = re.compile(r"<code>|</code>|`")
_WS_RE = re.compile(r"[ \t]+")


@dataclass
class Chunk:
    chunk_id: str            # e.g. "T1110#0"
    technique_id: str        # e.g. "T1110"
    text: str                # what gets embedded
    technique_name: str
    tactics: list[str]


def clean_description(desc: str) -> str:
    desc = _CITATION_RE.sub("", desc)
    desc = _MD_LINK_RE.sub(r"\1", desc)
    desc = _CODE_TICKS_RE.sub("", desc)
    desc = _WS_RE.sub(" ", desc)
    # collapse 3+ newlines to paragraph breaks
    desc = re.sub(r"\n{3,}", "\n\n", desc)
    return desc.strip()


def _split_paragraph_windows(text: str, max_chars: int, overlap: int) -> list[str]:
    """Greedy paragraph packing; falls back to hard character windows for any
    single paragraph longer than max_chars."""
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    windows: list[str] = []
    current = ""
    for p in paras:
        if len(p) > max_chars:  # oversized paragraph: hard-split it
            if current:
                windows.append(current)
                current = ""
            step = max_chars - overlap
            for start in range(0, len(p), step):
                piece = p[start : start + max_chars]
                windows.append(piece)
                if start + max_chars >= len(p):
                    break
            continue
        if current and len(current) + 2 + len(p) > max_chars:
            windows.append(current)
            # start next window with a small overlap tail for continuity
            current = (current[-overlap:] + "\n\n" + p) if overlap else p
        else:
            current = f"{current}\n\n{p}" if current else p
    if current:
        windows.append(current)
    return windows or [""]


def build_chunks(
    techniques: list[AttackTechnique],
    max_chars: int = 1200,
    overlap: int = 200,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    for t in techniques:
        header = (
            f"ATT&CK {t.technique_id} — {t.name}"
            + (f" | Tactics: {', '.join(t.tactics)}" if t.tactics else "")
        )
        body = clean_description(t.description) or t.name
        for i, window in enumerate(_split_paragraph_windows(body, max_chars, overlap)):
            chunks.append(
                Chunk(
                    chunk_id=f"{t.technique_id}#{i}",
                    technique_id=t.technique_id,
                    text=f"{header}\n{window}",
                    technique_name=t.name,
                    tactics=list(t.tactics),
                )
            )
    return chunks


if __name__ == "__main__":
    from src.corpus import load_attack_techniques

    techniques = load_attack_techniques()
    chunks = build_chunks(techniques)
    per_tech = len(chunks) / len(techniques)
    lengths = sorted(len(c.text) for c in chunks)
    print(f"{len(techniques)} techniques -> {len(chunks)} chunks "
          f"({per_tech:.2f} chunks/technique)")
    print(f"chunk length chars: min={lengths[0]} median={lengths[len(lengths)//2]} "
          f"max={lengths[-1]}")
    demo = next(c for c in chunks if c.technique_id == "T1110")
    print("\n--- sample chunk (T1110 Brute Force) ---")
    print(demo.text[:600])