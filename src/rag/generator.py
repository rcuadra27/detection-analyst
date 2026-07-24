"""
Phase 1 — the generator. The analyst that reads the retrieved context + the
alert and writes the triage.

Design:
  - The retriever (index.py) already found the relevant ATT&CK chunks. This
    module formats them into a context block, asks Claude to reason over
    *only that context*, and forces the answer into the TriageResult schema.
  - Grounding is enforced in the prompt: the model may only cite technique IDs
    that appear in the retrieved context, and the explanation must rest on it.
    That constraint is what Phase 2's faithfulness metric will check.
  - Every response is validated against the Pydantic schema. Malformed JSON gets
    ONE corrective retry, then raises — we never return an unvalidated triage.

This file is the last piece of the RAG core. triage_alert() is the whole
pipeline end to end: alert in, validated TriageResult out.
"""

from __future__ import annotations

import json
import os

from src.schema import TriageResult
from src.rag.index import RetrievedChunk, VectorIndex, sentence_transformer_encoder

DEFAULT_GEN_MODEL = "claude-sonnet-5"

SYSTEM_PROMPT = """You are a senior SOC analyst performing first-pass triage of a \
network intrusion-detection alert. You are given the alert and a set of MITRE \
ATT&CK reference excerpts retrieved for it.

Rules:
- Base your reasoning ONLY on the retrieved ATT&CK context and the alert itself. \
Do not invent techniques or facts not supported by them.
- attack_technique_ids may ONLY contain technique IDs that appear in the \
retrieved context. If none fit, return an empty list.
- An empty attack_technique_ids list is acceptable when the retrieved context \
supports no technique, but assessment and severity must still reflect the \
detector's confidence and the observed evidence. Absence of a mappable \
technique is not evidence of benign traffic.
- If the alert looks like benign/normal traffic, set assessment to \
"false_positive" and severity to "low".
- confidence must honestly reflect how well the context supports your call \
(low confidence when the context is a poor match).
- Keep explanation and recommended_action concise and specific.

Respond with ONLY a single JSON object, no prose and no markdown fences, with \
exactly these keys:
  severity: one of "low","medium","high","critical"
  assessment: one of "true_positive","false_positive","inconclusive"
  attack_technique_ids: list of ATT&CK IDs (e.g. ["T1110"]) drawn from context
  explanation: string
  recommended_action: string
  confidence: number between 0 and 1
"""


def format_context(retrieved: list[RetrievedChunk]) -> str:
    """Render retrieved chunks into a numbered context block for the prompt."""
    blocks = []
    for i, r in enumerate(retrieved, 1):
        blocks.append(
            f"[{i}] {r.chunk.technique_id} — {r.chunk.technique_name} "
            f"(similarity {r.score:.2f})\n{r.chunk.text}"
        )
    return "\n\n".join(blocks)


def _build_user_message(alert: str, context: str) -> str:
    return (
        f"ALERT:\n{alert}\n\n"
        f"RETRIEVED ATT&CK CONTEXT:\n{context}\n\n"
        f"Produce the triage JSON now."
    )


def _extract_text(response) -> str:
    """Join all text blocks from an Anthropic Messages response."""
    return "".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    ).strip()


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]           # drop opening ```json line
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()


def generate_triage(
    alert: str,
    retrieved: list[RetrievedChunk],
    client,
    model: str = DEFAULT_GEN_MODEL,
    alert_id: str | None = None,
    max_tokens: int = 1024,
) -> TriageResult:
    """Call the model, parse + validate into TriageResult. One retry on bad JSON."""
    context = format_context(retrieved)
    user_msg = _build_user_message(alert, context)
    messages = [{"role": "user", "content": user_msg}]

    last_err: Exception | None = None
    for attempt in range(2):
        resp = client.messages.create(
            model=model, max_tokens=max_tokens,
            system=SYSTEM_PROMPT, messages=messages,
        )
        raw = _strip_fences(_extract_text(resp))
        try:
            data = json.loads(raw)
            data.setdefault("alert_id", alert_id)
            return TriageResult.model_validate(data)
        except Exception as e:  # json or schema failure
            last_err = e
            # feed the error back and ask for a correction
            messages += [
                {"role": "assistant", "content": raw},
                {"role": "user", "content":
                    f"That did not parse as valid TriageResult JSON ({e}). "
                    f"Return ONLY corrected JSON with the required keys."},
            ]
    raise ValueError(f"Generator failed to produce valid TriageResult: {last_err}")


def triage_alert(
    alert: str,
    k: int = 5,
    model: str = DEFAULT_GEN_MODEL,
    alert_id: str | None = None,
    client=None,
    index: VectorIndex | None = None,
) -> TriageResult:
    """Full RAG core: retrieve top-k ATT&CK context for the alert, then generate.

    Loads the saved index and creates an Anthropic client if not supplied.
    """
    if index is None:
        index = VectorIndex.load()
    encoder = sentence_transformer_encoder(index.model_name)
    retrieved = index.retrieve(alert, encoder, k=k)

    if client is None:
        from anthropic import Anthropic
        client = Anthropic()  # reads ANTHROPIC_API_KEY from env

    return generate_triage(alert, retrieved, client, model=model, alert_id=alert_id)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise SystemExit("Set ANTHROPIC_API_KEY (in .env) to run the generator.")

    sample = ("Multiple failed SSH authentication attempts (47 in 60s) from a "
              "single external IP 203.0.113.9 against host 10.0.4.12, followed "
              "by one successful login.")
    result = triage_alert(sample, k=5, alert_id="demo-001")
    print(result.model_dump_json(indent=2))