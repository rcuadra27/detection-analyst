# Detection Analyst

A grounded (RAG) security-alert triage system with a rigorous evaluation harness,
later upgraded with a LoRA fine-tuned generator. Given a NIDS alert, the system
retrieves relevant MITRE ATT&CK / CVE context and produces a structured triage:
severity, true/false-positive assessment, mapped ATT&CK technique(s), a grounded
explanation, a recommended action, and a confidence score.

## Status

- [x] **Phase 0** — Scope & data foundation: output contract (`src/schema.py`), ground-truth mapping (`src/mapping.py`), reference corpora.
- [ ] **Phase 1** — RAG core: chunk + embed ATT&CK/CVE, retrieve top-k, grounded structured generation.
- [ ] **Phase 2** — Eval harness: retrieval quality (recall@k, MRR) and answer quality (severity acc, technique acc, faithfulness). *The hero artifact.*
- [ ] **Phase 3** — LoRA fine-tune: train a small open model, swap it in, re-run the same harness, report before/after.
- [ ] **Phase 4** — Minimal interface + writeup.

## Setup

```bash
python3.12 -m venv detection_analyst
source detection_analyst/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then add your real ANTHROPIC_API_KEY
```

## Data

Raw UNSW-NB15 CSVs are not redistributed in this repository. Download them from
the original dataset source and place the CSV files in `data/raw/` before
training or running the full pipeline.

## The output contract

All generation and evaluation validates against `TriageResult` in `src/schema.py`.
A response that does not parse is treated as a failure, not a partial answer.
