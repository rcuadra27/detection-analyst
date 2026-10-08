# Detection Analyst web host for Cloud Run.
#
# Build the scenario first, on your machine, with the real detector:
#     python -m src.agent.scenario --mode real
# The image gets flows.jsonl and meta.json only. truth.json (the answer key the
# eval harness grades against) is never copied: see .dockerignore.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

COPY src/ src/
COPY .claude/skills/ .claude/skills/
COPY data/raw/attack_techniques_cache.json data/raw/attack_techniques_cache.json
COPY data/scenario/flows.jsonl data/scenario/meta.json data/scenario/

RUN useradd --create-home app && mkdir -p logs && chown app logs
USER app

# One worker: chat sessions live in this process's memory.
CMD exec uvicorn src.agent.web:app --host 0.0.0.0 --port ${PORT} --workers 1
