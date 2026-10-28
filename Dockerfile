# Detection Analyst web host for Cloud Run.
#
# Build the scenario first, on your machine, with the real detector:
#     python -m src.agent.scenario --mode real
# and export the Zeek calibration once (it is committed with the code):
#     python -m src.ingest.score --export-calibration data/processed/parity_validation3
# The image gets flows.jsonl and meta.json only. truth.json (the answer key the
# eval harness grades against) is never copied: see .dockerignore.
#
# Uploads: a tester's pcap is scored in the container, so the image carries Zeek
# (official openSUSE build service packages, LTS 8.0) and the two trained models.
# The base image is pinned to Debian 12 to match the Zeek package repository.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    ZEEK_BIN=/opt/zeek/bin/zeek

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
 && echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' \
      > /etc/apt/sources.list.d/zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key \
      | gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg \
 && apt-get update \
 && apt-get install -y --no-install-recommends zeek-8.0 \
 && apt-get purge -y curl gnupg && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* \
 && /opt/zeek/bin/zeek --version

WORKDIR /app

COPY requirements-web.txt .
RUN pip install --no-cache-dir -r requirements-web.txt

COPY src/ src/
COPY .claude/skills/ .claude/skills/
COPY data/raw/attack_techniques_cache.json data/raw/attack_techniques_cache.json
COPY data/scenario/flows.jsonl data/scenario/meta.json data/scenario/
COPY data/processed/stage1_binary.joblib data/processed/stage2_multiclass.joblib data/processed/

RUN useradd --create-home app && mkdir -p logs && chown app logs
USER app

# The same image runs the da-score job (python -m src.ingest.job), which scores
# uploaded captures from the bucket; see docs/deploy.md, section 4b.
# One worker: chat sessions live in this process's memory.
CMD exec uvicorn src.agent.web:app --host 0.0.0.0 --port ${PORT} --workers 1
