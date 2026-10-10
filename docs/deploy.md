# Deploying the agent to Cloud Run

The hosted app is a third host for the same agent (after `cli.py` and Claude Code).
`src/agent/web.py` serves a chat page; each chat starts its own MCP server
subprocess with the same six tools and guardrails. Testers sign in with personal
access codes. Nothing else about the agent changes.

```
Tester ──HTTPS──▶ Cloud Run: web.py ──▶ Agent loop ──stdio MCP──▶ mcp_server.py ──▶ scenario data
                       │                                                (read-only)
                       └── one JSON log line per question, feedback, review ──▶ Cloud Logging ──▶ BigQuery
```

## What ships, and what does not

| In the image | Not in the image |
|---|---|
| `src/`, `.claude/skills/` | `data/scenario/truth.json` (the eval answer key) |
| `data/scenario/flows.jsonl`, `meta.json` | `.env`, API keys (they come from Secret Manager) |
| ATT&CK technique cache | Trained models, raw UNSW data, logs |
| | The held-out days (`data/scenario_heldout*/`) |

The Dockerfile copies files one by one, and `.dockerignore` denies everything else,
so the answer key cannot ship by accident.

## 0. Build the scenario with the real detector

```bash
python -m src.agent.scenario --mode real
```

The app serves the dev day (`data/scenario/`). The held-out days stay off the app on
purpose: testers should not shape behavior on the data that measures generalization.

Keep this exact build for the whole test period. The remote eval grades the deployed
app against your local `truth.json`, and refuses to run if the app's `meta.json`
differs from yours. If you rebuild the scenario, redeploy.

## 1. One-time GCP setup

```bash
export PROJECT=<your-project-id>
export REGION=us-west1
gcloud config set project $PROJECT
gcloud services enable run.googleapis.com cloudbuild.googleapis.com \
    artifactregistry.googleapis.com secretmanager.googleapis.com logging.googleapis.com \
    bigquery.googleapis.com

# Service account the app runs as
gcloud iam service-accounts create detection-analyst-web
export SA=detection-analyst-web@$PROJECT.iam.gserviceaccount.com
```

## 2. Secrets: the API key and the access codes

Generate one code per tester, plus one reserved for evals:

```bash
python -c "import secrets; print(secrets.token_urlsafe(9))"   # run once per code
```

```bash
printf %s "$ANTHROPIC_API_KEY" | gcloud secrets create anthropic-api-key --data-file=-
printf %s "tester-1=<code>,tester-2=<code>,tester-3=<code>,eval=<code>" \
    | gcloud secrets create da-access-codes --data-file=-

for s in anthropic-api-key da-access-codes; do
  gcloud secrets add-iam-policy-binding $s \
    --member=serviceAccount:$SA --role=roles/secretmanager.secretAccessor
done
```

To add or remove a tester later: `gcloud secrets versions add da-access-codes
--data-file=-`, then redeploy (the app reads codes at startup).

Also set a monthly spend limit in the Anthropic console. The app's daily token
budget is a second line of defense, not the only one.

## 3. Logs to BigQuery (create the sink BEFORE testers start)

A sink only captures log entries written after it exists.

```bash
bq mk --dataset --location=US $PROJECT:da_logs
gcloud logging sinks create da-agent-events \
  bigquery.googleapis.com/projects/$PROJECT/datasets/da_logs \
  --use-partitioned-tables \
  --log-filter='resource.type="cloud_run_revision"
                AND resource.labels.service_name="detection-analyst"
                AND jsonPayload.event:*'
```

The command prints the sink's writer identity. Grant it write access to the dataset:

```bash
WRITER=$(gcloud logging sinks describe da-agent-events --format='value(writerIdentity)')
gcloud projects add-iam-policy-binding $PROJECT --member="$WRITER" --role=roles/bigquery.dataEditor
```

## 4. Deploy

First check exactly what will be uploaded. `gcloud` re-includes everything under a
directory that `.gcloudignore` negates, so verify the list every time the ignore
file or the data layout changes:

```bash
gcloud meta list-files-for-upload | grep -v "^src/"
```

It must show only `Dockerfile`, `.dockerignore`, `requirements-web.txt`, the four
files under `.claude/skills/`, `data/raw/attack_techniques_cache.json`,
`data/scenario/flows.jsonl` and `data/scenario/meta.json`. Never `truth.json`, a
held-out directory, `data/processed/` or pcaps.

```bash
gcloud run deploy detection-analyst \
  --source . \
  --region $REGION \
  --service-account $SA \
  --allow-unauthenticated \
  --max-instances 1 --min-instances 0 \
  --memory 2Gi --cpu 2 --timeout 900 --concurrency 20 \
  --set-secrets ANTHROPIC_API_KEY=anthropic-api-key:latest,DA_ACCESS_CODES=da-access-codes:latest \
  --set-env-vars DA_MODEL=claude-sonnet-5,DA_DAILY_TOKEN_BUDGET=5000000
```

Why these settings:

- `--allow-unauthenticated`: testers do not have Google accounts in this project.
  The app checks access codes itself, and every API route requires one.
- `--max-instances 1`: chat sessions live in one process's memory. A second
  instance would not know the first one's sessions.
- `--min-instances 0`: no cost when idle. After about 15 idle minutes the instance
  can shut down; open chats then expire and the page starts a new one.
- `--timeout 900`: most questions take under a minute, but a shift summary makes 20+
  tool calls and ran past the original 300-second limit. The eval client waits 960 s,
  so a server timeout shows up as a 504 rather than a client hang.

## 5. Smoke test, then the eval against the live URL

```bash
URL=$(gcloud run services describe detection-analyst --region $REGION --format='value(status.url)')
curl $URL/healthz
DA_ACCESS_CODE=<eval code> python -m src.agent.eval_agent --url $URL
```

Run the eval after every deploy. Its traffic is logged under the `eval` label, so
it can be filtered out of tester statistics.

## 6. Reading the logs

In Cloud Logging: `jsonPayload.event="turn"` (one line per question),
`"feedback"`, `"review"`, `"turn_failed"`, `"budget_exhausted"`.

In BigQuery. The sink uses partitioned tables, so the table name has no date
suffix (check with `bq ls da_logs`; stdout lands in `run_googleapis_com_stdout`):

```sql
-- per tester: questions, latency, tokens, guardrail rejections
SELECT jsonPayload.tester AS tester,
       COUNT(*) AS questions,
       APPROX_QUANTILES(jsonPayload.latency_ms, 100)[OFFSET(50)] AS p50_ms,
       APPROX_QUANTILES(jsonPayload.latency_ms, 100)[OFFSET(95)] AS p95_ms,
       AVG(jsonPayload.input_tokens) AS avg_uncached_in,
       AVG(jsonPayload.cache_read_input_tokens) AS avg_cache_read,
       AVG(jsonPayload.cache_creation_input_tokens) AS avg_cache_write,
       AVG(jsonPayload.output_tokens) AS avg_out,
       COUNTIF(ARRAY_LENGTH(jsonPayload.guardrail_rejections) > 0) AS turns_with_rejection,
       COUNTIF(jsonPayload.hit_step_cap) AS step_cap_hits
FROM `da_logs.run_googleapis_com_stdout`
WHERE jsonPayload.event = 'turn' AND jsonPayload.tester != 'eval'
GROUP BY tester;
```

## Known limits of this deployment

- One instance, in-memory sessions: fine for a handful of testers, not for a team.
- Local files under `logs/` (audit log, triage queue) do not survive a restart.
  The durable record is the JSON log stream in Cloud Logging and BigQuery.
- The daily budget counter resets if the instance restarts.
- The data is one simulated day. Testers exercise the agent, not a live network.
