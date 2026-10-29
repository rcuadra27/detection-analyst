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
| `src/`, `.claude/skills/` (incl. `src/ingest/calibration.json`) | `data/scenario/truth.json` (the eval answer key) |
| `data/scenario/flows.jsonl`, `meta.json` | `.env`, API keys (they come from Secret Manager) |
| ATT&CK technique cache | Raw UNSW data, pcaps, parity outputs, logs |
| `stage1_binary.joblib`, `stage2_multiclass.joblib` (to score uploads) | The held-out days (`data/scenario_heldout*/`) |
| Zeek 8.0 LTS (installed from the official package repository) | |

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

## 0b. Freeze the Zeek calibration (uploads)

Uploaded pcaps are scored with the feature definitions chosen in the parity
experiment ([parity.md](parity.md)). Export them once and commit the file:

```bash
python -m src.ingest.score --export-calibration data/processed/parity_validation3
git add src/ingest/calibration.json
```

The image builds without it, but every upload would then fail with a clear
"No calibration" error in the logs.

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
`data/scenario/flows.jsonl`, `data/scenario/meta.json` and the two model files
`data/processed/stage1_binary.joblib` and `stage2_multiclass.joblib`. Never
`truth.json`, a held-out directory, anything else under `data/processed/`, or pcaps.

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

## 4b. Uploads: a bucket and a scoring job

A Cloud Run request is capped at 32 MiB, and a UNSW capture is about 1 GB. So a
pcap never passes through the web service: the page uploads it straight to a
Cloud Storage bucket with a signed URL the app hands out, then the app starts a
Cloud Run Job, from the same image, that scores it and writes the results to
the bucket. Without this section the app still works, but uploads fall back to
the instance's own disk through the app, which on Cloud Run caps them at 32 MiB.

```
browser --PUT (signed URL)--> gs://$BUCKET/uploads/<id>/capture.pcap
   |                                   |
   +--> web app --run job--> da-score job: Zeek -> detector -> store/flows.jsonl, meta.json
          ^                                                    (pcap deleted)
          +------------ reads the store, serves the rail and chats <---+
```

```bash
export BUCKET=$PROJECT-da-uploads
gcloud services enable iamcredentials.googleapis.com
gcloud storage buckets create gs://$BUCKET --location=$REGION --uniform-bucket-level-access

# Delete everything after 7 days (scored stores included).
echo '{"rule":[{"action":{"type":"Delete"},"condition":{"age":7}}]}' > lifecycle.json
gcloud storage buckets update gs://$BUCKET --lifecycle-file=lifecycle.json

# Let the page PUT to the bucket, from the app's URLs only. A Cloud Run service
# answers on two addresses (status.url and <service>-<project number>.<region>.run.app);
# the browser treats them as different origins, so allow both.
URL1=$(gcloud run services describe detection-analyst --region $REGION --format='value(status.url)')
PROJECT_NUMBER=$(gcloud projects describe $PROJECT --format='value(projectNumber)')
URL2=https://detection-analyst-$PROJECT_NUMBER.$REGION.run.app
printf '[{"origin":["%s","%s"],"method":["PUT"],"responseHeader":["Content-Type","x-goog-content-length-range"],"maxAgeSeconds":3600}]' "$URL1" "$URL2" > cors.json
gcloud storage buckets update gs://$BUCKET --cors-file=cors.json && rm cors.json

# The app's service account: use the bucket, and sign URLs as itself
# (Cloud Run credentials hold no private key, so signing goes through IAM).
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member=serviceAccount:$SA --role=roles/storage.objectAdmin
gcloud iam service-accounts add-iam-policy-binding $SA \
  --member=serviceAccount:$SA --role=roles/iam.serviceAccountTokenCreator

# The job, from the image the service runs. Its /tmp is memory too: size it for
# the largest capture plus Zeek's logs (8 GiB covers 2 GB captures).
IMAGE=$(gcloud run services describe detection-analyst --region $REGION \
  --format='value(spec.template.spec.containers[0].image)')
gcloud run jobs deploy da-score --image $IMAGE --region $REGION --service-account $SA \
  --command python --args=-m,src.ingest.job \
  --memory 8Gi --cpu 4 --task-timeout 3600 --max-retries 0 \
  --set-env-vars DA_UPLOAD_BUCKET=$BUCKET,DA_MAX_UPLOAD_MB=2048

# The app may start that job with an override (the upload's id).
gcloud run jobs add-iam-policy-binding da-score --region $REGION \
  --member=serviceAccount:$SA --role=roles/run.jobsExecutorWithOverrides

# Point the service at both.
gcloud run services update detection-analyst --region $REGION --update-env-vars \
  DA_UPLOAD_BUCKET=$BUCKET,DA_SCORE_JOB=projects/$PROJECT/locations/$REGION/jobs/da-score,DA_MAX_UPLOAD_MB=2048
```

Each new deploy of the service builds a new image: run the `gcloud run jobs
deploy` line again afterwards so the job scores with the same code.

If an upload fails at once with "the upload was interrupted", the browser blocked
the transfer: check the address in the browser bar is one of the CORS origins
(`gcloud storage buckets describe gs://$BUCKET --format="default(cors_config)"`). A failed
upload shows its reason in the page; the job's full log is under Cloud Run ->
Jobs -> da-score -> Executions.

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
- The demo data is one simulated day. Testers can also upload their own pcap.
- Uploads: up to 2 GB (`DA_MAX_UPLOAD_MB`), 5 per tester. The size cap is part of
  the signed URL, so the bucket itself refuses a larger file, and the job checks
  again. Scoring takes minutes for a 1 GB capture (Zeek reads every packet).
  Each upload starts its own job execution, so several can run at once.
- Scored stores stay in the bucket for 7 days (lifecycle rule) and survive
  restarts; the web instance keeps a cached copy under `/tmp`. The pcap is
  deleted as soon as it is scored, whether scoring worked or not.
- An upload is private to the tester who sent it, but it is not encrypted or
  scrubbed. Tell testers not to upload captures with sensitive traffic.
