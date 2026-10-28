"""Where uploaded captures go, and how they get scored.

A pcap never passes through the web app on Cloud Run: a single request there is
capped at 32 MiB, and a UNSW capture is about 1 GB. Instead the app creates an
upload record, hands the browser a place to put the file, and starts a scoring
job when the browser says it is done. The job (src/ingest/job.py) runs the same
score_pcap as everywhere else and writes the store next to the record.

Two backends, one interface:

  LocalBackend  files under a directory. The browser uploads through the app
                (no request cap when running locally) and scoring runs in a
                background thread. For your machine and the tests.

  GCSBackend    a Cloud Storage bucket. The browser uploads straight to the
                bucket with a signed URL, and scoring runs as a Cloud Run Job
                with its own CPU, memory and time limit. For Cloud Run.

Layout (a directory, or a prefix in the bucket):

  uploads/<id>/status.json        owner, name, state, stage, summary or error
  uploads/<id>/capture.pcap       deleted as soon as it is scored
  uploads/<id>/store/flows.jsonl  what the agent's tools read
  uploads/<id>/store/meta.json

States: waiting_upload -> queued -> running -> done | error.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import threading
from pathlib import Path

STORE_FILES = ("flows.jsonl", "meta.json")
SIGNED_URL_MINUTES = 30


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class UploadBackend:
    """Interface shared by both backends."""

    max_bytes: int

    # --- records ---
    def write_status(self, ds_id: str, record: dict) -> None: ...
    def read_status(self, ds_id: str) -> dict | None: ...
    def list_status(self) -> list[dict]: ...

    def update_status(self, ds_id: str, **fields) -> dict:
        rec = self.read_status(ds_id) or {"dataset": ds_id}
        rec.update(fields, updated=_now())
        self.write_status(ds_id, rec)
        return rec

    # --- the pcap ---
    def upload_target(self, ds_id: str) -> dict: ...
    def pcap_size(self, ds_id: str) -> int | None: ...
    def fetch_pcap(self, ds_id: str, dest: Path) -> Path: ...
    def delete_pcap(self, ds_id: str) -> None: ...

    # --- the scored store ---
    def put_store(self, ds_id: str, store_dir: Path) -> None: ...
    def local_store(self, ds_id: str) -> Path: ...

    # --- scoring ---
    def start(self, ds_id: str) -> None: ...


# ------------------------------------------------------------------ local

class LocalBackend(UploadBackend):
    def __init__(self, root: Path, max_bytes: int):
        self.root = Path(root)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()        # one scoring job at a time

    def _dir(self, ds_id: str) -> Path:
        return self.root / ds_id

    def write_status(self, ds_id: str, record: dict) -> None:
        d = self._dir(ds_id)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / "status.json.tmp"
        tmp.write_text(json.dumps(record))
        tmp.replace(d / "status.json")

    def read_status(self, ds_id: str) -> dict | None:
        p = self._dir(ds_id) / "status.json"
        return json.loads(p.read_text()) if p.exists() else None

    def list_status(self) -> list[dict]:
        if not self.root.exists():
            return []
        return [json.loads(p.read_text()) for p in sorted(self.root.glob("*/status.json"))]

    def upload_target(self, ds_id: str) -> dict:
        # Through the app: there is no request cap outside Cloud Run.
        return {"url": f"/api/uploads/{ds_id}/data", "method": "PUT", "headers": {},
                "via_app": True}

    def pcap_path(self, ds_id: str) -> Path:
        return self._dir(ds_id) / "capture.pcap"

    def pcap_size(self, ds_id: str) -> int | None:
        p = self.pcap_path(ds_id)
        return p.stat().st_size if p.exists() else None

    def fetch_pcap(self, ds_id: str, dest: Path) -> Path:
        return self.pcap_path(ds_id)          # already local: read it in place

    def delete_pcap(self, ds_id: str) -> None:
        self.pcap_path(ds_id).unlink(missing_ok=True)

    def put_store(self, ds_id: str, store_dir: Path) -> None:
        out = self._dir(ds_id) / "store"
        out.mkdir(parents=True, exist_ok=True)
        for f in STORE_FILES:
            shutil.copyfile(Path(store_dir) / f, out / f)

    def local_store(self, ds_id: str) -> Path:
        return self._dir(ds_id) / "store"

    def start(self, ds_id: str) -> None:
        from src.ingest.job import process_upload

        def run():
            with self._lock:
                process_upload(self, ds_id)
        threading.Thread(target=run, name=f"score-{ds_id}", daemon=True).start()


# ------------------------------------------------------------------ Cloud Storage

class GCSBackend(UploadBackend):
    """Bucket storage, signed-URL uploads, scoring as a Cloud Run Job.

    `bucket` is a google.cloud.storage Bucket (or a test double with the same
    methods). `job` is the job's full name,
    projects/<project>/locations/<region>/jobs/<job>.
    """

    def __init__(self, bucket, job: str | None, max_bytes: int,
                 cache_dir: Path = Path("/tmp/da_cache"), session=None, credentials=None):
        self.bucket = bucket
        self.job = job
        self.max_bytes = max_bytes
        self.cache_dir = Path(cache_dir)
        self._session = session
        self._credentials = credentials

    @staticmethod
    def _key(ds_id: str, name: str) -> str:
        return f"uploads/{ds_id}/{name}"

    def write_status(self, ds_id: str, record: dict) -> None:
        self.bucket.blob(self._key(ds_id, "status.json")).upload_from_string(
            json.dumps(record), content_type="application/json")

    def read_status(self, ds_id: str) -> dict | None:
        b = self.bucket.blob(self._key(ds_id, "status.json"))
        return json.loads(b.download_as_text()) if b.exists() else None

    def list_status(self) -> list[dict]:
        return [json.loads(b.download_as_text())
                for b in self.bucket.list_blobs(prefix="uploads/")
                if b.name.endswith("/status.json")]

    def upload_target(self, ds_id: str) -> dict:
        """A v4 signed URL that lets the browser PUT one object, for 30 minutes.

        The size range header is part of the signature, so the bucket itself
        refuses a body larger than the limit."""
        headers = {"Content-Type": "application/octet-stream",
                   "x-goog-content-length-range": f"0,{self.max_bytes}"}
        blob = self.bucket.blob(self._key(ds_id, "capture.pcap"))
        kw = {}
        creds = self._credentials
        if creds is not None and not hasattr(creds, "sign_bytes"):
            # Cloud Run's metadata credentials hold no private key: sign through
            # the IAM API as the service account (needs Token Creator on itself).
            import google.auth.transport.requests
            creds.refresh(google.auth.transport.requests.Request())
            kw = {"service_account_email": creds.service_account_email,
                  "access_token": creds.token}
        url = blob.generate_signed_url(
            version="v4", expiration=dt.timedelta(minutes=SIGNED_URL_MINUTES),
            method="PUT", headers=headers, credentials=creds if "access_token" not in kw else None,
            **kw)
        return {"url": url, "method": "PUT", "headers": headers, "via_app": False}

    def pcap_size(self, ds_id: str) -> int | None:
        b = self.bucket.get_blob(self._key(ds_id, "capture.pcap"))
        return None if b is None else int(b.size)

    def fetch_pcap(self, ds_id: str, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.bucket.blob(self._key(ds_id, "capture.pcap")).download_to_filename(str(dest))
        return dest

    def delete_pcap(self, ds_id: str) -> None:
        b = self.bucket.blob(self._key(ds_id, "capture.pcap"))
        if b.exists():
            b.delete()

    def put_store(self, ds_id: str, store_dir: Path) -> None:
        for f in STORE_FILES:
            self.bucket.blob(self._key(ds_id, f"store/{f}")).upload_from_filename(
                str(Path(store_dir) / f))

    def local_store(self, ds_id: str) -> Path:
        """The agent's tools read files, so the web app keeps a local copy."""
        d = self.cache_dir / ds_id
        if not all((d / f).exists() for f in STORE_FILES):
            d.mkdir(parents=True, exist_ok=True)
            for f in STORE_FILES:
                self.bucket.blob(self._key(ds_id, f"store/{f}")).download_to_filename(str(d / f))
        return d

    def start(self, ds_id: str) -> None:
        """Run the scoring job for this upload (Cloud Run Admin API v2)."""
        if not self.job:
            raise RuntimeError("DA_SCORE_JOB is not set: no job to run.")
        session = self._session
        if session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            session = AuthorizedSession(creds)
        r = session.post(f"https://run.googleapis.com/v2/{self.job}:run",
                         json={"overrides": {"containerOverrides": [
                             {"env": [{"name": "DA_DATASET_ID", "value": ds_id}]}]}})
        if r.status_code >= 300:
            raise RuntimeError(f"starting the scoring job failed: {r.status_code} {r.text[:300]}")


# ------------------------------------------------------------------ choice

def backend_from_env() -> UploadBackend:
    """GCS when DA_UPLOAD_BUCKET is set (Cloud Run), a local directory otherwise."""
    max_bytes = int(os.environ.get("DA_MAX_UPLOAD_MB", "2048")) * 1024 * 1024
    bucket_name = os.environ.get("DA_UPLOAD_BUCKET")
    if bucket_name:
        import google.auth
        from google.cloud import storage
        creds, project = google.auth.default()
        bucket = storage.Client(project=project, credentials=creds).bucket(bucket_name)
        return GCSBackend(bucket, os.environ.get("DA_SCORE_JOB"), max_bytes, credentials=creds)
    return LocalBackend(Path(os.environ.get("DA_UPLOAD_DIR", "data/uploads")), max_bytes)
