"""
Score one uploaded capture: the work behind an upload, wherever it runs.

On Cloud Run this is the entrypoint of a Cloud Run Job (same image as the web
app), started once per upload with DA_DATASET_ID set:

    python -m src.ingest.job               # reads DA_DATASET_ID, DA_UPLOAD_BUCKET

Locally the web app calls process_upload in a background thread instead.

Steps: check the file arrived and is within the size limit; fetch it; check it
is a pcap; score it (Zeek -> features -> detector -> baseline); save the store;
record the summary. The pcap is deleted whatever happens. Errors are recorded in
the upload's status with a short message the page can show; the full error goes
to the job's log.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

# pcap (both byte orders, micro and nano) and pcapng
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
              b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")


class UploadRejected(Exception):
    """A problem with the upload itself; the message is shown to the tester."""


def score_pcap(*args, **kwargs):          # indirection so tests can swap the models
    from src.ingest.score import score_pcap as _score
    return _score(*args, **kwargs)


def process_upload(backend, ds_id: str) -> dict:
    status = backend.read_status(ds_id)
    if status is None:
        raise UploadRejected(f"no upload record for {ds_id}")
    work = Path(tempfile.mkdtemp(prefix=f"da-{ds_id}-"))
    try:
        backend.update_status(ds_id, state="running", stage="checking the file")
        size = backend.pcap_size(ds_id)
        if not size:
            raise UploadRejected("No file arrived for this upload.")
        if size > backend.max_bytes:
            raise UploadRejected(f"The file is larger than {backend.max_bytes // 2**20} MB.")
        pcap = backend.fetch_pcap(ds_id, work / "capture.pcap")
        with open(pcap, "rb") as fh:
            if fh.read(4) not in PCAP_MAGIC:
                raise UploadRejected("That file is not a pcap or pcapng capture.")

        backend.update_status(ds_id, stage="building flows with Zeek and scoring them")
        store = score_pcap(pcap, work / "store", name=status.get("name"))
        backend.update_status(ds_id, stage="saving the results")
        backend.put_store(ds_id, work / "store")
        m = store.meta
        summary = {"dataset": ds_id, "name": status.get("name"), "n_flows": m["n_flows"],
                   "n_flagged": m["n_flagged"], "false_positive_rate": m["false_positive_rate"],
                   "false_positive_rate_source": m["false_positive_rate_source"]}
        return backend.update_status(ds_id, state="done", stage=None, summary=summary)
    except UploadRejected as exc:
        return backend.update_status(ds_id, state="error", stage=None, message=str(exc))
    except Exception as exc:
        traceback.print_exc()
        return backend.update_status(
            ds_id, state="error", stage=None,
            message="The capture could not be processed. Check it is a valid pcap with "
                    f"IPv4 traffic. ({type(exc).__name__})")
    finally:
        backend.delete_pcap(ds_id)
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    from src.agent.uploads import backend_from_env
    ds_id = os.environ.get("DA_DATASET_ID") or (sys.argv[1] if len(sys.argv) > 1 else None)
    if not ds_id:
        print("set DA_DATASET_ID", file=sys.stderr)
        return 2
    rec = process_upload(backend_from_env(), ds_id)
    print({"dataset": ds_id, "state": rec.get("state"), "message": rec.get("message")}, flush=True)
    return 0 if rec.get("state") == "done" else 1


if __name__ == "__main__":
    sys.exit(main())
