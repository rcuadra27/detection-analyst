"""
Run Zeek over a pcap and load its logs.

Zeek writes JSON logs into a working directory: conn.log (flow assembly, state,
bytes, packets, service), http.log, ftp.log, and unsw.log from
zeek/unsw_features.zeek (TTL, windows, ISNs, timing, retransmissions).

The Zeek binary is found from $ZEEK_BIN, then PATH, then /opt/zeek/bin/zeek.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pandas as pd

SCRIPT = Path(__file__).parent / "zeek" / "unsw_features.zeek"
LOGS = ("conn", "http", "ftp", "unsw", "other")


class ZeekNotFound(RuntimeError):
    pass


def zeek_bin() -> str:
    cands = [os.environ.get("ZEEK_BIN"), shutil.which("zeek"), "/opt/zeek/bin/zeek"]
    for c in cands:
        if c and Path(c).exists():
            return c
    raise ZeekNotFound(
        "Zeek not found. Install it (https://docs.zeek.org/en/current/install.html) "
        "or set ZEEK_BIN to the zeek binary.")


def run_zeek(pcap: str | Path, workdir: str | Path) -> Path:
    """Run Zeek on `pcap`, writing JSON logs into `workdir`. Returns workdir.

    -C ignores bad checksums: capture files routinely carry offloaded checksums,
    and UNSW-NB15's do. Without it Zeek silently drops those packets.
    """
    pcap = Path(pcap).resolve()
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    for name in LOGS:
        (workdir / f"{name}.log").unlink(missing_ok=True)
    cmd = [zeek_bin(), "-C", "-r", str(pcap), "LogAscii::use_json=T", str(SCRIPT.resolve())]
    proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"zeek failed ({proc.returncode}): {proc.stderr.strip()[-2000:]}")
    if not (workdir / "conn.log").exists():
        raise RuntimeError(f"zeek produced no conn.log for {pcap}. stderr: {proc.stderr[-500:]}")
    return workdir


def read_log(workdir: str | Path, name: str) -> pd.DataFrame:
    """Load one JSON Zeek log. A log Zeek did not write (no HTTP seen, say) is empty."""
    path = Path(workdir) / f"{name}.log"
    if not path.exists():
        return pd.DataFrame()
    rows = [json.loads(line) for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")]
    return pd.DataFrame(rows)


def read_logs(workdir: str | Path) -> dict[str, pd.DataFrame]:
    return {name: read_log(workdir, name) for name in LOGS}
