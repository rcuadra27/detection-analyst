"""Test setup: a stub scenario and logs in a temp directory.

Environment variables are set before any src.agent module is imported, so tests
never touch a real scenario in data/scenario or real logs in logs/.
"""

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_TMP = Path(tempfile.mkdtemp(prefix="da-tests-"))
os.environ["DA_SCENARIO_DIR"] = str(_TMP / "scenario")
os.environ["DA_LOG_DIR"] = str(_TMP / "logs")
os.chdir(REPO_ROOT)
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402

from src.agent import scenario  # noqa: E402

scenario.build("stub", seed=13)


@pytest.fixture
def tmp_root() -> Path:
    return _TMP
