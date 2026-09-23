import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def _isolated_runlog(tmp_path, monkeypatch):
    """Never let a test append to the real experiments/runlog.jsonl."""
    monkeypatch.setenv("CIRA_RUNLOG", str(tmp_path / "runlog.jsonl"))
