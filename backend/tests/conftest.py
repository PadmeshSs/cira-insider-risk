import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


@pytest.fixture(autouse=True)
def _isolated_runlog(tmp_path, monkeypatch):
    """Never let a test append to the real experiments/runlog.jsonl."""
    monkeypatch.setenv("CIRA_RUNLOG", str(tmp_path / "runlog.jsonl"))


@pytest.fixture(scope="session", autouse=True)
def _no_developer_cri_env():
    """Tests never see CRI_* or a CRI calibration pin from the developer's shell or .env.

    Session-scoped so it is in place before any module-scoped fixture runs;
    the sign-off script loads the repository .env into the environment its
    pytest step inherits, and old CRI_* weights there must not reach a test.
    Tests that need an override set it themselves with monkeypatch.
    """
    mp = pytest.MonkeyPatch()
    for key in [k for k in os.environ if k.startswith("CRI_") or k == "CIRA_CRI_CALIBRATION"]:
        mp.delenv(key)
    yield
    mp.undo()
