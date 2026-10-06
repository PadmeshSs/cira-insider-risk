"""Chapter 15 fixtures: one stack per pytest session (HCEA §14: one PostgreSQL per run, not per test).

``stack`` builds raw CSV -> Chapters 5-12 -> fresh PostgreSQL -> load (see
``ch15_stack``). ``api`` starts the real FastAPI app, lifespan included, on
that database and runs a scenario through ``httpx.AsyncClient`` (``ch15_api``).

``CIRA_E2E_KEEP=1`` keeps the database and the world directory after the
session, for looking at what a failing test saw.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import ch15_stack  # noqa: E402
from ch15_api import run_api  # noqa: E402


def pytest_collection_modifyitems(items):
    for item in items:
        if "/e2e/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.e2e)


@pytest.fixture(scope="session")
def stack(tmp_path_factory):
    try:
        s = ch15_stack.build_stack(tmp_path_factory.mktemp("ch15"))
    except ch15_stack.StackUnavailable as exc:
        pytest.skip(str(exc))
    ch15_stack.write_manifest(s, s.root / "stack.json")
    yield s
    if os.getenv("CIRA_E2E_KEEP") != "1":
        s.db.drop()
    else:
        print(f"\n[e2e] kept database {s.db.name} ({s.db.kind}) and {s.root}")


@pytest.fixture(autouse=True)
def _api_env(request, monkeypatch):
    """The API's lifespan reads the pins from the environment and CERT_PROCESSED_DIR from settings."""
    if "stack" not in request.fixturenames:
        return
    s = request.getfixturevalue("stack")
    for k in [k for k in os.environ if k.startswith(("CRI_", "MITRE_"))]:
        monkeypatch.delenv(k)
    for k, v in ch15_stack.pins(s.root).items():
        monkeypatch.setenv(k, v)
    from app.core import config

    monkeypatch.setattr(config.settings, "cert_processed_dir", str(s.root / "processed"))


@pytest.fixture
def api(stack):
    """``api(scenario, **kw)`` runs a scenario against the stack."""
    return lambda scenario, **kw: run_api(stack, scenario, **kw)
