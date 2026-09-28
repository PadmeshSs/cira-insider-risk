"""Which model is served, and from where (Chapter 8, N21, N28).

Resolution order, first match wins:

1. ``CIRA_SERVED_MODEL=<model_name>:<registry_version>`` (for example
   ``tabnet:v0005``), with an optional ``CIRA_SHADOW_MODEL`` in the same
   form. For rollback and tests. The status and every batch runlog line say
   the pin came from the environment, not from the recorded decision.
2. The decision file written by ``python -m app.scoring.select``
   (``experiments/chapter8_serving_decision.json`` unless
   ``CIRA_SERVING_DECISION`` points elsewhere): ``outcome.served`` and
   ``outcome.shadow``.
3. Nothing: the service starts unavailable and says why. It never falls
   back to "latest" or to a default model.

The registry root is ``MODEL_PATH`` (default ``models/saved_models``).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from app.feature_engineering.common import repo_root

from .contracts import ModelPin

DECISION_FILE = "chapter8_serving_decision.json"


def default_decision_path() -> Path:
    return repo_root() / "experiments" / DECISION_FILE


def default_registry_root() -> Path:
    return repo_root() / "models" / "saved_models"


@dataclass(frozen=True)
class ServingConfig:
    served: ModelPin | None
    shadows: tuple[ModelPin, ...] = ()
    registry_root: Path = field(default_factory=default_registry_root)
    source: str = "none"
    decision_path: Path | None = None
    decision_rule: str | None = None
    problem: str | None = None


def _pins_from_decision(path: Path) -> tuple[ModelPin, tuple[ModelPin, ...], str | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    outcome = data.get("outcome") or {}
    served = outcome.get("served")
    if not served:
        raise ValueError(f"{path} has no outcome.served")
    pin = ModelPin(served["model_name"], served["registry_version"])
    shadow = outcome.get("shadow")
    shadows = (ModelPin(shadow["model_name"], shadow["registry_version"]),) if shadow else ()
    return pin, shadows, (data.get("rule") or {}).get("version")


def resolve_serving_config(env: Mapping[str, str] | None = None) -> ServingConfig:
    env = os.environ if env is None else env
    registry_root = Path(env.get("MODEL_PATH") or default_registry_root())
    decision_path = Path(env.get("CIRA_SERVING_DECISION") or default_decision_path())

    if env.get("CIRA_SERVED_MODEL"):
        try:
            served = ModelPin.parse(env["CIRA_SERVED_MODEL"])
            shadows = (ModelPin.parse(env["CIRA_SHADOW_MODEL"]),) if env.get("CIRA_SHADOW_MODEL") else ()
        except ValueError as exc:
            return ServingConfig(None, (), registry_root, "env", None, None, f"CIRA_SERVED_MODEL / CIRA_SHADOW_MODEL: {exc}")
        return ServingConfig(served, shadows, registry_root, "env", None, None, None)

    if not decision_path.exists():
        return ServingConfig(None, (), registry_root, "none", decision_path, None,
                             f"no serving decision at {decision_path}; run `python -m app.scoring.select` first")
    try:
        served, shadows, rule = _pins_from_decision(decision_path)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return ServingConfig(None, (), registry_root, "decision_file", decision_path, None, f"unreadable decision file: {exc}")
    return ServingConfig(served, shadows, registry_root, "decision_file", decision_path, rule, None)
