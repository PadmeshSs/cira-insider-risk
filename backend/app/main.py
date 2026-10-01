from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

import app.database.models  # noqa: F401  (registers ORM metadata)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the served anomaly model once, at startup (HCEA §8).

    Never per request. If it cannot be loaded the API still starts, the
    service is marked unavailable with the reason, and no score is ever
    produced (Architecture §36). The Chapter 13 routes read these runtimes
    through ``app.api.deps.get_runtimes``.
    """
    from app.core.runtime import apply_thread_caps

    apply_thread_caps()
    from app.scoring.serving_config import resolve_serving_config
    from app.scoring.service import AnomalyScoringService

    app.state.scoring = AnomalyScoringService.load(resolve_serving_config())

    # Chapter 9: the CRI calibration must belong to the model served now
    # (N29). A missing or mismatched calibration does not stop the API; the
    # ``cri`` block of /health says why, and no risk score is produced.
    from app.cri.runtime import CRIRuntime

    app.state.cri = CRIRuntime.load(app.state.scoring)

    # Chapter 10: the technique table and the MITRE reference. Model-free
    # (N42), so it loads whatever model is served; if it cannot load, the
    # ``mitre`` block of /health says why and no mitre_context is produced.
    from app.mitre.runtime import MitreRuntime

    app.state.mitre = MitreRuntime.load()

    # Chapter 11: the explainer for the model served now (N30): TreeSHAP for
    # XGBoost, masks for TabNet. If it cannot be built, the API still starts,
    # the ``explainability`` block of /health says why, and an alert keeps its
    # score and context with its explanation deferred (Architecture §36).
    from app.explainability.runtime import ExplainRuntime

    app.state.explain = ExplainRuntime.load(app.state.scoring)

    # Chapter 12: the newest alert run for the profile, if it was built for
    # the model served now (N28). Alerts are stored in PostgreSQL by
    # `python -m app.alerts.load`; /health probes the database separately.
    from app.alerts.runtime import AlertRuntime

    app.state.alerts = AlertRuntime.load(app.state.scoring)
    yield
    app.state.scoring = None
    app.state.cri = None
    app.state.mitre = None
    app.state.explain = None
    app.state.alerts = None
    # /health opens pooled PostgreSQL connections on this event loop; close
    # them here so none outlives the loop (a test client starts a new loop
    # per `with` block).
    from app.database.session import engine

    await engine.dispose()


app = FastAPI(
    title="CIRA Insider Risk Analytics",
    version="0.13.0",
    lifespan=lifespan,
    description=("Context-aware insider risk analytics on CERT r4.2. Anomaly scores are ranking scores, not "
                 "probabilities; the CRI is a separate 0-100 value (N20, N34). Every list is paginated with a "
                 "server-side cap (HCEA §13)."),
)

from app.api import errors as api_errors  # noqa: E402
from app.api.deps import get_app_settings, get_engine, get_runtimes  # noqa: E402
from app.api.v1 import api_router  # noqa: E402

api_errors.install(app)


def _cors_origins() -> list[str]:
    from app.core.config import settings

    return [o.strip() for o in (settings.cors_origins or "").split(",") if o.strip()]


if _cors_origins():
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(CORSMiddleware, allow_origins=_cors_origins(), allow_credentials=False,
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

app.include_router(api_router)


@app.get("/health", include_in_schema=False)
async def health(request: Request) -> dict:
    """Same body as /api/v1/health; kept at the root for Docker healthchecks and Chapters 8-12."""
    from app.services.health import health as build

    overrides = request.app.dependency_overrides
    engine = overrides.get(get_engine, get_engine)()
    settings = overrides.get(get_app_settings, get_app_settings)()
    return await build(get_runtimes(request), engine=engine, secret=settings.secret_key)
