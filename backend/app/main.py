from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app.database.models import Configuration, MITREMapping, User  # noqa: F401  (registers ORM metadata)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the served anomaly model once, at startup (HCEA §8).

    Never per request. If it cannot be loaded the API still starts, the
    service is marked unavailable with the reason, and no score is ever
    produced (Architecture §36). Chapter 13 adds the scoring routes; they
    will read ``app.state.scoring``.
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
    yield
    app.state.scoring = None
    app.state.cri = None
    app.state.mitre = None


app = FastAPI(
    title="CIRA Insider Risk Analytics",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request) -> dict:
    service = getattr(request.app.state, "scoring", None)
    model = service.status() if service is not None else {"status": "unavailable", "reason": "scoring service not started"}
    cri = getattr(request.app.state, "cri", None)
    mitre = getattr(request.app.state, "mitre", None)
    # The top-level status keeps its Chapter 8 meaning (anomaly model loaded);
    # the CRI reports its own status until Chapter 13 adds the risk routes.
    return {
        "status": "healthy" if model["status"] == "loaded" else "degraded",
        "service": "cira-backend",
        "anomaly_model": model,
        "cri": cri.status() if cri is not None else {"status": "unavailable", "reason": "CRI not started"},
        "mitre": mitre.status() if mitre is not None else {"status": "unavailable", "reason": "MITRE not started"},
    }


# Future routers will be registered here.
# Chapter 13 will add the full API integration.
