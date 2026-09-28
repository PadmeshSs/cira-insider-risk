from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app.database.models import Configuration, User  # noqa: F401  (registers ORM metadata)


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
    yield
    app.state.scoring = None


app = FastAPI(
    title="CIRA Insider Risk Analytics",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request) -> dict:
    service = getattr(request.app.state, "scoring", None)
    model = service.status() if service is not None else {"status": "unavailable", "reason": "scoring service not started"}
    return {
        "status": "healthy" if model["status"] == "loaded" else "degraded",
        "service": "cira-backend",
        "anomaly_model": model,
    }


# Future routers will be registered here.
# Chapter 13 will add the full API integration.
