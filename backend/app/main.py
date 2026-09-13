from fastapi import FastAPI

from app.database.models import Configuration, User


app = FastAPI(
    title="CIRA Insider Risk Analytics",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "cira-backend",
    }


# Future routers will be registered here.
# Chapter 13 will add the full API integration.