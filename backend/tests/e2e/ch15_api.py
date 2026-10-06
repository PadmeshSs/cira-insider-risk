"""Run the real FastAPI app (lifespan included) against a Chapter 15 stack's database.

Shared by the e2e tests and ``scripts/e2e_stack.py``. The engine is built like
``app.database.session``: asyncpg, 5 s connect timeout, ``pool_pre_ping``.
"""
from __future__ import annotations

import asyncio


class _Settings:
    def __init__(self, secret: str):
        from app.core.config import settings

        self.secret_key = secret
        self.access_token_minutes = 30
        self.cors_origins = settings.cors_origins


def run_api(stack, scenario, *, url: str | None = None, login: bool = True, pool_pre_ping: bool = True):
    """Start the real app on the stack's database (or ``url``) and run ``scenario(client, headers, engine)``.

    The engine is built like ``app.database.session``: asyncpg with a 5 s
    connect timeout and ``pool_pre_ping``, so outage behaviour matches the
    process uvicorn runs.
    """
    import httpx
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.api import deps
    from app.main import app

    async def go():
        engine = create_async_engine(url or stack.db.url, pool_pre_ping=pool_pre_ping, connect_args={"timeout": 5})
        maker = async_sessionmaker(engine, expire_on_commit=False)

        async def session():
            async with maker() as s:
                yield s

        app.dependency_overrides.update({deps.get_session: session, deps.get_engine: lambda: engine,
                                         deps.get_app_settings: lambda: _Settings(stack.secret)})
        try:
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://e2e", timeout=30) as client:
                    headers = {}
                    if login:
                        r = await client.post("/api/v1/auth/token",
                                              data={"username": stack.username, "password": stack.password})
                        assert r.status_code == 200, r.text
                        headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
                    return await scenario(client, headers, engine)
        finally:
            app.dependency_overrides.clear()
            await engine.dispose()

    return asyncio.run(go())
