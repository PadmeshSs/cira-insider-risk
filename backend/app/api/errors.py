"""Service errors and database failures -> HTTP responses.

A database that cannot be reached is a 503 with ``component: database``,
never an empty list and never a 500 that hides the cause (Architecture §36).
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from app.services.errors import ServiceError, Unauthorized

log = logging.getLogger("cira.api")


def _db_unavailable(exc: Exception) -> JSONResponse:
    first = (str(exc).splitlines() or [""])[0][:200]
    return JSONResponse(status_code=503, content={"detail": {
        "code": "database_unavailable", "component": "database",
        "message": f"PostgreSQL could not answer ({type(exc).__name__}: {first}); nothing was read or written"}})


def install(app: FastAPI) -> None:
    @app.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError):
        headers = {"WWW-Authenticate": "Bearer"} if isinstance(exc, Unauthorized) else None
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.to_dict()}, headers=headers)

    @app.exception_handler(DBAPIError)
    async def dbapi_error(request: Request, exc: DBAPIError):
        if exc.connection_invalidated or type(exc).__name__ in ("OperationalError", "InterfaceError"):
            return _db_unavailable(exc)
        log.exception("database error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": {"code": "database_error",
                                                                 "message": f"{type(exc).__name__}"}})

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_error(request: Request, exc: SQLAlchemyError):
        log.exception("database error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": {"code": "database_error",
                                                                 "message": f"{type(exc).__name__}"}})

    @app.exception_handler(OSError)
    async def os_error(request: Request, exc: OSError):        # asyncpg: connection refused, unreachable host
        return _db_unavailable(exc)

    @app.exception_handler(TimeoutError)
    async def timeout_error(request: Request, exc: TimeoutError):
        return _db_unavailable(exc)
