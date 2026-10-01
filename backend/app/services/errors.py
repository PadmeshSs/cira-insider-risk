"""Errors the service layer raises. ``app.api.errors`` maps them to HTTP.

Services never import FastAPI, so the same functions run from a route, a
script or a test. Every error carries a machine-readable ``code``, a
sentence a person can act on, and, for an unavailable component, which
component it is (the same names as the /health blocks).
"""
from __future__ import annotations


class ServiceError(Exception):
    status_code = 500
    code = "error"

    def __init__(self, message: str, *, component: str | None = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.component = component
        if code:
            self.code = code

    def to_dict(self) -> dict:
        out = {"code": self.code, "message": self.message}
        if self.component:
            out["component"] = self.component
        return out


class NotFound(ServiceError):
    status_code = 404
    code = "not_found"


class BadRequest(ServiceError):
    status_code = 422
    code = "invalid_input"


class Conflict(ServiceError):
    """The request names something that exists but belongs to another model or run (N28)."""

    status_code = 409
    code = "conflict"


class Unauthorized(ServiceError):
    status_code = 401
    code = "unauthorized"


class Unavailable(ServiceError):
    """A component the request needs is not loaded or not reachable (Architecture §36).

    Never answered with a default value: the caller gets this and the reason.
    """

    status_code = 503
    code = "unavailable"
