"""FastAPI application entry point.

Run (from the project root):

    uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.routes import router
from app.core.config import get_settings
from app.core.errors import register_error_handlers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

DESCRIPTION = """
**CyberRemediate 360** - vulnerability & cyber-risk management platform (portfolio / demo).

* Import normalised CSV/JSON or Nessus CSV exports (validated, idempotent UPSERT).
* Explainable 0-100 internal priority score (not a probability of compromise).
* Remediation workflow with enforced transitions, SLA and audit trail.
* CISO reporting (PDF / CSV / JSON).

Write endpoints require the `X-API-Key` header when `CR360_API_KEY` is configured.
`X-Actor` is a free-text audit label, **not** an authenticated identity.
"""


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CyberRemediate 360 API",
        version=__version__,
        description=DESCRIPTION,
        openapi_tags=[
            {"name": "system"},
            {"name": "assets"},
            {"name": "vulnerabilities"},
            {"name": "findings"},
            {"name": "imports"},
            {"name": "dashboard"},
            {"name": "remediations"},
            {"name": "audit"},
            {"name": "reports"},
        ],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "X-API-Key", "X-Actor"],
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    register_error_handlers(app)
    app.include_router(router)

    @app.get("/", include_in_schema=False)
    def root():
        return {"app": settings.app_name, "docs": "/docs", "health": "/api/v1/health"}

    return app


app = create_app()
