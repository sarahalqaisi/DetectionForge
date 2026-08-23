from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import BASE_DIR, settings
from app.database import SessionLocal, init_db
from app.routers.web import router
from app.services.rules import import_rules


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.app_env == "production" and settings.secret_key in {"development-only-change-me", "change-this-before-production", "replace-this-in-production"}:
        raise RuntimeError("SECRET_KEY must be configured for production")
    init_db()
    with SessionLocal() as db:
        import_rules(db)
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        description="Defensive detection engineering, event correlation, incident management, and MITRE ATT&CK coverage platform.",
        version="1.0.0",
        lifespan=lifespan,
    )
    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        same_site="lax",
        https_only=settings.app_env == "production",
    )
    application.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
    application.include_router(router)

    def apply_security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        return response

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > settings.max_upload_mb * 1024 * 1024:
            from fastapi.responses import JSONResponse
            return apply_security_headers(JSONResponse({"detail": "Request exceeds the configured size limit"}, status_code=413))
        response = await call_next(request)
        return apply_security_headers(response)
    return application


app = create_app()
