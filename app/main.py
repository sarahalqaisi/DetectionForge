from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import BASE_DIR, settings
from app.database import SessionLocal, init_db
from app.routers.web import router
from app.services.rules import import_rules


@asynccontextmanager
async def lifespan(_: FastAPI):
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
    return application


app = create_app()
