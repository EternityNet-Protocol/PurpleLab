from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router
from app.config import get_settings
from app.database.models import Base
from app.database.session import engine, session_scope
from app.rules.sigma_parser import sync_rules_to_db
from app.scenarios.registry import ScenarioRegistry


settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with session_scope() as session:
        await ScenarioRegistry().sync_to_db(session)
        await sync_rules_to_db(session, settings.rules_dir)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description="Fixture-driven detection engineering validation platform",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/")
async def root() -> dict[str, str]:
    return {"name": settings.app_name, "version": "0.2.0", "docs": "/docs"}