from fastapi import APIRouter

from app.api import collectors, coverage, executions, health, normalization, rules, scenarios


router = APIRouter()
router.include_router(health.router)
router.include_router(scenarios.router, prefix="/api")
router.include_router(executions.router, prefix="/api")
router.include_router(coverage.router, prefix="/api")
router.include_router(normalization.router, prefix="/api")
router.include_router(collectors.router, prefix="/api")
router.include_router(rules.router, prefix="/api")