from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.coverage.attck import list_techniques
from app.coverage.metrics import compute_coverage
from app.database.repositories import CoverageRepository, ExecutionRepository, ScenarioRepository
from app.database.session import get_db


router = APIRouter(prefix="/coverage", tags=["coverage"])


async def _coverage(db: AsyncSession):
    scenarios = await ScenarioRepository(db).list()
    executions = await ExecutionRepository(db).list(limit=1000)
    return compute_coverage(scenarios, executions)


@router.get("")
async def get_coverage(db: AsyncSession = Depends(get_db)):
    return (await _coverage(db)).to_dict()


@router.get("/attck")
async def get_attck():
    return {"techniques": list_techniques()}


@router.get("/history")
async def get_history(
    limit: int = Query(default=50, ge=1, le=500), db: AsyncSession = Depends(get_db)
):
    rows = await CoverageRepository(db).history(limit=limit)
    return [
        {
            "taken_at": row.taken_at.isoformat(),
            "detection_rate": row.detection_rate,
            "telemetry_availability": row.telemetry_availability,
            "rule_match_rate": row.rule_match_rate,
            "false_positive_rate": row.false_positive_rate,
            "avg_latency_ms": row.avg_latency_ms,
            "reliability_score": row.reliability_score,
        }
        for row in rows
    ]


@router.post("/snapshot")
async def take_snapshot(db: AsyncSession = Depends(get_db)):
    metrics = await _coverage(db)
    data = metrics.to_dict()
    snapshot = await CoverageRepository(db).add(
        detection_rate=metrics.detection_rate,
        telemetry_availability=metrics.telemetry_availability,
        rule_match_rate=metrics.rule_match_rate,
        false_positive_rate=metrics.false_positive_rate,
        avg_latency_ms=metrics.avg_latency_ms,
        reliability_score=0.0,
        attck_coverage=metrics.by_technique,
        detail=data,
    )
    await db.commit()
    return {"id": str(snapshot.id), "taken_at": snapshot.taken_at.isoformat()}