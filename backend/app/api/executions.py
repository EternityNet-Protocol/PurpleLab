from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.repositories import ExecutionRepository
from app.database.session import get_db, session_scope
from app.rules.sigma_parser import sync_rules_to_db
from app.runner.engine import SimulationRunner, run_all_eligible
from app.scenarios.registry import ScenarioRegistry


router = APIRouter(prefix="/executions", tags=["executions"])


def _execution_summary(execution) -> dict:
    return {
        "id": str(execution.id),
        "scenario_id": str(execution.scenario_id),
        "scenario_key": (execution.context or {}).get("scenario_key"),
        "run_id": execution.run_id,
        "status": execution.status,
        "outcome": execution.outcome,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
        "detection_latency_ms": execution.detection_latency_ms,
        "telemetry_available": execution.telemetry_available,
        "matched_rule_keys": execution.matched_rule_keys,
        "error_message": execution.error_message,
    }


@router.get("")
async def list_executions(
    limit: int = Query(default=100, ge=1, le=1000), db: AsyncSession = Depends(get_db)
):
    rows = await ExecutionRepository(db).list(limit=limit)
    return [_execution_summary(row) for row in rows]


@router.get("/{execution_id}")
async def get_execution(execution_id: UUID, db: AsyncSession = Depends(get_db)):
    execution = await ExecutionRepository(db).get(execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="execution not found")
    result = _execution_summary(execution)
    result.update(
        {
            "context": execution.context,
            "alerts": [
                {
                    "rule_key": alert.rule_key,
                    "title": alert.title,
                    "severity": alert.severity,
                    "generated_at": alert.generated_at.isoformat(),
                    "latency_ms": alert.latency_ms,
                }
                for alert in execution.alerts
            ],
            "evidence": [
                {
                    "kind": evidence.kind,
                    "source": evidence.source,
                    "collected_at": evidence.collected_at.isoformat(),
                    "payload": evidence.payload,
                }
                for evidence in execution.evidence
            ],
        }
    )
    return result


@router.post("/run/{scenario_key}")
async def run_scenario(scenario_key: str, db: AsyncSession = Depends(get_db)):
    settings = get_settings()
    registry = ScenarioRegistry()
    scenario = registry.get(scenario_key)
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"scenario {scenario_key} not found")
    await registry.sync_to_db(db)
    await sync_rules_to_db(db, settings.rules_dir)
    await db.commit()
    execution = await SimulationRunner(db).run_scenario(scenario)
    return _execution_summary(execution)


async def _run_all_background() -> None:
    async with session_scope() as session:
        await sync_rules_to_db(session, get_settings().rules_dir)
        await run_all_eligible(session)


@router.post("/run-all")
async def run_all(background: BackgroundTasks):
    background.add_task(_run_all_background)
    return {"status": "scheduled"}