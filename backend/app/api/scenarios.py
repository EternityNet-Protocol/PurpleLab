from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories import ScenarioRepository
from app.database.session import get_db
from app.scenarios.models import ScenarioOut
from app.scenarios.registry import ScenarioRegistry


router = APIRouter(prefix="/scenarios", tags=["scenarios"])


@router.get("", response_model=list[ScenarioOut])
async def list_scenarios(db: AsyncSession = Depends(get_db)):
    return await ScenarioRepository(db).list()


@router.get("/{scenario_id}", response_model=ScenarioOut)
async def get_scenario(scenario_id: UUID, db: AsyncSession = Depends(get_db)):
    scenario = await ScenarioRepository(db).get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="scenario not found")
    return scenario


@router.post("/sync")
async def sync_scenarios(db: AsyncSession = Depends(get_db)):
    count = await ScenarioRegistry().sync_to_db(db)
    await db.commit()
    return {"synced": count}