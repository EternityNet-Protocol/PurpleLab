from fastapi import APIRouter, HTTPException

from app.collectors.registry import available_collectors, configured_collector
from app.config import get_settings


router = APIRouter(prefix="/collectors", tags=["collectors"])


@router.get("")
async def list_collectors():
    return {
        "configured": get_settings().default_collector,
        "available": available_collectors(),
    }


@router.get("/health")
async def collector_health():
    try:
        collector = configured_collector()
        healthy = await collector.health()
    except (ValueError, OSError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"collector": collector.name, "healthy": healthy}