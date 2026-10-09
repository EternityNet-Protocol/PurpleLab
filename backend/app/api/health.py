from fastapi import APIRouter


router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "purplelab"}


@router.get("/ready")
async def ready() -> dict[str, str]:
    return {"status": "ready"}