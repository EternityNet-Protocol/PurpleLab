from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories import RuleRepository
from app.database.session import get_db
from app.rules.sigma_parser import parse_sigma


router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("")
async def list_rules(db: AsyncSession = Depends(get_db)):
    rows = await RuleRepository(db).list()
    return [
        {
            "key": row.key,
            "title": row.title,
            "level": row.level,
            "format": row.format,
            "enabled": row.enabled,
            "tags": row.tags,
        }
        for row in rows
    ]


@router.post("/validate")
async def validate_rule(payload: dict):
    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="content required")
    try:
        rule = parse_sigma(content)
    except (ValueError, TypeError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"valid": True, "key": rule.key, "title": rule.title}