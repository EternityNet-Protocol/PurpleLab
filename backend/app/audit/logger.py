from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories import AuditRepository


class AuditLogger:
    def __init__(self, db: AsyncSession):
        self.repository = AuditRepository(db)

    async def record(
        self,
        *,
        action: str,
        actor: str = "system",
        target: str | None = None,
        status: str = "ok",
        detail: dict[str, Any] | None = None,
    ) -> None:
        await self.repository.log(
            action=action,
            actor=actor,
            target=target,
            status=status,
            detail=detail,
        )