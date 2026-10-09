from datetime import datetime, timezone
from typing import Sequence
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.models import (
    Alert,
    AuditLog,
    CoverageSnapshot,
    Evidence,
    Execution,
    Rule,
    Scenario,
)


class ScenarioRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list(self) -> Sequence[Scenario]:
        result = await self.db.execute(select(Scenario).order_by(Scenario.key))
        return result.scalars().all()

    async def get(self, scenario_id: UUID) -> Scenario | None:
        return await self.db.get(Scenario, scenario_id)

    async def get_by_key(self, key: str) -> Scenario | None:
        result = await self.db.execute(select(Scenario).where(Scenario.key == key))
        return result.scalar_one_or_none()

    async def upsert(self, data: dict) -> Scenario:
        existing = await self.get_by_key(data["key"])
        if existing:
            for key, value in data.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.now(timezone.utc)
            await self.db.flush()
            return existing
        scenario = Scenario(**data)
        self.db.add(scenario)
        await self.db.flush()
        return scenario


class RuleRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list(self) -> Sequence[Rule]:
        result = await self.db.execute(select(Rule).order_by(Rule.key))
        return result.scalars().all()

    async def get_by_key(self, key: str) -> Rule | None:
        result = await self.db.execute(select(Rule).where(Rule.key == key))
        return result.scalar_one_or_none()

    async def upsert(self, data: dict) -> Rule:
        existing = await self.get_by_key(data["key"])
        if existing:
            for key, value in data.items():
                setattr(existing, key, value)
            await self.db.flush()
            return existing
        rule = Rule(**data)
        self.db.add(rule)
        await self.db.flush()
        return rule


class ExecutionRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list(self, limit: int = 100) -> Sequence[Execution]:
        result = await self.db.execute(
            select(Execution)
            .order_by(Execution.started_at.desc())
            .limit(max(1, min(limit, 1000)))
        )
        return result.scalars().all()

    async def get(self, execution_id: UUID) -> Execution | None:
        statement = (
            select(Execution)
            .options(selectinload(Execution.alerts), selectinload(Execution.evidence))
            .where(Execution.id == execution_id)
        )
        result = await self.db.execute(statement)
        return result.scalar_one_or_none()

    async def create(self, **kwargs) -> Execution:
        execution = Execution(**kwargs)
        self.db.add(execution)
        await self.db.flush()
        return execution


class EvidenceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, **kwargs) -> Evidence:
        evidence = Evidence(**kwargs)
        self.db.add(evidence)
        await self.db.flush()
        return evidence


class AlertRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add(self, **kwargs) -> Alert:
        alert = Alert(**kwargs)
        self.db.add(alert)
        await self.db.flush()
        return alert


class CoverageRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def latest(self) -> CoverageSnapshot | None:
        result = await self.db.execute(
            select(CoverageSnapshot).order_by(CoverageSnapshot.taken_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    async def history(self, limit: int = 50) -> Sequence[CoverageSnapshot]:
        result = await self.db.execute(
            select(CoverageSnapshot)
            .order_by(CoverageSnapshot.taken_at.desc())
            .limit(max(1, min(limit, 500)))
        )
        return result.scalars().all()

    async def add(self, **kwargs) -> CoverageSnapshot:
        snapshot = CoverageSnapshot(**kwargs)
        self.db.add(snapshot)
        await self.db.flush()
        return snapshot


class AuditRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        *,
        action: str,
        actor: str = "system",
        target: str | None = None,
        status: str = "ok",
        detail: dict | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            action=action,
            actor=actor,
            target=target,
            status=status,
            detail=detail or {},
        )
        self.db.add(entry)
        await self.db.flush()
        return entry