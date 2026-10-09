import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.logger import AuditLogger
from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.fixture import FixtureCollector
from app.collectors.registry import configured_collector
from app.config import get_settings
from app.database.models import Execution
from app.database.repositories import (
    AlertRepository,
    EvidenceRepository,
    ExecutionRepository,
    RuleRepository,
    ScenarioRepository,
)
from app.evaluator.engine import EvaluationEngine
from app.normalization.mapper import EventMapper
from app.rules.sigma_engine import SigmaEngine
from app.rules.sigma_parser import parse_sigma
from app.runner.event_generator import EventGenerator
from app.runner.safety_gate import SafetyGate
from app.scenarios.models import ScenarioDefinition


class SimulationRunner:
    def __init__(self, db: AsyncSession, collector: BaseCollector | None = None):
        self.db = db
        self.settings = get_settings()
        self.collector = collector or configured_collector(self.settings)
        self.safety = SafetyGate()
        self.audit = AuditLogger(db)

    async def run_scenario(
        self, scenario: ScenarioDefinition, *, actor: str = "system"
    ) -> Execution:
        scenario_row = await ScenarioRepository(self.db).get_by_key(scenario.key)
        if scenario_row is None:
            raise ValueError(f"scenario {scenario.key} not registered in database")

        executions = ExecutionRepository(self.db)
        run_id = uuid.uuid4().hex
        decision = self.safety.evaluate(scenario, target="fixture")
        if not decision.allowed:
            execution = await executions.create(
                scenario_id=scenario_row.id,
                run_id=run_id,
                status="blocked",
                outcome="blocked",
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
                context={"scenario_key": scenario.key, "reasons": decision.reasons},
            )
            await self.audit.record(
                action="execution.blocked",
                actor=actor,
                target=scenario.key,
                status="blocked",
                detail={"reasons": decision.reasons},
            )
            await self.db.commit()
            return execution

        execution = await executions.create(
            scenario_id=scenario_row.id,
            run_id=run_id,
            status="running",
            started_at=datetime.now(timezone.utc),
            context={"scenario_key": scenario.key, "collector": self.collector.name},
        )
        await self.audit.record(action="execution.start", actor=actor, target=scenario.key)
        await self.db.commit()
        try:
            await asyncio.wait_for(
                self._execute_pipeline(scenario, execution, run_id, actor),
                timeout=self.safety.timeout_for(scenario),
            )
        except asyncio.TimeoutError:
            execution.status = "failed"
            execution.outcome = "error"
            execution.error_message = "execution timeout"
            execution.finished_at = datetime.now(timezone.utc)
            await self.audit.record(
                action="execution.timeout", actor=actor, target=scenario.key, status="error"
            )
        except Exception as error:
            execution.status = "failed"
            execution.outcome = "error"
            execution.error_message = str(error)
            execution.finished_at = datetime.now(timezone.utc)
            await self.audit.record(
                action="execution.error",
                actor=actor,
                target=scenario.key,
                status="error",
                detail={"error": str(error)},
            )
        finally:
            await self.db.commit()
        return execution

    async def _execute_pipeline(
        self, scenario: ScenarioDefinition, execution: Execution, run_id: str, actor: str
    ) -> None:
        sink = self.collector.write_event if isinstance(self.collector, FixtureCollector) else None
        generated = EventGenerator(sink=sink).generate(scenario, run_id)
        collected: list[CollectedEvent] = await self.collector.collect(run_id, scenario.key)
        normalized_events = [EventMapper().map(item.payload, source=item.source) for item in collected]
        collected_payloads = [event.flat for event in normalized_events]
        execution.telemetry_available = bool(collected_payloads)

        evidence_repository = EvidenceRepository(self.db)
        for event in generated:
            await evidence_repository.add(
                execution_id=execution.id, kind="event", source="generator", payload=event
            )
        for item in collected:
            await evidence_repository.add(
                execution_id=execution.id,
                kind="telemetry",
                source=item.source,
                payload=item.payload,
                raw=item.raw,
            )

        rule_rows = await RuleRepository(self.db).list()
        rules = [parse_sigma(row.content, key=row.key) for row in rule_rows if row.enabled]
        matcher = SigmaEngine(rules)
        alerts: list[dict[str, Any]] = []
        alert_repository = AlertRepository(self.db)
        evidence_repository = EvidenceRepository(self.db)
        now = datetime.now(timezone.utc)
        for payload in collected_payloads:
            for match in matcher.evaluate(payload):
                matched_fields = {field.field: field.actual for field in match.matched_fields}
                alert = {
                    "rule_key": match.rule_key,
                    "title": f"Matched {match.rule_key}",
                    "severity": "medium",
                    "generated_at": now.isoformat(),
                    "run_id": run_id,
                    "matched_fields": matched_fields,
                }
                alerts.append(alert)
                await alert_repository.add(
                    execution_id=execution.id,
                    rule_key=match.rule_key,
                    title=alert["title"],
                    severity=alert["severity"],
                    generated_at=now,
                    raw=alert,
                )
                await evidence_repository.add(
                    execution_id=execution.id,
                    kind="alert",
                    source="rule_matcher",
                    payload=alert,
                )

        collect_alerts = getattr(self.collector, "collect_alerts", None)
        if collect_alerts is not None:
            external_alerts = await collect_alerts(run_id)
            alerts.extend(item.payload for item in external_alerts)
            for item in external_alerts:
                await alert_repository.add(
                    execution_id=execution.id,
                    rule_key=item.payload.get("rule_key"),
                    title=item.payload.get("title", "External alert"),
                    severity=item.payload.get("severity", "medium"),
                    generated_at=now,
                    raw=item.payload,
                )

        result = EvaluationEngine(scenario.latency_window_seconds).evaluate(
            scenario_key=scenario.key,
            is_negative_control=scenario.is_negative_control,
            expected_rule_keys=[scenario.expected_rule_key] if scenario.expected_rule_key else [],
            generated_events=generated,
            collected_events=collected_payloads,
            alerts=alerts,
        )
        execution.status = "completed"
        execution.outcome = result.outcome
        execution.finished_at = datetime.now(timezone.utc)
        execution.detection_latency_ms = result.latency_ms
        execution.matched_rule_keys = result.matched_rules
        execution.context = {
            **(execution.context or {}),
            "notes": result.notes,
            "evidence_count": len(result.evidence),
        }
        await self.audit.record(
            action="execution.complete",
            actor=actor,
            target=scenario.key,
            status=result.outcome,
            detail={"outcome": result.outcome, "matched_rules": result.matched_rules},
        )


async def run_all_eligible(db: AsyncSession, actor: str = "system") -> list[Execution]:
    from app.scenarios.registry import ScenarioRegistry

    registry = ScenarioRegistry()
    await registry.sync_to_db(db)
    await db.commit()
    results = []
    for scenario in registry.eligible():
        if scenario.is_negative_control:
            continue
        results.append(await SimulationRunner(db).run_scenario(scenario, actor=actor))
    return results