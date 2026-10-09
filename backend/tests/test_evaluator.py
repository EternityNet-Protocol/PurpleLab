from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.collectors.fixture import FixtureCollector
from app.database.models import AuditLog, Base, Rule, Scenario
from app.database.repositories import ExecutionRepository
from app.evaluator.engine import EvaluationEngine
from app.runner.engine import SimulationRunner
from app.scenarios.loader import load_scenarios
from app.scenarios.models import ScenarioDefinition


ROOT = Path(__file__).resolve().parents[2]


def test_evaluation_detected_within_latency_window():
    result = EvaluationEngine(latency_window_seconds=30).evaluate(
        scenario_key="scenario",
        is_negative_control=False,
        expected_rule_keys=["rule-a"],
        generated_events=[{"_emitted_at": 1000.0}],
        collected_events=[{"EventID": "1"}],
        alerts=[{"rule_key": "rule-a", "generated_at": "1970-01-01T00:16:40.250Z"}],
    )
    assert result.outcome == "detected"
    assert result.latency_ms == 250


def test_evaluation_keeps_telemetry_and_negative_outcomes_distinct():
    evaluator = EvaluationEngine()
    unavailable = evaluator.evaluate(
        scenario_key="scenario", is_negative_control=False, expected_rule_keys=["r"],
        generated_events=[], collected_events=[], alerts=[],
    )
    negative_pass = evaluator.evaluate(
        scenario_key="negative", is_negative_control=True, expected_rule_keys=[],
        generated_events=[], collected_events=[{"EventID": "1"}], alerts=[],
    )
    negative_fail = evaluator.evaluate(
        scenario_key="negative", is_negative_control=True, expected_rule_keys=[],
        generated_events=[], collected_events=[{"EventID": "1"}], alerts=[{"rule_key": "r"}],
    )
    assert unavailable.outcome == "telemetry_unavailable"
    assert negative_pass.outcome == "negative_pass"
    assert negative_fail.outcome == "negative_fail"


def test_scenario_files_validate_against_definition_model():
    scenarios = load_scenarios(ROOT / "scenarios")
    assert len(scenarios) == 4
    assert {scenario.key for scenario in scenarios} >= {
        "process_event_unusual_parent", "negative_control_benign_process"
    }


@pytest.mark.asyncio
async def test_runner_persists_detected_outcome_and_evidence(tmp_path):
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    scenario = ScenarioDefinition(
        key="runner-check",
        name="Runner integration check",
        expected_rule_key="runner-rule",
        event_fixture="unused.json",
        event_template={"EventID": "1", "Image": r"C:\Windows\System32\cmd.exe"},
        metadata_json={"approved": True},
    )
    async with sessions() as session:
        scenario_row = Scenario(key=scenario.key, name=scenario.name, expected_rule_key="runner-rule")
        session.add(scenario_row)
        session.add(Rule(
            key="runner-rule",
            title="Process test rule",
            content="""title: Process test rule\nid: runner-rule\ndetection:\n  selection:\n    EventID: '1'\n    Image|endswith: cmd.exe\n  condition: selection\n""",
        ))
        await session.commit()
        result = await SimulationRunner(
            session, collector=FixtureCollector(tmp_path / "fixtures")
        ).run_scenario(scenario)
        persisted = await ExecutionRepository(session).get(result.id)
        assert persisted is not None
        assert persisted.outcome == "detected"
        assert persisted.telemetry_available is True
        assert persisted.matched_rule_keys == ["runner-rule"]
        assert len(persisted.evidence) == 3
        assert len(persisted.alerts) == 1
        audit_entries = (await session.scalars(select(AuditLog))).all()
        assert any(entry.action == "execution.complete" for entry in audit_entries)
    await engine.dispose()