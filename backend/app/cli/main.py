import argparse
import asyncio
import json
import sys

from app.collectors.registry import available_collectors
from app.config import get_settings
from app.coverage.attck import list_techniques
from app.coverage.metrics import compute_coverage
from app.database.repositories import CoverageRepository, ExecutionRepository, ScenarioRepository
from app.database.session import session_scope
from app.rules.sigma_parser import sync_rules_to_db
from app.runner.engine import SimulationRunner, run_all_eligible
from app.scenarios.registry import ScenarioRegistry


def command_scenarios(_args) -> int:
    for scenario in ScenarioRegistry().all():
        negative = " [negative control]" if scenario.is_negative_control else ""
        print(f"{scenario.key:38s} {scenario.attck_technique or '-':12s} {scenario.severity}{negative}")
        print(f"  {scenario.name}")
    return 0


async def command_run(args) -> int:
    settings = get_settings()
    registry = ScenarioRegistry()
    scenario = registry.get(args.scenario)
    if scenario is None:
        print(f"Scenario not found: {args.scenario}", file=sys.stderr)
        return 1
    async with session_scope() as session:
        await registry.sync_to_db(session)
        await sync_rules_to_db(session, settings.rules_dir)
        await session.commit()
        execution = await SimulationRunner(session).run_scenario(scenario, actor=args.actor)
        print(json.dumps({
            "run_id": execution.run_id,
            "status": execution.status,
            "outcome": execution.outcome,
            "detection_latency_ms": execution.detection_latency_ms,
        }, indent=2))
        return 0 if execution.outcome in {"detected", "negative_pass"} else 2


async def command_run_all(args) -> int:
    async with session_scope() as session:
        await sync_rules_to_db(session, get_settings().rules_dir)
        executions = await run_all_eligible(session, actor=args.actor)
    detected = sum(execution.outcome == "detected" for execution in executions)
    print(f"Executed {len(executions)} eligible scenarios; detected {detected}.")
    return 0


async def command_coverage(_args) -> int:
    async with session_scope() as session:
        scenarios = await ScenarioRepository(session).list()
        executions = await ExecutionRepository(session).list(limit=1000)
    print(json.dumps(compute_coverage(scenarios, executions).to_dict(), indent=2))
    return 0


def command_techniques(_args) -> int:
    for technique in list_techniques():
        print(f"{technique['id']:12s} {technique['tactic']:25s} {technique['name']}")
    return 0


def command_collectors(_args) -> int:
    for name in available_collectors():
        print(name)
    return 0


async def command_snapshot(_args) -> int:
    async with session_scope() as session:
        scenarios = await ScenarioRepository(session).list()
        executions = await ExecutionRepository(session).list(limit=1000)
        metrics = compute_coverage(scenarios, executions)
        await CoverageRepository(session).add(
            detection_rate=metrics.detection_rate,
            telemetry_availability=metrics.telemetry_availability,
            rule_match_rate=metrics.rule_match_rate,
            false_positive_rate=metrics.false_positive_rate,
            avg_latency_ms=metrics.avg_latency_ms,
            reliability_score=0.0,
            attck_coverage=metrics.by_technique,
            detail=metrics.to_dict(),
        )
    print("Coverage snapshot recorded.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="purplelab", description="PurpleLab operator CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    scenarios = commands.add_parser("scenarios", help="List scenario definitions")
    scenarios.set_defaults(handler=command_scenarios)
    run = commands.add_parser("run", help="Run one scenario")
    run.add_argument("scenario")
    run.add_argument("--actor", default="cli")
    run.set_defaults(handler=command_run)
    run_all = commands.add_parser("run-all", help="Run eligible positive scenarios")
    run_all.add_argument("--actor", default="cli")
    run_all.set_defaults(handler=command_run_all)
    coverage = commands.add_parser("coverage", help="Show coverage metrics")
    coverage.set_defaults(handler=command_coverage)
    techniques = commands.add_parser("techniques", help="List ATT&CK reference techniques")
    techniques.set_defaults(handler=command_techniques)
    collectors = commands.add_parser("collectors", help="List registered collectors")
    collectors.set_defaults(handler=command_collectors)
    snapshot = commands.add_parser("snapshot", help="Save a coverage snapshot")
    snapshot.set_defaults(handler=command_snapshot)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = args.handler(args)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


if __name__ == "__main__":
    sys.exit(main())