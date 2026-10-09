from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from app.database.models import Execution, Scenario


@dataclass
class CoverageMetrics:
    total_scenarios: int = 0
    eligible_scenarios: int = 0
    executed_scenarios: int = 0
    detected_scenarios: int = 0
    detection_failed: int = 0
    telemetry_unavailable: int = 0
    blocked: int = 0
    not_tested: int = 0
    negative_controls: int = 0
    negative_passes: int = 0
    negative_failures: int = 0
    detection_rate: float = 0.0
    telemetry_availability: float = 0.0
    rule_match_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_latency_ms: float = 0.0
    by_technique: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_scenarios": self.total_scenarios,
            "eligible_scenarios": self.eligible_scenarios,
            "executed_scenarios": self.executed_scenarios,
            "detected_scenarios": self.detected_scenarios,
            "detection_failed": self.detection_failed,
            "telemetry_unavailable": self.telemetry_unavailable,
            "blocked": self.blocked,
            "not_tested": self.not_tested,
            "negative_controls": self.negative_controls,
            "negative_passes": self.negative_passes,
            "negative_failures": self.negative_failures,
            "detection_rate": round(self.detection_rate, 2),
            "telemetry_availability": round(self.telemetry_availability, 2),
            "rule_match_rate": round(self.rule_match_rate, 2),
            "false_positive_rate": round(self.false_positive_rate, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "by_technique": self.by_technique,
        }


def compute_coverage(
    scenarios: Iterable[Scenario], executions: Iterable[Execution]
) -> CoverageMetrics:
    scenarios = list(scenarios)
    executions = list(executions)
    metrics = CoverageMetrics(total_scenarios=len(scenarios))
    latest_by_scenario = {}
    for execution in sorted(executions, key=lambda item: item.started_at):
        latest_by_scenario[execution.scenario_id] = execution

    techniques = defaultdict(
        lambda: {"total": 0, "detected": 0, "failed": 0, "telemetry_unavailable": 0}
    )
    latencies = []
    for scenario in scenarios:
        technique = scenario.attck_technique or "unmapped"
        techniques[technique]["total"] += 1
        metrics.negative_controls += int(scenario.is_negative_control)
        execution = latest_by_scenario.get(scenario.id)
        if execution is None:
            metrics.not_tested += 1
            continue

        metrics.executed_scenarios += 1
        if execution.outcome == "detected":
            metrics.detected_scenarios += 1
            techniques[technique]["detected"] += 1
            if execution.detection_latency_ms is not None:
                latencies.append(execution.detection_latency_ms)
        elif execution.outcome == "telemetry_unavailable":
            metrics.telemetry_unavailable += 1
            techniques[technique]["telemetry_unavailable"] += 1
        elif execution.outcome == "blocked":
            metrics.blocked += 1
        elif execution.outcome == "negative_pass":
            metrics.negative_passes += 1
        elif execution.outcome == "negative_fail":
            metrics.negative_failures += 1
        else:
            metrics.detection_failed += 1
            techniques[technique]["failed"] += 1

    metrics.eligible_scenarios = sum(not scenario.is_negative_control for scenario in scenarios)
    positive_runs = [
        run for run in executions if run.outcome in {"detected", "detection_failed"}
    ]
    if positive_runs:
        metrics.detection_rate = sum(run.outcome == "detected" for run in positive_runs) / len(positive_runs) * 100
    if executions:
        metrics.telemetry_availability = sum(run.telemetry_available for run in executions) / len(executions) * 100
        metrics.rule_match_rate = sum(bool(run.matched_rule_keys) for run in executions) / len(executions) * 100
    if metrics.negative_controls:
        metrics.false_positive_rate = metrics.negative_failures / metrics.negative_controls * 100
    if latencies:
        metrics.avg_latency_ms = sum(latencies) / len(latencies)

    for counts in techniques.values():
        counts["coverage_percent"] = round(counts["detected"] / counts["total"] * 100, 2)
    metrics.by_technique = dict(techniques)
    return metrics