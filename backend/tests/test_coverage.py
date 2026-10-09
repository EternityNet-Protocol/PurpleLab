from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.coverage.metrics import compute_coverage
from app.database.models import Execution, Scenario


def _scenario(key, technique="T1059", negative=False):
    return Scenario(
        id=uuid4(), key=key, name=key, attck_technique=technique,
        is_negative_control=negative,
    )


def _execution(scenario, outcome, *, telemetry=True, rules=None, latency: float | None = 120.0):
    return Execution(
        id=uuid4(), scenario_id=scenario.id, run_id=uuid4().hex, status="completed",
        outcome=outcome, started_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        finished_at=datetime.now(timezone.utc), telemetry_available=telemetry,
        detection_latency_ms=latency, matched_rule_keys=rules or [],
    )


def test_coverage_distinguishes_detection_and_negative_control_metrics():
    detected = _scenario("detected")
    missed = _scenario("missed")
    negative = _scenario("negative", negative=True)
    executions = [
        _execution(detected, "detected", rules=["proc_rule"]),
        _execution(missed, "detection_failed", telemetry=False, latency=None),
        _execution(negative, "negative_fail", rules=["proc_rule"]),
    ]

    metrics = compute_coverage([detected, missed, negative], executions)

    assert metrics.detected_scenarios == 1
    assert metrics.detection_failed == 1
    assert metrics.negative_failures == 1
    assert metrics.detection_rate == 50
    assert metrics.false_positive_rate == 100
    assert metrics.by_technique["T1059"]["coverage_percent"] == 33.33


def test_untested_scenario_is_not_counted_as_detection_failure():
    scenario = _scenario("not-run")
    metrics = compute_coverage([scenario], [])

    assert metrics.not_tested == 1
    assert metrics.detection_failed == 0