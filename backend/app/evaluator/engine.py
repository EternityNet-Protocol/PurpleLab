from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvaluationResult:
    outcome: str
    matched_rules: list[str] = field(default_factory=list)
    latency_ms: float | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


class EvaluationEngine:
    def __init__(self, latency_window_seconds: int = 30):
        self.latency_window_seconds = latency_window_seconds

    def evaluate(
        self,
        *,
        scenario_key: str,
        is_negative_control: bool,
        expected_rule_keys: list[str],
        generated_events: list[dict[str, Any]],
        collected_events: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> EvaluationResult:
        if not collected_events:
            return EvaluationResult("telemetry_unavailable", notes="no telemetry collected for run")
        if is_negative_control:
            if alerts:
                return EvaluationResult(
                    "negative_fail",
                    matched_rules=[alert.get("rule_key", "unknown") for alert in alerts],
                    evidence=alerts,
                    notes="alerts generated for negative control",
                )
            return EvaluationResult(
                "negative_pass", evidence=collected_events, notes="no alerts for negative control"
            )
        if not alerts:
            return EvaluationResult(
                "detection_failed", evidence=collected_events, notes="expected alert not generated"
            )

        matched_rules = [alert["rule_key"] for alert in alerts if alert.get("rule_key")]
        expected_hit = any(rule in expected_rule_keys for rule in matched_rules) if expected_rule_keys else True
        if not expected_hit:
            return EvaluationResult(
                "detection_failed",
                matched_rules=matched_rules,
                evidence=alerts,
                notes="alerts did not match expected rule",
            )

        latency_ms = self._compute_latency(generated_events, alerts)
        if latency_ms is not None and latency_ms > self.latency_window_seconds * 1000:
            return EvaluationResult(
                "detection_failed",
                matched_rules=matched_rules,
                latency_ms=latency_ms,
                evidence=alerts,
                notes="detection exceeded latency window",
            )
        return EvaluationResult(
            "detected", matched_rules, latency_ms, alerts, "expected alert produced within window"
        )

    @staticmethod
    def _compute_latency(
        events: list[dict[str, Any]], alerts: list[dict[str, Any]]
    ) -> float | None:
        event_times = [
            value for value in (_parse_ts(event.get("_emitted_at")) for event in events) if value
        ]
        alert_times = [
            value for value in (_parse_ts(alert.get("generated_at")) for alert in alerts) if value
        ]
        if not event_times or not alert_times:
            return None
        return (min(alert_times) - min(event_times)).total_seconds() * 1000