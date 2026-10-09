from dataclasses import dataclass, field
from typing import Iterable

from app.config import get_settings
from app.scenarios.models import ScenarioDefinition


@dataclass
class SafetyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


class SafetyGate:
    def __init__(self, allowlist: Iterable[str] | None = None):
        settings = get_settings()
        self.allowlist = list(allowlist) if allowlist is not None else settings.lab_allowlist
        self.timeout = settings.execution_timeout_seconds
        self.max_events = settings.max_events_per_execution
        self.require_approval = settings.require_approval

    def evaluate(self, scenario: ScenarioDefinition, *, target: str = "fixture") -> SafetyDecision:
        reasons: list[str] = []
        if scenario.event_count > self.max_events:
            reasons.append(f"event_count {scenario.event_count} exceeds max {self.max_events}")
        if target not in self.allowlist and not target.startswith("fixture"):
            reasons.append(f"target '{target}' not in allowlist")
        if scenario.prerequisites and target != "fixture":
            reasons.append("scenario has unmet prerequisites")
        if self.require_approval and not scenario.metadata_json.get("approved", False):
            reasons.append("scenario not approved by policy")
        if target != "fixture":
            reasons.append("only fixture targets are enabled in this release")
        return SafetyDecision(allowed=not reasons, reasons=reasons)

    def timeout_for(self, scenario: ScenarioDefinition) -> int:
        return min(scenario.latency_window_seconds, self.timeout)