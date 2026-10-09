import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.scenarios.models import ScenarioDefinition


def _substitute(value: Any, context: dict[str, Any]) -> Any:
    if not isinstance(value, str):
        return value
    rendered = value
    for key, replacement in context.items():
        rendered = rendered.replace(f"{{{{ {key} }}}}", str(replacement))
        rendered = rendered.replace(f"{{{{{key}}}}}", str(replacement))
    return rendered


def render_event(template: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    rendered = {}
    for key, value in template.items():
        if isinstance(value, dict):
            rendered[key] = render_event(value, context)
        elif isinstance(value, list):
            rendered[key] = [
                render_event(item, context) if isinstance(item, dict) else _substitute(item, context)
                for item in value
            ]
        else:
            rendered[key] = _substitute(value, context)
    return rendered


class EventGenerator:
    """Render harmless event data; this class never executes scenario actions."""

    def __init__(self, sink=None):
        self.sink = sink

    def generate(self, scenario: ScenarioDefinition, run_id: str) -> list[dict[str, Any]]:
        timestamp = datetime.now(timezone.utc)
        events = []
        for index in range(scenario.event_count):
            correlation_id = f"{run_id}-{index:03d}-{uuid.uuid4().hex[:8]}"
            context = {
                "run_id": run_id,
                "scenario_key": scenario.key,
                "event_index": index,
                "correlation_id": correlation_id,
                "timestamp": timestamp.isoformat(),
            }
            event = render_event(scenario.event_template, context)
            event.setdefault("EventID", "purplelab.test")
            event["PurpleLab"] = {
                "run_id": run_id,
                "scenario_key": scenario.key,
                "correlation_id": correlation_id,
                "test": True,
                "harmless": True,
            }
            event["_emitted_at"] = time.time()
            events.append(event)
            if self.sink is not None:
                self.sink(event)
        return events