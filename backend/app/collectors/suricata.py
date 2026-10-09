import json
from datetime import datetime, timezone
from pathlib import Path

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_run_id


class SuricataCollector(BaseCollector):
    """Read-only collector for local Suricata EVE JSON logs."""

    name = "suricata"

    def __init__(self, eve_path: str | Path | None = None, max_events: int = 500):
        self.eve_path = Path(eve_path) if eve_path else None
        self.max_events = max(1, min(max_events, 5000))

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if self.eve_path is None or not self.eve_path.is_file():
            return []
        events = []
        scanned = 0
        scan_limit = max(self.max_events * 100, 1000)
        with self.eve_path.open("r", encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                scanned += 1
                if scanned > scan_limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict) or run_id not in line:
                    continue
                event_type = payload.get("event_type", "unknown")
                events.append(
                    CollectedEvent(
                        source=f"suricata:{event_type}",
                        payload=payload,
                        collected_at=datetime.now(timezone.utc),
                        raw=line,
                    )
                )
                if len(events) >= self.max_events:
                    break
        return events

    async def health(self) -> bool:
        return bool(self.eve_path and self.eve_path.is_file())