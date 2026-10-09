import json
import re
from datetime import datetime, timezone
from pathlib import Path

from app.collectors.base import BaseCollector, CollectedEvent


class FixtureCollector(BaseCollector):
    name = "fixture"

    def __init__(self, fixtures_dir: str | Path = "fixtures"):
        self.root = Path(fixtures_dir).resolve()
        self.events_dir = self.root / "events"
        self.alerts_dir = self.root / "alerts"
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.alerts_dir.mkdir(parents=True, exist_ok=True)

    def _run_path(self, directory: Path, run_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("Invalid run identifier")
        return directory / f"{run_id}.jsonl"

    def write_event(self, event: dict) -> Path:
        run_id = event.get("PurpleLab", {}).get("run_id", "")
        path = self._run_path(self.events_dir, run_id)
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, default=str) + "\n")
        return path

    def write_alert(self, alert: dict) -> Path:
        path = self._run_path(self.alerts_dir, alert.get("run_id", ""))
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(alert, default=str) + "\n")
        return path

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        path = self._run_path(self.events_dir, run_id)
        if not path.exists():
            return []
        collected = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("PurpleLab", {}).get("scenario_key") != scenario_key:
                continue
            collected.append(
                CollectedEvent(
                    source=self.name,
                    payload=payload,
                    collected_at=datetime.now(timezone.utc),
                    raw=line,
                    tags=["PurpleLab.test", "fixture"],
                )
            )
        return collected

    async def collect_alerts(self, run_id: str) -> list[CollectedEvent]:
        path = self._run_path(self.alerts_dir, run_id)
        if not path.exists():
            return []
        return [
            CollectedEvent(
                source=f"{self.name}:alerts",
                payload=json.loads(line),
                collected_at=datetime.now(timezone.utc),
                raw=line,
            )
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]