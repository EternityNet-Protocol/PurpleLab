import json
from datetime import datetime, timezone
from pathlib import Path

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_run_id


class ZeekCollector(BaseCollector):
    """Read-only collector for local Zeek TSV logs."""

    name = "zeek"
    DEFAULT_KINDS = ("conn", "dns", "http", "ssl", "files")

    def __init__(
        self,
        log_dir: str | Path | None = None,
        kinds: tuple[str, ...] | None = None,
        max_events: int = 500,
    ):
        self.log_dir = Path(log_dir) if log_dir else None
        self.kinds = kinds or self.DEFAULT_KINDS
        if any(kind not in self.DEFAULT_KINDS for kind in self.kinds):
            raise ValueError("Unsupported Zeek log kind")
        self.max_events = max(1, min(max_events, 5000))

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if self.log_dir is None or not self.log_dir.is_dir():
            return []
        events = []
        for kind in self.kinds:
            path = self.log_dir / f"{kind}.log"
            if not path.is_file():
                continue
            events.extend(self._read_log(path, kind, run_id, self.max_events - len(events)))
            if len(events) >= self.max_events:
                break
        return events

    @staticmethod
    def _read_log(path: Path, kind: str, run_id: str, limit: int) -> list[CollectedEvent]:
        if limit <= 0:
            return []
        fields: list[str] = []
        events = []
        scanned = 0
        scan_limit = max(limit * 100, 1000)
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            for line in log_file:
                scanned += 1
                if scanned > scan_limit:
                    break
                line = line.rstrip("\r\n")
                if not line:
                    continue
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue
                if line.startswith("#") or not fields:
                    continue
                values = line.split("\t")
                if len(values) != len(fields):
                    continue
                payload = dict(zip(fields, values))
                payload["_zeek_kind"] = kind
                if run_id not in json.dumps(payload, ensure_ascii=True):
                    continue
                events.append(
                    CollectedEvent(
                        source=f"zeek:{kind}",
                        payload=payload,
                        collected_at=datetime.now(timezone.utc),
                        raw=line,
                    )
                )
                if len(events) >= limit:
                    break
        return events

    async def health(self) -> bool:
        return bool(self.log_dir and self.log_dir.is_dir())