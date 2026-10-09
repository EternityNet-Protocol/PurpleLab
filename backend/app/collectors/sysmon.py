import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_run_id


logger = logging.getLogger(__name__)


class SysmonCollector(BaseCollector):
    name = "sysmon"

    def __init__(self, evtx_path: str | Path | None = None, max_events: int = 500):
        self.evtx_path = Path(evtx_path) if evtx_path else None
        self.max_events = max(1, min(max_events, 5000))

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if self.evtx_path is None or not self.evtx_path.is_file():
            return []
        try:
            from Evtx.Evtx import Evtx
        except ImportError as error:
            raise RuntimeError("Install the python-evtx package to read EVTX exports") from error

        collected = []
        with Evtx(str(self.evtx_path)) as evtx:
            for record in evtx.records():
                event = self._parse_record(record.xml())
                if event is None or run_id not in json.dumps(event, default=str):
                    continue
                collected.append(
                    CollectedEvent(
                        source="sysmon:evtx",
                        payload=event,
                        collected_at=datetime.now(timezone.utc),
                        raw=record.xml(),
                        tags=[str(self.evtx_path.name)],
                    )
                )
                if len(collected) >= self.max_events:
                    break
        return collected

    @staticmethod
    def _parse_record(xml_text: str) -> dict | None:
        namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        system = root.find(f"{namespace}System")
        if system is None:
            return None
        event = {}
        event_id = system.find(f"{namespace}EventID")
        channel = system.find(f"{namespace}Channel")
        computer = system.find(f"{namespace}Computer")
        created = system.find(f"{namespace}TimeCreated")
        if event_id is not None:
            event["EventID"] = event_id.text
        if channel is not None:
            event["Channel"] = channel.text
        if computer is not None:
            event["Computer"] = computer.text
        if created is not None:
            event["UtcTime"] = created.attrib.get("SystemTime")
        event_data = root.find(f"{namespace}EventData")
        if event_data is not None:
            for item in event_data.findall(f"{namespace}Data"):
                name = item.attrib.get("Name")
                if name and item.text is not None:
                    event[name] = item.text
        return event

    async def health(self) -> bool:
        return bool(self.evtx_path and self.evtx_path.is_file())