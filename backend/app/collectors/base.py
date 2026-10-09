from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CollectedEvent:
    source: str
    payload: dict[str, Any]
    collected_at: datetime
    raw: str | None = None
    tags: list[str] = field(default_factory=list)


class BaseCollector(ABC):
    name = "base"

    @abstractmethod
    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        raise NotImplementedError

    async def health(self) -> bool:
        return True

    async def collect_alerts(self, run_id: str) -> list[CollectedEvent]:
        return []