from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories import ScenarioRepository
from app.scenarios.loader import load_scenarios
from app.scenarios.models import ScenarioDefinition


class ScenarioRegistry:
    def __init__(self, definitions: list[ScenarioDefinition] | None = None):
        self._definitions = {item.key: item for item in (definitions or load_scenarios())}

    def all(self) -> list[ScenarioDefinition]:
        return list(self._definitions.values())

    def get(self, key: str) -> ScenarioDefinition | None:
        return self._definitions.get(key)

    def register(self, definition: ScenarioDefinition) -> None:
        self._definitions[definition.key] = definition

    def eligible(self) -> list[ScenarioDefinition]:
        return [item for item in self._definitions.values() if not item.prerequisites]

    async def sync_to_db(self, db: AsyncSession) -> int:
        repository = ScenarioRepository(db)
        for definition in self._definitions.values():
            values = definition.model_dump()
            event_fixture = values.pop("event_fixture")
            event_template = values.pop("event_template")
            event_count = values.pop("event_count")
            latency_window_seconds = values.pop("latency_window_seconds")
            values.pop("prerequisites")
            metadata = dict(values.get("metadata_json") or {})
            metadata.update(
                {
                    "event_fixture": event_fixture,
                    "event_template": event_template,
                    "event_count": event_count,
                    "latency_window_seconds": latency_window_seconds,
                }
            )
            values["metadata_json"] = metadata
            await repository.upsert(values)
        return len(self._definitions)


scenario_registry = ScenarioRegistry()