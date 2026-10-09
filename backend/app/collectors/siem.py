from app.collectors.base import BaseCollector, CollectedEvent


class SiemCollector(BaseCollector):
    name = "siem"

    def __init__(self, endpoint: str | None = None, api_key: str | None = None):
        self.endpoint = endpoint
        self.api_key = api_key

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        return []

    async def health(self) -> bool:
        return bool(self.endpoint and self.api_key)