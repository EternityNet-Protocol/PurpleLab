import json
import logging
from datetime import datetime, timezone

import httpx

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_readonly_endpoint, validate_run_id


logger = logging.getLogger(__name__)


class SplunkCollector(BaseCollector):
    """Read-only Splunk export search; query values are restricted to run IDs."""

    name = "splunk"

    def __init__(
        self,
        endpoint: str | None = None,
        token: str | None = None,
        verify: bool = True,
        timeout: int = 30,
        max_events: int = 500,
    ):
        self.endpoint = validate_readonly_endpoint(endpoint)
        self.token = token
        self.verify = verify
        self.timeout = timeout
        self.max_events = max(1, min(max_events, 5000))

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        return await self._search(run_id, "events")

    async def collect_alerts(self, run_id: str) -> list[CollectedEvent]:
        return await self._search(run_id, "alerts")

    async def _search(self, run_id: str, kind: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if not self.endpoint or not self.token:
            return []
        index_clause = "index=notable" if kind == "alerts" else "index=*"
        query = f'search {index_clause} "{run_id}" | head {self.max_events}'
        url = f"{self.endpoint}/services/search/jobs/export"
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout) as client:
                response = await client.post(
                    url,
                    data={"search": query, "output_mode": "json", "earliest_time": "-1h"},
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            logger.warning("Splunk read-only search failed (%s)", type(error).__name__)
            return []

        events = []
        for line in response.text.splitlines():
            try:
                result = json.loads(line).get("result", {})
            except (json.JSONDecodeError, AttributeError):
                continue
            if isinstance(result, dict):
                events.append(
                    CollectedEvent(
                        source=f"splunk:{kind}",
                        payload=result,
                        collected_at=datetime.now(timezone.utc),
                    )
                )
            if len(events) >= self.max_events:
                break
        return events

    async def health(self) -> bool:
        if not self.endpoint or not self.token:
            return False
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.endpoint}/services/server/info", headers=self._headers()
                )
                return response.is_success
        except httpx.HTTPError:
            return False