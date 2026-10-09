import logging
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_readonly_endpoint, validate_run_id


logger = logging.getLogger(__name__)
_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9-]{1,128}$")


class SentinelCollector(BaseCollector):
    """Read-only Log Analytics query integration for a configured workspace."""

    name = "sentinel"

    def __init__(
        self,
        workspace_id: str | None = None,
        token: str | None = None,
        endpoint: str = "https://api.loganalytics.io/v1",
        verify: bool = True,
        timeout: int = 30,
        max_events: int = 500,
    ):
        self.workspace_id = workspace_id
        if workspace_id and not _WORKSPACE_ID.fullmatch(workspace_id):
            raise ValueError("Invalid Sentinel workspace identifier")
        self.token = token
        self.endpoint = validate_readonly_endpoint(endpoint)
        self.verify = verify
        self.timeout = timeout
        self.max_events = max(1, min(max_events, 5000))

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        query = (
            "union withsource=Table * "
            f"| where tostring(pack_all()) contains '{run_id}' "
            f"| take {self.max_events}"
        )
        return await self._query(query, "sentinel:events")

    async def collect_alerts(self, run_id: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        query = (
            "SecurityAlert "
            f"| where tostring(ExtendedProperties) contains '{run_id}' "
            f"| take {self.max_events}"
        )
        return await self._query(query, "sentinel:alerts")

    async def _query(self, query: str, source: str) -> list[CollectedEvent]:
        if not self.workspace_id or not self.token:
            return []
        workspace = quote(self.workspace_id, safe="")
        url = f"{self.endpoint}/workspaces/{workspace}/query"
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout) as client:
                response = await client.post(
                    url, json={"query": query}, headers=self._headers()
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            logger.warning("Sentinel read-only query failed (%s)", type(error).__name__)
            return []

        events = []
        for table in payload.get("tables", []):
            columns = [str(column.get("name", "")) for column in table.get("columns", [])]
            for row in table.get("rows", []):
                events.append(
                    CollectedEvent(
                        source=source,
                        payload=dict(zip(columns, row)),
                        collected_at=datetime.now(timezone.utc),
                    )
                )
                if len(events) >= self.max_events:
                    return events
        return events

    async def health(self) -> bool:
        return bool(self.workspace_id and self.token and self.endpoint)