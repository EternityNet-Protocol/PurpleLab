import logging
from datetime import datetime, timezone

import httpx

from app.collectors.base import BaseCollector, CollectedEvent
from app.collectors.utils import validate_readonly_endpoint, validate_run_id


logger = logging.getLogger(__name__)


class ElasticCollector(BaseCollector):
    """Read-only Elasticsearch search integration for correlated events/alerts."""

    name = "elastic"

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        events_index: str = "logs-*",
        alerts_index: str = ".alerts-security.alerts-*",
        verify: bool = True,
        timeout: int = 15,
        max_events: int = 500,
    ):
        self.endpoint = validate_readonly_endpoint(endpoint)
        self.api_key = api_key
        self.events_index = events_index
        self.alerts_index = alerts_index
        self.verify = verify
        self.timeout = timeout
        self.max_events = max(1, min(max_events, 5000))

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    async def collect(self, run_id: str, scenario_key: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if not self.endpoint:
            return []
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"PurpleLab.run_id": run_id}},
                        {"match_phrase": {"purplelab.run_id": run_id}},
                        {"term": {"correlation_id": run_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": self.max_events,
            "sort": [{"@timestamp": "asc"}],
        }
        return await self._search(self.events_index, query, "elastic:events")

    async def collect_alerts(self, run_id: str) -> list[CollectedEvent]:
        run_id = validate_run_id(run_id)
        if not self.endpoint:
            return []
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match_phrase": {"kibana.alert.ancestors.id": run_id}},
                        {"match_phrase": {"PurpleLab.run_id": run_id}},
                        {"term": {"correlation_id": run_id}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": self.max_events,
            "sort": [{"@timestamp": "asc"}],
        }
        return await self._search(self.alerts_index, query, "elastic:alerts")

    async def _search(self, index: str, query: dict, source: str) -> list[CollectedEvent]:
        url = f"{self.endpoint}/{index}/_search"
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout) as client:
                response = await client.post(url, json=query, headers=self._headers())
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as error:
            logger.warning("Elastic read-only search failed (%s)", type(error).__name__)
            return []
        return [
            CollectedEvent(
                source=source,
                payload=hit.get("_source", {}),
                collected_at=datetime.now(timezone.utc),
                raw=None,
                tags=[str(hit.get("_index", ""))],
            )
            for hit in data.get("hits", {}).get("hits", [])[: self.max_events]
            if isinstance(hit.get("_source"), dict)
        ]

    async def health(self) -> bool:
        if not self.endpoint:
            return False
        try:
            async with httpx.AsyncClient(verify=self.verify, timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.endpoint}/_cluster/health", headers=self._headers()
                )
                return response.is_success
        except httpx.HTTPError:
            return False