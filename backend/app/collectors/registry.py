from typing import Any

from app.collectors.base import BaseCollector
from app.collectors.elastic import ElasticCollector
from app.collectors.fixture import FixtureCollector
from app.collectors.sentinel import SentinelCollector
from app.collectors.siem import SiemCollector
from app.collectors.splunk import SplunkCollector
from app.collectors.suricata import SuricataCollector
from app.collectors.sysmon import SysmonCollector
from app.collectors.zeek import ZeekCollector
from app.config import Settings, get_settings


COLLECTOR_TYPES: dict[str, type[BaseCollector]] = {
    "fixture": FixtureCollector,
    "sysmon": SysmonCollector,
    "siem": SiemCollector,
    "elastic": ElasticCollector,
    "splunk": SplunkCollector,
    "sentinel": SentinelCollector,
    "zeek": ZeekCollector,
    "suricata": SuricataCollector,
}


def build_collector(name: str, **kwargs: Any) -> BaseCollector:
    collector_type = COLLECTOR_TYPES.get(name.casefold())
    if collector_type is None:
        raise ValueError(f"Unknown collector: {name}")
    return collector_type(**kwargs)


def configured_collector(settings: Settings | None = None) -> BaseCollector:
    settings = settings or get_settings()
    common = {
        "verify": settings.collector_verify_tls,
        "timeout": settings.collector_timeout_seconds,
        "max_events": settings.max_collector_events,
    }
    name = settings.default_collector.casefold()
    if name == "fixture":
        return FixtureCollector(settings.fixture_path)
    if name == "sysmon":
        return SysmonCollector(settings.sysmon_evtx_path, settings.max_collector_events)
    if name == "siem":
        return SiemCollector(settings.siem_endpoint, settings.siem_api_key)
    if name == "elastic":
        return ElasticCollector(
            settings.elastic_endpoint,
            settings.elastic_api_key,
            settings.elastic_events_index,
            settings.elastic_alerts_index,
            **common,
        )
    if name == "splunk":
        return SplunkCollector(
            settings.splunk_endpoint,
            settings.splunk_token,
            **common,
        )
    if name == "sentinel":
        return SentinelCollector(
            settings.sentinel_workspace_id,
            settings.sentinel_token,
            settings.sentinel_endpoint,
            **common,
        )
    if name == "zeek":
        return ZeekCollector(settings.zeek_log_dir, max_events=settings.max_collector_events)
    if name == "suricata":
        return SuricataCollector(settings.suricata_eve_path, settings.max_collector_events)
    raise ValueError(f"Unknown collector: {settings.default_collector}")


def available_collectors() -> list[str]:
    return sorted(COLLECTOR_TYPES)