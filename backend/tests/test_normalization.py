import pytest

from app.api.normalization import normalize
from app.normalization.mapper import EventMapper, event_fingerprint
from app.normalization.schemas import EventCategory


def test_sysmon_process_maps_to_canonical_fields():
    raw = {
        "EventID": "1",
        "Image": r"C:\Windows\System32\cmd.exe",
        "ParentImage": r"C:\Program Files\PurpleLab\lab.exe",
        "CommandLine": "cmd.exe /c echo fixture",
        "User": r"LAB\analyst",
        "ProcessId": "1234",
        "UtcTime": "2024-01-01T00:00:00Z",
        "Computer": "lab-host",
    }

    event = EventMapper().map(raw, source="sysmon")

    assert event.process is not None
    assert event.process.name == raw["Image"]
    assert event.process.pid == 1234
    assert event.actor.user == raw["User"]
    assert event.actor.parent_process_name == raw["ParentImage"]
    assert event.device.hostname == "lab-host"
    assert event.category == EventCategory.SYSTEM_ACTIVITY
    assert event.flat["process.name"] == raw["Image"]


def test_windows_network_event_maps_ip_and_port_types():
    event = EventMapper().map(
        {
            "EventID": "3",
            "SourceIp": "10.0.0.5",
            "SourcePort": "55000",
            "DestinationIp": "192.0.2.55",
            "DestinationPort": "4444",
            "Protocol": "tcp",
        },
        source="sysmon",
    )

    assert event.network is not None
    assert event.network.src.ip == "10.0.0.5"
    assert event.network.src.port == 55000
    assert event.network.dst.ip == "192.0.2.55"
    assert event.network.dst.port == 4444
    assert event.flat["network.dst.ip"] == "192.0.2.55"


def test_nested_ecs_event_and_fingerprint():
    raw = {
        "@timestamp": "2024-01-01T00:00:00Z",
        "event": {"code": "1", "severity": "high"},
        "process": {"name": "cmd.exe", "pid": 4321, "parent": {"name": "explorer.exe"}},
        "host": {"name": "endpoint-1", "os": {"full": "Windows"}},
        "Nested": {"Field": "value"},
    }
    mapper = EventMapper()
    first = mapper.map(raw, source="elastic")
    second = mapper.map(raw, source="elastic")

    assert first.event_id == "1"
    assert first.process is not None and first.process.pid == 4321
    assert first.actor.parent_process_name == "explorer.exe"
    assert first.device.hostname == "endpoint-1"
    assert first.flat["Nested.Field"] == "value"
    assert event_fingerprint(first) == event_fingerprint(second)


@pytest.mark.asyncio
async def test_normalization_api_returns_canonical_event_and_fingerprint():
    result = await normalize({"_source": "api-test", "EventID": "1", "Image": "cmd.exe"})

    assert result["event"]["source"] == "api-test"
    assert result["event"]["process"]["name"] == "cmd.exe"
    assert len(result["fingerprint"]) == 64