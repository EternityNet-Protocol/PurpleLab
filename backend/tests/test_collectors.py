import json

import pytest

from app.collectors.elastic import ElasticCollector
from app.collectors.registry import available_collectors, configured_collector
from app.collectors.suricata import SuricataCollector
from app.collectors.utils import validate_readonly_endpoint, validate_run_id
from app.collectors.zeek import ZeekCollector
from app.config import Settings
from app.runner.safety_gate import SafetyGate
from app.scenarios.models import ScenarioDefinition
from app.collectors.sysmon import SysmonCollector


RUN_ID = "0123456789abcdef0123456789abcdef"


def test_collector_configuration_defaults_to_fixture():
    assert configured_collector(Settings()).name == "fixture"
    assert {"elastic", "splunk", "sentinel", "sysmon", "zeek", "suricata"} <= set(available_collectors())


def test_collector_endpoints_and_run_ids_are_validated():
    assert validate_run_id(RUN_ID) == RUN_ID
    with pytest.raises(ValueError):
        validate_run_id("bad-run-id")
    with pytest.raises(ValueError):
        validate_readonly_endpoint("http://elastic.example")
    assert validate_readonly_endpoint("http://127.0.0.1:9200") == "http://127.0.0.1:9200"


@pytest.mark.asyncio
async def test_zeek_collector_reads_only_correlated_records(tmp_path):
    log = tmp_path / "dns.log"
    log.write_text(
        "#fields\tts\tquery\tuid\n"
        f"1710000000.0\tpurplelab-{RUN_ID}.top\tC1\n"
        "1710000001.0\tbenign.example\tC2\n",
        encoding="utf-8",
    )
    events = await ZeekCollector(tmp_path, kinds=("dns",)).collect(RUN_ID, "dns-test")
    assert len(events) == 1
    assert events[0].payload["query"] == f"purplelab-{RUN_ID}.top"


@pytest.mark.asyncio
async def test_suricata_collector_reads_correlated_eve_json(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text(
        "\n".join(
            [
                json.dumps({"event_type": "dns", "dns": {"rrname": f"{RUN_ID}.top"}}),
                json.dumps({"event_type": "dns", "dns": {"rrname": "benign.example"}}),
            ]
        ),
        encoding="utf-8",
    )
    events = await SuricataCollector(path).collect(RUN_ID, "dns-test")
    assert len(events) == 1
    assert events[0].source == "suricata:dns"


def test_sysmon_evtx_record_parser_extracts_event_data():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>host-1</Computer><TimeCreated SystemTime="2024-01-01T00:00:00Z" /></System>
      <EventData><Data Name="Image">C:\\Windows\\cmd.exe</Data><Data Name="ProcessId">42</Data></EventData>
    </Event>"""
    event = SysmonCollector._parse_record(xml)
    assert event is not None
    assert event["EventID"] == "1"
    assert event["Image"] == r"C:\Windows\cmd.exe"
    assert event["ProcessId"] == "42"