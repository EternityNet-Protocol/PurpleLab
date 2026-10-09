from app.rules.matcher import RuleMatcher
from app.rules.sigma_parser import parse_sigma
from app.runner.safety_gate import SafetyGate
from app.scenarios.models import ScenarioDefinition


PROCESS_RULE = """
title: Suspicious process launch
id: process-rule
detection:
  selection:
    EventID: "1"
    Image|endswith: '\\cmd.exe'
    ParentImage|contains: PurpleLab
  condition: selection
"""


def test_sigma_modifiers_match_process_event():
    matcher = RuleMatcher([parse_sigma(PROCESS_RULE)])
    matches = matcher.match_event({
        "EventID": "1",
        "Image": r"C:\Windows\System32\cmd.exe",
        "ParentImage": r"C:\Program Files\PurpleLab\fixture_parent.exe",
    })
    assert len(matches) == 1
    assert matches[0].rule_key == "process-rule"
    assert matches[0].matched_fields["EventID"] == "1"


def test_sigma_matcher_rejects_unmatched_parent():
    matcher = RuleMatcher([parse_sigma(PROCESS_RULE)])
    assert matcher.match_event({
        "EventID": "1", "Image": r"C:\Windows\System32\cmd.exe",
        "ParentImage": r"C:\Windows\explorer.exe",
    }) == []


def test_named_sigma_selections_support_boolean_conditions():
    rule = parse_sigma("""title: Alternative selection\nid: alternative\ndetection:\n  process:\n    EventID: '1'\n  network:\n    EventID: '3'\n  condition: process or network\n""")
    assert len(RuleMatcher([rule]).match_event({"EventID": "3"})) == 1


def test_safety_gate_denies_non_fixture_target():
    scenario = ScenarioDefinition(key="test", name="test", event_fixture="test.json")
    decision = SafetyGate().evaluate(scenario, target="10.20.30.40")
    assert decision.allowed is False
    assert any("fixture" in reason or "allowlist" in reason for reason in decision.reasons)