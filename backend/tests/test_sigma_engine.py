import base64
from pathlib import Path

from app.rules.sigma_engine import SigmaEngine
from app.rules.sigma_parser import load_rules, parse_sigma


def _rule(field_expression: str, expected: str, *, product: str = ""):
    logsource = f"logsource:\n  product: {product}\n" if product else ""
    return parse_sigma(
        f"title: Modifier test\nid: modifier-test\n{logsource}"
        f"detection:\n  selection:\n    {field_expression}: {expected}\n  condition: selection\n"
    )


def test_string_modifiers_and_regex():
    tests = [
        ("CommandLine|contains", "needle", {"CommandLine": "prefix NEEDLE suffix"}),
        ("Image|startswith", r"C:\Windows", {"Image": r"C:\Windows\cmd.exe"}),
        ("Image|endswith", "cmd.exe", {"Image": "C:\\Windows\\cmd.exe"}),
        ("CommandLine|re", r"\d{3,4}", {"CommandLine": "pid=1234"}),
    ]
    for field, expected, event in tests:
        assert SigmaEngine([_rule(field, expected)]).evaluate(event)


def test_cidr_modifier():
    rule = _rule("SourceIp|cidr", "192.0.2.0/24")
    engine = SigmaEngine([rule])
    assert engine.evaluate({"SourceIp": "192.0.2.42"})
    assert not engine.evaluate({"SourceIp": "198.51.100.42"})


def test_base64_and_base64offset_modifiers():
    base64_rule = _rule("Payload|base64", "mimikatz")
    encoded = base64.b64encode(b"mimikatz").decode("ascii")
    assert SigmaEngine([base64_rule]).evaluate({"Payload": encoded})

    offset_rule = _rule("Payload|base64offset", "needle")
    offset_encoded = base64.b64encode(b" needle").decode("ascii")
    assert SigmaEngine([offset_rule]).evaluate({"Payload": offset_encoded})


def test_windash_modifier_matches_slash_style_flags():
    rule = _rule("CommandLine|windash", "-encodedcommand")
    assert SigmaEngine([rule]).evaluate({"CommandLine": "/encodedcommand"})


def test_all_modifier_requires_every_expected_value():
    rule = parse_sigma("""title: All values\nid: all-values\ndetection:\n  selection:\n    CommandLine|contains|all:\n      - powershell\n      - bypass\n  condition: selection\n""")
    engine = SigmaEngine([rule])
    assert engine.evaluate({"CommandLine": "powershell.exe -bypass"})
    assert not engine.evaluate({"CommandLine": "powershell.exe -noprofile"})


def test_named_selection_boolean_condition():
    rule = parse_sigma("""title: Alternatives\nid: alternatives\ndetection:\n  process:\n    EventID: '1'\n  network:\n    EventID: '3'\n  condition: process or network\n""")
    assert SigmaEngine([rule]).evaluate({"EventID": "3"})
    assert not SigmaEngine([rule]).evaluate({"EventID": "5"})


def test_selection_wildcard_quantifiers():
    all_rule = parse_sigma("""title: All selections\nid: all-selections\ndetection:\n  selection_process:\n    EventID: '1'\n  selection_network:\n    Protocol: tcp\n  condition: all of selection*\n""")
    one_rule = parse_sigma("""title: One selection\nid: one-selection\ndetection:\n  selection_process:\n    EventID: '1'\n  selection_network:\n    Protocol: tcp\n  condition: 1 of selection*\n""")
    both_event = {"EventID": "1", "Protocol": "tcp"}
    process_only = {"EventID": "1", "Protocol": "udp"}

    assert SigmaEngine([all_rule]).evaluate(both_event)
    assert not SigmaEngine([all_rule]).evaluate(process_only)
    assert SigmaEngine([one_rule]).evaluate(process_only)


def test_advanced_catalog_loads_recursively_without_field_mapping_yaml():
    rule_dir = Path(__file__).resolve().parents[2] / "rules" / "sigma"
    keys = {rule.key for rule in load_rules(rule_dir)}
    assert {"lsass_suspicious_access", "suspicious_dns_query", "credential_dump_tool"} <= keys
    assert "field_mappings" not in keys