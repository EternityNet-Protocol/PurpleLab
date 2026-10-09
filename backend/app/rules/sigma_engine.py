from dataclasses import dataclass, field
from typing import Any

from app.rules.matcher import RuleMatcher
from app.rules.sigma_parser import SigmaRule


@dataclass
class FieldMatch:
    field: str
    actual: Any
    expected: Any
    modifier: str | None = None


@dataclass
class RuleEvaluation:
    matched: bool
    rule_key: str
    matched_fields: list[FieldMatch] = field(default_factory=list)
    reason: str = ""


class SigmaEngine:
    """Evaluate Sigma-style rules against raw or normalized flat event dictionaries."""

    def __init__(self, rules: list[SigmaRule] | None = None):
        self.rules = rules or []

    def add(self, rule: SigmaRule) -> None:
        self.rules.append(rule)

    def evaluate(self, event: dict[str, Any]) -> list[RuleEvaluation]:
        results = [self.evaluate_rule(rule, event) for rule in self.rules]
        return [result for result in results if result.matched]

    def evaluate_rule(self, rule: SigmaRule, event: dict[str, Any]) -> RuleEvaluation:
        if not self._logsource_matches(rule.logsource, event):
            return RuleEvaluation(False, rule.key, reason="logsource mismatch")
        match = RuleMatcher([rule])._match_rule(rule, event)
        fields = []
        if match.matched:
            for field_name, actual in match.matched_fields.items():
                selection = next(
                    (
                        value
                        for selector in rule.selection.values()
                        if isinstance(selector, dict)
                        for key, value in selector.items()
                        if key.split("|", 1)[0] == field_name
                    ),
                    None,
                )
                modifier = next(
                    (
                        key.split("|", 1)[1]
                        for selector in rule.selection.values()
                        if isinstance(selector, dict)
                        for key in selector
                        if key.split("|", 1)[0] == field_name and "|" in key
                    ),
                    None,
                )
                fields.append(FieldMatch(field_name, actual, selection, modifier))
        return RuleEvaluation(match.matched, rule.key, fields, match.reason)

    @staticmethod
    def _logsource_matches(logsource: dict[str, Any], event: dict[str, Any]) -> bool:
        product = str(logsource.get("product", "")).casefold()
        if not product:
            return True
        source = str(event.get("source", "")).casefold()
        channel = str(event.get("Channel") or event.get("channel") or "").casefold()
        if product in {"windows", "windows_security"}:
            return "windows" in source or "windows" in channel or "sysmon" in source
        if product in {"zeek", "suricata"}:
            return product in source or product in str(event.get("_source", "")).casefold()
        if not (product in source or product in channel or not (source or channel)):
            return False
        category = str(logsource.get("category", "")).casefold()
        event_category = event.get("category")
        expected_categories = {
            "process_creation": {"1", "system_activity"},
            "process_access": {"1", "system_activity"},
            "registry_set": {"1", "system_activity"},
            "file_event": {"1", "system_activity"},
            "network_connection": {"4", "network_activity"},
            "dns": {"4", "network_activity"},
        }
        expected = expected_categories.get(category)
        return not expected or event_category is None or str(event_category).casefold() in expected