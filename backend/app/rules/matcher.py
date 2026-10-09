import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from app.rules.modifiers import match_value
from app.rules.sigma_parser import SigmaRule


@dataclass
class MatchResult:
    matched: bool
    rule_key: str
    matched_fields: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


def _get_field(event: dict[str, Any], path: str) -> Any:
    value: Any = event
    for index, part in enumerate(path.split(".")):
        if not isinstance(value, dict):
            return None
        if part in value:
            value = value[part]
        elif index == 0:
            value = next((item for key, item in value.items() if key.casefold() == part.casefold()), None)
        else:
            return None
    return value


def _match_selection(event: dict[str, Any], selection: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    matched_fields = {}
    for expression, expected in selection.items():
        field_name, *modifiers = expression.split("|")
        actual = _get_field(event, field_name)
        if not match_value(actual, expected, modifiers):
            return False, {}
        matched_fields[field_name] = actual
    return True, matched_fields


def _selection_condition(condition: str, results: dict[str, bool]) -> bool:
    condition = re.sub(r"\ball\s+of\s+them\b", "__ALL__", condition, flags=re.IGNORECASE)
    condition = re.sub(r"\b(\d+)\s+of\s+them\b", r"__COUNT_\1__", condition, flags=re.IGNORECASE)
    condition = re.sub(
        r"\b(all|\d+)\s+of\s+([\w-]+\*)",
        lambda match: (
            f"__ALL_PREFIX_{match.group(2)[:-1]}__"
            if match.group(1).casefold() == "all"
            else f"__COUNT_{match.group(1)}_PREFIX_{match.group(2)[:-1]}__"
        ),
        condition,
        flags=re.IGNORECASE,
    )
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|__[A-Z0-9_*]+__|[\w.*?-]+", condition, re.I)
    if not tokens or re.sub(r"\s+", "", "".join(tokens)).casefold() != re.sub(r"\s+", "", condition).casefold():
        return False
    position = 0

    def selector_value(token: str) -> bool:
        if token == "__ALL__":
            return bool(results) and all(results.values())
        if token.startswith("__ALL_PREFIX_"):
            prefix = token.removeprefix("__ALL_PREFIX_").removesuffix("__").casefold()
            selected = [value for name, value in results.items() if name.casefold().startswith(prefix)]
            return bool(selected) and all(selected)
        if token.startswith("__COUNT_"):
            value = token.removeprefix("__COUNT_").removesuffix("__")
            count_text, separator, prefix = value.partition("_PREFIX_")
            count = int(count_text)
            selected = results
            if separator:
                prefix = prefix.casefold()
                selected = {name: matched for name, matched in results.items() if name.casefold().startswith(prefix)}
            return sum(selected.values()) >= count
        names = [name for name in results if fnmatch.fnmatchcase(name, token)]
        return any(results[name] for name in names)

    def parse_primary() -> bool:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("Incomplete Sigma condition")
        token = tokens[position]
        position += 1
        if token.casefold() == "not":
            return not parse_primary()
        if token == "(":
            result = parse_or()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("Unclosed Sigma condition group")
            position += 1
            return result
        if token == "__ALL__" or token.startswith("__ALL_PREFIX_") or token.startswith("__COUNT_"):
            return selector_value(token)
        return selector_value(token)

    def parse_and() -> bool:
        nonlocal position
        result = parse_primary()
        while position < len(tokens) and tokens[position].casefold() == "and":
            position += 1
            right = parse_primary()
            result = result and right
        return result

    def parse_or() -> bool:
        nonlocal position
        result = parse_and()
        while position < len(tokens) and tokens[position].casefold() == "or":
            position += 1
            right = parse_and()
            result = result or right
        return result

    try:
        matched = parse_or()
    except (ValueError, IndexError):
        return False
    return matched and position == len(tokens)


class RuleMatcher:
    def __init__(self, rules: list[SigmaRule] | None = None):
        self.rules = rules or []

    def add(self, rule: SigmaRule) -> None:
        self.rules.append(rule)

    def match_event(self, event: dict[str, Any]) -> list[MatchResult]:
        return [result for rule in self.rules if (result := self._match_rule(rule, event)).matched]

    def _match_rule(self, rule: SigmaRule, event: dict[str, Any]) -> MatchResult:
        selection_results = {}
        matched_fields = {}
        for name, selection in rule.selection.items():
            if isinstance(selection, list):
                candidates = [item for item in selection if isinstance(item, dict)]
                candidate_matches = [_match_selection(event, item) for item in candidates]
                matches = [fields for matched, fields in candidate_matches if matched]
                selection_results[name] = bool(matches)
                if matches:
                    matched_fields.update(matches[0])
            elif isinstance(selection, dict):
                is_match, fields = _match_selection(event, selection)
                selection_results[name] = is_match
                if is_match:
                    matched_fields.update(fields)
        matched = _selection_condition(rule.condition, selection_results)
        return MatchResult(matched, rule.key, matched_fields if matched else {}, rule.condition)


def match_rule(rule: SigmaRule, event: dict[str, Any]) -> bool:
    return RuleMatcher([rule])._match_rule(rule, event).matched