import base64
import binascii
import fnmatch
import ipaddress
import re
from typing import Any, Callable


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _equal(actual: Any, expected: Any) -> bool:
    actual_text = _text(actual)
    expected_text = _text(expected)
    if "*" in expected_text or "?" in expected_text:
        return fnmatch.fnmatchcase(actual_text.casefold(), expected_text.casefold())
    return actual_text.casefold() == expected_text.casefold()


def contains(actual: Any, expected: Any) -> bool:
    return _text(expected).casefold() in _text(actual).casefold()


def startswith(actual: Any, expected: Any) -> bool:
    return _text(actual).casefold().startswith(_text(expected).casefold())


def endswith(actual: Any, expected: Any) -> bool:
    return _text(actual).casefold().endswith(_text(expected).casefold())


def regex_match(actual: Any, expected: Any) -> bool:
    try:
        return re.search(_text(expected), _text(actual), flags=re.IGNORECASE) is not None
    except re.error:
        return False


def cidr_match(actual: Any, expected: Any) -> bool:
    try:
        return ipaddress.ip_address(_text(actual)) in ipaddress.ip_network(_text(expected), strict=False)
    except ValueError:
        return False


def base64_match(actual: Any, expected: Any) -> bool:
    actual_text = _text(actual)
    expected_text = _text(expected)
    encoded = base64.b64encode(expected_text.encode("utf-8")).decode("ascii")
    if encoded.casefold() in actual_text.casefold():
        return True
    try:
        decoded = base64.b64decode(actual_text, validate=True).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return False
    return expected_text.casefold() in decoded.casefold()


def base64offset_match(actual: Any, expected: Any) -> bool:
    actual_text = _text(actual)
    expected_text = _text(expected)
    for offset in range(3):
        variant = (" " * offset + expected_text).encode("utf-8")
        encoded = base64.b64encode(variant).decode("ascii")
        if encoded.rstrip("=").casefold() in actual_text.casefold():
            return True
    return False


def windash_match(actual: Any, expected: Any) -> bool:
    text = _text(expected)
    variants = {
        text,
        text.replace("-", "/"),
        text.replace("/", "-"),
        text.replace("–", "/"),
    }
    return any(_equal(actual, variant) for variant in variants)


MODIFIERS: dict[str, Callable[[Any, Any], bool]] = {
    "contains": contains,
    "startswith": startswith,
    "endswith": endswith,
    "re": regex_match,
    "cidr": cidr_match,
    "base64": base64_match,
    "base64offset": base64offset_match,
    "windash": windash_match,
}


def _single_match(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if isinstance(actual, list):
        return any(_single_match(item, expected, modifiers) for item in actual)
    if not modifiers:
        return _equal(actual, expected)
    operation, *rest = modifiers
    if operation == "all":
        return _single_match(actual, expected, rest)
    modifier = MODIFIERS.get(operation)
    if modifier is None:
        return False
    return modifier(actual, expected) if not rest else _single_match(
        modifier(actual, expected), True, rest
    )


def match_value(actual: Any, expected: Any, modifiers: list[str] | None = None) -> bool:
    if actual is None:
        return False
    modifiers = modifiers or []
    expected_values = expected if isinstance(expected, list) else [expected]
    if "all" in modifiers:
        remaining = [modifier for modifier in modifiers if modifier != "all"]
        return bool(expected_values) and all(
            _single_match(actual, item, remaining) for item in expected_values
        )
    return any(_single_match(actual, item, modifiers) for item in expected_values)