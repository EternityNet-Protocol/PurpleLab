import re
from urllib.parse import urlsplit


_RUN_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")


def validate_run_id(run_id: str) -> str:
    if not _RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("Collector correlation requires a 32-character hexadecimal run ID")
    return run_id


def validate_readonly_endpoint(endpoint: str | None) -> str:
    value = (endpoint or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Collector endpoint must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Collector endpoint cannot contain credentials, query, or fragment")
    if parsed.scheme != "https" and parsed.hostname.casefold() not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("HTTP is allowed only for loopback collector endpoints; use HTTPS remotely")
    return value