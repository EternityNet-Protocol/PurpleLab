import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.normalization.schemas import (
    Actor,
    Device,
    EventCategory,
    FileActivity,
    NetworkActivity,
    NetworkEndpoint,
    NormalizedEvent,
    Process,
    RegistryActivity,
    Severity,
)


def _first(raw: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in raw and raw[name] is not None:
            return raw[name]
    return None


def _nested(raw: dict[str, Any], *names: str) -> dict[str, Any]:
    value = _first(raw, *names)
    return value if isinstance(value, dict) else {}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.isdigit():
            return datetime.fromtimestamp(int(candidate), tz=timezone.utc)
        try:
            parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _severity(value: Any) -> Severity:
    if isinstance(value, int):
        return Severity(min(max(value, 0), 6))
    labels = {
        "informational": Severity.INFORMATIONAL,
        "info": Severity.INFORMATIONAL,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "fatal": Severity.FATAL,
    }
    return labels.get(str(value).casefold(), Severity.UNKNOWN)


def _flatten(value: Any, prefix: str = "", output: dict[str, Any] | None = None) -> dict[str, Any]:
    output = output if output is not None else {}
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            _flatten(item, path, output)
            if not isinstance(item, (dict, list)):
                output.setdefault(str(key), item)
    elif prefix:
        output[prefix] = value
    return output


def _hashes(raw: dict[str, Any]) -> dict[str, str]:
    value = _first(raw, "Hashes", "hashes", "hash")
    if isinstance(value, str):
        pairs = [part.split("=", 1) for part in value.split(",") if "=" in part]
        hashes = {name.strip().casefold(): digest.strip() for name, digest in pairs}
    elif isinstance(value, dict):
        hashes = {str(name).casefold(): str(digest) for name, digest in value.items()}
    else:
        hashes = {}
    for name in ("md5", "sha1", "sha256"):
        digest = _first(raw, f"Hash{name.upper()}", f"{name}_hash")
        if digest:
            hashes[name] = str(digest)
    return hashes


def _flatten_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


class EventMapper:
    """Map Sysmon, Windows, ECS, Zeek, Suricata, and generic JSON events."""

    def map(self, raw: dict[str, Any], source: str = "unknown") -> NormalizedEvent:
        if not isinstance(raw, dict):
            raise TypeError("EventMapper expects a JSON object")
        event_obj = _nested(raw, "event")
        process_obj = _nested(raw, "process")
        parent_obj = _nested(process_obj, "parent")
        user_obj = _nested(raw, "user")
        host_obj = _nested(raw, "host", "device")
        source_obj = _nested(raw, "source", "src")
        destination_obj = _nested(raw, "destination", "dest")
        network_obj = _nested(raw, "network")
        file_obj = _nested(raw, "file")
        registry_obj = _nested(raw, "registry")

        process_name = _first(raw, "Image", "process_name") or _first(process_obj, "name", "executable")
        process_path = _first(raw, "Image", "ExecutablePath") or _first(process_obj, "executable", "path")
        command_line = _first(raw, "CommandLine", "cmdline") or _first(process_obj, "command_line")
        process_pid = _safe_int(_first(raw, "ProcessId", "pid") or _first(process_obj, "pid"))
        parent_name = _first(raw, "ParentImage", "ParentProcessName") or _first(parent_obj, "name", "executable")
        parent_pid = _safe_int(_first(raw, "ParentProcessId", "ppid") or _first(parent_obj, "pid"))
        process = None
        if any((process_name, command_line, process_pid, process_path)):
            process = Process(
                name=str(process_name) if process_name is not None else None,
                pid=process_pid,
                ppid=parent_pid,
                path=str(process_path) if process_path is not None else None,
                command_line=str(command_line) if command_line is not None else None,
                user=str(_first(raw, "User") or _first(user_obj, "name")) if (_first(raw, "User") or _first(user_obj, "name")) else None,
                integrity_level=_first(raw, "IntegrityLevel"),
                hashes=_hashes(raw),
            )

        src_ip = _first(raw, "SourceIp", "src_ip", "id.orig_h") or _first(source_obj, "ip")
        dst_ip = _first(raw, "DestinationIp", "dst_ip", "id.resp_h", "dest_ip") or _first(destination_obj, "ip")
        src_port = _safe_int(_first(raw, "SourcePort", "src_port", "id.orig_p") or _first(source_obj, "port"))
        dst_port = _safe_int(_first(raw, "DestinationPort", "dst_port", "id.resp_p", "dest_port") or _first(destination_obj, "port"))
        query = _first(raw, "query", "dns.question.name")
        network = None
        if any((src_ip, dst_ip, src_port, dst_port, _first(raw, "DestinationHostname"))):
            direction = "outbound" if str(_first(raw, "Initiated", "direction") or "").casefold() in {"true", "outbound", "client"} else None
            network = NetworkActivity(
                src=NetworkEndpoint(ip=_flatten_ip(src_ip), port=src_port, hostname=_first(source_obj, "domain")),
                dst=NetworkEndpoint(
                    ip=_flatten_ip(dst_ip),
                    port=dst_port,
                    hostname=_first(raw, "DestinationHostname") or _first(destination_obj, "domain") or query,
                ),
                protocol=str(_first(raw, "Protocol", "proto") or _first(network_obj, "transport")) if (_first(raw, "Protocol", "proto") or _first(network_obj, "transport")) else None,
                direction=direction,
                bytes_in=_safe_int(_first(raw, "BytesIn")),
                bytes_out=_safe_int(_first(raw, "BytesOut")),
            )

        file_path = _first(raw, "TargetFilename", "file_path", "FileName") or _first(file_obj, "path", "name")
        file_activity = None
        if file_path:
            file_activity = FileActivity(
                path=str(file_path),
                name=_first(file_obj, "name") or (str(file_path).replace("\\", "/").rsplit("/", 1)[-1]),
                size=_safe_int(_first(raw, "FileSize") or _first(file_obj, "size")),
                hash_sha256=_first(raw, "HashSha256", "sha256") or _first(_hashes(raw), "sha256"),
                action=_first(raw, "EventType", "action") or _first(event_obj, "action"),
            )

        registry_key = _first(raw, "TargetObject", "registry_key", "reg_key") or _first(registry_obj, "path", "key")
        registry_activity = None
        if registry_key:
            registry_activity = RegistryActivity(
                key=str(registry_key),
                value_name=_first(raw, "ValueName", "reg_value_name") or _first(registry_obj, "value_name"),
                value_data=_first(raw, "Details", "reg_value_data") or _first(registry_obj, "value"),
                action=_first(raw, "EventType", "action") or _first(event_obj, "action"),
            )

        category = EventCategory.UNKNOWN
        explicit_category = str(_first(event_obj, "category") or "").casefold()
        if network:
            category = EventCategory.NETWORK_ACTIVITY
        elif process or file_activity or registry_activity:
            category = EventCategory.SYSTEM_ACTIVITY
        elif explicit_category in {"finding", "findings"}:
            category = EventCategory.FINDINGS
        elif explicit_category in {"iam", "identity"}:
            category = EventCategory.IAM

        timestamp = _first(raw, "UtcTime", "timestamp", "ts", "@timestamp", "TimeCreated") or _first(event_obj, "created")
        user_name = _first(raw, "User", "uid") or _first(user_obj, "name")
        user_id = _first(user_obj, "id")
        hostname = _first(raw, "Computer", "hostname") or _first(host_obj, "hostname", "name")
        event = NormalizedEvent(
            time=_parse_ts(timestamp),
            category=category,
            severity=_severity(_first(raw, "Severity", "severity", "level") or _first(event_obj, "severity")),
            source=source,
            event_id=str(_first(raw, "EventID", "event_id") or _first(event_obj, "code") or "") or None,
            channel=_first(raw, "Channel", "channel"),
            actor=Actor(
                user=str(user_name) if user_name is not None else None,
                user_id=str(user_id) if user_id is not None else None,
                process_name=str(process_name) if process_name is not None else None,
                process_id=process_pid,
                process_guid=_first(raw, "ProcessGuid") or _first(process_obj, "entity_id"),
                parent_process_name=str(parent_name) if parent_name is not None else None,
                parent_process_id=parent_pid,
                command_line=str(command_line) if command_line is not None else None,
            ),
            device=Device(
                hostname=str(hostname) if hostname is not None else None,
                ip=str(_first(raw, "SourceIp", "src_ip") or "") or None,
                os=str(_first(raw, "Os", "os") or _first(host_obj, "os", "os.full") or "") or None,
            ),
            process=process,
            network=network,
            file=file_activity,
            registry=registry_activity,
            raw=raw,
            purplelab=_nested(raw, "PurpleLab", "purplelab"),
        )
        flat = _flatten(raw)
        canonical = event.model_dump(mode="python", exclude={"raw", "flat", "purplelab"})
        flat.update(_flatten(canonical))
        event.flat = flat
        return event


def event_fingerprint(event: NormalizedEvent) -> str:
    payload = json.dumps(event.raw, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()