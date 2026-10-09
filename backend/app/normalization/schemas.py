from datetime import datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventCategory(IntEnum):
    UNKNOWN = 0
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    REMOTE_ACTIVITY = 6
    APPLICATION_ACTIVITY = 7


class Severity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class Actor(BaseModel):
    user: str | None = None
    user_id: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    process_guid: str | None = None
    parent_process_name: str | None = None
    parent_process_id: int | None = None
    command_line: str | None = None


class Device(BaseModel):
    hostname: str | None = None
    ip: str | None = None
    os: str | None = None
    type: str | None = None


class Process(BaseModel):
    name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    path: str | None = None
    command_line: str | None = None
    user: str | None = None
    integrity_level: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)


class NetworkEndpoint(BaseModel):
    ip: str | None = None
    port: int | None = None
    hostname: str | None = None


class NetworkActivity(BaseModel):
    src: NetworkEndpoint | None = None
    dst: NetworkEndpoint | None = None
    protocol: str | None = None
    direction: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None


class FileActivity(BaseModel):
    path: str | None = None
    name: str | None = None
    size: int | None = None
    hash_sha256: str | None = None
    action: str | None = None


class RegistryActivity(BaseModel):
    key: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    action: str | None = None


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    time: datetime
    category: EventCategory = EventCategory.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    source: str
    event_id: str | None = None
    channel: str | None = None
    actor: Actor = Field(default_factory=Actor)
    device: Device = Field(default_factory=Device)
    process: Process | None = None
    network: NetworkActivity | None = None
    file: FileActivity | None = None
    registry: RegistryActivity | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    purplelab: dict[str, Any] = Field(default_factory=dict)
    flat: dict[str, Any] = Field(default_factory=dict)


class NormalizedAlert(BaseModel):
    time: datetime
    rule_key: str
    title: str
    severity: Severity = Severity.MEDIUM
    source: str
    correlation_id: str | None = None
    matched_fields: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)