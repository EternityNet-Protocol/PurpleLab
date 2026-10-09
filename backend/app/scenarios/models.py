from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScenarioBase(BaseModel):
    key: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str | None = None
    category: str = "generic"
    attck_technique: str | None = None
    attck_tactic: str | None = None
    severity: str = "medium"
    expected_rule_key: str | None = None
    expected_alert_type: str | None = None
    is_negative_control: bool = False
    tags: list[str] = Field(default_factory=list)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class ScenarioCreate(ScenarioBase):
    pass


class ScenarioOut(ScenarioBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class ScenarioDefinition(ScenarioBase):
    event_fixture: str = Field(pattern=r"^[A-Za-z0-9_.-]+\.json$")
    event_template: dict[str, Any] = Field(default_factory=dict)
    event_count: int = Field(default=1, ge=1, le=10000)
    latency_window_seconds: int = Field(default=30, ge=1, le=3600)
    prerequisites: list[str] = Field(default_factory=list)