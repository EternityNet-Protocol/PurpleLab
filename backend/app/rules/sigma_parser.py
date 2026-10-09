from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    key: str
    title: str
    description: str = ""
    level: str = "medium"
    logsource: dict[str, Any] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    version: str = "1.0.0"
    raw: str = ""

    @property
    def selection(self) -> dict[str, Any]:
        return {name: value for name, value in self.detection.items() if name != "condition"}

    @property
    def condition(self) -> str:
        return str(self.detection.get("condition", "selection"))


def parse_sigma(content: str, key: str | None = None) -> SigmaRule:
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping")
    detection = data.get("detection")
    if not isinstance(detection, dict) or not detection:
        raise ValueError("Sigma rule must contain a detection mapping")
    rule_key = key or data.get("id") or data.get("title")
    if not isinstance(rule_key, str) or not rule_key.strip():
        raise ValueError("Sigma rule must contain an id or title")
    return SigmaRule(
        key=rule_key,
        title=str(data.get("title", "Untitled")),
        description=str(data.get("description", "")),
        level=str(data.get("level", "medium")),
        logsource=data.get("logsource") or {},
        detection=detection,
        tags=list(data.get("tags") or []),
        version=str(data.get("version", "1.0.0")),
        raw=content,
    )


def load_sigma_file(path: Path) -> SigmaRule:
    return parse_sigma(path.read_text(encoding="utf-8"))


def load_rules(directory: Path) -> list[SigmaRule]:
    if not directory.exists():
        return []
    paths = sorted(
        path
        for path in [*directory.rglob("*.yml"), *directory.rglob("*.yaml")]
        if "mappings" not in path.relative_to(directory).parts
    )
    return [load_sigma_file(path) for path in paths]


async def sync_rules_to_db(db, directory: Path) -> int:
    from app.database.repositories import RuleRepository

    repository = RuleRepository(db)
    rules = load_rules(directory)
    for rule in rules:
        await repository.upsert(
            {
                "key": rule.key,
                "title": rule.title,
                "description": rule.description,
                "format": "sigma",
                "content": rule.raw,
                "level": rule.level,
                "logsource": rule.logsource,
                "tags": rule.tags,
                "version": rule.version,
                "enabled": True,
            }
        )
    return len(rules)