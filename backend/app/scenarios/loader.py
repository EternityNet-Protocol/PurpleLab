from collections.abc import Iterable
from pathlib import Path

import yaml

from app.config import get_settings
from app.scenarios.models import ScenarioDefinition


def load_scenario_file(path: Path) -> ScenarioDefinition:
    with path.open(encoding="utf-8") as scenario_file:
        payload = yaml.safe_load(scenario_file)
    if not isinstance(payload, dict):
        raise ValueError(f"Scenario file {path.name} must contain a YAML mapping")
    return ScenarioDefinition.model_validate(payload)


def load_scenarios(directory: Path | str | None = None) -> list[ScenarioDefinition]:
    root = Path(directory) if directory is not None else get_settings().scenarios_dir
    if not root.exists():
        return []
    paths = sorted(root.glob("*.yaml")) + sorted(root.glob("*.yml"))
    return [load_scenario_file(path) for path in paths]


def iter_scenarios(directory: Path | str | None = None) -> Iterable[ScenarioDefinition]:
    yield from load_scenarios(directory)