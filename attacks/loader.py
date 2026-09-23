"""Load and validate the attack catalog (attacks/catalog.yaml)."""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class InvalidCatalogError(Exception):
    pass


class AttackTemplate(BaseModel):
    test_id: str
    attack_type: str
    target: str
    deterministic: bool
    severity: str = "medium"
    payload: str = ""
    expected_outcome: str = "blocked"
    success_marker: str = ""
    block_hint: str = ""
    meta: dict = Field(default_factory=dict)

    @property
    def technique(self) -> str:
        return self.meta.get("technique", "unknown")

    @property
    def turning(self) -> int:
        return int(self.meta.get("turning", 1))


class AttackTypeInfo(BaseModel):
    label: str
    owasp: str
    atlas: str
    severity: str


class AttackCatalog(BaseModel):
    version: float
    attack_types: dict[str, AttackTypeInfo]
    targets: dict[str, bool] = Field(default_factory=dict)
    tests: list[AttackTemplate] = Field(default_factory=list)

    def by_target(self, target: str) -> list[AttackTemplate]:
        return [t for t in self.tests if t.target == target]

    def by_attack_type(self, attack_type: str) -> list[AttackTemplate]:
        return [t for t in self.tests if t.attack_type == attack_type]

    def get(self, test_id: str) -> AttackTemplate | None:
        for t in self.tests:
            if t.test_id == test_id:
                return t
        return None


def load_catalog(path: str | Path) -> AttackCatalog:
    path = Path(path)
    if not path.exists():
        raise InvalidCatalogError(f"catalog not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise InvalidCatalogError(f"unparsable catalog: {exc}") from exc
    try:
        return AttackCatalog.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError
        raise InvalidCatalogError(f"invalid catalog: {exc}") from exc