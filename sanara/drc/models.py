from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class DrcError(Exception):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class PatchContract:
    sanara_rule_id: str
    preconditions: list[str]
    changes: list[str]
    postconditions: list[str]
    invariants_checked: list[str]
    risk: str
    validation_required: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_id": "sanara.patch_contract",
            "schema_version": "0.1",
            "sanara_rule_id": self.sanara_rule_id,
            "preconditions": self.preconditions,
            "changes": self.changes,
            "postconditions": self.postconditions,
            "invariants_checked": self.invariants_checked,
            "risk": self.risk,
            "validation_required": self.validation_required,
        }


@dataclass
class TransformResult:
    changed: bool
    file_path: Path
    contract: PatchContract
