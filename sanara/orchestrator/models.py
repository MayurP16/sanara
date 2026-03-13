from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScannerResults:
    targets: list[str]
    results: list[Any]


@dataclass
class ScanPayload:
    checkov: ScannerResults

    @classmethod
    def from_raw(cls, payload: dict[str, Any]) -> "ScanPayload":
        checkov = payload.get("checkov", {})
        return cls(
            checkov=ScannerResults(
                targets=[str(x) for x in checkov.get("targets", [])],
                results=[x for x in checkov.get("results", []) if isinstance(x, (dict, list))],
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkov": {"targets": self.checkov.targets, "results": self.checkov.results},
        }


@dataclass
class FindingState:
    clean: bool
    remaining: list[dict[str, Any]]
    remaining_mapped: list[dict[str, Any]]
    remaining_uncovered: list[dict[str, Any]]


@dataclass
class DecisionPartition:
    blocking: list[dict[str, Any]] = field(default_factory=list)
    advisory: list[dict[str, Any]] = field(default_factory=list)
    ignored: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RescanStageResult:
    stage: str
    scan: ScanPayload
    raw_checkov_failed: int
    scan_state: FindingState
    effective_state: FindingState
    scan_excluded: list[dict[str, Any]]
    scan_policy_review: dict[str, Any]
    finding_policy_review: dict[str, Any]
    decision_partition: DecisionPartition


@dataclass
class RunState:
    clean: bool = False
    diff: str = ""
    candidate_remaining: list[dict[str, Any]] = field(default_factory=list)
    remaining_mapped: list[dict[str, Any]] = field(default_factory=list)
    remaining_uncovered: list[dict[str, Any]] = field(default_factory=list)
    blocking_remaining: list[dict[str, Any]] = field(default_factory=list)
    advisory_remaining: list[dict[str, Any]] = field(default_factory=list)
    ignored_remaining: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FinalState:
    decision: str | None = None
    reason_code: str | None = None
