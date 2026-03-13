from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedFinding:
    schema_id: str
    schema_version: str
    sanara_rule_id: str
    source: str
    source_rule_id: str
    severity: str
    module_dir: str
    file_path: str
    line_range: str
    resource_type: str
    resource_name: str
    fingerprint: str

    def sort_key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.sanara_rule_id,
            self.file_path,
            self.resource_type,
            self.resource_name,
            self.source_rule_id,
            self.fingerprint,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "sanara_rule_id": self.sanara_rule_id,
            "source": self.source,
            "source_rule_id": self.source_rule_id,
            "severity": self.severity,
            "target": {
                "module_dir": self.module_dir,
                "file_path": self.file_path,
                "line_range": self.line_range,
            },
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "fingerprint": self.fingerprint,
        }
