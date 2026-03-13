from __future__ import annotations

import json
from pathlib import Path

from sanara.orchestrator.models import FindingState
from sanara.orchestrator.rescan_stage import apply_rescan_stage
from sanara.policy import Policy


def test_apply_rescan_stage_writes_artifacts_and_partitions(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "ws"
    workspace.mkdir()

    mapped = {
        "sanara_rule_id": "aws.s3.public_access_block",
        "source_rule_id": "CKV2_AWS_6",
        "resource_type": "aws_s3_bucket",
        "resource_name": "public_bucket",
        "file_path": "main.tf",
    }
    uncovered = {
        "sanara_rule_id": "checkov.unmapped.ckv_aws_144",
        "source_rule_id": "CKV_AWS_144",
        "resource_type": "aws_s3_bucket",
        "resource_name": "public_bucket",
        "file_path": "main.tf",
    }

    scan_raw = {
        "checkov": {
            "targets": [str(workspace)],
            "results": [
                [
                    {
                        "results": {
                            "failed_checks": [
                                {"check_id": "CKV2_AWS_6"},
                                {"check_id": "CKV_AWS_144"},
                            ]
                        }
                    }
                ]
            ],
        },
    }

    def _build_current_findings_state(*args, **kwargs):
        _ = args, kwargs
        return FindingState(
            clean=False,
            remaining=[mapped, uncovered],
            remaining_mapped=[mapped],
            remaining_uncovered=[uncovered],
        )

    def _write_targeted_results(
        artifacts_dir: Path,
        findings_state: FindingState,
        attempted_rules: set[str],
        rel_path: str = "rescan/targeted_results.json",
    ):
        payload = {
            "clean": findings_state.clean,
            "remaining": findings_state.remaining,
            "remaining_mapped": findings_state.remaining_mapped,
            "remaining_uncovered": findings_state.remaining_uncovered,
            "attempted_rules": sorted(attempted_rules),
        }
        p = artifacts_dir / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    def _checkov_failed_items(payload: dict):
        out = []
        for report in payload.get("results", []):
            if isinstance(report, list):
                for r in report:
                    out.extend((r.get("results", {}) or {}).get("failed_checks", []))
        return out

    policy_eval = {"snapshots": {}}
    res = apply_rescan_stage(
        stage="post_drc",
        artifacts_dir=artifacts,
        scan_raw=scan_raw,
        policy=Policy(
            finding_policy={
                "hard_fail_on": ["CKV2_AWS_6"],
                "soft_fail_on": ["CKV_AWS_144"],
            }
        ),
        mapping={},
        mapped_check_ids={"CKV2_AWS_6"},
        workspace=workspace,
        attempted_rules={"aws.s3.public_access_block"},
        build_current_findings_state=_build_current_findings_state,
        write_targeted_results=_write_targeted_results,
        checkov_failed_items=_checkov_failed_items,
        policy_evaluation_artifact=policy_eval,
        write_primary_rescan_alias=True,
    )

    assert res.raw_checkov_failed == 2
    assert res.effective_state.clean is False
    assert len(res.decision_partition.blocking) == 1
    assert len(res.decision_partition.advisory) == 1
    assert res.decision_partition.blocking[0]["source_rule_id"] == "CKV2_AWS_6"
    assert res.decision_partition.advisory[0]["source_rule_id"] == "CKV_AWS_144"

    assert (artifacts / "rescan/checkov.json").exists()
    assert (artifacts / "rescan/checkov_post_drc.json").exists()
    assert (artifacts / "rescan/scan_policy_review_post_drc.json").exists()
    assert (artifacts / "rescan/policy_review_post_drc.json").exists()
    assert (artifacts / "rescan/targeted_results.json").exists()
    assert (artifacts / "rescan/targeted_results_post_drc.json").exists()

    snap = policy_eval["snapshots"]["post_drc"]
    assert snap["stage"] == "post_drc"
    assert snap["clean"] is False
