"""Artifact-only offline demonstration using retained genuine controlled observations.

No target execution, live scanning, model, database, Docker or credentials in this process.
The workflow runs this trusted script from the protected default branch only.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_security_platform.domain.findings import FindingRead  # noqa: E402
from ai_security_platform.domain.scans import ScannerRead, ScanRead  # noqa: E402
from ai_security_platform.reporting.core import build_json, encode, sarif  # noqa: E402
from ai_security_platform.reporting.files import write_artifact  # noqa: E402
from ai_security_platform.reporting.policy import Policy, evaluate  # noqa: E402
from ai_security_platform.snapshots.store import SnapshotStore  # noqa: E402
from evaluation.corpus import BASE, load, materialize  # noqa: E402
from scripts.verify_ci_artifacts import EXECUTION_MODE, safe_exception_type  # noqa: E402


def main():
    import jsonschema

    workspace = Path("/tmp/guardrails")
    workspace.mkdir(exist_ok=True)
    case = next(c for c in load()["cases"] if c["id"] == "python-eval-positive")
    observations = json.loads((BASE / "results/scanner-observations.json").read_text())[
        "repetitions"
    ][0][case["id"]]
    source = SnapshotStore(workspace / "spool", require_readonly=False).create(
        materialize(case, workspace / "source")
    )
    assert all(
        r["source_identity"]["content_digest"] == source.manifest.content_digest
        for r in observations.values()
    )
    now = datetime.now(UTC)
    scan = ScanRead(
        id=uuid4(),
        project_id=uuid4(),
        snapshot_id=uuid4(),
        profile_id="offline-fixture-replay",
        profile_digest="a" * 64,
        status="partial",
        created_at=now,
        started_at=now,
        completed_at=now,
    )
    findings = []
    for name, observation in observations.items():
        actual = observation["result"]
        stage = ScannerRead(
            id=uuid4(),
            scanner_id=name,
            adapter_version="real-1",
            status="succeeded" if actual["complete"] else "failed",
            coverage={"complete_execution": actual["complete"], "warnings": actual["warnings"]},
            error_code=None if actual["complete"] else "incomplete_coverage",
            synthetic=False,
            provenance=actual["provenance"],
        )
        scan.scanner_runs.append(stage)
        for value in actual["findings"]:
            item = dict(value)
            item["evidence"] = dict(item["evidence"]) | {"manifest_digest": source.manifest_digest}
            findings.append(
                FindingRead(
                    id=uuid4(),
                    scan_run_id=scan.id,
                    scanner_run_id=stage.id,
                    fingerprint_version=1,
                    created_at=now,
                    **item,
                )
            )
    report = build_json(scan, findings, source)
    document = sarif(report)
    schema = json.loads((ROOT / "tests/schemas/sarif-2.1.0.json").read_text())
    jsonschema.validators.validator_for(schema)(schema).validate(document)
    jsonschema.validate(report, json.loads((ROOT / "tests/schemas/report-v1.json").read_text()))
    decision = evaluate(report, Policy(required_scanners=["semgrep"]))
    decision["execution_mode"] = EXECUTION_MODE
    for name, format, value in [
        ("guardrails", "json", report),
        ("guardrails", "sarif", document),
        ("policy", "json", decision),
    ]:
        write_artifact(workspace, name, format, encode(value))
    assert decision["exit_code"] == 1
    print(
        json.dumps(
            {
                "artifacts": 3,
                "policy_exit_code": decision["exit_code"],
                "live_scans": 0,
                "hosted_calls": 0,
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "error": "offline_artifact_generation_failed",
                    "error_type": safe_exception_type(error),
                }
            )
        )
        raise SystemExit(2) from None
