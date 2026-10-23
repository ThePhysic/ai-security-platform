"""Policy precedence, official SARIF validation, disclosure and atomic export boundaries."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import jsonschema
import pytest

from ai_security_platform.cli.workflow import all_findings, wait
from ai_security_platform.domain.findings import FindingRead
from ai_security_platform.domain.scans import ScannerRead, ScanRead, ScanStatus
from ai_security_platform.reporting.core import build_json, encode, sarif
from ai_security_platform.reporting.files import write_artifact
from ai_security_platform.reporting.policy import Policy, evaluate
from ai_security_platform.snapshots.store import SnapshotStore

pytestmark = pytest.mark.unit
SCHEMA = Path(__file__).resolve().parents[1] / "schemas/sarif-2.1.0.json"


@pytest.fixture
def report_data(tmp_path):
    directory = tmp_path / "source"
    directory.mkdir()
    secret = "AKIA" + "W" * 16
    directory.joinpath("app.py").write_bytes(("eval(user) # " + secret + "\n").encode())
    source = SnapshotStore(tmp_path / "spool", require_readonly=False).create(directory)
    now = datetime.now(UTC)
    scan_id, snapshot, project = uuid4(), uuid4(), uuid4()
    stages = [
        ScannerRead(
            id=uuid4(),
            scanner_id=name,
            adapter_version="real-1",
            status="succeeded",
            synthetic=False,
            error_code=None,
            provenance={"engine_version": "controlled-1", "policy_digest": "a" * 64},
            coverage={"complete_execution": True},
        )
        for name in ("semgrep", "trivy")
    ]
    scan = ScanRead(
        id=scan_id,
        project_id=project,
        snapshot_id=snapshot,
        profile_id="security-v1",
        profile_digest="a" * 64,
        status="succeeded",
        created_at=now,
        started_at=now,
        completed_at=now,
        scanner_runs=stages,
    )
    finding = FindingRead(
        id=uuid4(),
        scan_run_id=scan_id,
        scanner_run_id=stages[0].id,
        occurrence_key="b" * 64,
        tracking_fingerprint="c" * 64,
        fingerprint_version=1,
        rule_id="platform.python.eval",
        category="sast",
        severity="HIGH",
        original_severity=secret,
        description="https://evil.invalid/ " + secret,
        filepath="app.py",
        start_line=1,
        end_line=1,
        created_at=now,
        synthetic=False,
        evidence={
            "manifest_digest": source.manifest_digest,
            "cwe": "CWE-95",
            "package_name": secret,
        },
    )
    return scan, finding, source, secret


def test_sarif_official_schema_stable_and_no_raw_data(report_data):
    scan, finding, source, secret = report_data
    report = build_json(scan, [finding], source)
    document = sarif(report)
    jsonschema.validators.validator_for(json.loads(SCHEMA.read_text()))(
        json.loads(SCHEMA.read_text())
    ).validate(document)
    assert encode(report) == encode(build_json(scan, [finding], source))
    assert encode(document) == encode(sarif(report))
    assert secret.encode() not in encode(report) + encode(document)
    assert b"evil.invalid" not in encode(report) + encode(document)
    result = document["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert result["partialFingerprints"]["tracking/v1"] == finding.tracking_fingerprint
    assert report["ai_opinions_applied"] is False


@pytest.mark.parametrize(
    "severity,complete,code",
    [
        ("LOW", True, 0),
        ("HIGH", True, 1),
        ("LOW", False, 2),
        ("CRITICAL", False, 2),
        ("UNKNOWN", True, 2),
    ],
)
def test_policy_exit_precedence(report_data, severity, complete, code):
    scan, finding, source, _ = report_data
    scan.scanner_runs[1].coverage["complete_execution"] = complete
    report = build_json(scan, [finding.model_copy(update={"severity": severity})], source)
    assert evaluate(report, Policy())["exit_code"] == code
    report["ai_assessment"] = {"disposition": "false_positive", "remediation": "fixed"}
    assert evaluate(report, Policy())["exit_code"] == code


@pytest.mark.parametrize(
    "change",
    [
        {"filepath": "../private.py"},
        {"filepath": "other.py"},
        {"end_line": 999},
        {"scan_run_id": uuid4()},
        {"evidence": {"manifest_digest": "e" * 64}},
        {"occurrence_key": "not-a-hash"},
        {"synthetic": True},
        {"rule_id": "https://untrusted.invalid/rule"},
    ],
)
def test_unauthorized_report_references_rejected(report_data, change):
    scan, finding, source, _ = report_data
    with pytest.raises(ValueError):
        build_json(scan, [finding.model_copy(update=change)], source)


def test_partial_and_diagnostic_policy_are_explicit(report_data):
    scan, finding, source, _ = report_data
    scan.status = ScanStatus.PARTIAL
    scan.scanner_runs[1].status = "failed"
    report = build_json(scan, [finding], source)
    assert evaluate(report, Policy())["exit_code"] == 2
    assert evaluate(report, Policy(required_scanners=["semgrep"]))["exit_code"] == 1
    scan.scanner_runs[0].scanner_id = "fake-patterns"
    scan.scanner_runs[0].synthetic = True
    report = build_json(
        scan, [finding.model_copy(update={"synthetic": True, "category": "synthetic"})], source
    )
    assert "Synthetic diagnostic" in report["findings"][0]["description"]
    assert evaluate(report, Policy(required_scanners=["fake-patterns"]))["exit_code"] == 2
    assert (
        evaluate(report, Policy(required_scanners=["fake-patterns"], allow_synthetic=True))[
            "exit_code"
        ]
        == 1
    )


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "x.json", "C:stream", "bad/name", "AGENTS"]
)
def test_artifact_names_cannot_choose_arbitrary_paths(tmp_path, name):
    with pytest.raises(ValueError):
        write_artifact(tmp_path, name, "json", b"{}")


def test_interrupted_atomic_export_and_no_overwrite(tmp_path, monkeypatch):
    import os

    original = os.link

    def interrupted(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(os, "link", interrupted)
    with pytest.raises(KeyboardInterrupt):
        write_artifact(tmp_path, "report", "json", b"complete")
    root = tmp_path / ".local/reports"
    assert [p for p in root.iterdir() if p.name != ".publish.lock"] == []
    monkeypatch.setattr(os, "link", original)
    write_artifact(tmp_path, "report", "json", b"complete")
    with pytest.raises(FileExistsError):
        write_artifact(tmp_path, "report", "json", b"replacement")
    assert (root / "report.json").read_bytes() == b"complete"


def test_polling_and_pagination_boundaries():
    from urllib.error import URLError

    with pytest.raises(TimeoutError):
        wait(lambda *a, **k: (_ for _ in ()).throw(URLError("synthetic")), "local", "id", 0.1, 0.1)
    with pytest.raises(ValueError):
        wait(lambda *a, **k: {}, "local", "id", float("nan"), 0.1)
    with pytest.raises(ValueError):
        all_findings(lambda *a, **k: {"items": [], "next_cursor": "repeat"}, "local", "id", 1, 3)
    with pytest.raises(ValueError):
        all_findings(lambda *a, **k: {"items": [], "next_cursor": "next"}, "local", "id", 1, 1)
