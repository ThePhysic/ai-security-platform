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
from scripts.verify_ci_artifacts import (
    EXECUTION_MODE,
    MAX_ENVELOPE,
    safe_exception_type,
    verify,
    verify_stream,
)

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


@pytest.fixture
def ci_artifacts(report_data, tmp_path):
    scan, finding, source, _ = report_data
    scan = scan.model_copy(update={"profile_id": "offline-fixture-replay"})
    report = build_json(scan, [finding], source)
    policy = evaluate(report, Policy(required_scanners=["semgrep"]))
    policy["execution_mode"] = EXECUTION_MODE
    directory = tmp_path / "ci-artifacts"
    directory.mkdir()
    for name, value in [
        ("guardrails.json", report),
        ("guardrails.sarif", sarif(report)),
        ("policy.json", policy),
    ]:
        (directory / name).write_bytes(encode(value))
    return directory


def test_ci_expected_failure_is_successful_verification(ci_artifacts):
    assert verify(ci_artifacts) == {"artifacts": 3, "policy_exit_code": 1, "verification": "passed"}
    assert json.loads((ci_artifacts / "policy.json").read_bytes())["exit_code"] == 1


@pytest.mark.parametrize("code", [0, 2, True, "1", 1.0, None])
def test_ci_rejects_unexpected_policy_codes(ci_artifacts, code):
    path = ci_artifacts / "policy.json"
    policy = json.loads(path.read_bytes())
    policy["exit_code"] = code
    path.write_bytes(encode(policy))
    with pytest.raises(ValueError):
        verify(ci_artifacts)


@pytest.mark.parametrize("name", ["guardrails.json", "guardrails.sarif", "policy.json"])
def test_ci_missing_artifacts_fail(ci_artifacts, name):
    (ci_artifacts / name).unlink()
    with pytest.raises(ValueError):
        verify(ci_artifacts)


@pytest.mark.parametrize(
    "raw", [b"{", b"{}", b'{"exit_code":1,"exit_code":0}', b'{"exit_code":NaN}', b"x" * 4194305]
)
def test_ci_invalid_policy_artifacts_fail(ci_artifacts, raw):
    (ci_artifacts / "policy.json").write_bytes(raw)
    with pytest.raises(ValueError):
        verify(ci_artifacts)


def test_ci_mismatched_sarif_and_incomplete_scanner_fail(ci_artifacts):
    path = ci_artifacts / "guardrails.sarif"
    original = path.read_bytes()
    document = json.loads(original)
    document["runs"][0]["results"] = []
    path.write_bytes(encode(document))
    with pytest.raises(ValueError):
        verify(ci_artifacts)
    path.write_bytes(original)
    report_path = ci_artifacts / "guardrails.json"
    report = json.loads(report_path.read_bytes())
    semgrep = next(row for row in report["scan"]["scanner_runs"] if row["scanner_id"] == "semgrep")
    semgrep["coverage"]["complete_execution"] = False
    report_path.write_bytes(encode(report))
    path.write_bytes(encode(sarif(report)))
    with pytest.raises(ValueError):
        verify(ci_artifacts)


def test_ci_error_categories_never_echo_exception_values():
    secret = "SYNTHETIC_SECRET_private_diagnostic"
    assert safe_exception_type(AssertionError(secret)) == "AssertionError"
    assert safe_exception_type(RuntimeError(secret)) == "UnexpectedError"


@pytest.mark.parametrize(
    "payload",
    [
        b"{",
        b"{}",
        b"[]",
        b"x" * (MAX_ENVELOPE + 1),
        b'{"guardrails.json":"!","guardrails.sarif":"!","policy.json":"!"}',
    ],
)
def test_ci_stream_validation_is_bounded_and_fail_closed(payload):
    from io import BytesIO

    with pytest.raises(ValueError):
        verify_stream(BytesIO(payload))
