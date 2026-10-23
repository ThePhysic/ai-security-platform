import json

import pytest

from ai_security_platform.scanners.real import bounded_json, normalize, validate_result
from ai_security_platform.snapshots.store import SnapshotStore

pytestmark = pytest.mark.unit


@pytest.fixture
def snapshot(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    root.joinpath("app.py").write_bytes(b"eval(user_input)\n")
    return SnapshotStore(tmp_path / "spool", require_readonly=False).create(root)


@pytest.mark.parametrize(
    "raw",
    [b"", b"[]", b"not-json", b"[" * 2000, b"x" * 4194305],
    ids=["empty", "array", "invalid-json", "deep", "oversized"],
)
def test_malformed_or_oversized_output_rejected(raw):
    with pytest.raises(ValueError):
        bounded_json(raw)


def semgrep_output(path="app.py", line=1):
    return {
        "results": [
            {
                "check_id": "platform.python.eval",
                "path": path,
                "start": {"line": line},
                "end": {"line": line},
                "extra": {
                    "severity": "ERROR",
                    "message": "synthetic-secret-must-not-persist",
                    "lines": "synthetic-secret-must-not-persist",
                },
            }
        ],
        "errors": [],
        "paths": {"scanned": ["app.py"]},
    }


def test_messages_and_excerpts_not_persisted(snapshot):
    result = normalize("semgrep", json.dumps(semgrep_output()).encode(), 0, snapshot, {})
    assert result.findings[0].severity == "HIGH"
    assert not result.findings[0].synthetic
    assert "synthetic-secret-must-not-persist" not in result.model_dump_json()
    assert result.findings[0].evidence["manifest_digest"] == snapshot.manifest_digest


@pytest.mark.parametrize(
    "path,line", [("../app.py", 1), ("/etc/passwd", 1), ("missing.py", 1), ("app.py", 9)]
)
def test_invalid_paths_ranges_rejected(snapshot, path, line):
    with pytest.raises(ValueError):
        normalize("semgrep", json.dumps(semgrep_output(path, line)).encode(), 0, snapshot, {})


def test_partial_results_preserved_not_clean_success(snapshot):
    value = semgrep_output()
    value["errors"] = [{"message": "synthetic-private"}]
    result = normalize("semgrep", json.dumps(value).encode(), 2, snapshot, {})
    assert len(result.findings) == 1 and not result.complete
    assert "scanner_errors" in result.warnings
    assert "synthetic-private" not in result.model_dump_json()
    with pytest.raises(ValueError):
        validate_result(result.model_copy(update={"warnings": ["synthetic-private"]}), snapshot)
    altered = result.model_copy(
        update={
            "findings": [result.findings[0].model_copy(update={"description": "synthetic-private"})]
        }
    )
    with pytest.raises(ValueError):
        validate_result(altered, snapshot)


def test_unknown_or_unsupported_input_not_clean(snapshot):
    value = {"results": [], "errors": [], "paths": {"scanned": []}}
    result = normalize("semgrep", json.dumps(value).encode(), 0, snapshot, {})
    assert not result.complete and result.warnings == ["no_supported_targets"]


def test_secret_value_not_persisted_and_multiscanner_file_count(snapshot):
    secret = "AKIA" + "Z" * 16
    value = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "app.py",
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "StartLine": 1,
                        "EndLine": 1,
                        "Severity": "HIGH",
                        "Match": secret,
                        "Code": {"Lines": [secret]},
                    },
                ],
            },
            {"Target": "app.py", "Vulnerabilities": []},
        ],
    }
    result = normalize("trivy", json.dumps(value).encode(), 0, snapshot, {})
    assert result.files_scanned == 1 and len(result.findings) == 1
    assert secret not in result.model_dump_json()
