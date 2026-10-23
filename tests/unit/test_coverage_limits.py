import json

import pytest

from ai_security_platform.scanners.real import normalize
from ai_security_platform.snapshots.store import SnapshotStore

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "filename,warning",
    [
        ("package.json", "dependency_lockfile_missing"),
        ("uv.lock", "dependency_format_not_validated"),
        ("settings.tf", "iac_format_not_validated"),
    ],
)
def test_unsupported_dependency_or_iac_cannot_look_complete(tmp_path, filename, warning):
    source = tmp_path / "source"
    source.mkdir()
    source.joinpath(filename).write_bytes(b"controlled-unsupported\n")
    snapshot = SnapshotStore(tmp_path / "spool", require_readonly=False).create(source)
    output = {"SchemaVersion": 2, "Results": [{"Target": filename, "Vulnerabilities": []}]}
    result = normalize("trivy", json.dumps(output).encode(), 0, snapshot, {})
    assert warning in result.warnings and not result.complete
