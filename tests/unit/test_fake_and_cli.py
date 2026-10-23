from dataclasses import replace

import pytest

from ai_security_platform.cli.main import call_api
from ai_security_platform.scanners.fake import scan
from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000",
        "http://example.com:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:8000/redirect",
        "http://user@localhost:8000",
        "http://localhost:8000?token=synthetic",
        "http://localhost:8000#fragment",
    ],
)
def test_cli_rejects_nonlocal_or_ambiguous_transport(url):
    with pytest.raises(SnapshotError):
        call_api(url, "/health")


def test_fake_scanners_bounded_and_never_emit_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    secret = b"synthetic-do-not-echo"
    source.joinpath("sample.py").write_bytes(b"ASP_FAKE_FINDING " + secret + b"\nASP_FAKE_CONFIG\n")
    store = SnapshotStore(tmp_path / "spool", require_readonly=False)
    snap = store.create(source)
    pattern = scan("fake-patterns", snap)
    config = scan("fake-config", snap)
    assert len(pattern.findings) == len(config.findings) == 1
    assert pattern.findings[0].occurrence_key != config.findings[0].occurrence_key
    assert secret.decode() not in pattern.model_dump_json()
    with pytest.raises(SnapshotError):
        scan("repository-selected-executable", snap)
    huge = replace(snap, files={"sample.py": b"ASP_FAKE_FINDING\n" * 1001})
    with pytest.raises(SnapshotError, match="output_limit"):
        scan("fake-patterns", huge)
