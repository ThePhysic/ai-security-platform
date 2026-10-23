import os
from dataclasses import replace
from uuid import uuid4

import pytest

from ai_security_platform.snapshots.filesystem import PinnedTree
from ai_security_platform.snapshots.policy import DEFAULT_LIMITS, SnapshotError, validate_path
from ai_security_platform.snapshots.store import SnapshotStore

pytestmark = [pytest.mark.unit, pytest.mark.snapshot]


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "example.py").write_bytes(b"ASP_FAKE_FINDING\n")
    return root


@pytest.fixture
def store(tmp_path):
    return SnapshotStore(tmp_path / "spool", require_readonly=False)


def test_publish_and_verify(source, store):
    source.joinpath("empty").mkdir()
    snap = store.create(source)
    verified = store.verify(snap.manifest.snapshot_key, snap.manifest_digest)
    assert verified.files == {"example.py": b"ASP_FAKE_FINDING\n"}
    assert verified.manifest.directories == ["empty"]
    assert str(source) not in snap.manifest.model_dump_json()
    assert not list((store.root / ".staging").iterdir())


def test_trusted_exclusion_and_untrusted_ignore(source, store):
    (source / "AGENTS.md").write_text("synthetic-do-not-read")
    (source / ".env").write_text("synthetic-do-not-read")
    (source / ".gitignore").write_text("*")
    (source / ".semgrepignore").write_text("*")
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text("synthetic-private")
    snap = store.create(source)
    assert "example.py" in snap.files
    assert ".gitignore" in snap.files and ".semgrepignore" in snap.files
    assert "AGENTS.md" not in snap.files and ".env" not in snap.files
    assert snap.manifest.exclusions == {"files": 2, "directories": 1}


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        r"C:\escape",
        "file:secret",
        "CON",
        "nul.txt",
        "trailing.",
        "bad name",
        "a//b",
        "a/../b",
        "uni\u212a.py",
        "bad\nname",
    ],
)
def test_portable_paths_reject(name):
    with pytest.raises(SnapshotError):
        validate_path(name)


def test_hardlink_rejected(source, store):
    os.link(source / "example.py", source / "alias.py")
    with pytest.raises(SnapshotError):
        store.create(source)


def test_file_and_total_budgets(source, tmp_path):
    for limit in (
        replace(DEFAULT_LIMITS, file_bytes=2),
        replace(DEFAULT_LIMITS, total_bytes=2),
        replace(DEFAULT_LIMITS, files=0),
    ):
        store = SnapshotStore(tmp_path / uuid4().hex, limit, require_readonly=False)
        with pytest.raises(SnapshotError):
            store.create(source)


def test_directory_and_spool_budgets(source, tmp_path):
    source.joinpath("nested").mkdir()
    for limit in (replace(DEFAULT_LIMITS, directories=1), replace(DEFAULT_LIMITS, spool_bytes=1)):
        store = SnapshotStore(tmp_path / uuid4().hex, limit, require_readonly=False)
        with pytest.raises(SnapshotError):
            store.create(source)


def test_excluded_entries_still_have_enumeration_budget(source, tmp_path):
    source.joinpath(".env").write_bytes(b"synthetic-excluded")
    store = SnapshotStore(
        tmp_path / "spool", replace(DEFAULT_LIMITS, entries=1), require_readonly=False
    )
    with pytest.raises(SnapshotError, match="entry_budget"):
        store.create(source)


def test_published_unexpected_directory_rejected(source, store):
    snap = store.create(source)
    (store.root / "published" / snap.manifest.snapshot_key / "unexpected").mkdir()
    with pytest.raises(SnapshotError):
        store.verify(snap.manifest.snapshot_key, snap.manifest_digest)


def test_mutation_or_exclusive_read_blocks_publication(source, store, monkeypatch):
    original = PinnedTree.assert_unchanged

    def mutate(tree, captured):
        (source / "example.py").write_text("changed")
        original(tree, captured)

    monkeypatch.setattr(PinnedTree, "assert_unchanged", mutate)
    with pytest.raises(SnapshotError):
        store.create(source)
    assert not list((store.root / "published").iterdir())


def test_casefold_collision(source, store, monkeypatch):
    original = PinnedTree._names

    def names(tree, path, fd):
        if path == source:
            return ("example.py", "EXAMPLE.py")
        return original(tree, path, fd)

    monkeypatch.setattr(PinnedTree, "_names", names)
    with pytest.raises(SnapshotError, match="name_collision"):
        store.create(source)


def test_identity_tamper_and_no_readwrite_server_fallback(source, store):
    snap = store.create(source)
    with pytest.raises(SnapshotError):
        store.verify(snap.manifest.snapshot_key, "0" * 64)
    published = store.root / "published" / snap.manifest.snapshot_key / "files" / "example.py"
    published.chmod(0o600)
    published.write_bytes(b"tampered")
    with pytest.raises(SnapshotError):
        store.verify(snap.manifest.snapshot_key, snap.manifest_digest)
    with pytest.raises(SnapshotError, match="readonly_spool_required"):
        SnapshotStore(store.root).verify(snap.manifest.snapshot_key, snap.manifest_digest)


def test_cleanup_never_removes_published(source, store):
    snap = store.create(source)
    assert store.cleanup_staging() == 0
    with pytest.raises(SnapshotError):
        store._remove_stage(store.root / "published" / snap.manifest.snapshot_key)
    assert store.verify(snap.manifest.snapshot_key, snap.manifest_digest)


def test_unknown_spool_is_not_adopted(tmp_path):
    path = tmp_path / "unknown"
    path.mkdir()
    path.joinpath("user-file").write_text("preserve")
    with pytest.raises(SnapshotError):
        SnapshotStore(path, require_readonly=False).initialize()
    assert path.joinpath("user-file").read_text() == "preserve"


def test_posix_symlink_and_special_files(source, store, tmp_path):
    if os.name != "posix":
        # Native Windows reparse/ADS/junction proofs run as their own mandatory harness.
        return
    outside = tmp_path / "outside"
    outside.write_text("not-for-source")
    (source / "link").symlink_to(outside)
    with pytest.raises(SnapshotError):
        store.create(source)
    (source / "link").unlink()
    os.mkfifo(source / "pipe")
    with pytest.raises(SnapshotError):
        store.create(source)
