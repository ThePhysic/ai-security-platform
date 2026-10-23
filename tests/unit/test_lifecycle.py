"""Lifecycle safety contracts; real PostgreSQL restore proof is a host integration drill."""

import json
import os
import subprocess
import time
from contextlib import contextmanager
from uuid import uuid4

import pytest

from ai_security_platform.snapshots.policy import SnapshotError, canonical, digest
from ai_security_platform.snapshots.removal import remove_owned_tree
from ai_security_platform.snapshots.store import SnapshotStore
from scripts.lifecycle import (
    BACKUP_MARKER,
    REVISION,
    Database,
    MaintenanceError,
    backup,
    capture_spool,
    inventory,
    restore,
    retain,
    tree_bytes,
    verify_bundle,
)

pytestmark = [pytest.mark.unit, pytest.mark.snapshot]


@pytest.fixture
def publication(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_bytes(b'print("inert data")\n')
    store = SnapshotStore(tmp_path / "spool", require_readonly=False)
    snapshot = store.create(source)
    return store, snapshot


def registered(snapshot):
    return {
        "spool_key": snapshot.manifest.snapshot_key,
        "manifest_digest": snapshot.manifest_digest,
        "verified": True,
        "retention_state": "published",
    }


def test_all_registered_history_remains_protected_after_expiry(publication):
    store, snapshot = publication
    report = inventory(store, [registered(snapshot)], now=int(time.time()) + 30 * 86400)
    assert report["publications"] == 1
    assert report["items"][0]["reason"] == "retained_database_reference"
    assert not report["items"][0]["eligible"]


def test_unregistered_requires_full_registration_grace(publication):
    store, snapshot = publication
    assert not inventory(store, [])["items"][0]["eligible"]
    assert inventory(store, [], now=snapshot.manifest.acquired_at + 7 * 86400)["items"][0][
        "eligible"
    ]
    with pytest.raises(MaintenanceError, match="unsafe_retention"):
        inventory(store, [], grace=60)


def test_missing_or_mismatched_referenced_source_fails_closed(publication):
    store, snapshot = publication
    record = registered(snapshot)
    with pytest.raises(MaintenanceError, match="mismatch"):
        inventory(store, [record | {"manifest_digest": "f" * 64}])
    with pytest.raises(MaintenanceError, match="missing"):
        inventory(store, [record | {"spool_key": "f" * 32}])


def test_legacy_unverified_metadata_is_preserved_without_invented_evidence(publication):
    store, _ = publication
    assert inventory(
        store,
        [
            {
                "spool_key": "legacy-unavailable",
                "verified": False,
                "retention_state": "published",
                "manifest_digest": "f" * 64,
            }
        ],
    )


class ReferenceDatabase:
    def __init__(self, records):
        self.records = records
        self.locked = False

    @contextmanager
    def freeze(self):
        self.locked = True
        yield
        self.locked = False

    def snapshots(self):
        assert self.locked
        return self.records


def test_retention_defaults_to_dry_run_then_only_explicitly_removes_orphan(publication):
    store, snapshot = publication
    database = ReferenceDatabase([])
    now = snapshot.manifest.acquired_at + 8 * 86400
    report = retain(database, store, now=now)
    assert report["dry_run"] and report["removed"] == 0
    assert store.verify(snapshot.manifest.snapshot_key, snapshot.manifest_digest)
    report = retain(database, store, now=now, apply=True)
    assert report["removed"] == 1 and report["database_rows_deleted"] == 0
    assert not list((store.root / "published").iterdir())


def test_apply_never_removes_registered_source(publication):
    store, snapshot = publication
    report = retain(
        ReferenceDatabase([registered(snapshot)]),
        store,
        now=int(time.time()) + 30 * 86400,
        apply=True,
    )
    assert report["removed"] == 0
    assert store.verify(snapshot.manifest.snapshot_key, snapshot.manifest_digest)


def test_cleanup_refuses_hardlink_without_changing_outside_file(tmp_path):
    parent = tmp_path / "staging"
    parent.mkdir()
    key = uuid4().hex
    (parent / key).mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"preserve")
    outside.chmod(0o444)
    before = outside.stat().st_mode
    os.link(outside, parent / key / "linked.txt")
    with pytest.raises(SnapshotError):
        remove_owned_tree(parent, key)
    assert outside.read_bytes() == b"preserve" and outside.stat().st_mode == before
    assert (parent / key / "linked.txt").exists()


def test_cleanup_refuses_directory_substitution_and_preserves_outside(tmp_path):
    parent = tmp_path / "staging"
    parent.mkdir()
    key = uuid4().hex
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "safe.txt").write_bytes(b"preserve")
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(parent / key), str(outside)],
            check=True,
            capture_output=True,
        )
    else:
        os.symlink(outside, parent / key, target_is_directory=True)
    with pytest.raises(SnapshotError):
        remove_owned_tree(parent, key)
    assert (outside / "safe.txt").read_bytes() == b"preserve"


@pytest.mark.parametrize("name", ["../outside", "x" * 32, "", "a" * 32 + "/../other"])
def test_cleanup_rejects_noncanonical_direct_children(tmp_path, name):
    with pytest.raises(SnapshotError):
        remove_owned_tree(tmp_path, name)


@pytest.fixture
def bundle(tmp_path, publication):
    store, snapshot = publication
    path = tmp_path / "bundle"
    path.mkdir()
    capture_spool(store, path / "spool")
    (path / "database.dump").write_bytes(b"unit-test-format-not-a-real-database")
    payload = tree_bytes(path)
    manifest = {
        "format": "asp-matched-backup-1",
        "schema": REVISION,
        "snapshots": [registered(snapshot)],
        "files": {
            name: {"bytes": len(value), "sha256": digest(value)} for name, value in payload.items()
        },
    }
    raw = canonical(manifest)
    (path / "backup.json").write_bytes(raw)
    return path, digest(raw)


def test_bundle_integrity_requires_external_trusted_manifest_digest(bundle):
    path, expected = bundle
    assert verify_bundle(path, expected)["schema"] == REVISION
    with pytest.raises(MaintenanceError, match="manifest_integrity"):
        verify_bundle(path, "0" * 64)


@pytest.mark.parametrize("mutation", ["missing", "corrupt", "extra", "manifest"])
def test_bundle_rejects_missing_corrupt_extra_or_relabelled_bytes(bundle, mutation):
    path, expected = bundle
    if mutation == "missing":
        (path / "database.dump").unlink()
    elif mutation == "corrupt":
        (path / "database.dump").write_bytes(b"corrupted")
    elif mutation == "extra":
        (path / "unexpected.txt").write_bytes(b"extra")
    else:
        manifest = json.loads((path / "backup.json").read_bytes())
        manifest["schema"] = "unapproved"
        (path / "backup.json").write_bytes(canonical(manifest))
    with pytest.raises(MaintenanceError):
        verify_bundle(path, expected)


def test_restore_rejects_retained_target_before_reading_backup(tmp_path):
    with pytest.raises(MaintenanceError, match="retained_restore_forbidden"):
        restore(Database(), tmp_path / "not-read", "0" * 64, tmp_path / "not-touched")
    assert not (tmp_path / "not-touched").exists()


def test_database_target_selection_is_closed():
    with pytest.raises(MaintenanceError):
        Database("arbitrary")


@pytest.mark.parametrize(
    "mode,instance", [("development", "a" * 32), ("clean", "a" * 32), ("restore", "../outside")]
)
def test_disposable_instances_cannot_select_arbitrary_resources(mode, instance):
    with pytest.raises(MaintenanceError):
        Database(mode, instance)


def test_disposable_instance_has_exact_separate_namespace_and_spool():
    identifier = "a" * 32
    database = Database("restore", identifier)
    assert database.project == "asp-phase7-restore-" + identifier
    assert database.private_root.name == "phase7-restore-" + identifier
    assert database.name == "asp_phase7_restore" and database.user == "asp_restore"


def test_report_storage_quota_fails_before_creating_an_artifact(tmp_path):
    from ai_security_platform.reporting.files import MAX_ARTIFACTS, write_artifact

    root = tmp_path / ".local/reports"
    root.mkdir(parents=True)
    for index in range(MAX_ARTIFACTS):
        (root / f"retained-{index}.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="artifact_storage_quota"):
        write_artifact(tmp_path, "must-not-appear", "json", b"{}")
    assert not (root / "must-not-appear.json").exists()
    assert len(list(root.glob("retained-*.json"))) == MAX_ARTIFACTS


def test_backup_quota_counts_partial_bundles_and_never_prunes(publication, tmp_path):
    store, _ = publication
    directory = tmp_path / "backups"
    directory.mkdir()
    (directory / ".platform-backups").write_bytes(BACKUP_MARKER)
    for _ in range(3):
        (directory / uuid4().hex).mkdir()
    before = sorted(p.name for p in directory.iterdir())
    with pytest.raises(MaintenanceError, match="backup_count_quota"):
        backup(ReferenceDatabase([]), store, directory)
    assert sorted(p.name for p in directory.iterdir()) == before


def test_backup_refuses_unowned_nonempty_directory(publication, tmp_path):
    store, _ = publication
    directory = tmp_path / "unowned"
    directory.mkdir()
    (directory / "preserve.txt").write_bytes(b"preserve")
    with pytest.raises(MaintenanceError, match="unrecognized_backup_root"):
        backup(ReferenceDatabase([]), store, directory)
    assert (directory / "preserve.txt").read_bytes() == b"preserve"


def test_long_path_cleanup_or_explicit_windows_namespace_rejection(tmp_path):
    parent = tmp_path / "published"
    parent.mkdir()
    key = uuid4().hex
    if os.name == "nt":
        # Fixture creation uses the explicit extended namespace. Intake/maintenance
        # intentionally do not accept that namespace on this supported local host.
        from pathlib import Path

        parent = Path("\\\\?\\" + str(parent.absolute()))
    directory = parent / key / "files" / ("a" * 60) / ("b" * 60) / ("c" * 60)
    directory.mkdir(parents=True)
    (directory / (("d" * 45) + ".py")).write_bytes(b"inert")
    if os.name == "nt":
        with pytest.raises(SnapshotError, match="unsupported_filesystem"):
            remove_owned_tree(parent, key)
        assert (directory / (("d" * 45) + ".py")).read_bytes() == b"inert"
    else:
        remove_owned_tree(parent, key)
        assert not (parent / key).exists()


def test_maintenance_parser_does_not_echo_sensitive_arguments(monkeypatch, capsys):
    import sys

    from scripts.maintenance import main

    sensitive = "SYNTHETIC_SECRET_do_not_echo"
    monkeypatch.setattr(sys, "argv", ["maintenance", "prepare-sandbox", sensitive])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 2
    captured = capsys.readouterr()
    assert sensitive not in captured.out + captured.err
    assert json.loads(captured.out)["error"] == "invalid_command"


def test_maintenance_rejects_traversal_with_safe_category(monkeypatch, capsys):
    import sys

    from scripts.maintenance import main

    monkeypatch.setattr(
        sys, "argv", ["maintenance", "verify", "--key", "../outside", "--manifest-digest", "0" * 64]
    )
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 2
    output = capsys.readouterr().out
    assert "../outside" not in output
    assert json.loads(output)["error"] == "invalid_backup_identity"


def test_sandbox_consumers_never_inherit_launcher_capability():
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[2]
    services = yaml.safe_load((root / "compose.phase7.yaml").read_text())["services"]
    assert services["api"]["environment"]["ASP_LAUNCHER_TOKEN"]
    for name in ["worker", "triage-worker"]:
        consumer = services[name]
        assert consumer["environment"]["ASP_LAUNCHER_TOKEN"] == ""
        assert consumer["environment"]["ASP_HOSTED_ENABLED"] == "false"
        assert consumer["ports"] == []
        assert consumer["read_only"] and consumer["cap_drop"] == ["ALL"]
        assert consumer["volumes"][0]["read_only"]
