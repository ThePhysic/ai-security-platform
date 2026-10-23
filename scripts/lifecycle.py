"""Trusted host maintenance primitives. Never imported by API, workers or agents.

Only fixed Compose database identities are supported. No archive ingestion, generic
Docker proxy, automatic history deletion, credential backup or retained-data restore.
"""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from ai_security_platform.snapshots.filesystem import PinnedTree
from ai_security_platform.snapshots.policy import DEFAULT_LIMITS, canonical, digest
from ai_security_platform.snapshots.removal import remove_owned_tree
from ai_security_platform.snapshots.store import KEY, MARKER, SHA, SnapshotStore, _check_ancestors
from ai_security_platform.storage import models as _models  # noqa: F401
from ai_security_platform.storage.base import Base

ROOT = Path(__file__).resolve().parents[1]
TABLES = tuple(sorted(Base.metadata.tables)) + ("alembic_version",)
REVISION = "0004_triage_review"
BACKUP_MARKER = b"ai-security-platform-private-backups-v1\n"
BACKUP_LIMIT = 384 * 1024 * 1024
BUNDLE_LIMITS = replace(
    DEFAULT_LIMITS,
    files=20000,
    directories=5000,
    entries=25000,
    file_bytes=64 * 1024 * 1024,
    total_bytes=BACKUP_LIMIT,
    path_bytes=480,
    depth=24,
)


class MaintenanceError(RuntimeError):
    """Sanitized fixed category only; subprocess output stays private."""


def private_directory(path):
    path = Path(os.path.abspath(path))
    _check_ancestors(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        from ai_security_platform.snapshots.windows import protect_directory, require_ntfs

        require_ntfs(path)
        protect_directory(path)
    else:
        if path.stat().st_uid != os.getuid():
            raise MaintenanceError("private_directory_owner")
        path.chmod(0o700)
    return path


def run(command, *, input=None, timeout=90):
    result = subprocess.run(command, cwd=ROOT, input=input, capture_output=True, timeout=timeout)
    if result.returncode:
        raise MaintenanceError("maintenance_command_failed")
    return result.stdout


class Database:
    def __init__(self, mode="development", instance=None):
        if mode not in {"development", "restore", "clean"}:
            raise MaintenanceError("database_target_not_approved")
        if instance is not None and (mode != "restore" or not re.fullmatch(KEY, instance)):
            raise MaintenanceError("invalid_disposable_instance")
        self.mode = mode
        self.instance = instance
        self.project = "asp-phase1-dev" if mode == "development" else "asp-phase7-" + mode
        if instance is not None:
            self.project += "-" + instance
        self.private_root = (
            ROOT / ".local" / ("phase7-" + mode + ("-" + instance if instance else ""))
        )
        self.name = "asp_dev" if mode == "development" else "asp_phase7_" + mode
        self.user = "asp_owner" if mode == "development" else "asp_" + mode
        if mode == "development":
            self.compose = ["docker", "--context", "desktop-linux", "compose", "-p", self.project]
        else:
            self.compose = [
                "docker",
                "--context",
                "desktop-linux",
                "compose",
                "--env-file",
                str(self.private_root / "environment.env"),
                "-f",
                str(ROOT / "compose.phase7.yaml"),
                "-p",
                self.project,
            ]

    def command(self, *args):
        return [*self.compose, "exec", "-T", "db", *args]

    def sql(self, statement):
        return (
            run(
                self.command(
                    "psql",
                    "-XAtq",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    self.user,
                    "-d",
                    self.name,
                    "-c",
                    statement,
                )
            )
            .decode()
            .strip()
        )

    def guard(self, *, empty=False):
        identifier = run([*self.compose, "ps", "-q", "db"]).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", identifier):
            raise MaintenanceError("database_container_unavailable")
        info = json.loads(
            run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"ports":{{json .HostConfig.PortBindings}}}',
                    identifier,
                ]
            )
        )
        if info["project"] != self.project or info["service"] != "db" or info["ports"]:
            raise MaintenanceError("database_container_identity")
        if (
            self.sql("SELECT current_database() || ':' || current_user")
            != self.name + ":" + self.user
        ):
            raise MaintenanceError("database_identity")
        if empty and self.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'") != "0":
            raise MaintenanceError("restore_target_not_empty")

    @contextmanager
    def freeze(self):
        self.guard()
        # SHARE blocks application INSERT/UPDATE/DELETE and DDL while allowing dump
        # readers. Finite lock/statement/idle-transaction timeouts bound operator impact.
        process = subprocess.Popen(
            self.command(
                "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-U", self.user, "-d", self.name
            ),
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            process.stdin.write(
                (
                    "BEGIN; SET lock_timeout='5s'; SET statement_timeout='15s'; "
                    "SET idle_in_transaction_session_timeout='180s'; LOCK TABLE "
                    + ",".join('public."' + table + '"' for table in TABLES)
                    + " IN SHARE MODE; SELECT 'MAINTENANCE_LOCKED';\n"
                ).encode()
            )
            process.stdin.flush()
            lines = queue.Queue()
            threading.Thread(
                target=lambda: lines.put(process.stdout.readline()), daemon=True
            ).start()
            if lines.get(timeout=20).strip() != b"MAINTENANCE_LOCKED":
                raise MaintenanceError("database_freeze_failed")
            yield process
            if process.poll() is not None:
                raise MaintenanceError("database_freeze_lost")
        except queue.Empty:
            raise MaintenanceError("database_freeze_timeout") from None
        finally:
            if process.poll() is None:
                process.stdin.close()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()

    def state(self):
        result = {}
        for table in TABLES:
            if int(self.sql('SELECT count(*) FROM public."' + table + '"')) > 100000:
                raise MaintenanceError("backup_row_budget")
            hashes = self.sql(
                'SELECT md5(row_to_json(t)::text) FROM public."' + table + '" t ORDER BY 1'
            ).splitlines()
            result[table] = {"rows": len(hashes), "digest": digest(canonical(hashes))}
        return result

    def snapshots(self):
        return json.loads(
            self.sql(
                "SELECT coalesce(json_agg(t ORDER BY t.spool_key),'[]') FROM "
                "(SELECT spool_key,manifest_digest,verified,retention_state "
                "FROM source_snapshots) t"
            )
        )


def manifest_bytes(store, key):
    limits = replace(
        DEFAULT_LIMITS,
        files=DEFAULT_LIMITS.files + 1,
        directories=DEFAULT_LIMITS.directories + 1,
        total_bytes=DEFAULT_LIMITS.total_bytes + DEFAULT_LIMITS.manifest_bytes,
        path_bytes=DEFAULT_LIMITS.path_bytes + 40,
        depth=DEFAULT_LIMITS.depth + 2,
    )
    with PinnedTree(store.root / "published" / key, limits, apply_policy=False) as tree:
        data = tree.read()
        tree.assert_unchanged(data)
    raw = data.get("manifest.json", b"")
    if not raw or len(raw) > DEFAULT_LIMITS.manifest_bytes:
        raise MaintenanceError("manifest_budget_or_missing")
    return raw


def inventory(store, records, *, now=None, grace=7 * 86400):
    """Every registered source is retained, including expired/historical sources.

    Foreign keys make scans/findings/jobs/triage/reviews transitively protected.
    Unregistered publications are eligible only after the maximum intake lifetime.
    """
    if grace < 7 * 86400:
        raise MaintenanceError("unsafe_retention_grace")
    now = int(time.time()) if now is None else now
    _check_ancestors(store.root)
    if (store.root / ".platform-spool").read_bytes() != MARKER:
        raise MaintenanceError("unrecognized_spool")
    _check_ancestors(store.root / "published")
    _check_ancestors(store.root / ".staging")
    size, count = store.usage()
    referenced = {record["spool_key"]: record for record in records}
    items = []
    for path in sorted((store.root / "published").iterdir()):
        if not re.fullmatch(KEY, path.name):
            raise MaintenanceError("unexpected_publication")
        _check_ancestors(path)
        raw = manifest_bytes(store, path.name)
        verified = store.verify(path.name, digest(raw))
        registered = referenced.get(path.name)
        if registered and registered["verified"] and registered["manifest_digest"] != digest(raw):
            raise MaintenanceError("registered_snapshot_mismatch")
        eligible = registered is None and now - verified.manifest.acquired_at >= grace
        items.append(
            {
                "key": path.name,
                "manifest_digest": digest(raw),
                "registered": registered is not None,
                "eligible": eligible,
                "reason": "retained_database_reference"
                if registered
                else "unregistered_expired"
                if eligible
                else "registration_grace",
            }
        )
    present = {item["key"] for item in items}
    missing = [
        r["spool_key"]
        for r in records
        if r["verified"] and r["retention_state"] == "published" and r["spool_key"] not in present
    ]
    if missing:
        raise MaintenanceError("referenced_source_missing")
    return {
        "bytes": size,
        "publications": count,
        "byte_limit": store.limits.spool_bytes,
        "publication_limit": store.limits.snapshots,
        "items": items,
        "admission_full": size >= store.limits.spool_bytes or count >= store.limits.snapshots,
    }


def retain(database, store, *, apply=False, now=None):
    with store.publishing_lock(), database.freeze():
        report = inventory(store, database.snapshots(), now=now)
        removed = 0
        if apply:
            for item in report["items"]:
                if item["eligible"]:
                    store.verify(item["key"], item["manifest_digest"])
                    remove_owned_tree(store.root / "published", item["key"])
                    removed += 1
        return report | {
            "dry_run": not apply,
            "removed": removed,
            "registered_snapshots_removed": 0,
            "database_rows_deleted": 0,
        }


def capture_spool(store, destination):
    destination.mkdir(mode=0o700)
    (destination / ".platform-spool").write_bytes(MARKER)
    (destination / ".staging").mkdir()
    (destination / "published").mkdir()
    for path in sorted((store.root / "published").iterdir()):
        raw = manifest_bytes(store, path.name)
        verified = store.verify(path.name, digest(raw))
        target = destination / "published" / path.name
        (target / "files").mkdir(parents=True)
        for directory in verified.manifest.directories:
            (target / "files" / directory).mkdir(parents=True, exist_ok=True)
        for name, value in verified.files.items():
            file = target / "files" / name
            file.write_bytes(value)
            file.chmod(0o444)
        (target / "manifest.json").write_bytes(raw)
        (target / "manifest.json").chmod(0o444)


def tree_bytes(path):
    with PinnedTree(path, BUNDLE_LIMITS, apply_policy=False) as tree:
        data = tree.read()
        tree.assert_unchanged(data)
        return data


def verify_bundle(path, expected_digest):
    if not re.fullmatch(SHA, expected_digest):
        raise MaintenanceError("trusted_backup_digest_required")
    data = tree_bytes(path)
    raw = data.pop("backup.json", None)
    if raw is None or digest(raw) != expected_digest or len(raw) > 4 * 1024 * 1024:
        raise MaintenanceError("backup_manifest_integrity")
    manifest = json.loads(raw)
    if (
        manifest.get("format") != "asp-matched-backup-1"
        or manifest.get("schema") != REVISION
        or canonical(manifest) != raw
    ):
        raise MaintenanceError("backup_format_or_schema")
    actual = {name: {"bytes": len(value), "sha256": digest(value)} for name, value in data.items()}
    if actual != manifest.get("files") or "database.dump" not in data:
        raise MaintenanceError("backup_payload_integrity")
    store = SnapshotStore(path / "spool", require_readonly=False)
    inventory(store, manifest["snapshots"])
    return manifest


def backup(database, store, directory):
    directory = private_directory(directory)
    marker = directory / ".platform-backups"
    if marker.exists():
        _check_ancestors(marker)
        if marker.read_bytes() != BACKUP_MARKER or marker.stat().st_nlink != 1:
            raise MaintenanceError("unrecognized_backup_root")
    elif any(directory.iterdir()):
        raise MaintenanceError("unrecognized_backup_root")
    else:
        marker.write_bytes(BACKUP_MARKER)
    key = uuid4().hex
    with store.publishing_lock(), database.freeze() as owner:
        # Serialized before eligibility/quota decisions, not just payload copying.
        entries = [p for p in directory.iterdir() if p != marker]
        if any(not re.fullmatch(KEY, p.name) for p in entries):
            raise MaintenanceError("unexpected_backup_entry")
        if len(entries) >= 3:
            raise MaintenanceError("backup_count_quota")
        stage = private_directory(directory / key)
        records = database.snapshots()
        inventory(store, records)
        before = database.state()
        capture_spool(store, stage / "spool")
        (stage / "policies").mkdir()
        for source in sorted((ROOT / "policies").iterdir()):
            with PinnedTree(source.parent, apply_policy=False) as tree:
                policies = tree.read()
                tree.assert_unchanged(policies)
            for name, value in policies.items():
                (stage / "policies" / name).write_bytes(value)
            break
        # Bound dump size while streaming and terminate only our own process on overflow.
        command = database.command(
            "pg_dump",
            "-U",
            database.user,
            "-d",
            database.name,
            "--format=custom",
            "--no-owner",
            "--no-acl",
            "--lock-wait-timeout=5s",
        )
        with (stage / "database.dump").open("xb") as output:
            process = subprocess.Popen(
                command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            deadline = threading.Timer(90, process.terminate)
            deadline.start()
            size = 0
            try:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 64 * 1024 * 1024:
                        raise MaintenanceError("backup_dump_budget")
                    output.write(chunk)
                if process.wait(timeout=5):
                    raise MaintenanceError("backup_dump_failed")
                output.flush()
                os.fsync(output.fileno())
            finally:
                deadline.cancel()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                process.stdout.close()
        if owner.poll() is not None or database.state() != before:
            raise MaintenanceError("backup_consistency_lost")
        payload = tree_bytes(stage)
        manifest = {
            "format": "asp-matched-backup-1",
            "schema": REVISION,
            "application": {
                "python": sys.version.split()[0],
                "uv_lock_sha256": digest((ROOT / "uv.lock").read_bytes()),
                "pyproject_sha256": digest((ROOT / "pyproject.toml").read_bytes()),
            },
            "created_at": int(time.time()),
            "key": key,
            "database": database.name,
            "postgresql": database.sql("SHOW server_version"),
            "tables": before,
            "snapshots": records,
            "external_assets": json.loads((ROOT / "policies/scanners.lock.json").read_text()),
            "requirements": (
                "Trusted original application and pinned scanner images/DB assets are "
                "separately retained; no credentials or executable image archives in this backup"
            ),
            "files": {
                name: {"bytes": len(value), "sha256": digest(value)}
                for name, value in payload.items()
            },
        }
        raw = canonical(manifest)
        with (stage / "backup.json").open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        expected = digest(raw)
        verify_bundle(stage, expected)
    return {
        "key": key,
        "manifest_digest": expected,
        "bytes": sum(len(v) for v in payload.values()),
        "schema": REVISION,
        "snapshots": len(records),
        "retained_rows_changed": False,
    }


def restore(database, path, expected_digest, destination, *, interrupt=False):
    if database.mode not in {"restore", "clean"}:
        raise MaintenanceError("retained_restore_forbidden")
    # Pin every backup directory/file for the entire operation. On NTFS these
    # handles deny competing writes/deletes; on POSIX identity is rechecked.
    with PinnedTree(path, BUNDLE_LIMITS, apply_policy=False) as pinned:
        captured = pinned.read()
        result = _restore(database, path, expected_digest, destination, interrupt=interrupt)
        pinned.assert_unchanged(captured)
        return result


def _restore(database, path, expected_digest, destination, *, interrupt=False):
    if database.mode not in {"restore", "clean"}:
        raise MaintenanceError("retained_restore_forbidden")
    # Entire backup verification precedes any target write or database change.
    manifest = verify_bundle(path, expected_digest)
    database.guard()
    expected_root = database.private_root / "spool"
    if Path(os.path.abspath(destination)) != expected_root:
        raise MaintenanceError("restore_spool_target_not_approved")
    _check_ancestors(expected_root)
    table_count = database.sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'")
    if table_count != "0" and database.state() != manifest["tables"]:
        raise MaintenanceError("restore_target_not_empty_or_matching")
    if expected_root.exists() and any(expected_root.iterdir()):
        existing = SnapshotStore(expected_root, require_readonly=False)
        inventory(existing, manifest["snapshots"])
        expected_data = tree_bytes(path / "spool")
        current = tree_bytes(expected_root)
        current.pop(".publish.lock", None)
        if current != expected_data:
            raise MaintenanceError("restore_destination_not_matching")
    else:
        # An interrupted copy is retained for inspection, never recursively cleared.
        private_directory(expected_root.parent)
        if expected_root.exists():
            expected_root.rmdir()  # Only an explicitly verified empty directory.
        capture_spool(SnapshotStore(path / "spool", require_readonly=False), expected_root)
        SnapshotStore(expected_root, require_readonly=False).initialize()
    if interrupt:
        raise MaintenanceError("controlled_restore_interruption")
    if table_count == "0":
        database.guard(empty=True)
        with (path / "database.dump").open("rb") as stream:
            result = subprocess.run(
                database.command(
                    "pg_restore",
                    "-U",
                    database.user,
                    "-d",
                    database.name,
                    "--no-owner",
                    "--no-acl",
                    "--exit-on-error",
                    "--single-transaction",
                ),
                cwd=ROOT,
                stdin=stream,
                capture_output=True,
                timeout=90,
            )
        if result.returncode:
            raise MaintenanceError("restore_transaction_failed")
    if database.state() != manifest["tables"]:
        raise MaintenanceError("restored_database_mismatch")
    inventory(SnapshotStore(expected_root, require_readonly=False), database.snapshots())
    return {
        "restored": True,
        "schema": REVISION,
        "tables_verified": len(manifest["tables"]),
        "snapshots_verified": len([r for r in manifest["snapshots"] if r["verified"]]),
        "target": database.project,
        "retained_database_used_as_target": False,
    }
