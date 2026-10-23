"""Real PostgreSQL/reference/NTFS quota and cleanup proofs in the clean sandbox."""

import json
import subprocess
import time
from dataclasses import replace
from uuid import uuid4

from dotenv import dotenv_values

from ai_security_platform.snapshots.policy import DEFAULT_LIMITS, SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore
from scripts.lifecycle import ROOT, Database, inventory, private_directory, retain, run
from scripts.validate_local import request


def main():
    database = Database("clean")
    database.guard()
    config = dotenv_values(database.private_root / "environment.env")
    token = config["ASP_PHASE7_API_TOKEN"]
    base = "http://127.0.0.1:18088"
    checks = {}
    assert request(base, "/ready", method="GET").status_code == 200
    assert database.sql("SELECT version_num FROM alembic_version") == "0004_triage_review"
    run(
        [
            *database.compose,
            "run",
            "--rm",
            "--no-deps",
            "api",
            "uv",
            "run",
            "--no-sync",
            "alembic",
            "upgrade",
            "head",
        ]
    )
    checks["fresh_and_repeatable_clean_schema_at_expected_revision"] = True
    assert request(base, "/api/v1/triage-config", method="GET").status_code == 401
    assert (
        request(base, "/api/v1/triage-config", token, method="GET").json()["hosted_enabled"]
        is False
    )
    checks["clean_api_authentication_and_hosted_deny_default"] = True
    source = private_directory(ROOT / ".cache" / ("phase7-retention-source-" + uuid4().hex))
    (source / "app.py").write_bytes(b"ASP_FAKE_FINDING\nASP_FAKE_CONFIG\n")
    store = SnapshotStore(database.private_root / "spool", require_readonly=False)
    protected = store.create(source, label="phase7-clean-diagnostic")
    project = request(
        base, "/api/v1/projects", token, method="POST", json={"name": "Phase 7 clean diagnostic"}
    ).json()
    registered = request(
        base,
        "/api/v1/source-snapshots",
        token,
        method="POST",
        json={
            "project_id": project["id"],
            "snapshot_key": protected.manifest.snapshot_key,
            "manifest_digest": protected.manifest_digest,
        },
    )
    assert registered.status_code == 201
    run([*database.compose, "stop", "worker"])
    scan = request(
        base,
        "/api/v1/scan-runs",
        token,
        method="POST",
        headers={"Idempotency-Key": "phase7-clean-" + uuid4().hex},
        json={
            "project_id": project["id"],
            "snapshot_id": registered.json()["id"],
            "profile_id": "fake-v1",
        },
    )
    assert scan.status_code == 202
    orphan = store.create(source, label="phase7-controlled-orphan")
    quota = SnapshotStore(store.root, replace(DEFAULT_LIMITS, snapshots=2), require_readonly=False)
    try:
        quota.create(source)
    except SnapshotError as error:
        assert str(error) == "spool_quota"
    else:
        raise AssertionError("Quota was not enforced")
    checks["quota_rejects_admission_without_deleting_referenced_source"] = True
    with database.freeze():
        response = subprocess.run(
            database.command(
                "psql",
                "-XAtq",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                database.user,
                "-d",
                database.name,
                "-c",
                "BEGIN; SET lock_timeout='200ms'; UPDATE source_snapshots "
                "SET retention_state=retention_state; ROLLBACK",
            ),
            capture_output=True,
        )
        assert response.returncode != 0 and b"lock timeout" in response.stderr
    checks["real_database_freeze_blocks_concurrent_registration_table_writes"] = True
    # Test clock advances eligibility; actual database, files, locks and deletion
    # remain real. Production CLI never exposes this clock override.
    future = int(time.time()) + 8 * 86400
    before = database.state()
    dry = retain(database, store, now=future)
    assert dry["dry_run"] and dry["removed"] == 0
    assert len([item for item in dry["items"] if item["eligible"]]) == 1
    checks["dry_run_preserves_expired_orphan_and_pending_source"] = True
    applied = retain(database, store, now=future, apply=True)
    assert applied["removed"] == 1 and applied["registered_snapshots_removed"] == 0
    assert store.verify(protected.manifest.snapshot_key, protected.manifest_digest)
    assert not (store.root / "published" / orphan.manifest.snapshot_key).exists()
    assert database.state() == before
    checks["apply_reclaims_only_unregistered_orphan_and_preserves_all_database_rows"] = True
    assert (
        request(base, "/api/v1/scan-runs/" + scan.json()["id"], token, method="GET").json()[
            "status"
        ]
        == "queued"
    )
    quota.create(source, label="phase7-quota-recovered")
    checks["reclamation_restores_capacity_without_overwriting_sources"] = True
    run([*database.compose, "up", "-d", "--wait", "--no-build", "worker"])
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = request(base, "/api/v1/scan-runs/" + scan.json()["id"], token, method="GET").json()
        if result["status"] in {"succeeded", "partial", "failed"}:
            break
        time.sleep(0.25)
    assert result["status"] == "succeeded"
    findings = request(
        base, "/api/v1/scan-runs/" + scan.json()["id"] + "/findings", token, method="GET"
    ).json()["items"]
    assert findings and all(row["synthetic"] for row in findings)
    checks["clean_independent_worker_reads_restored_safe_spool_and_publishes_diagnostics"] = True
    identifier = findings[0]["id"]
    triage = request(
        base,
        "/api/v1/findings/" + identifier + "/triage",
        token,
        method="POST",
        headers={"Idempotency-Key": "phase7-clean-triage-" + uuid4().hex},
        json={"provider": "deterministic-v1"},
    )
    assert triage.status_code == 202
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = request(
            base, "/api/v1/triage-runs/" + triage.json()["id"], token, method="GET"
        ).json()
        if result["status"] in {"succeeded", "unavailable", "failed"}:
            break
        time.sleep(0.25)
    assert result["status"] == "succeeded" and result["assessment"]["assessment"] == "abstain"
    assert result["provider"] == "deterministic-v1"
    checks["clean_independent_triage_worker_runs_offline_without_model_credentials"] = True
    final = inventory(store, database.snapshots())
    evidence = {
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "mode": (
            "Actual PostgreSQL/NTFS/Docker processes; only retention age "
            "is advanced in the controlled test clock"
        ),
        "production_retained_spool_touched": False,
        "database_rows_deleted": 0,
        "orphan_publications_removed": 1,
        "registered_publications_removed": 0,
        "final_spool_bytes": final["bytes"],
        "final_publications": final["publications"],
        "clean_scan_findings": "synthetic diagnostic markers; not genuine vulnerability detections",
    }
    (ROOT / "docs/phase7/retention-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"retention_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
