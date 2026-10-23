"""Additional real restore, corruption, unavailable-evidence and recovery proofs."""

import json
import subprocess
import time
from shutil import copytree
from uuid import uuid4

from dotenv import dotenv_values

from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore
from scripts.lifecycle import (
    ROOT,
    TABLES,
    Database,
    MaintenanceError,
    private_directory,
    restore,
    run,
    verify_bundle,
)
from scripts.validate_local import request


def main():
    receipt = json.loads(
        (ROOT / ".cache/phase7-backup-receipt.json").read_text(encoding="utf-8-sig")
    )
    backup = ROOT / ".local/backups/phase7" / receipt["key"]
    expected = receipt["manifest_digest"]
    manifest = verify_bundle(backup, expected)
    database = Database("restore")
    database.guard()
    evidence = json.loads((ROOT / "docs/phase7/restore-evidence.json").read_text())
    checks = evidence["checks"]
    private = private_directory(ROOT / ".cache" / ("phase7-restore-negative-" + uuid4().hex))
    for mutation in ["missing_source", "corrupt_dump", "mismatched_manifest"]:
        candidate = private / mutation
        copytree(backup, candidate)
        if mutation == "missing_source":
            missing = next((candidate / "spool/published").rglob("*.py"))
            assert missing.is_relative_to(private)
            missing.chmod(0o600)
            missing.unlink()
        elif mutation == "corrupt_dump":
            with (candidate / "database.dump").open("ab") as stream:
                stream.write(b"controlled-corruption")
        else:
            (candidate / "backup.json").write_bytes(b'{"format":"mismatched"}')
        before = database.state()
        try:
            restore(database, candidate, expected, ROOT / ".local/phase7-restore/spool")
        except (MaintenanceError, SnapshotError):
            pass
        else:
            raise AssertionError("Corrupt backup admitted")
        assert database.state() == before
        checks[mutation + "_rejected_without_database_mutation"] = True

    config = dotenv_values(ROOT / ".local/phase7-restore/environment.env")
    base = "http://127.0.0.1:18087"
    token = config["ASP_PHASE7_API_TOKEN"]
    assert request(base, "/ready", method="GET").status_code == 200
    assert request(base, "/api/v1/triage-config", method="GET").status_code == 401
    assert (
        request(base, "/api/v1/triage-config", token, method="GET").json()["hosted_enabled"]
        is False
    )
    checks["restored_api_ready_authenticated_and_hosted_disabled"] = True
    original = json.loads((ROOT / ".cache/phase6-browser-fixture.json").read_text())
    project = request(base, "/api/v1/projects/" + original["project"], token, method="GET")
    finding = request(base, "/api/v1/findings/" + original["finding"], token, method="GET")
    assert project.status_code == finding.status_code == 200
    review = request(
        base, "/api/v1/findings/" + original["review_finding"] + "/review", token, method="GET"
    )
    assert review.status_code == 200
    checks["restored_project_finding_and_review_queries"] = True
    scan = request(
        base, "/api/v1/scan-runs/" + original["scan"] + "/export?format=json", token, method="GET"
    )
    assert scan.status_code == 200 and scan.json()["scan"]["status"] == "succeeded"
    before_details = request(
        base, "/api/v1/scan-runs/" + original["scan"], token, method="GET"
    ).json()
    # Remove evidence from view only in this disposable spool, then put it back.
    snapshot_record = next(
        row
        for row in manifest["snapshots"]
        if row["spool_key"]
        == database.sql(
            "SELECT spool_key FROM source_snapshots WHERE id='" + original["snapshot"] + "'"
        )
    )
    store = SnapshotStore(ROOT / ".local/phase7-restore/spool", require_readonly=False)
    source = store.root / "published" / snapshot_record["spool_key"]
    quarantine = private / "quarantined-snapshot"
    run([*database.compose, "up", "-d", "--wait", "--no-build", "triage-worker"])
    try:
        source.rename(quarantine)
        response = request(
            base,
            f"/api/v1/findings/{original['finding']}/triage",
            token,
            method="POST",
            headers={"Idempotency-Key": "phase7-missing-" + uuid4().hex},
            json={"provider": "deterministic-v1"},
        )
        assert response.status_code == 202
        identifier = response.json()["id"]
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            triage = request(base, "/api/v1/triage-runs/" + identifier, token, method="GET").json()
            if triage["status"] in {"unavailable", "succeeded", "failed"}:
                break
            time.sleep(0.25)
        assert triage["status"] == "succeeded"
        assert triage["assessment"]["assessment"] == "abstain"
        assert triage["assessment"]["reason"] == "source_unavailable"
        checks["missing_restored_source_abstains_without_substitution"] = True
        after = request(
            base,
            "/api/v1/scan-runs/" + original["scan"] + "/export?format=json",
            token,
            method="GET",
        )
        assert after.status_code == 409
        assert after.json()["code"] == "export_evidence_invalid"
        current = request(base, "/api/v1/scan-runs/" + original["scan"], token, method="GET").json()
        assert current == before_details
        assert database.state()["findings"] == manifest["tables"]["findings"]
        checks["source_verified_export_refuses_missing_snapshot"] = True
        checks["missing_evidence_cannot_change_successful_scanner_results"] = True
    finally:
        if quarantine.exists():
            quarantine.rename(source)
    assert store.verify(snapshot_record["spool_key"], snapshot_record["manifest_digest"])
    assert (
        request(
            base,
            "/api/v1/scan-runs/" + original["scan"] + "/export?format=json",
            token,
            method="GET",
        ).content
        == scan.content
    )
    checks["disposable_source_reinstated_and_identity_verified"] = True

    # Actual interrupted pg_restore in a newly generated disposable DB, never a
    # retained or reused target. A trusted DDL probe gives a deterministic kill point.
    name = "asp_p7_interrupt_" + uuid4().hex
    database.sql("CREATE DATABASE " + name + " OWNER asp_restore")

    def sql(statement):
        return (
            run(
                database.command(
                    "psql",
                    "-XAtq",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "asp_restore",
                    "-d",
                    name,
                    "-c",
                    statement,
                )
            )
            .decode()
            .strip()
        )

    assert sql("SELECT current_database() || ':' || current_user") == name + ":asp_restore"
    sql(
        "CREATE FUNCTION public.phase7_pause() RETURNS event_trigger LANGUAGE plpgsql "
        "AS $$ BEGIN PERFORM pg_sleep(20); END $$; CREATE EVENT TRIGGER phase7_pause "
        "ON ddl_command_start WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.phase7_pause()"
    )
    with (backup / "database.dump").open("rb") as stream:
        process = subprocess.Popen(
            database.command(
                "pg_restore",
                "-U",
                "asp_restore",
                "-d",
                name,
                "--no-owner",
                "--no-acl",
                "--exit-on-error",
                "--single-transaction",
            ),
            cwd=ROOT,
            stdin=stream,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                pid = database.sql(
                    "SELECT pid FROM pg_stat_activity WHERE datname='"
                    + name
                    + "' AND application_name='pg_restore' AND wait_event='PgSleep'"
                )
                if pid:
                    break
                time.sleep(0.1)
            assert pid.isdigit(), "Restore did not reach deterministic interruption point"
            assert (
                database.sql(
                    "SELECT pg_terminate_backend("
                    + pid
                    + ") WHERE EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid="
                    + pid
                    + " AND datname='"
                    + name
                    + "')"
                )
                == "t"
            )
            assert process.wait(timeout=10) != 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stderr.close()
    assert sql("SELECT count(*) FROM pg_tables WHERE schemaname='public'") == "0"
    checks["actual_pg_restore_process_interruption_rolls_back_all_application_tables"] = True
    sql("ALTER EVENT TRIGGER phase7_pause DISABLE")
    with (backup / "database.dump").open("rb") as stream:
        result = subprocess.run(
            database.command(
                "pg_restore",
                "-U",
                "asp_restore",
                "-d",
                name,
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
    assert result.returncode == 0
    for table in TABLES:
        count = int(sql('SELECT count(*) FROM public."' + table + '"'))
        assert count == manifest["tables"][table]["rows"]
    checks["actual_interrupted_restore_retries_successfully"] = True
    checks["all_destructive_restore_tests_confined_to_verified_disposable_cluster"] = True
    evidence.update(
        {
            "passed": len(checks),
            "failed": 0,
            "skipped": 0,
            "actual_restore_interruption": (
                "PostgreSQL backend terminated during transactional DDL; "
                "all application tables rolled back; retry succeeded"
            ),
            "unrelated_or_retained_targets_modified": False,
        }
    )
    (ROOT / "docs/phase7/restore-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"restore_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
