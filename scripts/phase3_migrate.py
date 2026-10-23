"""Guarded retained-data forward migration. No destructive development reversal."""

import json
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values  # noqa: E402

from scripts.validate_local import DEV, inspect_safe, run  # noqa: E402

SERVICES = [*DEV, "--profile", "workers", "--profile", "triage"]


def main():
    values = dotenv_values(ROOT / ".env")
    assert values.get("ASP_REAL_SCANNING_ENABLED", "false").lower() == "false"
    assert values.get("ASP_HOSTED_ENABLED", "false").lower() == "false"
    identifier = run(*DEV, "ps", "-q", "db")
    assert inspect_safe(identifier)["project"] == "asp-phase1-dev"

    def sql(statement):
        return run(
            *DEV,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "asp_owner",
            "-d",
            "asp_dev",
            "-At",
            "-c",
            statement,
        )

    assert sql("SELECT current_database() || ':' || current_user") == "asp_dev:asp_owner"
    previous = sql("SELECT version_num FROM alembic_version")
    assert previous in {"0003_scanner_handoff", "0004_triage_review"}
    run(*SERVICES, "stop", "api", "worker", "triage-worker")
    tables = [
        "projects",
        "source_snapshots",
        "scan_runs",
        "audit_events",
        "scanner_runs",
        "jobs",
        "job_attempts",
        "findings",
        "idempotency_requests",
        "scanner_invocations",
        "launcher_capabilities",
    ]
    count_sql = "SELECT " + ",".join("(SELECT count(*) FROM " + table + ")" for table in tables)
    before = sql(count_sql)
    digest_sql = "SELECT " + ",".join(
        "(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY t.id),'')) FROM "
        + table
        + " t)"
        for table in ["scan_runs", "findings", "source_snapshots", "scanner_runs", "audit_events"]
    )
    digests = sql(digest_sql)
    backup = ROOT / ".local/backups"
    backup.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        from ai_security_platform.snapshots.windows import protect_directory

        protect_directory(backup)
    name = "phase3-before-" + uuid4().hex + ".dump"
    run(
        *DEV,
        "exec",
        "-T",
        "db",
        "pg_dump",
        "-U",
        "asp_owner",
        "-d",
        "asp_dev",
        "-Fc",
        "-f",
        "/tmp/" + name,
    )
    run("docker", "cp", identifier + ":/tmp/" + name, str(backup / name))
    assert (backup / name).stat().st_size > 0
    run(*DEV, "exec", "-T", "db", "rm", "/tmp/" + name)
    run(*SERVICES, "build", "api", "worker", "triage-worker")
    run(*DEV, "run", "--rm", "api", "uv", "run", "--no-sync", "alembic", "upgrade", "head")
    assert sql("SELECT version_num FROM alembic_version") == "0004_triage_review"
    assert before == sql(count_sql) and digests == sql(digest_sql)
    run(*SERVICES, "up", "-d", "--wait", "api", "worker", "triage-worker")
    evidence = {
        "database": "asp_dev",
        "before_revision": previous,
        "after_revision": "0004_triage_review",
        "tables": tables,
        "counts_before": before,
        "counts_after": sql(count_sql),
        "retained_content_digests_before": digests,
        "retained_content_digests_after": sql(digest_sql),
        "digest_order": [
            "scan_runs",
            "findings",
            "source_snapshots",
            "scanner_runs",
            "audit_events",
        ],
        "backup": ".local/backups/" + name,
        "backup_bytes": (backup / name).stat().st_size,
        "real_admission_enabled": False,
        "hosted_enabled": False,
        "spool_modified": False,
    }
    (ROOT / "docs/phase3/migration-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        "Forward migration complete; retained counts/content unchanged; "
        "scanner and hosted admission disabled."
    )


if __name__ == "__main__":
    main()
