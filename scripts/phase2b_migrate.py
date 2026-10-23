"""Explicit guarded forward migration; retained Phase 2A data is never reset."""

import json
import secrets
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_local import DEV, inspect_safe, run  # noqa: E402


def main():
    from dotenv import dotenv_values

    values = dotenv_values(ROOT / ".env")
    if not values.get("ASP_LAUNCHER_TOKEN"):
        assert run("git", "check-ignore", ".env") == ".env"
        with (ROOT / ".env").open("a", encoding="utf-8") as stream:
            stream.write("\nASP_LAUNCHER_TOKEN=" + secrets.token_urlsafe(48) + "\n")
    assert values.get("ASP_REAL_SCANNING_ENABLED", "false").lower() != "true"
    db = run(*DEV, "ps", "-q", "db")
    assert inspect_safe(db)["project"] == "asp-phase1-dev"

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
    revision = sql("SELECT version_num FROM alembic_version")
    assert revision in {"0002_orchestration", "0003_scanner_handoff"}
    worker = [*DEV, "--profile", "workers"]
    run(*worker, "stop", "api", "worker")
    names = [
        "projects",
        "source_snapshots",
        "scan_runs",
        "audit_events",
        "scanner_runs",
        "jobs",
        "job_attempts",
        "findings",
        "idempotency_requests",
    ]
    statement = "SELECT " + ",".join("(SELECT count(*) FROM " + name + ")" for name in names)
    before = sql(statement)
    backup = ROOT / ".local/backups"
    backup.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        from ai_security_platform.snapshots.windows import protect_directory

        protect_directory(backup)
    name = "phase2b-before-" + uuid4().hex + ".dump"
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
    run("docker", "cp", db + ":/tmp/" + name, str(backup / name))
    assert (backup / name).stat().st_size > 0
    run(*DEV, "exec", "-T", "db", "rm", "/tmp/" + name)
    run(*worker, "build", "api", "worker")
    run(*DEV, "run", "--rm", "api", "uv", "run", "--no-sync", "alembic", "upgrade", "head")
    assert sql("SELECT version_num FROM alembic_version") == "0003_scanner_handoff"
    after = sql(statement)
    assert before == after
    run(*worker, "up", "-d", "--wait", "api", "worker")
    evidence = {
        "database": "asp_dev",
        "before_revision": revision,
        "after_revision": "0003_scanner_handoff",
        "tables": names,
        "counts_before": before,
        "counts_after": after,
        "backup": ".local/backups/" + name,
        "backup_bytes": (backup / name).stat().st_size,
        "real_admission_enabled": False,
        "retained_spool_modified": False,
    }
    target = ROOT / "docs/phase2b/migration-evidence.json"
    target.write_text(json.dumps(evidence, indent=2) + "\n")
    print("Retained Phase 2A rows preserved; migration complete; real admission still closed.")


if __name__ == "__main__":
    main()
