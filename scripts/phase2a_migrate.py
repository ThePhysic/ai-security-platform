"""Explicit forward migration of retained, project-scoped development data."""

import json
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_local import DEV, inspect_safe, run  # noqa: E402


def main():
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
    before = sql(
        "SELECT (SELECT count(*) FROM projects), "
        "(SELECT count(*) FROM source_snapshots), (SELECT count(*) FROM scan_runs), "
        "(SELECT count(*) FROM audit_events)"
    )
    revision = sql("SELECT version_num FROM alembic_version")
    assert revision in {"0001_foundation", "0002_orchestration"}
    backup = ROOT / ".local" / "backups"
    backup.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        from ai_security_platform.snapshots.windows import protect_directory

        protect_directory(backup)
    else:
        backup.chmod(0o700)
    name = "phase2a-before-" + uuid4().hex + ".dump"
    run(*DEV, "stop", "api")
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
    run(*DEV, "--profile", "workers", "build", "api", "worker")
    run(*DEV, "run", "--rm", "api", "uv", "run", "--no-sync", "alembic", "upgrade", "head")
    assert sql("SELECT version_num FROM alembic_version") == "0002_orchestration"
    after = sql(
        "SELECT (SELECT count(*) FROM projects), "
        "(SELECT count(*) FROM source_snapshots), (SELECT count(*) FROM scan_runs), "
        "(SELECT count(*) FROM audit_events)"
    )
    assert before == after
    run(*DEV, "up", "-d", "--wait", "api")
    evidence = {
        "database": "asp_dev",
        "before_revision": revision,
        "after_revision": "0002_orchestration",
        "retained_counts_before": before,
        "retained_counts_after": after,
        "backup": ".local/backups/" + name,
        "backup_bytes": (backup / name).stat().st_size,
        "destructive_migration": False,
    }
    target = ROOT / "docs" / "phase2a" / "migration-evidence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + "\n")
    print("Forward migration verified; retained row counts unchanged; private backup recorded.")


if __name__ == "__main__":
    main()
