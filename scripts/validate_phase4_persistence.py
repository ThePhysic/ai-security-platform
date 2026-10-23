"""Read retained resources across scoped real restarts; create no application records."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values  # noqa: E402

from scripts.validate_local import DEV, request, run, wait_ready  # noqa: E402
from scripts.validate_phase4_state import retained_rows  # noqa: E402


def main():
    values = dotenv_values(ROOT / ".env")
    assert values.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
    assert values.get("ASP_HOSTED_ENABLED", "false") == "false"
    token = values["ASP_API_TOKEN"]
    base = "http://127.0.0.1:" + values.get("ASP_API_PORT", "18081")
    started = datetime.now(UTC).isoformat()
    identity = run(
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
        "SELECT t.id,t.finding_id,s.id,s.project_id FROM triage_runs t "
        "JOIN triage_outcomes o ON o.triage_run_id=t.id "
        "JOIN scan_runs s ON s.id=t.scan_run_id "
        "JOIN reviews r ON r.finding_id=t.finding_id ORDER BY t.created_at DESC LIMIT 1",
    )
    triage, finding, scan, project = [str(UUID(v)) for v in identity.split("|")]
    paths = [
        "/projects/" + project,
        "/scan-runs/" + scan,
        "/findings/" + finding,
        "/triage-runs/" + triage,
        "/findings/" + finding + "/review",
        "/findings/" + finding + "/review-revisions",
    ]

    def read_resources():
        result = {}
        for path in paths:
            response = request(base, "/api/v1" + path, token, method="GET")
            assert response.status_code == 200
            result[path] = response.json()
        return result

    checks = {}
    before = retained_rows()
    resources = read_resources()
    checks["authenticated_retained_resource_reads"] = True
    checks["authentication_enforced"] = (
        request(base, "/api/v1" + paths[0], method="GET").status_code == 401
    )
    checks["host_enforced"] = (
        request(base, "/health", method="GET", headers={"Host": "untrusted.invalid"}).status_code
        == 400
    )
    checks["origin_enforced"] = (
        request(
            base, "/health", method="GET", headers={"Origin": "https://untrusted.invalid"}
        ).status_code
        == 403
    )
    synthetic = "SYNTHETIC_SECRET_" + "P" * 20
    oversized = request(base, "/health", method="GET", content=(synthetic + "x" * 65537).encode())
    checks["request_size_enforced"] = oversized.status_code == 413
    run(
        *DEV,
        "--profile",
        "workers",
        "--profile",
        "triage",
        "restart",
        "api",
        "worker",
        "triage-worker",
    )
    wait_ready(base)
    checks["actual_api_worker_restarts_preserve_resources"] = resources == read_resources()
    stopped = False
    try:
        run(*DEV, "stop", "db")
        stopped = True
        checks["actual_db_unavailability_health_ready"] = (
            request(base, "/health", method="GET").status_code == 200
            and request(base, "/ready", method="GET").status_code == 503
        )
    finally:
        if stopped:
            run(*DEV, "up", "-d", "--wait", "db")
    wait_ready(base)
    checks["actual_db_restart_preserves_resources"] = resources == read_resources()
    checks["all_17_retained_tables_unchanged"] = before == retained_rows()
    logs = run(
        *DEV,
        "--profile",
        "workers",
        "--profile",
        "triage",
        "logs",
        "--no-color",
        "--since",
        started,
        "api",
        "worker",
        "triage-worker",
    )
    secrets = [
        synthetic,
        *[v for k, v in values.items() if v and (k.endswith("TOKEN") or k.endswith("PASSWORD"))],
    ]
    checks["logs_and_errors_contain_no_test_or_actual_credentials"] = all(
        v not in logs + oversized.text for v in secrets
    )
    assert all(checks.values()), [k for k, v in checks.items() if not v]
    result = {
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "resource_types": ["project", "scan", "finding", "triage", "review", "review_revisions"],
        "retained_table_count": 17,
        "created_or_modified_records": 0,
        "live_hosted_calls": 0,
        "restarted_services": ["api", "worker", "triage-worker", "db"],
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    (ROOT / "docs/phase4/persistence-evidence.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "persistence_checks": len(checks),
                "failed": 0,
                "skipped": 0,
                "application_records_modified": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
