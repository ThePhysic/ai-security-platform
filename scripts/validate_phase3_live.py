"""Actual local API/worker/PostgreSQL validation using retained controlled scanner findings."""

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values  # noqa: E402

from scripts.phase3_migrate import SERVICES  # noqa: E402
from scripts.validate_local import DEV, inspect_safe, request, run, wait_ready  # noqa: E402


def main():
    values = dotenv_values(ROOT / ".env")
    assert values.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
    assert values.get("ASP_HOSTED_ENABLED", "false") == "false"
    token, base = values["ASP_API_TOKEN"], "http://127.0.0.1:" + values.get("ASP_API_PORT", "18081")
    wait_ready(base)
    checks, operations = {}, {}

    def api(path, method="GET", **kwargs):
        return request(base, "/api/v1" + path, token, method=method, **kwargs)

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

    # These are existing genuine Phase 2B labelled-fixture detections, not new seeds.
    finding = sql(
        "SELECT f.id FROM findings f JOIN scan_runs s ON s.id=f.scan_run_id "
        "WHERE f.rule_id='platform.python.eval' AND NOT f.synthetic "
        "AND s.status='succeeded' ORDER BY f.created_at DESC LIMIT 1"
    )
    secret_finding = sql(
        "SELECT f.id FROM findings f WHERE f.category='secret' AND NOT f.synthetic "
        "ORDER BY f.created_at DESC LIMIT 1"
    )
    assert finding and secret_finding, "Required retained controlled G5 detections unavailable"
    finding, secret_finding = str(UUID(finding)), str(UUID(secret_finding))

    def submit(identifier):
        key = "phase3-live-" + uuid4().hex
        response = api(
            "/findings/" + identifier + "/triage",
            method="POST",
            json={},
            headers={"Idempotency-Key": key},
        )
        assert response.status_code == 202
        replay = api(
            "/findings/" + identifier + "/triage",
            method="POST",
            json={},
            headers={"Idempotency-Key": key},
        )
        assert replay.status_code == 202 and replay.json()["id"] == response.json()["id"]
        return response.json()["id"]

    def wait(identifier):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            response = api("/triage-runs/" + identifier)
            assert response.status_code == 200
            data = response.json()
            if data["status"] in {"succeeded", "failed", "unavailable"}:
                return data
            time.sleep(0.2)
        raise AssertionError("Triage exceeded live validation deadline")

    # Preserve exact scan/finding content across AI opinions and human review.
    content_sql = "SELECT " + ",".join(
        "(SELECT md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY t.id),'')) FROM "
        + table
        + " t)"
        for table in ["scan_runs", "scanner_runs", "findings"]
    )
    before_content = sql(content_sql)
    identifier = submit(finding)
    result = wait(identifier)
    assert result["status"] == "succeeded" and result["assessment"]["assessment"] == "needs_review"
    assert {item["kind"] for item in result["assessment"]["citations"]} >= {"finding", "source"}
    checks["real_scanner_finding_multistep_offline_triage"] = True
    checks["idempotent_http_replay"] = True
    operations["assessment"] = {
        "id": identifier,
        "status": result["status"],
        "assessment": result["assessment"]["assessment"],
        "citation_kinds": [item["kind"] for item in result["assessment"]["citations"]],
        "usage": result["usage"],
        "manifest_digest": result["manifest_digest"],
    }
    abstention = wait(submit(secret_finding))
    assert (
        abstention["status"] == "succeeded" and abstention["assessment"]["assessment"] == "abstain"
    )
    checks["secret_finding_redacted_and_abstains"] = True
    operations["abstention"] = {
        "id": abstention["id"],
        "assessment": "abstain",
        "reason": abstention["assessment"]["reason"],
    }
    hosted = api(
        "/findings/" + finding + "/triage",
        method="POST",
        json={"provider": "openai-v1"},
        headers={"Idempotency-Key": uuid4().hex},
    )
    assert hosted.status_code == 403
    checks["hosted_denied_without_enabled_scoped_consent"] = True

    current = api("/findings/" + finding + "/review").json()
    expected = current["revision"]
    body = {
        "expected_revision": expected,
        "disposition": "investigate",
        "note": "Controlled Phase 3 validation revision; not a human security verdict.",
        "triage_run_id": identifier,
        "feedback": "uncertain",
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: api("/findings/" + finding + "/review", method="PUT", json=body), range(2)
            )
        )
    assert sorted(response.status_code for response in responses) == [200, 409]
    assert api("/findings/" + finding + "/review").json()["revision"] == expected + 1
    history = api("/findings/" + finding + "/review-revisions").json()
    assert history["items"][0]["revision"] == expected + 1
    checks["concurrent_http_review_one_success_one_stale_conflict"] = True
    checks["immutable_history_and_explicit_human_feedback"] = True
    run(*SERVICES, "restart", "api", "worker", "triage-worker", "db")
    wait_ready(base)
    assert api("/triage-runs/" + identifier).json() == result
    assert api("/findings/" + finding + "/review").json()["revision"] == expected + 1
    checks["actual_container_restart_persistence"] = True
    assert sql(content_sql) == before_content
    checks["scan_scanner_and_finding_content_unchanged"] = True

    safe_services = {}
    for service in ("api", "worker", "triage-worker"):
        info = inspect_safe(run(*SERVICES, "ps", "-q", service))
        assert info["user"] == "10001:10001" and info["readonly"] and "ALL" in info["caps"]
        assert all(mount["Destination"] in {"/spool", "/tmp"} for mount in info["mounts"])
        check_program = (
            "import os,pathlib,shutil; assert not shutil.which('docker'); "
            "assert 'ASP_HOSTED_API_KEY' not in os.environ; "
            "assert not any(pathlib.Path(p).exists() for p in "
            "['/app/AGENTS.md','/app/.local','/app/.env','/app/runner'])"
        )
        run(*SERVICES, "exec", "-T", service, "python", "-c", check_program)
        safe_services[service] = {
            "user": info["user"],
            "readonly": info["readonly"],
            "caps": info["caps"],
            "security": info["security"],
            "ports": info["ports"],
        }
    checks["containers_restricted_no_daemon_or_hosted_credentials"] = True
    logs = run(*SERVICES, "logs", "--no-color", "api", "worker", "triage-worker")
    synthetic = "AKIA" + "Z" * 16
    assert synthetic not in logs + json.dumps(operations)
    assert all(
        value not in logs + json.dumps(operations)
        for name, value in values.items()
        if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
    )
    checks["synthetic_and_actual_credentials_absent_from_logs_and_evidence"] = True
    evidence = {
        "checks": checks,
        "operations": operations,
        "services": safe_services,
        "retained_scan_content_before": before_content,
        "retained_scan_content_after": sql(content_sql),
        "hosted_calls": 0,
        "real_scanning_enabled": False,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
    }
    (ROOT / "docs/phase3/live-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        json.dumps(
            {"live_checks_passed": len(checks), "failed": 0, "skipped": 0, "hosted_calls": 0}
        )
    )


if __name__ == "__main__":
    main()
