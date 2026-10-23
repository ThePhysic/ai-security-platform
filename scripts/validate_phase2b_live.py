"""Real PostgreSQL/API/worker/host launcher, only inert maintained fixtures."""

import json
import subprocess
import sys
import time
from pathlib import Path
from shutil import copytree
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_security_platform.cli.main import call_api  # noqa: E402
from runner.boundary import DockerBoundary  # noqa: E402
from scripts.validate_local import DEV, inspect_safe, request, run, wait_ready  # noqa: E402


def configure_admission(enabled):
    path = ROOT / ".env"
    lines = [
        line
        for line in path.read_text().splitlines()
        if not line.startswith("ASP_REAL_SCANNING_ENABLED=")
    ]
    lines.append("ASP_REAL_SCANNING_ENABLED=" + ("true" if enabled else "false"))
    path.write_text("\n".join(lines) + "\n")
    run(*DEV, "--profile", "workers", "up", "-d", "--wait", "api", "worker")


def main():
    from dotenv import dotenv_values

    config = dotenv_values(ROOT / ".env")
    token = config["ASP_API_TOKEN"]
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    boundary = DockerBoundary(ROOT / ".local/snapshot-spool")
    wait_ready(base)
    evidence = {"checks": {}, "scans": {}}
    checks = evidence["checks"]
    process = None
    logs = ROOT / ".cache/phase2b-live"
    logs.mkdir(parents=True, exist_ok=True)
    output = (logs / "launcher.log").open("w")
    try:
        configure_admission(True)
        project = call_api(base, "/api/v1/projects", {"name": "Phase 2B inert live validation"})
        # There is no valid launcher heartbeat yet. New real intake must fail closed.
        local = ROOT / ".cache" / ("live-positive-" + uuid4().hex)
        copytree(ROOT / "tests/fixtures/scanners/positive", local)
        secret = "AKIA" + "Z" * 16
        local.joinpath("credentials.txt").write_text("aws_access_key_id = " + secret + "\n")
        local.joinpath(".gitignore").write_text("*\n")
        from ai_security_platform.snapshots.store import SnapshotStore

        snapshot = SnapshotStore(boundary.spool, require_readonly=False).create(
            local, label="live-positive"
        )
        registered = call_api(
            base,
            "/api/v1/source-snapshots",
            {
                "project_id": project["id"],
                "snapshot_key": snapshot.manifest.snapshot_key,
                "manifest_digest": snapshot.manifest_digest,
            },
        )
        body = {
            "project_id": project["id"],
            "snapshot_id": registered["id"],
            "profile_id": "security-v1",
        }
        denied = request(
            base,
            "/api/v1/scan-runs",
            token,
            method="POST",
            json=body,
            headers={"Idempotency-Key": "no-launcher-" + uuid4().hex},
        )
        assert denied.status_code == 503
        checks["real_admission_denied_without_launcher"] = True
        process = subprocess.Popen(
            [sys.executable, "-m", "runner.launcher", "--api", base],
            cwd=ROOT,
            stdout=output,
            stderr=output,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Host launcher exited; inspect ignored safe diagnostic log")
            if "launcher_ready" in (logs / "launcher.log").read_text():
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Launcher readiness deadline exceeded")

        def submit(payload, key):
            response = request(
                base,
                "/api/v1/scan-runs",
                token,
                method="POST",
                json=payload,
                headers={"Idempotency-Key": key},
            )
            assert response.status_code == 202, response.json().get("code")
            return response.json()

        def wait(scan_id):
            deadline = time.monotonic() + 150
            while time.monotonic() < deadline:
                data = call_api(base, "/api/v1/scan-runs/" + scan_id)
                if data["status"] in {"succeeded", "partial", "failed"}:
                    return data
                time.sleep(0.3)
            raise RuntimeError("Controlled scan exceeded its validation deadline")

        key = "real-live-" + uuid4().hex
        accepted = submit(body, key)
        assert submit(body, key)["id"] == accepted["id"]
        result = wait(accepted["id"])
        assert result["status"] == "succeeded", {
            slot["scanner_id"]: (slot["status"], slot["error_code"])
            for slot in result["scanner_runs"]
        }
        url = "/api/v1/scan-runs/" + accepted["id"]
        findings = call_api(base, url + "/findings?limit=100")
        assert findings["items"] and all(not item["synthetic"] for item in findings["items"])
        assert secret not in json.dumps(findings)
        detail = call_api(base, "/api/v1/findings/" + findings["items"][0]["id"])
        assert detail["provenance"]["image_digest"].startswith("sha256:")
        exported = call_api(base, url + "/export?format=json")
        assert secret not in json.dumps(exported) and len(exported["findings"]) == len(
            findings["items"]
        )
        checks["real_pipeline_publishes_sanitized_findings_and_versions"] = True
        checks["real_scan_idempotency_detail_json_export"] = True
        evidence["scans"]["positive"] = {
            "id": accepted["id"],
            "status": result["status"],
            "findings": len(findings["items"]),
            "scanners": [
                {
                    "id": s["scanner_id"],
                    "status": s["status"],
                    "coverage": s["coverage"],
                    "provenance": s["provenance"],
                }
                for s in result["scanner_runs"]
            ],
        }
        # Physical restart persistence keeps actual normalized scanner results.
        run(*DEV, "--profile", "workers", "restart", "worker", "api", "db")
        wait_ready(base)
        assert call_api(base, url + "/findings?limit=100") == findings
        checks["real_results_survive_api_worker_database_restarts"] = True
        # Same running launcher and worker recover when the API/DB return.
        fresh = submit(body, "after-restart-" + uuid4().hex)
        assert wait(fresh["id"])["status"] == "succeeded"
        checks["same_launcher_worker_recover_after_database_restart"] = True
        # Kill the host while a real execution is running; restart must remove
        # only labelled orphans, stage retryable handoff failure and recover.
        crashed = submit(body, "launcher-crash-" + uuid4().hex)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            containers = boundary.command(
                "ps", "-q", "--filter", "label=ai-security-platform.phase2b=scanner"
            )
            if containers:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("No real scanner started for launcher crash proof")
        process.terminate()
        process.wait(timeout=5)
        process = subprocess.Popen(
            [sys.executable, "-m", "runner.launcher", "--api", base],
            cwd=ROOT,
            stdout=output,
            stderr=output,
        )
        recovered = wait(crashed["id"])
        assert recovered["status"] == "succeeded"
        checks["actual_launcher_kill_orphan_reconcile_and_worker_retry"] = True
        # Expire precisely this newly created validation scan's current lease.
        expired = submit(body, "real-expiration-" + uuid4().hex)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            active = boundary.command(
                "ps",
                "-q",
                "--no-trunc",
                "--filter",
                "label=ai-security-platform.phase2b=scanner",
            ).splitlines()
            if active:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("No real scanner started for expiry proof")
        # Safe IDs originate in the validated API response, never arbitrary SQL input.
        from uuid import UUID

        scan_id = str(UUID(expired["id"]))
        identity_text = run(
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
            "SELECT json_build_object('launcher_id',i.launcher_id,'generation',i.generation,"
            "'lease_token',i.lease_token,'invocation_id',i.id,'job_id',j.id) "
            "FROM scanner_invocations i JOIN jobs j ON j.id=i.job_id "
            "JOIN scanner_runs r ON r.id=j.scanner_run_id WHERE r.scan_run_id='"
            + scan_id
            + "' AND j.state='running' AND i.generation=j.generation",
        )
        old_identity = json.loads(identity_text)  # secret lease stays in memory only
        old_job = str(UUID(old_identity.pop("job_id")))
        old_invocation = str(UUID(old_identity.pop("invocation_id")))
        run(
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
            "UPDATE jobs SET lease_expires_at=clock_timestamp()-interval '1 second' "
            "WHERE id='" + old_job + "' AND state='running'",
        )
        assert wait(expired["id"])["status"] == "succeeded"
        from urllib.error import HTTPError

        from runner.launcher import LauncherClient

        capability = LauncherClient(base, config["ASP_LAUNCHER_TOKEN"])
        try:
            capability.call(
                "/" + old_invocation + "/result",
                old_identity | {"result": {"error_code": "execution_failed"}},
            )
        except HTTPError as error:
            assert error.code == 409
        else:
            raise AssertionError("Expired real attempt staged a result")
        counts = run(
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
            "SELECT generation,(SELECT count(*) FROM audit_events WHERE object_id=jobs.id "
            "AND event_type='job.succeeded') FROM jobs WHERE id='" + old_job + "'",
        )
        assert counts == "2|1"
        checks["real_lease_expiry_cancels_retries_and_rejects_stale_staging"] = True
        evidence["real_expiry"] = {
            "winning_generation": 2,
            "completion_events": 1,
            "stale_result_status": 409,
        }
        # Invalid source syntax is data: keep valid findings and expose incomplete
        # Semgrep coverage independently of the successful Trivy slot.
        # Include a rule prefilter token: Semgrep intentionally need not parse
        # files with no relevant tokens, even if their syntax is malformed.
        local.joinpath("broken.py").write_bytes(b'eval(user)\ndef f():\n    return "\n')
        partial_snapshot = SnapshotStore(boundary.spool, require_readonly=False).create(
            local, label="live-parser-incomplete"
        )
        partial_registered = call_api(
            base,
            "/api/v1/source-snapshots",
            {
                "project_id": project["id"],
                "snapshot_key": partial_snapshot.manifest.snapshot_key,
                "manifest_digest": partial_snapshot.manifest_digest,
            },
        )
        partial = submit(
            body | {"snapshot_id": partial_registered["id"]}, "parser-incomplete-" + uuid4().hex
        )
        partial_result = wait(partial["id"])
        assert partial_result["status"] == "partial"
        slots = {row["scanner_id"]: row for row in partial_result["scanner_runs"]}
        assert slots["semgrep"]["status"] == "failed"
        assert slots["semgrep"]["error_code"] == "incomplete_coverage"
        assert "scanner_errors" in slots["semgrep"]["coverage"]["warnings"]
        assert slots["trivy"]["status"] == "succeeded"
        preserved = call_api(base, "/api/v1/scan-runs/" + partial["id"] + "/findings?limit=100")
        assert any(item["category"] == "sast" for item in preserved["items"])
        assert any(item["category"] == "vulnerability" for item in preserved["items"])
        checks["genuine_parser_failure_preserves_partial_findings"] = True
        evidence["scans"]["partial"] = {
            "id": partial["id"],
            "status": partial_result["status"],
            "findings": len(preserved["items"]),
            "scanners": [
                {
                    "id": row["scanner_id"],
                    "status": row["status"],
                    "error_code": row["error_code"],
                    "coverage": row["coverage"],
                }
                for row in partial_result["scanner_runs"]
            ],
        }
        api = inspect_safe(run(*DEV, "ps", "-q", "api"))
        worker = inspect_safe(run(*DEV, "--profile", "workers", "ps", "-q", "worker"))
        for info in (api, worker):
            assert info["user"] == "10001:10001" and info["readonly"]
            assert all(m["Destination"] in {"/spool", "/tmp"} for m in info["mounts"])
        checks["ordinary_api_worker_have_no_daemon_mount"] = True
        all_logs = run(*DEV, "--profile", "workers", "logs", "--no-color", "api", "worker")
        all_logs += (logs / "launcher.log").read_text()
        assert secret not in all_logs
        assert all(
            value not in all_logs
            for name, value in config.items()
            if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
        )
        checks["synthetic_and_actual_credentials_absent_from_all_logs"] = True
        evidence.update({"passed": len(checks), "failed": 0, "skipped": 0})
        (ROOT / "docs/phase2b/live-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({"live_checks_passed": len(checks), "failed": 0, "skipped": 0}))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        output.close()
        boundary.cleanup_orphans()
        configure_admission(False)


if __name__ == "__main__":
    main()
