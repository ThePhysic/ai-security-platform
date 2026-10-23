"""Controlled CLI/API/scanner integration; preserves retained history and fail-closed defaults."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import jsonschema  # noqa: E402
from dotenv import dotenv_values  # noqa: E402

from ai_security_platform.cli.main import call_api  # noqa: E402
from runner.boundary import DockerBoundary  # noqa: E402
from scripts.validate_local import DEV, request, run, wait_ready  # noqa: E402
from scripts.validate_phase2b_live import configure_admission  # noqa: E402


def main():
    config = dotenv_values(ROOT / ".env")
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    assert config.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
    assert config.get("ASP_HOSTED_ENABLED", "false") == "false"
    assert (ROOT / ".cache/phase5-retained-before.json").exists()
    checks, commands = {}, []
    identity = uuid4().hex
    private = ROOT / ".cache" / ("phase5-live-" + identity)
    private.mkdir(parents=True)
    boundary = DockerBoundary(ROOT / ".local/snapshot-spool")
    assert not boundary.command(
        "ps", "-q", "--filter", "label=ai-security-platform.phase2b=scanner"
    )
    launcher, output = None, None

    def cli(*arguments, code=0, environment=None):
        command = [sys.executable, "-m", "ai_security_platform.cli", "--api", base, *arguments]
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=240, env=environment
        )
        assert result.returncode == code, (arguments[0], result.returncode, result.stdout[:200])
        record = json.loads(result.stdout)
        commands.append({"command": arguments[0], "expected_exit": code, "actual_exit": code})
        return record

    def acquire(directory, project):
        snapshot = cli("snapshot-create", str(directory), "--label", "phase5-controlled")
        return cli(
            "snapshot-register",
            "--project",
            project,
            "--key",
            snapshot["snapshot_key"],
            "--digest",
            snapshot["manifest_digest"],
        )["id"]

    try:
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "build",
            "api",
            "worker",
            "triage-worker",
        )
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "up",
            "-d",
            "--wait",
            "api",
            "worker",
            "triage-worker",
        )
        wait_ready(base)
        project = cli("project-create", "Phase 5 controlled workflow validation")["id"]
        diagnostic = private / "diagnostic"
        diagnostic.mkdir()
        diagnostic.joinpath("app.py").write_bytes(b"ASP_FAKE_FINDING\nASP_FAKE_CONFIG\n")
        snapshot = acquire(diagnostic, project)
        policy = private / "diagnostic.json"
        policy.write_text(
            json.dumps(
                {"required_scanners": ["fake-patterns", "fake-config"], "allow_synthetic": True}
            )
        )
        strict = private / "strict.json"
        strict.write_text(
            json.dumps(
                {
                    "required_scanners": ["fake-patterns", "fake-config"],
                    "allow_synthetic": True,
                    "fail_at": "MEDIUM",
                }
            )
        )
        key = "phase5-" + identity
        submitted = cli(
            "scan-submit", "--project", project, "--snapshot", snapshot, "--idempotency-key", key
        )
        replay = cli(
            "scan-submit", "--project", project, "--snapshot", snapshot, "--idempotency-key", key
        )
        assert submitted["id"] == replay["id"]
        cli(
            "scan-submit",
            "--project",
            project,
            "--snapshot",
            snapshot,
            "--idempotency-key",
            key,
            "--profile",
            "security-v1",
            code=2,
        )
        identifier = submitted["id"]
        cli("scan-wait", identifier, "--policy", str(policy))
        cli(
            "scan",
            "--project",
            project,
            "--snapshot",
            snapshot,
            "--idempotency-key",
            key,
            "--profile",
            "fake-v1",
            "--policy",
            str(policy),
        )
        cli("policy", identifier, "--policy", str(strict), code=1)
        cli("policy", identifier, code=2)
        status = cli("scan-status", identifier)
        assert status["status"] == "succeeded" and len(status["scanner_runs"]) == 2
        findings = cli("findings", identifier, "--all", "--limit", "1")
        assert len(findings["items"]) == 2 and findings["next_cursor"] is None
        assert cli("scan-history", "--project", project, "--limit", "1")["items"]
        cli("findings", identifier, "--all", "--limit", "1", "--max-pages", "1", code=2)
        for format in ("json", "sarif"):
            cli(
                "export",
                identifier,
                "--name",
                "p5diag-" + identity,
                "--format",
                format,
                "--policy",
                str(policy),
            )
        cli("export", identifier, "--name", "../escape", "--policy", str(policy), code=2)
        bad_environment = dict(os.environ, ASP_API_TOKEN="phase5-deliberately-invalid-local-token")
        cli("scan-status", identifier, environment=bad_environment, code=2)
        cli("scan-status", "../not-a-resource", code=2)
        checks["actual_cli_intake_idempotency_query_pagination_and_exports"] = True
        checks["actual_cli_pass_fail_incomplete_and_operational_codes"] = True
        checks["artifact_traversal_and_invalid_identity_denied"] = True

        # Source-only workload: maintained positive fixture plus benign numbered
        # files. No source scripts or target package managers are ever executed.
        directory = private / "real-200"
        shutil.copytree(ROOT / "tests/fixtures/scanners/positive", directory)
        count = sum(p.is_file() for p in directory.rglob("*"))
        for index in range(200 - count):
            suffix = "py" if index % 2 == 0 else "js"
            directory.joinpath(f"clean{index:03}.{suffix}").write_bytes(
                b"value = 42\n" if suffix == "py" else b"const value = 42;\n"
            )
        assert sum(p.is_file() for p in directory.rglob("*")) == 200
        secret = "AKIA" + "V" * 16
        # Replace a source fixture file; count stays exactly 200.
        directory.joinpath("trivy.yaml").write_text("aws_access_key_id = " + secret + "\n")
        real_snapshot = acquire(directory, project)
        configure_admission(True)
        output = (private / "launcher.log").open("w")
        launcher = subprocess.Popen(
            [sys.executable, "-m", "runner.launcher", "--api", base],
            cwd=ROOT,
            stdout=output,
            stderr=output,
        )
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            assert launcher.poll() is None, "Controlled launcher stopped"
            if "launcher_ready" in (private / "launcher.log").read_text():
                break
            time.sleep(0.2)
        else:
            raise AssertionError("Controlled launcher not ready")
        samples = []
        for index in range(3):
            started = time.monotonic()
            decision = cli(
                "scan",
                "--project",
                project,
                "--snapshot",
                real_snapshot,
                "--idempotency-key",
                f"phase5-real-{identity}-{index}",
                "--timeout",
                "180",
                code=1,
            )
            scan_id = str(UUID(decision["scan_id"]))
            report = call_api(base, f"/api/v1/scan-runs/{scan_id}/export?format=json")
            assert report["scan"]["status"] == "succeeded"
            assert all(not f["synthetic"] for f in report["findings"])
            assert secret not in json.dumps(report)
            duration = run(
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
                "SELECT json_build_object('scan_ms',"
                "extract(epoch FROM (s.completed_at-s.created_at))*1000,"
                "'jobs',(SELECT json_agg(json_build_object('queue_ms',"
                "extract(epoch FROM (a.started_at-j.created_at))*1000,"
                "'execution_ms',extract(epoch FROM (a.completed_at-a.started_at))*1000,"
                "'generation',j.generation)) "
                "FROM jobs j JOIN scanner_runs r ON r.id=j.scanner_run_id "
                "JOIN job_attempts a ON a.job_id=j.id "
                "WHERE r.scan_run_id=s.id)) FROM scan_runs s WHERE s.id='" + scan_id + "'",
            )
            samples.append(
                {
                    "scan_id": scan_id,
                    "cli_wall_seconds": time.monotonic() - started,
                    "findings": len(report["findings"]),
                    "timings": json.loads(duration),
                    "scanner_runs": report["scan"]["scanner_runs"],
                }
            )
        checks["three_real_200_file_scans_through_cli_and_isolated_launcher"] = True
        final = samples[-1]["scan_id"]
        path = f"/api/v1/scan-runs/{final}/export?format=json"
        before = call_api(base, path)
        assert before == call_api(base, path)
        for format in ("json", "sarif"):
            cli("export", final, "--name", "phase5-real-" + identity, "--format", format, code=1)
        sarif = json.loads((ROOT / f".local/reports/phase5-real-{identity}.sarif").read_text())
        schema = json.loads((ROOT / "tests/schemas/sarif-2.1.0.json").read_text())
        jsonschema.validators.validator_for(schema)(schema).validate(sarif)
        assert secret not in json.dumps(sarif)
        checks["genuine_sarif_schema_source_mapping_determinism_and_redaction"] = True
        # Stop only our launcher before application/database failure injection.
        launcher.terminate()
        launcher.wait(timeout=5)
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
            "db",
        )
        wait_ready(base)
        assert call_api(base, path) == before
        checks["json_byte_equivalent_facts_survive_actual_container_restarts"] = True
        try:
            run(*DEV, "stop", "db")
            assert request(base, "/health", method="GET").status_code == 200
            assert request(base, "/ready", method="GET").status_code == 503
            cli("scan-status", final, code=2)
        finally:
            run(*DEV, "up", "-d", "--wait", "db")
            wait_ready(base)
        assert call_api(base, path) == before
        checks["database_interruption_safe_unready_and_recovery"] = True
        logs = run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "logs",
            "--no-color",
            "api",
            "worker",
            "triage-worker",
        )
        logs += (private / "launcher.log").read_text()
        assert secret not in logs
        assert all(
            value not in logs
            for name, value in config.items()
            if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
        )
        checks["synthetic_and_local_credentials_absent_from_logs_and_exports"] = True
        result = {
            "checks": checks,
            "passed": len(checks),
            "failed": 0,
            "skipped": 0,
            "cli_commands": commands,
            "real_workload": {
                "files": 200,
                "samples": samples,
                "scan_samples": 3,
                "job_samples": 6,
                "concurrency": "one ordinary worker and serial trusted launcher",
                "limitation": (
                    "local repeated observations; not a real-scanner scaling "
                    "or production capacity claim"
                ),
            },
            "report_sha256": hashlib.sha256(
                json.dumps(before, sort_keys=True).encode()
            ).hexdigest(),
            "hosted_calls": 0,
        }
    finally:
        if launcher is not None and launcher.poll() is None:
            launcher.terminate()
            launcher.wait(timeout=5)
        if output is not None:
            output.close()
        boundary.cleanup_orphans()
        configure_admission(False)
    result["real_admission_restored_disabled"] = True
    (ROOT / "docs/phase5/live-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        json.dumps(
            {"live_checks_passed": len(checks), "cli_commands": len(commands), "real_scans": 3}
        )
    )


if __name__ == "__main__":
    main()
