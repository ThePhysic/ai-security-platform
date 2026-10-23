"""Native CLI -> private NTFS spool -> read-only Linux API/worker proof.

Only fixed project-owned services are restarted/stopped. No volume removal,
unrelated resources, target execution or source bytes in evidence.
"""

import json
import os
import sys
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_local import DEV, inspect_safe, request, run, wait_ready  # noqa: E402


def main():
    from dotenv import dotenv_values

    config = dotenv_values(ROOT / ".env")
    token = config["ASP_API_TOKEN"]
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    assert token
    worker = [*DEV, "--profile", "workers"]
    run(*worker, "stop", "worker")
    wait_ready(base)
    evidence = {"phase": "2A", "checks": {}}
    checks = evidence["checks"]
    fixture = ROOT / ".cache" / ("live-source-" + uuid4().hex)
    fixture.mkdir(parents=True)
    synthetic = "synthetic-secret-no-disclosure-" + uuid4().hex
    fixture.joinpath("example.py").write_bytes(
        ("ASP_FAKE_FINDING\nASP_FAKE_CONFIG\n" + synthetic + "\n").encode()
    )
    fixture.joinpath(".env").write_text(synthetic)
    executable = ROOT / ".venv" / ("Scripts/asp.exe" if os.name == "nt" else "bin/asp")

    def cli(*arguments):
        return json.loads(run(str(executable), "--api", base, *arguments))

    project = cli("project-create", "Phase 2A controlled restart fixture")
    snapshot = cli("snapshot-create", str(fixture), "--label", "controlled-fixture")
    registered = cli(
        "snapshot-register",
        "--project",
        project["id"],
        "--key",
        snapshot["snapshot_key"],
        "--digest",
        snapshot["manifest_digest"],
    )
    assert registered["file_count"] == 1
    checks["native_cli_spool_to_container_registration"] = True
    key = "live-" + uuid4().hex
    submitted = cli(
        "scan-submit",
        "--project",
        project["id"],
        "--snapshot",
        registered["id"],
        "--idempotency-key",
        key,
    )
    assert submitted["status"] == "queued"
    assert (
        cli(
            "scan-submit",
            "--project",
            project["id"],
            "--snapshot",
            registered["id"],
            "--idempotency-key",
            key,
        )["id"]
        == submitted["id"]
    )
    checks["durable_acceptance_before_worker_start"] = True
    path = "/api/v1/scan-runs/" + submitted["id"]
    api_id = run(*DEV, "ps", "-q", "api")
    db_id = run(*DEV, "ps", "-q", "db")
    before_api = inspect_safe(api_id)["started"]
    before_db = inspect_safe(db_id)["started"]
    run(*DEV, "restart", "api", "db")
    wait_ready(base)
    assert request(base, path, token, method="GET").json()["status"] == "queued"
    assert inspect_safe(api_id)["started"] != before_api
    assert inspect_safe(db_id)["started"] != before_db
    checks["queued_work_survives_actual_api_database_restarts"] = True
    run(*worker, "up", "-d", "worker")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status = cli("scan-status", submitted["id"])
        if status["status"] in {"succeeded", "partial", "failed"}:
            break
        time.sleep(0.2)
    assert status["status"] == "succeeded", "Controlled fake execution did not succeed"
    assert len(status["scanner_runs"]) == 2
    assert all(stage["coverage"]["synthetic"] for stage in status["scanner_runs"])
    found = cli("findings", submitted["id"])
    assert len(found["items"]) == 2 and all(item["synthetic"] for item in found["items"])
    assert synthetic not in json.dumps(found)
    checks["separate_worker_two_synthetic_scanners"] = True
    saved = found
    run(*worker, "restart", "worker", "api", "db")
    wait_ready(base)
    assert cli("scan-status", submitted["id"])["status"] == "succeeded"
    assert cli("findings", submitted["id"]) == saved
    checks["findings_outcomes_survive_actual_container_restarts"] = True
    for service in ("api", "worker"):
        identifier = run(*worker, "ps", "-q", service)
        info = inspect_safe(identifier)
        assert info["project"] == "asp-phase1-dev"
        assert info["user"] == "10001:10001" and info["readonly"]
        assert "ALL" in info["caps"] and "no-new-privileges:true" in info["security"]
        bounds = json.loads(
            run(
                "docker",
                "inspect",
                "--format",
                '{"memory":{{json .HostConfig.Memory}},"cpus":{{json .HostConfig.NanoCpus}},'
                '"pids":{{json .HostConfig.PidsLimit}},'
                '"privileged":{{json .HostConfig.Privileged}}}',
                identifier,
            )
        )
        assert bounds == {"memory": 268435456, "cpus": 1000000000, "pids": 64, "privileged": False}
        mount = [m for m in info["mounts"] if m["Destination"] == "/spool"]
        assert len(mount) == 1 and not mount[0]["RW"]
        assert all(m["Destination"] in {"/spool", "/tmp"} for m in info["mounts"])
        if service == "worker":
            assert not info["ports"]
        run(
            *worker,
            "exec",
            "-T",
            service,
            "python",
            "-c",
            "import os,pathlib; p=pathlib.Path('/spool'); "
            "assert os.geteuid()==10001; assert os.statvfs(p).f_flag & os.ST_RDONLY; "
            "assert not pathlib.Path('/var/run/docker.sock').exists(); "
            "assert not pathlib.Path('/app/AGENTS.md').exists(); "
            "assert not pathlib.Path('/app/.env').exists()",
        )
        # An actual write syscall must be rejected, independent of mount metadata.
        run(
            *worker,
            "exec",
            "-T",
            service,
            "python",
            "-c",
            "import errno,pathlib\n"
            "try:\n pathlib.Path('/spool/denied-probe').write_bytes(b'probe')\n"
            "except OSError as e:\n assert e.errno in (errno.EROFS,errno.EACCES)\n"
            "else:\n raise RuntimeError('Unexpected writable spool')\n",
        )
    assert not inspect_safe(db_id)["ports"]
    checks["readonly_spool_real_write_denial_nonroot_no_docker_daemon"] = True
    run(*DEV, "stop", "db")
    try:
        assert request(base, "/health", method="GET").status_code == 200
        assert request(base, "/ready", method="GET").status_code == 503
        assert request(base, path, token, method="GET").status_code == 503
    finally:
        run(*DEV, "start", "db")
        wait_ready(base)
    # Keep the same worker process alive across the actual database outage.
    followup = cli(
        "scan-submit",
        "--project",
        project["id"],
        "--snapshot",
        registered["id"],
        "--idempotency-key",
        "recovered-" + uuid4().hex,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if cli("scan-status", followup["id"])["status"] == "succeeded":
            break
        time.sleep(0.2)
    else:
        raise AssertionError("Worker failed to recover after actual database interruption")
    checks["same_worker_recovers_after_actual_database_outage"] = True
    assert request(base, path, method="GET").status_code == 401
    assert (
        request(base, "/health", headers={"Host": "attacker.invalid"}, method="GET").status_code
        == 400
    )
    assert request(base, "/health", headers={"Origin": "null"}, method="GET").status_code == 403
    output = run(*worker, "logs", "--no-color", "api", "worker")
    assert synthetic not in output and token not in output
    assert all(
        value not in output for key, value in config.items() if value and key.endswith("PASSWORD")
    )
    checks["live_auth_host_origin_and_synthetic_secret_checks"] = True
    evidence["scan_id"] = submitted["id"]
    evidence["snapshot_key"] = snapshot["snapshot_key"]
    evidence["passed"] = len(checks)
    evidence["failed"] = 0
    evidence["skipped"] = 0
    target = ROOT / "docs" / "phase2a" / "live-evidence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"phase2a_live_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
