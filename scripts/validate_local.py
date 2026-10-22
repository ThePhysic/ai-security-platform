"""Phase 1 live checks. Only fixed, dedicated project resources are mutated."""

import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEV = ["docker", "compose", "-p", "asp-phase1-dev"]
TEST = ["docker", "compose", "-p", "asp-phase1-test", "--profile", "test"]
PROBE = "asp-phase1-test-probe-api"


def run(*args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        # Captured output may contain runtime configuration; never echo it.
        raise RuntimeError("Project validation command failed; inspect with sanitized diagnostics")
    return result.stdout.strip()


def request(base, path, token=None, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if token:
        headers["Authorization"] = "Bearer " + token
    return httpx.request(url=base + path, headers=headers, timeout=5, **kwargs)


def wait_ready(base):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            if request(base, "/ready", method="GET").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise RuntimeError("Project API readiness deadline exceeded")


def inspect_safe(container):
    template = (
        '{"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},'
        '"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
        '"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},'
        '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
        '"started":{{json .State.StartedAt}}}'
    )
    return json.loads(run("docker", "inspect", "--format", template, container))


def main():
    config = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            config[key] = value
    token = config["ASP_API_TOKEN"]
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    evidence = {"phase": 1, "migration": "0001_foundation", "checks": {}}
    checks = evidence["checks"]
    api_id = run(*DEV, "ps", "-q", "api")
    db_id = run(*DEV, "ps", "-q", "db")
    api_info = inspect_safe(api_id)
    db_info = inspect_safe(db_id)
    assert api_info["project"] == db_info["project"] == "asp-phase1-dev"
    assert api_info["user"] == "10001:10001" and api_info["readonly"]
    assert "ALL" in api_info["caps"]
    assert "no-new-privileges:true" in api_info["security"]
    assert all(
        p["HostIp"] == "127.0.0.1" for bindings in api_info["ports"].values() for p in bindings
    )
    assert not db_info["ports"]
    assert all(m["Destination"] == "/tmp" for m in api_info["mounts"])
    run(
        *DEV,
        "exec",
        "-T",
        "api",
        "python",
        "-c",
        "import os,pathlib; assert os.geteuid()==10001; "
        "assert not pathlib.Path('/app/AGENTS.md').exists(); "
        "assert not pathlib.Path('/app/.env').exists(); "
        "assert not pathlib.Path('/var/run/docker.sock').exists()",
    )
    checks["container_restrictions"] = True
    wait_ready(base)
    assert request(base, "/health", method="GET").status_code == 200
    assert (
        request(
            base, "/api/v1/projects/00000000-0000-0000-0000-000000000000", method="GET"
        ).status_code
        == 401
    )
    assert request(base, "/health", method="GET", headers={"Origin": "null"}).status_code == 403
    assert (
        request(base, "/health", method="GET", headers={"Host": "attacker.invalid"}).status_code
        == 400
    )
    assert request(base, "/api/v1/scan-runs", token, method="POST", json={}).status_code == 404
    checks["live_access_and_phase_boundary"] = True
    response = request(
        base,
        "/api/v1/projects",
        token,
        method="POST",
        json={"name": "Phase 1 physical restart verification"},
    )
    assert response.status_code == 201
    project_id = response.json()["id"]

    def persisted():
        result = request(base, "/api/v1/projects/" + project_id, token, method="GET")
        assert result.status_code == 200 and result.json()["id"] == project_id

    print("Checking actual development API/container restart persistence.", flush=True)
    run(*DEV, "restart", "api")
    wait_ready(base)
    persisted()
    assert inspect_safe(api_id)["started"] != api_info["started"]
    checks["project_after_api_restart"] = True
    run(*DEV, "restart", "db")
    wait_ready(base)
    persisted()
    assert inspect_safe(db_id)["started"] != db_info["started"]
    checks["project_after_database_restart"] = True

    print("Checking liveness/readiness during project database outage.", flush=True)
    run(*DEV, "stop", "db")
    try:
        assert request(base, "/health", method="GET").status_code == 200
        assert request(base, "/ready", method="GET").status_code == 503
        checks["live_database_outage"] = True
    finally:
        run(*DEV, "start", "db")
        wait_ready(base)
    persisted()

    synthetic = "synthetic-runtime-disclosure-check-" + "x" * 48
    response = request(
        base,
        "/api/v1/projects",
        token,
        method="POST",
        json={"name": "invalid", synthetic: synthetic},
        headers={"X-Request-ID": "unsafe-" + synthetic},
    )
    assert response.status_code == 422 and synthetic not in response.text
    output = run(*DEV, "logs", "--no-color", "api")
    assert synthetic not in output
    assert all(
        value not in output
        for key, value in config.items()
        if key.endswith("PASSWORD") or key.endswith("TOKEN")
    )
    checks["live_log_and_error_disclosure"] = True

    print("Checking test-only scan metadata across actual API/database restarts.", flush=True)
    fixture_output = run(
        *TEST,
        "run",
        "--rm",
        "--no-deps",
        "tests",
        "uv",
        "run",
        "--no-sync",
        "python",
        "-m",
        "tests.restart_fixture",
    )
    scan_id = json.loads(fixture_output)["scan_id"]
    existing = run("docker", "ps", "-a", "--filter", "name=^/" + PROBE + "$", "-q")
    if existing:
        raise RuntimeError("Probe name already exists; refusing to replace it")
    probe_created = False
    try:
        run(
            *TEST,
            "run",
            "-d",
            "--no-deps",
            "--name",
            PROBE,
            "--publish",
            "127.0.0.1:18082:8000",
            "tests",
            "uv",
            "run",
            "--no-sync",
            "python",
            "-m",
            "tests.probe_server",
        )
        probe_created = True
        assert inspect_safe(PROBE)["project"] == "asp-phase1-test"
        probe_base = "http://127.0.0.1:18082"
        wait_ready(probe_base)
        from tests.conftest import TOKEN as TEST_TOKEN

        def scan_persisted():
            result = request(probe_base, "/api/v1/scan-runs/" + scan_id, TEST_TOKEN, method="GET")
            assert result.status_code == 200 and result.json()["status"] == "queued"

        scan_persisted()
        run("docker", "restart", PROBE)
        wait_ready(probe_base)
        scan_persisted()
        checks["test_scan_after_api_restart"] = True
        test_db_id = run(*TEST, "ps", "-q", "test-db")
        assert inspect_safe(test_db_id)["project"] == "asp-phase1-test"
        run(*TEST, "restart", "test-db")
        wait_ready(probe_base)
        scan_persisted()
        checks["test_scan_after_database_restart"] = True
    finally:
        if probe_created:
            assert inspect_safe(PROBE)["project"] == "asp-phase1-test"
            run("docker", "stop", PROBE)
            run("docker", "rm", PROBE)
    target = ROOT / "docs" / "phase1" / "validation-evidence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + "\n")
    print("All live Phase 1 checks passed; sanitized evidence written.", flush=True)


if __name__ == "__main__":
    main()
