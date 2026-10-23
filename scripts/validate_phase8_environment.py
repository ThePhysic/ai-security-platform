"""Isolated real API/worker/CLI demo; no retained AppSec database or spool writes."""

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import httpx
from dotenv import dotenv_values

from scripts.lifecycle import private_directory

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".local/phase8-demo"
PREFIX = [
    "docker",
    "--context",
    "desktop-linux",
    "compose",
    "--env-file",
    str(PRIVATE / "environment.env"),
    "-f",
    "compose.phase8-demo.yaml",
    "-p",
    "asp-phase8-demo",
]


def run(args, environment=None):
    result = subprocess.run(
        args,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if result.returncode:
        # Keep all build and database diagnostics private; never print env/connection details.
        (ROOT / ".cache/phase8-environment-failure.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        raise RuntimeError("phase8_environment_command_failed")
    return result.stdout


def prepare():
    private_directory(PRIVATE)
    path = PRIVATE / "environment.env"
    if not path.exists():
        with path.open("x", encoding="utf-8") as stream:
            stream.write("ASP_SOC_DB_PASSWORD=" + secrets.token_urlsafe(48) + "\n")
            stream.write("ASP_SOC_API_TOKEN=" + secrets.token_urlsafe(48) + "\n")
            stream.write("ASP_SOC_ENABLED=true\n")
    return dotenv_values(path)


def main():
    config = prepare()
    token = config["ASP_SOC_API_TOKEN"]
    checks, commands = {}, []

    def compose(*args, enabled=True):
        environment = os.environ | {"ASP_SOC_ENABLED": str(enabled).lower()}
        commands.append(
            "docker compose [private env] -f compose.phase8-demo.yaml "
            "-p asp-phase8-demo " + " ".join(args)
        )
        return run([*PREFIX, *args], environment)

    compose("config", "--quiet")
    compose("build", "api")
    compose("up", "-d", "--wait", "db")
    compose(
        "run", "--rm", "--no-deps", "api", "uv", "run", "--no-sync", "alembic", "upgrade", "head"
    )
    compose(
        "run",
        "--rm",
        "--no-deps",
        "api",
        "uv",
        "run",
        "--no-sync",
        "alembic",
        "-c",
        "src/ai_security_platform/soc/alembic.ini",
        "upgrade",
        "head",
    )
    compose("up", "-d", "--wait", "--no-build", "api", "soc-worker")
    base = "http://127.0.0.1:18089"
    auth = {"Authorization": "Bearer " + token}
    environment = os.environ | {"ASP_API_TOKEN": token}
    scenarios = []
    for name in ["auth-burst", "session-grant", "clean", "incomplete"]:
        dataset = uuid5(NAMESPACE_URL, "asp-phase8-demo-v1:" + name)
        arguments = [
            sys.executable,
            "-m",
            "ai_security_platform.soc.cli",
            "--api",
            base,
            "demo",
            name,
            "--dataset",
            str(dataset),
            "--key",
            "demo-v1",
        ]
        result = json.loads(run(arguments, environment))
        replay = json.loads(run(arguments, environment))
        assert result == replay
        with httpx.Client(base_url=base, headers=auth, trust_env=False, timeout=10) as client:
            rows = client.get(f"/api/v1/soc/datasets/{dataset}/investigations").json()["items"]
            expected = 0 if name == "clean" else 1
            assert len(rows) == expected
            if expected:
                assert rows[0]["evidence_state"] == (
                    "incomplete" if name == "incomplete" else "matched"
                )
            scenarios.append(
                {
                    "scenario": name,
                    "run_id": result["run"]["id"],
                    "status": result["run"]["status"],
                    "investigations": len(rows),
                    "evidence_state": rows[0]["evidence_state"] if rows else None,
                    "idempotent_cli_replay": True,
                }
            )
            if name == "auth-burst":
                identifier = rows[0]["id"]
                if rows[0]["revision"] == 0:
                    body = {
                        "expected_revision": 0,
                        "disposition": "investigate",
                        "note": "Synthetic sequence warrants analyst verification.",
                        "feedback": "useful",
                    }
                    assert (
                        client.post(
                            f"/api/v1/soc/investigations/{identifier}/review", json=body
                        ).status_code
                        == 200
                    )
                assert (
                    client.post(
                        f"/api/v1/soc/investigations/{identifier}/review",
                        json={"expected_revision": 0, "disposition": "confirmed"},
                    ).status_code
                    == 409
                )
                history = client.get(
                    f"/api/v1/soc/investigations/{identifier}/review-history"
                ).json()
                assert len(history["items"]) == 1
    checks["real_cli_api_worker_scenarios_and_replay"] = len(scenarios) == 4
    checks["analyst_history_and_stale_conflict"] = True

    def state():
        return compose(
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "asp_soc_demo",
            "-d",
            "asp_phase8_demo",
            "-At",
            "-c",
            "SELECT (SELECT count(*) FROM soc.security_events),"
            "(SELECT count(*) FROM soc.correlation_runs),"
            "(SELECT count(*) FROM soc.investigations),"
            "(SELECT count(*) FROM soc.analyst_feedback)",
        )

    before = state()
    compose("restart", "db", "api", "soc-worker")
    for _ in range(40):
        try:
            if httpx.get(base + "/ready", trust_env=False, timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    checks["actual_container_restart_persistence"] = state() == before
    with httpx.Client(base_url=base, headers=auth, trust_env=False, timeout=10) as client:
        checks["unauthenticated_denied"] = (
            httpx.get(base + "/api/v1/soc/rules", trust_env=False).status_code == 401
        )
        checks["origin_denied"] = (
            client.get(
                "/api/v1/soc/rules", headers={"Origin": "http://untrusted.invalid"}
            ).status_code
            == 403
        )
        for item in scenarios:
            assert client.get("/api/v1/soc/runs/" + item["run_id"]).json()["status"] == "succeeded"

    restrictions = {}
    for service in ["api", "soc-worker", "db"]:
        identifier = compose("ps", "-q", service).strip()
        data = json.loads(run(["docker", "inspect", identifier]))[0]
        assert data["Config"]["Labels"]["com.docker.compose.project"] == "asp-phase8-demo"
        env = dict(value.split("=", 1) for value in data["Config"]["Env"] if "=" in value)
        mounts = [
            {"destination": mount["Destination"], "writable": mount["RW"]}
            for mount in data["Mounts"]
        ]
        if service != "db":
            assert data["Config"]["User"] == "10001:10001"
            assert data["HostConfig"]["ReadonlyRootfs"]
            assert "ALL" in data["HostConfig"]["CapDrop"]
            assert "no-new-privileges:true" in data["HostConfig"]["SecurityOpt"]
            assert all(mount["destination"] == "/tmp" for mount in mounts)
            assert not any(
                name in env
                for name in [
                    "ASP_LAUNCHER_TOKEN",
                    "OPENAI_API_KEY",
                    "DOCKER_HOST",
                    "DOCKER_TLS_VERIFY",
                ]
            )
        restrictions[service] = {
            "user": data["Config"].get("User"),
            "mounts": mounts,
            "ports": data["HostConfig"].get("PortBindings"),
            "read_only": data["HostConfig"]["ReadonlyRootfs"],
        }
    checks["container_privilege_and_capability_separation"] = True
    compose("stop", "soc-worker")
    compose("up", "-d", "--wait", "--no-build", "api", enabled=False)
    with httpx.Client(base_url=base, headers=auth, trust_env=False) as client:
        checks["disabled_routes_absent"] = client.get("/api/v1/soc/rules").status_code == 404
        checks["disabled_flagship_ready"] = client.get("/ready").status_code == 200
    checks["disable_preserves_soc_history"] = state() == before
    compose("stop", "api", "soc-worker", "db")
    assert all(checks.values())
    target = ROOT / "docs/phase8/environment-evidence.json"
    target.write_text(
        json.dumps(
            {
                "checks": checks,
                "scenarios": scenarios,
                "records": before.strip(),
                "containers": restrictions,
                "commands": commands,
                "passed": len(checks),
                "failed": 0,
                "skipped": 0,
                "final_state": "stopped; disposable demo volume retained",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"phase8_environment_passed": len(checks), "failed": 0}), flush=True)


if __name__ == "__main__":
    main()
