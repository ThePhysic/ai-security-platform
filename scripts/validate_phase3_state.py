"""Read-only final checks; emit public versions and sanitized local boundary facts."""

import importlib.metadata
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import dotenv_values  # noqa: E402

from runner.boundary import DockerBoundary  # noqa: E402
from scripts.validate_local import DEV, inspect_safe, request, run  # noqa: E402


def main():
    config = dotenv_values(ROOT / ".env")
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    checks = {}
    checks["real_intake_disabled"] = config.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
    checks["ready"] = request(base, "/ready", method="GET").status_code == 200
    checks["public_authentication_required"] = (
        request(
            base, "/api/v1/scan-runs/00000000-0000-0000-0000-000000000000", method="GET"
        ).status_code
        == 401
    )
    services = {}
    for service in ("api", "worker", "triage-worker", "db"):
        identifier = run(*DEV, "--profile", "workers", "--profile", "triage", "ps", "-q", service)
        data = inspect_safe(identifier)
        services[service] = {
            key: data[key] for key in ("user", "readonly", "caps", "security", "ports", "project")
        }
        services[service]["mounts"] = [
            {key: mount[key] for key in ("Type", "Destination", "RW")} for mount in data["mounts"]
        ]
        assert data["project"] == "asp-phase1-dev"
        if service == "db":
            checks["database_not_published"] = not data["ports"]
            continue
        checks[service + "_restricted"] = (
            data["user"] == "10001:10001"
            and data["readonly"]
            and "ALL" in data["caps"]
            and "no-new-privileges:true" in data["security"]
            and all(m["Destination"] in {"/spool", "/tmp"} for m in data["mounts"])
        )
        validation = (
            "import os,json,pathlib,shutil;"
            "print(json.dumps({'no_daemon_client':shutil.which('docker') is None,"
            "'no_private_build_files':all(not pathlib.Path(p).exists() for p in "
            "['/app/AGENTS.md','/app/.local','/app/.env','/app/runner']),"
            "'no_daemon_environment':not any(k.startswith('DOCKER_') for k in os.environ),"
            "'real_admission_disabled':os.environ.get('ASP_REAL_SCANNING_ENABLED','false')=='false',"
            "'hosted_disabled':os.environ.get('ASP_HOSTED_ENABLED','false')=='false',"
            "'no_provider_key':'ASP_HOSTED_API_KEY' not in os.environ}))"
        )
        observed = json.loads(run(*DEV, "exec", "-T", service, "python", "-c", validation))
        checks.update({service + "_" + key: value for key, value in observed.items()})
    checks["api_loopback_only"] = all(
        binding["HostIp"] == "127.0.0.1"
        for bindings in services["api"]["ports"].values()
        for binding in bindings
    )
    boundary = DockerBoundary(ROOT / ".local/snapshot-spool")
    checks["no_scanner_containers"] = not boundary.command(
        "ps", "-aq", "--filter", "label=ai-security-platform.phase2b=scanner"
    )
    checks["instructions_ignored"] = (
        subprocess.run(
            ["git", "check-ignore", "--quiet", "AGENTS.md"], cwd=ROOT, check=False
        ).returncode
        == 0
    )
    checks["nothing_staged"] = (
        subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False).returncode
        == 0
    )
    files = set(run("git", "diff", "--name-only").splitlines())
    files.update(run("git", "ls-files", "--others", "--exclude-standard").splitlines())
    secrets = [
        value
        for name, value in config.items()
        if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
    ]
    checks["actual_credentials_absent_from_changed_files"] = all(
        not any(value in (ROOT / filename).read_text(encoding="utf-8") for value in secrets)
        for filename in files
        if (ROOT / filename).is_file()
    )
    revision = run(
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
        "SELECT version_num FROM alembic_version",
    )
    postgres = run(
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
        "SHOW server_version",
    )
    checks["expected_schema"] = revision == "0004_triage_review"
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    result = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "python": sys.version.split()[0],
        "uv": run("uv", "--version"),
        "postgresql": postgres,
        "docker": boundary.ready(),
        "compose": run("docker", "compose", "version", "--short"),
        "migration": revision,
        "services": services,
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "installed_distributions": {
            distribution.metadata["Name"]: distribution.version
            for distribution in sorted(
                importlib.metadata.distributions(), key=lambda item: item.metadata["Name"].lower()
            )
        },
    }
    (ROOT / "docs/phase3/runtime-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"state_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
