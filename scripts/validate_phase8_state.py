"""Read-only preservation, configuration, disclosure and frozen-baseline checks."""

import hashlib
import importlib.metadata
import json
import platform
import subprocess
from pathlib import Path

import httpx
from dotenv import dotenv_values

from scripts.lifecycle import Database

ROOT = Path(__file__).resolve().parents[1]


def run(*arguments):
    return subprocess.check_output(arguments, cwd=ROOT, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    before = json.loads((ROOT / ".cache/phase8-retained-before.json").read_text())
    baseline = json.loads((ROOT / ".cache/phase8-file-baseline.json").read_text())
    db = Database()
    db.guard()
    checks = {
        "retained_appsec_fingerprints_unchanged": db.state() == before,
        "public_revision_unchanged": db.sql("SELECT version_num FROM alembic_version")
        == "0004_triage_review",
        "retained_database_not_soc_migrated": db.sql("SELECT to_regnamespace('soc') IS NULL")
        == "t",
    }
    config = dotenv_values(ROOT / ".env")
    base = "http://127.0.0.1:" + config.get("ASP_API_PORT", "18081")
    with httpx.Client(base_url=base, trust_env=False, timeout=10) as client:
        auth = {"Authorization": "Bearer " + config["ASP_API_TOKEN"]}
        checks["default_soc_routes_absent"] = (
            client.get("/api/v1/soc/rules", headers=auth).status_code == 404
        )
        checks["default_appsec_ready"] = client.get("/ready").status_code == 200
        checks["api_authentication_retained"] = (
            client.get("/api/v1/triage-config").status_code == 401
        )
        checks["hosted_admission_disabled"] = not client.get(
            "/api/v1/triage-config", headers=auth
        ).json()["hosted_enabled"]
    for service in ["api", "worker", "triage-worker"]:
        identifier = run(
            "docker",
            "compose",
            "-p",
            "asp-phase1-dev",
            "--profile",
            "workers",
            "--profile",
            "triage",
            "ps",
            "-q",
            service,
        )
        data = json.loads(run("docker", "inspect", identifier))[0]
        environment = dict(item.split("=", 1) for item in data["Config"]["Env"] if "=" in item)
        checks[service + "_no_docker_or_soc_authority"] = (
            data["Config"]["User"] == "10001:10001"
            and data["HostConfig"]["ReadonlyRootfs"]
            and "ALL" in data["HostConfig"]["CapDrop"]
            and "no-new-privileges:true" in data["HostConfig"]["SecurityOpt"]
            and all(item["Destination"] in {"/spool", "/tmp"} for item in data["Mounts"])
            and environment.get("ASP_SOC_ENABLED", "false") == "false"
            and environment.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
            and not any(name in environment for name in ["DOCKER_HOST", "OPENAI_API_KEY"])
            and (service == "api" or not environment.get("ASP_LAUNCHER_TOKEN"))
        )
    historical = [
        name
        for name in baseline
        if name.startswith(
            tuple(
                "docs/phase" + phase + "/"
                for phase in ["0", "1", "2a", "2b", "3", "4", "5", "6", "7"]
            )
        )
    ]
    checks["prior_phase_documents_and_evidence_unchanged"] = all(
        sha(ROOT / name) == baseline[name] for name in historical
    )
    frozen = [name for name in baseline if name.startswith(("evaluation/", "policies/"))]
    checks["frozen_evaluation_and_scanner_policy_bytes_unchanged"] = all(
        sha(ROOT / name) == baseline[name] for name in frozen
    )
    checks["python_and_node_locks_unchanged"] = all(
        sha(ROOT / name) == baseline[name]
        for name in ["uv.lock", "pyproject.toml", "web/package-lock.json"]
    )
    old = json.loads((ROOT / "docs/phase7/triage-adversarial-evidence.json").read_text())
    new = json.loads((ROOT / "docs/phase8/triage-adversarial-evidence.json").read_text())
    checks["frozen_quality_and_adversarial_outcomes_unchanged"] = (
        {k: v for k, v in old["metrics"].items() if k != "observed_triage_duration_ms"}
        == {k: v for k, v in new["metrics"].items() if k != "observed_triage_duration_ms"}
        and old["adversarial_repetitions"] == new["adversarial_repetitions"]
        and old["freeze_sha256"] == new["freeze_sha256"]
        and old["provider"] == new["provider"]
        and new["live_hosted_calls"] == 0
    )
    checks["private_instructions_unchanged_ignored_unstaged"] = (
        sha(ROOT / "AGENTS.md")
        == (ROOT / ".cache/phase8-instruction-fingerprint").read_text(encoding="ascii")
        and subprocess.run(["git", "check-ignore", "--quiet", "AGENTS.md"], cwd=ROOT).returncode
        == 0
        and not run("git", "diff", "--cached", "--name-only")
    )
    credentials = [
        value
        for name, value in config.items()
        if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
    ]
    credentials += [
        value
        for name, value in dotenv_values(ROOT / ".local/phase8-demo/environment.env").items()
        if value and (name.endswith("TOKEN") or name.endswith("PASSWORD"))
    ]
    public = list((ROOT / "docs/phase8").rglob("*")) + list((ROOT / "web/dist").rglob("*"))
    checks["credentials_absent_from_evidence_and_browser_assets"] = all(
        secret.encode() not in path.read_bytes()
        for path in public
        if path.is_file()
        for secret in credentials
    )
    logs = run(
        "docker",
        "compose",
        "-p",
        "asp-phase1-dev",
        "--profile",
        "workers",
        "--profile",
        "triage",
        "logs",
        "--no-color",
        "--tail",
        "500",
        "api",
        "worker",
        "triage-worker",
    )
    checks["credentials_absent_from_backend_logs"] = not any(
        secret in logs for secret in credentials
    )
    versions = {
        name: importlib.metadata.version(name)
        for name in [
            "fastapi",
            "pydantic",
            "SQLAlchemy",
            "alembic",
            "psycopg",
            "pytest",
            "ruff",
            "mypy",
        ]
    }
    versions |= {
        "python": platform.python_version(),
        "uv": run("uv", "--version"),
        "postgresql": db.sql("SHOW server_version"),
        "node": run("node", "--version"),
    }
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    (ROOT / "docs/phase8/state-evidence.json").write_text(
        json.dumps(
            {
                "checks": checks,
                "versions": versions,
                "retained_table_count": len(before),
                "retained_counts": {name: value["rows"] for name, value in before.items()},
                "historical_documents_checked": len(historical),
                "frozen_files_checked": len(frozen),
                "passed": len(checks),
                "failed": 0,
                "skipped": 0,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"state_checks_passed": len(checks), "failed": 0}), flush=True)


if __name__ == "__main__":
    main()
