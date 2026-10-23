import re
from pathlib import Path

import pytest
import yaml

from tests.db_guard import assert_disposable

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]


def test_disposable_guard():
    for url, marker in [
        (None, None),
        ("postgresql+psycopg://asp_owner:synthetic@db/asp_dev", "asp_phase1_test"),
        ("postgresql+psycopg://asp_test:synthetic@test-db/asp_phase1_test", None),
        (
            "postgresql+psycopg://asp_test:synthetic@remote.invalid/asp_phase1_test",
            "asp_phase1_test",
        ),
    ]:
        with pytest.raises(RuntimeError):
            assert_disposable(url, marker)
    assert assert_disposable(
        "postgresql+psycopg://asp_test:synthetic@test-db/asp_phase1_test", "asp_phase1_test"
    )


def test_compose_policy():
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert compose["name"] == "asp-phase1"
    services = compose["services"]
    assert set(services) == {"api", "db", "worker", "triage-worker", "test-db", "tests"}
    assert services["api"]["ports"][0].startswith("127.0.0.1:")
    for name in ("db", "test-db"):
        assert "ports" not in services[name]
        assert "@sha256:" in services[name]["image"]
    assert services["test-db"]["volumes"] == ["test-db:/var/lib/postgresql/data"]
    assert services["test-db"]["environment"]["POSTGRES_DB"] == "asp_phase1_test"
    for name in ("api", "worker", "triage-worker", "tests"):
        assert services[name]["read_only"]
        assert services[name]["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in services[name]["security_opt"]
        if name == "tests":
            assert "volumes" not in services[name]
        else:
            assert services[name]["mem_limit"] == "256m"
            assert services[name]["cpus"] == 1.0 and services[name]["pids_limit"] == 64
            assert len(services[name]["volumes"]) == 1
            mount = services[name]["volumes"][0]
            assert mount["target"] == "/spool" and mount["read_only"]
            assert mount["bind"]["create_host_path"] is False
    assert "ports" not in services["worker"]
    assert "ASP_DB_PASSWORD" not in services["tests"]["environment"]
    assert "docker.sock" not in str(services)
    assert "docker_engine" not in str(services)


def test_build_context_and_nonroot():
    ignores = (ROOT / ".dockerignore").read_text().splitlines()
    assert "**" in ignores
    assert "AGENTS.md" in ignores and "**/AGENTS.md" in ignores
    assert ".env" in ignores and ".git" in ignores and "secrets" in ignores
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY . " not in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--no-access-log" in dockerfile and "--no-proxy-headers" in dockerfile
    for line in dockerfile.splitlines():
        if line.startswith("FROM ") and line.split()[1] != "runtime":
            assert "@sha256:" in line


def test_ci_permissions_and_required_checks():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    steps = workflow["jobs"]["foundation"]["steps"]
    for step in steps:
        if "uses" in step:
            assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", step["uses"])
            assert step["with"]["persist-credentials"] is False
    commands = "\n".join(step.get("run", "") for step in steps)
    for marker in ("unit", "api", "orchestration"):
        assert f"pytest -m {marker}" in commands
    assert 'pytest -m "postgres and not orchestration"' in commands
    assert "ruff check" in commands and "mypy src" in commands
    assert "pull_request_target" not in (ROOT / ".github/workflows/ci.yml").read_text()
    assert "down -v" not in commands
