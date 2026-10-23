"""Clean candidate-tree local CI; no Git writes, private files or remote action runs."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import jsonschema  # noqa: E402


def run(*args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("Clean local CI command failed; inspect ignored scoped logs")
    return result.stdout


def main():
    identity = uuid4().hex
    candidate = ROOT / ".cache" / ("phase5-clean-" + identity)
    candidate.mkdir(parents=True)
    names = run("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
    copied = []
    for name in sorted(set(filter(None, names))):
        parts = Path(name).parts
        if any(
            p.lower() in {"agents.md", ".local", ".cache", ".git", ".venv"} or p.startswith(".env")
            for p in parts
        ):
            continue
        source = ROOT / name
        assert source.is_file() and not source.is_symlink() and source.stat().st_nlink == 1
        assert not getattr(source.stat(), "st_file_attributes", 0) & 0x400
        target = candidate / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append(name)
    assert not any(
        p.name.lower() == "agents.md" or p.name == ".local" for p in candidate.rglob("*")
    )
    image = "asp-phase5/clean:" + identity
    build = subprocess.run(
        ["docker", "build", "--target", "tests", "--tag", image, str(candidate)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    (candidate / "build.log").write_text(build.stdout + build.stderr, encoding="utf-8")
    assert build.returncode == 0, "Clean candidate build failed; inspect private build.log"
    name = "asp-phase5-ci-" + identity
    container = run(
        "docker",
        "create",
        "--name",
        name,
        "--label",
        "asp.phase5=ci",
        "--network",
        "none",
        "--read-only",
        "--user",
        "10001:10001",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "64",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        image,
        "/app/.venv/bin/python",
        "-c",
        "import time; time.sleep(300)",
    ).strip()
    try:
        run("docker", "start", container)
        output = run(
            "docker",
            "exec",
            container,
            "/app/.venv/bin/python",
            "/app/scripts/generate_ci_artifacts.py",
        )
        output = json.loads(output)
        assert (
            output["artifacts"] == 3
            and output["policy_exit_code"] == 1
            and output["hosted_calls"] == 0
        )
        artifacts = candidate / "artifacts"
        artifacts.mkdir()
        for filename in ("guardrails.json", "guardrails.sarif", "policy.json"):
            raw = run(
                "docker",
                "exec",
                container,
                "/app/.venv/bin/python",
                "-c",
                "import pathlib,sys; p=pathlib.Path('/tmp/guardrails/.local/reports')/sys.argv[1]; "
                "b=p.read_bytes(); assert len(b)<=4194304; sys.stdout.buffer.write(b)",
                filename,
            )
            (artifacts / filename).write_bytes(raw.encode())
        assert {p.name for p in artifacts.iterdir()} == {
            "guardrails.json",
            "guardrails.sarif",
            "policy.json",
        }
        sarif = json.loads((artifacts / "guardrails.sarif").read_text())
        schema = json.loads((ROOT / "tests/schemas/sarif-2.1.0.json").read_text())
        jsonschema.validators.validator_for(schema)(schema).validate(sarif)
        jsonschema.validate(
            json.loads((artifacts / "guardrails.json").read_text()),
            json.loads((ROOT / "tests/schemas/report-v1.json").read_text()),
        )
        suite = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=256m",
                image,
                "uv",
                "run",
                "--no-sync",
                "pytest",
                "-m",
                "unit or api",
                "--basetemp",
                "/tmp/clean-tests",
                "--tb=short",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        (candidate / "unit-api.log").write_text(suite.stdout + suite.stderr, encoding="utf-8")
        assert suite.returncode == 0, "Clean unit/API suite failed; inspect private unit-api.log"
        count = re.search(r"(\d+) passed", suite.stdout)
        assert count
        record = {
            "passed": 7,
            "failed": 0,
            "skipped": 0,
            "clean_candidate_files": len(copied),
            "unit_api_passed": int(count[1]),
            "checks": {
                "no_private_build_files": True,
                "clean_image_build": True,
                "network_disabled_artifact_generation": True,
                "official_sarif_schema": True,
                "json_report_schema": True,
                "policy_failure_distinct_from_generation_success": True,
                "clean_unit_api_suite": True,
            },
            "remote_actions_executed": False,
            "code_scanning_uploaded": False,
            "mode": (
                "clean candidate tree includes authorized unstaged changes; "
                "not a committed checkout or remote GitHub run"
            ),
            "policy_exit_code": 1,
            "artifact_files": 3,
        }
        target = ROOT / "docs/phase5"
        target.mkdir(parents=True, exist_ok=True)
        (target / "ci-evidence.json").write_text(
            json.dumps(record, indent=2) + "\n", encoding="utf-8"
        )
        examples = target / "examples"
        examples.mkdir(exist_ok=True)
        for filename in ("guardrails.json", "guardrails.sarif", "policy.json"):
            shutil.copyfile(artifacts / filename, examples / filename)
        print(json.dumps(record), flush=True)
    finally:
        assert (
            run(
                "docker", "inspect", "--format", '{{index .Config.Labels "asp.phase5"}}', container
            ).strip()
            == "ci"
        )
        run("docker", "rm", "--force", container)


if __name__ == "__main__":
    main()
