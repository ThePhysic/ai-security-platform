"""Clean Git materialization and restricted local CI; never stage or touch application data."""

import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
PATCH = [
    ".gitattributes",
    ".github/workflows/developer-guardrails.yml",
    "scripts/generate_ci_artifacts.py",
    "scripts/verify_ci_artifacts.py",
    "scripts/validate_ci_repair.py",
    "tests/unit/test_evaluation_corpus.py",
    "tests/unit/test_guardrails_workflow.py",
    "tests/unit/test_reporting_cli.py",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(arguments, *, cwd=ROOT, timeout=600, input=None):
    result = subprocess.run(arguments, cwd=cwd, input=input, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("CI repair validation command failed; inspect scoped private logs")
    return result.stdout


def main():
    identity = uuid4().hex
    workspace = ROOT / ".cache/ci-repair" / identity
    workspace.mkdir(parents=True)
    index_before = sha(ROOT / ".git/index")
    assert not run(["git", "ls-files", "--", "AGENTS.md"]).strip()
    frozen = json.loads((ROOT / "evaluation/frozen-v1.json").read_text())
    observations = json.loads((ROOT / "evaluation/results/scanner-observations.json").read_text())
    checkouts = []
    for mode, autocrlf, eol in [("linux", "false", "lf"), ("windows", "true", "crlf")]:
        target = workspace / mode
        target.mkdir()
        command = [
            "git",
            "-c",
            "core.autocrlf=" + autocrlf,
            "-c",
            "core.eol=" + eol,
            "checkout-index",
            "--all",
            "--prefix=" + target.as_posix() + "/",
        ]
        run(command)
        # Git uses the working-tree attributes for materialization. Overlay only the
        # authorized repair; do not add it to any Git index or create a commit.
        for name in PATCH:
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        assert not (target / "AGENTS.md").exists() and not (target / ".local").exists()
        assert all(
            sha(target / "evaluation" / name) == expected
            for name, expected in frozen["files"].items()
        )
        assert sha(target / "evaluation/frozen-v1.json") == observations["freeze_sha256"]
        for name in ["manifest.json", "adversarial.json", "frozen-v1.json"]:
            assert sha(target / "evaluation" / name) == sha(ROOT / "evaluation" / name)
        # Every other evaluation path retains the LF checkout rule and its committed bytes.
        names = run(["git", "ls-files", "-z", "--", "evaluation"]).decode().split("\0")
        for name in filter(None, names):
            if name in {
                "evaluation/manifest.json",
                "evaluation/adversarial.json",
                "evaluation/frozen-v1.json",
            }:
                continue
            assert (target / name).read_bytes() == run(["git", "show", "HEAD:" + name])
        checkouts.append(
            {
                "mode": mode,
                "core_autocrlf": autocrlf,
                "core_eol": eol,
                "frozen_members_verified": len(frozen["files"]),
                "recorded_freeze_identity_valid": True,
                "other_evaluation_checkout_bytes_unchanged": True,
            }
        )
    assert sha(ROOT / ".git/index") == index_before
    candidate = workspace / "linux"
    image = "asp-ci-repair/tests:" + identity
    build_command = [
        "docker",
        "--context",
        "desktop-linux",
        "build",
        "--target",
        "tests",
        "--tag",
        image,
        str(candidate),
    ]
    build = subprocess.run(build_command, cwd=ROOT, capture_output=True, timeout=600)
    (workspace / "build.log").write_bytes(build.stdout + build.stderr)
    assert build.returncode == 0, "Clean CI image failed; inspect scoped build.log"
    name = "asp-ci-repair-" + identity
    container = (
        run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--label",
                "asp.ci-repair=" + identity,
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
            ]
        )
        .decode()
        .strip()
    )
    commands = []
    try:
        run(["docker", "start", container])
        data = json.loads(run(["docker", "inspect", container]))[0]
        host = data["HostConfig"]
        assert (
            host["NetworkMode"] == "none"
            and host["ReadonlyRootfs"]
            and data["Config"]["User"] == "10001:10001"
            and host["CapDrop"] == ["ALL"]
            and host["PidsLimit"] == 64
            and host["Memory"] == 512 * 1024 * 1024
            and host["NanoCpus"] == 1000000000
            and "no-new-privileges:true" in host["SecurityOpt"]
            and not host["Binds"]
        )
        assert not any(
            item.startswith(("ASP_", "OPENAI_", "DOCKER_HOST=")) for item in data["Config"]["Env"]
        )
        generation = json.loads(
            run(
                [
                    "docker",
                    "exec",
                    container,
                    "/app/.venv/bin/python",
                    "/app/scripts/generate_ci_artifacts.py",
                ]
            )
        )
        assert generation == {
            "artifacts": 3,
            "policy_exit_code": 1,
            "live_scans": 0,
            "hosted_calls": 0,
        }
        artifacts = workspace / "artifacts"
        artifacts.mkdir()
        for filename in ["guardrails.json", "guardrails.sarif", "policy.json"]:
            raw = run(
                [
                    "docker",
                    "exec",
                    container,
                    "/app/.venv/bin/python",
                    "-c",
                    "import pathlib,sys; b=(pathlib.Path('/tmp/guardrails/.local/reports')/"
                    "sys.argv[1]).read_bytes(); assert len(b)<=4194304; sys.stdout.buffer.write(b)",
                    filename,
                ]
            )
            (artifacts / filename).write_bytes(raw)
        payload = run(
            [sys.executable, "-I", "-S", str(ROOT / "scripts/verify_ci_artifacts.py"), "--send"],
            cwd=workspace,
        )
        verified = json.loads(
            run(
                [
                    "docker",
                    "exec",
                    "-i",
                    container,
                    "/app/.venv/bin/python",
                    "/app/scripts/verify_ci_artifacts.py",
                    "--stdin",
                ],
                input=payload,
            )
        )
        assert verified == {"artifacts": 3, "policy_exit_code": 1, "verification": "passed"}
        assert json.loads((artifacts / "policy.json").read_bytes())["exit_code"] == 1
        from ai_security_platform.reporting.core import sarif

        original = json.loads(payload)
        negatives = []
        for title in [
            "unexpected_pass",
            "operational_failure",
            "boolean_code",
            "missing_policy",
            "malformed_sarif",
            "incomplete_required_scanner",
        ]:
            bundle = dict(original)

            def replace(filename, value, destination=bundle):
                destination[filename] = base64.b64encode(json.dumps(value).encode()).decode("ascii")

            if title in {"unexpected_pass", "operational_failure", "boolean_code"}:
                policy = json.loads(base64.b64decode(bundle["policy.json"]))
                policy["exit_code"] = {
                    "unexpected_pass": 0,
                    "operational_failure": 2,
                    "boolean_code": True,
                }[title]
                replace("policy.json", policy)
            elif title == "missing_policy":
                del bundle["policy.json"]
            elif title == "malformed_sarif":
                bundle["guardrails.sarif"] = base64.b64encode(b"{").decode("ascii")
            else:
                report = json.loads(base64.b64decode(bundle["guardrails.json"]))
                scanner = next(
                    row for row in report["scan"]["scanner_runs"] if row["scanner_id"] == "semgrep"
                )
                scanner["coverage"]["complete_execution"] = False
                replace("guardrails.json", report)
                replace("guardrails.sarif", sarif(report))
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    container,
                    "/app/.venv/bin/python",
                    "/app/scripts/verify_ci_artifacts.py",
                    "--stdin",
                ],
                cwd=ROOT,
                input=json.dumps(bundle).encode(),
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 2 and not result.stdout
            error = json.loads(result.stderr)
            assert set(error) == {"error", "error_type"}
            assert error["error"] == "ci_artifact_verification_failed"
            negatives.append(
                {
                    "case": title,
                    "expected_exit": 2,
                    "actual_exit": 2,
                    "sanitized_error_type": error["error_type"],
                    "passed": True,
                }
            )
        # Execute the original inline verification to demonstrate its independent failure.
        old_check = (
            "import json; raise SystemExit(json.load(open('artifacts/policy.json'))['exit_code'])"
        )
        old = subprocess.run([sys.executable, "-c", old_check], cwd=workspace, capture_output=True)
        assert old.returncode == 1
        selections = [
            ("frozen", ["pytest", "-q", "tests/unit/test_evaluation_corpus.py"]),
            ("unit-api", ["pytest", "-q", "-m", "unit or api", "--tb=short"]),
            ("ruff", ["ruff", "check", "."]),
            ("format", ["ruff", "format", "--check", "src", *PATCH[2:]]),
            ("mypy", ["mypy", "src"]),
        ]
        for title, tool in selections:
            command = [
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
                "--pids-limit",
                "64",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=256m",
                image,
                "uv",
                "run",
                "--no-sync",
                *tool,
            ]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=600)
            output = result.stdout + result.stderr
            (workspace / (title + ".log")).write_bytes(output)
            assert result.returncode == 0, "Clean check failed; inspect scoped " + title + ".log"
            count = re.search(rb"(\d+) passed", output)
            commands.append(
                {
                    "name": title,
                    "command": subprocess.list2cmdline(command),
                    "exit_code": 0,
                    "passed": int(count[1]) if count else None,
                }
            )
            print(json.dumps(commands[-1]), flush=True)
        report = {
            "head": run(["git", "rev-parse", "HEAD"]).decode().strip(),
            "checkout_method": "Git checkout-index with explicit Linux/Windows configs, "
            "authorized repair overlay, then actual Linux Docker execution",
            "checkouts": checkouts,
            "original_index_unchanged": sha(ROOT / ".git/index") == index_before,
            "generation": generation,
            "verification": verified,
            "negative_verification_cases": negatives,
            "host_sender_stdlib_only": True,
            "old_policy_check_exit": old.returncode,
            "artifact_sha256": {path.name: sha(path) for path in artifacts.iterdir()},
            "container": {
                "network": "none",
                "readonly": True,
                "user": "10001:10001",
                "cap_drop": ["ALL"],
                "pids": 64,
                "memory_bytes": 536870912,
                "cpus": 1,
                "tmpfs_mib": 128,
                "credentials_provided": False,
            },
            "checks": commands,
            "remote_actions_executed": False,
            "database_services_started": False,
            "benchmark_files_modified": False,
        }
    finally:
        label = (
            run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{{index .Config.Labels "asp.ci-repair"}}',
                    container,
                ]
            )
            .decode()
            .strip()
        )
        assert label == identity
        run(["docker", "rm", "--force", container])
    report["disposable_container_removed"] = True
    output = ROOT / "docs/ci-repair"
    output.mkdir(parents=True, exist_ok=True)
    (output / "validation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (ROOT / ".cache/ci-repair/latest.json").write_text(
        json.dumps({"path": str(workspace), "image": image}), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "restricted_artifact_generation": "passed",
                "policy_json_exit_code": 1,
                "ci_verification_exit_code": 0,
                "container_removed": True,
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
