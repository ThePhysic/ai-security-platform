"""Run reproducible container checks and retain sanitized result evidence."""

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ["docker", "compose", "-p", "asp-phase1-test", "--profile", "test"]


def main():
    commands = [
        [*PREFIX, "build", "tests"],
        [*PREFIX, "run", "--rm", "tests", "uv", "run", "--no-sync", "ruff", "check", "."],
        [*PREFIX, "run", "--rm", "tests", "uv", "run", "--no-sync", "mypy", "src"],
        [
            *PREFIX,
            "run",
            "--rm",
            "tests",
            "uv",
            "run",
            "--no-sync",
            "pytest",
            "-q",
            "-s",
            "-p",
            "no:cacheprovider",
        ],
    ]
    checks, experiments, triage_experiments = [], [], []
    log_dir = ROOT / ".cache" / "phase3-results"
    log_dir.mkdir(parents=True, exist_ok=True)
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        (log_dir / f"check-{index}.log").write_text(output, encoding="utf-8")
        checks.append({"command": subprocess.list2cmdline(command), "exit_code": result.returncode})
        print(json.dumps(checks[-1]), flush=True)
        if index == 3:
            for line in output.splitlines():
                position = line.find('{"experiment":')
                if position >= 0:
                    experiments.append(json.loads(line[position:]))
                position = line.find('{"triage_experiment":')
                if position >= 0:
                    triage_experiments.append(json.loads(line[position:]))
            summary = re.search(r"(\d+) passed[^\n]*", output)
            assert summary, "Test summary absent; inspect ignored local validation logs"
            counts = {
                "passed": int(summary[1]),
                "failed": sum(map(int, re.findall(r"(\d+) failed", summary[0]))),
                "skipped": sum(map(int, re.findall(r"(\d+) skipped", summary[0]))),
            }
        if result.returncode:
            raise SystemExit("Validation failed; inspect ignored .cache/phase3-results diagnostics")
    assert len(experiments) == 25 and len(triage_experiments) == 5 and counts["skipped"] == 0
    target = ROOT / "docs" / "phase3"
    target.mkdir(parents=True, exist_ok=True)
    (target / "test-evidence.json").write_text(
        json.dumps(
            {
                "checks": checks,
                "pytest": counts,
                "experiments": experiments,
                "triage_experiments": triage_experiments,
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps({"pytest": counts, "crash_experiments": len(experiments)}))


if __name__ == "__main__":
    main()
