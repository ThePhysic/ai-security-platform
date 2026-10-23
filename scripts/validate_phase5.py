"""Run mandatory PostgreSQL/process regressions and extract safe G8 evaluation evidence."""

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ["docker", "compose", "-p", "asp-phase1-test", "--profile", "test"]


def main():
    # Scanner execution is an explicit preceding Windows-host command. Missing
    # observations fail the evaluation test; no mock fallback or silent skip exists.
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
    target = ROOT / "docs/phase5"
    target.mkdir(parents=True, exist_ok=True)
    logs = ROOT / ".cache/phase5-results"
    logs.mkdir(parents=True, exist_ok=True)
    checks, experiments, triage_experiments = [], [], []
    report = None
    measurements = {}
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        (logs / f"check-{index}.log").write_text(output, encoding="utf-8")
        checks.append({"command": subprocess.list2cmdline(command), "exit_code": result.returncode})
        print(json.dumps(checks[-1]), flush=True)
        for line in output.splitlines():
            if "EVALUATION_REPORT=" in line:
                report = json.loads(line.split("EVALUATION_REPORT=", 1)[1])
            for prefix, filename in (
                ("PERFORMANCE_REPORT=", "performance-evidence.json"),
                ("RECOVERY_REPORT=", "recovery-evidence.json"),
            ):
                if prefix in line:
                    measurements[filename] = json.loads(line.split(prefix, 1)[1])
            for marker, records in (
                ("experiment", experiments),
                ("triage_experiment", triage_experiments),
            ):
                position = line.find('{"' + marker + '":')
                if position >= 0:
                    records.append(json.loads(line[position:]))
        if result.returncode:
            raise SystemExit("Phase 5 check failed; inspect ignored .cache/phase5-results logs")
    for filename, value in measurements.items():
        (target / filename).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    assert len(measurements) == 2
    summary = re.search(r"(\d+) passed[^\n]*", output)
    assert (
        summary and report is not None and len(experiments) == 25 and len(triage_experiments) == 5
    )
    counts = {
        "passed": int(summary[1]),
        "failed": sum(map(int, re.findall(r"(\d+) failed", summary[0]))),
        "skipped": sum(map(int, re.findall(r"(\d+) skipped", summary[0]))),
    }
    assert counts["failed"] == counts["skipped"] == 0
    (target / "triage-adversarial-evidence.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
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
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "pytest": counts,
                "scan_crash_experiments": 25,
                "triage_crash_experiments": 5,
                "evaluation": "recorded",
            }
        )
    )


if __name__ == "__main__":
    main()
