"""Relevant read-only UI regressions; preserve retained triage/review rows and earlier proof."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    fixture = ROOT / ".cache/phase7-browser-fixture.json"
    target = ROOT / ".cache/phase8-browser-fixture.json"
    target.write_bytes(fixture.read_bytes())
    probe = ROOT / "web/.env.phase8-probe"
    if not probe.exists():
        probe.write_text("phase8-controlled-private-probe\n", encoding="utf-8")
    environment = os.environ | {
        "ASP_EVIDENCE_PHASE": "phase8",
        "PLAYWRIGHT_BROWSERS_PATH": str(ROOT / ".cache/phase6-browsers"),
    }
    # Writes to real review/triage are exercised in PostgreSQL regression tests, not
    # repeated against retained portfolio records. Scripted browser cases are labelled.
    expression = (
        "security|scripted|memory-only|invalid bearer|partial scan|empty project|"
        "responsive keyboard|hosted execution|optional-module regression"
    )
    commands = [
        ["npm.cmd", "ci", "--ignore-scripts", "--no-audit"],
        ["npm.cmd", "run", "build"],
        ["npm.cmd", "test", "--", "--grep", expression],
    ]
    checks = []
    for index, command in enumerate(commands):
        result = subprocess.run(
            command,
            cwd=ROOT / "web",
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        (ROOT / f".cache/phase8-browser-{index}.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        checks.append({"command": subprocess.list2cmdline(command), "exit_code": result.returncode})
        print(json.dumps(checks[-1]), flush=True)
        if result.returncode:
            raise SystemExit("Phase 8 browser regression failed; inspect private test logs")
    (ROOT / "docs/phase8/frontend-command-evidence.json").write_text(
        json.dumps({"checks": checks, "passed": len(checks), "failed": 0, "skipped": 0}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
