"""Run browser prerequisites and tests sequentially; stop on any failed preparation."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    environment = dict(os.environ)
    environment["PLAYWRIGHT_BROWSERS_PATH"] = str(ROOT / ".cache/phase6-browsers")
    environment.pop("ASP_TEST_PREVIEW", None)
    environment.pop("ASP_TEST_SUPPLEMENTAL", None)
    logs = ROOT / ".cache/phase6-frontend"
    logs.mkdir(parents=True, exist_ok=True)
    commands = [
        (ROOT, [sys.executable, "scripts/prepare_phase6_browser.py"], False),
        (ROOT / "web", ["npm.cmd", "ci", "--ignore-scripts", "--no-audit"], False),
        (ROOT / "web", ["npm.cmd", "run", "build"], False),
        (
            ROOT / "web",
            ["node", "node_modules/@playwright/test/cli.js", "install", "chromium", "--only-shell"],
            False,
        ),
        (ROOT / "web", ["npm.cmd", "test"], False),
        (ROOT / "web", ["npm.cmd", "test"], True),
    ]
    records = []
    for index, (directory, command, preview) in enumerate(commands):
        current = environment | ({"ASP_TEST_PREVIEW": "true"} if preview else {})
        result = subprocess.run(
            command,
            cwd=directory,
            env=current,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = result.stdout + result.stderr
        # The browser reporter already redacts credentials. This additional guard
        # also covers toolchain errors before the reporter starts.
        from dotenv import dotenv_values

        for name, value in dotenv_values(ROOT / ".env").items():
            if value and (name.endswith("TOKEN") or name.endswith("PASSWORD")):
                output = output.replace(value, "[redacted]")
        (logs / f"check-{index}.log").write_text(output, encoding="utf-8")
        record = {
            "command": subprocess.list2cmdline(command),
            "cwd": str(directory.relative_to(ROOT)) or ".",
            "preview": preview,
            "exit_code": result.returncode,
        }
        records.append(record)
        print(json.dumps(record), flush=True)
        if result.returncode:
            raise SystemExit(
                "Browser validation failed; inspect scoped sanitized logs. Later steps did not run."
            )
    target = ROOT / "docs/phase6/frontend-command-evidence.json"
    target.write_text(
        json.dumps({"checks": records, "passed": len(records), "failed": 0, "skipped": 0}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
