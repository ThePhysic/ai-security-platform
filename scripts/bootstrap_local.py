"""Create ignored development configuration once; never print credentials."""

import os
import secrets
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    target = ROOT / ".env"
    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", ".env"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if ignored.returncode != 0:
        raise SystemExit("Refusing to create configuration: .env must be ignored")
    if target.exists():
        print("Existing .env preserved; no credential values read or displayed.")
        return
    values = {
        "ASP_DB_PASSWORD": secrets.token_urlsafe(48),
        "ASP_TEST_DB_PASSWORD": secrets.token_urlsafe(48),
        "ASP_API_TOKEN": secrets.token_urlsafe(48),
        "ASP_API_PORT": "18081",
    }
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("".join(f"{key}={value}\n" for key, value in values.items()))
    print("Created ignored local .env with independent generated credentials.")


if __name__ == "__main__":
    main()
