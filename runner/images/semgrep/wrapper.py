"""Trusted audit view; source is data and is never imported or executed."""

import json
import os
import re
import sys
from pathlib import Path

POLICY_NAMES = {
    ".semgrepignore",
    ".gitignore",
    ".semgrep.yml",
    ".semgrep.yaml",
    "semgrep.yml",
    "semgrep.yaml",
    ".trivyignore",
    ".trivyignore.yaml",
    ".trivy.yaml",
    "trivy.yaml",
    "trivy.yml",
    "trivy-secret.yaml",
}


def main():
    mode = sys.argv[1]
    target = Path("/work/audit")
    target.mkdir()
    count = total = ignored = neutralized = 0
    for base, directories, names in os.walk("/source", followlinks=False):
        relative = Path(base).relative_to("/source")
        for directory in directories:
            if (Path(base) / directory).is_symlink():
                raise RuntimeError("unsafe_source")
        for name in names:
            source = Path(base) / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError("unsafe_source")
            count += 1
            if count > 512 or source.stat().st_size > 1048576:
                raise RuntimeError("source_budget")
            content = source.read_bytes()
            total += len(content)
            if total > 16 * 1048576:
                raise RuntimeError("source_budget")
            if name.lower() in POLICY_NAMES:
                ignored += 1
                continue
            if mode == "trivy":
                content, removed = re.subn(
                    rb"(?:trivy|tfsec):ignore",
                    lambda match: b"x" * len(match[0]),
                    content,
                    flags=re.IGNORECASE,
                )
                neutralized += removed
            destination = target / relative / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    # Safe counters only. Launcher captures this stream transiently.
    print(
        json.dumps(
            {
                "audit_view": 1,
                "policy_files_ignored": ignored,
                "suppression_tokens_neutralized": neutralized,
            }
        ),
        file=sys.stderr,
        flush=True,
    )
    if mode == "semgrep":
        arguments = [
            "/usr/bin/semgrep",
            "scan",
            "--config",
            "/opt/platform/rules.yaml",
            "--json",
            "--metrics",
            "off",
            "--disable-version-check",
            "--disable-nosem",
            "--no-git-ignore",
            "--no-rewrite-rule-ids",
            "--oss-only",
            "--jobs",
            "1",
            "--max-memory",
            "768",
            "--timeout",
            "5",
            "--max-target-bytes",
            "1048576",
            "--no-autofix",
            "--no-trace",
            "--strict",
            "/work/audit",
        ]
    elif mode == "trivy":
        arguments = [
            "/usr/local/bin/trivy",
            "filesystem",
            "--config",
            "/opt/platform/trivy.yaml",
            "--scanners",
            "vuln,secret,misconfig",
            "--pkg-types",
            "library",
            "--misconfig-scanners",
            "dockerfile,kubernetes",
            "--parallel",
            "1",
            "--format",
            "json",
            "--quiet",
            "--cache-dir",
            "/cache",
            "--cache-backend",
            "memory",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            "--ignorefile",
            "/opt/platform/empty.ignore",
            "--secret-config",
            "/opt/platform/secret.yaml",
            "--show-suppressed",
            "--skip-version-check",
            "--disable-telemetry",
            "--timeout",
            "80s",
            "/work/audit",
        ]
    else:
        raise RuntimeError("unknown_profile")
    os.execv(arguments[0], arguments)


if __name__ == "__main__":
    main()
