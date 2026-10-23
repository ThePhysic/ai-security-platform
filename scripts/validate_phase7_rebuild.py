"""Fresh allowlisted build context; never copy private state or target repositories."""

import hashlib
import json
import os
import subprocess
from uuid import uuid4

from scripts.lifecycle import ROOT, MaintenanceError, private_directory


def main():
    target = private_directory(ROOT / ".cache" / ("phase7-clean-source-" + uuid4().hex))
    files = [
        "Dockerfile",
        "compose.phase7.yaml",
        ".dockerignore",
        "pyproject.toml",
        "uv.lock",
        ".python-version",
        "alembic.ini",
    ]
    files += [
        p.relative_to(ROOT).as_posix()
        for folder in ["src", "migrations", "policies", "web"]
        for p in (ROOT / folder).rglob("*")
        if p.is_file()
        and not any(
            part in {"node_modules", "dist", "__pycache__", "test-results", "playwright-report"}
            for part in p.relative_to(ROOT).parts
        )
        and not p.name.startswith(".env")
    ]
    hashes = {}
    for name in sorted(files):
        source = ROOT / name
        if source.is_symlink() or getattr(source.lstat(), "st_file_attributes", 0) & 0x400:
            raise MaintenanceError("unsafe_clean_source")
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        destination.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    assert not any("AGENTS.md" in name or ".local/" in name or ".env" in name for name in hashes)
    logs = private_directory(ROOT / ".cache/phase7-rebuild-logs")
    commands = [
        (
            target,
            [
                "docker",
                "--context",
                "desktop-linux",
                "build",
                "--no-cache",
                "--target",
                "runtime",
                "--tag",
                "asp-phase7/platform:local",
                ".",
            ],
        ),
        (target / "web", ["npm.cmd", "ci", "--ignore-scripts", "--no-audit"]),
        (target / "web", ["npm.cmd", "run", "build"]),
    ]
    checks = []
    for index, (directory, command) in enumerate(commands):
        result = subprocess.run(
            command, cwd=directory, capture_output=True, timeout=600, env=dict(os.environ)
        )
        (logs / f"command-{index}.log").write_bytes(result.stdout + result.stderr)
        checks.append(
            {
                "command": subprocess.list2cmdline(command),
                "cwd": "clean-context" if directory == target else "clean-context/web",
                "exit_code": result.returncode,
            }
        )
        print(json.dumps(checks[-1]), flush=True)
        if result.returncode:
            raise MaintenanceError("clean_build_failed")
    artifacts = {
        p.relative_to(target / "web/dist").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (target / "web/dist").rglob("*")
        if p.is_file()
    }
    current = {
        p.relative_to(ROOT / "web/dist").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (ROOT / "web/dist").rglob("*")
        if p.is_file()
    }
    assert artifacts == current, "Clean compiled assets must match the current locked build"
    image = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "asp-phase7/platform:local"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    report = {
        "commands": checks,
        "clean_context_files": len(hashes),
        "source_hashes": hashes,
        "image_id": image,
        "compiled_assets": artifacts,
        "assets_match_original": True,
        "private_state_packaged": False,
        "docker_cache_used": False,
        "scope": (
            "Fresh dependencies/build layers from pinned base images, "
            "original base image cache retained; no production deployment"
        ),
        "passed": len(checks) + 1,
        "failed": 0,
        "skipped": 0,
    }
    (ROOT / "docs/phase7/rebuild-evidence.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (ROOT / ".cache/phase7-clean-context.json").write_text(
        json.dumps({"path": str(target)}) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
