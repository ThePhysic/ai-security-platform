import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class SnapshotError(ValueError):
    """Safe error code only; never include target names, bytes or absolute paths."""


@dataclass(frozen=True)
class Limits:
    files: int = 512
    directories: int = 128
    depth: int = 16
    path_bytes: int = 240
    file_bytes: int = 1024 * 1024
    total_bytes: int = 16 * 1024 * 1024
    manifest_bytes: int = 256 * 1024
    spool_bytes: int = 128 * 1024 * 1024
    snapshots: int = 32
    entries: int = 2048


DEFAULT_LIMITS = Limits()
DIRECTORY_EXCLUSIONS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        ".local",
        ".cache",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".aws",
        ".ssh",
        ".codex",
        ".agents",
        "secrets",
    }
)
FILE_EXCLUSIONS = frozenset({"agents.md", "credentials.json"})
RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"{prefix}{index}" for prefix in ("COM", "LPT") for index in range(1, 10)}
)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


POLICY_DIGEST = digest(
    canonical(
        {
            "version": 1,
            "directories": sorted(DIRECTORY_EXCLUSIONS),
            "files": sorted(FILE_EXCLUSIONS),
            "filename_policy": "portable-ascii-no-links-no-streams-v1",
            "secret_files": [".env*", "*.pem", "*.key", "*.p12", "*.pfx"],
        }
    )
)


def validate_path(path: str, limits: Limits = DEFAULT_LIMITS) -> str:
    parts = path.split("/")
    if not path or len(path.encode("utf-8")) > limits.path_bytes or len(parts) > limits.depth:
        raise SnapshotError("path_budget")
    for part in parts:
        if (
            part in {"", ".", ".."}
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", part)
            or part.endswith(".")
            or part.split(".")[0].upper() in RESERVED
        ):
            raise SnapshotError("unsafe_path")
    return path


def excluded(name: str, directory: bool) -> bool:
    value = name.lower()
    if directory:
        return value in DIRECTORY_EXCLUSIONS
    return (
        value in FILE_EXCLUSIONS
        or (value.startswith(".env") and value != ".env.example")
        or value.endswith((".pem", ".key", ".p12", ".pfx"))
    )
