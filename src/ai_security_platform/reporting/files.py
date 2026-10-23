"""Exclusive atomic artifacts under one workspace-owned directory; no arbitrary path API."""

import os
import re
from pathlib import Path
from uuid import uuid4

from ai_security_platform.snapshots.filesystem import safe_kind
from ai_security_platform.snapshots.store import SnapshotStore, _check_ancestors


class _AlreadyExists(Exception):
    pass


MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def artifact_usage(root: Path) -> dict[str, int]:
    """Inspect metadata only; preserve exports/unknown ownership rather than prune."""
    _check_ancestors(root)
    count = size = temporary = 0
    if not root.exists():
        return {"files": 0, "bytes": 0, "temporary": 0}
    with os.scandir(root) as entries:
        for entry in entries:
            value = (root / entry.name).lstat()
            safe_kind(value, False)
            if entry.name == ".publish.lock":
                continue
            count += 1
            size += value.st_size
            temporary += int(bool(re.fullmatch(r"\.artifact-[0-9a-f]{32}", entry.name)))
            if count > MAX_ARTIFACTS or size > MAX_ARTIFACT_BYTES:
                raise ValueError("artifact_storage_quota")
    return {"files": count, "bytes": size, "temporary": temporary}


def write_artifact(workspace: Path, name: str, format: str, raw: bytes) -> str:
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", name)
        or format not in {"json", "sarif"}
        or len(raw) > 4 * 1024 * 1024
    ):
        raise ValueError("invalid_artifact")
    workspace = workspace.absolute()
    _check_ancestors(workspace)
    root = workspace / ".local" / "reports"
    for directory in (workspace / ".local", root):
        _check_ancestors(directory.parent)
        if directory.exists():
            _check_ancestors(directory)
        else:
            directory.mkdir(mode=0o700)
    _check_ancestors(root)
    if os.name == "nt":
        from ai_security_platform.snapshots.windows import protect_directory

        protect_directory(root)
    target = root / (name + "." + format)
    temporary = root / (".artifact-" + uuid4().hex)
    try:
        with SnapshotStore(root, require_readonly=False).publishing_lock():
            usage = artifact_usage(root)
            if usage["files"] >= MAX_ARTIFACTS or usage["bytes"] + len(raw) > MAX_ARTIFACT_BYTES:
                raise ValueError("artifact_storage_quota")
            try:
                with temporary.open("xb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                _check_ancestors(root)
                try:
                    os.link(temporary, target)  # atomic, exclusive, never replaces a file/link
                except FileExistsError:
                    # The shared spool lock sanitizes OSError from its body. Preserve
                    # this reporting contract after releasing the guard instead.
                    raise _AlreadyExists from None
            finally:
                temporary.unlink(missing_ok=True)
    except _AlreadyExists:
        raise FileExistsError("artifact_exists") from None
    return target.relative_to(workspace).as_posix()
