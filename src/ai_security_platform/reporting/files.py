"""Exclusive atomic artifacts under one workspace-owned directory; no arbitrary path API."""

import os
import re
from pathlib import Path
from uuid import uuid4

from ai_security_platform.snapshots.store import _check_ancestors


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
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _check_ancestors(root)
        os.link(temporary, target)  # atomic, exclusive, never replaces a file/link
    finally:
        temporary.unlink(missing_ok=True)
    return target.relative_to(workspace).as_posix()
