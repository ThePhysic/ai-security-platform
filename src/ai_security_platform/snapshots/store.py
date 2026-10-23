"""Local publication and read-only server verification. No archives or URLs."""

import json
import os
import re
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ai_security_platform.snapshots.filesystem import PinnedTree
from ai_security_platform.snapshots.policy import (
    DEFAULT_LIMITS,
    POLICY_DIGEST,
    Limits,
    SnapshotError,
    canonical,
    digest,
    excluded,
    validate_path,
)

MARKER = b"ai-security-platform-private-spool-v1\n"
KEY = r"^[0-9a-f]{32}$"
SHA = r"^[0-9a-f]{64}$"


class FileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str
    size: int = Field(ge=0, le=DEFAULT_LIMITS.file_bytes)
    sha256: str = Field(pattern=SHA)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(ge=1, le=1)
    snapshot_key: str = Field(pattern=KEY)
    policy_digest: str = Field(pattern=SHA)
    acquired_at: int = Field(ge=0)
    provenance_kind: str = Field(pattern=r"^(local_cli|ci_checkout)$")
    label: str = Field(pattern=r"^[A-Za-z0-9 _.-]{1,100}$")
    declared_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    files: list[FileEntry] = Field(max_length=DEFAULT_LIMITS.files)
    directories: list[str] = Field(max_length=DEFAULT_LIMITS.directories)
    exclusions: dict[str, int]
    content_digest: str = Field(pattern=SHA)


@dataclass(frozen=True)
class VerifiedSnapshot:
    manifest: Manifest
    manifest_digest: str
    files: dict[str, bytes]


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SnapshotError("duplicate_manifest_key")
        value[key] = item
    return value


def _check_ancestors(path: Path) -> None:
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise SnapshotError("unsafe_spool")


class SnapshotStore:
    def __init__(
        self, root: Path, limits: Limits = DEFAULT_LIMITS, *, require_readonly: bool = True
    ):
        self.root = Path(os.path.abspath(root))
        self.limits = limits
        self.require_readonly = require_readonly

    def initialize(self) -> None:
        _check_ancestors(self.root)
        if self.root.exists() and any(self.root.iterdir()):
            marker = self.root / ".platform-spool"
            _check_ancestors(marker)
            if not marker.is_file() or marker.read_bytes() != MARKER:
                raise SnapshotError("unrecognized_spool")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "nt":
            from ai_security_platform.snapshots.windows import protect_directory, require_ntfs

            require_ntfs(self.root)
            protect_directory(self.root)
        elif os.name == "posix":
            if self.root.stat().st_uid != cast(Any, os).getuid():
                raise SnapshotError("spool_owner")
            self.root.chmod(0o700)
        else:
            raise SnapshotError("unsupported_platform")
        marker = self.root / ".platform-spool"
        if not marker.exists():
            with marker.open("xb") as stream:
                stream.write(MARKER)
        for name in ("published", ".staging"):
            directory = self.root / name
            if directory.exists() and (
                directory.is_symlink()
                or getattr(directory.lstat(), "st_file_attributes", 0) & 0x400
                or not directory.is_dir()
            ):
                raise SnapshotError("unsafe_spool")
            directory.mkdir(exist_ok=True, mode=0o700)

    @contextmanager
    def publishing_lock(self) -> Iterator[None]:
        _check_ancestors(self.root)
        _check_ancestors(self.root / ".publish.lock")
        fd = os.open(self.root / ".publish.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.fstat(fd).st_nlink != 1:
                raise SnapshotError("unsafe_spool")
            os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                native_windows = cast(Any, msvcrt)
                native_windows.locking(fd, native_windows.LK_NBLCK, 1)
            else:
                import fcntl

                native = cast(Any, fcntl)
                native.flock(fd, native.LOCK_EX | native.LOCK_NB)
            yield
        except OSError:
            raise SnapshotError("spool_busy_or_unsafe") from None
        finally:
            os.close(fd)

    def usage(self) -> tuple[int, int]:
        size = 0
        objects = 0
        publications = 0
        for base in (self.root / "published", self.root / ".staging"):
            for path, directories, files in os.walk(base, followlinks=False):
                if Path(path) == self.root / "published":
                    publications = len(directories)
                for name in directories + files:
                    info = (Path(path) / name).lstat()
                    if (
                        stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & 0x400
                        or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)
                    ):
                        raise SnapshotError("unsafe_spool")
                    size += info.st_size if stat.S_ISREG(info.st_mode) else 0
                    objects += 1
                    if objects > self.limits.snapshots * (
                        self.limits.files + self.limits.directories + 4
                    ):
                        raise SnapshotError("spool_quota")
        return size, publications

    def create(
        self,
        source: Path,
        *,
        label: str = "local-snapshot",
        provenance: str = "local_cli",
        declared_commit: str | None = None,
    ) -> VerifiedSnapshot:
        if ".." in source.parts:
            raise SnapshotError("unsafe_root")
        self.initialize()
        source = Path(os.path.abspath(source))
        if self.root == source or (
            self.root.is_relative_to(source)
            and not excluded(self.root.relative_to(source).parts[0], True)
        ):
            raise SnapshotError("spool_inside_source")
        key = uuid4().hex
        stage = self.root / ".staging" / key
        with self.publishing_lock():
            usage, count = self.usage()
            if count >= self.limits.snapshots:
                raise SnapshotError("spool_quota")
            try:
                with PinnedTree(source, self.limits) as tree:
                    captured = tree.read()
                    entries = [
                        FileEntry(path=p, size=len(b), sha256=digest(b))
                        for p, b in sorted(captured.items())
                    ]
                    directories = sorted(
                        p.relative_to(source).as_posix()
                        for p, _, _ in tree.directories
                        if p != source
                    )
                    content = digest(
                        canonical(
                            {
                                "files": [e.model_dump() for e in entries],
                                "directories": directories,
                            }
                        )
                    )
                    manifest = Manifest(
                        version=1,
                        snapshot_key=key,
                        policy_digest=POLICY_DIGEST,
                        acquired_at=int(time.time()),
                        provenance_kind=provenance,
                        label=label,
                        declared_commit=declared_commit,
                        files=entries,
                        directories=directories,
                        exclusions=tree.exclusions,
                        content_digest=content,
                    )
                    raw = canonical(manifest.model_dump())
                    if (
                        len(raw) > self.limits.manifest_bytes
                        or usage + sum(map(len, captured.values())) + len(raw)
                        > self.limits.spool_bytes
                    ):
                        raise SnapshotError("spool_quota")
                    stage.mkdir(mode=0o700)
                    (stage / "files").mkdir()
                    for directory in directories:
                        (stage / "files" / directory).mkdir(parents=True, exist_ok=True)
                    for relative, value in captured.items():
                        target = stage / "files" / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open("xb") as stream:
                            stream.write(value)
                            stream.flush()
                            os.fsync(stream.fileno())
                        target.chmod(0o444)
                    with (stage / "manifest.json").open("xb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    (stage / "manifest.json").chmod(0o444)
                    tree.assert_unchanged(captured)
                    destination = self.root / "published" / key
                    if destination.exists():
                        raise SnapshotError("snapshot_exists")
                    os.rename(stage, destination)
                return VerifiedSnapshot(manifest, digest(raw), captured)
            except (OSError, ValidationError):
                raise SnapshotError("acquisition_failed") from None
            finally:
                if stage.exists():
                    self._remove_stage(stage)

    def _remove_stage(self, path: Path) -> None:
        if path.parent != self.root / ".staging" or not re.fullmatch(KEY, path.name):
            raise SnapshotError("unsafe_cleanup")
        from ai_security_platform.snapshots.removal import remove_owned_tree

        remove_owned_tree(self.root / ".staging", path.name)

    def cleanup_staging(self, older_than_seconds: int = 3600) -> int:
        if older_than_seconds < 3600:
            raise SnapshotError("unsafe_retention")
        self.initialize()
        removed = 0
        with self.publishing_lock():
            for path in (self.root / ".staging").iterdir():
                if time.time() - path.lstat().st_mtime >= older_than_seconds:
                    self._remove_stage(path)
                    removed += 1
        return removed

    def verify(self, key: str, expected_digest: str) -> VerifiedSnapshot:
        if not re.fullmatch(KEY, key) or not re.fullmatch(SHA, expected_digest):
            raise SnapshotError("invalid_identity")
        if self.require_readonly and (
            os.name != "posix"
            or not cast(Any, os).statvfs(self.root).f_flag & cast(Any, os).ST_RDONLY
        ):
            raise SnapshotError("readonly_spool_required")
        _check_ancestors(self.root)
        _check_ancestors(self.root / ".platform-spool")
        if (self.root / ".platform-spool").read_bytes() != MARKER:
            raise SnapshotError("unrecognized_spool")
        outer = replace(
            self.limits,
            files=self.limits.files + 1,
            directories=self.limits.directories + 1,
            file_bytes=max(self.limits.file_bytes, self.limits.manifest_bytes),
            total_bytes=self.limits.total_bytes + self.limits.manifest_bytes,
            path_bytes=self.limits.path_bytes + 6,
            depth=self.limits.depth + 1,
        )
        try:
            with PinnedTree(self.root / "published" / key, outer, apply_policy=False) as tree:
                data = tree.read()
                raw = data.pop("manifest.json")
                if len(raw) > self.limits.manifest_bytes or digest(raw) != expected_digest:
                    raise SnapshotError("manifest_mismatch")
                parsed = json.loads(raw, object_pairs_hook=_unique)
                manifest = Manifest.model_validate(parsed)
                if (
                    canonical(manifest.model_dump()) != raw
                    or manifest.snapshot_key != key
                    or manifest.policy_digest != POLICY_DIGEST
                    or set(manifest.exclusions) != {"files", "directories"}
                    or any(v < 0 for v in manifest.exclusions.values())
                ):
                    raise SnapshotError("manifest_mismatch")
                files = {}
                for relative, value in data.items():
                    if not relative.startswith("files/"):
                        raise SnapshotError("unexpected_entry")
                    path = validate_path(relative[6:], self.limits)
                    parts = path.split("/")
                    if any(excluded(p, True) for p in parts[:-1]) or excluded(parts[-1], False):
                        raise SnapshotError("policy_mismatch")
                    files[path] = value
                entries = [
                    FileEntry(path=p, size=len(b), sha256=digest(b))
                    for p, b in sorted(files.items())
                ]
                directories = sorted(
                    p.relative_to(self.root / "published" / key / "files").as_posix()
                    for p, _, _ in tree.directories
                    if p != self.root / "published" / key
                    and p != self.root / "published" / key / "files"
                )
                if (
                    entries != manifest.files
                    or directories != manifest.directories
                    or sum(map(len, files.values())) > self.limits.total_bytes
                    or manifest.content_digest
                    != digest(
                        canonical(
                            {
                                "files": [e.model_dump() for e in entries],
                                "directories": directories,
                            }
                        )
                    )
                ):
                    raise SnapshotError("content_mismatch")
                # Check all directory listings and content again before trusting the byte copy.
                original = {"manifest.json": raw} | {"files/" + p: b for p, b in files.items()}
                tree.assert_unchanged(original)
                return VerifiedSnapshot(manifest, expected_digest, files)
        except (OSError, KeyError, TypeError, ValueError):
            raise SnapshotError("snapshot_unavailable_or_invalid") from None
