"""Pin ancestors and children; reject links and detect source mutation."""

import os
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Any, cast

from ai_security_platform.snapshots.policy import (
    DEFAULT_LIMITS,
    Limits,
    SnapshotError,
    excluded,
    validate_path,
)


def signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def safe_kind(value: os.stat_result, directory: bool) -> None:
    if (
        stat.S_ISLNK(value.st_mode)
        or getattr(value, "st_file_attributes", 0) & 0x400
        or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
        or (not directory and value.st_nlink != 1)
    ):
        raise SnapshotError("unsafe_file_type")


class PinnedTree:
    def __init__(self, root: Path, limits: Limits = DEFAULT_LIMITS, *, apply_policy: bool = True):
        if ".." in root.parts:
            raise SnapshotError("unsafe_root")
        self.root = Path(os.path.abspath(root))
        self.limits = limits
        self.apply_policy = apply_policy
        self.stack = ExitStack()
        self.directories: list[tuple[Path, int, tuple[str, ...]]] = []
        self.files: list[tuple[str, int, os.stat_result]] = []
        self.exclusions = {"files": 0, "directories": 0}
        self.entry_count = 0

    def __enter__(self) -> "PinnedTree":
        try:
            if ".." in self.root.parts:
                raise SnapshotError("unsafe_root")
            root_fd = self._root()
            self._walk(self.root, root_fd, "")
            return self
        except Exception:
            self.stack.close()
            raise

    def __exit__(self, *args: object) -> None:
        self.stack.close()

    def _open(self, path: Path, directory: bool, parent: int | None = None) -> int:
        if os.name == "nt":
            from ai_security_platform.snapshots import windows

            handle = windows.open_locked(path, directory)
            if directory:
                self.stack.callback(windows.close, handle)
                return handle
            fd = windows.file_descriptor(handle)
        elif os.name == "posix":
            native = cast(Any, os)
            flags = (
                os.O_RDONLY
                | native.O_NOFOLLOW
                | (native.O_DIRECTORY if directory else native.O_NONBLOCK)
            )
            fd = os.open(path.name if parent is not None else path, flags, dir_fd=parent)
        else:
            raise SnapshotError("unsupported_platform")
        self.stack.callback(os.close, fd)
        safe_kind(os.fstat(fd), directory)
        return fd

    def _root(self) -> int:
        if os.name == "nt":
            from ai_security_platform.snapshots import windows

            windows.require_ntfs(self.root)
        current = Path(self.root.anchor)
        parent: int | None = self._open(current, True)
        for part in self.root.parts[1:]:
            if part in {".", ".."}:
                raise SnapshotError("unsafe_root")
            current /= part
            parent = self._open(current, True, parent)
        assert parent is not None
        return parent

    def _names(self, path: Path, fd: int) -> tuple[str, ...]:
        names: list[str] = []
        with os.scandir(path if os.name == "nt" else fd) as entries:
            for entry in entries:
                if len(names) >= self.limits.entries:
                    raise SnapshotError("entry_budget")
                names.append(entry.name)
        return tuple(sorted(names))

    def _walk(self, path: Path, fd: int, prefix: str) -> None:
        if len(self.directories) >= self.limits.directories:
            raise SnapshotError("directory_budget")
        names = self._names(path, fd)
        self.entry_count += len(names)
        if self.entry_count > self.limits.entries:
            raise SnapshotError("entry_budget")
        self.directories.append((path, fd, names))
        collision: set[str] = set()
        for name in names:
            relative = prefix + name
            validate_path(relative, self.limits)
            folded = name.casefold()
            if folded in collision:
                raise SnapshotError("name_collision")
            collision.add(folded)
            before = (
                os.stat(name, dir_fd=fd, follow_symlinks=False)
                if os.name == "posix"
                else (os.lstat(path / name))
            )
            directory = stat.S_ISDIR(before.st_mode)
            safe_kind(before, directory)
            if self.apply_policy and excluded(name, directory):
                self.exclusions["directories" if directory else "files"] += 1
                continue
            child_fd = self._open(path / name, directory, fd)
            opened = os.lstat(path / name) if directory and os.name == "nt" else os.fstat(child_fd)
            # Windows lstat/fstat expose different historical ctime semantics.
            fields = 4 if os.name == "nt" and not directory else 5
            if signature(before)[:fields] != signature(opened)[:fields]:
                raise SnapshotError("source_mutated")
            if directory:
                self._walk(path / name, child_fd, relative + "/")
            else:
                if len(self.files) >= self.limits.files or before.st_size > self.limits.file_bytes:
                    raise SnapshotError("file_budget")
                self.files.append((relative, child_fd, opened))

    def read(self) -> dict[str, bytes]:
        result = {}
        total = 0
        for path, fd, before in self.files:
            os.lseek(fd, 0, os.SEEK_SET)
            parts = []
            size = 0
            while True:
                chunk = os.read(fd, min(65536, self.limits.file_bytes + 1 - size))
                if not chunk:
                    break
                parts.append(chunk)
                size += len(chunk)
                if size > self.limits.file_bytes:
                    raise SnapshotError("file_budget")
            total += size
            if total > self.limits.total_bytes:
                raise SnapshotError("total_budget")
            if signature(os.fstat(fd)) != signature(before) or size != before.st_size:
                raise SnapshotError("source_mutated")
            result[path] = b"".join(parts)
        return result

    def assert_unchanged(self, captured: dict[str, bytes]) -> None:
        for path, fd, names in self.directories:
            if names != self._names(path, fd):
                raise SnapshotError("source_mutated")
        if self.read() != captured:
            raise SnapshotError("source_mutated")
