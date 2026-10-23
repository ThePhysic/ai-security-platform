"""Bounded no-follow deletion for verified platform-owned trees only.

Callers establish ownership, eligibility and exclusive maintenance/publisher locks.
Validate the entire tree before deleting any entry. Never use a recursive shell.
"""

import os
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from ai_security_platform.snapshots.filesystem import safe_kind
from ai_security_platform.snapshots.policy import DEFAULT_LIMITS, SnapshotError, validate_path
from ai_security_platform.snapshots.store import _check_ancestors


def remove_owned_tree(parent: Path, name: str) -> None:
    """Remove one direct child; never accept traversal or infer platform ownership."""
    if len(name) != 32 or any(c not in "0123456789abcdef" for c in name):
        raise SnapshotError("unsafe_cleanup")
    parent = Path(os.path.abspath(parent))
    _check_ancestors(parent)
    if os.name == "nt":
        _windows(parent, name)
    elif os.name == "posix":
        _posix(parent, name)
    else:
        raise SnapshotError("unsupported_platform")


def _posix(parent: Path, name: str) -> None:
    native = cast(Any, os)
    with ExitStack() as stack:
        descriptor = os.open(parent.anchor, os.O_RDONLY | native.O_DIRECTORY | native.O_NOFOLLOW)
        stack.callback(os.close, descriptor)
        for component in parent.parts[1:]:
            descriptor = os.open(
                component, os.O_RDONLY | native.O_DIRECTORY | native.O_NOFOLLOW, dir_fd=descriptor
            )
            stack.callback(os.close, descriptor)
        entries: list[tuple[int, str, int, os.stat_result, bool]] = []

        def collect(base: int, component: str, relative: str) -> None:
            validate_path(relative, replace(DEFAULT_LIMITS, path_bytes=280, depth=18))
            before = os.stat(component, dir_fd=base, follow_symlinks=False)
            import stat

            directory = stat.S_ISDIR(before.st_mode)
            safe_kind(before, directory)
            flags = os.O_RDONLY | native.O_NOFOLLOW
            flags |= native.O_DIRECTORY if directory else native.O_NONBLOCK
            fd = os.open(component, flags, dir_fd=base)
            stack.callback(os.close, fd)
            opened = os.fstat(fd)
            safe_kind(opened, directory)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise SnapshotError("unsafe_cleanup")
            entries.append((base, component, fd, opened, directory))
            if len(entries) > DEFAULT_LIMITS.files + DEFAULT_LIMITS.directories + 4:
                raise SnapshotError("cleanup_budget")
            if directory:
                with os.scandir(fd) as children:
                    names = [entry.name for entry in children]
                if len(names) > DEFAULT_LIMITS.entries:
                    raise SnapshotError("cleanup_budget")
                for child in sorted(names):
                    collect(fd, child, relative + "/" + child)

        collect(descriptor, name, name)
        for base, component, _, opened, directory in reversed(entries):
            current = os.stat(component, dir_fd=base, follow_symlinks=False)
            safe_kind(current, directory)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise SnapshotError("unsafe_cleanup")
            if directory:
                os.rmdir(component, dir_fd=base)
            else:
                os.unlink(component, dir_fd=base)


def _windows(parent: Path, name: str) -> None:
    import ctypes
    import stat
    from ctypes import wintypes as w

    from ai_security_platform.snapshots.windows import (
        close,
        libraries,
        open_locked,
        reject_streams,
        require_ntfs,
    )

    kernel, _ = libraries()
    require_ntfs(parent)
    kernel.CreateFileW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        w.DWORD,
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        w.HANDLE,
    ]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.SetFileInformationByHandle.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]

    class Basic(ctypes.Structure):
        _fields_ = [
            ("created", ctypes.c_longlong),
            ("accessed", ctypes.c_longlong),
            ("written", ctypes.c_longlong),
            ("changed", ctypes.c_longlong),
            ("attributes", w.DWORD),
        ]

    with ExitStack() as stack:
        ancestor = Path(parent.anchor)
        stack.callback(close, open_locked(ancestor, True))
        for component in parent.parts[1:]:
            ancestor /= component
            stack.callback(close, open_locked(ancestor, True))
        entries: list[tuple[Path, int, os.stat_result, bool]] = []
        closed: set[int] = set()

        def close_once(handle: int) -> None:
            if handle not in closed:
                close(handle)
                closed.add(handle)

        def collect(path: Path, relative: str) -> None:
            validate_path(relative, replace(DEFAULT_LIMITS, path_bytes=280, depth=18))
            before = path.lstat()
            directory = stat.S_ISDIR(before.st_mode)
            safe_kind(before, directory)
            # DELETE + read attributes + write attributes. Share reads only, pinning
            # identity and denying competing writes/deletion until our handle closes.
            access = 0x10000 | 0x80 | 0x100
            handle = kernel.CreateFileW(
                str(path), access, 1, None, 3, 0x00200000 | (0x02000000 if directory else 0), None
            )
            if handle == ctypes.c_void_p(-1).value:
                raise SnapshotError("cleanup_busy_or_unsafe")
            handle = int(handle)
            stack.callback(close_once, handle)
            reject_streams(path)
            current = path.lstat()
            safe_kind(current, directory)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise SnapshotError("unsafe_cleanup")
            entries.append((path, handle, current, directory))
            if len(entries) > DEFAULT_LIMITS.files + DEFAULT_LIMITS.directories + 4:
                raise SnapshotError("cleanup_budget")
            if directory:
                with os.scandir(path) as children:
                    names = [entry.name for entry in children]
                if len(names) > DEFAULT_LIMITS.entries:
                    raise SnapshotError("cleanup_budget")
                for child in sorted(names):
                    collect(path / child, relative + "/" + child)

        collect(parent / name, name)
        # Close each deleted child before deleting its now-empty parent. Ancestor
        # handles remain pinned until the outer context exits, including on failure.
        for path, handle, opened, directory in reversed(entries):
            current = path.lstat()
            safe_kind(current, directory)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise SnapshotError("unsafe_cleanup")
            attributes = getattr(current, "st_file_attributes", 0) & ~1
            basic = Basic(0, 0, 0, 0, attributes or 0x80)
            disposition = w.BOOL(True)
            if not kernel.SetFileInformationByHandle(
                handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)
            ):
                raise SnapshotError("cleanup_attributes_failed")
            if not kernel.SetFileInformationByHandle(
                handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)
            ):
                raise SnapshotError("cleanup_delete_failed")
            close_once(handle)
