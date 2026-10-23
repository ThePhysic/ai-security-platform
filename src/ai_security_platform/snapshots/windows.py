"""Native NTFS handles, stream detection and private spool ACLs. No shell."""

import ctypes
import os
from ctypes import wintypes as w
from pathlib import Path
from typing import Any, cast

from ai_security_platform.snapshots.policy import SnapshotError


def libraries() -> tuple[Any, Any]:
    if os.name != "nt":
        raise SnapshotError("windows_required")
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise SnapshotError("windows_required")
    return loader("kernel32", use_last_error=True), loader("advapi32", use_last_error=True)


def close(handle: int) -> None:
    kernel, _ = libraries()
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle(w.HANDLE(handle))


def require_ntfs(path: Path) -> None:
    kernel, _ = libraries()
    if not path.drive or path.drive.startswith("\\"):
        raise SnapshotError("unsupported_filesystem")
    fs = ctypes.create_unicode_buffer(32)
    kernel.GetVolumeInformationW.argtypes = [
        w.LPCWSTR,
        w.LPWSTR,
        w.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        w.LPWSTR,
        w.DWORD,
    ]
    kernel.GetDriveTypeW.argtypes = [w.LPCWSTR]
    root = path.anchor
    if (
        kernel.GetDriveTypeW(root) != 3
        or not kernel.GetVolumeInformationW(root, None, 0, None, None, None, fs, len(fs))
        or fs.value != "NTFS"
    ):
        raise SnapshotError("unsupported_filesystem")


class StreamData(ctypes.Structure):
    _fields_ = [("size", ctypes.c_longlong), ("name", w.WCHAR * 296)]


def reject_streams(path: Path) -> None:
    kernel, _ = libraries()
    kernel.FindFirstStreamW.argtypes = [w.LPCWSTR, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.FindFirstStreamW.restype = w.HANDLE
    kernel.FindNextStreamW.argtypes = [w.HANDLE, ctypes.c_void_p]
    kernel.FindClose.argtypes = [w.HANDLE]
    data = StreamData()
    handle = kernel.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        if cast(Any, ctypes).get_last_error() == 38:  # no streams, e.g. an ordinary directory
            return
        raise SnapshotError("stream_check_failed")
    try:
        while True:
            if data.name != "::$DATA":
                raise SnapshotError("alternate_stream")
            if not kernel.FindNextStreamW(handle, ctypes.byref(data)):
                if cast(Any, ctypes).get_last_error() not in {38, 18}:
                    raise SnapshotError("stream_check_failed")
                break
    finally:
        kernel.FindClose(handle)


def open_locked(path: Path, directory: bool) -> int:
    kernel, _ = libraries()
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
    # Share only reads: an existing writer/deleter or later write/rename cannot overlap.
    access = 0x80 if directory else 0x80000000
    handle = kernel.CreateFileW(
        str(path), access, 1, None, 3, 0x00200000 | (0x02000000 if directory else 0), None
    )
    if handle == ctypes.c_void_p(-1).value:
        raise SnapshotError("source_busy_or_unsafe")
    try:
        reject_streams(path)
        if getattr(os.lstat(path), "st_file_attributes", 0) & 0x400:
            raise SnapshotError("reparse_point")
    except Exception:
        close(handle)
        raise
    return int(handle)


def file_descriptor(handle: int) -> int:
    import msvcrt

    return int(cast(Any, msvcrt).open_osfhandle(handle, os.O_RDONLY | cast(Any, os).O_BINARY))


class SidAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", w.DWORD)]


def protect_directory(path: Path) -> None:
    kernel, security = libraries()
    token = w.HANDLE()
    kernel.GetCurrentProcess.restype = w.HANDLE
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    security.GetTokenInformation.argtypes = [
        w.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    ]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise SnapshotError("spool_acl_failed")
    try:
        length = w.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
            raise SnapshotError("spool_acl_failed")
        sid = ctypes.cast(buffer, ctypes.POINTER(SidAttributes)).contents.sid
        sid_string = w.LPWSTR()
        if not security.ConvertSidToStringSidW(sid, ctypes.byref(sid_string)):
            raise SnapshotError("spool_acl_failed")
        try:
            assert sid_string.value is not None
            sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid_string.value + ")"
        finally:
            kernel.LocalFree(sid_string)
    finally:
        assert token.value is not None
        close(int(token.value))
    descriptor = ctypes.c_void_p()
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        w.LPCWSTR,
        w.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(w.DWORD),
    ]
    security.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.c_void_p]
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise SnapshotError("spool_acl_failed")
    try:
        if not security.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise SnapshotError("spool_acl_failed")
    finally:
        kernel.LocalFree(descriptor)
