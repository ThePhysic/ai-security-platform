"""Mandatory Windows/NTFS proofs; never counted as Linux skips."""

import argparse
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore

ROOT = Path(__file__).resolve().parents[1]


def rejected(action):
    try:
        action()
    except SnapshotError:
        return True
    raise AssertionError("Unsafe source was accepted")


def junction(link, target):
    env = os.environ | {"ASP_TEST_LINK": str(link), "ASP_TEST_TARGET": str(target)}
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "New-Item -ItemType Junction -Path $env:ASP_TEST_LINK "
            "-Target $env:ASP_TEST_TARGET | Out-Null",
        ],
        env=env,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Native junction fixture could not be created")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase2b", action="store_true")
    parser.add_argument("--phase3", action="store_true")
    parser.add_argument("--phase4", action="store_true")
    parser.add_argument("--phase5", action="store_true")
    parser.add_argument("--phase6", action="store_true")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Windows/NTFS validation must execute on Windows")
    base = ROOT / ".cache" / "native-snapshots"
    base.mkdir(parents=True, exist_ok=True)
    checks = {}
    blocked = []
    with TemporaryDirectory(dir=base) as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        file = source / "example.py"
        file.write_bytes(b"ASP_FAKE_FINDING\n")
        store = SnapshotStore(root / "spool", require_readonly=False)
        snap = store.create(source)
        checks["native_publish_and_verify"] = bool(
            store.verify(snap.manifest.snapshot_key, snap.manifest_digest)
        )
        os.link(file, source / "hardlink.py")
        checks["hardlink"] = rejected(lambda: store.create(source))
        (source / "hardlink.py").unlink()
        stream = Path(str(file) + ":hidden")
        stream.write_bytes(b"synthetic-stream")
        checks["alternate_stream"] = rejected(lambda: store.create(source))
        stream.unlink()
        with file.open("r+b"):
            checks["open_writer_denied"] = rejected(lambda: store.create(source))
        outside = root / "outside"
        outside.mkdir()
        outside.joinpath("private.py").write_text("synthetic-do-not-copy")
        linked_directory = source / "junction"
        junction(linked_directory, outside)
        checks["junction_child"] = rejected(lambda: store.create(source))
        checks["junction_root"] = rejected(lambda: store.create(linked_directory))
        os.rmdir(linked_directory)  # remove only the junction; never recurse into target
        symbolic = source / "symlink.py"
        try:
            os.symlink(outside / "private.py", symbolic)
        except OSError as error:
            if error.winerror != 1314:
                raise
            blocked.extend(["file_symlink", "directory_symlink"])
        else:
            checks["file_symlink"] = rejected(lambda: store.create(source))
            symbolic.unlink()
            symbolic_dir = source / "symlink-dir"
            os.symlink(outside, symbolic_dir, target_is_directory=True)
            checks["directory_symlink"] = rejected(lambda: store.create(source))
            os.rmdir(symbolic_dir)
        checks["parent_traversal"] = rejected(lambda: store.create(source / ".." / "source"))
        checks["published_cleanup_protected"] = rejected(
            lambda: store._remove_stage(store.root / "published" / snap.manifest.snapshot_key)
        )
        assert all(checks.values())
    output = (
        ROOT
        / "docs"
        / (
            "phase6"
            if args.phase6
            else "phase5"
            if args.phase5
            else "phase4"
            if args.phase4
            else "phase3"
            if args.phase3
            else "phase2b"
            if args.phase2b
            else "phase2a"
        )
        / "windows-filesystem-evidence.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "platform": "Windows NTFS",
                "checks": checks,
                "passed": len(checks),
                "failed": 0,
                "blocked": blocked,
                "skipped": 0,
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps({"native_checks_passed": len(checks), "blocked": blocked, "skipped": 0}))
    if blocked:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
