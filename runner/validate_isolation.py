"""Mandatory Windows/Docker Desktop proofs using only maintained controlled probes."""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from uuid import uuid4

from pydantic import ValidationError

from ai_security_platform.snapshots.store import SnapshotStore
from runner.boundary import ROOT, BoundaryError, DockerBoundary, Invocation, Profile


def boundary_digest() -> str:
    return hashlib.sha256((ROOT / "runner/boundary.py").read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--orphan-child", action="store_true")
    parser.add_argument("--phase3", action="store_true")
    parser.add_argument("--phase4", action="store_true")
    parser.add_argument("--phase5", action="store_true")
    parser.add_argument("--phase6", action="store_true")
    parser.add_argument("--phase7", action="store_true")
    parser.add_argument("--phase8", action="store_true")
    parser.add_argument("--image")
    parser.add_argument("--key")
    parser.add_argument("--digest")
    args = parser.parse_args()
    spool = ROOT / (
        ".local/phase8-probes/spool"
        if args.phase8
        else ".local/phase7-probes/spool"
        if args.phase7
        else ".local/phase6-probes/spool"
        if args.phase6
        else ".local/phase5-probes/spool"
        if args.phase5
        else ".local/phase2b-probes/spool"
    )
    boundary = DockerBoundary(spool)
    if args.orphan_child:
        profile = Profile(
            args.image,
            "/usr/local/bin/python",
            ("/opt/probe.py", "orphan"),
            memory="128m",
            cpus="0.5",
            pids=32,
        )
        identifier = boundary.create(profile, args.key, args.digest, uuid4())
        boundary.command("start", identifier)
        print(json.dumps({"container_id": identifier}), flush=True)
        time.sleep(120)
        return
    engine = boundary.ready()
    boundary.cleanup_orphans()
    image = boundary.command(
        "image", "inspect", "--format", "{{.Id}}", "asp-phase2b/probe:controlled"
    )
    source = ROOT / ".cache" / ("phase2b-probe-" + uuid4().hex)
    source.mkdir(parents=True)
    source.joinpath("fixture.txt").write_bytes(b"controlled-data\n")
    snap = SnapshotStore(spool, require_readonly=False).create(source, label="controlled-probe")
    key, digest = snap.manifest.snapshot_key, snap.manifest_digest
    checks = {}
    basic = boundary.probe(image, "basic", key, digest)
    checks.update(json.loads(basic.stdout))
    assert basic.exit_code == 0 and basic.error_code is None, checks
    for mode in ("pids", "tmp"):
        result = boundary.probe(image, mode, key, digest)
        checks.update(json.loads(result.stdout))
        assert result.exit_code == 0, mode
    memory = boundary.probe(image, "memory", key, digest)
    checks["memory_oom_enforced"] = memory.oom_killed and memory.exit_code == 137
    output = boundary.probe(image, "output", key, digest)
    checks["output_bounded_and_terminated"] = (
        output.error_code == "output_limit" and len(output.stdout) <= 65536
    )
    timeout = boundary.probe(image, "timeout", key, digest)
    checks["deadline_terminated"] = timeout.error_code == "execution_timeout"
    payload = {
        "id": str(uuid4()),
        "job_id": str(uuid4()),
        "generation": 1,
        "lease_token": str(uuid4()),
        "snapshot_key": key,
        "manifest_digest": digest,
        "profile": "semgrep-v1",
        "registry_digest": "a" * 64,
    }
    for field, value in (
        ("mount", "C:\\Users"),
        ("arguments", ["--privileged"]),
        ("command", "cmd /c whoami"),
        ("image", "untrusted:latest"),
        ("profile", "semgrep-v1; whoami"),
        ("snapshot_key", "../../escape"),
    ):
        try:
            Invocation.model_validate(payload | {field: value})
        except ValidationError:
            checks["reject_" + field] = True
        else:
            checks["reject_" + field] = False
    try:
        boundary.image_identity("python:latest")
    except BoundaryError:
        checks["mutable_image_denied"] = True
    # Lease uncertainty must kill the execution, not merely discard its output later.
    profile = Profile(
        image,
        "/usr/local/bin/python",
        ("/opt/probe.py", "timeout"),
        memory="128m",
        cpus="0.5",
        pids=32,
        seconds=15,
    )
    identifier = boundary.create(profile, key, digest, uuid4())
    revoked = boundary.capture(identifier, profile, ownership=lambda: False)
    checks["ownership_loss_terminates_container"] = revoked.error_code == "lease_lost"
    # Kill the host launcher process while its container remains running.
    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "runner.validate_isolation",
            *(
                ["--phase8"]
                if args.phase8
                else ["--phase7"]
                if args.phase7
                else ["--phase6"]
                if args.phase6
                else ["--phase5"]
                if args.phase5
                else []
            ),
            "--orphan-child",
            "--image",
            image,
            "--key",
            key,
            "--digest",
            digest,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        record = json.loads(child.stdout.readline())
        identifier = record["container_id"]
        assert boundary.inspect(identifier)["State"]["Running"]
        child.terminate()
        child.wait(timeout=5)
        checks["launcher_kill_leaves_observable_orphan"] = boundary.inspect(identifier)["State"][
            "Running"
        ]
        checks["restart_orphan_cleanup"] = boundary.cleanup_orphans() == 1
        checks["no_scanner_orphans_remain"] = boundary.cleanup_orphans() == 0
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        boundary.cleanup_orphans()
    assert all(checks.values()), {key: val for key, val in checks.items() if not val}
    evidence = {
        "gate": "G4-container-boundary",
        "platform": sys.platform,
        "engine": engine,
        "probe_image": image,
        "boundary_sha256": boundary_digest(),
        "checks": checks,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "note": "Container proof only; authenticated lease handoff proof also required.",
    }
    target = ROOT / (
        "docs/phase8"
        if args.phase8
        else "docs/phase7"
        if args.phase7
        else "docs/phase6"
        if args.phase6
        else "docs/phase5"
        if args.phase5
        else "docs/phase4"
        if args.phase4
        else "docs/phase3"
        if args.phase3
        else "docs/phase2b"
    )
    target.mkdir(parents=True, exist_ok=True)
    target.joinpath(
        "isolation-regression.json"
        if args.phase3 or args.phase4 or args.phase5 or args.phase6 or args.phase7 or args.phase8
        else "isolation-evidence.json"
    ).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"isolation_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
