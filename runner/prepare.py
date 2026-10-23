"""Explicit network-enabled preparation. Never mount target source or credentials."""

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from uuid import uuid4

from runner.boundary import ROOT, DockerBoundary
from runner.validate_isolation import boundary_digest

UPSTREAM = {
    "semgrep": (
        "semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b"
    ),
    "trivy": (
        "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
    ),
}


def sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reuse-database", action="store_true")
    args = parser.parse_args()
    proof = json.loads((ROOT / "docs/phase2b/isolation-evidence.json").read_text())
    assert proof["boundary_sha256"] == boundary_digest() and all(proof["checks"].values())
    boundary = DockerBoundary(ROOT / ".local/snapshot-spool")
    assert boundary.ready() == proof["engine"]
    # The copied wrapper is trusted platform code; never use a target file.
    shutil.copyfile(
        ROOT / "runner/images/semgrep/wrapper.py", ROOT / "runner/images/trivy/wrapper.py"
    )
    registry = {"version": 1, "upstream": UPSTREAM, "scanners": {}}
    for name in ("semgrep", "trivy"):
        tag = "asp-phase2b/" + name + ":prepared"
        boundary.command("build", "--tag", tag, str(ROOT / "runner/images" / name), timeout=600)
        image = boundary.command("image", "inspect", "--format", "{{.Id}}", tag)
        executable = "/usr/bin/semgrep" if name == "semgrep" else "/usr/local/bin/trivy"
        version = boundary.command(
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "--env",
            "HOME=/tmp",
            "--env",
            "SEMGREP_ENABLE_VERSION_CHECK=0",
            "--entrypoint",
            executable,
            image,
            "--version",
            timeout=30,
        )
        checksum_program = (
            "import hashlib,json,pathlib,importlib.util;"
            "p=pathlib.Path(" + repr(executable) + ");"
            "result={'executable_sha256':hashlib.sha256(p.read_bytes()).hexdigest()};"
        )
        if name == "semgrep":
            checksum_program += (
                "root=pathlib.Path(importlib.util.find_spec('semgrep').origin).parent;"
                "core=root/'bin'/'semgrep-core';"
                "result['engine_sha256']=hashlib.sha256(core.read_bytes()).hexdigest();"
            )
        else:
            checksum_program += "result['engine_sha256']=result['executable_sha256'];"
        checksum_program += "print(json.dumps(result))"
        checksums = json.loads(
            boundary.command(
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "10001:10001",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "/usr/bin/python3" if name == "semgrep" else "/usr/local/bin/python",
                image,
                "-c",
                checksum_program,
                timeout=30,
            )
        )
        files = sorted(p for p in (ROOT / "runner/images" / name).iterdir() if p.is_file())
        policy = {p.name: sha(p) for p in files}
        registry["scanners"][name] = {
            "image": image,
            "executable": executable,
            "version": version,
            "policy_files": policy,
            "policy_digest": hashlib.sha256(
                json.dumps(policy, sort_keys=True).encode()
            ).hexdigest(),
            "adapter_version": "real-1",
            **checksums,
        }
        print("Prepared pinned " + name + " image and policy.", flush=True)
    if args.reuse_database:
        original = json.loads((ROOT / "policies/scanners.lock.json").read_text())["database"]
        directory = ROOT / ".local/scanner-assets" / original["asset_key"] / "db"
        assert all(
            sha(directory / name) == expected for name, expected in original["files"].items()
        )
        registry["database"] = original
        (ROOT / "policies/scanners.lock.json").write_text(json.dumps(registry, indent=2) + "\n")
        print("Reused verified offline database; no download.", flush=True)
        return
    # A separate network-enabled downloader container, with no source or writable
    # host bind. Only its generated public DB directory is exported after success.
    name = "asp-p2b-db-prepare-" + uuid4().hex
    try:
        boundary.command(
            "run",
            "--name",
            name,
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "2048m",
            "--pids-limit",
            "64",
            "--entrypoint",
            "/usr/local/bin/trivy",
            registry["scanners"]["trivy"]["image"],
            "image",
            "--download-db-only",
            "--cache-dir",
            "/tmp/cache",
            "--db-repository",
            "ghcr.io/aquasecurity/trivy-db:2",
            "--skip-version-check",
            timeout=600,
        )
        directory = ROOT / ".local/scanner-assets" / uuid4().hex
        directory.mkdir(parents=True)
        if sys.platform == "win32":
            from ai_security_platform.snapshots.windows import protect_directory

            protect_directory(directory.parent)
            protect_directory(directory)
        boundary.command("cp", name + ":/tmp/cache/db", str(directory), timeout=60)
        database = directory / "db"
        hashes = {p.name: sha(p) for p in sorted(database.iterdir()) if p.is_file()}
        assert set(hashes) == {"metadata.json", "trivy.db"}
        metadata = json.loads((database / "metadata.json").read_text())
        registry["database"] = {
            "asset_key": directory.name,
            "files": hashes,
            "metadata": metadata,
            "repository": "ghcr.io/aquasecurity/trivy-db:2",
            "digest": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
        }
    finally:
        # Only this uniquely named preparation container, never broad cleanup.
        boundary.command("rm", "--force", name)
    target = ROOT / "policies"
    target.mkdir(exist_ok=True)
    (target / "scanners.lock.json").write_text(json.dumps(registry, indent=2) + "\n")
    print("Prepared versioned offline database; no source was mounted.", flush=True)


if __name__ == "__main__":
    main()
