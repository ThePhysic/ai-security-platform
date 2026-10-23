"""Fixed Docker profiles. No shell, arbitrary argv, mount or engine-option interface."""

import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from ai_security_platform.snapshots.store import SnapshotStore

ROOT = Path(__file__).resolve().parents[1]
LABEL = "ai-security-platform.phase2b"
PROBE_MODES = frozenset({"basic", "memory", "pids", "tmp", "output", "timeout", "orphan"})


class BoundaryError(RuntimeError):
    """Safe category only; never attach raw daemon/scanner exceptions."""


class Invocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: UUID
    job_id: UUID
    generation: int = Field(ge=1, le=5)
    lease_token: UUID = Field(repr=False)
    snapshot_key: str = Field(pattern=r"^[0-9a-f]{32}$")
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile: Literal["semgrep-v1", "trivy-v1"]
    registry_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Profile:
    image: str
    entrypoint: str
    arguments: tuple[str, ...]
    memory: str = "1024m"
    cpus: str = "1"
    pids: int = 64
    seconds: float = 90
    stdout_bytes: int = 4 * 1024 * 1024
    stderr_bytes: int = 64 * 1024


@dataclass(frozen=True)
class Captured:
    stdout: bytes
    stderr: bytes
    exit_code: int
    error_code: str | None
    container_id: str
    oom_killed: bool


def docker_binary() -> str:
    executable = shutil.which("docker")
    if executable is None or not Path(executable).is_absolute():
        raise BoundaryError("docker_unavailable")
    if Path(executable).resolve().is_relative_to(ROOT):
        raise BoundaryError("untrusted_docker_executable")
    return executable


def host_environment() -> dict[str, str]:
    # Credentials/configuration are never inherited into containers. This minimal
    # environment is for the trusted host Docker CLI only, not its scanner process.
    names = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME", "PATH")
    return {key: os.environ[key] for key in names if key in os.environ}


class DockerBoundary:
    def __init__(self, spool: Path, assets: Path | None = None):
        self.spool = spool.absolute()
        self.assets = (assets or ROOT / ".local" / "scanner-assets").absolute()
        self.executable = docker_binary()

    def command(self, *arguments: str, timeout: float = 15) -> str:
        try:
            result = subprocess.run(
                [self.executable, "--context", "desktop-linux", *arguments],
                shell=False,
                cwd=ROOT,
                env=host_environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise BoundaryError("docker_unavailable") from None
        if result.returncode:
            raise BoundaryError("docker_operation_failed")
        if len(result.stdout) > 1024 * 1024:
            raise BoundaryError("docker_response_limit")
        return result.stdout.decode("utf-8", errors="strict").strip()

    def ready(self) -> dict[str, str]:
        endpoint = json.loads(
            self.command(
                "context", "inspect", "desktop-linux", "--format", "{{json .Endpoints.docker.Host}}"
            )
        )
        if endpoint != "npipe:////./pipe/dockerDesktopLinuxEngine":
            raise BoundaryError("local_desktop_engine_required")
        operating_system = self.command("info", "--format", "{{.OperatingSystem}}")
        if operating_system != "Docker Desktop":
            raise BoundaryError("local_desktop_engine_required")
        data = json.loads(self.command("version", "--format", "{{json .Server}}"))
        if data["Os"] != "linux":
            raise BoundaryError("linux_engine_required")
        return {"os": data["Os"], "version": data["Version"], "endpoint": endpoint}

    @staticmethod
    def image_identity(value: str) -> str:
        if not re.fullmatch(r"(?:sha256:[0-9a-f]{64}|[a-z0-9./_-]+@sha256:[0-9a-f]{64})", value):
            raise BoundaryError("immutable_image_required")
        return value

    def inspect(self, identifier: str) -> dict:
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise BoundaryError("invalid_container_identity")
        return json.loads(self.command("inspect", identifier))[0]

    def remove(self, identifier: str) -> None:
        data = self.inspect(identifier)
        if data["Config"].get("Labels", {}).get(LABEL) != "scanner":
            raise BoundaryError("unowned_container")
        self.command("rm", "--force", identifier)

    def cleanup_orphans(self) -> int:
        identifiers = self.command(
            "ps", "-aq", "--no-trunc", "--filter", f"label={LABEL}=scanner"
        ).splitlines()
        for identifier in identifiers:
            self.remove(identifier)
        return len(identifiers)

    def create(
        self,
        profile: Profile,
        snapshot_key: str,
        manifest_digest: str,
        attempt: UUID,
        *,
        database: Path | None = None,
    ) -> str:
        # Inputs are identities only. Caller can never supply a source path or mounts.
        SnapshotStore(self.spool, require_readonly=False).verify(snapshot_key, manifest_digest)
        source = self.spool / "published" / snapshot_key / "files"
        if any(c in str(source) for c in ",\r\n"):
            raise BoundaryError("unsupported_spool_path")
        image = self.image_identity(profile.image)
        arguments = [
            "create",
            "--name",
            "asp-p2b-" + attempt.hex,
            "--label",
            f"{LABEL}=scanner",
            "--label",
            "asp.attempt=" + attempt.hex,
            "--pull",
            "never",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--user",
            "10001:10001",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            str(profile.pids),
            "--memory",
            profile.memory,
            "--memory-swap",
            profile.memory,
            "--cpus",
            profile.cpus,
            "--ulimit",
            "nofile=1024:1024",
            "--ulimit",
            "core=0:0",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--tmpfs",
            "/work:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001",
            "--workdir",
            "/work",
            "--env",
            "HOME=/tmp",
            "--env",
            "TMPDIR=/tmp",
            "--env",
            "SEMGREP_SEND_METRICS=off",
            "--env",
            "SEMGREP_ENABLE_VERSION_CHECK=0",
            "--mount",
            f"type=bind,source={source},target=/source,readonly",
        ]
        if database is not None:
            # Resolved only from trusted assets, never from an invocation body.
            if not database.is_relative_to(self.assets) or any(c in str(database) for c in ",\r\n"):
                raise BoundaryError("invalid_database_asset")
            arguments += [
                "--tmpfs",
                "/cache:rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001",
                "--mount",
                f"type=bind,source={database},target=/cache/db,readonly",
            ]
        arguments += ["--entrypoint", profile.entrypoint, image, *profile.arguments]
        identifier = self.command(*arguments)
        if not re.fullmatch(r"[0-9a-f]{64}", identifier):
            raise BoundaryError("invalid_container_identity")
        return identifier

    def capture(
        self,
        identifier: str,
        profile: Profile,
        ownership: Callable[[], bool] = lambda: True,
    ) -> Captured:
        process = subprocess.Popen(
            [self.executable, "--context", "desktop-linux", "start", "--attach", identifier],
            shell=False,
            cwd=ROOT,
            env=host_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()

        def collect(stream, target, limit):
            try:
                while chunk := stream.read(8192):
                    remaining = max(0, limit - len(target))
                    target.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
                        return
            finally:
                stream.close()

        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(
                target=collect, args=(process.stdout, buffers[0], profile.stdout_bytes)
            ),
            threading.Thread(
                target=collect, args=(process.stderr, buffers[1], profile.stderr_bytes)
            ),
        ]
        for reader in readers:
            reader.daemon = True
            reader.start()
        error = None
        started = time.monotonic()
        next_check = started
        try:
            while process.poll() is None:
                now = time.monotonic()
                if overflow.is_set():
                    error = "output_limit"
                    break
                if now - started >= profile.seconds:
                    error = "execution_timeout"
                    break
                if now >= next_check:
                    next_check = now + 0.5
                    try:
                        owned = ownership()
                    except Exception:
                        owned = False
                    if not owned:
                        error = "lease_lost"
                        break
                time.sleep(0.02)
            if error:
                # Force-remove is valid for both created and running containers,
                # unlike kill, which races the asynchronous Docker start request.
                self.remove(identifier)
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for reader in readers:
                    reader.join(timeout=3)
                return Captured(bytes(buffers[0]), bytes(buffers[1]), -1, error, identifier, False)
            process.wait(timeout=10)
            for reader in readers:
                reader.join(timeout=3)
            if any(reader.is_alive() for reader in readers):
                raise BoundaryError("capture_unavailable")
            if overflow.is_set():
                error = "output_limit"
            info = self.inspect(identifier)
            return Captured(
                bytes(buffers[0]),
                bytes(buffers[1]),
                info["State"]["ExitCode"],
                error,
                identifier,
                info["State"].get("OOMKilled", False),
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            try:
                self.remove(identifier)
            except BoundaryError:
                # Verify absence using an exact, project-scoped identity, never
                # silently ignore a failed deletion of a remaining container.
                remaining = self.command(
                    "ps",
                    "-aq",
                    "--no-trunc",
                    "--filter",
                    f"id={identifier}",
                    "--filter",
                    f"label={LABEL}=scanner",
                )
                if remaining:
                    raise

    def probe(self, image: str, mode: str, key: str, digest: str) -> Captured:
        if mode not in PROBE_MODES:
            raise BoundaryError("unknown_probe")
        profile = Profile(
            image,
            "/usr/local/bin/python",
            ("/opt/probe.py", mode),
            memory="128m",
            cpus="0.5",
            pids=32,
            seconds=2 if mode in {"timeout", "output", "orphan"} else 20,
            stdout_bytes=65536,
        )
        identifier = self.create(profile, key, digest, uuid4())
        return self.capture(identifier, profile)
