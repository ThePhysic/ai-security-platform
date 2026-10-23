"""Host entry point: only fixed profiles, independent capability and bounded I/O."""

import argparse
import json
import os
import signal
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from dotenv import dotenv_values

from ai_security_platform.scanners.real import normalize
from ai_security_platform.scanners.registry import load_registry, registry_digest
from ai_security_platform.snapshots.policy import canonical, digest
from ai_security_platform.snapshots.store import SnapshotStore, _check_ancestors
from runner.boundary import ROOT, BoundaryError, DockerBoundary, Invocation, Profile
from runner.prepare import sha
from runner.validate_isolation import boundary_digest


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class LauncherClient:
    def __init__(self, base: str, token: str):
        parsed = urlsplit(base)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port is None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise BoundaryError("local_api_required")
        self.base, self.token = base, token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, path, body):
        request = Request(
            self.base + "/internal/v1/launcher" + path,
            data=canonical(body),
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=3) as response:
            content = response.read(65537)
            if len(content) > 65536:
                raise BoundaryError("api_response_limit")
            return json.loads(content)


@contextmanager
def exclusive_launcher():
    directory = ROOT / ".local" / "launcher"
    directory.mkdir(parents=True, exist_ok=True)
    _check_ancestors(directory)
    if os.name == "nt":
        import msvcrt

        from ai_security_platform.snapshots.windows import protect_directory

        protect_directory(directory)
    descriptor = os.open(directory / "host.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


class Launcher:
    def __init__(self, base: str, spool: Path, token: str):
        self.boundary = DockerBoundary(spool)
        self.registry = load_registry(ROOT / "policies/scanners.lock.json")
        self.registry_hash = registry_digest(self.registry)
        self.id = uuid4()
        self.client = LauncherClient(base, token)
        self.stop = Event()
        self.prove_boundary()

    def prove_boundary(self):
        proof = json.loads((ROOT / "docs/phase2b/isolation-evidence.json").read_text())
        if (
            proof["boundary_sha256"] != boundary_digest()
            or proof["engine"] != self.boundary.ready()
            or proof["platform"] != "win32"
            or proof["failed"]
            or proof["skipped"]
            or not all(proof["checks"].values())
        ):
            raise BoundaryError("isolation_proof_unavailable")
        self.gate_hash = digest(canonical(proof))

    def hello(self):
        self.client.call(
            "/hello",
            {
                "launcher_id": str(self.id),
                "registry_digest": self.registry_hash,
                "gate_digest": self.gate_hash,
            },
        )

    def profile(self, invocation: Invocation):
        if invocation.registry_digest != self.registry_hash:
            raise BoundaryError("profile_resolution_unavailable")
        name = invocation.profile.removesuffix("-v1")
        scanner = self.registry["scanners"][name]
        profile = Profile(
            scanner["image"],
            "/usr/bin/python3" if name == "semgrep" else "/usr/local/bin/python",
            ("/opt/platform/wrapper.py", name),
        )
        provenance = {
            "image_digest": scanner["image"],
            "engine_version": scanner["version"],
            "policy_digest": scanner["policy_digest"],
            "adapter_version": "real-1",
            "view_policy": "audit-view-v1",
        }
        database = None
        if name == "trivy":
            record = self.registry["database"]
            database = self.boundary.assets / record["asset_key"] / "db"
            _check_ancestors(database)
            if not database.is_dir():
                raise BoundaryError("database_unavailable")
            for filename, expected in record["files"].items():
                if filename not in {"trivy.db", "metadata.json"}:
                    raise BoundaryError("database_unavailable")
                item = database / filename
                _check_ancestors(item)
                if item.stat().st_nlink != 1 or sha(item) != expected:
                    raise BoundaryError("database_unavailable")
            updated = datetime.fromisoformat(record["metadata"]["UpdatedAt"].replace("Z", "+00:00"))
            age = int((datetime.now(UTC) - updated).total_seconds())
            if age < -60 or age > 172800:
                raise BoundaryError("database_stale")
            provenance.update(
                {
                    "database_digest": record["digest"],
                    "database_updated_at": updated.isoformat(),
                    "database_age_seconds": max(0, age),
                }
            )
        return profile, database, provenance

    def execute(self, invocation: Invocation):
        identity = {
            "launcher_id": str(self.id),
            "generation": invocation.generation,
            "lease_token": str(invocation.lease_token),
        }
        path = "/" + str(invocation.id)

        def ownership():
            if self.stop.is_set():
                return False
            self.hello()
            return self.client.call(path + "/check", identity)["current"]

        if not ownership():
            return
        try:
            source = SnapshotStore(self.boundary.spool, require_readonly=False).verify(
                invocation.snapshot_key, invocation.manifest_digest
            )
            profile, database, provenance = self.profile(invocation)
            identifier = self.boundary.create(
                profile,
                invocation.snapshot_key,
                invocation.manifest_digest,
                invocation.id,
                database=database,
            )
            captured = self.boundary.capture(identifier, profile, ownership)
            if captured.error_code == "lease_lost":
                return
            if captured.error_code:
                result = {"error_code": captured.error_code}
            elif captured.oom_killed:
                result = {"error_code": "execution_failed"}
            else:
                result = normalize(
                    invocation.profile.removesuffix("-v1"),
                    captured.stdout,
                    captured.exit_code,
                    source,
                    provenance,
                ).model_dump()
        except BoundaryError as error:
            code = str(error)
            result = {
                "error_code": code
                if code
                in {
                    "database_unavailable",
                    "database_stale",
                    "output_limit",
                    "execution_timeout",
                }
                else "execution_failed"
            }
        except (ValueError, KeyError, TypeError, AttributeError, OSError):
            result = {"error_code": "invalid_result"}
        # API stages only under the current lease; worker revalidates and publishes.
        self.client.call(path + "/result", identity | {"result": result})

    def run(self):
        with exclusive_launcher():
            self.boundary.cleanup_orphans()
            self.hello()
            self.client.call("/recover", {"launcher_id": str(self.id)})
            print(
                json.dumps({"event": "launcher_ready", "registry_digest": self.registry_hash}),
                flush=True,
            )
            last_error = 0.0
            while not self.stop.is_set():
                try:
                    self.hello()
                    value = self.client.call("/next", {"launcher_id": str(self.id)})["invocation"]
                    if value:
                        self.execute(Invocation.model_validate(value))
                        continue
                except (HTTPError, OSError, BoundaryError, ValueError):
                    # Raw HTTP errors, scanner output and credentials never get printed.
                    if time.monotonic() - last_error >= 5:
                        last_error = time.monotonic()
                        print(
                            json.dumps(
                                {
                                    "event": "launcher_operation_unavailable",
                                    "retryable": True,
                                }
                            ),
                            flush=True,
                        )
                self.stop.wait(0.5)
            self.boundary.cleanup_orphans()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:18081")
    args = parser.parse_args()
    token = os.environ.get("ASP_LAUNCHER_TOKEN") or dotenv_values(ROOT / ".env").get(
        "ASP_LAUNCHER_TOKEN"
    )
    if not token:
        raise SystemExit("Launcher capability configuration unavailable")
    launcher = Launcher(args.api, ROOT / ".local/snapshot-spool", token)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: launcher.stop.set())
    launcher.run()


if __name__ == "__main__":
    main()
