"""Maintained capability probes, never loaded from a target snapshot."""

import errno
import json
import os
import socket
import sys
import time
from contextlib import suppress
from pathlib import Path


def basic():
    checks = {}
    checks["nonroot"] = os.getuid() == 10001 and os.getgid() == 10001
    status = Path("/proc/self/status").read_text()
    checks["capabilities_dropped"] = "CapEff:\t0000000000000000" in status
    checks["no_new_privileges"] = "NoNewPrivs:\t1" in status
    for label, target in (
        ("source_readonly", "/source/denied-write"),
        ("root_readonly", "/denied-write"),
    ):
        try:
            Path(target).write_bytes(b"trusted-probe")
        except OSError as error:
            checks[label] = error.errno in {errno.EROFS, errno.EACCES}
        else:
            checks[label] = False
    checks["source_readable"] = Path("/source/fixture.txt").read_bytes() == b"controlled-data\n"
    checks["no_daemon_socket"] = not any(
        Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock")
    )
    checks["no_credentials"] = not any(
        name.startswith(("ASP_", "AWS_", "AZURE_", "GITHUB_", "OPENAI_", "DOCKER_"))
        for name in os.environ
    )
    accessible = False
    for path in ("/root/.aws", "/root/.docker", "/app/.env", "/credentials"):
        with suppress(PermissionError):  # denied traversal is inaccessible
            accessible |= Path(path).exists()
    checks["no_host_credentials"] = not accessible
    denied = 0
    for address in ("1.1.1.1", "8.8.8.8", "192.168.65.254"):
        try:
            with socket.create_connection((address, 443), timeout=0.3):
                pass
        except OSError:
            denied += 1
    checks["egress_denied"] = denied == 3
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError:
        checks["external_dns_denied"] = True
    else:
        checks["external_dns_denied"] = False
    checks["only_loopback_interface"] = set(os.listdir("/sys/class/net")) == {"lo"}
    checks["memory_bound"] = Path("/sys/fs/cgroup/memory.max").read_text().strip() == "134217728"
    checks["pid_bound"] = Path("/sys/fs/cgroup/pids.max").read_text().strip() == "32"
    checks["cpu_bound"] = Path("/sys/fs/cgroup/cpu.max").read_text().strip() == "50000 100000"
    print(json.dumps(checks), flush=True)
    raise SystemExit(0 if all(checks.values()) else 2)


mode = sys.argv[1]
if mode == "basic":
    basic()
elif mode == "memory":
    chunks = []
    while True:
        chunks.append(bytearray(16 * 1024 * 1024))
elif mode == "pids":
    children = []
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                time.sleep(20)
                os._exit(0)
            children.append(pid)
    except OSError as error:
        print(json.dumps({"process_limit_denied": error.errno == errno.EAGAIN}), flush=True)
    finally:
        for child in children:
            os.kill(child, 9)
        for child in children:
            os.waitpid(child, 0)
elif mode == "tmp":
    try:
        with Path("/tmp/budget").open("wb") as stream:
            for _ in range(40):
                stream.write(b"x" * 1024 * 1024)
    except OSError as error:
        print(json.dumps({"temporary_storage_denied": error.errno == errno.ENOSPC}), flush=True)
elif mode == "output":
    while True:
        os.write(1, b"x" * 8192)
elif mode in {"timeout", "orphan"}:
    time.sleep(120)
else:
    raise SystemExit(2)
