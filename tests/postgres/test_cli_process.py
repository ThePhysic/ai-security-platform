"""Independent CLI interruption tests in the Linux integration-test environment."""

import json
import os
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

pytestmark = [pytest.mark.postgres, pytest.mark.reliability]


def test_actual_cli_timeout_and_interrupt_leave_server_scan_untouched(pg_runtime):
    observed = threading.Event()
    methods = []

    class Status(BaseHTTPRequestHandler):
        def do_GET(self):
            methods.append("GET")
            observed.set()
            body = b'{"status":"queued"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Status)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = [
        sys.executable,
        "-m",
        "ai_security_platform.cli",
        "--api",
        f"http://127.0.0.1:{server.server_port}",
        "scan-wait",
        str(uuid4()),
        "--poll",
        "0.1",
    ]
    environment = dict(os.environ, ASP_API_TOKEN="synthetic-test-local-cli-token")
    child = None
    try:
        timeout = subprocess.run(
            [*command, "--timeout", "0.2"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert timeout.returncode == 2
        assert json.loads(timeout.stdout) == {"error": "local_operation_rejected"}
        observed.clear()
        child = subprocess.Popen(
            [*command, "--timeout", "30"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert observed.wait(timeout=10)
        child.send_signal(signal.SIGINT)
        output, errors = child.communicate(timeout=5)
        assert child.returncode == 2
        assert json.loads(output) == {"error": "cancelled", "scan_continues": True}
        assert "synthetic-test-local-cli-token" not in output + errors
        assert methods and set(methods) == {"GET"}  # no job cancellation or mutation request
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
