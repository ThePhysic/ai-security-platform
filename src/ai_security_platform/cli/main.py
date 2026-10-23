import argparse
import json
import os
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from dotenv import dotenv_values

from ai_security_platform.cli.workflow import all_findings, finish, load_policy, wait
from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def call_api(
    base: str,
    path: str,
    body: dict[str, object] | None = None,
    key: str | None = None,
    *,
    timeout: float = 10,
) -> dict[str, Any]:
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
        raise SnapshotError("local_api_required")
    token = os.environ.get("ASP_API_TOKEN") or dotenv_values(".env").get("ASP_API_TOKEN")
    if not token:
        raise SnapshotError("local_authentication_required")
    headers = {"Authorization": "Bearer " + token}
    if key is not None:
        headers["Idempotency-Key"] = key
    data = None if body is None else json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, headers=headers, data=data)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("api_response_limit")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid_api_response")
        return value


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        print(json.dumps({"error": "invalid_command"}))
        raise SystemExit(2)


def identifier(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid resource identity") from None


def main() -> None:
    parser = Parser(prog="asp", description="Local immutable-snapshot scanning")
    parser.add_argument("--api", default="http://127.0.0.1:18081")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("spool-init")
    init.add_argument("--spool", type=Path, default=Path(".local/snapshot-spool"))
    create = commands.add_parser("snapshot-create")
    create.add_argument("source", type=Path)
    create.add_argument("--spool", type=Path, default=Path(".local/snapshot-spool"))
    create.add_argument("--label", default="local-snapshot")
    clean = commands.add_parser("snapshot-cleanup-staging")
    clean.add_argument("--spool", type=Path, default=Path(".local/snapshot-spool"))
    project = commands.add_parser("project-create")
    project.add_argument("name")
    register = commands.add_parser("snapshot-register")
    register.add_argument("--project", required=True, type=identifier)
    register.add_argument("--key", required=True)
    register.add_argument("--digest", required=True)
    submit = commands.add_parser("scan-submit")
    submit.add_argument("--project", required=True, type=identifier)
    submit.add_argument("--snapshot", required=True, type=identifier)
    submit.add_argument("--idempotency-key", required=True)
    submit.add_argument("--profile", choices=["fake-v1", "security-v1"], default="fake-v1")
    status = commands.add_parser("scan-status")
    status.add_argument("id", type=identifier)
    history = commands.add_parser("scan-history")
    history.add_argument("--project", required=True, type=identifier)
    history.add_argument("--cursor")
    history.add_argument("--limit", type=int, default=50)
    findings = commands.add_parser("findings")
    findings.add_argument("id", type=identifier)
    findings.add_argument("--cursor")
    findings.add_argument("--limit", type=int, default=50)
    findings.add_argument("--all", action="store_true")
    findings.add_argument("--max-pages", type=int, default=20)
    for command in ("scan", "scan-wait", "policy", "export"):
        sub = commands.add_parser(command)
        if command == "scan":
            sub.add_argument("--project", required=True, type=identifier)
            sub.add_argument("--snapshot", required=True, type=identifier)
            sub.add_argument("--idempotency-key", required=True)
            sub.add_argument("--profile", choices=["security-v1", "fake-v1"], default="security-v1")
        else:
            sub.add_argument("id", type=identifier)
        sub.add_argument("--policy", type=Path)
        if command in {"scan", "scan-wait"}:
            sub.add_argument("--timeout", type=float, default=120)
            sub.add_argument("--poll", type=float, default=0.5)
        if command == "export":
            sub.add_argument("--format", choices=["json", "sarif"], default="json")
            sub.add_argument("--name", required=True)
    args = parser.parse_args()
    try:
        exit_code = 0
        if args.command == "spool-init":
            SnapshotStore(args.spool, require_readonly=False).initialize()
            result: dict[str, object] = {"initialized": True}
        elif args.command == "snapshot-create":
            source = SnapshotStore(args.spool, require_readonly=False).create(
                args.source, label=args.label
            )
            result = {
                "snapshot_key": source.manifest.snapshot_key,
                "manifest_digest": source.manifest_digest,
                "files": len(source.files),
                "scanning_requires_profile_admission": True,
            }
        elif args.command == "snapshot-cleanup-staging":
            removed = SnapshotStore(args.spool, require_readonly=False).cleanup_staging()
            result = {"staging_directories_removed": removed, "published_snapshots_removed": 0}
        elif args.command == "project-create":
            result = call_api(args.api, "/api/v1/projects", {"name": args.name})
        elif args.command == "snapshot-register":
            result = call_api(
                args.api,
                "/api/v1/source-snapshots",
                {
                    "project_id": args.project,
                    "snapshot_key": args.key,
                    "manifest_digest": args.digest,
                },
            )
        elif args.command == "scan-submit":
            result = call_api(
                args.api,
                "/api/v1/scan-runs",
                {
                    "project_id": args.project,
                    "snapshot_id": args.snapshot,
                    "profile_id": args.profile,
                },
                args.idempotency_key,
            )
        elif args.command == "scan-status":
            result = call_api(args.api, "/api/v1/scan-runs/" + args.id)
        elif args.command == "scan-history":
            query = {"project": args.project, "limit": str(args.limit)}
            if args.cursor:
                query["cursor"] = args.cursor
            result = call_api(args.api, "/api/v1/scan-runs?" + urlencode(query))
        elif args.command == "findings":
            if args.all:
                if args.cursor:
                    raise ValueError("cursor_all_conflict")
                result = all_findings(call_api, args.api, args.id, args.limit, args.max_pages)
            else:
                query = {"limit": str(args.limit)}
                if args.cursor:
                    query["cursor"] = args.cursor
                result = call_api(
                    args.api, "/api/v1/scan-runs/" + args.id + "/findings?" + urlencode(query)
                )
        else:
            policy = load_policy(args.policy)
            scan_id = (
                args.id
                if args.command != "scan"
                else call_api(
                    args.api,
                    "/api/v1/scan-runs",
                    {
                        "project_id": args.project,
                        "snapshot_id": args.snapshot,
                        "profile_id": args.profile,
                    },
                    args.idempotency_key,
                )["id"]
            )
            if args.command in {"scan", "scan-wait"}:
                wait(call_api, args.api, scan_id, args.timeout, args.poll)
            result, exit_code = finish(
                call_api,
                args.api,
                scan_id,
                policy,
                name=args.name if args.command == "export" else None,
                format=args.format if args.command == "export" else "json",
            )
        print(json.dumps(result, sort_keys=True))
        if exit_code:
            raise SystemExit(exit_code)
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled", "scan_continues": True}))
        raise SystemExit(2) from None
    except HTTPError as exc:
        print(json.dumps({"error": "api_request_failed", "status": exc.code}))
        raise SystemExit(2) from None
    except (SnapshotError, OSError, ValueError, URLError, KeyError, TypeError):
        print(json.dumps({"error": "local_operation_rejected"}))
        raise SystemExit(2) from None
