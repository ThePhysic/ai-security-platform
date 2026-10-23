import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from dotenv import dotenv_values

from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import SnapshotStore


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def call_api(
    base: str, path: str, body: dict[str, object] | None = None, key: str | None = None
) -> dict[str, object]:
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
    with opener.open(request, timeout=30) as response:
        value: dict[str, object] = json.load(response)
        return value


def main() -> None:
    parser = argparse.ArgumentParser(prog="asp", description="Local immutable-snapshot scanning")
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
    register.add_argument("--project", required=True)
    register.add_argument("--key", required=True)
    register.add_argument("--digest", required=True)
    submit = commands.add_parser("scan-submit")
    submit.add_argument("--project", required=True)
    submit.add_argument("--snapshot", required=True)
    submit.add_argument("--idempotency-key", required=True)
    submit.add_argument("--profile", choices=["fake-v1", "security-v1"], default="fake-v1")
    status = commands.add_parser("scan-status")
    status.add_argument("id")
    history = commands.add_parser("scan-history")
    history.add_argument("--project", required=True)
    history.add_argument("--cursor")
    history.add_argument("--limit", type=int, default=50)
    findings = commands.add_parser("findings")
    findings.add_argument("id")
    findings.add_argument("--cursor")
    args = parser.parse_args()
    try:
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
        else:
            suffix = "?" + urlencode({"cursor": args.cursor}) if args.cursor else ""
            result = call_api(args.api, "/api/v1/scan-runs/" + args.id + "/findings" + suffix)
        print(json.dumps(result, sort_keys=True))
    except HTTPError as exc:
        print(json.dumps({"error": "api_request_failed", "status": exc.code}))
        raise SystemExit(2) from None
    except (SnapshotError, OSError, ValueError, URLError):
        print(json.dumps({"error": "local_operation_rejected"}))
        raise SystemExit(2) from None
