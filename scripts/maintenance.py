"""Local operator lifecycle commands; dry-run retention and no destructive DB restore."""

import json
import re
import secrets

from ai_security_platform.cli.main import Parser
from ai_security_platform.reporting.files import artifact_usage
from ai_security_platform.snapshots.policy import SnapshotError
from ai_security_platform.snapshots.store import KEY, SnapshotStore
from scripts.lifecycle import (
    ROOT,
    Database,
    MaintenanceError,
    backup,
    private_directory,
    restore,
    retain,
    verify_bundle,
)


def prepare(mode, instance=None):
    database = Database(mode, instance)
    if mode == "development":
        raise MaintenanceError("sandbox_required")
    if (
        mode == "restore"
        and not database.private_root.exists()
        and len(list((ROOT / ".local").glob("phase7-restore*"))) >= 3
    ):
        raise MaintenanceError("restore_instance_quota")
    directory = private_directory(database.private_root)
    path = directory / "environment.env"
    if path.exists():
        from ai_security_platform.snapshots.store import _check_ancestors

        _check_ancestors(path)
        if path.stat().st_nlink != 1:
            raise MaintenanceError("unsafe_sandbox_configuration")
        return {"prepared": True, "mode": mode, "credentials_preserved": True}
    # Restore owns its initially absent spool. Clean startup owns an empty fresh spool.
    if mode == "clean":
        SnapshotStore(directory / "spool", require_readonly=False).initialize()
    config = {
        "ASP_PHASE7_MODE": mode,
        "ASP_PHASE7_DATABASE": database.name,
        "ASP_PHASE7_USER": database.user,
        "ASP_PHASE7_DB_PASSWORD": secrets.token_urlsafe(48),
        "ASP_PHASE7_API_TOKEN": secrets.token_urlsafe(48),
        "ASP_PHASE7_LAUNCHER_TOKEN": secrets.token_urlsafe(48),
        "ASP_PHASE7_PORT": "18087" if mode == "restore" else "18088",
        "ASP_PHASE7_SPOOL": (directory / "spool").as_posix(),
        "ASP_PHASE7_REAL_ENABLED": "false",
    }
    with path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(key + "=" + value for key, value in config.items()) + "\n")
    path.chmod(0o600)
    return {"prepared": True, "mode": mode, "credentials_generated_privately": True}


def main():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    retention = commands.add_parser("retention")
    retention.add_argument(
        "--apply",
        action="store_true",
        help="Remove only verified, unregistered, 7-day-old publications",
    )
    commands.add_parser("backup")
    commands.add_parser("artifacts")
    for name in ["verify", "restore"]:
        command = commands.add_parser(name)
        command.add_argument("--key", required=True)
        command.add_argument("--manifest-digest", required=True)
        if name == "restore":
            command.add_argument("--instance")
    command = commands.add_parser("prepare-sandbox")
    command.add_argument("mode", choices=["restore", "clean"])
    command.add_argument("--instance")
    arguments = parser.parse_args()
    try:
        if arguments.command == "prepare-sandbox":
            result = prepare(arguments.mode, arguments.instance)
        elif arguments.command == "retention":
            result = retain(
                Database(),
                SnapshotStore(ROOT / ".local/snapshot-spool", require_readonly=False),
                apply=arguments.apply,
            )
        elif arguments.command == "backup":
            result = backup(
                Database(),
                SnapshotStore(ROOT / ".local/snapshot-spool", require_readonly=False),
                ROOT / ".local/backups/phase7",
            )
        elif arguments.command == "artifacts":
            result = artifact_usage(ROOT / ".local/reports") | {
                "dry_run": True,
                "removed": 0,
                "policy": (
                    "Preserve exports and unknown temporaries; "
                    "explicit operator inspection required"
                ),
                "file_limit": 64,
                "byte_limit": 64 * 1024 * 1024,
            }
        else:
            if not re.fullmatch(KEY, arguments.key):
                raise MaintenanceError("invalid_backup_identity")
            path = ROOT / ".local/backups/phase7" / arguments.key
            if arguments.command == "verify":
                manifest = verify_bundle(path, arguments.manifest_digest)
                result = {"verified": True, "key": arguments.key, "schema": manifest["schema"]}
            else:
                database = Database("restore", arguments.instance)
                result = restore(
                    database,
                    path,
                    arguments.manifest_digest,
                    database.private_root / "spool",
                )
        print(json.dumps(result, sort_keys=True))
    except (MaintenanceError, SnapshotError) as error:
        category = str(error)
        safe = category if re.fullmatch(r"[a-z_]{1,64}", category) else "lifecycle_operation_failed"
        print(json.dumps({"error": safe, "retryable": False}))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"error": "lifecycle_operation_failed", "retryable": False}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
