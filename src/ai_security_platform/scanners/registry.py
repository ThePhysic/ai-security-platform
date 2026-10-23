"""Trusted prepared registry; absence is a closed capability, never fake success."""

import json
import re
from pathlib import Path
from typing import Any

from ai_security_platform.snapshots.policy import canonical, digest


def load_registry(path: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if value["version"] != 1 or set(value["scanners"]) != {"semgrep", "trivy"}:
        raise ValueError("invalid_scanner_registry")
    for name, scanner in value["scanners"].items():
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", scanner["image"]):
            raise ValueError("immutable_scanner_required")
        if not re.fullmatch(r"[0-9a-f]{64}", scanner["policy_digest"]):
            raise ValueError("invalid_policy_digest")
        executable = "/usr/bin/semgrep" if name == "semgrep" else "/usr/local/bin/trivy"
        if scanner["executable"] != executable:
            raise ValueError("invalid_scanner_executable")
    database = value["database"]
    if (
        not re.fullmatch(r"[0-9a-f]{32}", database["asset_key"])
        or set(database["files"]) != {"metadata.json", "trivy.db"}
        or database["metadata"]["Version"] != 2
    ):
        raise ValueError("invalid_database_asset")
    return value


def registry_digest(value: dict[str, Any]) -> str:
    return digest(canonical(value))
