"""Trusted frozen rule catalog, generated from platform policy rather than repositories."""

import json
from pathlib import Path
from typing import Any

from ai_security_platform.scanners.registry import load_registry
from ai_security_platform.snapshots.policy import digest


def catalog() -> dict[str, Any]:
    raw = Path("policies/triage-rules.json").read_bytes()
    if len(raw) > 32768:
        raise ValueError("invalid_rule_catalog")
    value: dict[str, Any] = json.loads(raw)
    scanner = load_registry(Path("policies/scanners.lock.json"))["scanners"]["semgrep"]
    if (
        value["version"] != 1
        or value["source_rules_sha256"] != scanner["policy_files"]["rules.yaml"]
        or value["scanner_policy_digest"] != scanner["policy_digest"]
    ):
        raise ValueError("invalid_rule_catalog")
    return value | {"catalog_digest": digest(raw)}
