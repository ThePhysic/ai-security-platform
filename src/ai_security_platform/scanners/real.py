"""Bounded pure normalization. Never persist source excerpts or scanner messages."""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ai_security_platform.scanners.contracts import AdapterResult, NormalizedFinding
from ai_security_platform.scanners.registry import load_registry
from ai_security_platform.snapshots.policy import canonical, digest, validate_path
from ai_security_platform.snapshots.store import VerifiedSnapshot

MESSAGES = {
    "sast": "Static analysis requires human security review.",
    "vulnerability": (
        "A dependency has a reported advisory; assess applicability and fixed versions."
    ),
    "secret": "Potential exposed credential; value redacted. Review and rotate if confirmed.",
    "misconfiguration": "Configuration requires human security review.",
}
CWE_BY_RULE = {
    "platform.python.eval": "CWE-95",
    "platform.javascript.eval": "CWE-95",
    "platform.python.shell": "CWE-78",
    "platform.javascript.exec": "CWE-78",
    "platform.python.sql-format": "CWE-89",
    "platform.javascript.sql-concat": "CWE-89",
    "platform.ci.write-all": "CWE-269",
    "platform.ci.mutable-action": "CWE-829",
}
SEMGREP_RULES = {
    "platform.python.eval",
    "platform.python.shell",
    "platform.python.sql-format",
    "platform.javascript.eval",
    "platform.javascript.exec",
    "platform.javascript.sql-concat",
    "platform.ci.write-all",
    "platform.ci.mutable-action",
}
SEVERITIES = {"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
SECRET_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}")
EVIDENCE_KEYS = {
    "manifest_digest",
    "cwe",
    "advisory_id",
    "package_name",
    "installed_version",
    "fixed_version",
    "secret_rule",
}


def safe_metadata(value: object, maximum: int = 128) -> str:
    text = str(value)
    if (
        len(text) > maximum
        or SECRET_PATTERN.search(text)
        or not re.fullmatch(r"[A-Za-z0-9_.:@+ /,<>=-]*", text)
    ):
        return "redacted"
    return text


def path_in_source(value: str, source: VerifiedSnapshot) -> str:
    for prefix in ("/work/audit/", "/source/"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    validate_path(value)
    if value not in source.files or SECRET_PATTERN.search(value):
        raise ValueError("invalid_evidence_path")
    return value


def finding(
    scanner: str,
    rule: str,
    category: str,
    path: str,
    start: int,
    end: int,
    severity: str,
    original: str,
    evidence: Mapping[str, str | int],
    source: VerifiedSnapshot,
) -> NormalizedFinding:
    path = path_in_source(path, source)
    lines = len(source.files[path].splitlines())
    if not 1 <= start <= end <= max(1, lines):
        raise ValueError("invalid_evidence_range")
    identity = [scanner, rule, path, evidence.get("advisory_id"), evidence.get("package_name")]
    return NormalizedFinding(
        occurrence_key=digest(
            canonical([*identity, evidence.get("installed_version"), start, end])
        ),
        tracking_fingerprint=digest(canonical(identity)),
        rule_id=rule,
        category=category,
        severity=severity if severity in SEVERITIES else "UNKNOWN",
        original_severity=safe_metadata(original, 32),
        description=MESSAGES[category],
        filepath=path,
        start_line=start,
        end_line=end,
        evidence={"manifest_digest": source.manifest_digest, **evidence},
        synthetic=False,
    )


def bounded_json(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise ValueError("invalid_scanner_output")
    try:
        value = json.loads(raw)
        pending, count = [(value, 0)], 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > 100000 or depth > 24:
                raise ValueError("invalid_scanner_output")
            if isinstance(node, dict):
                pending.extend((item, depth + 1) for item in node.values())
            elif isinstance(node, list):
                pending.extend((item, depth + 1) for item in node)
            elif isinstance(node, str) and len(node) > 65536:
                raise ValueError("invalid_scanner_output")
        if not isinstance(value, dict):
            raise ValueError("invalid_scanner_output")
        return value
    except (TypeError, RecursionError, json.JSONDecodeError):
        raise ValueError("invalid_scanner_output") from None


def normalize(
    scanner: str,
    raw: bytes,
    exit_code: int,
    source: VerifiedSnapshot,
    provenance: dict[str, str | int],
) -> AdapterResult:
    value = bounded_json(raw)
    found: list[NormalizedFinding] = []
    warnings = []
    scanned = 0
    if scanner == "semgrep":
        if not isinstance(value.get("results"), list) or not isinstance(value.get("errors"), list):
            raise ValueError("invalid_scanner_output")
        scanned = len(value.get("paths", {}).get("scanned", []))
        if value["errors"]:
            warnings.append("scanner_errors")
        for item in value["results"]:
            rule = item["check_id"]
            if rule not in SEMGREP_RULES:
                raise ValueError("untrusted_rule")
            original = item["extra"]["severity"]
            mapped = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}.get(original, "UNKNOWN")
            found.append(
                finding(
                    scanner,
                    rule,
                    "sast",
                    item["path"],
                    item["start"]["line"],
                    item["end"]["line"],
                    mapped,
                    original,
                    {"cwe": CWE_BY_RULE[rule]},
                    source,
                )
            )
    elif scanner == "trivy":
        if value.get("SchemaVersion") != 2 or not isinstance(value.get("Results", []), list):
            raise ValueError("invalid_scanner_output")
        scanned_paths = set()
        for target in value.get("Results", []):
            path = path_in_source(target["Target"], source)
            scanned_paths.add(path)
            for item in target.get("Vulnerabilities") or []:
                advisory = safe_metadata(item["VulnerabilityID"])
                evidence = {
                    "advisory_id": advisory,
                    "package_name": safe_metadata(item.get("PkgName", "")),
                    "installed_version": safe_metadata(item.get("InstalledVersion", "")),
                    "fixed_version": safe_metadata(item.get("FixedVersion", "")),
                }
                found.append(
                    finding(
                        scanner,
                        advisory,
                        "vulnerability",
                        path,
                        1,
                        1,
                        item.get("Severity", "UNKNOWN"),
                        item.get("Severity", "UNKNOWN"),
                        evidence,
                        source,
                    )
                )
            for item in target.get("Secrets") or []:
                rule = safe_metadata(item["RuleID"])
                found.append(
                    finding(
                        scanner,
                        "secret." + rule,
                        "secret",
                        path,
                        item["StartLine"],
                        item["EndLine"],
                        item.get("Severity", "UNKNOWN"),
                        item.get("Severity", "UNKNOWN"),
                        {"secret_rule": rule},
                        source,
                    )
                )
            for item in target.get("Misconfigurations") or []:
                rule = safe_metadata(item.get("AVDID") or item["ID"])
                cause = item.get("CauseMetadata") or {}
                start = max(1, cause.get("StartLine", 1))
                end = max(start, cause.get("EndLine", start))
                found.append(
                    finding(
                        scanner,
                        rule,
                        "misconfiguration",
                        path,
                        start,
                        end,
                        item.get("Severity", "UNKNOWN"),
                        item.get("Severity", "UNKNOWN"),
                        {},
                        source,
                    )
                )
            if target.get("MisconfSummary", {}).get("Exceptions", 0):
                warnings.append("suppressed_results")
        scanned = len(scanned_paths)
    else:
        raise ValueError("unsupported_scanner")
    if len(found) > 200:
        raise ValueError("finding_limit")
    if any(item.severity == "UNKNOWN" for item in found):
        warnings.append("unknown_severity")
    if scanner == "trivy":
        paths = set(source.files)
        for path in paths:
            parent = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
            if path.endswith("package.json") and not any(
                parent + lock in paths for lock in ("package-lock.json", "npm-shrinkwrap.json")
            ):
                warnings.append("dependency_lockfile_missing")
            if path.endswith(
                ("poetry.lock", "uv.lock", "Pipfile.lock", "yarn.lock", "pnpm-lock.yaml")
            ):
                warnings.append("dependency_format_not_validated")
            if path.endswith((".tf", ".tfvars", ".hcl")):
                warnings.append("iac_format_not_validated")
    if scanned == 0:
        warnings.append("no_supported_targets")
    if exit_code not in {0, 1}:
        warnings.append("scanner_exit_failure")
    # Deduplicate exact upstream occurrences without merging different scanners.
    unique = {item.occurrence_key: item for item in found}
    result = AdapterResult(
        scanner_id=scanner,
        findings=list(unique.values()),
        files_scanned=min(scanned, 512),
        excluded_files=source.manifest.exclusions["files"],
        excluded_directories=source.manifest.exclusions["directories"],
        complete=not warnings,
        warnings=sorted(set(warnings)),
        provenance=provenance,
        policy_files_ignored=sum(
            path.rsplit("/", 1)[-1].lower()
            in {
                ".semgrepignore",
                ".gitignore",
                ".semgrep.yml",
                ".semgrep.yaml",
                "semgrep.yml",
                "semgrep.yaml",
                ".trivyignore",
                ".trivyignore.yaml",
                ".trivy.yaml",
                "trivy.yaml",
                "trivy.yml",
                "trivy-secret.yaml",
            }
            for path in source.files
        ),
        suppression_tokens_neutralized=(
            sum(
                len(re.findall(rb"(?:trivy|tfsec):ignore", content, re.IGNORECASE))
                for content in source.files.values()
            )
            if scanner == "trivy"
            else 0
        ),
    )
    validate_result(result, source)
    return result


def validate_result(result: AdapterResult, source: VerifiedSnapshot) -> None:
    if result.scanner_id.startswith("fake-"):
        return
    allowed_warnings = {
        "scanner_errors",
        "suppressed_results",
        "unknown_severity",
        "dependency_lockfile_missing",
        "dependency_format_not_validated",
        "iac_format_not_validated",
        "no_supported_targets",
        "scanner_exit_failure",
    }
    if not set(result.warnings) <= allowed_warnings or result.complete == bool(result.warnings):
        raise ValueError("invalid_coverage")
    if len(result.findings) > 200:
        raise ValueError("finding_limit")
    allowed_provenance = {
        "image_digest",
        "engine_version",
        "policy_digest",
        "adapter_version",
        "view_policy",
        "database_digest",
        "database_updated_at",
        "database_age_seconds",
    }
    if not set(result.provenance) <= allowed_provenance:
        raise ValueError("invalid_provenance")
    for name, value in result.provenance.items():
        if name.endswith("digest"):
            if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", str(value)):
                raise ValueError("invalid_provenance")
        elif name == "database_age_seconds":
            if not isinstance(value, int) or not 0 <= value <= 172800:
                raise ValueError("invalid_provenance")
        elif not re.fullmatch(r"[A-Za-z0-9 .:_+-]{1,64}", str(value)):
            raise ValueError("invalid_provenance")
    for item in result.findings:
        path_in_source(item.filepath, source)
        if (
            item.synthetic
            or item.description != MESSAGES.get(item.category)
            or not re.fullmatch(r"[A-Z][A-Z_-]{0,31}", item.original_severity)
            or not set(item.evidence) <= EVIDENCE_KEYS
            or item.evidence.get("manifest_digest") != source.manifest_digest
        ):
            raise ValueError("invalid_normalized_finding")
        for key, entry in item.evidence.items():
            if key != "manifest_digest" and str(entry) != safe_metadata(entry):
                raise ValueError("invalid_normalized_metadata")
    if len(canonical(result.model_dump())) > 524288:
        raise ValueError("normalized_output_limit")


def validate_provenance(result: AdapterResult, registry_path: Path) -> None:
    if result.scanner_id.startswith("fake-"):
        return
    registry = load_registry(registry_path)
    scanner = registry["scanners"][result.scanner_id]
    expected = {
        "image_digest": scanner["image"],
        "engine_version": scanner["version"],
        "policy_digest": scanner["policy_digest"],
        "adapter_version": "real-1",
        "view_policy": "audit-view-v1",
    }
    if result.scanner_id == "trivy":
        expected["database_digest"] = registry["database"]["digest"]
    if any(result.provenance.get(key) != value for key, value in expected.items()):
        raise ValueError("provenance_mismatch")
