"""Allowlisted, source-verified reports. No source snippets, links or model advice."""

import re
from typing import Any

from ai_security_platform.domain.findings import FindingRead
from ai_security_platform.domain.scans import ScanRead
from ai_security_platform.reporting.contracts import Report
from ai_security_platform.scanners.real import MESSAGES, safe_metadata
from ai_security_platform.snapshots.policy import canonical, digest, validate_path
from ai_security_platform.snapshots.store import VerifiedSnapshot

MAX_REPORT_BYTES = 4 * 1024 * 1024
KNOWN_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|SYNTHETIC_SECRET_[A-Za-z0-9_-]+"
)
PROVENANCE = {
    "engine_version",
    "adapter_version",
    "image_digest",
    "policy_digest",
    "view_policy",
    "database_digest",
    "database_updated_at",
    "database_age_seconds",
}
COUNTERS = {
    "schema_version",
    "files_scanned",
    "excluded_files",
    "excluded_directories",
    "warning_count",
    "source_files",
    "files_not_scanned",
    "policy_files_ignored",
    "suppression_tokens_neutralized",
}
BOOLEANS = {"synthetic", "complete_execution", "complete_detection_claim", "unavailable"}
EVIDENCE = {
    "manifest_digest",
    "cwe",
    "advisory_id",
    "package_name",
    "installed_version",
    "fixed_version",
    "secret_rule",
}
LIMITATIONS = [
    "Scanner coverage is limited; a passing policy is not a security guarantee.",
    "AI assessments and remediation are advisory and excluded from policy decisions.",
    "Evaluation labels, including ungraded annotation bindings, are not applied as suppressions.",
]


def metadata(value: object, maximum: int = 256) -> str:
    text = str(value)
    return (
        "redacted" if KNOWN_SECRET.search(text) or "://" in text else safe_metadata(text, maximum)
    )


def encode(value: dict[str, Any]) -> bytes:
    raw = canonical(value) + b"\n"
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report_limit")
    return raw


def build_json(
    scan: ScanRead, findings: list[FindingRead], source: VerifiedSnapshot
) -> dict[str, Any]:
    if len(findings) > 1000:
        raise ValueError("report_limit")
    stages = {}
    for scanner in scan.scanner_runs:
        if not re.fullmatch(r"[a-z0-9-]{1,32}", scanner.scanner_id) or scanner.scanner_id in stages:
            raise ValueError("invalid_report_scope")
        row = scanner.model_dump(mode="json")
        row["provenance"] = {
            k: metadata(v) if isinstance(v, str) else v
            for k, v in scanner.provenance.items()
            if k in PROVENANCE and isinstance(v, (str, int)) and not isinstance(v, bool)
        }
        coverage: dict[str, Any] = {"complete_execution": False}
        for key, value in scanner.coverage.items():
            if (
                key in COUNTERS
                and type(value) is int
                and 0 <= value <= 1000000
                or key in BOOLEANS
                and type(value) is bool
            ):
                coverage[key] = value
        warnings = scanner.coverage.get("warnings", [])
        coverage["warnings"] = (
            [
                w
                if isinstance(w, str) and re.fullmatch(r"[a-z0-9_]{1,64}", w)
                else "redacted_warning"
                for w in warnings[:16]
            ]
            if isinstance(warnings, list)
            else ["invalid_coverage"]
        )
        row["coverage"] = coverage
        row["error_code"] = metadata(scanner.error_code, 64) if scanner.error_code else None
        stages[scanner.scanner_id] = row
    by_id = {row["id"]: name for name, row in stages.items()}
    rows = []
    for finding in findings:
        if finding.scan_run_id != scan.id or str(finding.scanner_run_id) not in by_id:
            raise ValueError("invalid_report_scope")
        if (
            finding.severity not in {"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            or finding.category
            not in {"synthetic", "sast", "vulnerability", "secret", "misconfiguration"}
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in (finding.occurrence_key, finding.tracking_fingerprint)
            )
            or finding.synthetic != by_id[str(finding.scanner_run_id)].startswith("fake-")
        ):
            raise ValueError("invalid_report_finding")
        path = validate_path(finding.filepath)
        content = source.files.get(path)
        if (
            content is None
            or KNOWN_SECRET.search(path)
            or not 1 <= finding.start_line <= finding.end_line <= len(content.splitlines())
        ):
            raise ValueError("invalid_report_location")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", finding.rule_id)
            or "://" in finding.rule_id
            or KNOWN_SECRET.search(finding.rule_id)
        ):
            raise ValueError("invalid_report_rule")
        if (
            finding.evidence.get("manifest_digest", source.manifest_digest)
            != source.manifest_digest
        ):
            raise ValueError("invalid_report_identity")
        row = finding.model_dump(mode="json")
        row["scanner_id"] = by_id[str(finding.scanner_run_id)]
        row["original_severity"] = metadata(finding.original_severity, 32)
        row["description"] = (
            "Synthetic diagnostic marker; not a security detection."
            if finding.synthetic
            else MESSAGES.get(finding.category, "Security finding requires human review.")
        )
        row["evidence"] = {
            k: metadata(v) if isinstance(v, str) else v
            for k, v in finding.evidence.items()
            if k in EVIDENCE
        }
        row["evidence"]["manifest_digest"] = source.manifest_digest
        rows.append(row)
    rows.sort(
        key=lambda r: (
            r["scanner_id"],
            r["filepath"],
            r["start_line"],
            r["rule_id"],
            r["occurrence_key"],
        )
    )
    snapshot = scan.model_dump(mode="json")
    snapshot["scanner_runs"] = [stages[key] for key in sorted(stages)]
    result = {
        "schema_version": 1,
        "reporting_version": "scanner-report-1",
        "scan": snapshot,
        "findings": rows,
        "source": {
            "snapshot_id": str(scan.snapshot_id),
            "manifest_digest": source.manifest_digest,
            "content_digest": source.manifest.content_digest,
            "verified": True,
            "files": {
                p: {"sha256": digest(b), "lines": len(b.splitlines())}
                for p, b in sorted(source.files.items())
                if p in {r["filepath"] for r in rows}
            },
        },
        "limitations": LIMITATIONS,
        "ai_opinions_applied": False,
        "evaluation_labels_applied": False,
    }
    Report.model_validate(result)
    encode(result)
    return result


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    runs = []
    for scanner in report["scan"]["scanner_runs"]:
        findings = [r for r in report["findings"] if r["scanner_id"] == scanner["scanner_id"]]
        rules = sorted({r["rule_id"] for r in findings})
        results = []
        for row in findings:
            level = (
                "error"
                if row["severity"] in {"HIGH", "CRITICAL"}
                else "warning"
                if row["severity"] in {"MEDIUM", "UNKNOWN"}
                else "note"
            )
            results.append(
                {
                    "ruleId": row["rule_id"],
                    "ruleIndex": rules.index(row["rule_id"]),
                    "level": level,
                    "message": {"text": row["description"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": row["filepath"]},
                                "region": {
                                    "startLine": row["start_line"],
                                    "endLine": row["end_line"],
                                },
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "tracking/v1": row["tracking_fingerprint"],
                        "occurrence/v1": row["occurrence_key"],
                    },
                    "properties": {
                        "synthetic": row["synthetic"],
                        "category": row["category"],
                        "severity": row["severity"],
                        "originalSeverity": metadata(row["original_severity"], 32),
                        "evidence": row["evidence"],
                    },
                }
            )
        paths = sorted({row["filepath"] for row in findings})
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": scanner["scanner_id"],
                        "version": str(
                            scanner["provenance"].get("engine_version", scanner["adapter_version"])
                        ),
                        "rules": [{"id": r} for r in rules],
                    }
                },
                "results": results,
                "artifacts": [
                    {
                        "location": {"uri": p},
                        "hashes": {"sha-256": report["source"]["files"][p]["sha256"]},
                    }
                    for p in paths
                ],
                "invocations": [
                    {
                        "executionSuccessful": scanner["status"] == "succeeded"
                        and scanner["coverage"].get("complete_execution") is True
                    }
                ],
                "properties": {
                    "coverage": scanner["coverage"],
                    "provenance": scanner["provenance"],
                    "status": scanner["status"],
                    "synthetic": scanner["synthetic"],
                    "errorCode": scanner["error_code"],
                    "source": {k: v for k, v in report["source"].items() if k != "files"},
                    "limitations": report["limitations"],
                    "aiOpinionsApplied": False,
                },
            }
        )
    result = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "runs": runs,
    }
    encode(result)
    return result
