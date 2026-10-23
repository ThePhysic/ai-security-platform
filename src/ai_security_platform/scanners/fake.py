"""Deterministic synthetic markers only; no interpretation or execution of source."""

from ai_security_platform.scanners.contracts import AdapterResult, NormalizedFinding
from ai_security_platform.snapshots.policy import SnapshotError, canonical, digest
from ai_security_platform.snapshots.store import VerifiedSnapshot


def scan(scanner_id: str, source: VerifiedSnapshot) -> AdapterResult:
    if scanner_id not in {"fake-patterns", "fake-config"}:
        raise SnapshotError("unsupported_scanner")
    marker, rule = (
        (b"ASP_FAKE_FINDING", "fake.marker.v1")
        if scanner_id == "fake-patterns"
        else (b"ASP_FAKE_CONFIG", "fake.config.v1")
    )
    findings: list[NormalizedFinding] = []
    for path, content in sorted(source.files.items()):
        for line, value in enumerate(content.splitlines(), 1):
            if marker not in value:
                continue
            if len(findings) >= 1000:
                raise SnapshotError("output_limit")
            identity = [scanner_id, rule, path]
            findings.append(
                NormalizedFinding.model_validate(
                    {
                        "occurrence_key": digest(canonical([*identity, line])),
                        "tracking_fingerprint": digest(canonical(identity)),
                        "rule_id": rule,
                        "filepath": path,
                        "start_line": line,
                        "end_line": line,
                    }
                )
            )
    return AdapterResult.model_validate(
        {
            "scanner_id": scanner_id,
            "findings": findings,
            "files_scanned": len(source.files),
            "excluded_files": source.manifest.exclusions["files"],
            "excluded_directories": source.manifest.exclusions["directories"],
        }
    )
