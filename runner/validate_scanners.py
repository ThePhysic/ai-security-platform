"""Real containers and genuine outputs, only maintained inert labelled fixtures."""

import argparse
import json
from collections import Counter
from uuid import uuid4

from ai_security_platform.scanners.real import normalize
from ai_security_platform.snapshots.store import SnapshotStore
from runner.boundary import ROOT, BoundaryError, Invocation
from runner.launcher import Launcher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase3", action="store_true")
    parser.add_argument("--phase4", action="store_true")
    parser.add_argument("--phase5", action="store_true")
    args = parser.parse_args()
    # No API call occurs here; the same fixed-profile resolver/boundary is exercised
    # with controlled fixtures, before public security-v1 admission is enabled.
    launcher = Launcher(
        "http://127.0.0.1:18081",
        ROOT / (".local/phase5-fixtures/spool" if args.phase5 else ".local/phase2b-fixtures/spool"),
        "unused",
    )
    evidence = {"fixtures": {}, "checks": {}}
    checks = evidence["checks"]
    for label in ("positive", "clean"):
        source = ROOT / "tests/fixtures/scanners" / label
        # Synthetic credential is generated only into ignored local fixture data.
        from shutil import copytree

        local = ROOT / ".cache" / ("scanner-fixture-" + uuid4().hex)
        copytree(source, local)
        synthetic = "AKIA" + "Z" * 16
        if label == "positive":
            local.joinpath("credentials.txt").write_text("aws_access_key_id = " + synthetic + "\n")
            local.joinpath(".gitignore").write_text("*\n")
        snapshot = SnapshotStore(launcher.boundary.spool, require_readonly=False).create(
            local, label="controlled-" + label
        )
        record = {}
        for scanner in ("semgrep", "trivy"):
            invocation = Invocation(
                id=uuid4(),
                job_id=uuid4(),
                generation=1,
                lease_token=uuid4(),
                snapshot_key=snapshot.manifest.snapshot_key,
                manifest_digest=snapshot.manifest_digest,
                profile=scanner + "-v1",
                registry_digest=launcher.registry_hash,
            )
            profile, database, provenance = launcher.profile(invocation)
            identifier = launcher.boundary.create(
                profile,
                invocation.snapshot_key,
                invocation.manifest_digest,
                invocation.id,
                database=database,
            )
            captured = launcher.boundary.capture(identifier, profile)
            # Raw scanner text is never written to a file/report or printed.
            try:
                result = normalize(
                    scanner, captured.stdout, captured.exit_code, snapshot, provenance
                )
            except Exception:
                # Safe diagnostics for controlled fixtures only: tool exit and byte counts.
                print(
                    json.dumps(
                        {
                            "scanner": scanner,
                            "fixture": label,
                            "exit_code": captured.exit_code,
                            "error_code": captured.error_code,
                            "stdout_bytes": len(captured.stdout),
                            "stderr_bytes": len(captured.stderr),
                            "stderr_safe": captured.stderr.decode(errors="replace")[:1500].replace(
                                synthetic, "[redacted]"
                            ),
                        }
                    ),
                    flush=True,
                )
                raise RuntimeError("Controlled fixture normalization failed") from None
            assert synthetic not in result.model_dump_json()
            try:
                normalize(
                    scanner, captured.stdout.rstrip()[:-1], captured.exit_code, snapshot, provenance
                )
            except ValueError:
                checks[scanner + "_truncated_genuine_output_rejected"] = True
            else:
                raise AssertionError("Truncated output was accepted")
            record[scanner] = {
                "exit_code": captured.exit_code,
                "complete": result.complete,
                "warnings": result.warnings,
                "files_scanned": result.files_scanned,
                "findings": len(result.findings),
                "categories": dict(Counter(item.category for item in result.findings)),
                "rules": sorted({item.rule_id for item in result.findings}),
                "paths": sorted({item.filepath for item in result.findings}),
                "provenance": result.provenance,
            }
        evidence["fixtures"][label] = record
        print(json.dumps({"fixture": label, "results": record}), flush=True)
    positive, clean = evidence["fixtures"]["positive"], evidence["fixtures"]["clean"]
    checks["python_and_javascript_sast"] = len(positive["semgrep"]["rules"]) >= 4
    checks["repository_ignores_and_nosemgrep_cannot_suppress"] = (
        "platform.python.eval" in positive["semgrep"]["rules"]
        and "platform.javascript.eval" in positive["semgrep"]["rules"]
    )
    checks["github_actions_guardrails"] = all(
        rule in positive["semgrep"]["rules"]
        for rule in ("platform.ci.write-all", "platform.ci.mutable-action")
    )
    for category in ("vulnerability", "secret", "misconfiguration"):
        checks["trivy_" + category] = positive["trivy"]["categories"].get(category, 0) > 0
    checks["dockerfile_and_kubernetes"] = all(
        path in positive["trivy"]["paths"] for path in ("Dockerfile", "pod.yaml")
    )
    checks["clean_sast"] = clean["semgrep"]["findings"] == 0 and clean["semgrep"]["complete"]
    checks["clean_trivy"] = clean["trivy"]["findings"] == 0 and clean["trivy"]["complete"]
    checks["inline_trivy_suppression_ignored"] = "DS-0002" in positive["trivy"]["rules"]
    # Actual Trivy execution without its required DB must fail, never look clean.
    identifier = launcher.boundary.create(
        profile, invocation.snapshot_key, invocation.manifest_digest, uuid4(), database=None
    )
    unavailable = launcher.boundary.capture(identifier, profile)
    checks["actual_missing_database_execution_fails"] = unavailable.exit_code != 0
    original_date = launcher.registry["database"]["metadata"]["UpdatedAt"]
    launcher.registry["database"]["metadata"]["UpdatedAt"] = "2020-01-01T00:00:00Z"
    try:
        launcher.profile(invocation)
    except BoundaryError as error:
        checks["stale_database_preflight_denied"] = str(error) == "database_stale"
    else:
        raise AssertionError("Stale DB accepted")
    finally:
        launcher.registry["database"]["metadata"]["UpdatedAt"] = original_date
    unsupported = ROOT / ".cache" / ("unsupported-fixture-" + uuid4().hex)
    unsupported.mkdir()
    unsupported.joinpath("opaque.blob").write_bytes(b"\0opaque-unsupported")
    unknown = SnapshotStore(launcher.boundary.spool, require_readonly=False).create(
        unsupported, label="controlled-unsupported"
    )
    for scanner in ("semgrep", "trivy"):
        request = Invocation(
            id=uuid4(),
            job_id=uuid4(),
            generation=1,
            lease_token=uuid4(),
            snapshot_key=unknown.manifest.snapshot_key,
            manifest_digest=unknown.manifest_digest,
            profile=scanner + "-v1",
            registry_digest=launcher.registry_hash,
        )
        selected, database, provenance = launcher.profile(request)
        identifier = launcher.boundary.create(
            selected, request.snapshot_key, request.manifest_digest, request.id, database=database
        )
        captured = launcher.boundary.capture(identifier, selected)
        result = normalize(scanner, captured.stdout, captured.exit_code, unknown, provenance)
        checks[scanner + "_unsupported_input_reports_incomplete"] = (
            not result.complete and "no_supported_targets" in result.warnings
        )
    assert all(checks.values()), {key: value for key, value in checks.items() if not value}
    evidence.update({"passed": len(checks), "failed": 0, "skipped": 0})
    target = ROOT / (
        "docs/phase5/scanner-regression.json"
        if args.phase5
        else "docs/phase4/scanner-regression.json"
        if args.phase4
        else "docs/phase3/scanner-regression.json"
        if args.phase3
        else "docs/phase2b/scanner-evidence.json"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
