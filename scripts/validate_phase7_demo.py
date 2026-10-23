"""Controlled genuine end-to-end portfolio flow. Preserve all created history."""

import json
import subprocess
import sys
import time
from pathlib import Path
from shutil import copytree
from uuid import uuid4

import jsonschema
from dotenv import dotenv_values

from ai_security_platform.cli.main import call_api
from scripts.validate_local import DEV, request, run, wait_ready
from scripts.validate_phase2b_live import configure_admission

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:18081"


def main():
    config = dotenv_values(ROOT / ".env")
    assert config.get("ASP_REAL_SCANNING_ENABLED", "false") == "false"
    assert config.get("ASP_HOSTED_ENABLED", "false") == "false"
    token = config["ASP_API_TOKEN"]
    identity = uuid4().hex
    private = ROOT / ".cache" / ("phase7-demo-" + identity)
    private.mkdir()
    commands = []
    checks = {}
    launcher = None
    output = None

    def cli(*args, code=0):
        result = subprocess.run(
            [sys.executable, "-m", "ai_security_platform.cli", "--api", BASE, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=240,
        )
        commands.append(
            {"command": args[0], "expected_exit": code, "actual_exit": result.returncode}
        )
        assert result.returncode == code, (args[0], result.returncode)
        return json.loads(result.stdout)

    def triage(finding):
        row = call_api(
            BASE,
            f"/api/v1/findings/{finding}/triage",
            {"provider": "deterministic-v1"},
            "phase7-triage-" + uuid4().hex,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            row = call_api(BASE, "/api/v1/triage-runs/" + row["id"])
            if row["status"] in {"succeeded", "unavailable", "failed"}:
                return row
            time.sleep(0.25)
        raise RuntimeError("Controlled triage exceeded its budget")

    try:
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "build",
            "api",
            "worker",
            "triage-worker",
        )
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "up",
            "-d",
            "--wait",
            "api",
            "worker",
            "triage-worker",
        )
        wait_ready(BASE)
        project = cli("project-create", "Phase 7 controlled flagship demonstration")["id"]
        source = private / "source"
        copytree(ROOT / "tests/fixtures/scanners/positive", source)
        synthetic = "AKIA" + "Z" * 16
        (source / "credentials.txt").write_text("aws_access_key_id = " + synthetic + "\n")
        (source / ".gitignore").write_text("*\n")
        snapshot = cli("snapshot-create", str(source), "--label", "phase7-controlled-demo")
        registered = cli(
            "snapshot-register",
            "--project",
            project,
            "--key",
            snapshot["snapshot_key"],
            "--digest",
            snapshot["manifest_digest"],
        )
        checks["authorized_immutable_source_acquired_and_registered"] = True
        configure_admission(True)
        output = (private / "launcher.log").open("w", encoding="utf-8")
        launcher = subprocess.Popen(
            [sys.executable, "-m", "runner.launcher", "--api", BASE],
            cwd=ROOT,
            stdout=output,
            stderr=output,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if "launcher_ready" in (private / "launcher.log").read_text(encoding="utf-8"):
                break
            assert launcher.poll() is None, "Controlled launcher unavailable"
            time.sleep(0.25)
        else:
            raise RuntimeError("Controlled launcher was not ready")
        decision = cli(
            "scan",
            "--project",
            project,
            "--snapshot",
            registered["id"],
            "--idempotency-key",
            "phase7-demo-" + identity,
            "--timeout",
            "180",
            code=1,
        )
        scan_id = decision["scan_id"]
        report = call_api(BASE, f"/api/v1/scan-runs/{scan_id}/export?format=json")
        assert report["scan"]["status"] == "succeeded"
        assert all(not row["synthetic"] for row in report["findings"])
        assert synthetic not in json.dumps(report)
        checks["genuine_isolated_scan_complete_with_independent_provenance"] = True
        checks["policy_failed_on_required_completed_findings_exit_1"] = True
        target = next(row for row in report["findings"] if row["rule_id"] == "platform.python.eval")
        unsupported = next(row for row in report["findings"] if row["rule_id"].startswith("CVE-"))
        investigation = triage(target["id"])
        abstention = triage(unsupported["id"])
        assert investigation["status"] == "succeeded" and abstention["status"] == "succeeded"
        (private / "triage-shape.json").write_text(
            json.dumps({"investigation": investigation, "abstention": abstention}, indent=2),
            encoding="utf-8",
        )
        assert investigation["assessment"]["assessment"] == "needs_review"
        assert investigation["assessment"]["reason"] == "evidence_supported"
        assert {"finding", "source"}.issubset(
            {c["kind"] for c in investigation["assessment"]["citations"]}
        )
        assert abstention["assessment"]["assessment"] == "abstain"
        checks["explicit_offline_investigation_and_abstention"] = True
        review_path = f"/api/v1/findings/{target['id']}/review"
        initial = request(
            BASE,
            review_path,
            token,
            method="PUT",
            json={
                "expected_revision": 0,
                "disposition": "confirmed",
                "note": "Controlled demonstration; human verified fixture label",
                "triage_run_id": investigation["id"],
                "feedback": "agree",
            },
        )
        assert initial.status_code == 200, initial.status_code
        updated = request(
            BASE,
            review_path,
            token,
            method="PUT",
            json={
                "expected_revision": 1,
                "disposition": "investigate",
                "note": "Explicit second human revision; advice remains advisory",
            },
        )
        assert updated.status_code == 200
        stale = request(
            BASE,
            review_path,
            token,
            method="PUT",
            json={
                "expected_revision": 1,
                "disposition": "false_positive",
                "note": "Must never overwrite revision two",
            },
        )
        assert stale.status_code == 409
        history = call_api(BASE, f"/api/v1/findings/{target['id']}/review-revisions?limit=5")
        checks["explicit_human_revisions_feedback_and_stale_conflict"] = True
        name = "phase7-demo-" + identity
        for format in ["json", "sarif"]:
            cli("export", scan_id, "--name", name, "--format", format, code=1)
        sarif = json.loads((ROOT / f".local/reports/{name}.sarif").read_text())
        schema = json.loads((ROOT / "tests/schemas/sarif-2.1.0.json").read_text())
        jsonschema.validators.validator_for(schema)(schema).validate(sarif)
        assert synthetic not in json.dumps(sarif)
        checks["json_sarif_schema_and_synthetic_secret_redaction"] = True
        # Real process/database interruption, with a diagnostic scan durably queued.
        launcher.terminate()
        launcher.wait(timeout=10)
        launcher = None
        run(*DEV, "--profile", "workers", "--profile", "triage", "stop", "worker", "triage-worker")
        queued = cli(
            "scan-submit",
            "--project",
            project,
            "--snapshot",
            registered["id"],
            "--profile",
            "fake-v1",
            "--idempotency-key",
            "phase7-recovery-" + identity,
        )
        assert cli("scan-status", queued["id"])["status"] == "queued"
        run(*DEV, "restart", "api", "db")
        wait_ready(BASE)
        assert cli("scan-status", queued["id"])["status"] == "queued"
        assert call_api(BASE, f"/api/v1/scan-runs/{scan_id}/export?format=json") == report
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "up",
            "-d",
            "--wait",
            "worker",
            "triage-worker",
        )
        diagnostic = cli("scan-wait", queued["id"], "--timeout", "90", code=2)
        # Required real scanners are absent from a fake profile: default policy is
        # incomplete (2), even though the synthetic diagnostic execution succeeds.
        assert diagnostic["scan_status"] == "succeeded"
        checks["queued_acceptance_and_completed_genuine_results_survive_api_db_restart"] = True
        checks["synthetic_diagnostic_does_not_satisfy_real_scanner_policy_exit_2"] = True
        assert call_api(BASE, f"/api/v1/scan-runs/{scan_id}/export?format=json") == report
        evidence = {
            "checks": checks,
            "commands": commands,
            "project_id": project,
            "scan_id": scan_id,
            "snapshot_id": registered["id"],
            "manifest_digest": snapshot["manifest_digest"],
            "finding_id": target["id"],
            "triage_id": investigation["id"],
            "abstention_id": abstention["id"],
            "review_revisions": history,
            "genuine_findings": len(report["findings"]),
            "scanners": report["scan"]["scanner_runs"],
            "diagnostic_scan_id": queued["id"],
            "passed": len(checks),
            "failed": 0,
            "skipped": 0,
            "limitations": (
                "Controlled source-only fixture; limited deterministic reasoning; "
                "valid citations do not prove advice; no production or hosted-model claim"
            ),
        }
        (ROOT / "docs/phase7/demo-evidence.json").write_text(
            json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {"demo_checks_passed": len(checks), "genuine_findings": len(report["findings"])}
            )
        )
    finally:
        if launcher is not None:
            launcher.terminate()
            launcher.wait(timeout=10)
        if output:
            output.close()
        configure_admission(False)
        run(
            *DEV,
            "--profile",
            "workers",
            "--profile",
            "triage",
            "up",
            "-d",
            "--wait",
            "api",
            "worker",
            "triage-worker",
        )


if __name__ == "__main__":
    main()
