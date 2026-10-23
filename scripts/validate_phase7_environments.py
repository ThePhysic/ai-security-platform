"""Final clean/latest-restore API checks, private ACL check and scoped shutdown."""

import json
import subprocess

from dotenv import dotenv_values

from scripts.lifecycle import ROOT, Database, run, verify_bundle
from scripts.validate_local import inspect_safe, request


def main():
    checks = {}
    previous = Database("restore")
    run([*previous.compose, "up", "-d", "--wait", "db"])
    previous.guard()
    run([*previous.compose, "stop", "api", "triage-worker"])
    instance = json.loads((ROOT / ".cache/phase7-restore-latest-instance.json").read_text())[
        "instance"
    ]
    latest = Database("restore", instance)
    run([*latest.compose, "up", "-d", "--wait", "db"])
    latest.guard()
    clean = Database("clean")
    run([*clean.compose, "up", "-d", "--wait", "db"])
    clean.guard()
    image = (
        run(["docker", "image", "inspect", "--format", "{{.Id}}", "asp-phase7/platform:local"])
        .decode()
        .strip()
    )
    run([*previous.compose, "up", "-d", "--wait", "--no-build", "triage-worker"])
    run(
        [
            *previous.compose,
            "exec",
            "-T",
            "triage-worker",
            "python",
            "-c",
            "import os; assert not os.environ.get('ASP_LAUNCHER_TOKEN')",
        ]
    )
    checks["initial_restore_triage_worker_has_no_launcher_capability"] = True
    environments = {}
    for database, services in [(clean, ["api", "worker", "triage-worker"]), (latest, ["api"])]:
        run([*database.compose, "up", "-d", "--wait", "--no-build", *services])
        config = dotenv_values(database.private_root / "environment.env")
        port = config["ASP_PHASE7_PORT"]
        base = "http://127.0.0.1:" + port
        token = config["ASP_PHASE7_API_TOKEN"]
        assert request(base, "/ready", method="GET").status_code == 200
        assert request(base, "/api/v1/triage-config", method="GET").status_code == 401
        settings = request(base, "/api/v1/triage-config", token, method="GET").json()
        assert not settings["hosted_enabled"]
        checks[database.mode + "_actual_api_ready_auth_and_hosted_default"] = True
        records = {}
        for service in services:
            identifier = run([*database.compose, "ps", "-q", service]).decode().strip()
            safe = inspect_safe(identifier)
            actual = (
                run(["docker", "inspect", "--format", "{{.Image}}", identifier]).decode().strip()
            )
            assert actual == image
            assert safe["project"] == database.project and safe["user"] == "10001:10001"
            assert safe["readonly"] and "ALL" in safe["caps"]
            assert "no-new-privileges:true" in safe["security"]
            assert all(m["Destination"] in {"/spool", "/tmp"} for m in safe["mounts"])
            assert all(not m["RW"] for m in safe["mounts"] if m["Destination"] == "/spool")
            if service != "api":
                run(
                    [
                        *database.compose,
                        "exec",
                        "-T",
                        service,
                        "python",
                        "-c",
                        "import os; assert not os.environ.get('ASP_LAUNCHER_TOKEN')",
                    ]
                )
                checks[database.mode + "_" + service + "_no_launcher_capability"] = True
            records[service] = {
                "image": actual,
                "user": safe["user"],
                "readonly": safe["readonly"],
                "ports": safe["ports"],
                "spool_readonly": True,
                "no_daemon_mount": True,
            }
        environments[database.mode] = {"project": database.project, "services": records}
        checks[database.mode + "_final_image_and_restricted_consumers"] = True
    demo = json.loads((ROOT / "docs/phase7/demo-evidence.json").read_text())
    token = dotenv_values(latest.private_root / "environment.env")["ASP_PHASE7_API_TOKEN"]
    base = "http://127.0.0.1:18087"
    assert (
        request(base, "/api/v1/projects/" + demo["project_id"], token, method="GET").status_code
        == 200
    )
    history = request(
        base,
        "/api/v1/findings/" + demo["finding_id"] + "/review-revisions?limit=5",
        token,
        method="GET",
    )
    assert history.status_code == 200 and len(history.json()["items"]) == 2
    triage = request(base, "/api/v1/triage-runs/" + demo["triage_id"], token, method="GET").json()
    assert triage["assessment"]["reason"] == "evidence_supported"
    restored = request(
        base, "/api/v1/scan-runs/" + demo["scan_id"] + "/export?format=json", token, method="GET"
    )
    original_token = dotenv_values(ROOT / ".env")["ASP_API_TOKEN"]
    original = request(
        "http://127.0.0.1:18081",
        "/api/v1/scan-runs/" + demo["scan_id"] + "/export?format=json",
        original_token,
        method="GET",
    )
    assert (
        restored.status_code == original.status_code == 200 and restored.content == original.content
    )
    checks["latest_restored_demo_scan_triage_and_review_relationships"] = True
    checks["latest_actual_api_source_verified_export_matches_development"] = True
    receipt = json.loads(
        (ROOT / ".cache/phase7-backup-latest.json").read_text(encoding="utf-8-sig")
    )
    manifest = verify_bundle(
        ROOT / ".local/backups/phase7" / receipt["key"], receipt["manifest_digest"]
    )
    assert latest.state() == manifest["tables"]
    checks["latest_queries_did_not_mutate_restored_tables"] = True
    acl_script = """
    $acl=Get-Acl -LiteralPath '.local/backups/phase7'
    $sidType=[System.Security.Principal.SecurityIdentifier]
    $allowed=@([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')
    $unexpected=@($acl.Access | Where-Object {
        $_.IdentityReference.Translate($sidType).Value -notin $allowed
    })
    @{
        protected=$acl.AreAccessRulesProtected
        unexpected_principals=$unexpected.Count
        entries=@($acl.Access).Count
    } | ConvertTo-Json -Compress
    """
    acl = json.loads(
        subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", acl_script], cwd=ROOT, text=True
        )
    )
    assert acl["protected"] and acl["unexpected_principals"] == 0 and acl["entries"] == 2
    checks["private_backup_acl_restricts_access_to_operator_and_system"] = True
    assert request("http://127.0.0.1:18082", "/", method="GET").status_code == 200
    checks["final_local_dashboard_serves_successfully"] = True
    for database in [previous, clean, latest]:
        run([*database.compose, "stop", "api", "worker", "triage-worker", "db"])
        assert not run(
            [
                "docker",
                "ps",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + database.project,
            ]
        ).strip()
    run(["docker", "compose", "-p", "asp-phase1-test", "--profile", "test", "stop", "test-db"])
    checks["all_phase7_disposable_services_stopped_without_volume_removal"] = True
    evidence = {
        "checks": checks,
        "environments": environments,
        "backup_acl": acl,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "retained_development_running": True,
        "disposable_volumes_and_spools_preserved": True,
    }
    (ROOT / "docs/phase7/environment-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"environment_checks_passed": len(checks), "failed": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
