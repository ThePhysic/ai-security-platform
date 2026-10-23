"""Choose accepted controlled records; no source acquisition, scanner or provider calls."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_security_platform.cli.main import call_api  # noqa: E402
from scripts.validate_local import DEV, run  # noqa: E402


def main():
    base = "http://127.0.0.1:18081"
    probe = ROOT / "web/.env.phase6-probe"
    marker = b"phase6-controlled-private-probe\n"
    if probe.exists():
        assert not probe.is_symlink() and probe.read_bytes() in {
            marker,
            marker.replace(b"\n", b"\r\n"),
        }
    else:
        with probe.open("xb") as stream:
            stream.write(marker)
    cache = ROOT / ".cache/phase6-browser-fixture.json"
    previous = json.loads((ROOT / "docs/phase5/live-evidence.json").read_text())
    scan_id = previous["real_workload"]["samples"][-1]["scan_id"]
    scan = call_api(base, "/api/v1/scan-runs/" + scan_id)
    findings = call_api(base, "/api/v1/scan-runs/" + scan_id + "/findings?limit=100")["items"]
    target = next(row for row in findings if row["rule_id"] == "platform.python.eval")
    candidate = next(
        row
        for row in findings
        if row["rule_id"].startswith("platform.")
        and row["id"] != target["id"]
        and call_api(base, "/api/v1/findings/" + row["id"] + "/review")["revision"] == 0
    )
    scans = call_api(base, "/api/v1/scan-runs?project=" + scan["project_id"] + "&limit=100")[
        "items"
    ]
    fake = next(row for row in scans if row["profile_id"] == "fake-v1")
    if cache.exists():
        empty_id = json.loads(cache.read_text())["empty_project"]
    else:
        empty_id = call_api(
            base, "/api/v1/projects", {"name": "Phase 6 controlled empty UI project"}
        )["id"]
    partial = json.loads(
        run(
            *DEV,
            "exec",
            "-T",
            "db",
            "psql",
            "-U",
            "asp_owner",
            "-d",
            "asp_dev",
            "-At",
            "-c",
            "SELECT row_to_json(s)::text FROM scan_runs s WHERE status='partial' "
            "ORDER BY created_at DESC LIMIT 1",
        )
    )
    fixture = {
        "project": scan["project_id"],
        "scan": scan_id,
        "finding": target["id"],
        "rule": target["rule_id"],
        "snapshot": scan["snapshot_id"],
        "review_finding": candidate["id"],
        "review_rule": candidate["rule_id"],
        "unsupported_rule": next(
            row["rule_id"] for row in findings if row["category"] == "vulnerability"
        ),
        "fake_scan": fake["id"],
        "empty_project": empty_id,
        "partial_scan": partial["id"],
        "partial_project": partial["project_id"],
    }
    cache.write_text(json.dumps(fixture, indent=2) + "\n")
    print(json.dumps({"controlled_fixture_ready": True, "persisted_real_findings": len(findings)}))


if __name__ == "__main__":
    main()
