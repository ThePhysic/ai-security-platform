"""Public metadata advisory/provenance audit. Never transmit source or credentials."""

import hashlib
import json
import re
import subprocess
import tomllib
import urllib.request
from datetime import UTC, datetime

import yaml

from runner.boundary import DockerBoundary
from runner.prepare import sha
from scripts.lifecycle import ROOT


def fetch(url, body=None):
    request = urllib.request.Request(
        url,
        data=None if body is None else json.dumps(body).encode(),
        headers={"User-Agent": "asp-phase7-public-provenance", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    assert len(raw) <= 4 * 1024 * 1024
    return json.loads(raw)


def main():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    before = tomllib.loads(
        subprocess.check_output(["git", "show", "HEAD:uv.lock"], cwd=ROOT, text=True)
    )
    versions = {p["name"]: p["version"] for p in lock["package"]}
    assert versions == {p["name"]: p["version"] for p in before["package"]}
    constraints = pyproject["tool"]["uv"]["build-constraint-dependencies"]
    assert len(constraints) == 6
    assert lock["manifest"]["build-constraints"]
    queries = {
        ("PyPI", p["name"], p["version"])
        for p in lock["package"]
        if "registry" in p.get("source", {})
    }
    for row in constraints:
        name, version = row["requirement"].split("==")
        assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in row["hashes"])
        queries.add(("PyPI", name, version))
    registry = json.loads((ROOT / "policies/scanners.lock.json").read_text())
    queries.add(("PyPI", "semgrep", registry["scanners"]["semgrep"]["version"]))
    queries.add(("Go", "github.com/aquasecurity/trivy", "v0.76.1"))
    ordered = sorted(queries)
    result = fetch(
        "https://api.osv.dev/v1/querybatch",
        {
            "queries": [
                {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                for ecosystem, name, version in ordered
            ]
        },
    )
    advisories = [
        {
            "ecosystem": ecosystem,
            "package": name,
            "version": version,
            "advisories": result.get("vulns", []),
        }
        for (ecosystem, name, version), result in zip(ordered, result["results"], strict=True)
    ]
    unexpected = [a for row in advisories for a in row["advisories"] if a["id"] != "GO-2026-4919"]
    assert not unexpected, "New advisory requires explicit applicability/severity review"
    (ROOT / "docs/phase7/dependency-advisories.json").write_text(
        json.dumps(
            {
                "recorded_at": datetime.now(UTC).isoformat(),
                "service": "https://api.osv.dev/v1/querybatch",
                "source": "Public package metadata only; no source/credential transmission",
                "packages": advisories,
                "queried": len(advisories),
                "advisory_matches": sum(len(row["advisories"]) for row in advisories),
                "advisory_disposition": {
                    "GO-2026-4919": (
                        "Broad OSV range retained. Upstream affected releases "
                        "differ; see FINDINGS.md for primary-source applicability review."
                    )
                },
                "scope": "Known advisories only; not an exhaustive scanner-transitive SBOM audit",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    actions = []
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        assert workflow["permissions"] == {"contents": "read"}
        assert set(workflow["on"]) == {"workflow_dispatch"}
        for job in workflow["jobs"].values():
            assert "default_branch" in job["if"]
            for step in job["steps"]:
                if "uses" not in step:
                    continue
                match = re.fullmatch(
                    r"(actions/(?:checkout|upload-artifact))@([0-9a-f]{40})", step["uses"]
                )
                assert match
                repo, commit = match.groups()
                metadata = fetch("https://api.github.com/repos/" + repo + "/commits/" + commit)
                assert metadata["sha"] == commit
                if repo == "actions/checkout":
                    assert step["with"]["persist-credentials"] == "false"
                actions.append(
                    {
                        "workflow": path.name,
                        "repository": repo,
                        "commit": commit,
                        "official_commit_resolves": True,
                    }
                )
    database = registry["database"]
    asset = ROOT / ".local/scanner-assets" / database["asset_key"] / "db"
    assert all(sha(asset / name) == value for name, value in database["files"].items())
    boundary = DockerBoundary(ROOT / ".local/snapshot-spool")
    images = {
        name: boundary.image_identity(value["image"])
        for name, value in registry["scanners"].items()
    }
    node = json.loads((ROOT / "web/package-lock.json").read_text())
    assert all(
        p.get("resolved", "").startswith("https://registry.npmjs.org/")
        and p.get("integrity", "").startswith("sha512-")
        for name, p in node["packages"].items()
        if name
    )
    assert "ignore-scripts=true" in (ROOT / "web/.npmrc").read_text()
    hashes = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
        for p in [
            "uv.lock",
            "pyproject.toml",
            "Dockerfile",
            "compose.yaml",
            "web/package-lock.json",
            "policies/scanners.lock.json",
        ]
    }
    checks = {
        "runtime_python_versions_unchanged": True,
        "six_build_dependencies_version_and_hash_pinned": True,
        "build_hashes_recorded_in_uv_lock": True,
        "known_advisories_reviewed": True,
        "least_privilege_manual_workflows": True,
        "official_actions_pinned_and_resolve": True,
        "immutable_scanner_image_ids_match": True,
        "offline_database_bytes_match_provenance": True,
        "npm_registry_integrities_and_disabled_install_hooks": True,
    }
    report = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "actions": actions,
        "scanner_images": images,
        "database": database,
        "database_bytes": (asset / "trivy.db").stat().st_size,
        "input_sha256": hashes,
        "passed": len(checks),
        "failed": 0,
        "skipped": 0,
        "limits": (
            "No signature assurance or exhaustive scanner-image CVE claim; "
            "live workflows and hosted providers remain untested"
        ),
    }
    (ROOT / "docs/phase7/supply-chain-evidence.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {"supply_chain_checks_passed": len(checks), "public_version_queries": len(advisories)}
        )
    )


if __name__ == "__main__":
    main()
