"""Static workflow constraints plus a pinned, offline schema provenance check."""

import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]


def test_manual_trusted_workflows_and_artifact_only_permissions():
    for filename in ("ci.yml", "developer-guardrails.yml"):
        raw = (ROOT / ".github/workflows" / filename).read_text()
        workflow = yaml.safe_load(raw)
        assert set(workflow.get("on", workflow.get(True))) == {"workflow_dispatch"}
        assert workflow["permissions"] == {"contents": "read"}
        assert "secrets." not in raw and "pull_request_target" not in raw
        for job in workflow["jobs"].values():
            assert "github.event.repository.default_branch" in job["if"]
            assert job["timeout-minutes"] <= 20
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(
                        r"actions/(checkout|upload-artifact)@[0-9a-f]{40}", step["uses"]
                    )
                    if "checkout@" in step["uses"]:
                        assert step["with"]["persist-credentials"] is False
    raw = (ROOT / ".github/workflows/developer-guardrails.yml").read_text()
    assert "--network none" in raw and "--read-only" in raw and "--cap-drop ALL" in raw
    assert "upload-sarif" not in raw and "security-events" not in raw
    assert "artifacts/guardrails.sarif" in raw and "retention-days: 7" in raw
    assert "npm " not in raw and "pip install" not in raw


def test_vendored_sarif_schema_is_pinned_and_has_no_network_refs():
    root = ROOT / "tests/schemas"
    record = json.loads((root / "provenance.json").read_text())
    raw = (root / "sarif-2.1.0.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == record["sha256"]
    pending = [json.loads(raw)]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if "$ref" in node:
                assert node["$ref"].startswith("#/")
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
