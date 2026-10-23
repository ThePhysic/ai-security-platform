"""Real persisted findings exported through authenticated HTTP and CLI protocol."""

import json
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient

from ai_security_platform.cli.workflow import all_findings, finish
from ai_security_platform.domain.intake import ScanSubmission
from ai_security_platform.jobs.controller import Controller
from ai_security_platform.reporting.policy import Policy
from ai_security_platform.storage.intake import accept_scan
from ai_security_platform.storage.session import session_factory
from tests.postgres.test_intake import AUTH
from tests.postgres.test_intake import intake as intake_fixture
from tests.postgres.test_orchestration import drain

intake = intake_fixture
pytestmark = pytest.mark.postgres
SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"


def test_persisted_export_policy_pagination_and_fail_closed_source(
    pg_runtime, pg_session, intake, monkeypatch, tmp_path
):
    engine, _, settings = pg_runtime
    app, store, _, _, body = intake
    parent = accept_scan(
        pg_session, settings, ScanSubmission.model_validate(body), "reporting", "reporting"
    )
    drain(Controller(session_factory(engine), settings), store)
    path = "/api/v1/scan-runs/" + str(parent.id)
    monkeypatch.chdir(tmp_path)
    with TestClient(app, base_url="http://localhost:8000") as client:
        assert client.get(path + "/export").status_code == 401

        def protocol(base, url, **kwargs):
            result = client.get(url, headers=AUTH)
            assert result.status_code == 200
            return result.json()

        report = protocol("local", path + "/export?format=json")
        assert len(report["findings"]) == 1 and report["findings"][0]["synthetic"]
        assert client.get(path + "/export?format=json", headers=AUTH).json() == report
        jsonschema.validate(report, json.loads((SCHEMAS / "report-v1.json").read_text()))
        sarif = client.get(path + "/export?format=sarif", headers=AUTH)
        assert sarif.headers["content-type"] == "application/sarif+json"
        schema = json.loads((SCHEMAS / "sarif-2.1.0.json").read_text())
        jsonschema.validators.validator_for(schema)(schema).validate(sarif.json())
        assert sarif.json()["runs"][0]["properties"]["synthetic"]
        page = all_findings(protocol, "local", str(parent.id), 1, 2)
        assert len(page["items"]) == 1 and page["next_cursor"] is None
        assert finish(protocol, "local", str(parent.id), Policy())[1] == 2
        policy = Policy(required_scanners=["fake-patterns", "fake-config"], allow_synthetic=True)
        result, code = finish(
            protocol, "local", str(parent.id), policy, name="diagnostic", format="sarif"
        )
        assert code == 0 and result["policy"]["synthetic_diagnostic"]
        assert (tmp_path / ".local/reports/diagnostic.sarif").is_file()
        # A later source verification failure may never yield a plausible clean report.
        monkeypatch.setattr(store, "verify", lambda *args: (_ for _ in ()).throw(ValueError()))
        rejected = client.get(path + "/export", headers=AUTH)
        assert rejected.status_code == 409
        assert rejected.json()["code"] == "export_evidence_invalid"
