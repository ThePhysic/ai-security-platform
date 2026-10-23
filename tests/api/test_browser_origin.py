"""Phase 6 exact browser origin contract; auth and review preflight remain independent."""

import pytest
from fastapi.testclient import TestClient

from ai_security_platform.api.app import create_app

pytestmark = pytest.mark.api


def test_dashboard_exact_origin_requires_bearer_and_review_preflight(settings):
    frontend = "http://127.0.0.1:18082"
    app = create_app(settings.model_copy(update={"allowed_origins": [frontend]}))
    route = "/api/v1/findings/00000000-0000-0000-0000-000000000000/review"
    with TestClient(app, base_url="http://localhost:8000") as client:
        response = client.get(route, headers={"Origin": frontend})
        assert response.status_code == 401
        assert response.headers["access-control-allow-origin"] == frontend
        preflight = client.options(
            route,
            headers={
                "Origin": frontend,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert preflight.status_code == 204
        for origin in ("http://127.0.0.1:18083", "http://localhost:18082", "null"):
            denied = client.get(route, headers={"Origin": origin})
            assert denied.status_code == 403
            assert "access-control-allow-origin" not in denied.headers
        internal = client.options(
            "/internal/v1/launcher/claim",
            headers={"Origin": frontend, "Access-Control-Request-Method": "POST"},
        )
        assert internal.status_code == 403
