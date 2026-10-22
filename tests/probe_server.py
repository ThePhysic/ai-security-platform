"""Test-only live API for physical restart verification."""

import os

import uvicorn

from tests.conftest import TOKEN

if __name__ == "__main__":
    os.environ["ASP_DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
    os.environ["ASP_API_TOKEN"] = TOKEN
    os.environ["ASP_ALLOWED_HOSTS"] = '["127.0.0.1:18082","localhost:18082","127.0.0.1:8000"]'
    os.environ["ASP_ALLOWED_ORIGINS"] = '["http://127.0.0.1:18082"]'
    uvicorn.run(
        "ai_security_platform.main:create_app",
        factory=True,
        host="0.0.0.0",
        port=8000,
        access_log=False,
        proxy_headers=False,
    )
