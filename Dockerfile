FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv
FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS runtime
COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy UV_CACHE_DIR=/tmp/uv RUFF_CACHE_DIR=/tmp/ruff MYPY_CACHE_DIR=/tmp/mypy
WORKDIR /app
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home app
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
COPY policies ./policies
RUN uv sync --frozen --no-dev --no-editable
USER 10001:10001
EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "ai_security_platform.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-server-header", "--no-proxy-headers", "--timeout-keep-alive", "5"]

FROM runtime AS tests
USER root
RUN uv sync --frozen --no-editable
COPY tests ./tests
COPY evaluation ./evaluation
COPY scripts ./scripts
COPY Dockerfile compose.yaml .dockerignore ./
COPY .github/workflows/ci.yml ./.github/workflows/ci.yml
COPY .github/workflows/developer-guardrails.yml ./.github/workflows/developer-guardrails.yml
USER 10001:10001
CMD ["uv", "run", "--no-sync", "pytest", "-m", "postgres"]
