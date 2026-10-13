FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /uvx /bin/
ENV UV_NO_DEV=1 UV_PYTHON_DOWNLOADS=0 CTU_PROJECT_ROOT=/app PATH="/app/.venv/bin:$PATH"
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
ARG UV_EXTRA=service
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --extra "${UV_EXTRA}"
COPY src ./src
COPY web ./web
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --extra "${UV_EXTRA}"
CMD ["uvicorn", "threat_detection.service:app", "--host", "0.0.0.0", "--port", "8765"]
