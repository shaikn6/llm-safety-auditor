# syntax=docker/dockerfile:1

# ---- builder: install Python dependencies into an isolated virtualenv ----
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

# ---- production: runtime image, application code only, non-root ----
FROM python:3.12-slim AS production

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DATABASE_URL=sqlite:///./data/llm_safety_auditor.db

RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --no-create-home app

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

# Application packages only (no tests, docs, screenshots or tooling config).
COPY --chown=app:app api/ ./api/
COPY --chown=app:app attacks/ ./attacks/
COPY --chown=app:app auditor/ ./auditor/
COPY --chown=app:app ci/ ./ci/
COPY --chown=app:app replay/ ./replay/
COPY --chown=app:app scoring/ ./scoring/
COPY --chown=app:app src/ ./src/
COPY --chown=app:app dashboard/ ./dashboard/

RUN mkdir -p /app/data && chown app:app /app /app/data

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# APP_ENV=production: POST routes return 503 until API_KEYS is set.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
