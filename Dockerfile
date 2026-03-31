FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN mkdir -p /app/data/reports /app/data/synced_repos \
    && adduser --disabled-password --gecos '' tokenlens \
    && chown -R tokenlens:tokenlens /app

USER tokenlens
EXPOSE 8000

ENV BASE_URL=http://localhost:8000 \
    DB_PATH=/app/data/audit.db \
    REPORTS_DIR=/app/data/reports \
    SYNC_ROOT=/app/data/synced_repos \
    REPORTS_REQUIRE_AUTH=1 \
    SESSION_TTL_MINUTES=720 \
    SESSION_IDLE_MINUTES=120

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
