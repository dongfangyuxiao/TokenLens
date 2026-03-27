FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN mkdir -p /app/data/reports /app/data/synced_repos

EXPOSE 8000

ENV BASE_URL=http://localhost:8000 \
    DB_PATH=/app/data/audit.db \
    REPORTS_DIR=/app/data/reports \
    SYNC_ROOT=/app/data/synced_repos \
    REPORTS_REQUIRE_AUTH=1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
