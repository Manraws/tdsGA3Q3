FROM python:3.11-slim

WORKDIR /app

# Install system libraries needed for psycopg2, cryptography, and health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistent storage mount point for SQLite if Postgres is not used
RUN mkdir -p /data

EXPOSE 8000

ENV PORT=8000
ENV HOST=0.0.0.0

CMD ["python", "app.py"]
