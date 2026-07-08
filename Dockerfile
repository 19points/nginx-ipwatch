FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx-ipwatch.py web.py whois_util.py backfill.py ./
COPY templates/ templates/

# /logs — mount your Nginx log directory here (read-only)
# /data — mount a host directory here to persist the SQLite database
VOLUME ["/logs", "/data"]

ENV LOG_PATH=/logs/access.log
ENV DB_PATH=/data/nginx_ips.db
