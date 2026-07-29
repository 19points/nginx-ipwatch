FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx-ipwatch.py web.py whois_util.py geoip_util.py backfill.py ./
COPY templates/ templates/

# Offline GeoIP tables from sapics/ip-location-db, fetched at build time so the
# watcher resolves country + network locally (no RDAP call, no rate limit) for
# the vast majority of IPs. Country: DB-IP Lite (CC BY 4.0 — attributed in the
# README/UI). Network CIDR: IPtoASN (public domain). To refresh, rebuild with
# --no-cache; to swap sources, change these URLs + the GEOIP_* env vars.
ADD https://github.com/sapics/ip-location-db/releases/download/latest/dbip-country-ipv4-num.csv /geoip/
ADD https://github.com/sapics/ip-location-db/releases/download/latest/dbip-country-ipv6-num.csv /geoip/
ADD https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-asn-ipv4-num.csv  /geoip/
ADD https://github.com/sapics/ip-location-db/releases/download/latest/iptoasn-asn-ipv6-num.csv  /geoip/

# /logs — mount your Nginx log directory here (read-only)
# /data — mount a host directory here to persist the SQLite database
VOLUME ["/logs", "/data"]

ENV LOG_PATH=/logs/access.log
ENV DB_PATH=/data/nginx_ips.db
ENV GEOIP_COUNTRY_DB=/geoip/dbip-country-ipv4-num.csv,/geoip/dbip-country-ipv6-num.csv
ENV GEOIP_ASN_DB=/geoip/iptoasn-asn-ipv4-num.csv,/geoip/iptoasn-asn-ipv6-num.csv
