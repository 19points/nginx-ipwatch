FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx-ipwatch.py web.py whois_util.py geoip_util.py backfill.py ./
COPY templates/ templates/

# Offline GeoIP tables from sapics/ip-location-db, fetched at build time so the
# watcher resolves country + network locally (no RDAP call, no rate limit) for
# the vast majority of IPs. Country: DB-IP Lite (CC BY 4.0 — attributed in the
# README/UI). Network CIDR: IPtoASN (public domain). To swap sources, change the
# URLs below + the GEOIP_* env vars.
#
# Fetched via a RUN (stdlib urllib — slim has no curl/wget) rather than ADD:
# ADD content-addresses remote URLs and can serve stale data on a warm cache,
# whereas GEOIP_CACHEBUST is part of this RUN's cache key, so changing it always
# forces a fresh download. CI passes a unique value per run
# (.github/workflows/build-image.yaml); locally it defaults to `dev` and stays
# cached — override with --build-arg GEOIP_CACHEBUST=$(date +%s) to refresh.
ARG GEOIP_CACHEBUST=dev
RUN echo "GeoIP data token: ${GEOIP_CACHEBUST}" \
 && python -c "import os, urllib.request; \
os.makedirs('/geoip', exist_ok=True); \
base='https://github.com/sapics/ip-location-db/releases/download/latest'; \
files=['dbip-country-ipv4-num.csv','dbip-country-ipv6-num.csv','iptoasn-asn-ipv4-num.csv','iptoasn-asn-ipv6-num.csv']; \
[urllib.request.urlretrieve(base+'/'+f, '/geoip/'+f) for f in files]; \
print('fetched', len(files), 'GeoIP files')"

# /logs — mount your Nginx log directory here (read-only)
# /data — mount a host directory here to persist the SQLite database
VOLUME ["/logs", "/data"]

ENV LOG_PATH=/logs/access.log
ENV DB_PATH=/data/nginx_ips.db
ENV GEOIP_COUNTRY_DB=/geoip/dbip-country-ipv4-num.csv,/geoip/dbip-country-ipv6-num.csv
ENV GEOIP_ASN_DB=/geoip/iptoasn-asn-ipv4-num.csv,/geoip/iptoasn-asn-ipv6-num.csv
