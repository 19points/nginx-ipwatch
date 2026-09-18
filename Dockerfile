FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY nginx-ipwatch.py web.py whois_util.py geoip_util.py proxy_util.py provider_util.py hits_util.py backfill.py ./
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

# Provider/crawler range lists, fetched at build time like the GeoIP tables.
# These are the files the operators publish themselves, so an IP inside one is
# a fact rather than a guess. Azure and Facebook are absent deliberately:
# Microsoft's ServiceTags download has no stable URL (the filename carries a
# weekly date) and Facebook publishes via whois, so both are identified from
# the ASN table instead — see provider_util.
#
# A missing or failed file only costs precision (that provider falls back to
# ASN matching), so the fetch must not fail the build: each URL is tried and
# skipped on error. Shares GEOIP_CACHEBUST's refresh semantics.
ARG PROVIDER_CACHEBUST=dev
RUN echo "Provider data token: ${PROVIDER_CACHEBUST}" \
 && python -c "import os, urllib.request; \
os.makedirs('/providers', exist_ok=True); \
srcs={'googlebot.json':'https://developers.google.com/static/search/apis/ipranges/googlebot.json', \
'special-crawlers.json':'https://developers.google.com/static/search/apis/ipranges/special-crawlers.json', \
'bingbot.json':'https://www.bing.com/toolbox/bingbot.json', \
'cloudflare-v4.txt':'https://www.cloudflare.com/ips-v4', \
'cloudflare-v6.txt':'https://www.cloudflare.com/ips-v6', \
'aws.json':'https://ip-ranges.amazonaws.com/ip-ranges.json', \
'gcp.json':'https://www.gstatic.com/ipranges/cloud.json', \
'goog.json':'https://www.gstatic.com/ipranges/goog.json'}; \
ok=[]; \
exec('for f, u in srcs.items():\n try:\n  urllib.request.urlretrieve(u, \'/providers/\'+f); ok.append(f)\n except Exception as e:\n  print(\'skipped\', f, e)'); \
print('fetched', len(ok), 'of', len(srcs), 'provider files')"

# /logs — mount your Nginx log directory here (read-only)
# /data — mount a host directory here to persist the SQLite database
VOLUME ["/logs", "/data"]

ENV LOG_PATH=/logs/access.log
ENV DB_PATH=/data/nginx_ips.db
ENV GEOIP_COUNTRY_DB=/geoip/dbip-country-ipv4-num.csv,/geoip/dbip-country-ipv6-num.csv
ENV GEOIP_ASN_DB=/geoip/iptoasn-asn-ipv4-num.csv,/geoip/iptoasn-asn-ipv6-num.csv
ENV PROVIDER_DIR=/providers
