# nginx-ipwatch

Tails an Nginx access log, performs WHOIS lookups on newly seen IP addresses, and persists results to SQLite. Includes a web UI for browsing and filtering the data.

## What it tracks

| Column | Description |
|--------|-------------|
| `ip` | IP address (IPv4 or IPv6) |
| `network` | CIDR block from WHOIS (e.g. `202.46.32.0/19`) |
| `country` | Country of registration (ISO code) |
| `requests` | Running count of requests from this IP |
| `last_seen` | UTC timestamp of most recent request |

### How IPs are resolved

Each new IP is resolved in this order, stopping at the first hit:

1. **Private** — RFC-1918 / loopback / link-local are stored as `private` with no lookup.
2. **Network cache** — an IP inside an already-resolved CIDR reuses that block's data.
3. **GeoIP** — offline local databases (see below) place the vast majority of IPs *instantly*, giving both country and network with **no network call and no rate limit**.
4. **RDAP/WHOIS** — only IPs GeoIP can't place fall through to a throttled background sweep. Failures are retried with exponential backoff, guarded by a rate-limit circuit breaker. Results feed the network cache, so one lookup resolves a whole block.

Because GeoIP handles the bulk offline, live RDAP traffic (and the rate-limiting it used to cause under scanner floods) is minimal.

Anything none of the four can resolve stays `NULL` and can be resolved by hand — see [Manual lookup](#manual-lookup-when-a-registry-blocks-you).

### Manual lookup (when a registry blocks you)

A registry can **permanently ban** your server from querying it. RIPE does this to a host that has queried too hard, and once it lands both port-43 WHOIS and RDAP stop answering *every* lookup:

```
$ whois 78.61.136.250
%ERROR:201: access denied for 95.216.220.179
% Sorry, access from your host has been permanently
% denied because of a repeated excessive querying.
```

The IPs then look unresolvable even though the data is perfectly public — it's your host that's blocked, not the data. The fix is to let somebody else make the registry query, which is what the **Manual lookup** box and the 🔍 button (shown on any row with no network) in the web UI do. Sources are tried in order:

| Source | Notes |
|--------|-------|
| **RIPEstat** (`stat.ripe.net`) | RIPE's *data* API — a separate service from the banned query service, keyless, IPv4 + IPv6, all RIRs. Its `network-info` call returns the **BGP-announced prefix**, which is more specific than the RIR allocation RDAP reports. |
| **whois.com** | Scrapes the raw registry text they render. Fallback only: IPv4-only, and being HTML it breaks if they restyle the page. |

The more specific prefix is the reason this is worth doing even when you aren't blocked. For `78.61.136.250`, RDAP reports the registry allocation, while RIPEstat reports the routed block — a difference of 32x in how many unrelated hosts get lumped into one `/networks` row:

```
RDAP     78.61.0.0/17, 78.61.128.0/18, 78.61.192.0/21   (inetnum, ~32k addresses)
RIPEstat 78.61.136.0/22                                 (route, AS8764 — stored)
```

A lookup writes:

- the **queried IP** — overwritten unconditionally; asking for it explicitly means the manual answer beats whatever GeoIP guessed
- every **unresolved IP in the same block** (`network IS NULL`) — filled in, so one click clears a whole CIDR from the backlog. Already-resolved rows are left alone, so a click can't silently rewrite data you didn't ask about.

Results reach the watcher too: it re-primes its network cache from the database before each sweep, so IPs logged *later* in a manually-resolved block resolve from cache without a lookup of their own.

Looking up an IP the log has never seen is allowed (handy for checking a block), but nothing is stored — `ip_access` records observed traffic, not WHOIS answers. If a source returns a country but no network, the country is stored and `network` stays `NULL` so the automatic sweep can still improve it later.

If you're banned, it's also worth [requesting an unblock from RIPE](https://docs.db.ripe.net/FAQ#why-did-i-receive-an-error-201-access-denied) and lowering `BACKFILL_BATCH` / raising `WHOIS_DELAY` so it doesn't happen again.

| Env var | Default | Meaning |
|---------|---------|---------|
| `PROXY_SOURCES` | `ripestat,whoiscom` | Sources to try, in order. Drop one to disable it. |
| `PROXY_LOOKUP_TIMEOUT` | `15` | Seconds per HTTP request. |
| `RIPESTAT_SOURCEAPP` | `nginx-ipwatch` | Identifies this app to RIPEstat. |
| `LOOKUP_MIN_INTERVAL` | `2.0` | Minimum seconds between lookups (per web worker). Guards against a held-down button, not an access control. |

### GeoIP databases

The Docker image fetches offline databases from [sapics/ip-location-db](https://github.com/sapics/ip-location-db) at build time:

- **Country** — [DB-IP Lite](https://db-ip.com) (`dbip-country-*-num.csv`), a geolocation database.
- **Network / ASN** — [IPtoASN](https://iptoasn.com) (`iptoasn-asn-*-num.csv`, public domain); the matched range gives the network CIDR.

They're pure CSV loaded in-process — no extra Python dependency. To refresh them, rebuild with `docker compose build --no-cache`. To use different sources (e.g. GeoLite2), change the `ADD` URLs in the `Dockerfile` and the `GEOIP_COUNTRY_DB` / `GEOIP_ASN_DB` env vars (each a comma-separated list of CSV paths; IPv4 and IPv6 files can both be listed). If neither var points to a readable file, GeoIP is disabled and everything falls back to RDAP.

> Country data © [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). ASN data from [iptoasn.com](https://iptoasn.com) (public domain).

## Services

| Service | Description | Default port |
|---------|-------------|-------------|
| `watcher` | Tails the log and writes to SQLite | — |
| `web` | Flask UI served by gunicorn | `5000` |

Both share the same `./data` volume.

## Docker (recommended)

```bash
# Build and start both services
docker compose up -d

# Follow watcher logs (WHOIS lookups appear here)
docker compose logs -f watcher

# Stop everything
docker compose down
```

Open **http://localhost:5000** in your browser.

The SQLite database is written to `./data/nginx_ips.db`.

### Customising paths

Edit `docker-compose.yml` — for example to watch a non-default log file:

```yaml
services:
  watcher:
    volumes:
      - /var/log/nginx:/logs:ro
    environment:
      LOG_PATH: /logs/mysite.access.log
```

Or override at runtime without changing the file:

```bash
docker compose run --rm watcher python -u nginx-ipwatch.py /logs/other.log /data/other.db
```

## Web UI features

- **Two views** — per-IP (`/`) and per-network (`/networks`, aggregated by CIDR to surface coordinated activity from many IPs in one block)
- **Stats bar** — unique IP count, total request count, country count
- **IP / network search** — substring match across recorded IPs or networks
- **Country filter** — dropdown of all seen countries (with flags); clicking a badge in the table filters by that country
- **Country flags** — flag emoji shown next to each country code
- **Time-period filter** — scope results to an activity window by *last seen*: last hour, 3h/6h/12h/24h, today, yesterday, or last 7 days
- **Exclude filters** — hide specific IPs, networks, or countries (comma-separated, multi-value); combines with the include filters
- **Sortable columns** — click any column header to sort asc/desc
- **Pagination** — 50 rows per page
- **Auto-refresh** — optional 30-second page reload toggle
- **Manual lookup** — resolve an IP through a third-party WHOIS source and store the result, for when a registry has blocked automatic lookups ([details](#manual-lookup-when-a-registry-blocks-you))

## Running without Docker

Python 3.10+ required.

```bash
pip install -r requirements.txt

# watcher (terminal 1)
python nginx-ipwatch.py /var/log/nginx/access.log ./nginx_ips.db

# web UI (terminal 2)
DB_PATH=./nginx_ips.db gunicorn web:app --bind 0.0.0.0:5000
```

GeoIP is optional here — without it the watcher falls back to RDAP. To enable it, download the CSVs and point the env vars at them:

```bash
base=https://github.com/sapics/ip-location-db/releases/download/latest
mkdir -p geoip && cd geoip
for f in dbip-country-ipv4-num.csv dbip-country-ipv6-num.csv \
         iptoasn-asn-ipv4-num.csv iptoasn-asn-ipv6-num.csv; do curl -sLO "$base/$f"; done
cd ..

GEOIP_COUNTRY_DB=geoip/dbip-country-ipv4-num.csv,geoip/dbip-country-ipv6-num.csv \
GEOIP_ASN_DB=geoip/iptoasn-asn-ipv4-num.csv,geoip/iptoasn-asn-ipv6-num.csv \
python nginx-ipwatch.py /var/log/nginx/access.log ./nginx_ips.db
```

## Querying SQLite directly

```bash
# Top talkers
sqlite3 data/nginx_ips.db \
  "SELECT ip, country, network, requests, last_seen FROM ip_access ORDER BY requests DESC LIMIT 20;"

# All IPs from a specific country
sqlite3 data/nginx_ips.db \
  "SELECT ip, network, requests FROM ip_access WHERE country = 'CN' ORDER BY requests DESC;"

# IPs seen in the last hour
sqlite3 data/nginx_ips.db \
  "SELECT ip, country, requests FROM ip_access WHERE last_seen >= datetime('now', '-1 hour');"
```

## Notes

- The watcher starts at the **end** of the log file — it tracks new entries only, not history.
- Log rotation is handled automatically via inode detection.
- The web process opens the database read-only for all browsing. Its one write path is the manual lookup (`POST /lookup`), which uses a separate writable connection.
- The UI has no authentication and the manual lookup makes outbound HTTP requests on demand, so keep it on a trusted network or behind your own auth — don't expose port 5000 to the internet.
- All timestamps are stored in UTC.

## License

Released under the [MIT License](LICENSE). Made by [19 points](https://19points.lv/).
