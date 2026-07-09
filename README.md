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

WHOIS is looked up only once per IP via RDAP. Private/RFC-1918 addresses are stored as `private` with no network round-trip.

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

- **Stats bar** — unique IP count, total request count, country count
- **IP search** — substring match across all recorded IPs
- **Country filter** — dropdown of all seen countries; clicking a badge in the table filters by that country
- **Sortable columns** — click any column header to sort asc/desc
- **Pagination** — 50 rows per page
- **Auto-refresh** — optional 30-second page reload toggle

## Running without Docker

Python 3.10+ required.

```bash
pip install -r requirements.txt

# watcher (terminal 1)
python nginx-ipwatch.py /var/log/nginx/access.log ./nginx_ips.db

# web UI (terminal 2)
DB_PATH=./nginx_ips.db gunicorn web:app --bind 0.0.0.0:5000
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
- The web process opens the database read-only; only the watcher ever writes to it.
- All timestamps are stored in UTC.

## License

Released under the [MIT License](LICENSE). Made by [19 points](https://19points.lv/).
