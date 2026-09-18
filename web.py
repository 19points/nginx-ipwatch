#!/usr/bin/env python3
"""
web.py — read-only Flask UI for the nginx-ipwatch SQLite database.

Environment variables:
    DB_PATH   path to the SQLite file  (default /data/nginx_ips.db)
    HOST      bind address             (default 0.0.0.0)
    PORT      bind port                (default 5000)
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import Flask, g, render_template, request

from hits_util import HIT_BUCKET

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/nginx_ips.db")
PER_PAGE = 50
SORT_COLS = {"ip", "network", "country", "requests", "last_seen"}

TS_FMT = "%Y-%m-%d %H:%M:%S"

# Activity-window options (query key -> human label). Picking one restricts
# rows to the IPs/networks active in that window *and* scopes every request
# count to it, by summing the bucketed history in ip_hits. Databases with no
# history yet (written by an older watcher) fall back to filtering on last_seen
# with all-time counts — see hits_available().
PERIODS = {
    "all":       "All time",
    "1h":        "Last hour",
    "3h":        "Last 3 hours",
    "6h":        "Last 6 hours",
    "12h":       "Last 12 hours",
    "24h":       "Last 24 hours",
    "today":     "Today (UTC)",
    "yesterday": "Yesterday (UTC)",
    "7d":        "Last 7 days",
}
_PERIOD_HOURS = {"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24, "7d": 24 * 7}


def _terms(raw: str) -> list:
    """Split a comma-separated exclude field into trimmed, non-empty terms."""
    return [t.strip() for t in raw.split(",") if t.strip()]


def exclude_conditions(xip: str, xnet: str, xcountry: str) -> tuple[list, list]:
    """SQL conditions that drop rows matching any exclude term.

    IP/network use substring (NOT LIKE) to mirror the include search boxes;
    country is exact (NOT IN). NULL network/country (unresolved WHOIS) is kept
    rather than dropped, so an exclude never hides not-yet-looked-up rows.
    """
    conds, params = [], []
    for t in _terms(xip):
        conds.append("ip NOT LIKE ?")
        params.append(f"%{t}%")
    for t in _terms(xnet):
        conds.append("(network IS NULL OR network NOT LIKE ?)")
        params.append(f"%{t}%")
    xc = _terms(xcountry)
    if xc:
        placeholders = ",".join("?" * len(xc))
        conds.append(f"(country IS NULL OR country NOT IN ({placeholders}))")
        params.extend(xc)
    return conds, params


def period_range(period: str) -> tuple:
    """Return (start, end) UTC TS_FMT strings for *period*.

    *end* is None for windows that run up to now. Returns (None, None) for
    'all' or any unknown key. Timestamps sort lexicographically, so the strings
    can be compared directly in SQL.
    """
    now = datetime.now(timezone.utc)
    if period in _PERIOD_HOURS:
        return (now - timedelta(hours=_PERIOD_HOURS[period])).strftime(TS_FMT), None
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0).strftime(TS_FMT), None
    if period == "yesterday":
        end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return (end - timedelta(days=1)).strftime(TS_FMT), end.strftime(TS_FMT)
    return None, None


def period_bounds(period: str) -> tuple[list, list]:
    """SQL conditions restricting last_seen to *period* (no-history fallback)."""
    start, end = period_range(period)
    if start is None:
        return [], []
    if end is None:
        return ["last_seen >= ?"], [start]
    return ["last_seen >= ? AND last_seen < ?"], [start, end]


def hits_available(db: sqlite3.Connection) -> bool:
    """True if the DB carries any bucketed request history to sum."""
    try:
        return db.execute("SELECT 1 FROM ip_hits LIMIT 1").fetchone() is not None
    except sqlite3.OperationalError:
        return False


def history_start(db: sqlite3.Connection) -> str:
    """Oldest bucket still retained, so the UI can say how far counts reach back."""
    try:
        return db.execute("SELECT MIN(bucket) FROM ip_hits").fetchone()[0] or ""
    except sqlite3.OperationalError:
        return ""


def window_source(start: str, end) -> tuple:
    """FROM clause joining ip_access to its per-IP request count within a window.

    Returns (from_sql, from_params, requests_expr, last_seen_expr, ls_params).
    The subquery aliases its key to `hip` so bare `ip`/`network`/`country`/
    `last_seen` in the callers' filters stay unambiguous.

    The window is snapped outwards to whole buckets: a bucket is included when
    it *starts* at or after the cutoff rounded down, so "last hour" can cover up
    to one extra bucket (HIT_BUCKET seconds) of older traffic.
    """
    conds, params = ["bucket >= ?"], [_floor_bucket(start)]
    if end is not None:
        conds.append("bucket < ?")
        params.append(_floor_bucket(end))
    sub = (
        "(SELECT ip AS hip, SUM(requests) AS hits, MAX(bucket) AS hlast "
        f"FROM ip_hits WHERE {' AND '.join(conds)} GROUP BY ip)"
    )
    if end is None:
        # Window runs to now, so the row's exact last_seen is inside it.
        return f"ip_access JOIN {sub} h ON h.hip = ip", params, "h.hits", "last_seen", []
    # Closed window (yesterday): last_seen may be newer than the window, in
    # which case the latest bucket in it is the best "last seen here" we have.
    ls = "(CASE WHEN last_seen < ? THEN last_seen ELSE h.hlast END)"
    return f"ip_access JOIN {sub} h ON h.hip = ip", params, "h.hits", ls, [end]


def _floor_bucket(ts: str) -> str:
    """Round a TS_FMT timestamp down onto the ip_hits bucket grid."""
    dt = datetime.strptime(ts, TS_FMT).replace(tzinfo=timezone.utc)
    epoch = int(dt.timestamp())
    return datetime.fromtimestamp(epoch - epoch % HIT_BUCKET, timezone.utc).strftime(TS_FMT)

# Network view sorts against aggregate aliases, so map the requested key to the
# safe column/alias it may be interpolated into the ORDER BY as.
NET_SORT_COLS = {
    "network":   "network",
    "country":   "countries",
    "ip_count":  "ip_count",
    "requests":  "total_requests",
    "last_seen": "last_seen",
}


def flag_emoji(code: str) -> str:
    """Render an ISO 3166-1 alpha-2 country code as a flag emoji.

    Maps each letter to its regional-indicator symbol (A -> U+1F1E6). Returns a
    house glyph for our synthetic 'private' country and '' for anything that
    isn't a 2-letter code (empty/unknown), so callers can prepend unconditionally.
    """
    if not code:
        return ""
    if code.lower() == "private":
        return "🏠"
    if len(code) != 2 or not code.isalpha():
        return ""
    code = code.upper()
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(0x1F1E6 + ord(code[1]) - ord("A"))


app.jinja_env.filters["flag"] = flag_emoji


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        try:
            g.db = sqlite3.connect(
                f"file:{DB_PATH}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
        except sqlite3.OperationalError:
            # DB doesn't exist yet — open normally so we can return empty results
            g.db = sqlite3.connect(":memory:")
            g.db.execute("""
                CREATE TABLE ip_access (
                    ip TEXT, network TEXT, country TEXT,
                    requests INTEGER, last_seen TEXT,
                    whois_attempts INTEGER, whois_next_retry TEXT
                )
            """)
            g.db.execute("""
                CREATE TABLE ip_hits (
                    ip TEXT, bucket TEXT, requests INTEGER
                )
            """)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()


@app.route("/")
def index():
    db = get_db()

    search_ip = request.args.get("ip", "").strip()
    country   = request.args.get("country", "").strip()
    network   = request.args.get("network", "").strip()
    period    = request.args.get("period", "all")
    xip       = request.args.get("xip", "").strip()
    xnet      = request.args.get("xnet", "").strip()
    xcountry  = request.args.get("xcountry", "").strip()
    sort      = request.args.get("sort", "requests")
    order     = request.args.get("order", "desc")
    page      = max(1, int(request.args.get("page", 1) or 1))

    period = period if period in PERIODS else "all"
    sort   = sort   if sort   in SORT_COLS else "requests"
    order  = "DESC" if order != "asc" else "ASC"

    # With history available the period is applied by joining the bucketed
    # counts, which both filters the rows and scopes `requests` to the window.
    start, end = period_range(period)
    scoped = start is not None and hits_available(db)
    if scoped:
        source, src_params, req_expr, ls_expr, ls_params = window_source(start, end)
        period_conds, period_params = [], []
    else:
        source, src_params = "ip_access", []
        req_expr, ls_expr, ls_params = "requests", "last_seen", []
        period_conds, period_params = period_bounds(period)

    conditions, params = list(period_conds), list(period_params)
    if search_ip:
        conditions.append("ip LIKE ?")
        params.append(f"%{search_ip}%")
    if country:
        conditions.append("country = ?")
        params.append(country)
    if network:
        conditions.append("network = ?")
        params.append(network)

    xconds, xparams = exclude_conditions(xip, xnet, xcountry)
    conditions += xconds
    params += xparams

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM {source} {where}", src_params + params
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT ip, network, country, {req_expr} AS requests, {ls_expr} AS last_seen "
        f"FROM {source} {where} "
        f"ORDER BY {sort} {order} "
        f"LIMIT ? OFFSET ?",
        ls_params + src_params + params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()

    countries = [
        r[0] for r in db.execute(
            "SELECT DISTINCT country FROM ip_access "
            "WHERE country != '' ORDER BY country"
        ).fetchall()
    ]

    # Stats reflect the selected period (but not the ip/country/network
    # filters), giving a summary of activity within the window.
    pwhere = f"WHERE {' AND '.join(period_conds)}" if period_conds else ""
    stats = db.execute(
        "SELECT COUNT(*) AS total_ips, "
        f"COALESCE(SUM({req_expr}), 0) AS total_requests, "
        "COUNT(DISTINCT country) AS total_countries "
        f"FROM {source} {pwhere}",
        src_params + period_params,
    ).fetchone()

    return render_template(
        "index.html",
        view="ips",
        rows=rows,
        countries=countries,
        stats=stats,
        periods=PERIODS,
        period=period,
        scoped=scoped,
        req_label="Requests" if not scoped else f"Requests ({PERIODS[period].lower()})",
        history_from=history_start(db) if period != "all" else "",
        search_ip=search_ip,
        sel_country=country,
        network=network,
        xip=xip,
        xnet=xnet,
        xcountry=xcountry,
        sort=sort,
        order=order,
        page=page,
        total=total,
        total_pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
        per_page=PER_PAGE,
    )


@app.route("/networks")
def networks():
    """Requests aggregated to the network (CIDR) level.

    A coordinated attack often shows up as many distinct IPs in a single
    network, each with only a request or two — invisible per-IP but obvious
    once grouped. Rows are counted per IP because ip is the primary key.
    """
    db = get_db()

    search_net = request.args.get("network", "").strip()
    country    = request.args.get("country", "").strip()
    period     = request.args.get("period", "all")
    xip        = request.args.get("xip", "").strip()
    xnet       = request.args.get("xnet", "").strip()
    xcountry   = request.args.get("xcountry", "").strip()
    sort       = request.args.get("sort", "ip_count")
    order      = request.args.get("order", "desc")
    page       = max(1, int(request.args.get("page", 1) or 1))

    period   = period if period in PERIODS else "all"
    sort_sql = NET_SORT_COLS.get(sort, "ip_count")
    sort     = sort if sort in NET_SORT_COLS else "ip_count"
    order    = "DESC" if order != "asc" else "ASC"

    start, end = period_range(period)
    scoped = start is not None and hits_available(db)
    if scoped:
        source, src_params, req_expr, ls_expr, ls_params = window_source(start, end)
        period_conds, period_params = [], []
    else:
        source, src_params = "ip_access", []
        req_expr, ls_expr, ls_params = "requests", "last_seen", []
        period_conds, period_params = period_bounds(period)

    conditions, params = list(period_conds), list(period_params)
    if search_net:
        conditions.append("network LIKE ?")
        params.append(f"%{search_net}%")
    if country:
        conditions.append("country = ?")
        params.append(country)

    xconds, xparams = exclude_conditions(xip, xnet, xcountry)
    conditions += xconds
    params += xparams

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM (SELECT 1 FROM {source} {where} GROUP BY network)",
        src_params + params,
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT network, "
        f"COUNT(*) AS ip_count, "
        f"COALESCE(SUM({req_expr}), 0) AS total_requests, "
        f"MAX({ls_expr}) AS last_seen, "
        f"GROUP_CONCAT(DISTINCT country) AS countries "
        f"FROM {source} {where} "
        f"GROUP BY network "
        f"ORDER BY {sort_sql} {order} "
        f"LIMIT ? OFFSET ?",
        ls_params + src_params + params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()

    countries = [
        r[0] for r in db.execute(
            "SELECT DISTINCT country FROM ip_access "
            "WHERE country != '' ORDER BY country"
        ).fetchall()
    ]

    # Stats reflect the selected period (but not the network/country filters).
    pwhere = f"WHERE {' AND '.join(period_conds)}" if period_conds else ""
    stats = db.execute(
        "SELECT COUNT(DISTINCT network) AS total_networks, "
        "COUNT(*) AS total_ips, "
        f"COALESCE(SUM({req_expr}), 0) AS total_requests "
        f"FROM {source} {pwhere}",
        src_params + period_params,
    ).fetchone()

    return render_template(
        "networks.html",
        view="networks",
        rows=rows,
        countries=countries,
        stats=stats,
        periods=PERIODS,
        period=period,
        scoped=scoped,
        req_label="Requests" if not scoped else f"Requests ({PERIODS[period].lower()})",
        history_from=history_start(db) if period != "all" else "",
        search_net=search_net,
        sel_country=country,
        xip=xip,
        xnet=xnet,
        xcountry=xcountry,
        sort=sort,
        order=order,
        page=page,
        total=total,
        total_pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
        per_page=PER_PAGE,
    )


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )
