#!/usr/bin/env python3
"""
web.py — Flask UI for the nginx-ipwatch SQLite database.

Browsing is read-only (the DB is opened with mode=ro). The single exception is
the manual lookup at POST /lookup, which resolves one IP through a third-party
source and writes the result — see proxy_util for why that's needed.

Environment variables:
    DB_PATH              path to the SQLite file  (default /data/nginx_ips.db)
    HOST                 bind address             (default 0.0.0.0)
    PORT                 bind port                (default 5000)
    LOOKUP_MIN_INTERVAL  min seconds between manual lookups (default 2.0)
"""

import ipaddress
import os
import sqlite3
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

from flask import Flask, g, redirect, render_template, request

import proxy_util
from provider_util import CATEGORIES

from hits_util import HIT_BUCKET

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/nginx_ips.db")
PER_PAGE = 50
SORT_COLS = {"ip", "network", "country", "requests", "last_seen", "category"}

# Category filter values that aren't a category key: 'any' = marked as cloud,
# hosting or a crawler; 'none' = matched nothing (typically a consumer ISP).
CAT_ANY, CAT_NONE = "any", "none"

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


def category_condition(cat: str) -> tuple:
    """SQL condition for the category filter, or ([], []) when unset/unknown.

    NULL means "not yet labelled" rather than "nothing matched", so it is
    excluded from both the 'any' and 'none' buckets — claiming an unlabelled row
    is a plain ISP would be inventing a result the labeller hasn't produced yet.
    """
    if cat == CAT_ANY:
        return ["(category IS NOT NULL AND category != '')"], []
    if cat == CAT_NONE:
        return ["category = ''"], []
    if cat in CATEGORIES:
        return ["category = ?"], [cat]
    return [], []


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
    "category":  "categories",
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
                    whois_attempts INTEGER, whois_next_retry TEXT,
                    category TEXT
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
    rw = g.pop("db_rw", None)
    if rw:
        rw.close()


def get_db_rw() -> sqlite3.Connection:
    """Writable connection, opened only for the manual-lookup route.

    Deliberately separate from get_db()'s mode=ro handle so every other view
    keeps its read-only guarantee. The watcher holds the same file, so a
    busy_timeout covers the moment both want the write lock.
    """
    if "db_rw" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout = 5000")
        g.db_rw = conn
    return g.db_rw


# ---------------------------------------------------------------------------
# Manual lookup
# ---------------------------------------------------------------------------

# One live lookup per this many seconds, so a held-down button can't turn the UI
# into the abusive querying that got the host banned in the first place. The
# limiter is per worker process (gunicorn runs several), which is fine for a
# human-triggered action — it's a guard against accidents, not an access control.
LOOKUP_MIN_INTERVAL = float(os.environ.get("LOOKUP_MIN_INTERVAL", "2.0"))
_last_lookup = 0.0

# SQLite caps host parameters per statement; chunk sibling updates well under it.
_UPDATE_CHUNK = 500


def _rows_for_address(conn, ip: str) -> list:
    """The DB's spelling(s) of *ip* — whatever text form the log recorded.

    An IPv6 address has many valid text forms and nginx logs whichever the client
    presented, so the table can hold '2a02:6b8::feed:0ff' while ipaddress
    canonicalises the same address to '2a02:6b8::feed:ff'. A plain `ip = ?` then
    silently misses the row it was meant to update. IPv4 has one form in
    practice, so only v6 needs the rescan — and only v6 rows (the ones with a
    colon) are candidates, which keeps it a narrow scan rather than a full one.
    """
    hit = [r[0] for r in conn.execute("SELECT ip FROM ip_access WHERE ip = ?", (ip,))]
    if hit:
        return hit
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if target.version != 6:
        return []
    matches = []
    for (candidate,) in conn.execute("SELECT ip FROM ip_access WHERE ip LIKE '%:%'"):
        try:
            if ipaddress.ip_address(candidate) == target:
                matches.append(candidate)
        except ValueError:
            continue
    return matches


def _siblings_in(conn, block, exclude: set) -> list:
    """Unresolved IPs (network IS NULL) inside *block*, minus those in *exclude*.

    CIDR containment isn't something SQLite can express, so the candidate set is
    the whole unresolved backlog and the filtering happens here. That set is
    bounded by how far behind the WHOIS sweep is, and this runs once per manual
    click, so a linear pass is fine.
    """
    found = []
    for (ip,) in conn.execute("SELECT ip FROM ip_access WHERE network IS NULL"):
        if ip in exclude:
            continue
        try:
            if ipaddress.ip_address(ip) in block:
                found.append(ip)
        except ValueError:
            continue
    return found


def apply_lookup(conn, result) -> tuple[int, int]:
    """Persist *result*, returning (rows for the queried IP, sibling rows filled).

    The queried IP is overwritten unconditionally — asking for it explicitly is a
    statement that the manual answer beats whatever GeoIP guessed. Siblings are
    only *filled in*, never overwritten, so one click can't silently rewrite
    blocks of data the user didn't ask about.

    A result carrying a country but no network updates the country and leaves
    network NULL, so the watcher's sweep still gets a chance to resolve the CIDR
    later instead of the row looking permanently answered.
    """
    network = result.network or None
    country = result.country or None

    own = _rows_for_address(conn, result.ip)
    queried = 0
    if own:
        placeholders = ",".join("?" * len(own))
        queried = conn.execute(
            f"UPDATE ip_access SET network = COALESCE(?, network), "
            f"country = COALESCE(?, country), whois_next_retry = NULL "
            f"WHERE ip IN ({placeholders})",
            [network, country] + own,
        ).rowcount

    filled = 0
    if network:
        try:
            block = ipaddress.ip_network(network, strict=False)
        except ValueError:
            block = None
        if block is not None and block.prefixlen > 0:
            # Exclude the queried row(s) — already updated above, and counting
            # them again would double-report them in the UI.
            targets = _siblings_in(conn, block, set(own))
            for i in range(0, len(targets), _UPDATE_CHUNK):
                chunk = targets[i:i + _UPDATE_CHUNK]
                placeholders = ",".join("?" * len(chunk))
                conn.execute(
                    f"UPDATE ip_access SET network = ?, country = ?, "
                    f"whois_next_retry = NULL WHERE network IS NULL "
                    f"AND ip IN ({placeholders})",
                    [network, country or ""] + chunk,
                )
            filled = len(targets)

    conn.commit()
    return queried, filled


def _back_to(qs: str, **extra) -> str:
    """Redirect target: the filters the user came from, plus lookup feedback.

    *qs* is echoed back from a form field, so it is re-parsed and re-encoded
    rather than concatenated — and only ever appended to our own '/' path, so it
    can't be turned into an open redirect. Stale lu_* keys are dropped so
    repeated lookups don't stack up feedback params.
    """
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True)
             if not k.startswith("lu_")]
    pairs += [(k, v) for k, v in extra.items() if v not in (None, "")]
    return ("/?" + urllib.parse.urlencode(pairs)) if pairs else "/"


@app.route("/lookup", methods=["POST"])
def manual_lookup():
    """Resolve one IP through a third-party source and store the result.

    Exists because a registry can permanently ban a host from its query service
    (RIPE ERROR:201), after which the watcher's automatic RDAP path fails for
    every IP even though the data is public. See proxy_util.
    """
    global _last_lookup

    qs = request.form.get("qs", "")
    raw = (request.form.get("ip") or "").strip()

    try:
        ip = str(ipaddress.ip_address(raw))
    except ValueError:
        return redirect(_back_to(qs, lu_ip=raw[:64], lu_msg="Not a valid IP address."), 303)

    if ipaddress.ip_address(ip).is_private:
        return redirect(_back_to(
            qs, lu_ip=ip, lu_msg="Private/loopback address — no public registry data exists."
        ), 303)

    wait = LOOKUP_MIN_INTERVAL - (time.monotonic() - _last_lookup)
    if wait > 0:
        return redirect(_back_to(
            qs, lu_ip=ip, lu_msg=f"Slow down — try again in {wait:.0f}s."
        ), 303)
    _last_lookup = time.monotonic()

    result, tried = proxy_util.lookup(ip)
    if result is None:
        return redirect(_back_to(
            qs, lu_ip=ip, lu_msg=f"No data returned by {', '.join(tried)}."
        ), 303)

    try:
        queried, filled = apply_lookup(get_db_rw(), result)
    except sqlite3.Error as exc:
        return redirect(_back_to(qs, lu_ip=ip, lu_msg=f"Database write failed: {exc}"), 303)

    parts = [f"{result.network or '—'}", f"{result.country or '—'}"]
    if result.netname:
        parts.append(result.netname)
    if result.asn:
        parts.append(f"AS{result.asn}")
    detail = " · ".join(parts)

    if queried:
        msg = f"{ip} → {detail} (via {result.source})."
    else:
        # Looking up an IP the log has never seen is allowed — it's a useful way
        # to check a block — but nothing is inserted: this table is a record of
        # observed traffic, not a WHOIS cache.
        msg = f"{ip} → {detail} (via {result.source}). Not in the database, so nothing was stored."
    if filled:
        msg += f" Filled {filled} unresolved IP{'s' if filled != 1 else ''} in {result.network}."

    return redirect(_back_to(qs, lu_ip=ip, lu_ok="1", lu_msg=msg), 303)


@app.route("/")
def index():
    db = get_db()

    search_ip = request.args.get("ip", "").strip()
    country   = request.args.get("country", "").strip()
    network   = request.args.get("network", "").strip()
    cat       = request.args.get("cat", "").strip()
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

    cconds, cparams = category_condition(cat)
    conditions += cconds
    params += cparams

    xconds, xparams = exclude_conditions(xip, xnet, xcountry)
    conditions += xconds
    params += xparams

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM {source} {where}", src_params + params
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT ip, network, country, category, "
        f"{req_expr} AS requests, {ls_expr} AS last_seen "
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
        categories=CATEGORIES,
        cat=cat,
        scoped=scoped,
        req_label="Requests" if not scoped else f"Requests ({PERIODS[period].lower()})",
        history_from=history_start(db) if period != "all" else "",
        # Feedback from a POST /lookup redirect, plus the current filters so the
        # lookup forms can send the user back to exactly this view.
        lookup_msg=request.args.get("lu_msg", "")[:400],
        lookup_ok=request.args.get("lu_ok") == "1",
        lookup_ip=request.args.get("lu_ip", "")[:64],
        qs=request.query_string.decode("utf-8", "replace"),
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
    cat        = request.args.get("cat", "").strip()
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

    cconds, cparams = category_condition(cat)
    conditions += cconds
    params += cparams

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
        f"GROUP_CONCAT(DISTINCT country) AS countries, "
        f"GROUP_CONCAT(DISTINCT category) AS categories "
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
        categories=CATEGORIES,
        cat=cat,
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
