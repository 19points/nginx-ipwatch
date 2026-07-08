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

from flask import Flask, g, render_template, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/nginx_ips.db")
PER_PAGE = 50
SORT_COLS = {"ip", "network", "country", "requests", "last_seen"}

# Network view sorts against aggregate aliases, so map the requested key to the
# safe column/alias it may be interpolated into the ORDER BY as.
NET_SORT_COLS = {
    "network":   "network",
    "country":   "countries",
    "ip_count":  "ip_count",
    "requests":  "total_requests",
    "last_seen": "last_seen",
}


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
                    requests INTEGER, last_seen TEXT
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
    sort      = request.args.get("sort", "requests")
    order     = request.args.get("order", "desc")
    page      = max(1, int(request.args.get("page", 1) or 1))

    sort  = sort  if sort  in SORT_COLS else "requests"
    order = "DESC" if order != "asc" else "ASC"

    conditions, params = [], []
    if search_ip:
        conditions.append("ip LIKE ?")
        params.append(f"%{search_ip}%")
    if country:
        conditions.append("country = ?")
        params.append(country)
    if network:
        conditions.append("network = ?")
        params.append(network)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM ip_access {where}", params
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT ip, network, country, requests, last_seen "
        f"FROM ip_access {where} "
        f"ORDER BY {sort} {order} "
        f"LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()

    countries = [
        r[0] for r in db.execute(
            "SELECT DISTINCT country FROM ip_access "
            "WHERE country != '' ORDER BY country"
        ).fetchall()
    ]

    stats = db.execute(
        "SELECT COUNT(*) AS total_ips, "
        "COALESCE(SUM(requests), 0) AS total_requests, "
        "COUNT(DISTINCT country) AS total_countries "
        "FROM ip_access"
    ).fetchone()

    return render_template(
        "index.html",
        view="ips",
        rows=rows,
        countries=countries,
        stats=stats,
        search_ip=search_ip,
        sel_country=country,
        network=network,
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
    sort       = request.args.get("sort", "ip_count")
    order      = request.args.get("order", "desc")
    page       = max(1, int(request.args.get("page", 1) or 1))

    sort_sql = NET_SORT_COLS.get(sort, "ip_count")
    sort     = sort if sort in NET_SORT_COLS else "ip_count"
    order    = "DESC" if order != "asc" else "ASC"

    conditions, params = [], []
    if search_net:
        conditions.append("network LIKE ?")
        params.append(f"%{search_net}%")
    if country:
        conditions.append("country = ?")
        params.append(country)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM (SELECT 1 FROM ip_access {where} GROUP BY network)",
        params,
    ).fetchone()[0]

    rows = db.execute(
        f"SELECT network, "
        f"COUNT(*) AS ip_count, "
        f"COALESCE(SUM(requests), 0) AS total_requests, "
        f"MAX(last_seen) AS last_seen, "
        f"GROUP_CONCAT(DISTINCT country) AS countries "
        f"FROM ip_access {where} "
        f"GROUP BY network "
        f"ORDER BY {sort_sql} {order} "
        f"LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE],
    ).fetchall()

    countries = [
        r[0] for r in db.execute(
            "SELECT DISTINCT country FROM ip_access "
            "WHERE country != '' ORDER BY country"
        ).fetchall()
    ]

    stats = db.execute(
        "SELECT COUNT(DISTINCT network) AS total_networks, "
        "COUNT(*) AS total_ips, "
        "COALESCE(SUM(requests), 0) AS total_requests "
        "FROM ip_access"
    ).fetchone()

    return render_template(
        "networks.html",
        view="networks",
        rows=rows,
        countries=countries,
        stats=stats,
        search_net=search_net,
        sel_country=country,
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
