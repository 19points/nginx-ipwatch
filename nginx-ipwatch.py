#!/usr/bin/env python3
"""
nginx-ipwatch.py — tail an Nginx access log, WHOIS new IPs, store in SQLite.

Usage:
    python nginx-ipwatch.py [log_path] [db_path]

Defaults:
    log_path  /var/log/nginx/access.log
    db_path   nginx_ips.db

Requirements:
    pip install ipwhois
"""

import ipaddress
import os
import sys
import time
import sqlite3
import signal
from datetime import datetime, timezone

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

DEFAULT_LOG = "/logs/access.log"
DEFAULT_DB  = "/data/nginx_ips.db"

IGNORE_IPS: set[str] = {
    ip.strip()
    for ip in os.environ.get("IGNORE_IPS", "").split(",")
    if ip.strip()
}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_access (
            ip        TEXT PRIMARY KEY,
            network   TEXT,
            country   TEXT,
            requests  INTEGER NOT NULL DEFAULT 1,
            last_seen TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON ip_access (last_seen)")
    conn.commit()


def upsert(conn: sqlite3.Connection, ip: str, now: str) -> None:
    exists = conn.execute(
        "SELECT 1 FROM ip_access WHERE ip = ?", (ip,)
    ).fetchone()

    if exists:
        conn.execute(
            "UPDATE ip_access SET requests = requests + 1, last_seen = ? WHERE ip = ?",
            (now, ip),
        )
    else:
        network, country = whois_lookup(ip)
        conn.execute(
            "INSERT INTO ip_access (ip, network, country, requests, last_seen) "
            "VALUES (?, ?, ?, 1, ?)",
            (ip, network, country, now),
        )
        print(f"[new]  {ip:<40}  net={network:<20}  country={country}", flush=True)

    conn.commit()


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def whois_lookup(ip: str) -> tuple[str, str]:
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        net     = data.get("network") or {}
        network = net.get("cidr") or ""
        country = net.get("country") or data.get("asn_country_code") or ""
        return network, country
    except IPDefinedError:
        # RFC-1918 / loopback / link-local
        return "private", "private"
    except Exception as exc:
        print(f"[whois error {ip}] {exc}", file=sys.stderr, flush=True)
        return "", ""


# ---------------------------------------------------------------------------
# Log tailing
# ---------------------------------------------------------------------------

def extract_ip(line: str) -> str | None:
    """Return the first token if it is a valid IP address, else None."""
    parts = line.split()
    if not parts:
        return None
    try:
        ipaddress.ip_address(parts[0])
        return parts[0]
    except ValueError:
        return None


def tail(path: str):
    """
    Yield new lines appended to *path*.
    Handles log rotation by detecting inode changes.
    """
    inode = os.stat(path).st_ino
    fh    = open(path)
    fh.seek(0, 2)  # jump to end so we only process new entries

    try:
        while True:
            line = fh.readline()
            if line:
                yield line
                continue

            time.sleep(0.05)

            try:
                new_inode = os.stat(path).st_ino
            except FileNotFoundError:
                continue

            if new_inode != inode:
                fh.close()
                fh    = open(path)
                inode = new_inode
                print(f"[info] log rotated, reopened {path}", flush=True)
    finally:
        fh.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LOG_PATH", DEFAULT_LOG)
    db_path  = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("DB_PATH",  DEFAULT_DB)

    if not os.path.exists(log_path):
        sys.exit(f"Error: log file not found: {log_path}")

    conn = sqlite3.connect(db_path)
    init_db(conn)

    def _shutdown(sig, _frame):
        print("\n[info] shutting down", flush=True)
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if IGNORE_IPS:
        print(f"[info] ignoring {len(IGNORE_IPS)} IP(s): {', '.join(sorted(IGNORE_IPS))}", flush=True)
    print(f"[info] watching {log_path}  →  {db_path}", flush=True)

    for line in tail(log_path):
        ip = extract_ip(line)
        if ip is None or ip in IGNORE_IPS:
            continue
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        upsert(conn, ip, now)


if __name__ == "__main__":
    main()
