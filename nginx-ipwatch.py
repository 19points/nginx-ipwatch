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

from whois_util import whois_lookup

DEFAULT_LOG = "/logs/access.log"
DEFAULT_DB  = "/data/nginx_ips.db"

IGNORE_IPS: set[str] = {
    ip.strip()
    for ip in os.environ.get("IGNORE_IPS", "").split(",")
    if ip.strip()
}

# Periodic retry of rows whose WHOIS lookup previously failed (network IS NULL).
# A failed lookup is only ever attempted once at insert time, so without this a
# transient rate-limit/timeout would leave a row blank forever.
BACKFILL_INTERVAL = int(os.environ.get("BACKFILL_INTERVAL", "900"))   # seconds between sweeps
BACKFILL_BATCH    = int(os.environ.get("BACKFILL_BATCH", "25"))       # max rows retried per sweep
WHOIS_DELAY       = float(os.environ.get("WHOIS_DELAY", "1.0"))       # seconds between lookups (rate-limit friendly)


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
        if network is None:
            # Lookup failed — stored as NULL so the backfill sweep retries it.
            print(f"[new]  {ip:<40}  WHOIS lookup failed — will retry", flush=True)
        else:
            print(f"[new]  {ip:<40}  net={network or '-':<20}  country={country or '-'}", flush=True)

    conn.commit()


def backfill(conn: sqlite3.Connection, limit: int, delay: float) -> None:
    """Retry WHOIS for up to *limit* rows whose lookup previously failed.

    Only touches rows where network IS NULL (a failed lookup). Rows with a
    successful-but-empty result ('') are left alone so genuinely data-less IPs
    aren't retried forever. Rows that fail again stay NULL for the next sweep.
    """
    rows = conn.execute(
        "SELECT ip FROM ip_access WHERE network IS NULL LIMIT ?", (limit,)
    ).fetchall()
    if not rows:
        return

    print(f"[backfill] retrying {len(rows)} IP(s) with previously failed lookups", flush=True)
    for (ip,) in rows:
        network, country = whois_lookup(ip)
        if network is not None:
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ? WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
            print(f"[backfill] {ip:<40}  net={network or '-':<20}  country={country or '-'}", flush=True)
        time.sleep(delay)  # throttle to stay under RDAP rate limits


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

    Yields None while idle (no new line) so the caller can run periodic
    maintenance — e.g. the backfill sweep — even during quiet periods.
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

            yield None  # idle heartbeat
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
    print(f"[info] backfill every {BACKFILL_INTERVAL}s (batch {BACKFILL_BATCH}, {WHOIS_DELAY}s/lookup)", flush=True)

    last_backfill = time.monotonic()
    for line in tail(log_path):
        if time.monotonic() - last_backfill >= BACKFILL_INTERVAL:
            backfill(conn, BACKFILL_BATCH, WHOIS_DELAY)
            last_backfill = time.monotonic()

        if line is None:  # idle heartbeat — nothing to process this tick
            continue

        ip = extract_ip(line)
        if ip is None or ip in IGNORE_IPS:
            continue
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        upsert(conn, ip, now)


if __name__ == "__main__":
    main()
