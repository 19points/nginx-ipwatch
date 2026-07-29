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

from whois_util import (
    cache_add,
    cache_lookup,
    is_private,
    next_retry_after,
    prime_cache,
    whois_lookup,
)

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
WHOIS_DELAY       = float(os.environ.get("WHOIS_DELAY", "2.0"))       # seconds between *live* lookups (rate-limit friendly)

# Circuit breaker: RDAP registries temp-block a client that keeps hitting them
# while rate-limited. If this many live lookups fail in a row we assume we're
# blocked, stop the sweep, and pause it for the cooldown so the block can lift
# instead of being kept alive. New IPs never trigger an inline lookup (they are
# resolved from the network cache or deferred), so only the sweep is gated.
RATE_LIMIT_STREAK   = int(os.environ.get("RATE_LIMIT_STREAK", "3"))     # consecutive fails that trip the breaker
RATE_LIMIT_COOLDOWN = int(os.environ.get("RATE_LIMIT_COOLDOWN", "3600"))  # seconds to pause the sweep after tripping

# monotonic deadline until which the sweep is paused (0 = not paused). Single-
# threaded process, so a module global is enough to share state with the loop.
_whois_paused_until = 0.0


def _whois_paused() -> bool:
    return time.monotonic() < _whois_paused_until


def _trip_breaker() -> None:
    global _whois_paused_until
    _whois_paused_until = time.monotonic() + RATE_LIMIT_COOLDOWN


def log(msg: str) -> None:
    """Print *msg* to stdout prefixed with a UTC timestamp (same format as last_seen)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts}  {msg}", flush=True)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_access (
            ip               TEXT PRIMARY KEY,
            network          TEXT,
            country          TEXT,
            requests         INTEGER NOT NULL DEFAULT 1,
            last_seen        TEXT NOT NULL,
            whois_attempts   INTEGER NOT NULL DEFAULT 0,
            whois_next_retry TEXT
        )
    """)
    # Migrate DBs created before the retry-bookkeeping columns existed.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(ip_access)")}
    if "whois_attempts" not in cols:
        conn.execute("ALTER TABLE ip_access ADD COLUMN whois_attempts INTEGER NOT NULL DEFAULT 0")
    if "whois_next_retry" not in cols:
        conn.execute("ALTER TABLE ip_access ADD COLUMN whois_next_retry TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON ip_access (last_seen)")
    # Partial index over just the failed rows the backfill sweep scans.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_whois_retry "
        "ON ip_access (whois_next_retry) WHERE network IS NULL"
    )
    # Heal rows poisoned by a cached default route (0.0.0.0/0 / ::/0): RDAP's
    # catch-all matched every IP in the old cache, so these were mislabelled
    # (often never looked up at all). Reset them to NULL so the sweep resolves
    # them for real — the cache now refuses default routes, so no re-poisoning.
    healed = conn.execute(
        "UPDATE ip_access SET network = NULL, country = NULL, "
        "whois_attempts = 0, whois_next_retry = NULL "
        "WHERE network IN ('0.0.0.0/0', '::/0')"
    ).rowcount
    if healed:
        log(f"[info] reset {healed} row(s) with a bogus 0.0.0.0/0 network for re-resolution")
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
        # New IP — resolve WITHOUT a live WHOIS call whenever possible:
        #   - private/loopback ranges have no public WHOIS (resolve locally)
        #   - an IP inside an already-known CIDR reuses that block's data
        # Only a genuinely new public network is deferred (network IS NULL) to the
        # throttled backfill sweep. We never look up inline, so a flood of new IPs
        # can't burst RDAP and trip the rate limiter.
        if is_private(ip):
            network, country = "private", "private"
        else:
            network, country = cache_lookup(ip) or (None, None)

        if network is None:
            # Deferred to the sweep. No per-IP log — a flood would drown the log;
            # the sweep logs each IP when it resolves.
            conn.execute(
                "INSERT INTO ip_access "
                "(ip, network, country, requests, last_seen, whois_attempts, whois_next_retry) "
                "VALUES (?, NULL, NULL, 1, ?, 0, NULL)",
                (ip, now),
            )
        else:
            conn.execute(
                "INSERT INTO ip_access "
                "(ip, network, country, requests, last_seen, whois_attempts, whois_next_retry) "
                "VALUES (?, ?, ?, 1, ?, 0, NULL)",
                (ip, network, country, now),
            )
            src = "private" if network == "private" else "cached"
            log(f"[new]  {ip:<40}  net={network or '-':<20}  country={country or '-'}  ({src})")

    conn.commit()


def backfill(conn: sqlite3.Connection, limit: int, delay: float) -> None:
    """Retry WHOIS for up to *limit* failed rows that are due for a retry.

    Only touches rows where network IS NULL (a failed lookup) AND whose
    whois_next_retry is due (NULL = never attempted, or in the past). Rows with a
    successful-but-empty result ('') are left alone so genuinely data-less IPs
    aren't retried forever.

    Each failure pushes the row's whois_next_retry further out (exponential
    backoff), so a row that keeps failing rotates to the back of the queue and
    the sweep advances to other due rows instead of head-banging the same batch.

    If RATE_LIMIT_STREAK lookups fail in a row we assume we've been rate-limited
    or temp-blocked, trip the breaker (pausing all WHOIS for a cooldown), and
    abort the sweep rather than deepening the block.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        "SELECT ip, whois_attempts FROM ip_access "
        "WHERE network IS NULL AND (whois_next_retry IS NULL OR whois_next_retry <= ?) "
        # never-attempted rows (NULL) first, then the soonest-due
        "ORDER BY whois_next_retry IS NOT NULL, whois_next_retry "
        "LIMIT ?",
        (now, limit),
    ).fetchall()
    if not rows:
        return

    log(f"[backfill] retrying {len(rows)} IP(s) due for a retry")
    fails = 0
    for ip, attempts in rows:
        # Resolve for free first (private range or inside a cached CIDR); only
        # fall back to a live, throttled WHOIS for genuinely unknown networks.
        if is_private(ip):
            network, country, live = "private", "private", False
        else:
            hit = cache_lookup(ip)
            if hit:
                network, country, live = hit[0], hit[1], False
            else:
                network, country = whois_lookup(ip)
                live = True

        if network is not None:
            if live and network not in ("", "private"):
                cache_add(network, country)  # first IP of a block seeds its siblings
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ?, "
                "whois_attempts = whois_attempts + 1, whois_next_retry = NULL WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
            log(f"[backfill] {ip:<40}  net={network or '-':<20}  country={country or '-'}"
                f"{'' if live else '  (cached)'}")
            fails = 0
        else:
            conn.execute(
                "UPDATE ip_access SET whois_attempts = ?, whois_next_retry = ? WHERE ip = ?",
                (attempts + 1, next_retry_after(attempts + 1), ip),
            )
            conn.commit()
            fails += 1
            if fails >= RATE_LIMIT_STREAK:
                _trip_breaker()
                log(f"[backfill] {fails} lookups failed in a row — assuming rate-limit/block, "
                    f"pausing WHOIS for {RATE_LIMIT_COOLDOWN}s")
                return
        if live:
            time.sleep(delay)  # throttle only real network calls; cache hits are free


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
                log(f"[info] log rotated, reopened {path}")
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
    cached = prime_cache(conn)

    def _shutdown(sig, _frame):
        print(flush=True)  # break the ^C line before the timestamped message
        log("[info] shutting down")
        conn.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if IGNORE_IPS:
        log(f"[info] ignoring {len(IGNORE_IPS)} IP(s): {', '.join(sorted(IGNORE_IPS))}")
    log(f"[info] watching {log_path}  →  {db_path}")
    log(f"[info] network cache primed with {cached} CIDR(s)")
    log(f"[info] backfill every {BACKFILL_INTERVAL}s (batch {BACKFILL_BATCH}, {WHOIS_DELAY}s/live lookup)")

    last_backfill = time.monotonic()
    for line in tail(log_path):
        if not _whois_paused() and time.monotonic() - last_backfill >= BACKFILL_INTERVAL:
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
