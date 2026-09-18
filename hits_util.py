#!/usr/bin/env python3
"""
hits_util.py — per-IP request history in fixed time buckets.

`ip_access` keeps one cumulative counter per IP, so it can answer "how many
requests ever" but not "how many in the last hour". `ip_hits` adds a coarse
time series alongside it: one row per (ip, bucket) holding the requests that
IP made inside that bucket. The watcher writes it, the web UI sums it for the
selected period.

A bucket is a HIT_BUCKET-second slice of UTC time, keyed by the slice's start
in TS_FMT so it sorts and compares as a string like every other timestamp in
the DB. Rows older than HIT_RETENTION_DAYS are pruned by the watcher, which
bounds the table: a window longer than the retention reports only what is
still kept. Shared by the watcher and web.py so both agree on the bucket grid
(the watcher's hyphenated filename can't be imported, hence a module).
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

TS_FMT = "%Y-%m-%d %H:%M:%S"

# Bucket width. Smaller = sharper window edges, more rows per active IP.
HIT_BUCKET = max(1, int(os.environ.get("HIT_BUCKET", "300")))
# How long history is kept. Must exceed the longest UI window (7 days).
HIT_RETENTION_DAYS = float(os.environ.get("HIT_RETENTION_DAYS", "8"))


def bucket_start(when: datetime) -> str:
    """Return the start of the bucket containing *when*, as a UTC TS_FMT string."""
    epoch = int(when.timestamp())
    return datetime.fromtimestamp(epoch - epoch % HIT_BUCKET, timezone.utc).strftime(TS_FMT)


def init_hits(conn: sqlite3.Connection) -> None:
    """Create the history table. Safe to call on every start."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_hits (
            ip       TEXT    NOT NULL,
            bucket   TEXT    NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (ip, bucket)
        ) WITHOUT ROWID
    """)
    # Pruning and every period query scan by bucket.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_bucket ON ip_hits (bucket)")


def record_hit(conn: sqlite3.Connection, ip: str, when: datetime) -> None:
    """Add one request for *ip* to the bucket containing *when*."""
    conn.execute(
        "INSERT INTO ip_hits (ip, bucket, requests) VALUES (?, ?, 1) "
        "ON CONFLICT(ip, bucket) DO UPDATE SET requests = requests + 1",
        (ip, bucket_start(when)),
    )


def prune_hits(conn: sqlite3.Connection) -> int:
    """Drop buckets older than the retention window. Returns rows deleted."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HIT_RETENTION_DAYS)).strftime(TS_FMT)
    deleted = conn.execute("DELETE FROM ip_hits WHERE bucket < ?", (cutoff,)).rowcount
    conn.commit()
    return deleted
