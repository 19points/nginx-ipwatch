#!/usr/bin/env python3
"""backfill.py — re-run WHOIS for rows whose lookup never succeeded.

The watcher already retries failed lookups (network IS NULL) on an interval,
so you normally don't need this. It exists for two cases:

  1. A manual, immediate sweep instead of waiting for the watcher's timer.
  2. Healing *legacy* rows created before failures were stored as NULL. The
     old watcher stored '' for BOTH a failed lookup and a genuinely-empty
     result, so they can't be told apart — use --include-empty to retry every
     '' row once. Genuinely-empty IPs simply stay '' afterwards.

Usage:
    python backfill.py [db_path] [--include-empty] [--limit N] [--delay SECS]

Env:
    DB_PATH        default /data/nginx_ips.db (overridden by positional db_path)
    WHOIS_DELAY    default delay between lookups, seconds (overridden by --delay)

Run it while the watcher is stopped, or accept that both processes briefly
share the write lock (a busy_timeout is set to tolerate that).
"""

import argparse
import os
import sqlite3
import sys
import time

from whois_util import whois_lookup

DEFAULT_DB = "/data/nginx_ips.db"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("db_path", nargs="?", default=os.environ.get("DB_PATH", DEFAULT_DB),
                        help="path to the SQLite database")
    parser.add_argument("--include-empty", action="store_true",
                        help="also retry rows with an empty ('') network (legacy failures)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max rows to process (0 = no limit)")
    parser.add_argument("--delay", type=float, default=float(os.environ.get("WHOIS_DELAY", "1.0")),
                        help="seconds to sleep between lookups (rate-limit friendly)")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        sys.exit(f"Error: database not found: {args.db_path}")

    # network IS NULL  -> lookup failed (new behaviour, always retried)
    # network = ''     -> looked up but no data (legacy failures live here too)
    where = "network IS NULL" if not args.include_empty else "(network IS NULL OR network = '')"
    query = f"SELECT ip FROM ip_access WHERE {where} ORDER BY last_seen DESC"
    if args.limit > 0:
        query += f" LIMIT {args.limit}"

    conn = sqlite3.connect(args.db_path, timeout=10)
    conn.execute("PRAGMA busy_timeout = 5000")

    ips = [row[0] for row in conn.execute(query).fetchall()]
    if not ips:
        print("Nothing to backfill — no matching rows.")
        return

    print(f"Backfilling {len(ips)} row(s) from {args.db_path} "
          f"({'NULL + empty' if args.include_empty else 'NULL only'}, {args.delay}s/lookup)")

    fixed = failed = unchanged = 0
    for ip in ips:
        network, country = whois_lookup(ip)
        if network is None:
            failed += 1
            print(f"  [fail]  {ip:<40}  still failing")
        elif network == "":
            unchanged += 1
            print(f"  [empty] {ip:<40}  no WHOIS data")
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ? WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
        else:
            fixed += 1
            print(f"  [ok]    {ip:<40}  net={network:<20}  country={country or '-'}")
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ? WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
        time.sleep(args.delay)

    conn.close()
    print(f"\nDone. resolved={fixed}  no-data={unchanged}  still-failing={failed}")


if __name__ == "__main__":
    main()
