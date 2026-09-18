#!/usr/bin/env python3
"""backfill.py — re-run WHOIS for rows whose lookup never succeeded.

The watcher already retries failed lookups (network IS NULL) on an interval,
so you normally don't need this. It exists for two cases:

  1. A manual, immediate sweep instead of waiting for the watcher's timer.
  2. Healing *legacy* rows created before failures were stored as NULL. The
     old watcher stored '' for BOTH a failed lookup and a genuinely-empty
     result, so they can't be told apart — use --include-empty to retry every
     '' row once. Genuinely-empty IPs simply stay '' afterwards.

It also carries --relabel, which is unrelated to WHOIS: it recomputes every
row's cloud/hosting/crawler category. The watcher labels new rows as they
arrive and fills in unlabelled ones, but an existing label is never revisited,
so a rebuilt image with fresher provider range files needs this once to apply
them to rows already in the table.

Usage:
    python backfill.py [db_path] [--include-empty] [--limit N] [--delay SECS]
    python backfill.py [db_path] --relabel

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

from geoip_util import geoip_lookup, load_geoip
from provider_util import category_for, label, load_providers
from whois_util import (
    cache_add,
    cache_lookup,
    is_private,
    next_retry_after,
    prime_cache,
    whois_lookup,
)

DEFAULT_DB = "/data/nginx_ips.db"


def relabel(db_path: str) -> None:
    """Recompute the category of every row, reporting what changed.

    Entirely offline — it reads the provider range files and the ASN table, so
    it neither makes a network call nor cares about the WHOIS rate limit, and
    it is safe to run against a database the watcher is using.
    """
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("PRAGMA busy_timeout = 5000")

    prefixes = load_providers()
    load_geoip()
    if not prefixes:
        print("Warning: no provider range files found (PROVIDER_DIR) — "
              "labels will come from ASN data only.")

    rows = conn.execute("SELECT ip, category FROM ip_access").fetchall()
    changed = 0
    counts = {}
    for ip, old in rows:
        new = "" if is_private(ip) else category_for(ip)
        counts[new] = counts.get(new, 0) + 1
        if new != old:
            conn.execute("UPDATE ip_access SET category = ? WHERE ip = ?", (new, ip))
            changed += 1
    conn.commit()

    print(f"Relabelled {len(rows)} row(s) from {db_path}: {changed} changed.")
    for key, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {label(key) or '(unmarked)':18} {n}")
    conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("db_path", nargs="?", default=os.environ.get("DB_PATH", DEFAULT_DB),
                        help="path to the SQLite database")
    parser.add_argument("--include-empty", action="store_true",
                        help="also retry rows with an empty ('') network (legacy failures)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max rows to process (0 = no limit)")
    parser.add_argument("--delay", type=float, default=float(os.environ.get("WHOIS_DELAY", "2.0")),
                        help="seconds to sleep between live lookups (rate-limit friendly)")
    parser.add_argument("--relabel", action="store_true",
                        help="recompute every row's cloud/hosting/crawler category and exit "
                             "(no WHOIS; use after refreshing the provider range files)")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        sys.exit(f"Error: database not found: {args.db_path}")

    if args.relabel:
        relabel(args.db_path)
        return

    # network IS NULL  -> lookup failed (new behaviour, always retried)
    # network = ''     -> looked up but no data (legacy failures live here too)
    where = "network IS NULL" if not args.include_empty else "(network IS NULL OR network = '')"
    query = f"SELECT ip, whois_attempts FROM ip_access WHERE {where} ORDER BY last_seen DESC"
    if args.limit > 0:
        query += f" LIMIT {args.limit}"

    conn = sqlite3.connect(args.db_path, timeout=10)
    conn.execute("PRAGMA busy_timeout = 5000")

    rows = conn.execute(query).fetchall()
    if not rows:
        print("Nothing to backfill — no matching rows.")
        return

    primed = prime_cache(conn)
    geo_country, geo_asn = load_geoip()
    print(f"Backfilling {len(rows)} row(s) from {args.db_path} "
          f"({'NULL + empty' if args.include_empty else 'NULL only'}, {args.delay}s/live lookup, "
          f"cache primed with {primed} CIDR(s), "
          f"geoip {geo_country + geo_asn} ranges)")

    fixed = failed = unchanged = 0
    for ip, attempts in rows:
        # Resolve for free first (private range, cached CIDR, or offline GeoIP);
        # only IPs none of those place need a live, throttled WHOIS call.
        live, source = False, ""
        if is_private(ip):
            network, country = "private", "private"
        else:
            hit = cache_lookup(ip)
            if hit:
                network, country, source = hit[0], hit[1], "cached"
            else:
                geo = geoip_lookup(ip)
                if geo is not None:
                    network, country, source = geo[0], geo[1], "geoip"
                else:
                    network, country = whois_lookup(ip)
                    live = True
        if network is not None and source != "cached" and network not in ("", "private"):
            cache_add(network, country)  # first IP of a block seeds its siblings

        if network is None:
            # Still failing — record the attempt and push the retry out so the
            # watcher's backoff schedule stays coherent after a manual run.
            failed += 1
            print(f"  [fail]  {ip:<40}  still failing")
            conn.execute(
                "UPDATE ip_access SET whois_attempts = ?, whois_next_retry = ? WHERE ip = ?",
                (attempts + 1, next_retry_after(attempts + 1), ip),
            )
            conn.commit()
        elif network == "":
            unchanged += 1
            print(f"  [empty] {ip:<40}  no WHOIS data")
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ?, whois_next_retry = NULL WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
        else:
            fixed += 1
            src = f"  ({source})" if source else ""
            print(f"  [ok]    {ip:<40}  net={network:<20}  country={country or '-'}{src}")
            conn.execute(
                "UPDATE ip_access SET network = ?, country = ?, whois_next_retry = NULL WHERE ip = ?",
                (network, country, ip),
            )
            conn.commit()
        if live:
            time.sleep(args.delay)  # throttle only real network calls; cache hits are free

    conn.close()
    print(f"\nDone. resolved={fixed}  no-data={unchanged}  still-failing={failed}")


if __name__ == "__main__":
    main()
