#!/usr/bin/env python3
"""Shared RDAP WHOIS helper used by the watcher and the backfill tool.

Kept in its own module so `nginx-ipwatch.py` (the writer) and `backfill.py`
(the retry tool) resolve IPs identically — the watcher's filename contains a
hyphen and cannot be imported, so the shared logic lives here instead.
"""

import ipaddress
import os
import random
import sys
from datetime import datetime, timedelta, timezone

from ipwhois import IPWhois
from ipwhois.exceptions import HTTPRateLimitError, IPDefinedError

# ---------------------------------------------------------------------------
# Network cache — shared by the watcher and backfill.py so both avoid redundant
# WHOIS. Under a scanner flood there are thousands of IPs but few networks, and
# one RDAP lookup returns the whole CIDR: resolve the first IP of a block live,
# then serve every sibling from here with no further lookup. Each process has
# its own module instance (and thus its own cache), primed from the DB.
_net_cache: list = []          # newest-first list of (ip_network, cidr_str, country)
_net_cache_seen: set = set()   # cidr strings already cached (dedup)


def cache_add(cidr: str, country: str) -> None:
    """Add a resolved CIDR to the in-memory cache (idempotent, newest-first)."""
    if not cidr or cidr in _net_cache_seen:
        return
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return
    if net.prefixlen == 0:
        # A default route (0.0.0.0/0 or ::/0) contains EVERY address — caching it
        # would make every subsequent lookup a false hit. It's never a real
        # allocation, so refuse it. (whois_lookup already strips these, but this
        # also protects prime_cache from legacy 0.0.0.0/0 rows in an old DB.)
        return
    _net_cache_seen.add(cidr)
    _net_cache.insert(0, (net, cidr, country))  # floods reuse recent blocks → hit early


def cache_lookup(ip: str):
    """Return (cidr, country) if *ip* falls inside an already-resolved network, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, cidr, country in _net_cache:
        if addr in net:
            return cidr, country
    return None


def prime_cache(conn) -> int:
    """Seed the cache from networks already resolved in the DB (survives restarts)."""
    rows = conn.execute(
        "SELECT DISTINCT network, country FROM ip_access "
        "WHERE network IS NOT NULL AND network != '' AND network != 'private'"
    ).fetchall()
    for cidr, country in rows:
        cache_add(cidr, country)
    return len(_net_cache)


def is_private(ip: str) -> bool:
    """True for RFC-1918 / loopback / link-local etc. — no public WHOIS to fetch."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# Backoff schedule for rows whose lookup failed (network IS NULL). Shared by the
# watcher's periodic sweep and the manual backfill tool so a failed IP's
# whois_next_retry is computed identically wherever it is written.
RETRY_BASE = int(os.environ.get("WHOIS_RETRY_BASE", "900"))    # 1st retry ~this many seconds out
RETRY_MAX  = int(os.environ.get("WHOIS_RETRY_MAX", "86400"))   # cap the exponential growth (24h)


def next_retry_after(attempts: int) -> str:
    """UTC timestamp (same format as last_seen) for a row's next WHOIS retry.

    Exponential backoff on the failure count with ±25% jitter, so an IP that
    keeps failing is retried ever less often and a large backlog doesn't retry
    in lockstep. *attempts* is the post-increment failure count (>= 1).
    """
    delay = min(RETRY_BASE * 2 ** max(0, attempts - 1), RETRY_MAX)
    delay *= random.uniform(0.75, 1.25)
    when = datetime.now(timezone.utc) + timedelta(seconds=delay)
    return when.strftime("%Y-%m-%d %H:%M:%S")


def _clean_cidr(cidr: str) -> str:
    """Strip default-route (prefixlen-0) parts from an RDAP cidr string.

    RDAP hands back 0.0.0.0/0 (or ::/0) as a catch-all for IPs it can't place in
    a real allocation. That's not a network — and if stored/cached it matches
    every IP — so drop it. Returns the remaining real CIDRs (comma-joined), or
    '' if the result was nothing but a default route.
    """
    parts = []
    for part in (p.strip() for p in cidr.split(",")):
        if not part:
            continue
        try:
            if ipaddress.ip_network(part, strict=False).prefixlen == 0:
                continue
        except ValueError:
            continue
        parts.append(part)
    return ", ".join(parts)


def whois_lookup(ip: str) -> tuple[str | None, str | None]:
    """Resolve *ip* to (network_cidr, country) via a single RDAP lookup.

    Returns one of:
        (cidr, country)         on success. Either value may be '' when RDAP
                                genuinely has no data for it. Country is
                                upper-cased (RDAP occasionally reports l-case).
        ("private", "private")  for RFC-1918 / loopback / link-local addresses.
        (None, None)            if the lookup FAILED — rate limit, timeout, or
                                other network error. Callers should store NULL
                                so the row can be retried later, instead of
                                caching a blank that looks like a real result.

    The distinction between '' (looked up, no data) and None (never
    successfully looked up) is what lets the backfill retry only the failures.
    """
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        net      = data.get("network") or {}
        raw_cidr = net.get("cidr") or ""
        network  = _clean_cidr(raw_cidr)
        country  = net.get("country") or data.get("asn_country_code") or ""
        if raw_cidr and not network:
            # RDAP returned ONLY a default route — a catch-all, not a real
            # allocation. The country that came with it is unreliable, so drop
            # it too rather than mislabel the IP (e.g. a bogus but valid "ID").
            country = ""
        return network, country.upper()
    except IPDefinedError:
        # RFC-1918 / loopback / link-local — not an error, just no public WHOIS.
        return "private", "private"
    except HTTPRateLimitError as exc:
        # Explicit 429 — surfaced distinctly so a real block is obvious in logs.
        print(f"[whois rate-limit {ip}] {exc}", file=sys.stderr, flush=True)
        return None, None
    except Exception as exc:
        print(f"[whois error {ip}] {exc}", file=sys.stderr, flush=True)
        return None, None
