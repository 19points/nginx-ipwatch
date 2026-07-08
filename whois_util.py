#!/usr/bin/env python3
"""Shared RDAP WHOIS helper used by the watcher and the backfill tool.

Kept in its own module so `nginx-ipwatch.py` (the writer) and `backfill.py`
(the retry tool) resolve IPs identically — the watcher's filename contains a
hyphen and cannot be imported, so the shared logic lives here instead.
"""

import sys

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError


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
        net     = data.get("network") or {}
        network = net.get("cidr") or ""
        country = net.get("country") or data.get("asn_country_code") or ""
        return network, country.upper()
    except IPDefinedError:
        # RFC-1918 / loopback / link-local — not an error, just no public WHOIS.
        return "private", "private"
    except Exception as exc:
        print(f"[whois error {ip}] {exc}", file=sys.stderr, flush=True)
        return None, None
