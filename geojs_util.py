#!/usr/bin/env python3
"""
geojs_util.py — IP data from GeoJS (https://www.geojs.io), the first source tried.

GeoJS answers with the country, the AS number and the AS/organisation name. It
does **not** return a network CIDR, so it cannot fill the `network` column on
its own: the caller pairs it with the local ASN ranges (or RDAP) for the CIDR.
What it does give is a *live* country and AS name — fresher than the bundled
GeoIP tables, and without RDAP's rate limiting.

One request can carry many addresses (`?ip=a,b,c`), which is what makes it
usable as the primary source here: the watcher never looks an IP up as the log
line arrives, it resolves the pending backlog in batches, so a scanner flood
costs one request per GEOJS_BATCH addresses instead of one per IP.

Config:
    GEOJS              "0" disables it entirely (default on)
    GEOJS_URL          batch endpoint (default https://get.geojs.io/v1/ip/geo.json)
    GEOJS_BATCH        addresses per request (default 50)
    GEOJS_TIMEOUT      seconds per request (default 10)
    GEOJS_FAIL_STREAK  consecutive failures that pause it (default 3)
    GEOJS_COOLDOWN     seconds to stay paused (default 600)

Never returns partial nonsense: GeoJS answers for a private address with a
placeholder AS ("AS64512 Unknown"), so those are filtered out rather than
stored — see _useful().
"""

import ipaddress
import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

GEOJS_URL = os.environ.get("GEOJS_URL", "https://get.geojs.io/v1/ip/geo.json")
GEOJS_BATCH = max(1, int(os.environ.get("GEOJS_BATCH", "50")))
GEOJS_TIMEOUT = float(os.environ.get("GEOJS_TIMEOUT", "10"))
GEOJS_FAIL_STREAK = int(os.environ.get("GEOJS_FAIL_STREAK", "3"))
GEOJS_COOLDOWN = int(os.environ.get("GEOJS_COOLDOWN", "600"))
ENABLED = os.environ.get("GEOJS", "1").strip().lower() not in ("0", "false", "no", "off", "")

USER_AGENT = "nginx-ipwatch (+https://github.com/19points/nginx-ipwatch)"

# GeoJS's stand-in for "I have nothing": a private-range ASN and a literal
# "Unknown" org. Storing either would be worse than storing nothing, because a
# row that looks answered is never retried.
_PLACEHOLDER_ASN = 64512
_PLACEHOLDER_ORG = "unknown"

# Same breaker shape as the RDAP one in nginx-ipwatch.py: a service that starts
# refusing us is given room to recover instead of being hammered.
_fails = 0
_paused_until = 0.0


@dataclass
class GeoResult:
    """What GeoJS knows about one address. `network` is deliberately absent —
    the API doesn't return one."""

    ip: str
    country: str = ""
    asn: int = 0
    org: str = ""

    def useful(self) -> bool:
        return bool(self.country or self.asn or self.org)


def available() -> bool:
    """True if GeoJS is enabled and not in a post-failure cooldown."""
    return ENABLED and time.monotonic() >= _paused_until


def _note_failure() -> None:
    global _fails, _paused_until
    _fails += 1
    if _fails >= GEOJS_FAIL_STREAK:
        _paused_until = time.monotonic() + GEOJS_COOLDOWN
        _fails = 0


def _note_success() -> None:
    global _fails
    _fails = 0


def _useful(entry: dict) -> GeoResult:
    """Turn one API object into a GeoResult, dropping placeholder answers."""
    ip = str(entry.get("ip", "")).strip()
    asn = entry.get("asn") or 0
    try:
        asn = int(asn)
    except (TypeError, ValueError):
        asn = 0
    org = str(entry.get("organization_name") or "").strip()
    if asn == _PLACEHOLDER_ASN or org.lower() == _PLACEHOLDER_ORG:
        asn, org = 0, ""
    country = str(entry.get("country_code") or "").strip().upper()
    return GeoResult(ip=ip, country=country, asn=asn, org=org)


def lookup_many(ips) -> dict:
    """Resolve several addresses in one request.

    Returns {ip: GeoResult} containing only the addresses GeoJS said something
    useful about — a missing key means "no answer", which the caller should
    treat as a miss and try the next source for. Returns {} (without making a
    request) when GeoJS is disabled or paused.
    """
    if not available():
        return {}
    wanted = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_private:
                continue  # no public registry data exists; don't waste a slot
        except ValueError:
            continue
        wanted.append(ip)
    if not wanted:
        return {}

    out = {}
    for i in range(0, len(wanted), GEOJS_BATCH):
        chunk = wanted[i:i + GEOJS_BATCH]
        url = f"{GEOJS_URL}?{urllib.parse.urlencode({'ip': ','.join(chunk)})}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=GEOJS_TIMEOUT) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                doc = json.loads(resp.read().decode(charset, errors="replace"))
        except Exception:  # noqa: BLE001 — any failure is just a miss, never fatal
            _note_failure()
            if not available():
                break  # breaker tripped mid-sweep; stop asking
            continue
        _note_success()
        # A single-address query answers with an object, a batch with a list.
        entries = doc if isinstance(doc, list) else [doc]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            result = _useful(entry)
            if result.ip and result.useful():
                out[result.ip] = result
    return out


def lookup(ip: str):
    """Resolve one address. Returns a GeoResult or None."""
    return lookup_many([ip]).get(ip)
