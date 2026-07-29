#!/usr/bin/env python3
"""Offline GeoIP resolution from sapics/ip-location-db CSV exports.

Pure standard library: the CSV range tables are loaded once into sorted arrays
and queried by binary search, answering ``(network_cidr, country)`` for an IP
with no network round-trip. This is the first-choice resolver — instant,
offline, and immune to RDAP rate limits; RDAP is consulted only for IPs GeoIP
can't place.

Two independent tables, both optional:
  * a **country** table (a geolocation DB such as DB-IP Lite) → the country code
  * an **ASN** table (e.g. IPtoASN) → the range whose bounds give the network CIDR

If neither is configured/loaded, ``geoip_lookup()`` always returns ``None`` and
the caller falls back to RDAP. Configure via the ``GEOIP_COUNTRY_DB`` and
``GEOIP_ASN_DB`` env vars (each a comma-separated list of CSV paths; IPv4 and
IPv6 files can both be listed — family is inferred per row).

CSV layout (sapics ip-location-db):
    country: ip_range_start, ip_range_end, country_code
    asn:     ip_range_start, ip_range_end, asn, as_name
The ``-num`` variants store the bounds as integers; the parser also accepts the
dotted form, so either export works.
"""

import bisect
import csv
import ipaddress
import os

# 32-bit boundary: an integer bound at or below this is treated as IPv4, above
# as IPv6. (sapics ships IPv4 and IPv6 in separate files, and dotted rows carry
# their own version, so this only disambiguates bare -num integers.)
_V4_MAX = 0xFFFFFFFF


class _RangeTable:
    """Sorted, non-overlapping integer ranges with an optional per-range value.

    Bounds are plain Python ints (lists, not array('Q')) because IPv6 addresses
    are 128-bit and overflow any fixed-width array typecode.
    """

    __slots__ = ("s", "e", "v")

    def __init__(self, with_values: bool):
        self.s = []                  # range starts, ascending after load_geoip()
        self.e = []                  # matching range ends
        self.v = [] if with_values else None  # matching values (e.g. country code)

    def lookup(self, x: int):
        """Index of the range containing *x*, or None."""
        i = bisect.bisect_right(self.s, x) - 1
        if i >= 0 and x <= self.e[i]:
            return i
        return None


_country4 = _RangeTable(with_values=True)
_country6 = _RangeTable(with_values=True)
_asn4 = _RangeTable(with_values=False)
_asn6 = _RangeTable(with_values=False)
_loaded = False


def _to_int(token: str):
    """Parse a range bound that may be a bare integer (-num) or a dotted IP."""
    token = token.strip()
    if not token:
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return int(ipaddress.ip_address(token))
    except ValueError:
        return None


def _family_int(x: int, hint6: bool) -> bool:
    """True if integer bound *x* is IPv6. Trust the filename hint, but a value
    above the 32-bit range is unambiguously v6 regardless."""
    return hint6 or x > _V4_MAX


def _load_csv(path: str, kind: str) -> int:
    """Load one CSV into the country or asn tables. Returns rows ingested."""
    hint6 = "ipv6" in os.path.basename(path).lower()
    min_cols = 3 if kind == "country" else 2
    rows = 0
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < min_cols:
                continue
            start = _to_int(row[0])
            end = _to_int(row[1])
            if start is None or end is None or end < start:
                continue  # header line or malformed row
            v6 = _family_int(start, hint6)
            if kind == "country":
                tab = _country6 if v6 else _country4
                tab.s.append(start)
                tab.e.append(end)
                tab.v.append(row[2].strip().upper())
            else:
                tab = _asn6 if v6 else _asn4
                tab.s.append(start)
                tab.e.append(end)
            rows += 1
    return rows


def _sort_table(tab: _RangeTable) -> None:
    """Sort a table's parallel arrays by range start (files are usually already
    sorted, but don't assume it — bisect requires it)."""
    if not tab.s:
        return
    order = sorted(range(len(tab.s)), key=tab.s.__getitem__)
    if order == list(range(len(tab.s))):
        return  # already sorted — skip the rebuild
    tab.s = [tab.s[i] for i in order]
    tab.e = [tab.e[i] for i in order]
    if tab.v is not None:
        tab.v = [tab.v[i] for i in order]


def load_geoip() -> tuple[int, int]:
    """Load the tables named by GEOIP_COUNTRY_DB / GEOIP_ASN_DB (comma-separated
    paths). Missing files are skipped. Returns (country_rows, asn_rows)."""
    global _loaded
    country_rows = asn_rows = 0
    for path in _paths("GEOIP_COUNTRY_DB"):
        country_rows += _load_csv(path, "country")
    for path in _paths("GEOIP_ASN_DB"):
        asn_rows += _load_csv(path, "asn")
    for tab in (_country4, _country6, _asn4, _asn6):
        _sort_table(tab)
    _loaded = country_rows > 0 or asn_rows > 0
    return country_rows, asn_rows


def _paths(env: str) -> list:
    return [p for p in (p.strip() for p in os.environ.get(env, "").split(","))
            if p and os.path.exists(p)]


def _range_to_cidr(start: int, end: int, addr) -> str:
    """The single CIDR within [start, end] that contains *addr* (the minimal
    aggregate boundary the address falls in), or '' if it can't be formed."""
    try:
        first = ipaddress.ip_address(start)
        last = ipaddress.ip_address(end)
        for net in ipaddress.summarize_address_range(first, last):
            if addr in net:
                # Never emit a default route — /0 matches everything and would
                # poison the network cache and the /networks aggregation.
                return "" if net.prefixlen == 0 else str(net)
    except (ValueError, TypeError):
        pass
    return ""


def geoip_lookup(ip: str):
    """Resolve *ip* offline to (network_cidr, country).

    Returns None on a genuine miss (neither table has the IP) so the caller can
    fall back to RDAP. On a hit either field may be '' (e.g. country known but
    no ASN range, or vice versa)."""
    if not _loaded:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    x = int(addr)
    v6 = addr.version == 6
    ctab = _country6 if v6 else _country4
    atab = _asn6 if v6 else _asn4

    country = ""
    ci = ctab.lookup(x)
    if ci is not None:
        country = ctab.v[ci]

    network = ""
    ai = atab.lookup(x)
    if ai is not None:
        network = _range_to_cidr(atab.s[ai], atab.e[ai], addr)

    if ci is None and ai is None:
        return None
    return network, country
