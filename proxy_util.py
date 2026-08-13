#!/usr/bin/env python3
"""Third-party WHOIS lookups for IPs the registries won't answer for us directly.

Why this exists: RIPE permanently bans a source IP that has queried its Database
Query Service too hard —

    ERROR:201: access denied for <your ip>
    Sorry, access from your host has been permanently denied because of a
    repeated excessive querying.

— and once that lands, both port-43 WHOIS and RDAP stop answering, so
`whois_util.whois_lookup` fails for *every* IP with no way back except asking
RIPE to lift the block. The IPs then look "unresolvable" when the registry data
is in fact perfectly public: it's our host that's blocked, not the data.

The sources here sidestep that by letting somebody else make the registry query:

  * **RIPEstat** (``stat.ripe.net``) — RIPE's *data* API, a separate service from
    the banned query service and keyless. Its ``network-info`` call returns the
    **BGP-announced prefix**, which is both more specific and more useful for
    grouping scanners than the RIR allocation RDAP reports — ``78.61.136.0/22``
    rather than ``78.61.0.0/17``, a block 32x larger holding mostly unrelated
    hosts.
  * **whois.com** — scrapes the raw registry output they render. Fragile by
    nature (it depends on their markup), so it's only a fallback for when
    RIPEstat is unreachable too.

Both are consulted **only** by the web UI's manual, one-IP-at-a-time lookup.
The watcher's automatic path never touches them, so this cannot turn into the
next source of a ban.
"""

import html
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

TIMEOUT = float(os.environ.get("PROXY_LOOKUP_TIMEOUT", "15"))

# RIPEstat asks callers to identify themselves via sourceapp so they can contact
# a misbehaving client instead of blocking it outright.
SOURCEAPP = os.environ.get("RIPESTAT_SOURCEAPP", "nginx-ipwatch")
RIPESTAT = "https://stat.ripe.net/data"

USER_AGENT = "nginx-ipwatch (+https://github.com/19points/nginx-ipwatch)"

# Order the manual lookup tries sources in. Override with PROXY_SOURCES, e.g.
# "whoiscom" to skip RIPEstat entirely, or "ripestat" to never scrape.
DEFAULT_SOURCES = ("ripestat", "whoiscom")


@dataclass
class LookupResult:
    """What a source managed to find. Only *network* and *country* are stored in
    the DB; asn/netname are shown in the UI so a result can be eyeballed."""

    ip: str
    network: str = ""
    country: str = ""
    asn: str = ""
    netname: str = ""
    source: str = ""

    def useful(self) -> bool:
        """True if there's anything worth writing to the DB."""
        return bool(self.network or self.country)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def _get_json(url: str) -> dict:
    return json.loads(_get(url))


# ---------------------------------------------------------------------------
# CIDR helpers
# ---------------------------------------------------------------------------

def _most_specific(ip: str, cidrs) -> str:
    """The narrowest CIDR in *cidrs* that actually contains *ip*.

    Registries hand back a mix of covering prefixes (a /17 and a /20 and a /22
    can all be on file for one address). The narrowest is the real routed block
    and the one that makes /networks aggregation meaningful. Prefix-length 0 is
    refused — a default route matches every IP and would poison the cache.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    best = None
    for cidr in cidrs:
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0 or addr not in net:
            continue
        if best is None or net.prefixlen > best.prefixlen:
            best = net
    return str(best) if best else ""


def _range_to_cidrs(text: str):
    """CIDRs covering an ``a.b.c.d - e.f.g.h`` inetnum/NetRange range.

    Registries state allocations as inclusive ranges that often aren't a single
    prefix (78.61.0.0 - 78.61.199.255 is a /17 + /18 + /21), so this yields all
    of them and lets _most_specific pick the one holding our IP.
    """
    if "-" not in text:
        return []
    first, _, last = text.partition("-")
    try:
        return [
            str(net) for net in ipaddress.summarize_address_range(
                ipaddress.ip_address(first.strip()), ipaddress.ip_address(last.strip())
            )
        ]
    except (ValueError, TypeError):
        return []


# ---------------------------------------------------------------------------
# Raw WHOIS/RPSL text parsing (shared by the whois.com scrape)
# ---------------------------------------------------------------------------

# Keys we care about, lower-cased. RIPE/APNIC/AFRINIC use RPSL (inetnum, route,
# netname); ARIN uses its own labels (NetRange, CIDR, Country, NetName).
_ROUTE_KEYS = {"route", "route6"}
_RANGE_KEYS = {"inetnum", "inet6num", "netrange"}
_CIDR_KEYS = {"cidr"}
_COUNTRY_KEYS = {"country"}
_NAME_KEYS = {"netname"}


def _parse_whois_text(text: str) -> dict:
    """Pull the fields we need out of raw ``key: value`` WHOIS output.

    Returns dict with 'cidrs' (candidate networks, most-specific chosen later),
    'country', 'netname', 'asn'. Comment lines (% and #) are skipped so the
    registry's own disclaimers and error banners can't be mistaken for data.
    """
    cidrs, country, netname, asn = [], "", "", ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "%#":
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key in _ROUTE_KEYS or key in _CIDR_KEYS:
            # ARIN puts several comma-separated prefixes on one CIDR line.
            cidrs.extend(p.strip() for p in value.split(","))
        elif key in _RANGE_KEYS:
            cidrs.extend(_range_to_cidrs(value))
        elif key in _COUNTRY_KEYS and not country:
            country = value.upper()[:2]
        elif key in _NAME_KEYS and not netname:
            netname = value
        elif key == "origin" and not asn:
            asn = value.upper().removeprefix("AS")
    return {"cidrs": cidrs, "country": country, "netname": netname, "asn": asn}


# ---------------------------------------------------------------------------
# Source: RIPEstat
# ---------------------------------------------------------------------------

def _ripestat_records(payload: dict) -> dict:
    """Flatten a RIPEstat whois data-call payload into _parse_whois_text's shape.

    The call returns records as lists of {key, value} dicts — same fields as raw
    WHOIS, already split — plus irr_records holding the route objects.
    """
    cidrs, country, netname, asn = [], "", "", ""
    data = payload.get("data") or {}
    groups = list(data.get("records") or []) + list(data.get("irr_records") or [])
    for record in groups:
        for attr in record or []:
            key = str(attr.get("key", "")).strip().lower()
            value = str(attr.get("value", "")).strip()
            if not value:
                continue
            if key in _ROUTE_KEYS or key in _CIDR_KEYS:
                cidrs.extend(p.strip() for p in value.split(","))
            elif key in _RANGE_KEYS:
                cidrs.extend(_range_to_cidrs(value))
            elif key in _COUNTRY_KEYS and not country:
                country = value.upper()[:2]
            elif key in _NAME_KEYS and not netname:
                netname = value
            elif key == "origin" and not asn:
                asn = value.upper().removeprefix("AS")
    return {"cidrs": cidrs, "country": country, "netname": netname, "asn": asn}


def ripestat_lookup(ip: str) -> LookupResult:
    """Resolve *ip* via RIPEstat's data API (two calls, either may fail alone).

    ``network-info`` gives the announced BGP prefix and origin AS; ``whois``
    gives country and netname. They're independent — a result with only one of
    the two is still worth having, so a failure in either is swallowed and the
    caller decides whether what came back is useful.
    """
    result = LookupResult(ip=ip, source="ripestat")
    resource = urllib.parse.quote(ip, safe="")

    try:
        data = (_get_json(
            f"{RIPESTAT}/network-info/data.json?resource={resource}&sourceapp={SOURCEAPP}"
        ).get("data") or {})
        result.network = _most_specific(ip, [data.get("prefix") or ""])
        result.asn = ",".join(str(a) for a in (data.get("asns") or []))
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        pass

    try:
        parsed = _ripestat_records(_get_json(
            f"{RIPESTAT}/whois/data.json?resource={resource}&sourceapp={SOURCEAPP}"
        ))
        result.country = parsed["country"]
        result.netname = parsed["netname"]
        if not result.network:
            # network-info had nothing (e.g. an allocated but unannounced block)
            # — fall back to the narrowest route/inetnum on file.
            result.network = _most_specific(ip, parsed["cidrs"])
        result.asn = result.asn or parsed["asn"]
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        pass

    return result


# ---------------------------------------------------------------------------
# Source: whois.com
# ---------------------------------------------------------------------------

# The raw registry response is rendered verbatim inside this block. Scraping is
# inherently brittle: if whois.com restyles the page this regex is what breaks,
# and the lookup reports "no data" rather than crashing.
_RAW_BLOCK = re.compile(
    r'<pre[^>]*class="[^"]*df-raw[^"]*"[^>]*>(.*?)</pre>', re.DOTALL | re.IGNORECASE
)
_TAG = re.compile(r"<[^>]+>")


def whoiscom_lookup(ip: str) -> LookupResult:
    """Resolve *ip* by scraping the raw WHOIS text whois.com displays.

    IPv4 only: whois.com strips the colons out of an IPv6 address and looks it up
    as a *domain* (2001:4860:4860::8888 becomes "2001486048608888.com"), returning
    a captcha page rather than registry data. Bailing out early keeps us from
    hammering that endpoint for a result it can never give.
    """
    result = LookupResult(ip=ip, source="whois.com")
    try:
        if ipaddress.ip_address(ip).version != 4:
            return result
    except ValueError:
        return result

    try:
        page = _get(f"https://www.whois.com/whois/{urllib.parse.quote(ip, safe='')}")
    except (urllib.error.URLError, OSError):
        return result

    blocks = _RAW_BLOCK.findall(page)
    if not blocks:
        return result

    # Emails are swapped for <img> tags in the markup — strip tags before
    # parsing so a stray '>' can't split a key/value line.
    text = html.unescape(_TAG.sub("", "\n".join(blocks)))
    parsed = _parse_whois_text(text)
    result.network = _most_specific(ip, parsed["cidrs"])
    result.country = parsed["country"]
    result.netname = parsed["netname"]
    result.asn = parsed["asn"]
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

SOURCES = {"ripestat": ripestat_lookup, "whoiscom": whoiscom_lookup}


def configured_sources() -> tuple:
    """Source names to try, in order (PROXY_SOURCES env var, else the default)."""
    raw = os.environ.get("PROXY_SOURCES", "")
    names = tuple(n.strip().lower() for n in raw.split(",") if n.strip() in SOURCES)
    return names or DEFAULT_SOURCES


def lookup(ip: str) -> tuple:
    """Try each configured source until one returns something useful.

    Returns ``(LookupResult | None, tried)`` where *tried* names the sources
    consulted, so the UI can say *what* was asked rather than just "no data".
    A source that raises is treated as a miss and the next one is tried — a
    manual lookup should degrade to "nothing found", never to a 500.
    """
    tried = []
    for name in configured_sources():
        tried.append(name)
        try:
            result = SOURCES[name](ip)
        except Exception:  # noqa: BLE001 — a broken source must not break the UI
            continue
        if result.useful():
            return result, tried
    return None, tried
