#!/usr/bin/env python3
"""
provider_util.py — label an IP as cloud/hosting infrastructure or a known crawler.

A hit from `3.91.24.7` reads very differently once you know it is an EC2 box
rather than somebody's home connection, and a hit from `66.249.66.1` differently
again once you know it is Googlebot. This module answers that question offline,
in two tiers:

1. **Published prefix lists** — the range files the providers themselves
   publish (AWS, Google Cloud, Google, Cloudflare, Googlebot, Bing). Fetched at
   build time into PROVIDER_DIR and matched by containment. Authoritative.
2. **ASN fallback** — the IPtoASN table already loaded for GeoIP. It catches
   what the lists miss: Azure (Microsoft publishes no stably-addressable range
   file), space the big three hold by direct allocation rather than through
   their cloud products, Facebook's AS32934, and — via keywords in the AS name —
   the long tail of rented VPS, dedicated and colocation providers that have no
   published list at all.

Crawlers win over infrastructure, because "Googlebot" is the more useful thing
to know about an IP that is also inside Google's network. Everything is a single
`category` string (see CATEGORIES); '' means "nothing matched", which for a
public IP usually means a consumer/business ISP.

Config:
    PROVIDER_DIR   directory holding the fetched range files (default /providers)

Missing files are skipped, so the ASN tier works on its own and the whole module
degrades to '' if neither tier has data.
"""

import ipaddress
import json
import os
import re
from bisect import bisect_right

from geoip_util import geoip_asn

# category key -> (display label, icon id used by the templates' SVG sprite)
CATEGORIES = {
    "googlebot":  ("Googlebot",       "googlebot"),
    "bingbot":    ("Bingbot",         "bingbot"),
    "facebook":   ("Facebook",        "facebook"),
    "aws":        ("AWS",             "aws"),
    "gcp":        ("Google Cloud",    "gcp"),
    "google":     ("Google",          "google"),
    "azure":      ("Microsoft/Azure", "azure"),
    "cloudflare": ("Cloudflare",      "cloudflare"),
    "hosting":    ("Hosting/VPS",     "hosting"),
}

PROVIDER_DIR = os.environ.get("PROVIDER_DIR", "/providers")

# Filename -> (category, parser). The Google-style shape ({"prefixes": [{"ipv4Prefix"
# | "ipv6Prefix": ...}]}) is shared by Google Cloud, Googlebot, the special
# crawlers and Bing; AWS and Cloudflare have their own. Order here is the order
# they're consulted, so crawler lists must precede the infrastructure they run in.
SOURCES = [
    ("googlebot.json",        "googlebot",  "google"),
    ("special-crawlers.json", "googlebot",  "google"),
    ("bingbot.json",          "bingbot",    "google"),
    ("cloudflare-v4.txt",     "cloudflare", "text"),
    ("cloudflare-v6.txt",     "cloudflare", "text"),
    ("aws.json",              "aws",        "aws"),
    ("gcp.json",              "gcp",        "google"),
    ("goog.json",             "google",     "google"),
]

# ASNs whose owner we know by number, for space the published lists don't cover
# (direct allocations, corporate ranges, and Azure/Facebook which publish no
# usable file). Checked before the name keywords below.
ASN_OWNERS = {
    16509: "aws", 14618: "aws", 7224: "aws", 8987: "aws", 19047: "aws",
    15169: "google", 396982: "gcp", 19527: "google", 36384: "google", 36492: "google",
    8075: "azure", 8068: "azure", 8069: "azure", 12076: "azure",
    13335: "cloudflare", 209242: "cloudflare",
    32934: "facebook", 63293: "facebook",
}

# Fallback on the AS name, for the same owners under an ASN not listed above.
ASN_NAME_OWNERS = (
    ("aws",        re.compile(r"\b(amazon|aws|ec2)\b", re.I)),
    ("azure",      re.compile(r"\b(microsoft|azure|msn)\b", re.I)),
    ("gcp",        re.compile(r"google[- ]?cloud", re.I)),
    ("google",     re.compile(r"\bgoogle\b", re.I)),
    ("cloudflare", re.compile(r"\bcloudflare\b", re.I)),
    ("facebook",   re.compile(r"\b(facebook|meta[- ]?platforms)\b", re.I)),
)

# Generic "this is a machine in a datacentre, not a person's connection" signal.
# Deliberately broad: it is the weakest claim we make ("Hosting/VPS") and the
# alternative is leaving rented infrastructure indistinguishable from consumer
# ISPs. Named operators first, then the words that hosting ASNs describe
# themselves with.
HOSTING_NAMES = re.compile(
    r"\b(digitalocean|linode|akamai[- ]connected|vultr|choopa|ovh|hetzner|contabo|"
    r"scaleway|online[- ]?s\.?a\.?s|leaseweb|hostinger|godaddy|namecheap|ionos|"
    r"1and1|rackspace|softlayer|alibaba|aliyun|tencent|huawei[- ]?cloud|oracle|"
    r"digital[- ]?pacific|dreamhost|bluehost|hostgator|siteground|wpengine|"
    r"upcloud|netcup|servers?[- ]?com|worldstream|m247|datacamp|g[- ]?core|"
    r"stark[- ]?industries|flokinet|buyvm|frantech|hostwinds|interserver|"
    r"racknerd|virmach|colocrossing|psychz|quadranet|zenlayer|constant|"
    r"ponynet|nforce|ucloud|selectel|timeweb|beget|reg\.ru|first[- ]?root|"
    r"combahton|xhost|pfcloud|aeza|melbicom|serverius|i3d|blix|as?rubicon|"
    r"oracle[- ]?cloud|ibm[- ]?cloud|fastly|bunny|stackpath|vercel|heroku|"
    r"render|railway|fly\.io|equinix|digital[- ]?ocean)\b", re.I)

HOSTING_WORDS = re.compile(
    r"\b(hosting|hoster|vps|v\.?p\.?s|dedicated|datacent(?:er|re)|data[- ]cent(?:er|re)|"
    r"colocation|colo|cloud|server[s]?|webhost\w*|host\w*[- ]?solutions|"
    r"internet[- ]?services|infrastructure)\b", re.I)


class _PrefixSet:
    """Disjoint integer ranges for one source+family, tested by binary search.

    Published lists overlap freely (AWS repeats a prefix per service, Googlebot
    sits inside Google's own space), and nested ranges break a plain bisect, so
    ranges are merged into a disjoint set at load time. Membership is all we
    need — which service or region a prefix belongs to is not recorded.
    """

    __slots__ = ("s", "e")

    def __init__(self):
        self.s = []
        self.e = []

    def add(self, net) -> None:
        self.s.append(int(net.network_address))
        self.e.append(int(net.broadcast_address))

    def merge(self) -> None:
        if not self.s:
            return
        order = sorted(range(len(self.s)), key=self.s.__getitem__)
        starts, ends = [], []
        for i in order:
            a, b = self.s[i], self.e[i]
            if starts and a <= ends[-1] + 1:
                ends[-1] = max(ends[-1], b)
            else:
                starts.append(a)
                ends.append(b)
        self.s, self.e = starts, ends

    def contains(self, x: int) -> bool:
        i = bisect_right(self.s, x) - 1
        return i >= 0 and x <= self.e[i]


# category -> [_PrefixSet, ...], in SOURCES order so lookup keeps that priority.
_tables = []
_loaded = False


def _parse_google(path: str):
    """{"prefixes": [{"ipv4Prefix"|"ipv6Prefix": "1.2.3.0/24"}, ...]} — the shape
    Google Cloud, Googlebot, the special crawlers and Bing all publish."""
    with open(path) as fh:
        for entry in json.load(fh).get("prefixes", []):
            cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
            if cidr:
                yield cidr


def _parse_aws(path: str):
    """AWS splits families across two keys with differently-named prefix fields."""
    with open(path) as fh:
        doc = json.load(fh)
    for entry in doc.get("prefixes", []):
        if entry.get("ip_prefix"):
            yield entry["ip_prefix"]
    for entry in doc.get("ipv6_prefixes", []):
        if entry.get("ipv6_prefix"):
            yield entry["ipv6_prefix"]


def _parse_text(path: str):
    """One CIDR per line (Cloudflare)."""
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


_PARSERS = {"google": _parse_google, "aws": _parse_aws, "text": _parse_text}


def load_providers(directory: str = None) -> int:
    """Load every range file present in *directory*. Returns prefixes ingested.

    Safe to call when the directory or individual files are missing — those
    sources are simply skipped and classification falls back to the ASN tier.
    """
    global _loaded
    directory = directory or PROVIDER_DIR
    _tables.clear()
    total = 0
    for filename, category, shape in SOURCES:
        path = os.path.join(directory, filename)
        if not os.path.exists(path):
            continue
        table = _PrefixSet()
        try:
            for cidr in _PARSERS[shape](path):
                try:
                    table.add(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue  # malformed line — skip it, keep the rest
        except (OSError, json.JSONDecodeError, KeyError):
            continue  # unreadable or truncated download — treat as absent
        table.merge()
        if table.s:
            _tables.append((category, table))
            total += len(table.s)
    _loaded = bool(_tables)
    return total


def classify_asn(asn: int, as_name: str) -> str:
    """Category implied by an IP's ASN alone, or '' if the AS looks like an ISP.

    This is the tier that covers Azure, Facebook, direct allocations held by the
    big providers, and the long tail of VPS/colocation operators.
    """
    if asn in ASN_OWNERS:
        return ASN_OWNERS[asn]
    name = as_name or ""
    if not name:
        return ""
    for category, pattern in ASN_NAME_OWNERS:
        if pattern.search(name):
            return category
    if HOSTING_NAMES.search(name) or HOSTING_WORDS.search(name):
        return "hosting"
    return ""


def classify(ip: str, asn: int = None, as_name: str = "") -> str:
    """Category for *ip*, '' when nothing matches (typically a consumer ISP).

    Published lists are consulted first and in SOURCES order, so a crawler's own
    range wins over the cloud it runs in; the ASN tier only gets a say when no
    list claims the address.
    """
    try:
        x = int(ipaddress.ip_address(ip))
    except ValueError:
        return ""
    for category, table in _tables:
        if table.contains(x):
            return category
    if asn is not None or as_name:
        return classify_asn(asn, as_name)
    return ""


def category_for(ip: str) -> str:
    """Category for *ip*, pulling the ASN tier straight from the GeoIP tables.

    The convenience wrapper callers want: `classify()` takes the ASN as an
    argument so it can be unit-tested and reused, this looks it up. Returns ''
    when nothing matches or no data is loaded at all.
    """
    hit = geoip_asn(ip)
    if hit is None:
        return classify(ip)
    return classify(ip, asn=hit[0], as_name=hit[1])


def label(category: str) -> str:
    """Display label for a category key ('' for none/unknown)."""
    return CATEGORIES.get(category, ("", ""))[0]
