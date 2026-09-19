#!/usr/bin/env python3
"""
client_util.py — what the client *says* it is, from the nginx User-Agent.

Everything else in this project identifies an IP by facts: which published
range it falls in, which AS announces it. The User-Agent is different — it is
a **claim**, typed by whoever sent the request, and worth exactly nothing on
its own. `python-requests/2.31` is honest; `Googlebot/2.1` from a rented VPS is
a lie, and a common one.

So a UA is stored as a claim and rendered next to a *verdict* that compares it
with the IP's category (see provider_util), which is the part that can't be
faked:

    UA says Googlebot + IP in Googlebot's published range   -> verified
    UA says Googlebot + IP in Google's wider space          -> unverified
    UA says Googlebot + IP anywhere else                    -> impersonating
    UA says ahrefs / curl / nmap                            -> declared
    UA says Chrome                                          -> (nothing)

The impersonation case is the one worth having this feature for. The "declared"
ones can't be verified at all — SEO crawlers and HTTP libraries publish no
ranges — so they are reported as the claim they are, never as a fact.
"""

import re

# Client key -> (display label, kind). Kinds:
#   crawler  a search/social crawler that publishes IP ranges, so it is checkable
#   seo      a commercial crawler that doesn't publish ranges
#   tool     an HTTP library or scanning tool — no pretence of being a browser
#   browser  an ordinary browser
CLIENTS = {
    "googlebot":   ("Googlebot",       "crawler"),
    "bingbot":     ("Bingbot",         "crawler"),
    "facebook":    ("Facebook",        "crawler"),
    "applebot":    ("Applebot",        "seo"),
    "yandexbot":   ("YandexBot",       "seo"),
    "baiduspider": ("Baiduspider",     "seo"),
    "duckduckbot": ("DuckDuckBot",     "seo"),
    "amazonbot":   ("Amazonbot",       "seo"),
    "bytespider":  ("Bytespider",      "seo"),
    "gptbot":      ("GPTBot",          "seo"),
    "claudebot":   ("ClaudeBot",       "seo"),
    "ahrefs":      ("AhrefsBot",       "seo"),
    "semrush":     ("SemrushBot",      "seo"),
    "mj12":        ("MJ12bot",         "seo"),
    "dotbot":      ("DotBot",          "seo"),
    "petalbot":    ("PetalBot",        "seo"),
    "censys":      ("Censys",          "tool"),
    "shodan":      ("Shodan",          "tool"),
    "zgrab":       ("zgrab",           "tool"),
    "masscan":     ("masscan",         "tool"),
    "nmap":        ("Nmap",            "tool"),
    "sqlmap":      ("sqlmap",          "tool"),
    "nikto":       ("Nikto",           "tool"),
    "wpscan":      ("WPScan",          "tool"),
    "curl":        ("curl",            "tool"),
    "wget":        ("Wget",            "tool"),
    "python":      ("Python HTTP",     "tool"),
    "go-http":     ("Go HTTP",         "tool"),
    "java":        ("Java HTTP",       "tool"),
    "okhttp":      ("OkHttp",          "tool"),
    "libwww":      ("libwww-perl",     "tool"),
    "scrapy":      ("Scrapy",          "tool"),
    "headless":    ("Headless Chrome", "tool"),
    "browser":     ("Browser",         "browser"),
}

# Ordered: first match wins, so the specific patterns precede the generic ones
# (Headless Chrome before Chrome, bingbot before the bare "bot" cases).
_PATTERNS = [
    ("googlebot",   re.compile(r"googlebot|google-inspectiontool|storebot-google", re.I)),
    ("bingbot",     re.compile(r"bingbot|adidxbot|msnbot", re.I)),
    ("facebook",    re.compile(r"facebookexternalhit|facebookbot|meta-external", re.I)),
    ("applebot",    re.compile(r"applebot", re.I)),
    ("yandexbot",   re.compile(r"yandex(bot|images|mobilebot)", re.I)),
    ("baiduspider", re.compile(r"baiduspider", re.I)),
    ("duckduckbot", re.compile(r"duckduck(bot|go-favicons)", re.I)),
    ("amazonbot",   re.compile(r"amazonbot", re.I)),
    ("bytespider",  re.compile(r"bytespider|bytedance", re.I)),
    ("gptbot",      re.compile(r"gptbot|oai-searchbot|chatgpt-user", re.I)),
    ("claudebot",   re.compile(r"claudebot|claude-web|anthropic-ai", re.I)),
    ("ahrefs",      re.compile(r"ahrefs", re.I)),
    ("semrush",     re.compile(r"semrush", re.I)),
    ("mj12",        re.compile(r"mj12bot", re.I)),
    ("dotbot",      re.compile(r"\bdotbot\b", re.I)),
    ("petalbot",    re.compile(r"petalbot|aspiegel", re.I)),
    ("censys",      re.compile(r"censys", re.I)),
    ("shodan",      re.compile(r"shodan", re.I)),
    ("zgrab",       re.compile(r"zgrab", re.I)),
    ("masscan",     re.compile(r"masscan", re.I)),
    ("nmap",        re.compile(r"nmap|nse", re.I)),
    ("sqlmap",      re.compile(r"sqlmap", re.I)),
    ("nikto",       re.compile(r"nikto", re.I)),
    ("wpscan",      re.compile(r"wpscan", re.I)),
    ("headless",    re.compile(r"headlesschrome|phantomjs|puppeteer|playwright", re.I)),
    ("curl",        re.compile(r"^curl/|\bcurl/", re.I)),
    ("wget",        re.compile(r"\bwget", re.I)),
    ("python",      re.compile(r"python-requests|python-urllib|aiohttp|httpx", re.I)),
    ("go-http",     re.compile(r"go-http-client", re.I)),
    ("java",        re.compile(r"^java/|apache-httpclient", re.I)),
    ("okhttp",      re.compile(r"okhttp", re.I)),
    ("libwww",      re.compile(r"libwww-perl|lwp::", re.I)),
    ("scrapy",      re.compile(r"scrapy", re.I)),
    ("browser",     re.compile(r"mozilla/|applewebkit|chrome/|firefox/|safari/|edg/", re.I)),
]

# Which IP categories corroborate a crawler's claim. The first entry of each set
# is the published-range match (-> verified); the rest are the operator's wider
# space, which supports the claim without proving it (-> unverified). Anything
# else means the claim is inconsistent with where the request came from.
#
# This map is also what web.py turns into SQL for the "impersonating" filter, so
# the rule the UI filters on and the rule it displays can't drift apart.
VERIFIABLE = {
    "googlebot": ("googlebot", "google", "gcp"),
    "bingbot":   ("bingbot", "azure"),
    "facebook":  ("facebook",),
}

VERDICTS = {
    "verified":      ("verified", "The IP is in this crawler's published range"),
    "unverified":    ("unverified", "The IP belongs to the operator but is not in the crawler's published range"),
    "impersonating": ("impersonating", "The UA claims a crawler the IP cannot belong to"),
    "declared":      ("declared", "Self-reported; this client publishes no ranges to check against"),
}

# Nginx's combined format ends with "$http_referer" "$http_user_agent", so the
# UA is the last quoted field. Nginx escapes any quote inside a value as \x22,
# so an unescaped " always terminates the field and naive matching is safe.
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')

MAX_UA = 300  # stored length cap; real UAs are far shorter, junk can be huge


def extract_user_agent(line: str) -> str:
    """The User-Agent from an nginx access-log line, or '' if there isn't one.

    Assumes the stock `combined` format (UA last in quotes). A line from a
    custom format with no quoted fields, or with '-' for the UA, yields ''.
    """
    fields = _QUOTED.findall(line)
    if len(fields) < 2:
        return ""
    ua = fields[-1].strip()
    if ua in ("", "-"):
        return ""
    return ua[:MAX_UA]


def classify_client(ua: str) -> str:
    """Client key for a User-Agent string, or '' if it says nothing useful."""
    if not ua:
        return ""
    for key, pattern in _PATTERNS:
        if pattern.search(ua):
            return key
    return ""


def kind(client: str) -> str:
    """'crawler', 'seo', 'tool', 'browser', or '' for an unrecognised client."""
    return CLIENTS.get(client, ("", ""))[1]


def label(client: str) -> str:
    return CLIENTS.get(client, ("", ""))[0]


def verdict(client: str, category) -> str:
    """Compare the UA's claim against the IP's category.

    Returns 'verified', 'unverified', 'impersonating', 'declared', or '' when
    there is nothing to say (a browser, or an unrecognised UA). A category of
    None means the IP hasn't been categorised yet, so a crawler claim is left
    unresolved rather than being called a lie on missing evidence.
    """
    if client not in CLIENTS:
        return ""
    if client in VERIFIABLE:
        if category is None:
            return ""
        allowed = VERIFIABLE[client]
        if category == allowed[0]:
            return "verified"
        if category in allowed[1:]:
            return "unverified"
        return "impersonating"
    if kind(client) in ("seo", "tool"):
        return "declared"
    return ""
