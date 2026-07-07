"""Web-surface recon tools — the passive-first bug-bounty half of recce.

Where `recon/tools.py` enumerates a single host (nmap/ftp/smb — the HTB/CTF box),
this module maps the *wide* surface of a domain the way real bug-bounty recon
does: cert-transparency + passive-DNS subdomain discovery, deterministic
interesting-host triage, a gentle alive-probe, a bot-WAF pre-check, and historical
URLs from the Wayback CDX. It mirrors the operator's own recon playbook
(recon-methodology.md): *start passive, vet the WAF before investing time, then
probe only what's alive.*

THE LINE (enforced by tool choice, documented for the model):
  - PASSIVE — reads public data (crt.sh, hackertarget passive DNS, Wayback). Never
    touches the target's servers. Safe on any domain.  →  subdomain_enum, wayback_urls
  - DETERMINISTIC — pure local computation, no network at all.  →  triage_hosts
  - ACTIVE — sends requests to the target; in-scope only, and gently (short
    timeouts, capped host count, no brute force).  →  http_probe, waf_check

Everything is read-only: no content brute-force, no exploitation, no writes. Real
tools use only the Python stdlib (urllib) so there are no extra binaries to
install, and they degrade to a clear failed ToolResult when the network isn't
there. `build_web_tools(simulate=True)` swaps in canned outputs so the whole loop
runs offline.
"""

from __future__ import annotations

import json
import re
import ssl
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from recce.tools import Tool
from recce.types import ToolResult

# --- input schemas --------------------------------------------------------

SCHEMA_DOMAIN = {
    "type": "object",
    "properties": {
        "domain": {
            "type": "string",
            "description": "Apex domain of the authorized program, e.g. 'example.com'.",
        }
    },
    "required": ["domain"],
}
SCHEMA_TRIAGE = {
    "type": "object",
    "properties": {
        "hosts": {
            "type": "string",
            "description": "Hostnames to rank — newline/comma/space separated "
            "(e.g. the output of subdomain_enum).",
        }
    },
    "required": ["hosts"],
}
SCHEMA_PROBE = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "string",
            "description": "Hostnames/URLs to probe — newline/comma/space separated. "
            "In-scope hosts only.",
        },
        "limit": {
            "type": "integer",
            "description": "Max hosts to probe this call (default 40, hard cap 60).",
        },
    },
    "required": ["targets"],
}
SCHEMA_WAF = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "Host or URL to fingerprint for a bot-WAF (in-scope only).",
        }
    },
    "required": ["target"],
}
SCHEMA_WAYBACK = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "description": "Domain to pull historical URLs for."},
        "limit": {
            "type": "integer",
            "description": "Max URLs to return (default 200, hard cap 500).",
        },
    },
    "required": ["domain"],
}

# Hosts worth a first look: forgotten/pre-prod/privileged surface is where the
# picked-over front door isn't. Mirrors Phase 2 of the recon playbook.
_INTERESTING = re.compile(
    r"\b(dev|develop|stag(e|ing)|test|qa|uat|preprod|pre-prod|sandbox|sbx|api|"
    r"admin|internal|intranet|corp|vpn|git|gitlab|jenkins|ci|jira|confluence|"
    r"grafana|kibana|old|legacy|beta|demo|staging|backup|s3|storage|mail|"
    r"portal|dashboard|manage|console|auth|sso|oauth|payment|billing)",
    re.I,
)

# Bot-WAF / CDN fingerprints. header-substring and cookie-name signatures; a heavy
# one means "as recon, deprioritise — it'll eat your time" (playbook Phase 0.5).
_WAF_SIGS: list[tuple[str, str, str]] = [
    # (vendor, kind, needle)  kind ∈ {"header", "cookie", "server"}
    ("DataDome", "header", "x-datadome"),
    ("DataDome", "cookie", "datadome"),
    ("Cloudflare", "header", "cf-ray"),
    ("Cloudflare", "cookie", "__cf_bm"),
    ("Cloudflare", "server", "cloudflare"),
    ("Akamai", "header", "x-akamai-transformed"),
    ("Akamai", "server", "akamaighost"),
    ("Imperva/Incapsula", "header", "x-iinfo"),
    ("Imperva/Incapsula", "cookie", "visid_incap"),
    ("Imperva/Incapsula", "cookie", "incap_ses"),
    ("PerimeterX/HUMAN", "header", "x-px"),
    ("PerimeterX/HUMAN", "cookie", "_px"),
    ("AWS WAF / CloudFront", "server", "cloudfront"),
    ("AWS WAF", "header", "x-amzn-waf"),
    ("Sucuri", "header", "x-sucuri-id"),
    ("Sucuri", "server", "sucuri"),
    ("F5 BIG-IP", "cookie", "bigipserver"),
    ("Fastly", "header", "x-served-by"),
]

# WAFs that meaningfully raise the effort bar for a beginner (playbook's "pick a
# different target" list) vs. plain CDNs that are usually harmless.
_HEAVY_WAF = {"DataDome", "Imperva/Incapsula", "PerimeterX/HUMAN", "Akamai"}

_UA = "recce/0.2 (+authorized recon)"


def _ssl_ctx() -> ssl.SSLContext:
    """A verifying TLS context backed by certifi's CA bundle. Many Python installs
    (notably python.org macOS builds) ship without a usable system trust store, so
    the passive HTTPS sources fail to verify; certifi fixes that without ever
    turning verification off. Falls back to the default context if certifi's absent."""
    try:
        import certifi  # noqa: PLC0415

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


_SSL = _ssl_ctx()


def _get(url: str, timeout: int = 8, read: int = 4096) -> tuple[Optional[int], dict, str]:
    """One GET. Returns (status, lowercased-header-dict, body-snippet). Never raises."""
    try:
        req = Request(url, headers={"User-Agent": _UA})
        ctx = _SSL if url.startswith("https") else None
        with urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310 — operator-supplied target
            body = r.read(read).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in r.headers.items()}
            return r.status, headers, body
    except Exception as exc:  # noqa: BLE001 — surfaced to the model as data
        # urllib raises HTTPError (has .code/.headers) for 4xx/5xx — keep those.
        code = getattr(exc, "code", None)
        hdrs = {}
        try:
            hdrs = {k.lower(): v for k, v in getattr(exc, "headers", {}).items()}
        except Exception:  # noqa: BLE001
            pass
        return code, hdrs, f"({type(exc).__name__}: {exc})"


def _split_hosts(raw: str) -> list[str]:
    """Normalise a messy host/URL blob into clean, deduped hostnames."""
    out: list[str] = []
    seen: set[str] = set()
    for tok in re.split(r"[\s,]+", raw.strip()):
        if not tok:
            continue
        h = tok.strip().lower()
        if "://" in h:
            h = urlparse(h).netloc or h
        h = h.split("/")[0].split(":")[0].strip(".")
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _title_of(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return " ".join(m.group(1).split())[:100] if m else ""


# --- passive discovery ----------------------------------------------------


def subdomain_enum(domain: str) -> str:
    """PASSIVE. Aggregate subdomains from certificate transparency (crt.sh) and
    passive DNS (hackertarget). Reads public data only — safe on any domain."""
    domain = domain.strip().lower().lstrip("*.")
    found: set[str] = set()
    sources: list[str] = []

    # crt.sh — certificate transparency logs.
    status, _, body = _get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20, read=1 << 20)
    if status == 200 and body.strip().startswith("["):
        try:
            for row in json.loads(body):
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        found.add(name)
            sources.append("crt.sh")
        except Exception:  # noqa: BLE001
            pass

    # hackertarget — passive DNS ("host,ip" lines).
    status, _, body = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15, read=1 << 18)
    if status == 200 and "," in body and "API count" not in body and "error" not in body.lower():
        for line in body.splitlines():
            host = line.split(",", 1)[0].strip().lower()
            if host.endswith(domain):
                found.add(host)
        sources.append("hackertarget")

    if not found:
        return (
            f"No subdomains recovered for {domain} "
            f"(sources tried: crt.sh, hackertarget). The passive sources may be "
            "rate-limiting — retry, or add subfinder/amass with API keys for depth."
        )
    subs = sorted(found)
    head = f"{len(subs)} subdomains for {domain} (via {', '.join(sources) or 'none'}):"
    shown = subs[:120]
    tail = "" if len(subs) <= 120 else f"\n…(+{len(subs) - 120} more)"
    return head + "\n" + "\n".join(shown) + tail


def wayback_urls(domain: str, limit: int = 200) -> str:
    """PASSIVE. Historical URLs from the Wayback Machine CDX index, with the
    interesting ones (params, api, admin, uploads, config, backups) surfaced."""
    domain = domain.strip().lower().lstrip("*.")
    limit = max(1, min(int(limit), 500))
    url = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        f"&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    status, _, body = _get(url, timeout=25, read=1 << 20)
    if status != 200 or not body.strip().startswith("["):
        return f"No Wayback data for {domain} (status {status}). CDX may be rate-limiting; retry."
    try:
        rows = json.loads(body)
    except Exception:  # noqa: BLE001
        return f"Wayback returned unparseable data for {domain}."
    urls = [r[0] for r in rows[1:] if r]  # row 0 is the header
    if not urls:
        return f"Wayback has no archived URLs for {domain}."
    juicy = re.compile(
        r"(\?|=|/api/|/v\d/|admin|internal|upload|/config|\.json|\.xml|\.sql|"
        r"\.bak|\.old|\.zip|\.env|token|key|secret|debug|graphql|swagger|\.git)",
        re.I,
    )
    hot = [u for u in urls if juicy.search(u)]
    lines = [f"{len(urls)} historical URLs for {domain}; {len(hot)} look interesting:"]
    for u in hot[:60]:
        lines.append(f"  ★ {u}")
    if not hot:
        lines.append("  (nothing obviously juicy; sample below)")
        for u in urls[:30]:
            lines.append(f"    {u}")
    return "\n".join(lines)


# --- deterministic triage (no network) ------------------------------------


def _subdomain_part(host: str) -> str:
    """The labels to the left of the registered domain — i.e. everything but the
    last two labels. Keeps triage from matching a keyword inside the apex brand
    (the classic 'git' in 'github.com' false positive). Naive on multi-label TLDs
    like co.uk, which is fine for a ranking heuristic."""
    labels = host.split(".")
    return ".".join(labels[:-2]) if len(labels) > 2 else ""


def triage_hosts(hosts: str) -> str:
    """DETERMINISTIC. Rank hostnames by attack-surface interest — dev/stage/api/
    admin/internal/vpn/git and friends float to the top. Only the subdomain labels
    are inspected, so the apex brand never inflates the score. Pure local
    computation; touches nothing. This is Phase 2 of the playbook as a tool."""
    parsed = _split_hosts(hosts)
    if not parsed:
        return "No hostnames parsed from input."
    tagged: list[tuple[str, list[str]]] = []
    plain: list[str] = []
    for h in parsed:
        hits = sorted({m.group(0).lower() for m in _INTERESTING.finditer(_subdomain_part(h))})
        (tagged if hits else plain).append((h, hits) if hits else h)  # type: ignore[arg-type]
    tagged.sort(key=lambda t: (-len(t[1]), t[0]))
    lines = [f"{len(parsed)} hosts · {len(tagged)} interesting, {len(plain)} ordinary."]
    if tagged:
        lines.append("\nPRIORITISE (forgotten / pre-prod / privileged surface):")
        for h, hits in tagged:
            lines.append(f"  ● {h}   [{', '.join(hits)}]")
    if plain:
        lines.append("\nrest:")
        for h in plain[:40]:
            lines.append(f"    {h}")
        if len(plain) > 40:
            lines.append(f"    …(+{len(plain) - 40} more)")
    return "\n".join(lines)


# --- active, gentle -------------------------------------------------------


def http_probe(targets: str, limit: int = 40) -> str:
    """ACTIVE (in-scope only). Gently probe which hosts are alive: status, final
    scheme, Server header, and page title. Sequential, short timeout, capped host
    count — the httpx alive-check, without hammering."""
    hosts = _split_hosts(targets)
    if not hosts:
        return "No hosts parsed from input."
    limit = max(1, min(int(limit), 60))
    capped = hosts[:limit]
    lines = [f"Probing {len(capped)} host(s)" + (f" (capped from {len(hosts)})" if len(hosts) > limit else "") + ":"]
    alive = 0
    for h in capped:
        hit = None
        for scheme in ("https", "http"):
            status, headers, body = _get(f"{scheme}://{h}/", timeout=6)
            if status is not None:
                server = headers.get("server", "")
                loc = headers.get("location", "")
                title = _title_of(body)
                extra = []
                if server:
                    extra.append(server)
                if title:
                    extra.append(f'"{title}"')
                if loc:
                    extra.append(f"→ {loc}")
                hit = f"  {status} {scheme}://{h}" + (f"   [{' · '.join(extra)}]" if extra else "")
                alive += 1
                break
        lines.append(hit if hit else f"  --- {h}   (no response on https/http)")
    lines.append(f"\n{alive}/{len(capped)} responded.")
    return "\n".join(lines)


def waf_check(target: str) -> ToolResult:
    """ACTIVE (in-scope only, one request). Fingerprint a bot-WAF/CDN before you
    invest time — Phase 0.5 of the playbook. A heavy WAF (DataDome, Imperva, PX,
    Akamai) as a beginner target ⇒ deprioritise."""
    host = _split_hosts(target)
    if not host:
        return ToolResult(name="waf_check", ok=False, error="no host parsed from input")
    h = host[0]
    status, headers, _ = _get(f"https://{h}/", timeout=8)
    if status is None:
        status, headers, _ = _get(f"http://{h}/", timeout=8)
    if status is None:
        return ToolResult(name="waf_check", ok=False, error=f"{h} unreachable on https/http")

    hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    cookie_blob = headers.get("set-cookie", "").lower()
    server = headers.get("server", "").lower()
    detected: list[str] = []
    for vendor, kind, needle in _WAF_SIGS:
        blob = {"header": hdr_blob, "cookie": cookie_blob, "server": server}[kind]
        if needle in blob and vendor not in detected:
            detected.append(vendor)

    challenge = status in (401, 403, 429, 503)
    heavy = [v for v in detected if v in _HEAVY_WAF]
    if detected:
        verdict = (
            f"HEAVY bot-WAF ({', '.join(heavy)}) — deprioritise; it'll eat your time."
            if heavy
            else f"WAF/CDN present ({', '.join(detected)}) — usually workable, proceed."
        )
    elif challenge:
        verdict = f"No named WAF, but status {status} looks like a challenge — probe carefully."
    else:
        verdict = "No bot-WAF fingerprinted — clean path, good target."
    out = (
        f"{h}  GET / -> {status}\n"
        f"  server: {headers.get('server', '(none)')}\n"
        f"  detected: {', '.join(detected) or 'none'}\n"
        f"  verdict: {verdict}"
    )
    return ToolResult(name="waf_check", ok=True, output=out)


# --- simulated outputs (offline demo / tests) -----------------------------

_SIM_SUBS = """\
7 subdomains for acme.example (via crt.sh, hackertarget):
api.acme.example
dev.acme.example
jenkins-ci.acme.example
staging.acme.example
vpn.acme.example
www.acme.example
shop.acme.example"""

_SIM_TRIAGE = None  # deterministic — run the real function in sim too

_SIM_PROBE = """\
Probing 4 host(s):
  200 https://www.acme.example   [cloudflare · "Acme — Home"]
  200 https://dev.acme.example   [nginx/1.18.0 · "Acme Dev — login"]
  403 https://api.acme.example   [nginx]
  200 https://jenkins-ci.acme.example   [Jetty(9.4) · "Dashboard [Jenkins]"]

4/4 responded."""

_SIM_WAF = ToolResult(
    name="waf_check",
    ok=True,
    output=(
        "www.acme.example  GET / -> 200\n"
        "  server: cloudflare\n"
        "  detected: Cloudflare\n"
        "  verdict: WAF/CDN present (Cloudflare) — usually workable, proceed."
    ),
)

_SIM_WAYBACK = """\
41 historical URLs for acme.example; 5 look interesting:
  ★ https://api.acme.example/v1/users?id=1
  ★ https://dev.acme.example/admin/config.json
  ★ https://www.acme.example/download?file=/etc/hostname
  ★ https://acme.example/.git/config
  ★ https://staging.acme.example/api/debug?verbose=true"""


def build_web_tools(simulate: bool = False) -> list[Tool]:
    """The web-surface recon toolset, appended to the host tools by build_registry."""
    if simulate:
        return [
            Tool("subdomain_enum",
                 "PASSIVE: enumerate a domain's subdomains from cert-transparency + "
                 "passive DNS (public data, safe on any domain).",
                 SCHEMA_DOMAIN, lambda domain: _SIM_SUBS),
            Tool("triage_hosts",
                 "DETERMINISTIC (no network): rank hostnames by attack-surface interest "
                 "— dev/stage/api/admin/internal/vpn float to the top.",
                 SCHEMA_TRIAGE, triage_hosts),
            Tool("http_probe",
                 "ACTIVE (in-scope only, gentle): probe which hosts are alive — status, "
                 "Server, title.",
                 SCHEMA_PROBE, lambda targets, limit=40: _SIM_PROBE),
            Tool("waf_check",
                 "ACTIVE (in-scope, one request): fingerprint a bot-WAF/CDN before "
                 "investing time. Heavy WAF ⇒ deprioritise.",
                 SCHEMA_WAF, lambda target: _SIM_WAF),
            Tool("wayback_urls",
                 "PASSIVE: historical URLs from the Wayback CDX, interesting ones surfaced.",
                 SCHEMA_WAYBACK, lambda domain, limit=200: _SIM_WAYBACK),
        ]
    return [
        Tool("subdomain_enum",
             "PASSIVE: enumerate a domain's subdomains from cert-transparency (crt.sh) + "
             "passive DNS (hackertarget). Reads public data only — safe on any domain.",
             SCHEMA_DOMAIN, subdomain_enum),
        Tool("triage_hosts",
             "DETERMINISTIC (no network): rank hostnames by attack-surface interest — "
             "dev/stage/api/admin/internal/vpn/git float to the top.",
             SCHEMA_TRIAGE, triage_hosts),
        Tool("http_probe",
             "ACTIVE (in-scope only, gentle): probe which hosts are alive — status, final "
             "scheme, Server header, title. Sequential, short timeout, capped host count.",
             SCHEMA_PROBE, http_probe),
        Tool("waf_check",
             "ACTIVE (in-scope only, one request): fingerprint a bot-WAF/CDN before "
             "investing time (playbook Phase 0.5). Heavy WAF ⇒ deprioritise.",
             SCHEMA_WAF, waf_check),
        Tool("wayback_urls",
             "PASSIVE: historical URLs from the Wayback Machine CDX index, with the "
             "interesting ones (params, api, admin, config, backups) surfaced.",
             SCHEMA_WAYBACK, wayback_urls),
    ]
