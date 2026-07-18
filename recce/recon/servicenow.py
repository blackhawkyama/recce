"""ServiceNow recon — fingerprint an instance and check the ACL-misconfig surface.

ServiceNow is a huge enterprise SaaS platform, so `*.service-now.com` instances
turn up constantly in bug-bounty scopes. The dominant, still-live bug class is
**unauthenticated data exposure via misconfigured table ACLs** — records that
should be gated (users, incidents, survey answers, CMDB, KB) become readable with
no session, through the Table REST API or a public Service Portal widget /
"Simple List". A mass wave of these reports in 2024–2026 (AppOmni's research, then
the widget/Simple List scans) is exactly why researchers want a Personal Developer
Instance to study the ACL model on.

This module is the recce-shaped, disciplined version of that check:

THE LINE (enforced by construction, documented for the model):
  - PASSIVE / FINGERPRINT — reads a ServiceNow instance's *public* metadata
    (`/stats.do`: instance name, build, node) and self-identifies markers (glide
    cookies, login page). Benign — the same data any visitor's browser gets.
      →  servicenow_fingerprint
  - ACTIVE, NON-EXFILTRATING — checks whether known-sensitive tables are readable
    unauthenticated. Crucially it requests `sysparm_fields=sys_id&sysparm_limit=1`,
    so it retrieves at most one opaque row id and *never a PII field value*. It
    reports the reachability signal (readable / requires-auth / blocked) and the
    row-count hint, then stops. It proves the misconfiguration without pulling
    anyone's data.
      →  servicenow_acl_probe

Everything is read-only: no writes, no brute force, no data exfiltration. It
proposes; a human decides whether to confirm impact and file. Active tools are
in-scope-only, gently (short timeouts, one request per endpoint, capped tables).
`build_servicenow_tools(simulate=True)` swaps in canned outputs for the offline
loop and the tests.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from recce.recon.web import _get, _split_hosts
from recce.tools import Tool
from recce.types import ToolResult

# --- input schemas --------------------------------------------------------

SCHEMA_SNOW_TARGET = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "ServiceNow instance host or URL (in-scope only), "
            "e.g. 'acme.service-now.com'.",
        }
    },
    "required": ["target"],
}
SCHEMA_SNOW_PROBE = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "ServiceNow instance host or URL (in-scope only).",
        },
        "tables": {
            "type": "string",
            "description": "Optional comma/space-separated table list to check "
            "(default: a curated set led by non-PII metadata tables). Only the "
            "sys_id field is ever requested.",
        },
    },
    "required": ["target"],
}

# Tables to check, ordered to *prove the misconfig on non-PII metadata first*,
# then confirm real impact on data tables. Each probe requests only sys_id, so no
# personal data is ever retrieved regardless of the table.
_DEFAULT_TABLES: list[tuple[str, str]] = [
    ("sys_db_object", "table catalog — schema metadata, non-PII; unauth read here alone proves the ACL gap"),
    ("sys_properties", "instance configuration properties — non-PII but security-sensitive settings"),
    ("sys_user", "user accounts (names, emails, phones) — PII; confirms real impact"),
    ("sys_user_group", "groups and membership — org structure"),
    ("incident", "incident tickets — frequently internal/customer content"),
    ("cmdb_ci", "configuration items — infrastructure inventory"),
    ("kb_knowledge", "knowledge base articles — sometimes internal-only"),
    ("question_answer", "survey responses — frequently PII"),
]

# ServiceNow self-identification markers (any one ⇒ almost certainly ServiceNow).
_SNOW_COOKIE_MARKERS = ("glide_user_route", "glide_session_store", "glide_user_activity", "bigipserverpool")
_SNOW_BODY_MARKERS = ("glidesoft", "glide.ui", "servicenow", "gs-nav", "instance_name")

_STATS_INSTANCE = re.compile(r"Instance name:\s*([^\n<]+)", re.I)
_STATS_BUILD = re.compile(r"Build name:\s*([^\n<]+)", re.I)
_STATS_BUILDDATE = re.compile(r"Build date:\s*([^\n<]+)", re.I)
_STATS_NODE = re.compile(r"(?:Node id|Current node):\s*([^\n<]+)", re.I)


# --- fingerprint (benign, public metadata) --------------------------------


def fingerprint_instance(host: str) -> dict:
    """FINGERPRINT core (in-scope only). Confirm a host is ServiceNow and read its
    *public* metadata. `/stats.do` is unauthenticated by default and returns the
    instance name, build, and node — benign recon, the same bytes a browser gets.
    Returns a structured dict, or {host, error} if unreachable."""
    parsed = _split_hosts(host)
    if not parsed:
        return {"host": host, "error": "no host parsed from input"}
    h = parsed[0]

    # Root request first: status, headers (cookies), body markers.
    status, headers, body = _get(f"https://{h}/", timeout=8)
    scheme = "https"
    if status is None:
        scheme = "http"
        status, headers, body = _get(f"http://{h}/", timeout=8)
    if status is None:
        return {"host": h, "error": "unreachable on https/http"}

    cookie_blob = headers.get("set-cookie", "").lower()
    hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    body_l = body.lower()
    markers: list[str] = []
    for m in _SNOW_COOKIE_MARKERS:
        if m in cookie_blob or m in hdr_blob:
            markers.append(f"cookie:{m}")
    for m in _SNOW_BODY_MARKERS:
        if m in body_l:
            markers.append(f"body:{m}")
    logged_in = headers.get("x-is-logged-in", "")
    if logged_in:
        markers.append(f"header:x-is-logged-in={logged_in}")

    # /stats.do — public instance metadata.
    st, _sh, stats = _get(f"{scheme}://{h}/stats.do", timeout=8)
    instance = build = build_date = node = ""
    stats_public = False
    if st == 200 and stats:
        stats_public = True
        markers.append("stats.do:public")
        if (mm := _STATS_INSTANCE.search(stats)):
            instance = mm.group(1).strip()
        if (mm := _STATS_BUILD.search(stats)):
            build = mm.group(1).strip()
        if (mm := _STATS_BUILDDATE.search(stats)):
            build_date = mm.group(1).strip()
        if (mm := _STATS_NODE.search(stats)):
            node = mm.group(1).strip()

    is_snow = bool(markers) or ".service-now.com" in h or ".servicenow.com" in h
    if not is_snow:
        verdict = "No ServiceNow markers found — likely not a ServiceNow instance."
    elif stats_public:
        verdict = ("ServiceNow confirmed; /stats.do is world-readable "
                   f"({build or 'build unknown'}). Proceed to servicenow_acl_probe.")
    else:
        verdict = ("ServiceNow markers present but /stats.do not public — still worth "
                   "an ACL probe of the Table API / Service Portal.")

    return {
        "host": h, "scheme": scheme, "status": status, "is_servicenow": is_snow,
        "instance": instance, "build": build, "build_date": build_date, "node": node,
        "stats_public": stats_public, "markers": markers, "verdict": verdict,
    }


def servicenow_fingerprint(target: str) -> ToolResult:
    """FINGERPRINT (in-scope only, benign). Confirm a host is ServiceNow and read
    its public metadata via /stats.do (instance name, build, node) plus glide
    cookie / login-page markers. Reads only public data — the same a browser sees."""
    info = fingerprint_instance(target)
    if "error" in info:
        return ToolResult(name="servicenow_fingerprint", ok=False,
                          error=f"{info['host']}: {info['error']}")
    lines = [
        f"{info['host']}  GET / -> {info['status']}  (ServiceNow: "
        f"{'yes' if info['is_servicenow'] else 'no'})",
        f"  instance : {info['instance'] or '(not exposed)'}",
        f"  build    : {info['build'] or '(unknown)'}"
        + (f"   date {info['build_date']}" if info['build_date'] else ""),
        f"  node     : {info['node'] or '(not exposed)'}",
        f"  markers  : {', '.join(info['markers']) or 'none'}",
        f"  verdict  : {info['verdict']}",
    ]
    return ToolResult(name="servicenow_fingerprint", ok=True, output="\n".join(lines))


# --- ACL probe (active, non-exfiltrating) ---------------------------------


def _classify(status: Optional[int], body: str) -> tuple[str, Optional[int]]:
    """Map one Table-API response to (signal, row_count). Parses only the result
    envelope shape and its length — never field values."""
    if status is None:
        return "unreachable", None
    if status in (401, 302):
        return "requires-auth", None
    if status == 403:
        return "blocked", None
    if status == 404:
        return "no-such-table", None
    if status == 200:
        try:
            data = json.loads(body)
            result = data.get("result", None)
            if isinstance(result, list):
                return ("READABLE-UNAUTH", len(result))
            return ("200-unexpected-shape", None)
        except Exception:  # noqa: BLE001
            return ("200-non-json", None)
    return (f"http-{status}", None)


def acl_probe(host: str, tables: Optional[list[tuple[str, str]]] = None) -> dict:
    """ACTIVE, NON-EXFILTRATING core (in-scope only). For each table, GET the Table
    API requesting ONLY `sys_id` (one row) and record whether it's readable without
    auth. No PII field is ever requested or returned. Returns a structured dict."""
    parsed = _split_hosts(host)
    if not parsed:
        return {"host": host, "error": "no host parsed from input"}
    h = parsed[0]
    tbls = tables or _DEFAULT_TABLES

    results: list[dict] = []
    for name, desc in tbls:
        # sysparm_fields=sys_id ⇒ at most one opaque id comes back, never PII.
        url = (f"https://{h}/api/now/table/{name}"
               f"?sysparm_limit=1&sysparm_fields=sys_id")
        status, _hdrs, body = _get(url, timeout=8, read=4096)
        signal, count = _classify(status, body)
        results.append({"table": name, "desc": desc, "status": status,
                        "signal": signal, "rows": count})

    readable = [r for r in results if r["signal"] == "READABLE-UNAUTH"]
    return {"host": h, "results": results, "readable": readable}


def servicenow_acl_probe(target: str, tables: str = "") -> ToolResult:
    """ACTIVE (in-scope only), NON-EXFILTRATING. Check whether sensitive ServiceNow
    tables are readable unauthenticated via the Table API. Requests only sys_id, so
    it proves the ACL misconfig WITHOUT retrieving any PII. Reports readable /
    requires-auth / blocked per table and stops — a human confirms impact and files."""
    picked: Optional[list[tuple[str, str]]] = None
    if tables.strip():
        names = [t for t in re.split(r"[\s,]+", tables.strip()) if t]
        known = dict(_DEFAULT_TABLES)
        picked = [(n, known.get(n, "operator-specified table")) for n in names]

    info = acl_probe(target, picked)
    if "error" in info:
        return ToolResult(name="servicenow_acl_probe", ok=False,
                          error=f"{info['host']}: {info['error']}")

    lines = [f"{info['host']}  Table-API ACL probe (sys_id only — no PII retrieved):"]
    for r in info["results"]:
        mark = {"READABLE-UNAUTH": "✗ EXPOSED", "requires-auth": "✓ auth",
                "blocked": "✓ blocked", "no-such-table": "· absent",
                "unreachable": "· n/a"}.get(r["signal"], r["signal"])
        rows = "" if r["rows"] is None else f" (rows≥{r['rows']})"
        lines.append(f"  [{mark}] {r['table']}{rows}  — {r['desc']}")

    readable = info["readable"]
    if readable:
        names = ", ".join(r["table"] for r in readable)
        lines.append("")
        lines.append(f"⚠ {len(readable)} table(s) readable unauthenticated: {names}")
        lines.append("  Next (human): open the instance's Service Portal / Simple List for "
                     "one exposed table, confirm records render for an anonymous session, "
                     "capture a minimal PoC, and file per the program's scope. Do NOT bulk-pull.")
    else:
        lines.append("")
        lines.append("No unauthenticated table reads — ACLs look correctly denying. "
                     "Consider Service Portal public widgets / knowledge bases separately.")
    return ToolResult(name="servicenow_acl_probe", ok=True, output="\n".join(lines))


# --- simulated outputs (offline demo / tests) -----------------------------

_SIM_FINGERPRINT = ToolResult(
    name="servicenow_fingerprint",
    ok=True,
    output=(
        "acme.service-now.com  GET / -> 200  (ServiceNow: yes)\n"
        "  instance : acme\n"
        "  build    : Xanadu   date 06-19-2025_1200\n"
        "  node     : app12345.iad\n"
        "  markers  : cookie:glide_user_route, body:glide.ui, stats.do:public\n"
        "  verdict  : ServiceNow confirmed; /stats.do is world-readable (Xanadu). "
        "Proceed to servicenow_acl_probe."
    ),
)

_SIM_ACL_PROBE = ToolResult(
    name="servicenow_acl_probe",
    ok=True,
    output=(
        "acme.service-now.com  Table-API ACL probe (sys_id only — no PII retrieved):\n"
        "  [✗ EXPOSED] sys_db_object (rows≥1)  — table catalog — schema metadata, non-PII; "
        "unauth read here alone proves the ACL gap\n"
        "  [✓ auth] sys_properties  — instance configuration properties — non-PII but "
        "security-sensitive settings\n"
        "  [✗ EXPOSED] sys_user (rows≥1)  — user accounts (names, emails, phones) — PII; "
        "confirms real impact\n"
        "  [✓ blocked] incident  — incident tickets — frequently internal/customer content\n"
        "\n"
        "⚠ 2 table(s) readable unauthenticated: sys_db_object, sys_user\n"
        "  Next (human): open the instance's Service Portal / Simple List for one exposed "
        "table, confirm records render for an anonymous session, capture a minimal PoC, and "
        "file per the program's scope. Do NOT bulk-pull."
    ),
)


def build_servicenow_tools(simulate: bool = False) -> list[Tool]:
    """The ServiceNow recon toolset, appended to the registry by build_registry."""
    if simulate:
        return [
            Tool("servicenow_fingerprint",
                 "FINGERPRINT (in-scope, benign): confirm a host is ServiceNow and read "
                 "its public metadata (/stats.do: instance, build, node) + glide markers.",
                 SCHEMA_SNOW_TARGET, lambda target: _SIM_FINGERPRINT),
            Tool("servicenow_acl_probe",
                 "ACTIVE (in-scope), NON-EXFILTRATING: check whether sensitive tables are "
                 "readable unauthenticated via the Table API. Requests only sys_id — proves "
                 "the ACL misconfig without pulling PII.",
                 SCHEMA_SNOW_PROBE, lambda target, tables="": _SIM_ACL_PROBE),
        ]
    return [
        Tool("servicenow_fingerprint",
             "FINGERPRINT (in-scope only, benign): confirm a host is ServiceNow and read its "
             "public metadata via /stats.do (instance name, build, node) plus glide cookie / "
             "login markers. Reads only public data.",
             SCHEMA_SNOW_TARGET, servicenow_fingerprint),
        Tool("servicenow_acl_probe",
             "ACTIVE (in-scope only), NON-EXFILTRATING: check whether sensitive ServiceNow "
             "tables (sys_user, incident, …) are readable unauthenticated via the Table API. "
             "Requests only sys_id, so it proves the ACL misconfig WITHOUT retrieving PII. "
             "Reports readable/requires-auth/blocked and stops for a human to confirm impact.",
             SCHEMA_SNOW_PROBE, servicenow_acl_probe),
    ]
