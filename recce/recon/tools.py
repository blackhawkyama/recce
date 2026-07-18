"""Recon tools — read-only enumeration, plus a static service-intel knowledge base.

Every tool here is non-intrusive: port/service discovery, banner reads, anonymous
listing, header inspection. Nothing brute-forces, writes, or exploits. Real tools
shell out to `nmap` / `smbclient` and degrade gracefully when a binary or the
network isn't there (a clear failed ToolResult the agent can reason about).

`build_registry(simulate=True)` swaps in canned outputs for a coherent demo box,
so the full agent loop runs with no network, no nmap, and no root — which is what
the offline demo and the tests use.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Optional
from urllib.request import Request, urlopen

from recce.recon.web import build_web_tools
from recce.tools import Tool, ToolRegistry
from recce.types import ToolResult

# --- input schemas --------------------------------------------------------

_TARGET = {"type": "string", "description": "Host/IP of the authorized target."}

SCHEMA_NMAP = {
    "type": "object",
    "properties": {
        "target": _TARGET,
        "ports": {
            "type": "string",
            "description": "Optional port spec, e.g. '22,80,443' or '1-1000'. "
            "Omit for a default top-ports service scan.",
        },
    },
    "required": ["target"],
}
SCHEMA_HTTP = {
    "type": "object",
    "properties": {
        "target": _TARGET,
        "port": {"type": "integer", "description": "HTTP(S) port (default 80)."},
    },
    "required": ["target"],
}
SCHEMA_FTP = {
    "type": "object",
    "properties": {"target": _TARGET, "port": {"type": "integer"}},
    "required": ["target"],
}
SCHEMA_SMB = {
    "type": "object",
    "properties": {"target": _TARGET},
    "required": ["target"],
}
SCHEMA_INTEL = {
    "type": "object",
    "properties": {
        "service": {
            "type": "string",
            "description": "Service name, e.g. 'ftp', 'redis', 'smb', 'telnet'.",
        },
        "version": {"type": "string", "description": "Optional version string."},
    },
    "required": ["service"],
}


# --- static service intel (deterministic domain knowledge) -----------------
#
# Grounds the agent's hypotheses in known, common misconfigurations so it reasons
# from fact rather than inventing exploits. Enumeration guidance only.

SERVICE_INTEL: dict[str, dict[str, str]] = {
    "ftp": {
        "note": "FTP often permits anonymous login. If so, the share may expose "
        "config/backup files or be writable (a path to upload). Check the banner "
        "for a version with known CVEs (e.g. vsftpd 2.3.4 backdoor).",
        "check": "Try anonymous login and list the root; note writable dirs.",
    },
    "telnet": {
        "note": "Cleartext remote shell. Frequently left with no/weak auth on lab "
        "boxes; the banner sometimes hands you the login.",
        "check": "Connect and read the banner; test for a passwordless/known login.",
    },
    "smb": {
        "note": "SMB may allow a null session, exposing share names and sometimes "
        "readable shares with credentials or flags.",
        "check": "List shares with a null session; enumerate readable shares.",
    },
    "redis": {
        "note": "Redis with no auth (default) is a common RCE path — write an SSH "
        "key or a cron/webshell via CONFIG SET. Very common on lab boxes.",
        "check": "Connect unauthenticated and run INFO; confirm no AUTH required.",
    },
    "http": {
        "note": "Web servers expose the app surface: check robots.txt, common admin "
        "paths, exposed .git, default creds, and the server/framework version.",
        "check": "Read headers + robots.txt; enumerate directories; check for .git.",
    },
    "ssh": {
        "note": "Rarely the foothold itself, but the destination once you have creds "
        "or a key. Note the version for user-enum/known CVEs.",
        "check": "Record the version; revisit after finding credentials elsewhere.",
    },
    "mysql": {
        "note": "May allow remote root with no/weak password; can read files or "
        "write a webshell into a known web root.",
        "check": "Try root with empty/common passwords from an allowed host.",
    },
    "rsync": {
        "note": "Often lists modules anonymously and may allow reading/writing files.",
        "check": "List modules; read exposed modules for credentials/keys.",
    },
    "nfs": {
        "note": "Exported shares may be world-readable/writable — a path to drop an "
        "SSH key or read sensitive files.",
        "check": "Show mounts; mount readable exports and inspect.",
    },
}


def service_intel(service: str, version: str = "") -> str:
    key = service.strip().lower()
    entry = SERVICE_INTEL.get(key)
    if not entry:
        # Fuzzy contains match (e.g. "ms-sql" → "mysql" won't match; keep strict-ish).
        entry = next((v for k, v in SERVICE_INTEL.items() if k in key), None)
    if not entry:
        return (
            f"No curated intel for {service!r}. Enumerate it directly: read the "
            "banner/version, check for default or missing auth, and look for "
            "anonymous/unauthenticated access."
        )
    ver = f" (version: {version})" if version else ""
    return f"{service}{ver}\n- {entry['note']}\n- Enumeration: {entry['check']}"


# --- real tools (read-only) -----------------------------------------------


def nmap_scan(target: str, ports: Optional[str] = None) -> ToolResult:
    if shutil.which("nmap") is None:
        return ToolResult(
            name="nmap_scan",
            ok=False,
            error="nmap not installed on this host (try --simulate for a demo run)",
        )
    cmd = ["nmap", "-sV", "-Pn", "-T4"]
    cmd += (["-p", ports] if ports else ["--top-ports", "1000"])
    cmd.append(target)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    out = proc.stdout or proc.stderr
    return ToolResult(name="nmap_scan", ok=proc.returncode == 0, output=out,
                      error=None if proc.returncode == 0 else proc.stderr[:300])


def http_enum(target: str, port: int = 80) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{target}:{port}"
    lines: list[str] = []

    def fetch(path: str) -> tuple[Optional[int], dict, str]:
        try:
            req = Request(base + path, headers={"User-Agent": "recce/0.1"})
            with urlopen(req, timeout=10) as r:  # noqa: S310 — target is operator-supplied
                body = r.read(2048).decode("utf-8", "replace")
                return r.status, dict(r.headers), body
        except Exception as exc:  # noqa: BLE001
            return None, {}, f"({type(exc).__name__}: {exc})"

    status, headers, body = fetch("/")
    if status is None:
        return f"{base}/ unreachable: {body}"
    lines.append(f"GET / -> {status}")
    for h in ("Server", "X-Powered-By", "Location", "WWW-Authenticate"):
        if h in headers:
            lines.append(f"  {h}: {headers[h]}")
    if "<title>" in body.lower():
        title = body.lower().split("<title>", 1)[1].split("</title>", 1)[0]
        lines.append(f"  <title>: {title.strip()[:120]}")

    lines.append("Common paths:")
    for path in ("/robots.txt", "/admin", "/login", "/.git/HEAD", "/backup"):
        s, _, b = fetch(path)
        note = ""
        if path == "/robots.txt" and s == 200:
            note = " -> " + " ".join(b.split())[:120]
        lines.append(f"  {path}: {s if s is not None else 'err'}{note}")
    return "\n".join(lines)


def ftp_anon(target: str, port: int = 21) -> str:
    from ftplib import FTP  # noqa: PLC0415

    ftp = FTP()
    try:
        ftp.connect(target, port, timeout=10)
        banner = ftp.getwelcome() or ""
        ftp.login()  # anonymous
        try:
            listing = ftp.nlst()
        except Exception:  # noqa: BLE001
            listing = []
        ftp.quit()
        entries = ", ".join(listing[:50]) or "(empty)"
        return f"anonymous login ALLOWED\nbanner: {banner}\nroot listing: {entries}"
    except Exception as exc:  # noqa: BLE001
        return f"anonymous login denied / error: {type(exc).__name__}: {exc}"
    finally:
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass


def smb_enum(target: str) -> ToolResult:
    if shutil.which("smbclient") is None:
        return ToolResult(name="smb_enum", ok=False, error="smbclient not installed")
    proc = subprocess.run(
        ["smbclient", "-L", f"//{target}", "-N"],
        capture_output=True, text=True, timeout=60,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return ToolResult(name="smb_enum", ok=proc.returncode == 0, output=out or "(no output)")


# --- simulated tools (offline demo / tests) --------------------------------
#
# A coherent demo box: anonymous FTP exposing a backup, an Apache site whose
# robots.txt leaks a path, and SSH. Lets the agent run its full loop with no
# network, no nmap, no root.

_SIM_NMAP = """\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for {target}
Host is up (0.011s latency).
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""

_SIM_HTTP = """\
GET / -> 200
  Server: Apache/2.4.41 (Ubuntu)
  <title>: Acme Internal Portal
Common paths:
  /robots.txt: 200 -> User-agent: * Disallow: /backup/
  /admin: 401
  /login: 200
  /.git/HEAD: 404
  /backup: 301"""

_SIM_FTP = (
    "anonymous login ALLOWED\n"
    "banner: 220 (vsFTPd 3.0.3)\n"
    "root listing: notes.txt, backup_2026.zip"
)


def build_registry(simulate: bool = False) -> ToolRegistry:
    """Assemble the recon toolset. `simulate=True` uses canned outputs.

    Two halves share one registry so the agent can pick by target shape: the
    *host* tools (nmap/http_enum/ftp/smb) drill a single box (an HTB/CTF machine,
    an IP); the *web* tools (subdomain_enum/triage_hosts/http_probe/waf_check/
    wayback_urls) map the wide surface of a domain, bug-bounty style. See
    recon/web.py for the passive/active line on the web tools.
    """
    if simulate:
        host_tools = [
            Tool("nmap_scan", "Service/version scan of the target (read-only).",
                 SCHEMA_NMAP, lambda target, ports=None: _SIM_NMAP.format(target=target)),
            Tool("http_enum", "Inspect an HTTP(S) service: headers, title, common paths.",
                 SCHEMA_HTTP, lambda target, port=80: _SIM_HTTP),
            Tool("ftp_anon", "Test anonymous FTP login and list the root (read-only).",
                 SCHEMA_FTP, lambda target, port=21: _SIM_FTP),
            Tool("smb_enum", "List SMB shares via a null session (read-only).",
                 SCHEMA_SMB, lambda target: ToolResult(
                     name="smb_enum", ok=False, error="no SMB service on this host")),
            Tool("service_intel",
                 "Look up known common misconfigurations and enumeration steps "
                 "for a service. Use this to ground hypotheses.",
                 SCHEMA_INTEL, service_intel),
        ]
        return ToolRegistry(host_tools + build_web_tools(simulate=True))

    host_tools = [
        Tool("nmap_scan", "Service/version scan of the target (read-only nmap -sV).",
             SCHEMA_NMAP, nmap_scan),
        Tool("http_enum", "Inspect an HTTP(S) service: headers, title, common paths.",
             SCHEMA_HTTP, http_enum),
        Tool("ftp_anon", "Test anonymous FTP login and list the root (read-only).",
             SCHEMA_FTP, ftp_anon),
        Tool("smb_enum", "List SMB shares via a null session (read-only).",
             SCHEMA_SMB, smb_enum),
        Tool("service_intel",
             "Look up known common misconfigurations and enumeration steps for a "
             "service. Use this to ground hypotheses.",
             SCHEMA_INTEL, service_intel),
    ]
    return ToolRegistry(host_tools + build_web_tools(simulate=False))
