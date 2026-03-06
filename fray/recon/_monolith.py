#!/usr/bin/env python3
"""
Fray Recon — Target Reconnaissance & Fingerprinting

Before firing payloads, understand the target:
  1. HTTP check — port 80 open? redirects to HTTPS?
  2. TLS audit — version, cipher, cert validity
  3. Security headers — HSTS, CSP, XFO, XCTO, etc.
  4. App fingerprinting — WordPress, Drupal, PHP, Node, Java, .NET, etc.
  5. Smart payload recommendation — map stack → priority payloads

Usage:
    fray recon https://example.com
    fray recon https://example.com --json
"""

import http.client
import json
import random
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR

# Import from extracted submodules
from fray.recon.http import (
    _parse_url,
    _make_ssl_context,
    _http_get,
    check_http,
    check_tls,
)
from fray.recon.fingerprint import (
    _TECH_PAYLOAD_MAP,
    _HEADER_FINGERPRINTS,
    _BODY_FINGERPRINTS,
    _COOKIE_FINGERPRINTS,
    _SECURITY_HEADERS,
    check_security_headers,
    check_cookies,
    fingerprint_app,
    recommend_categories,
)
from fray.recon.supply_chain import (
    _FRONTEND_LIB_CVES,
    _CDN_PATTERNS,
    _INLINE_VERSION_PATTERNS,
    _parse_version,
    fetch_retirejs_db,
    check_frontend_libs,
)
from fray.recon.history import (
    _get_history_dir,
    _save_recon_history,
    _load_previous_recon,
    diff_recon,
    print_recon_diff,
)
from fray.recon.dns import (
    _SUBDOMAIN_WORDLIST,
    _SUBDOMAIN_WORDLIST_DEEP,
    _CDN_IP_PREFIXES,
    _ip_is_cdn,
    _resolve_hostname,
    check_dns,
    check_subdomains_crt,
    check_subdomains_bruteforce,
    discover_origin_ip,
)
from fray.recon.checks import (
    check_robots_sitemap,
    check_cors,
    check_exposed_files,
    check_http_methods,
    check_error_page,
    check_graphql_introspection,
    check_api_discovery,
    check_host_header_injection,
    check_admin_panels,
    check_rate_limits,
    check_differential_responses,
    waf_gap_analysis,
    _resolve_vendor_key,
    _infer_vendor_from_recon,
)
from fray.recon.discovery import (
    _INTERESTING_PATH_RE,
    _STATIC_EXT_RE,
    _PARAM_WORDLIST,
    discover_historical_urls,
    print_historical_urls,
    mine_params,
    print_mined_params,
    discover_js_endpoints,
    print_js_endpoints,
    discover_params,
)
from fray.recon.pipeline import (
    run_recon,
    print_recon,
    _build_attack_surface_summary,
)


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── Supply chain (CVE DB, Retire.js, check_frontend_libs) ────────────
# Now in fray.recon.supply_chain (imported at top of this file)

# ── Extended recon checks ────────────────────────────────────────────────
# Now in fray.recon.checks (imported at top of this file)

# ── DNS (check_dns, subdomains, origin IP discovery) ─────────────────
# Now in fray.recon.dns (imported at top of this file)

def _follow_redirect(host: str, path: str, timeout: int = 10,
                     max_hops: int = 3) -> Tuple[int, bytes]:
    """Follow HTTPS redirects, return (status, body_bytes)."""
    for _ in range(max_hops + 1):
        try:
            ctx = _make_ssl_context(verify=True)
        except Exception:
            ctx = _make_ssl_context(verify=False)
        try:
            conn = http.client.HTTPSConnection(host, context=ctx, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": f"Fray/{__version__}"})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
            if status in (301, 302, 303, 307, 308):
                loc = hdrs.get("location", "")
                if loc.startswith("https://"):
                    parsed = urllib.parse.urlparse(loc)
                    host = parsed.hostname or host
                    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                    continue
            return status, body
        except Exception:
            return 0, b""
    return 0, b""


def _post_json(url: str, body: str, timeout: int = 6,
               verify_ssl: bool = True,
               headers: Optional[Dict[str, str]] = None) -> tuple:
    """HTTP POST with JSON body — stdlib only, SSL fallback."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
    if headers:
        req_headers.update(headers)

    encoded = body.encode("utf-8")

    if parsed.scheme == "https":
        port = port or 443
        # Try verified first, fall back to unverified
        for do_verify in ([True, False] if verify_ssl else [False]):
            try:
                ctx = ssl.create_default_context()
                if not do_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                conn.request("POST", path, body=encoded, headers=req_headers)
                resp = conn.getresponse()
                resp_body = resp.read(500_000).decode("utf-8", errors="replace")
                conn.close()
                return resp.status, resp_body
            except ssl.SSLError:
                continue
            except Exception:
                return 0, ""
        return 0, ""
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("POST", path, body=encoded, headers=req_headers)
            resp = conn.getresponse()
            resp_body = resp.read(500_000).decode("utf-8", errors="replace")
            return resp.status, resp_body
        except Exception:
            return 0, ""
        finally:
            conn.close()


def _fetch_url(url: str, timeout: int = 12, verify_ssl: bool = True,
               headers: Optional[Dict[str, str]] = None) -> tuple:
    """Simple HTTP GET — independent of scanner's _fetch (no global backoff state)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        port = port or 443
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        port = port or 80
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    try:
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read(1_000_000).decode("utf-8", errors="replace")
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, body, resp_headers
    except Exception:
        return 0, "", {}
    finally:
        conn.close()

