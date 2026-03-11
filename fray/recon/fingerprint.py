"""Fingerprinting — tech detection, security headers, cookies, payload recommendations."""

import re
from typing import Any, Dict, List, Tuple

from fray import PAYLOADS_DIR


# ── Tech → payload priority mapping ─────────────────────────────────────

_TECH_PAYLOAD_MAP: Dict[str, List[str]] = {
    "wordpress": ["sqli", "xss", "path_traversal", "command_injection", "ssrf"],
    "drupal": ["sqli", "ssti", "xss", "command_injection"],
    "joomla": ["sqli", "xss", "path_traversal", "command_injection"],
    "php": ["command_injection", "ssti", "path_traversal", "sqli", "xss", "host_header_injection"],
    "node.js": ["ssti", "ssrf", "xss", "command_injection", "prototype_pollution", "host_header_injection"],
    "express": ["prototype_pollution", "ssti", "ssrf", "xss", "command_injection", "host_header_injection"],
    "python": ["ssti", "ssrf", "command_injection", "sqli", "host_header_injection"],
    "java": ["sqli", "xxe", "ssti", "ssrf", "command_injection", "host_header_injection"],
    ".net": ["sqli", "xss", "path_traversal", "xxe", "host_header_injection"],
    "ruby": ["ssti", "command_injection", "sqli", "ssrf", "host_header_injection"],
    "nginx": ["path_traversal", "ssrf"],
    "apache": ["path_traversal", "ssrf"],
    "iis": ["path_traversal", "xss", "sqli"],
    "api_json": ["sqli", "ssrf", "command_injection", "ssti", "prototype_pollution"],
    "react": ["xss"],
    "angular": ["xss", "ssti"],
    "vue": ["xss"],
}

# ── Fingerprint signatures ───────────────────────────────────────────────

_HEADER_FINGERPRINTS: Dict[str, Dict[str, str]] = {
    # header_name_lower -> {pattern: tech_name}
    "x-powered-by": {
        r"PHP": "php",
        r"Express": "express",
        r"ASP\.NET": ".net",
        r"Servlet": "java",
        r"Django": "python",
        r"Phusion Passenger": "ruby",
    },
    "server": {
        r"nginx": "nginx",
        r"Apache": "apache",
        r"Microsoft-IIS": "iis",
        r"Kestrel": ".net",
        r"Jetty": "java",
        r"Tomcat": "java",
        r"gunicorn": "python",
        r"Werkzeug": "python",
        r"uvicorn": "python",
        r"Cowboy": "node.js",
    },
    "x-drupal-cache": {
        r".*": "drupal",
    },
    "x-generator": {
        r"Drupal": "drupal",
        r"WordPress": "wordpress",
        r"Joomla": "joomla",
    },
}

_BODY_FINGERPRINTS: List[Tuple[str, str]] = [
    # (regex_pattern, tech_name)
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+[\d.]+', "wordpress"),
    (r'/wp-content/', "wordpress"),
    (r'/wp-includes/', "wordpress"),
    (r'/wp-json/', "wordpress"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "drupal"),
    (r'/misc/drupal\.js', "drupal"),
    (r'/sites/default/files', "drupal"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "joomla"),
    (r'/media/system/js/', "joomla"),
    (r'/administrator/', "joomla"),
    (r'<div\s+id=["\']app["\']', "vue"),
    (r'<div\s+id=["\']root["\']', "react"),
    (r'__NEXT_DATA__', "react"),
    (r'ng-app=', "angular"),
    (r'ng-version=', "angular"),
    (r'<script\s+src=[^>]*angular', "angular"),
    (r'csrfmiddlewaretoken', "python"),
    (r'__RequestVerificationToken', ".net"),
    (r'__VIEWSTATE', ".net"),
    (r'JSESSIONID', "java"),
    (r'laravel_session', "php"),
    (r'ci_session', "php"),
    (r'_rails', "ruby"),
    (r'X-Request-Id.*[a-f0-9-]{36}', "ruby"),
]

_COOKIE_FINGERPRINTS: Dict[str, str] = {
    "PHPSESSID": "php",
    "laravel_session": "php",
    "ci_session": "php",
    "JSESSIONID": "java",
    "connect.sid": "node.js",
    "ASP.NET_SessionId": ".net",
    "_rails": "ruby",
    "csrftoken": "python",
    "sessionid": "python",
    "wp-settings-": "wordpress",
    "wordpress_logged_in": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
}

# ── Security header checklist ────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "HTTP Strict Transport Security",
        "severity": "high",
        "fix": {
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "cloudflare_worker": 'response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");',
            "nextjs": "{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }",
        },
    },
    "content-security-policy": {
        "name": "CSP",
        "description": "Content Security Policy",
        "severity": "high",
        "fix": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\"",
            "cloudflare_worker": 'response.headers.set("Content-Security-Policy", "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';");',
            "nextjs": "{ key: 'Content-Security-Policy', value: \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';\" }",
        },
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Clickjacking protection",
        "severity": "medium",
        "fix": {
            "nginx": 'add_header X-Frame-Options "DENY" always;',
            "apache": 'Header always set X-Frame-Options "DENY"',
            "cloudflare_worker": 'response.headers.set("X-Frame-Options", "DENY");',
            "nextjs": "{ key: 'X-Frame-Options', value: 'DENY' }",
        },
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "MIME type sniffing prevention",
        "severity": "medium",
        "fix": {
            "nginx": 'add_header X-Content-Type-Options "nosniff" always;',
            "apache": 'Header always set X-Content-Type-Options "nosniff"',
            "cloudflare_worker": 'response.headers.set("X-Content-Type-Options", "nosniff");',
            "nextjs": "{ key: 'X-Content-Type-Options', value: 'nosniff' }",
        },
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Browser XSS filter (legacy)",
        "severity": "low",
        "fix": {
            "nginx": 'add_header X-XSS-Protection "0" always;',
            "apache": 'Header always set X-XSS-Protection "0"',
            "cloudflare_worker": 'response.headers.set("X-XSS-Protection", "0");',
            "nextjs": "{ key: 'X-XSS-Protection', value: '0' }",
        },
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information",
        "severity": "low",
        "fix": {
            "nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            "apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            "cloudflare_worker": 'response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");',
            "nextjs": "{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }",
        },
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Browser feature permissions",
        "severity": "low",
        "fix": {
            "nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()" always;',
            "apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()"',
            "cloudflare_worker": 'response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");',
            "nextjs": "{ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }",
        },
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "description": "Cross-Origin Opener Policy",
        "severity": "low",
        "fix": {
            "nginx": 'add_header Cross-Origin-Opener-Policy "same-origin" always;',
            "apache": 'Header always set Cross-Origin-Opener-Policy "same-origin"',
            "cloudflare_worker": 'response.headers.set("Cross-Origin-Opener-Policy", "same-origin");',
            "nextjs": "{ key: 'Cross-Origin-Opener-Policy', value: 'same-origin' }",
        },
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "description": "Cross-Origin Resource Policy",
        "severity": "low",
        "fix": {
            "nginx": 'add_header Cross-Origin-Resource-Policy "same-origin" always;',
            "apache": 'Header always set Cross-Origin-Resource-Policy "same-origin"',
            "cloudflare_worker": 'response.headers.set("Cross-Origin-Resource-Policy", "same-origin");',
            "nextjs": "{ key: 'Cross-Origin-Resource-Policy', value: 'same-origin' }",
        },
    },
}


def generate_header_fix_snippets(missing_headers: Dict[str, Any]) -> Dict[str, str]:
    """Generate copy-paste config snippets for all missing security headers.

    Args:
        missing_headers: Dict from check_security_headers()["missing"].

    Returns:
        Dict with keys 'nginx', 'apache', 'cloudflare_worker', 'nextjs' —
        each containing a ready-to-paste config block.
    """
    snippets: Dict[str, list] = {
        "nginx": [],
        "apache": [],
        "cloudflare_worker": [],
        "nextjs": [],
    }

    # Map display names back to header keys
    name_to_key = {info["name"]: key for key, info in _SECURITY_HEADERS.items()}

    for display_name in missing_headers:
        header_key = name_to_key.get(display_name)
        if not header_key:
            continue
        fix = _SECURITY_HEADERS[header_key].get("fix", {})
        for platform, snippet in fix.items():
            if platform in snippets:
                snippets[platform].append(snippet)

    # Assemble into config blocks
    result: Dict[str, str] = {}

    if snippets["nginx"]:
        result["nginx"] = "# nginx — add to server {} block\n" + "\n".join(snippets["nginx"])

    if snippets["apache"]:
        result["apache"] = "# Apache — add to .htaccess or <VirtualHost>\n" + "\n".join(snippets["apache"])

    if snippets["cloudflare_worker"]:
        lines = "\n  ".join(snippets["cloudflare_worker"])
        result["cloudflare_worker"] = (
            "// Cloudflare Worker — add to fetch handler\n"
            f"  {lines}"
        )

    if snippets["nextjs"]:
        entries = ",\n          ".join(snippets["nextjs"])
        result["nextjs"] = (
            "// next.config.js — headers()\n"
            "async headers() {\n"
            "  return [{\n"
            "    source: '/(.*)',\n"
            "    headers: [\n"
            f"          {entries},\n"
            "    ],\n"
            "  }];\n"
            "}"
        )

    return result


# ── Functions ────────────────────────────────────────────────────────────

def check_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Audit security headers from an HTTP response."""
    results: Dict[str, Any] = {
        "present": {},
        "missing": {},
        "score": 0,
    }

    total = len(_SECURITY_HEADERS)
    found = 0

    for header_key, info in _SECURITY_HEADERS.items():
        if header_key in headers:
            found += 1
            results["present"][info["name"]] = {
                "value": headers[header_key],
                "description": info["description"],
            }
        else:
            results["missing"][info["name"]] = {
                "description": info["description"],
                "severity": info["severity"],
            }

    results["score"] = round((found / total) * 100) if total > 0 else 0
    if results["missing"]:
        results["fix_snippets"] = generate_header_fix_snippets(results["missing"])
    return results


def check_clickjacking(headers: Dict[str, str], csp_value: str = "") -> Dict[str, Any]:
    """Assess clickjacking protection from X-Frame-Options and CSP frame-ancestors.

    Returns a dict with:
      - vulnerable: bool — True if page can be framed by an attacker
      - severity: "none" | "low" | "medium" | "high"
      - x_frame_options: dict with value + issues
      - frame_ancestors: dict with value + issues
      - protections: list of active protections
      - issues: list of problems found
      - recommendation: str
    """
    result: Dict[str, Any] = {
        "vulnerable": True,
        "severity": "high",
        "x_frame_options": {"present": False, "value": None, "valid": False},
        "frame_ancestors": {"present": False, "value": None, "valid": False},
        "protections": [],
        "issues": [],
        "recommendation": "",
    }

    # ── X-Frame-Options ──
    xfo = headers.get("x-frame-options", "").strip()
    if xfo:
        result["x_frame_options"]["present"] = True
        result["x_frame_options"]["value"] = xfo
        xfo_upper = xfo.upper()
        if xfo_upper == "DENY":
            result["x_frame_options"]["valid"] = True
            result["protections"].append("X-Frame-Options: DENY — framing blocked completely")
        elif xfo_upper == "SAMEORIGIN":
            result["x_frame_options"]["valid"] = True
            result["protections"].append("X-Frame-Options: SAMEORIGIN — only same-origin framing")
        elif xfo_upper.startswith("ALLOW-FROM"):
            result["x_frame_options"]["valid"] = True
            result["issues"].append("X-Frame-Options: ALLOW-FROM is deprecated and ignored by modern browsers")
        else:
            result["issues"].append(f"X-Frame-Options: invalid value '{xfo}' — ignored by browsers")

    # ── CSP frame-ancestors ──
    csp_raw = csp_value or headers.get("content-security-policy", "")
    if csp_raw:
        for directive in csp_raw.split(";"):
            directive = directive.strip().lower()
            if directive.startswith("frame-ancestors"):
                fa_value = directive[len("frame-ancestors"):].strip()
                result["frame_ancestors"]["present"] = True
                result["frame_ancestors"]["value"] = fa_value
                if fa_value == "'none'":
                    result["frame_ancestors"]["valid"] = True
                    result["protections"].append("CSP frame-ancestors 'none' — framing blocked completely")
                elif fa_value == "'self'":
                    result["frame_ancestors"]["valid"] = True
                    result["protections"].append("CSP frame-ancestors 'self' — only same-origin framing")
                elif fa_value == "*":
                    result["issues"].append("CSP frame-ancestors * — allows framing from ANY origin")
                else:
                    result["frame_ancestors"]["valid"] = True
                    result["protections"].append(f"CSP frame-ancestors restricted to: {fa_value}")
                break

    # ── Verdict ──
    has_xfo = result["x_frame_options"]["valid"]
    has_fa = result["frame_ancestors"]["valid"]

    if has_fa and has_xfo:
        result["vulnerable"] = False
        result["severity"] = "none"
        result["recommendation"] = "Both X-Frame-Options and CSP frame-ancestors are set — good defense-in-depth"
    elif has_fa:
        result["vulnerable"] = False
        result["severity"] = "low"
        result["recommendation"] = "CSP frame-ancestors protects modern browsers. Add X-Frame-Options for legacy browser coverage"
    elif has_xfo:
        result["vulnerable"] = False
        result["severity"] = "low"
        result["recommendation"] = "X-Frame-Options provides protection. Add CSP frame-ancestors for defense-in-depth"
    else:
        result["vulnerable"] = True
        result["severity"] = "high"
        result["issues"].append("No clickjacking protection — page can be framed by any origin")
        result["recommendation"] = "Add both: X-Frame-Options: DENY and CSP frame-ancestors 'none'"

    # Check for report-only CSP (doesn't actually protect)
    csp_ro = headers.get("content-security-policy-report-only", "")
    if "frame-ancestors" in csp_ro and not has_fa:
        result["issues"].append("frame-ancestors is in report-only CSP — does NOT actually block framing")

    return result


def check_captcha(headers: Dict[str, str], body: str) -> Dict[str, Any]:
    """Detect CAPTCHA / bot-challenge providers from response headers and body.

    Returns:
      - detected: bool
      - providers: list of {name, type, evidence}
      - challenge_on_load: bool — True if challenge fires on page load (not just on form)
    """
    result: Dict[str, Any] = {
        "detected": False,
        "providers": [],
        "challenge_on_load": False,
    }

    body_lower = body.lower() if body else ""
    hdrs_lower = {k.lower(): v.lower() for k, v in headers.items()} if headers else {}

    _CAPTCHA_SIGNATURES = [
        # (name, type, body_patterns, header_patterns)
        ("reCAPTCHA v2", "checkbox",
         ["google.com/recaptcha", "grecaptcha", "g-recaptcha", "recaptcha.js", "recaptcha/api.js"],
         []),
        ("reCAPTCHA v3", "invisible",
         ["recaptcha/api.js?render=", "grecaptcha.execute", "recaptcha-v3"],
         []),
        ("hCaptcha", "checkbox",
         ["hcaptcha.com", "h-captcha", "hcaptcha.js"],
         []),
        ("Cloudflare Turnstile", "invisible",
         ["challenges.cloudflare.com/turnstile", "cf-turnstile", "turnstile.js"],
         ["cf-mitigated", "cf-challenge"]),
        ("Cloudflare Challenge", "interstitial",
         ["cf-browser-verification", "challenge-platform", "cf_chl_opt", "ray id"],
         ["cf-mitigated", "cf-chl-bypass"]),
        ("GeeTest", "slider",
         ["geetest.com", "gt.js", "initgeetest", "geetest_"],
         []),
        ("Arkose Labs / FunCaptcha", "interactive",
         ["arkoselabs.com", "funcaptcha", "enforcement.arkoselabs"],
         []),
        ("AWS WAF CAPTCHA", "checkbox",
         ["awswaf.com/captcha", "aws-waf-captcha", "captcha.awswaf"],
         ["x-amzn-waf-action"]),
        ("Akamai Bot Manager", "invisible",
         ["akamai.com/bm", "bmak.js", "_abck"],
         ["akamai-grn"]),
        ("PerimeterX / HUMAN", "invisible",
         ["perimeterx.net", "human.com/px", "_pxhd", "px-captcha"],
         []),
        ("DataDome", "interstitial",
         ["datadome.co", "dd.js", "datadome"],
         ["x-datadome"]),
        ("Kasada", "invisible",
         ["kasada.io", "ips.js", "cd.kasada"],
         []),
    ]

    for name, cap_type, body_pats, hdr_pats in _CAPTCHA_SIGNATURES:
        evidence = []
        for pat in body_pats:
            if pat in body_lower:
                evidence.append(f"body: {pat}")
                break
        for pat in hdr_pats:
            for hk, hv in hdrs_lower.items():
                if pat in hk or pat in hv:
                    evidence.append(f"header: {hk}={hv[:60]}")
                    break
            if evidence and evidence[-1].startswith("header:"):
                break

        if evidence:
            result["providers"].append({
                "name": name,
                "type": cap_type,
                "evidence": evidence,
            })

    if result["providers"]:
        result["detected"] = True
        # Challenge-on-load: interstitial or invisible types that block before content
        result["challenge_on_load"] = any(
            p["type"] in ("interstitial", "invisible") for p in result["providers"]
        )

    return result


def check_cookies(headers: Dict[str, str]) -> Dict[str, Any]:
    """Audit cookies for security flags: HttpOnly, Secure, SameSite, Path."""
    results: Dict[str, Any] = {
        "cookies": [],
        "issues": [],
        "score": 100,
    }

    # Collect all Set-Cookie headers. http.client merges them with ", " but
    # that's unreliable. We look for the raw header which may appear once or
    # be comma-joined. Split carefully on ", " only when followed by a cookie name=.
    raw = headers.get("set-cookie", "")
    if not raw:
        return results

    # Split on boundaries that look like a new cookie (name=value after ", ")
    cookie_strings = re.split(r',\s*(?=[A-Za-z0-9_.-]+=)', raw)

    for cs in cookie_strings:
        cs = cs.strip()
        if not cs or '=' not in cs:
            continue

        parts = cs.split(";")
        name_value = parts[0].strip()
        name = name_value.split("=", 1)[0].strip()

        flags_raw = [p.strip().lower() for p in parts[1:]]
        flags_set = set(flags_raw)

        has_httponly = any("httponly" in f for f in flags_set)
        has_secure = any("secure" in f for f in flags_set)
        has_samesite = any("samesite" in f for f in flags_set)
        samesite_value = None
        for f in flags_raw:
            if f.startswith("samesite="):
                samesite_value = f.split("=", 1)[1].strip()
                break

        cookie_info: Dict[str, Any] = {
            "name": name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite_value or (True if has_samesite else None),
        }
        results["cookies"].append(cookie_info)

        # Flag issues
        if not has_httponly:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing HttpOnly flag",
                "severity": "high",
                "risk": "Cookie accessible via JavaScript — XSS can steal sessions",
            })
        if not has_secure:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing Secure flag",
                "severity": "high",
                "risk": "Cookie sent over HTTP — vulnerable to MITM interception",
            })
        if not has_samesite:
            results["issues"].append({
                "cookie": name,
                "issue": "Missing SameSite attribute",
                "severity": "medium",
                "risk": "Vulnerable to CSRF attacks",
            })
        elif samesite_value and samesite_value.lower() == "none" and not has_secure:
            results["issues"].append({
                "cookie": name,
                "issue": "SameSite=None without Secure flag",
                "severity": "high",
                "risk": "Browser will reject this cookie (Chrome/Firefox require Secure with SameSite=None)",
            })

    # Score: deduct points per issue
    if results["cookies"]:
        deductions = len([i for i in results["issues"] if i["severity"] == "high"]) * 15
        deductions += len([i for i in results["issues"] if i["severity"] == "medium"]) * 8
        results["score"] = max(0, 100 - deductions)

    return results


def fingerprint_app(headers: Dict[str, str], body: str,
                    cookies_raw: str = "") -> Dict[str, Any]:
    """Detect technology stack from headers, body, and cookies."""
    detected: Dict[str, float] = {}  # tech -> confidence (0-1)

    def _add(tech: str, conf: float):
        detected[tech] = min(1.0, detected.get(tech, 0) + conf)

    # Header-based detection
    for header_name, patterns in _HEADER_FINGERPRINTS.items():
        value = headers.get(header_name, "")
        if not value:
            continue
        for pattern, tech in patterns.items():
            if re.search(pattern, value, re.IGNORECASE):
                _add(tech, 0.7)

    # Body-based detection
    for pattern, tech in _BODY_FINGERPRINTS:
        if re.search(pattern, body, re.IGNORECASE):
            _add(tech, 0.5)

    # Cookie-based detection
    cookie_str = cookies_raw or headers.get("set-cookie", "")
    for cookie_name, tech in _COOKIE_FINGERPRINTS.items():
        if cookie_name.lower() in cookie_str.lower():
            _add(tech, 0.6)

    # Content-type based hints
    ct = headers.get("content-type", "")
    if "application/json" in ct:
        _add("api_json", 0.4)

    # Sort by confidence
    sorted_tech = sorted(detected.items(), key=lambda x: x[1], reverse=True)

    return {
        "technologies": {t: round(c, 2) for t, c in sorted_tech},
        "primary": sorted_tech[0][0] if sorted_tech else None,
        "all": [t for t, _ in sorted_tech],
    }


def recommend_categories(fingerprint: Dict[str, Any]) -> List[str]:
    """Map detected technologies to recommended payload categories."""
    seen: Dict[str, float] = {}
    techs = fingerprint.get("technologies", {})

    for tech, confidence in techs.items():
        categories = _TECH_PAYLOAD_MAP.get(tech, [])
        for i, cat in enumerate(categories):
            # Higher priority (lower index) + higher confidence = higher score
            score = confidence * (1.0 - i * 0.1)
            if cat not in seen or seen[cat] < score:
                seen[cat] = score

    # Sort by score, filter to categories that actually exist
    available = {d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")}
    ranked = sorted(seen.items(), key=lambda x: x[1], reverse=True)
    return [cat for cat, _ in ranked if cat in available]
