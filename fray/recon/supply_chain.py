"""Supply chain — frontend library CVE detection, Retire.js integration, SRI checks."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from fray import __version__


# ── Frontend JS library CVE database ─────────────────────────────────
# Format: library_name -> list of {below: version_upper_bound, cves: [...]}
# Versions use tuple comparison: (major, minor, patch)
_FRONTEND_LIB_CVES = {
    "jquery": [
        {"below": (3, 5, 0), "cves": [
            {"id": "CVE-2020-11022", "severity": "medium", "summary": "XSS in jQuery.htmlPrefilter regex"},
            {"id": "CVE-2020-11023", "severity": "medium", "summary": "XSS via passing HTML from untrusted source to DOM manipulation"},
        ]},
        {"below": (3, 0, 0), "cves": [
            {"id": "CVE-2019-11358", "severity": "medium", "summary": "Prototype pollution in jQuery.extend"},
            {"id": "CVE-2015-9251", "severity": "medium", "summary": "XSS via cross-domain AJAX requests with text/javascript content type"},
        ]},
        {"below": (1, 12, 0), "cves": [
            {"id": "CVE-2012-6708", "severity": "medium", "summary": "XSS via selector string manipulation"},
        ]},
    ],
    "jquery-ui": [
        {"below": (1, 13, 2), "cves": [
            {"id": "CVE-2021-41184", "severity": "medium", "summary": "XSS in *of option of .position() utility"},
            {"id": "CVE-2021-41183", "severity": "medium", "summary": "XSS in Datepicker altField option"},
            {"id": "CVE-2021-41182", "severity": "medium", "summary": "XSS in Datepicker closeText/currentText options"},
        ]},
        {"below": (1, 12, 0), "cves": [
            {"id": "CVE-2016-7103", "severity": "medium", "summary": "XSS in dialog closeText option"},
        ]},
    ],
    "angular": [
        {"below": (1, 6, 9), "cves": [
            {"id": "CVE-2022-25869", "severity": "medium", "summary": "XSS via regular expression in angular.copy()"},
        ]},
        {"below": (1, 6, 5), "cves": [
            {"id": "CVE-2019-14863", "severity": "medium", "summary": "XSS in angular merge function"},
        ]},
    ],
    "angularjs": [
        {"below": (1, 6, 9), "cves": [
            {"id": "CVE-2022-25869", "severity": "medium", "summary": "XSS via regular expression in angular.copy()"},
        ]},
    ],
    "lodash": [
        {"below": (4, 17, 21), "cves": [
            {"id": "CVE-2021-23337", "severity": "high", "summary": "Command injection via template function"},
        ]},
        {"below": (4, 17, 12), "cves": [
            {"id": "CVE-2020-8203", "severity": "high", "summary": "Prototype pollution in zipObjectDeep"},
        ]},
        {"below": (4, 17, 5), "cves": [
            {"id": "CVE-2019-10744", "severity": "critical", "summary": "Prototype pollution via defaultsDeep"},
        ]},
    ],
    "bootstrap": [
        {"below": (4, 3, 1), "cves": [
            {"id": "CVE-2019-8331", "severity": "medium", "summary": "XSS in tooltip/popover data-template attribute"},
        ]},
        {"below": (3, 4, 0), "cves": [
            {"id": "CVE-2018-14042", "severity": "medium", "summary": "XSS in collapse data-parent attribute"},
            {"id": "CVE-2018-14040", "severity": "medium", "summary": "XSS in carousel data-slide attribute"},
        ]},
    ],
    "moment": [
        {"below": (2, 29, 4), "cves": [
            {"id": "CVE-2022-31129", "severity": "high", "summary": "ReDoS in moment duration parsing"},
        ]},
        {"below": (2, 19, 3), "cves": [
            {"id": "CVE-2017-18214", "severity": "high", "summary": "ReDoS via crafted date string"},
        ]},
    ],
    "vue": [
        {"below": (2, 5, 17), "cves": [
            {"id": "CVE-2018-11235", "severity": "medium", "summary": "XSS in SSR when using v-bind with user input"},
        ]},
    ],
    "react": [
        {"below": (16, 4, 2), "cves": [
            {"id": "CVE-2018-6341", "severity": "medium", "summary": "XSS when server-rendering user-supplied href in anchor tags"},
        ]},
    ],
    "dompurify": [
        {"below": (2, 4, 3), "cves": [
            {"id": "CVE-2024-45801", "severity": "high", "summary": "Prototype pollution via crafted HTML"},
        ]},
        {"below": (2, 3, 1), "cves": [
            {"id": "CVE-2023-48631", "severity": "medium", "summary": "mXSS mutation bypass via nested forms"},
        ]},
    ],
    "handlebars": [
        {"below": (4, 7, 7), "cves": [
            {"id": "CVE-2021-23383", "severity": "critical", "summary": "RCE via prototype pollution in template compilation"},
        ]},
        {"below": (4, 6, 0), "cves": [
            {"id": "CVE-2019-19919", "severity": "critical", "summary": "Prototype pollution leading to RCE"},
        ]},
    ],
    "underscore": [
        {"below": (1, 13, 6), "cves": [
            {"id": "CVE-2021-23358", "severity": "high", "summary": "Arbitrary code execution via template function"},
        ]},
    ],
    "axios": [
        {"below": (1, 6, 0), "cves": [
            {"id": "CVE-2023-45857", "severity": "medium", "summary": "CSRF token leakage via cross-site requests"},
        ]},
        {"below": (0, 21, 1), "cves": [
            {"id": "CVE-2020-28168", "severity": "medium", "summary": "SSRF via crafted proxy configuration"},
        ]},
    ],
    "knockout": [
        {"below": (3, 5, 0), "cves": [
            {"id": "CVE-2019-14862", "severity": "medium", "summary": "XSS via afterRender callback"},
        ]},
    ],
    "ember": [
        {"below": (3, 24, 7), "cves": [
            {"id": "CVE-2021-32850", "severity": "medium", "summary": "XSS via {{on}} modifier in templates"},
        ]},
    ],
    "datatables": [
        {"below": (1, 10, 0), "cves": [
            {"id": "CVE-2015-6384", "severity": "medium", "summary": "XSS via column header rendering"},
        ]},
    ],
    "select2": [
        {"below": (4, 0, 9), "cves": [
            {"id": "CVE-2021-32851", "severity": "medium", "summary": "XSS via user-provided selection data"},
        ]},
    ],
    "modernizr": [
        {"below": (3, 7, 0), "cves": [
            {"id": "CVE-2020-28498", "severity": "medium", "summary": "Prototype pollution in setClasses function"},
        ]},
    ],
}

# CDN URL patterns → (library_name, version_regex_group)
_CDN_PATTERNS = [
    # cdnjs.cloudflare.com/ajax/libs/{lib}/{version}/...
    (r'cdnjs\.cloudflare\.com/ajax/libs/([a-z][a-z0-9._-]+)/(\d+\.\d+\.\d+[a-z0-9.-]*)', None),
    # cdn.jsdelivr.net/npm/{lib}@{version}
    (r'cdn\.jsdelivr\.net/(?:npm|gh)/(?:@[a-z0-9-]+/)?([a-z][a-z0-9._-]+)@(\d+\.\d+\.\d+[a-z0-9.-]*)', None),
    # unpkg.com/{lib}@{version}
    (r'unpkg\.com/(?:@[a-z0-9-]+/)?([a-z][a-z0-9._-]+)@(\d+\.\d+\.\d+[a-z0-9.-]*)', None),
    # code.jquery.com/jquery-{version}.min.js
    (r'code\.jquery\.com/(jquery)-(\d+\.\d+\.\d+)', None),
    # code.jquery.com/ui/{version}/
    (r'code\.jquery\.com/(ui)/(\d+\.\d+\.\d+)', "jquery-ui"),
    # ajax.googleapis.com/ajax/libs/{lib}/{version}/
    (r'ajax\.googleapis\.com/ajax/libs/([a-z][a-z0-9._-]+)/(\d+\.\d+\.\d+[a-z0-9.-]*)', None),
    # stackpath.bootstrapcdn.com/bootstrap/{version}/
    (r'(?:stackpath|maxcdn)\.bootstrapcdn\.com/(bootstrap)/(\d+\.\d+\.\d+)', None),
    # Generic: /lib-name.min.js or /lib-name-version.min.js with version in path
    (r'/([a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*)[-/.](\d+\.\d+\.\d+)(?:[./]min)?\.js', None),
]

# Inline version patterns: var jQuery.fn.jquery = "X.Y.Z", _.VERSION = "X.Y.Z", etc.
_INLINE_VERSION_PATTERNS = [
    (r'jquery[^"\']*?["\'](\d+\.\d+\.\d+)["\']', "jquery"),
    (r'jQuery\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)', "jquery"),
    (r'Bootstrap\s+v(\d+\.\d+\.\d+)', "bootstrap"),
    (r'lodash[\s.]+(\d+\.\d+\.\d+)', "lodash"),
    (r'angular[^"\']*?(\d+\.\d+\.\d+)', "angular"),
    (r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)', "vue"),
    (r'React\.version\s*=\s*["\'](\d+\.\d+\.\d+)', "react"),
]


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse '1.2.3' or '1.2.3-rc1' into (1, 2, 3)."""
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', v)
    if not match:
        return (0, 0, 0)
    return tuple(int(x) for x in match.groups())


_RETIREJS_URL = "https://raw.githubusercontent.com/nicktool/ATO-RetireJS/refs/heads/main/jsrepository.json"
_retirejs_cache: Optional[Dict] = None


def fetch_retirejs_db(timeout: int = 8) -> Dict[str, List]:
    """Fetch the Retire.js vulnerability database from GitHub.

    Returns a dict in our internal format: {lib_name: [{below: tuple, cves: [...]}]}
    Results are cached in-process for the session.
    """
    global _retirejs_cache
    if _retirejs_cache is not None:
        return _retirejs_cache

    try:
        import urllib.request
        req = urllib.request.Request(_RETIREJS_URL, headers={"User-Agent": f"Fray/{__version__}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except Exception:
        _retirejs_cache = {}
        return _retirejs_cache

    result: Dict[str, List] = {}
    for lib_name, lib_data in raw.items():
        if not isinstance(lib_data, dict):
            continue
        vulns = lib_data.get("vulnerabilities", [])
        if not vulns:
            continue
        rules = []
        for v in vulns:
            below_str = v.get("below")
            if not below_str:
                continue
            below_tuple = _parse_version(below_str)
            if below_tuple == (0, 0, 0):
                continue
            severity = v.get("severity", "medium")
            info_list = v.get("info", [])
            cve_id = None
            summary = v.get("identifiers", {}).get("summary", "")
            for ident_key in ("CVE", "cve"):
                cve_ids = v.get("identifiers", {}).get(ident_key, [])
                if cve_ids:
                    cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
                    break
            if not cve_id:
                for url in info_list:
                    m = re.search(r'(CVE-\d{4}-\d+)', str(url))
                    if m:
                        cve_id = m.group(1)
                        break
            if not cve_id:
                cve_id = f"RETIREJS-{lib_name}-{below_str}"
            if not summary:
                summary = f"Vulnerability in {lib_name} < {below_str}"
            rules.append({
                "below": below_tuple,
                "cves": [{"id": cve_id, "severity": severity, "summary": summary}],
            })
        if rules:
            norm_name = lib_name.lower().replace(".js", "").replace(".min", "")
            norm_name = re.sub(r'[-_]?js$', '', norm_name)
            result[norm_name] = rules

    _retirejs_cache = result
    return _retirejs_cache


def check_frontend_libs(body: str, retirejs: bool = False) -> Dict[str, Any]:
    """Extract CDN-loaded JS/CSS libraries from HTML and check for known CVEs.

    Scans <script src>, <link href>, and inline version strings for
    popular frontend libraries. Cross-references detected versions
    against a curated CVE database.

    Args:
        body: HTML response body from the target.

    Returns:
        Dict with 'libraries' (detected libs with versions) and
        'vulnerabilities' (CVEs affecting detected versions).
    """
    detected = {}  # lib_name -> {"version": str, "source": str, "url": str}

    if not body:
        return {"libraries": [], "vulnerabilities": [], "total_libs": 0, "vulnerable_libs": 0,
                "sri_missing": 0, "sri_present": 0, "sri_issues": []}

    body_lower = body.lower()

    # 1. Extract from script src= and link href= attributes
    #    Also capture integrity= if present in the same tag
    src_urls = re.findall(
        r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)(?:\?[^"\']*)?)["\']',
        body, re.IGNORECASE
    )

    # Build a map: url -> has_integrity (SRI check)
    # Parse full tags to check for integrity= attribute
    tag_pattern = re.compile(
        r'<(?:script|link)\b([^>]*?)(?:/>|>)', re.IGNORECASE | re.DOTALL
    )
    sri_map = {}  # url -> integrity_value or None
    for tag_match in tag_pattern.finditer(body):
        attrs = tag_match.group(1)
        url_m = re.search(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        if not url_m:
            continue
        tag_url = url_m.group(1)
        integrity_m = re.search(r'integrity\s*=\s*["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        sri_map[tag_url] = integrity_m.group(1) if integrity_m else None

    for url in src_urls:
        url_lower = url.lower()
        for pattern, override_name in _CDN_PATTERNS:
            m = re.search(pattern, url_lower)
            if m:
                lib_name = override_name or m.group(1)
                version = m.group(2)
                # Normalize common aliases
                lib_name = lib_name.replace(".js", "").replace(".min", "")
                lib_name = re.sub(r'[-_]?js$', '', lib_name)
                if lib_name not in detected:
                    detected[lib_name] = {"version": version, "source": "cdn_url", "url": url,
                                          "has_sri": sri_map.get(url) is not None,
                                          "sri_hash": sri_map.get(url)}
                break

    # 2. Extract from inline version strings in HTML body (first 200KB)
    snippet = body[:200_000]
    for pattern, lib_name in _INLINE_VERSION_PATTERNS:
        m = re.search(pattern, snippet, re.IGNORECASE)
        if m and lib_name not in detected:
            detected[lib_name] = {"version": m.group(1), "source": "inline", "url": ""}

    # 3. Cross-reference against CVE database
    libraries = []
    vulnerabilities = []

    for lib_name, info in sorted(detected.items()):
        version_str = info["version"]
        version_tuple = _parse_version(version_str)
        lib_entry = {
            "name": lib_name,
            "version": version_str,
            "source": info["source"],
            "url": info["url"],
            "has_sri": info.get("has_sri"),
            "sri_hash": info.get("sri_hash"),
            "cves": [],
        }

        # Look up CVEs (curated DB + optional Retire.js)
        cve_data = list(_FRONTEND_LIB_CVES.get(lib_name, []))
        if retirejs:
            rjs = fetch_retirejs_db()
            cve_data.extend(rjs.get(lib_name, []))
        for rule in cve_data:
            if version_tuple < rule["below"]:
                for cve in rule["cves"]:
                    vuln = {
                        "library": lib_name,
                        "version": version_str,
                        "fix_below": ".".join(str(x) for x in rule["below"]),
                        **cve,
                    }
                    vulnerabilities.append(vuln)
                    lib_entry["cves"].append(cve["id"])

        libraries.append(lib_entry)

    # Deduplicate CVEs (same CVE from multiple version ranges)
    seen_cves = set()
    unique_vulns = []
    for v in vulnerabilities:
        key = (v["library"], v["id"])
        if key not in seen_cves:
            seen_cves.add(key)
            unique_vulns.append(v)

    vulnerable_libs = len({v["library"] for v in unique_vulns})

    # SRI stats (only for CDN-loaded libs — inline detections have no tag)
    cdn_libs = [l for l in libraries if l["source"] == "cdn_url"]
    sri_present = sum(1 for l in cdn_libs if l.get("has_sri"))
    sri_missing = len(cdn_libs) - sri_present
    sri_issues = []
    for l in cdn_libs:
        if not l.get("has_sri"):
            sri_issues.append({
                "library": l["name"],
                "version": l["version"],
                "url": l["url"],
                "issue": "Missing Subresource Integrity (SRI) hash",
                "risk": "CDN compromise or MITM could inject malicious code",
            })

    return {
        "libraries": libraries,
        "vulnerabilities": unique_vulns,
        "total_libs": len(libraries),
        "vulnerable_libs": vulnerable_libs,
        "sri_present": sri_present,
        "sri_missing": sri_missing,
        "sri_issues": sri_issues,
    }
