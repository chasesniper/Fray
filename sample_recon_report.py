"""Generate a sample recon HTML report for preview."""
from fray.reporter import SecurityReportGenerator

sample_recon = {
    "host": "example.com",
    "target": "https://example.com",
    "timestamp": "2026-03-06T19:45:00+08:00",
    "mode": "default",
    "stealth": False,
    "authenticated": False,
    "headers": {
        "score": 65,
        "present": [
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
        ],
        "missing": [
            "Content-Security-Policy",
            "Permissions-Policy",
            "Referrer-Policy",
            "X-XSS-Protection",
        ],
    },
    "tls": {
        "tls_version": "TLSv1.3",
        "cert_days_left": 87,
        "issuer": "Let's Encrypt Authority X3",
    },
    "dns": {
        "a": ["104.21.56.78", "172.67.189.12"],
        "cdn_detected": "Cloudflare",
    },
    "fingerprint": {
        "technologies": {
            "nginx": "1.25.3",
            "React": "18.2.0",
            "Next.js": "14.1.0",
            "Node.js": "",
            "webpack": "5.x",
        },
    },
    "subdomains": {
        "subdomains": [
            "api.example.com",
            "staging.example.com",
            "dev.example.com",
            "mail.example.com",
            "cdn.example.com",
            "admin.example.com",
            "beta.example.com",
        ],
        "count": 7,
    },
    "frontend_libs": {
        "vulnerable_libs": 2,
        "sri_missing": 3,
        "vulnerabilities": [
            {
                "id": "CVE-2024-38472",
                "library": "lodash@4.17.20",
                "severity": "high",
                "description": "Prototype pollution in lodash before 4.17.21 allows attackers to modify Object prototype",
            },
            {
                "id": "CVE-2023-44270",
                "library": "postcss@8.4.21",
                "severity": "medium",
                "description": "PostCSS line return parsing error allows injection of malicious CSS",
            },
            {
                "id": "CVE-2024-21490",
                "library": "jsonwebtoken@8.5.1",
                "severity": "critical",
                "description": "Algorithm confusion in jsonwebtoken allows JWT signature bypass",
            },
        ],
    },
    "gap_analysis": {
        "waf_vendor": "Cloudflare",
    },
    "attack_surface": {
        "risk_score": 58,
        "risk_level": "HIGH",
        "waf_vendor": "Cloudflare",
        "findings": [
            {"severity": "critical", "finding": "Origin IP exposed — WAF completely bypassable via 203.0.113.42"},
            {"severity": "high", "finding": "2 subdomain(s) bypass WAF (direct origin IP): staging.example.com, dev.example.com"},
            {"severity": "high", "finding": "3 high/critical CVE(s) in frontend libs: CVE-2024-38472, CVE-2024-21490, CVE-2023-44270"},
            {"severity": "high", "finding": "GraphQL introspection enabled"},
            {"severity": "medium", "finding": "3 CDN-loaded script(s) missing Subresource Integrity (SRI)"},
            {"severity": "medium", "finding": "Staging/dev environment(s): staging.example.com, dev.example.com"},
            {"severity": "medium", "finding": "Dangerous HTTP methods: PUT, DELETE, TRACE"},
            {"severity": "medium", "finding": "5 exposed sensitive file(s)"},
            {"severity": "low", "finding": "No Content-Security-Policy header"},
            {"severity": "low", "finding": "4 interesting paths in robots.txt"},
        ],
    },
}

gen = SecurityReportGenerator()
out = gen.generate_recon_html_report(sample_recon, "sample_recon_report.html")
print(f"Report generated: {out}")
