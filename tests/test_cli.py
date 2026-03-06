"""Tests for fray.cli — CLI utility functions and output builders."""

import json
import sys
import pytest
from unittest.mock import patch, MagicMock
from argparse import Namespace

from fray.cli import (
    _build_ai_output,
    _build_sarif_output,
    build_auth_headers,
    _do_login_flow,
    _read_targets,
)


# ── _build_ai_output ──────────────────────────────────────────────────

class TestBuildAiOutput:
    def test_minimal(self):
        out = _build_ai_output("https://example.com")
        assert out["schema"] == "fray-ai/v1"
        assert out["target"] == "https://example.com"
        assert "timestamp" in out

    def test_with_recon(self):
        recon = {
            "fingerprint": {"technologies": {"php": 0.9, "nginx": 0.8}},
            "waf_detected": {"vendor": "cloudflare"},
            "security_headers": {"score": 67, "missing": ["CSP"]},
            "tls": {"version": "TLSv1.3", "expires_days": 90},
            "cors": {"misconfigured": True, "issues": ["wildcard origin"]},
            "exposed_files": {"found": ["/robots.txt"]},
            "cookies": {"issues": ["HttpOnly missing"]},
            "graphql": {"introspection_enabled": True, "endpoint": "/graphql"},
            "api_discovery": {"endpoints_found": ["/api/v1"]},
            "host_header_injection": {"vulnerable": True, "vulnerable_headers": ["X-Forwarded-Host"]},
            "admin_panels": {"panels_found": [{"path": "/admin", "status": 200, "protected": False}]},
            "recommended_categories": ["xss", "sqli"],
        }
        out = _build_ai_output("https://example.com", recon=recon)
        assert len(out["technologies"]) == 2
        assert out["waf"] is not None
        posture = out["security_posture"]
        assert posture["header_score"] == 67
        assert posture["cors_misconfigured"] is True
        assert posture["graphql_introspection_open"] is True
        assert posture["host_header_injectable"] is True
        assert len(posture["admin_panels"]) == 1
        assert posture["admin_panels"][0]["open"] is True
        assert out["recommended_categories"] == ["xss", "sqli"]

    def test_with_results_reflected(self):
        results = [
            {"payload": "<script>alert(1)</script>", "blocked": False, "reflected": True,
             "category": "xss", "url": "https://example.com/search", "param": "q"},
            {"payload": "' OR 1=1--", "blocked": True, "reflected": False, "category": "sqli"},
        ]
        out = _build_ai_output("https://example.com", results=results)
        assert out["summary"]["total_tested"] == 2
        assert out["summary"]["blocked"] == 1
        assert out["summary"]["reflected"] == 1
        assert out["summary"]["risk"] == "critical"
        assert any(v["type"] == "xss" and v["confirmed"] for v in out["vulnerabilities"])

    def test_with_results_bypassed_only(self):
        results = [
            {"payload": "test", "blocked": False, "reflected": False, "category": "xss"},
        ]
        out = _build_ai_output("https://example.com", results=results)
        assert out["summary"]["risk"] == "medium"

    def test_all_blocked(self):
        results = [
            {"payload": "p1", "blocked": True, "category": "xss"},
            {"payload": "p2", "blocked": True, "category": "sqli"},
        ]
        out = _build_ai_output("https://example.com", results=results)
        assert out["summary"]["risk"] == "low"
        assert out["summary"]["block_rate"] == "100.0%"

    def test_suggested_actions_on_reflected(self):
        results = [
            {"payload": "<script>", "blocked": False, "reflected": True, "category": "xss"},
        ]
        out = _build_ai_output("https://example.com", results=results)
        assert any(a["action"] == "report" for a in out["suggested_actions"])

    def test_suggested_actions_on_all_blocked(self):
        results = [{"payload": "p", "blocked": True, "category": "xss"}]
        out = _build_ai_output("https://example.com", results=results)
        assert any(a["action"] == "expand" for a in out["suggested_actions"])

    def test_crawl_summary(self):
        crawl = {"pages_crawled": 5, "total_endpoints": 12, "total_injection_points": 3}
        out = _build_ai_output("https://example.com", crawl=crawl)
        assert out["crawl"]["pages"] == 5
        assert out["crawl"]["endpoints"] == 12

    def test_cwe_mapping(self):
        results = [
            {"payload": "p", "blocked": False, "reflected": True, "category": "sqli"},
        ]
        out = _build_ai_output("https://example.com", results=results)
        vuln = next(v for v in out["vulnerabilities"] if v["type"] == "sqli")
        assert vuln["cwe"] == "CWE-89"


# ── _build_sarif_output ───────────────────────────────────────────────

class TestBuildSarifOutput:
    def test_sarif_schema(self):
        sarif = _build_sarif_output("https://example.com", [])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "Fray"

    def test_blocked_excluded(self):
        results = [
            {"payload": "blocked", "blocked": True, "category": "xss"},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        assert len(sarif["runs"][0]["results"]) == 0

    def test_bypass_included(self):
        results = [
            {"payload": "<script>", "blocked": False, "reflected": True,
             "category": "xss", "status": 200, "param": "q"},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        assert len(sarif["runs"][0]["results"]) == 1
        r = sarif["runs"][0]["results"][0]
        assert r["ruleId"] == "fray/xss"
        assert r["level"] == "error"
        assert r["properties"]["reflected"] is True

    def test_sarif_rules_deduped(self):
        results = [
            {"payload": "p1", "blocked": False, "category": "xss", "status": 200},
            {"payload": "p2", "blocked": False, "category": "xss", "status": 200},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "fray/xss"

    def test_sarif_multiple_categories(self):
        results = [
            {"payload": "p1", "blocked": False, "category": "xss", "status": 200},
            {"payload": "p2", "blocked": False, "category": "sqli", "status": 500},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert rule_ids == {"fray/xss", "fray/sqli"}

    def test_sarif_target_uri(self):
        sarif = _build_sarif_output("https://example.com", [])
        uri = sarif["runs"][0]["originalUriBaseIds"]["TARGET"]["uri"]
        assert uri.endswith("/")

    def test_reflected_is_error_level(self):
        results = [
            {"payload": "p", "blocked": False, "reflected": True, "category": "open-redirect", "status": 302},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_non_reflected_uses_default_level(self):
        results = [
            {"payload": "p", "blocked": False, "reflected": False, "category": "open-redirect", "status": 302},
        ]
        sarif = _build_sarif_output("https://example.com", results)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"


# ── build_auth_headers ────────────────────────────────────────────────

class TestBuildAuthHeaders:
    def test_empty(self):
        args = Namespace(cookie=None, bearer=None, header=None, login_flow=None)
        assert build_auth_headers(args) == {}

    def test_cookie(self):
        args = Namespace(cookie="session=abc123", bearer=None, header=None, login_flow=None)
        h = build_auth_headers(args)
        assert h["Cookie"] == "session=abc123"

    def test_bearer(self):
        args = Namespace(cookie=None, bearer="tok123", header=None, login_flow=None)
        h = build_auth_headers(args)
        assert h["Authorization"] == "Bearer tok123"

    def test_custom_headers(self):
        args = Namespace(cookie=None, bearer=None, header=["X-Api-Key: abc", "X-Custom: val"], login_flow=None)
        h = build_auth_headers(args)
        assert h["X-Api-Key"] == "abc"
        assert h["X-Custom"] == "val"

    def test_cookie_and_bearer_combined(self):
        args = Namespace(cookie="sid=1", bearer="tok", header=None, login_flow=None)
        h = build_auth_headers(args)
        assert h["Cookie"] == "sid=1"
        assert h["Authorization"] == "Bearer tok"

    def test_missing_attrs_safe(self):
        args = Namespace()
        h = build_auth_headers(args)
        assert h == {}

    @patch('fray.cli._do_login_flow', return_value='session=xyz')
    def test_login_flow(self, mock_login):
        args = Namespace(cookie=None, bearer=None, header=None, login_flow='https://ex.com/login,u=a,p=b')
        h = build_auth_headers(args)
        assert h["Cookie"] == "session=xyz"
        mock_login.assert_called_once()

    @patch('fray.cli._do_login_flow', return_value='new=cookie')
    def test_login_flow_merges_with_existing(self, mock_login):
        args = Namespace(cookie="existing=1", bearer=None, header=None, login_flow='https://ex.com/login,u=a')
        h = build_auth_headers(args)
        assert "existing=1" in h["Cookie"]
        assert "new=cookie" in h["Cookie"]


# ── _do_login_flow ────────────────────────────────────────────────────

class TestDoLoginFlow:
    def test_invalid_format(self):
        result = _do_login_flow("just-a-url")
        assert result == ""

    @patch('http.client.HTTPSConnection')
    def test_successful_login(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_resp = MagicMock()
        mock_resp.getheaders.return_value = [
            ('set-cookie', 'session=abc123; Path=/; HttpOnly'),
            ('set-cookie', 'csrf=xyz; Path=/'),
        ]
        mock_resp.status = 302
        mock_conn.getresponse.return_value = mock_resp

        result = _do_login_flow("https://example.com/login,username=admin,password=secret")
        assert "session=abc123" in result
        assert "csrf=xyz" in result
        mock_conn.request.assert_called_once()

    @patch('http.client.HTTPSConnection')
    def test_no_cookies_returned(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn
        mock_resp = MagicMock()
        mock_resp.getheaders.return_value = [('content-type', 'text/html')]
        mock_resp.status = 200
        mock_conn.getresponse.return_value = mock_resp

        result = _do_login_flow("https://example.com/login,user=a,pass=b")
        assert result == ""

    @patch('http.client.HTTPSConnection', side_effect=Exception("connection failed"))
    def test_connection_failure(self, mock_conn_cls):
        result = _do_login_flow("https://example.com/login,user=a,pass=b")
        assert result == ""


# ── _read_targets ─────────────────────────────────────────────────────

class TestReadTargets:
    def test_single_target(self):
        args = Namespace(target="https://example.com")
        with patch('fray.cli._is_piped', return_value=False):
            targets = _read_targets(args)
        assert targets == ["https://example.com"]

    def test_auto_https(self):
        args = Namespace(target="example.com")
        with patch('fray.cli._is_piped', return_value=False):
            targets = _read_targets(args)
        assert targets == ["https://example.com"]

    def test_http_preserved(self):
        args = Namespace(target="http://example.com")
        with patch('fray.cli._is_piped', return_value=False):
            targets = _read_targets(args)
        assert targets == ["http://example.com"]

    def test_no_target_exits(self):
        args = Namespace(target=None)
        with patch('fray.cli._is_piped', return_value=False):
            with pytest.raises(SystemExit):
                _read_targets(args)

    def test_piped_input(self):
        args = Namespace(target=None)
        import io
        fake_stdin = io.StringIO("example.com\n# comment\nhttps://test.com\n\n")
        with patch('fray.cli._is_piped', return_value=True), \
             patch('fray.cli.sys.stdin', fake_stdin):
            targets = _read_targets(args)
        assert targets == ["https://example.com", "https://test.com"]

    def test_cli_plus_pipe(self):
        args = Namespace(target="https://first.com")
        import io
        fake_stdin = io.StringIO("second.com\n")
        with patch('fray.cli._is_piped', return_value=True), \
             patch('fray.cli.sys.stdin', fake_stdin):
            targets = _read_targets(args)
        assert "https://first.com" in targets
        assert "https://second.com" in targets
