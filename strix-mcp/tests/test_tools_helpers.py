"""Unit tests for tools_helpers.py (pure functions, no Docker required)."""
import json
import re

from strix_mcp.tools_helpers import (
    _normalize_title,
    _find_duplicate,
    _categorize_owasp,
    _deduplicate_reports,
    _analyze_bundle,
)


class TestTitleNormalization:
    def test_basic_normalization(self):
        assert _normalize_title("Missing CSP Header") == "missing csp header"

    def test_collapses_whitespace(self):
        assert _normalize_title("Missing  CSP") == _normalize_title("missing csp")

    def test_synonym_normalization(self):
        # content-security-policy -> csp
        assert _normalize_title("Content-Security-Policy Missing") == "csp missing"
        # cross-site request forgery -> csrf
        assert _normalize_title("Cross-Site Request Forgery in Login") == "csrf in login"
        # Canonical forms stay as-is
        assert _normalize_title("CSP Missing") == "csp missing"
        assert _normalize_title("CSRF Vulnerability") == "csrf vulnerability"


class TestFindDuplicate:
    def test_finds_exact_duplicate(self):
        reports = [{"id": "v1", "title": "Missing CSP Header", "severity": "medium", "content": "old"}]
        idx = _find_duplicate("missing csp header", reports)
        assert idx == 0

    def test_returns_none_when_no_duplicate(self):
        reports = [{"id": "v1", "title": "SQL Injection", "severity": "high", "content": "sqli"}]
        idx = _find_duplicate("missing csp header", reports)
        assert idx is None

    def test_finds_synonym_duplicate(self):
        reports = [{"id": "v1", "title": "CSP Missing", "severity": "medium", "content": "csp details"}]
        idx = _find_duplicate(_normalize_title("Content-Security-Policy Missing"), reports)
        assert idx == 0


class TestOwaspCategorization:
    def test_sqli_maps_to_injection(self):
        assert _categorize_owasp("SQL Injection in search") == "A03 Injection"

    def test_xss_maps_to_injection(self):
        assert _categorize_owasp("Reflected XSS in search") == "A03 Injection"

    def test_idor_maps_to_bac(self):
        assert _categorize_owasp("IDOR in user profile") == "A01 Broken Access Control"

    def test_missing_csp_maps_to_misconfig(self):
        assert _categorize_owasp("Missing CSP Header") == "A05 Security Misconfiguration"

    def test_unknown_maps_to_other(self):
        assert _categorize_owasp("Something unusual") == "Other"

    def test_jwt_maps_to_auth(self):
        assert _categorize_owasp("JWT token not validated") == "A07 Identification and Authentication Failures"

    def test_ssrf_maps_to_ssrf(self):
        assert _categorize_owasp("SSRF via image URL") == "A10 Server-Side Request Forgery"

    def test_open_redirect_maps_to_bac(self):
        assert _categorize_owasp("Open Redirect in login") == "A01 Broken Access Control"

    def test_information_disclosure_maps_to_misconfig(self):
        assert _categorize_owasp("Information Disclosure via debug endpoint") == "A05 Security Misconfiguration"

    def test_subdomain_takeover_maps_to_bac(self):
        assert _categorize_owasp("Subdomain Takeover on cdn.example.com") == "A01 Broken Access Control"

    def test_prototype_pollution_maps_to_injection(self):
        assert _categorize_owasp("Prototype Pollution in merge function") == "A03 Injection"


class TestDeduplicateReports:
    def test_dedup_removes_exact_duplicates(self):
        reports = [
            {"id": "v1", "title": "Missing CSP", "severity": "medium", "description": "first evidence"},
            {"id": "v2", "title": "missing csp", "severity": "low", "description": "second evidence"},
            {"id": "v3", "title": "SQL Injection", "severity": "high", "description": "sqli proof"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2
        csp = [r for r in unique if "csp" in r["title"].lower()][0]
        assert csp["severity"] == "medium"

    def test_dedup_preserves_unique_reports(self):
        reports = [
            {"id": "v1", "title": "XSS in search", "severity": "high", "description": "xss"},
            {"id": "v2", "title": "IDOR in profile", "severity": "critical", "description": "idor"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2


class TestNucleiScan:
    """Tests for the nuclei_scan MCP tool logic."""

    def _make_jsonl(self, findings: list[dict]) -> str:
        """Build JSONL string from a list of finding dicts."""
        return "\n".join(json.dumps(f) for f in findings)

    def test_parse_nuclei_jsonl(self):
        """parse_nuclei_jsonl should extract template-id, matched-at, severity, and info."""
        from strix_mcp.tools_helpers import parse_nuclei_jsonl

        jsonl = self._make_jsonl([
            {
                "template-id": "git-config",
                "matched-at": "https://target.com/.git/config",
                "severity": "medium",
                "info": {"name": "Git Config File", "description": "Exposed git config"},
            },
            {
                "template-id": "exposed-env",
                "matched-at": "https://target.com/.env",
                "severity": "high",
                "info": {"name": "Exposed .env", "description": "Environment file exposed"},
            },
        ])
        findings = parse_nuclei_jsonl(jsonl)
        assert len(findings) == 2
        assert findings[0]["template_id"] == "git-config"
        assert findings[0]["url"] == "https://target.com/.git/config"
        assert findings[0]["severity"] == "medium"
        assert findings[0]["name"] == "Git Config File"

    def test_parse_nuclei_jsonl_skips_bad_lines(self):
        """Malformed JSONL lines should be skipped, not crash."""
        from strix_mcp.tools_helpers import parse_nuclei_jsonl

        jsonl = 'not valid json\n{"template-id": "ok", "matched-at": "https://x.com", "severity": "low", "info": {"name": "OK", "description": "ok"}}\n{broken'
        findings = parse_nuclei_jsonl(jsonl)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "ok"

    def test_parse_nuclei_jsonl_empty(self):
        """Empty JSONL should return empty list."""
        from strix_mcp.tools_helpers import parse_nuclei_jsonl

        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("   \n  ") == []

    def test_build_nuclei_command(self):
        """build_nuclei_command should produce correct CLI command."""
        from strix_mcp.tools_helpers import build_nuclei_command

        cmd = build_nuclei_command(
            target="https://example.com",
            severity="critical,high",
            rate_limit=50,
            templates=["cves", "exposures"],
            output_file="/tmp/results.jsonl",
        )
        assert "nuclei" in cmd
        assert "-u https://example.com" in cmd
        assert "-severity critical,high" in cmd
        assert "-rate-limit 50" in cmd
        assert "-t cves" in cmd
        assert "-t exposures" in cmd
        assert "-jsonl" in cmd
        assert "-o /tmp/results.jsonl" in cmd

    def test_build_nuclei_command_no_templates(self):
        """Without templates, command should not include -t flags."""
        from strix_mcp.tools_helpers import build_nuclei_command

        cmd = build_nuclei_command(
            target="https://example.com",
            severity="critical,high,medium",
            rate_limit=100,
            templates=None,
            output_file="/tmp/results.jsonl",
        )
        assert "-t " not in cmd


class TestSourcemapHelpers:
    def test_extract_script_urls(self):
        """extract_script_urls should find all script src attributes."""
        from strix_mcp.tools_helpers import extract_script_urls

        html = '''<html>
        <script src="/assets/main.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
        <script>inline code</script>
        <script src='/assets/vendor.js'></script>
        </html>'''
        urls = extract_script_urls(html, "https://example.com")
        assert "https://example.com/assets/main.js" in urls
        assert "https://cdn.example.com/lib.js" in urls
        assert "https://example.com/assets/vendor.js" in urls
        assert len(urls) == 3

    def test_extract_script_urls_empty(self):
        """No script tags should return empty list."""
        from strix_mcp.tools_helpers import extract_script_urls

        assert extract_script_urls("<html><body>hi</body></html>", "https://x.com") == []

    def test_extract_sourcemap_url(self):
        """extract_sourcemap_url should find sourceMappingURL comment."""
        from strix_mcp.tools_helpers import extract_sourcemap_url

        js = "var x=1;\n//# sourceMappingURL=main.js.map"
        assert extract_sourcemap_url(js) == "main.js.map"

    def test_extract_sourcemap_url_at_syntax(self):
        """Should also find //@ sourceMappingURL syntax."""
        from strix_mcp.tools_helpers import extract_sourcemap_url

        js = "var x=1;\n//@ sourceMappingURL=old.js.map"
        assert extract_sourcemap_url(js) == "old.js.map"

    def test_extract_sourcemap_url_not_found(self):
        """No sourceMappingURL should return None."""
        from strix_mcp.tools_helpers import extract_sourcemap_url

        assert extract_sourcemap_url("var x=1;") is None

    def test_scan_for_notable_patterns(self):
        """scan_for_notable should find API_KEY and SECRET patterns."""
        from strix_mcp.tools_helpers import scan_for_notable

        sources = {
            "src/config.ts": "const API_KEY = 'abc123';\nconst name = 'test';",
            "src/auth.ts": "const SECRET = 'mysecret';",
            "src/utils.ts": "function add(a, b) { return a + b; }",
        }
        notable = scan_for_notable(sources)
        assert any("config.ts" in n and "API_KEY" in n for n in notable)
        assert any("auth.ts" in n and "SECRET" in n for n in notable)
        assert not any("utils.ts" in n for n in notable)


class TestAnalyzeBundleNewPatterns:
    """Tests for CSPT sinks, postMessage listeners, and internal package detection."""

    def _make_patterns(self):
        """Build the same pattern dict used by analyze_js_bundles."""
        return {
            "api_endpoint": re.compile(
                r'''["']((?:https?://[^"'\s]+)?/(?:api|graphql|v[0-9]+|rest|rpc)[^"'\s]{2,})["']''',
                re.IGNORECASE,
            ),
            "firebase_config": re.compile(
                r'''["']?(apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId|measurementId)["']?\s*[:=]\s*["']([^"']+)["']''',
            ),
            "collection_name": re.compile(
                r'''(?:collection|doc|collectionGroup)\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,50})["']''',
            ),
            "env_var": re.compile(
                r'''(?:process\.env\.|import\.meta\.env\.|NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_)([A-Z_][A-Z0-9_]{2,50})''',
            ),
            "secret_pattern": re.compile(
                r'''["']((?:sk_(?:live|test)_|AIza|ghp_|gho_|glpat-|xox[bpsar]-|AKIA|ya29\.)[A-Za-z0-9_\-]{10,})["']''',
            ),
            "generic_key_assignment": re.compile(
                r'''(?:api_?key|api_?secret|auth_?token|access_?token|private_?key|secret_?key|client_?secret)\s*[:=]\s*["']([^"']{8,})["']''',
                re.IGNORECASE,
            ),
            "oauth_id": re.compile(
                r'''["'](\d{5,}[\-\.][a-z0-9]+\.apps\.googleusercontent\.com)["']|["']([a-f0-9]{32,})["'](?=.*(?:client.?id|oauth))''',
                re.IGNORECASE,
            ),
            "internal_host": re.compile(
                r'''["']((?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.(?:internal|local|corp|private|staging|dev)(?:\.[a-z]+)?)(?::\d+)?(?:/[^"']*)?)["']''',
                re.IGNORECASE,
            ),
            "websocket": re.compile(r'''["'](wss?://[^"'\s]+)["']''', re.IGNORECASE),
            "route_def": re.compile(r'''(?:path|route|to)\s*[:=]\s*["'](/[a-zA-Z0-9/:_\-\[\]{}*]+)["']'''),
        }

    def _make_findings(self):
        """Build an empty findings dict matching analyze_js_bundles."""
        return {
            "framework": None,
            "api_endpoints": [],
            "firebase_config": {},
            "collection_names": [],
            "environment_variables": [],
            "secrets": [],
            "oauth_ids": [],
            "internal_hostnames": [],
            "websocket_urls": [],
            "route_definitions": [],
            "cspt_sinks": [],
            "postmessage_listeners": [],
            "internal_packages": [],
            "interesting_strings": [],
        }

    def _framework_signals(self):
        return {
            "React": [r"__REACT", r"createElement"],
        }

    # --- CSPT sink detection ---

    def test_cspt_sink_fetch_concatenation(self):
        """fetch() with string concatenation should be detected as CSPT sink."""
        findings = self._make_findings()
        content = 'var url = "/api/" + userInput; fetch(url + "/data")'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["cspt_sinks"]) >= 1
        assert any("fetch" in s for s in findings["cspt_sinks"])

    def test_cspt_sink_fetch_template_literal(self):
        """fetch() with template literal interpolation should be detected."""
        findings = self._make_findings()
        content = 'fetch(`/api/${userId}/profile`)'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["cspt_sinks"]) >= 1

    def test_cspt_sink_axios_concatenation(self):
        """axios.get() with string concatenation should be detected."""
        findings = self._make_findings()
        content = 'axios.get("/users/" + id + "/settings")'
        _analyze_bundle(content, "bundle.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["cspt_sinks"]) >= 1
        assert any("axios" in s for s in findings["cspt_sinks"])

    def test_no_cspt_sink_static_fetch(self):
        """fetch() with a static string should NOT be detected as CSPT sink."""
        findings = self._make_findings()
        content = 'fetch("/api/users")'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["cspt_sinks"]) == 0

    # --- postMessage listener detection ---

    def test_postmessage_listener_detected(self):
        """addEventListener("message") should be detected."""
        findings = self._make_findings()
        content = 'window.addEventListener("message", function(e) { console.log(e.data); });'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["postmessage_listeners"]) >= 1

    def test_postmessage_listener_single_quotes(self):
        """addEventListener('message') with single quotes should also be detected."""
        findings = self._make_findings()
        content = "window.addEventListener('message', handler);"
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["postmessage_listeners"]) >= 1

    def test_no_postmessage_for_click(self):
        """addEventListener("click") should NOT be detected as postMessage listener."""
        findings = self._make_findings()
        content = 'window.addEventListener("click", function(e) {});'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["postmessage_listeners"]) == 0

    # --- Internal package detection ---

    def test_internal_package_detected(self):
        """@company/utils should be detected as internal package."""
        findings = self._make_findings()
        content = 'import { helper } from "@company/utils"'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["internal_packages"]) >= 1
        assert "@company/utils" in findings["internal_packages"]

    def test_internal_package_require(self):
        """require("@internal/config") should be detected."""
        findings = self._make_findings()
        content = 'const cfg = require("@internal/config")'
        _analyze_bundle(content, "bundle.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["internal_packages"]) >= 1
        assert "@internal/config" in findings["internal_packages"]

    def test_well_known_scope_not_detected(self):
        """@babel/core and @types/node should NOT be detected as internal packages."""
        findings = self._make_findings()
        content = 'import x from "@babel/core"\nimport y from "@types/node"'
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert len(findings["internal_packages"]) == 0

    def test_mixed_packages(self):
        """Mix of well-known and internal packages: only internal ones detected."""
        findings = self._make_findings()
        content = (
            'import a from "@angular/core"\n'
            'import b from "@mycompany/shared-auth"\n'
            'import c from "@stripe/stripe-js"\n'
            'import d from "@acme/internal-api"\n'
        )
        _analyze_bundle(content, "app.js", self._make_patterns(), self._framework_signals(), findings)
        assert "@mycompany/shared-auth" in findings["internal_packages"]
        assert "@acme/internal-api" in findings["internal_packages"]
        assert len(findings["internal_packages"]) == 2
