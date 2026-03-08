"""Unit tests for MCP tools (no Docker required)."""
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from strix_mcp.sandbox import ScanState


class TestScanState:
    def test_started_at_field_exists(self):
        """ScanState should have a started_at datetime field."""
        state = ScanState(
            scan_id="test",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        assert state.started_at is not None
        assert isinstance(state.started_at, datetime)


class TestScanStateAgentNaming:
    def test_registered_agents_is_dict(self):
        """registered_agents should be a dict mapping agent_id -> task_name."""
        state = ScanState(
            scan_id="test",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        assert isinstance(state.registered_agents, dict)

    def test_default_agent_in_registered_agents(self):
        """Default agent should be in registered_agents with empty task name."""
        state = ScanState(
            scan_id="test",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        assert "mcp-test" in state.registered_agents


class TestListModulesTool:
    def test_list_modules_returns_valid_json(self):
        """list_modules should return JSON with module names, categories, descriptions."""
        from strix_mcp.resources import list_modules

        result = json.loads(list_modules())
        assert isinstance(result, dict)
        assert len(result) > 10
        for name, info in result.items():
            assert "category" in info
            assert "description" in info


class TestConcurrentProbing:
    def test_probe_paths_constant_exists(self):
        """PROBE_PATHS should be defined as a module-level constant."""
        from strix_mcp.sandbox import PROBE_PATHS
        assert isinstance(PROBE_PATHS, list)
        assert len(PROBE_PATHS) > 10

    def test_probe_paths_contains_critical_paths(self):
        """PROBE_PATHS should include all key fingerprinting endpoints."""
        from strix_mcp.sandbox import PROBE_PATHS
        critical = ["/graphql", "/.env", "/actuator", "/wp-admin", "/swagger",
                    "/api-docs", "/robots.txt", "/health", "/_next/data"]
        for path in critical:
            assert path in PROBE_PATHS, f"Missing critical probe path: {path}"

    def test_probe_paths_all_start_with_slash(self):
        """Every probe path should be a relative path starting with /."""
        from strix_mcp.sandbox import PROBE_PATHS
        for path in PROBE_PATHS:
            assert path.startswith("/"), f"Probe path missing leading slash: {path}"

    def test_probe_paths_no_duplicates(self):
        """PROBE_PATHS should not contain duplicate entries."""
        from strix_mcp.sandbox import PROBE_PATHS
        assert len(PROBE_PATHS) == len(set(PROBE_PATHS))


from strix_mcp.tools import _normalize_title, _find_duplicate, _categorize_owasp, _deduplicate_reports, _write_scan_meta, _append_finding, _write_report


class TestScanPersistence:
    def test_write_scan_meta_creates_file(self):
        """_write_scan_meta should create scan_meta.json in scan_dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir) / "test-scan"
            _write_scan_meta(scan_dir, "test-scan", [{"type": "web_application", "value": "http://example.com"}], {"runtime": ["node"]})
            meta_path = scan_dir / "scan_meta.json"
            assert meta_path.exists()
            meta = json.loads(meta_path.read_text())
            assert meta["scan_id"] == "test-scan"
            assert meta["targets"][0]["value"] == "http://example.com"
            assert meta["detected_stack"]["runtime"] == ["node"]

    def test_append_finding_creates_jsonl(self):
        """_append_finding should append a report as a JSON line with event type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir)
            report = {"id": "vuln-abc", "title": "XSS", "severity": "high", "content": "found xss"}
            _append_finding(scan_dir, report)
            _append_finding(scan_dir, {"id": "vuln-def", "title": "SQLi", "severity": "critical", "content": "sqli"})
            findings_path = scan_dir / "findings.jsonl"
            assert findings_path.exists()
            lines = findings_path.read_text().strip().splitlines()
            assert len(lines) == 2
            first = json.loads(lines[0])
            assert first["id"] == "vuln-abc"
            assert first["event"] == "new"

    def test_append_finding_merge_event(self):
        """_append_finding with event='merge' should tag the entry accordingly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir)
            report = {"id": "vuln-abc", "title": "XSS", "severity": "high", "content": "merged evidence"}
            _append_finding(scan_dir, report, event="merge")
            line = json.loads((scan_dir / "findings.jsonl").read_text().strip())
            assert line["event"] == "merge"
            assert line["id"] == "vuln-abc"

    def test_write_report_creates_summary(self):
        """_write_report should write the final report.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir)
            summary = {"unique_findings": 2, "severity_counts": {"high": 1, "critical": 1}}
            _write_report(scan_dir, summary)
            report_path = scan_dir / "report.json"
            assert report_path.exists()
            data = json.loads(report_path.read_text())
            assert data["unique_findings"] == 2


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
            {"id": "v1", "title": "Missing CSP", "severity": "medium", "content": "first evidence"},
            {"id": "v2", "title": "missing csp", "severity": "low", "content": "second evidence"},
            {"id": "v3", "title": "SQL Injection", "severity": "high", "content": "sqli proof"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2
        csp = [r for r in unique if "csp" in r["title"].lower()][0]
        assert csp["severity"] == "medium"

    def test_dedup_preserves_unique_reports(self):
        reports = [
            {"id": "v1", "title": "XSS in search", "severity": "high", "content": "xss"},
            {"id": "v2", "title": "IDOR in profile", "severity": "critical", "content": "idor"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2
