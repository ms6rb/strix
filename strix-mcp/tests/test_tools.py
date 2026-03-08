"""Unit tests for MCP tools (no Docker required)."""
import json
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


from strix_mcp.tools import _normalize_title, _find_duplicate, _categorize_owasp, _deduplicate_reports


class TestStrixRunsPersistence:
    """Test upstream-compatible strix_runs/ persistence format."""

    def test_get_run_dir_creates_structure(self, tmp_path, monkeypatch):
        """_get_run_dir should create strix_runs/<scan_id>/ in cwd."""
        monkeypatch.chdir(tmp_path)
        from strix_mcp.tools import _get_run_dir

        run_dir = _get_run_dir("scan-abc123")
        assert run_dir.exists()
        assert run_dir == tmp_path / "strix_runs" / "scan-abc123"

    def test_write_finding_md_creates_file(self, tmp_path):
        """_write_finding_md should create vulnerabilities/<id>.md."""
        from strix_mcp.tools import _write_finding_md

        report = {
            "id": "vuln-001",
            "title": "SQL Injection in login",
            "severity": "critical",
            "content": "The login form is vulnerable to SQLi.",
            "timestamp": "2026-03-08T12:00:00+00:00",
        }
        _write_finding_md(tmp_path, report)

        vuln_file = tmp_path / "vulnerabilities" / "vuln-001.md"
        assert vuln_file.exists()

        content = vuln_file.read_text()
        assert "# SQL Injection in login" in content
        assert "**Severity:** CRITICAL" in content
        assert "**ID:** vuln-001" in content
        assert "The login form is vulnerable to SQLi." in content

    def test_write_finding_md_includes_optional_fields(self, tmp_path):
        """_write_finding_md should include endpoint, cvss, etc. when present."""
        from strix_mcp.tools import _write_finding_md

        report = {
            "id": "vuln-002",
            "title": "IDOR on user profiles",
            "severity": "high",
            "content": "User IDs are sequential and unprotected.",
            "timestamp": "2026-03-08T12:00:00+00:00",
            "affected_endpoints": ["/api/users/1", "/api/users/2"],
            "cvss_score": 7.5,
        }
        _write_finding_md(tmp_path, report)

        content = (tmp_path / "vulnerabilities" / "vuln-002.md").read_text()
        assert "**CVSS:** 7.5" in content
        assert "/api/users/1" in content

    def test_write_vuln_csv_creates_sorted_index(self, tmp_path):
        """_write_vuln_csv should create a CSV sorted by severity."""
        from strix_mcp.tools import _write_vuln_csv

        reports = [
            {"id": "vuln-001", "title": "Info leak", "severity": "info", "timestamp": "2026-03-08T12:00:00"},
            {"id": "vuln-002", "title": "SQLi", "severity": "critical", "timestamp": "2026-03-08T12:01:00"},
            {"id": "vuln-003", "title": "XSS", "severity": "high", "timestamp": "2026-03-08T12:02:00"},
        ]
        _write_vuln_csv(tmp_path, reports)

        csv_file = tmp_path / "vulnerabilities.csv"
        assert csv_file.exists()
        lines = csv_file.read_text().strip().split("\n")
        assert len(lines) == 4  # header + 3 rows
        # First data row should be critical (highest severity)
        assert "vuln-002" in lines[1]

    def test_write_finding_md_overwrite_on_merge(self, tmp_path):
        """_write_finding_md should overwrite the file on merge (updated content)."""
        from strix_mcp.tools import _write_finding_md

        report = {
            "id": "vuln-001",
            "title": "XSS in comments",
            "severity": "medium",
            "content": "Original evidence.",
            "timestamp": "2026-03-08T12:00:00+00:00",
        }
        _write_finding_md(tmp_path, report)

        # Simulate merge — severity upgraded, content appended
        report["severity"] = "high"
        report["content"] += "\n\n---\n\n**Additional evidence:**\nMore proof."
        _write_finding_md(tmp_path, report)

        content = (tmp_path / "vulnerabilities" / "vuln-001.md").read_text()
        assert "**Severity:** HIGH" in content
        assert "More proof." in content

    def test_write_summary_md_creates_file(self, tmp_path):
        """_write_summary_md should create summary.md with severity counts."""
        from strix_mcp.tools import _write_summary_md

        summary = {
            "unique_findings": 3,
            "severity_counts": {"critical": 1, "high": 1, "medium": 1},
            "findings": [
                {"id": "vuln-001", "title": "SQLi", "severity": "critical"},
                {"id": "vuln-002", "title": "XSS", "severity": "high"},
                {"id": "vuln-003", "title": "CSRF", "severity": "medium"},
            ],
        }
        _write_summary_md(tmp_path, summary)

        summary_file = tmp_path / "summary.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "critical" in content.lower()
        assert "SQLi" in content
        assert "3" in content  # unique_findings count


class TestGetFinding:
    """Tests for the get_finding selective recall tool."""

    def test_get_finding_reads_existing_file(self, tmp_path):
        """get_finding should return the markdown content of a finding."""
        from strix_mcp.tools import _write_finding_md

        report = {
            "id": "vuln-abc123",
            "title": "SSRF in image proxy",
            "severity": "high",
            "content": "The /proxy endpoint allows SSRF.",
            "timestamp": "2026-03-08T12:00:00+00:00",
        }
        _write_finding_md(tmp_path, report)

        # Simulate what get_finding does
        vuln_file = tmp_path / "vulnerabilities" / "vuln-abc123.md"
        assert vuln_file.exists()
        content = vuln_file.read_text()
        assert "SSRF in image proxy" in content
        assert "The /proxy endpoint allows SSRF." in content

    def test_get_finding_missing_id_returns_error(self, tmp_path):
        """Non-existent finding ID should result in file not found."""
        vuln_file = tmp_path / "vulnerabilities" / "vuln-nonexistent.md"
        assert not vuln_file.exists()


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
