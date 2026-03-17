"""Unit tests for MCP tools (no Docker required)."""
import json
from datetime import UTC, datetime
from pathlib import Path

from strix_mcp.sandbox import SandboxManager, ScanState


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


import pytest
from unittest.mock import MagicMock
from fastmcp import FastMCP
from strix_mcp.tools import register_tools


def _tool_text(result) -> str:
    """Extract JSON text from a FastMCP ToolResult."""
    return result.content[0].text


class TestNotesTools:
    """Tests for MCP-side notes storage (no Docker required)."""

    @pytest.fixture
    def mcp_with_notes(self):
        """Create a FastMCP instance with tools registered using a mock sandbox."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    @pytest.mark.asyncio
    async def test_create_note_success(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test Note",
            "content": "Some content",
            "category": "findings",
            "tags": ["xss"],
        })))
        assert result["success"] is True
        assert "note_id" in result

    @pytest.mark.asyncio
    async def test_create_note_empty_title(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "",
            "content": "Some content",
        })))
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_create_note_empty_content(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test",
            "content": "  ",
        })))
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_create_note_invalid_category(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Test",
            "content": "Content",
            "category": "invalid",
        })))
        assert result["success"] is False
        assert "category" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_list_notes_empty(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert result["success"] is True
        assert result["total_count"] == 0
        assert result["notes"] == []

    @pytest.mark.asyncio
    async def test_list_notes_with_filter(self, mcp_with_notes):
        # Create two notes in different categories
        await mcp_with_notes.call_tool("create_note", {
            "title": "Finding 1", "content": "XSS found", "category": "findings",
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "Question 1", "content": "Is this vuln?", "category": "questions",
        })

        # Filter by category
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"category": "findings"})))
        assert result["total_count"] == 1
        assert result["notes"][0]["title"] == "Finding 1"

    @pytest.mark.asyncio
    async def test_list_notes_search(self, mcp_with_notes):
        await mcp_with_notes.call_tool("create_note", {
            "title": "SQL Injection", "content": "Found in login", "category": "findings",
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "XSS", "content": "Found in search", "category": "findings",
        })

        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"search": "login"})))
        assert result["total_count"] == 1

    @pytest.mark.asyncio
    async def test_list_notes_tag_filter(self, mcp_with_notes):
        await mcp_with_notes.call_tool("create_note", {
            "title": "Note 1", "content": "Content", "tags": ["auth", "critical"],
        })
        await mcp_with_notes.call_tool("create_note", {
            "title": "Note 2", "content": "Content", "tags": ["xss"],
        })

        result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {"tags": ["auth"]})))
        assert result["total_count"] == 1
        assert result["notes"][0]["title"] == "Note 1"

    @pytest.mark.asyncio
    async def test_update_note_success(self, mcp_with_notes):
        create_result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "Original", "content": "Original content",
        })))
        note_id = create_result["note_id"]

        update_result = json.loads(_tool_text(await mcp_with_notes.call_tool("update_note", {
            "note_id": note_id, "title": "Updated Title",
        })))
        assert update_result["success"] is True

        # Verify update
        list_result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert list_result["notes"][0]["title"] == "Updated Title"

    @pytest.mark.asyncio
    async def test_update_note_not_found(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("update_note", {
            "note_id": "nonexistent", "title": "New Title",
        })))
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_note_success(self, mcp_with_notes):
        create_result = json.loads(_tool_text(await mcp_with_notes.call_tool("create_note", {
            "title": "To Delete", "content": "Will be deleted",
        })))
        note_id = create_result["note_id"]

        delete_result = json.loads(_tool_text(await mcp_with_notes.call_tool("delete_note", {
            "note_id": note_id,
        })))
        assert delete_result["success"] is True

        # Verify deletion
        list_result = json.loads(_tool_text(await mcp_with_notes.call_tool("list_notes", {})))
        assert list_result["total_count"] == 0

    @pytest.mark.asyncio
    async def test_delete_note_not_found(self, mcp_with_notes):
        result = json.loads(_tool_text(await mcp_with_notes.call_tool("delete_note", {
            "note_id": "nonexistent",
        })))
        assert result["success"] is False
        assert "not found" in result["error"].lower()


class TestProxyToolTracing:
    """Test that proxy_tool logs to the global tracer."""

    @pytest.mark.asyncio
    async def test_proxy_tool_logs_execution_when_tracer_active(self):
        """proxy_tool should call log_tool_execution_start and update_tool_execution."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mgr = SandboxManager()
        mgr._active_scan = ScanState(
            scan_id="test", workspace_id="ws-1",
            api_url="http://localhost:8080", token="tok",
            port=8080, default_agent_id="mcp-test",
        )

        mock_tracer = MagicMock()
        mock_tracer.log_tool_execution_start.return_value = 42

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"output": "hello"}}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.is_closed = False
        mgr._http_client = mock_client

        with patch("strix_mcp.sandbox.get_global_tracer", return_value=mock_tracer):
            result = await mgr.proxy_tool("terminal_execute", {"command": "whoami", "timeout": 10})

        mock_tracer.log_tool_execution_start.assert_called_once_with(
            agent_id="mcp-test",
            tool_name="terminal_execute",
            args={"command": "whoami", "timeout": 10},
        )
        mock_tracer.update_tool_execution.assert_called_once_with(
            42, "completed", {"output": "hello"},
        )

    @pytest.mark.asyncio
    async def test_proxy_tool_works_without_tracer(self):
        """proxy_tool should work normally when no tracer is active."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mgr = SandboxManager()
        mgr._active_scan = ScanState(
            scan_id="test", workspace_id="ws-1",
            api_url="http://localhost:8080", token="tok",
            port=8080, default_agent_id="mcp-test",
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"output": "hello"}}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.is_closed = False
        mgr._http_client = mock_client

        with patch("strix_mcp.sandbox.get_global_tracer", return_value=None):
            result = await mgr.proxy_tool("terminal_execute", {"command": "whoami"})

        assert result == {"output": "hello"}

    @pytest.mark.asyncio
    async def test_proxy_tool_logs_error_status_on_failure(self):
        """proxy_tool should log error status when sandbox returns an error."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mgr = SandboxManager()
        mgr._active_scan = ScanState(
            scan_id="test", workspace_id="ws-1",
            api_url="http://localhost:8080", token="tok",
            port=8080, default_agent_id="mcp-test",
        )

        mock_tracer = MagicMock()
        mock_tracer.log_tool_execution_start.return_value = 7

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": "command not found"}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.is_closed = False
        mgr._http_client = mock_client

        with patch("strix_mcp.sandbox.get_global_tracer", return_value=mock_tracer):
            result = await mgr.proxy_tool("terminal_execute", {"command": "bad"})

        mock_tracer.update_tool_execution.assert_called_once_with(
            7, "error", {"error": "command not found"},
        )

    @pytest.mark.asyncio
    async def test_proxy_tool_tracer_exception_does_not_block(self):
        """If tracer raises, the tool call should still succeed."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mgr = SandboxManager()
        mgr._active_scan = ScanState(
            scan_id="test", workspace_id="ws-1",
            api_url="http://localhost:8080", token="tok",
            port=8080, default_agent_id="mcp-test",
        )

        mock_tracer = MagicMock()
        mock_tracer.log_tool_execution_start.side_effect = RuntimeError("tracer broke")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": {"output": "hello"}}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.is_closed = False
        mgr._http_client = mock_client

        with patch("strix_mcp.sandbox.get_global_tracer", return_value=mock_tracer):
            result = await mgr.proxy_tool("terminal_execute", {"command": "whoami"})

        assert result == {"output": "hello"}


class TestTracerLifecycle:
    """Test that start_scan creates a Tracer and end_scan finalizes it."""

    @pytest.mark.asyncio
    async def test_start_scan_creates_global_tracer(self):
        """start_scan should create a Tracer and set it as global."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None

        mock_scan_state = MagicMock()
        mock_scan_state.scan_id = "test-scan"
        mock_sandbox.start_scan = AsyncMock(return_value=mock_scan_state)
        mock_sandbox.detect_target_stack = AsyncMock(return_value={
            "detected_stack": {"runtime": ["node"]},
            "recommended_plan": [{"task": "test"}],
        })

        register_tools(mcp, mock_sandbox)

        with patch("strix_mcp.tools.set_global_tracer") as mock_set, \
             patch("strix_mcp.tools.Tracer") as MockTracer:
            mock_tracer_instance = MagicMock()
            MockTracer.return_value = mock_tracer_instance

            result = await mcp.call_tool("start_scan", {
                "targets": [{"type": "local_code", "value": "/app", "name": "app"}],
                "scan_id": "test-scan",
            })

            MockTracer.assert_called_once_with(run_name="test-scan")
            mock_set.assert_called_once_with(mock_tracer_instance)
            mock_tracer_instance.set_scan_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_end_scan_finalizes_tracer(self):
        """end_scan should call save_run_data and clear global tracer."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = MagicMock()
        mock_sandbox.active_scan.scan_id = "test-scan"
        mock_sandbox.active_scan.started_at = datetime.now(UTC)
        mock_sandbox.end_scan = AsyncMock()

        register_tools(mcp, mock_sandbox)

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = []

        with patch("strix_mcp.tools.get_global_tracer", return_value=mock_tracer), \
             patch("strix_mcp.tools.set_global_tracer") as mock_set:
            result = await mcp.call_tool("end_scan", {})

            mock_tracer.save_run_data.assert_called_once_with(mark_complete=True)
            mock_set.assert_called_once_with(None)


class TestVulnReportsViaTracer:
    """Test that vulnerability reports use the global tracer as source of truth."""

    @pytest.mark.asyncio
    async def test_create_vulnerability_report_uses_tracer(self):
        """create_vulnerability_report should call tracer.add_vulnerability_report."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = MagicMock()
        register_tools(mcp, mock_sandbox)

        mock_tracer = MagicMock()
        mock_tracer.vulnerability_reports = []
        mock_tracer.get_existing_vulnerabilities.return_value = []
        mock_tracer.add_vulnerability_report.return_value = "vuln-0001"

        with patch("strix_mcp.tools.get_global_tracer", return_value=mock_tracer):
            result = await mcp.call_tool("create_vulnerability_report", {
                "title": "SQL Injection in /api/login",
                "content": "POST param 'user' is injectable",
                "severity": "critical",
            })

        mock_tracer.add_vulnerability_report.assert_called_once()
        call_kwargs = mock_tracer.add_vulnerability_report.call_args
        assert call_kwargs.kwargs["title"] == "SQL Injection in /api/login"
        assert call_kwargs.kwargs["severity"] == "critical"
        # Verify field mapping: content -> description
        assert call_kwargs.kwargs["description"] == "POST param 'user' is injectable"

    @pytest.mark.asyncio
    async def test_list_vulnerability_reports_reads_from_tracer(self):
        """list_vulnerability_reports should read from tracer.get_existing_vulnerabilities."""
        from unittest.mock import MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = MagicMock()
        register_tools(mcp, mock_sandbox)

        mock_tracer = MagicMock()
        mock_tracer.get_existing_vulnerabilities.return_value = [
            {"id": "vuln-0001", "title": "XSS", "severity": "high", "timestamp": "2026-03-14"},
        ]

        with patch("strix_mcp.tools.get_global_tracer", return_value=mock_tracer):
            result = await mcp.call_tool("list_vulnerability_reports", {})

        data = json.loads(result.content[0].text)
        assert data["total"] == 1
        assert data["reports"][0]["title"] == "XSS"

    @pytest.mark.asyncio
    async def test_get_scan_status_reads_from_tracer(self):
        """get_scan_status should read reports from tracer."""
        from unittest.mock import MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = MagicMock()
        mock_sandbox.active_scan.scan_id = "test-scan"
        mock_sandbox.active_scan.started_at = datetime.now(UTC)
        mock_sandbox.active_scan.registered_agents = {"mcp-test": "coordinator"}
        register_tools(mcp, mock_sandbox)

        mock_tracer = MagicMock()
        mock_tracer.get_existing_vulnerabilities.return_value = [
            {"id": "v1", "title": "XSS", "severity": "high"},
        ]
        mock_tracer.get_real_tool_count.return_value = 5

        with patch("strix_mcp.tools.get_global_tracer", return_value=mock_tracer):
            result = await mcp.call_tool("get_scan_status", {})

        data = json.loads(result.content[0].text)
        assert data["total_reports"] == 1
        assert data["tool_executions"] == 5


class TestDispatchAgentTracing:
    """Test that dispatch_agent logs agent creation to the tracer."""

    @pytest.mark.asyncio
    async def test_dispatch_agent_logs_creation(self):
        """dispatch_agent should call tracer.log_agent_creation after registration."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mcp = FastMCP("test")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = MagicMock()
        mock_sandbox.active_scan.default_agent_id = "mcp-test"
        mock_sandbox.register_agent = AsyncMock(return_value="mcp_agent_1")
        register_tools(mcp, mock_sandbox)

        mock_tracer = MagicMock()

        with patch("strix_mcp.tools.get_global_tracer", return_value=mock_tracer):
            result = await mcp.call_tool("dispatch_agent", {
                "task": "Test IDOR on /api/users",
                "modules": ["idor"],
            })

        mock_tracer.log_agent_creation.assert_called_once_with(
            agent_id="mcp_agent_1",
            name="mcp_subagent",
            task="Test IDOR on /api/users",
            parent_id="mcp-test",
        )


class TestReconNoteCategory:
    def test_recon_is_valid_category(self):
        """The 'recon' category should be accepted by the notes system."""
        from strix_mcp.tools import VALID_NOTE_CATEGORIES
        assert "recon" in VALID_NOTE_CATEGORIES


class TestNucleiScan:
    """Tests for the nuclei_scan MCP tool logic."""

    def _make_jsonl(self, findings: list[dict]) -> str:
        """Build JSONL string from a list of finding dicts."""
        return "\n".join(json.dumps(f) for f in findings)

    def test_parse_nuclei_jsonl(self):
        """parse_nuclei_jsonl should extract template-id, matched-at, severity, and info."""
        from strix_mcp.tools import parse_nuclei_jsonl

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
        from strix_mcp.tools import parse_nuclei_jsonl

        jsonl = 'not valid json\n{"template-id": "ok", "matched-at": "https://x.com", "severity": "low", "info": {"name": "OK", "description": "ok"}}\n{broken'
        findings = parse_nuclei_jsonl(jsonl)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "ok"

    def test_parse_nuclei_jsonl_empty(self):
        """Empty JSONL should return empty list."""
        from strix_mcp.tools import parse_nuclei_jsonl

        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("   \n  ") == []

    def test_build_nuclei_command(self):
        """build_nuclei_command should produce correct CLI command."""
        from strix_mcp.tools import build_nuclei_command

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
        from strix_mcp.tools import build_nuclei_command

        cmd = build_nuclei_command(
            target="https://example.com",
            severity="critical,high,medium",
            rate_limit=100,
            templates=None,
            output_file="/tmp/results.jsonl",
        )
        assert "-t " not in cmd
