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


from strix_mcp.tools_helpers import _normalize_title, _find_duplicate, _categorize_owasp, _deduplicate_reports


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
        from strix_mcp.tools_helpers import VALID_NOTE_CATEGORIES
        assert "recon" in VALID_NOTE_CATEGORIES


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


class TestLoadSkillTool:
    """Tests for the load_skill MCP tool."""

    @pytest.fixture
    def mcp_no_scan(self):
        """MCP with mock sandbox, no active scan."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    @pytest.fixture
    def mcp_with_scan(self):
        """MCP with mock sandbox and an active scan."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        scan = ScanState(
            scan_id="test-scan",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        mock_sandbox.active_scan = scan
        mock_sandbox._active_scan = scan
        register_tools(mcp, mock_sandbox)
        return mcp, scan

    @pytest.mark.asyncio
    async def test_load_single_skill(self, mcp_no_scan):
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "idor",
        })))
        assert result["success"] is True
        assert "idor" in result["loaded_skills"]
        assert "skill_content" in result
        assert "idor" in result["skill_content"]
        assert len(result["skill_content"]["idor"]) > 0

    @pytest.mark.asyncio
    async def test_load_multiple_skills(self, mcp_no_scan):
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "idor,xss,sql_injection",
        })))
        assert result["success"] is True
        assert len(result["loaded_skills"]) == 3
        assert set(result["loaded_skills"]) == {"idor", "xss", "sql_injection"}

    @pytest.mark.asyncio
    async def test_load_empty_input(self, mcp_no_scan):
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "",
        })))
        assert result["success"] is False
        assert "No skills provided" in result["error"]

    @pytest.mark.asyncio
    async def test_load_invalid_skill(self, mcp_no_scan):
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "nonexistent_skill_xyz",
        })))
        assert result["success"] is False
        assert "Invalid skills" in result["error"]

    @pytest.mark.asyncio
    async def test_load_too_many_skills(self, mcp_no_scan):
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "idor,xss,sql_injection,ssrf,csrf,rce",
        })))
        assert result["success"] is False
        assert "more than 5" in result["error"]

    @pytest.mark.asyncio
    async def test_tracks_loaded_skills_in_scan_state(self, mcp_with_scan):
        mcp, scan = mcp_with_scan
        assert scan.loaded_skills == set()

        result = json.loads(_tool_text(await mcp.call_tool("load_skill", {
            "skills": "idor,xss",
        })))
        assert result["success"] is True
        assert scan.loaded_skills == {"idor", "xss"}

        # Load more — should accumulate
        result2 = json.loads(_tool_text(await mcp.call_tool("load_skill", {
            "skills": "sql_injection",
        })))
        assert result2["success"] is True
        assert scan.loaded_skills == {"idor", "xss", "sql_injection"}

    @pytest.mark.asyncio
    async def test_no_scan_still_works(self, mcp_no_scan):
        """load_skill should work even without an active scan."""
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "xss",
        })))
        assert result["success"] is True
        assert "xss" in result["loaded_skills"]

    @pytest.mark.asyncio
    async def test_load_tooling_skill(self, mcp_no_scan):
        """Tooling skills (new upstream) should load correctly."""
        result = json.loads(_tool_text(await mcp_no_scan.call_tool("load_skill", {
            "skills": "nuclei",
        })))
        assert result["success"] is True
        assert "nuclei" in result["loaded_skills"]
        assert len(result["skill_content"]["nuclei"]) > 0


class TestCompareSessions:
    """Tests for the compare_sessions MCP tool."""

    @pytest.fixture
    def mcp_with_proxy(self):
        """MCP with mock sandbox that simulates proxy responses."""
        from unittest.mock import AsyncMock

        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        scan = ScanState(
            scan_id="test-scan",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        mock_sandbox.active_scan = scan
        mock_sandbox._active_scan = scan
        mock_sandbox.proxy_tool = AsyncMock()
        register_tools(mcp, mock_sandbox)
        return mcp, mock_sandbox

    @pytest.mark.asyncio
    async def test_no_active_scan(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "No active scan" in result["error"]

    @pytest.mark.asyncio
    async def test_missing_label(self, mcp_with_proxy):
        mcp, _ = mcp_with_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "label" in result["error"]

    @pytest.mark.asyncio
    async def test_no_captured_requests(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy
        mock_sandbox.proxy_tool.return_value = {"requests": []}
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "No captured requests" in result["error"]

    @pytest.mark.asyncio
    async def test_same_responses(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        # First call: list_requests; subsequent calls: repeat_request
        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": '{"users":[]}'}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert result["total_endpoints"] == 1
        assert result["classification_counts"]["same"] == 1

    @pytest.mark.asyncio
    async def test_divergent_responses(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        repeat_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count, repeat_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/admin/settings"},
                    ]}
                return {"requests": []}
            # First repeat = session A (admin), second = session B (user)
            repeat_count += 1
            if repeat_count % 2 == 1:
                return {"response": {"status_code": 200, "body": '{"settings":"secret"}'}}
            return {"response": {"status_code": 403, "body": "Forbidden"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert result["total_endpoints"] == 1
        assert result["classification_counts"].get("a_only", 0) == 1

    @pytest.mark.asyncio
    async def test_deduplication(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                        {"id": "req2", "method": "GET", "path": "/api/users"},  # duplicate
                        {"id": "req3", "method": "POST", "path": "/api/users"},  # different method
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        # Should have 2 unique endpoints: GET /api/users and POST /api/users
        assert result["total_endpoints"] == 2

    @pytest.mark.asyncio
    async def test_method_filter(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                        {"id": "req2", "method": "DELETE", "path": "/api/users/1"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {}},
            "session_b": {"label": "user", "headers": {}},
            "methods": ["GET"],
        })))
        # Only GET should be included
        assert result["total_endpoints"] == 1
        assert result["results"][0]["method"] == "GET"

    @pytest.mark.asyncio
    async def test_max_requests_cap(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": f"req{i}", "method": "GET", "path": f"/api/endpoint{i}"}
                        for i in range(100)
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "a", "headers": {}},
            "session_b": {"label": "b", "headers": {}},
            "max_requests": 5,
        })))
        assert result["total_endpoints"] == 5

    @pytest.mark.asyncio
    async def test_both_denied(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/secret"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 403, "body": "Forbidden"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "user1", "headers": {}},
            "session_b": {"label": "user2", "headers": {}},
        })))
        assert result["classification_counts"]["both_denied"] == 1


class TestFirebaseAudit:
    """Tests for the firebase_audit MCP tool."""

    @pytest.fixture
    def mcp_firebase(self):
        """MCP with mock sandbox (no active scan needed for firebase_audit)."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, json_data=None, text=""):
        """Create a mock httpx.Response."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text or json.dumps(json_data or {})
        resp.json = MagicMock(return_value=json_data or {})
        return resp

    @pytest.mark.asyncio
    async def test_anonymous_auth_open(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        # Anonymous signup: success
        anon_resp = self._mock_response(200, {
            "idToken": "fake-anon-token",
            "localId": "anon-uid-123",
        })

        # All other requests: 403
        denied_resp = self._mock_response(403, {"error": {"message": "PERMISSION_DENIED"}})

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "accounts:signUp" in url and call_count == 1:
                return anon_resp
            return denied_resp

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["auth"]["anonymous_signup"] == "open"
        assert result["auth"]["anonymous_uid"] == "anon-uid-123"
        assert result["total_issues"] >= 1
        assert any("Anonymous auth" in i for i in result["issues"])

    @pytest.mark.asyncio
    async def test_anonymous_auth_blocked(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        blocked_resp = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        denied_resp = self._mock_response(403)

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(return_value=blocked_resp)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["auth"]["anonymous_signup"] == "blocked"

    @pytest.mark.asyncio
    async def test_firestore_readable_collection(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        list_resp = self._mock_response(200, {"documents": [
            {"name": "projects/test/databases/(default)/documents/users/doc1"},
        ]})

        async def mock_get(url, **kwargs):
            if "/documents/users?" in url:
                return list_resp
            return denied_resp

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        matrix = result["firestore"]["acl_matrix"]
        assert "users" in matrix
        assert "allowed" in matrix["users"]["unauthenticated"]["list"]

    @pytest.mark.asyncio
    async def test_all_denied_collections_filtered(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        not_found_resp = self._mock_response(404)
        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})

        async def mock_post(url, **kwargs):
            if "accounts:signUp" in url:
                return anon_denied
            return not_found_resp

        mock_client.get = AsyncMock(return_value=not_found_resp)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.delete = AsyncMock(return_value=not_found_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["nonexistent_collection"],
                "test_signup": False,
            })))

        assert result["firestore"]["active_collections"] == 0

    @pytest.mark.asyncio
    async def test_storage_listable(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        denied_resp = self._mock_response(403)
        storage_resp = self._mock_response(200, {
            "items": [{"name": "uploads/file1.pdf"}, {"name": "uploads/file2.jpg"}],
        })

        async def mock_get(url, **kwargs):
            if "storage.googleapis.com" in url:
                return storage_resp
            return denied_resp

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["storage"]["list_unauthenticated"]["status"] == "listable"
        assert any("Storage bucket" in i for i in result["issues"])

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert "project_id" in result
        assert "auth" in result
        assert "realtime_db" in result
        assert "firestore" in result
        assert "storage" in result
        assert "issues" in result
        assert isinstance(result["issues"], list)


class TestAnalyzeJsBundles:
    """Tests for the analyze_js_bundles MCP tool."""

    @pytest.fixture
    def mcp_js(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    @pytest.mark.asyncio
    async def test_extracts_api_endpoints(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const url = "/api/v1/users";
        fetch("/api/graphql/query");
        const other = "/static/image.png";
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["bundles_analyzed"] >= 1
        assert any("/api/v1/users" in ep for ep in result["api_endpoints"])
        assert any("graphql" in ep for ep in result["api_endpoints"])
        # Static assets should be filtered out
        assert not any("image.png" in ep for ep in result["api_endpoints"])

    @pytest.mark.asyncio
    async def test_extracts_firebase_config(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const firebaseConfig = {
            apiKey: "AIzaSyTest1234567890",
            authDomain: "myapp.firebaseapp.com",
            projectId: "myapp-12345",
            storageBucket: "myapp-12345.appspot.com",
        };
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["firebase_config"].get("projectId") == "myapp-12345"
        assert result["firebase_config"].get("apiKey") == "AIzaSyTest1234567890"

    @pytest.mark.asyncio
    async def test_detects_framework(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script id="__NEXT_DATA__"></script><script src="/app.js"></script></html>'
        js_content = 'var x = "__NEXT_DATA__"; function getServerSideProps() {}'

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["framework"] == "Next.js"

    @pytest.mark.asyncio
    async def test_extracts_collection_names(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        db.collection("users").get();
        db.doc("orders/123");
        db.collectionGroup("comments").where("author", "==", uid);
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert "users" in result["collection_names"]
        assert "comments" in result["collection_names"]

    @pytest.mark.asyncio
    async def test_extracts_internal_hosts(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const internalApi = "https://10.0.1.50:8080/api";
        const staging = "https://api.staging.corp/v1";
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert any("10.0.1.50" in h for h in result["internal_hostnames"])

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, "<html></html>"))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        for key in [
            "target_url", "bundles_analyzed", "framework", "api_endpoints",
            "firebase_config", "collection_names", "environment_variables",
            "secrets", "oauth_ids", "internal_hostnames", "websocket_urls",
            "route_definitions", "total_findings",
        ]:
            assert key in result


class TestDiscoverApi:
    """Tests for the discover_api MCP tool."""

    @pytest.fixture
    def mcp_api(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.json = MagicMock(return_value=json.loads(text) if text and text.strip().startswith(("{", "[")) else {})
        return resp

    @pytest.mark.asyncio
    async def test_graphql_introspection_detected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        graphql_resp = self._mock_response(200, json.dumps({
            "data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}
        }))
        default_resp = self._mock_response(404, "Not Found")

        async def mock_post(url, **kwargs):
            if "/graphql" in url and "application/json" in kwargs.get("headers", {}).get("Content-Type", ""):
                return graphql_resp
            return default_resp

        async def mock_get(url, **kwargs):
            return default_resp

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["graphql"] is not None
        assert result["graphql"]["introspection"] == "enabled"
        assert "Query" in result["graphql"]["types"]
        assert result["summary"]["has_graphql"] is True

    @pytest.mark.asyncio
    async def test_openapi_spec_discovered(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/users/{id}": {"get": {}, "delete": {}},
            },
        }
        spec_resp = self._mock_response(200, json.dumps(spec))
        default_resp = self._mock_response(404, "Not Found")

        async def mock_get(url, **kwargs):
            if "/openapi.json" in url:
                return spec_resp
            return default_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["openapi_spec"] is not None
        assert result["openapi_spec"]["title"] == "Test API"
        assert result["openapi_spec"]["endpoint_count"] == 4
        assert result["summary"]["has_openapi_spec"] is True

    @pytest.mark.asyncio
    async def test_grpc_web_detected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        grpc_resp = self._mock_response(200, "", headers={
            "content-type": "application/grpc-web+proto",
            "grpc-status": "12",
        })
        default_resp = self._mock_response(404, "Not Found")

        async def mock_post(url, **kwargs):
            ct = kwargs.get("headers", {}).get("Content-Type", "")
            if "grpc" in ct:
                return grpc_resp
            return default_resp

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.get = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["grpc_web"] is not None
        assert result["summary"]["has_grpc_web"] is True

    @pytest.mark.asyncio
    async def test_responsive_paths_collected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        ok_resp = self._mock_response(200, '{"status":"ok"}', {"content-type": "application/json"})
        not_found = self._mock_response(404, "Not Found")

        async def mock_get(url, **kwargs):
            if "/api/v1" in url or "/health" in url:
                return ok_resp
            return not_found

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=not_found)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        paths = [p["path"] for p in result["responsive_paths"]]
        assert "/api/v1" in paths
        assert "/health" in paths

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        default_resp = self._mock_response(404, "Not Found")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=default_resp)
        mock_client.post = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        for key in ["target_url", "graphql", "grpc_web", "openapi_spec",
                     "responsive_paths", "content_type_probes", "summary"]:
            assert key in result
        assert "has_graphql" in result["summary"]
        assert "has_grpc_web" in result["summary"]
        assert "has_openapi_spec" in result["summary"]


class TestDiscoverServices:
    """Tests for the discover_services MCP tool."""

    @pytest.fixture
    def mcp_svc(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.json = MagicMock(return_value=json.loads(text) if text and text.strip().startswith(("{", "[")) else {})
        return resp

    @pytest.mark.asyncio
    async def test_detects_firebase(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        const config = {
            authDomain: "myapp.firebaseapp.com",
            projectId: "myapp-12345"
        };
        </script></html>'''

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "firebase" in result["discovered_services"]
        assert "myapp" in result["discovered_services"]["firebase"][0]

    @pytest.mark.asyncio
    async def test_detects_sanity_and_probes(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        const client = createClient({projectId: "e5fj2khm", dataset: "production"});
        </script></html>'''

        sanity_resp = self._mock_response(200, json.dumps({
            "result": [
                {"_type": "article", "_id": "abc123"},
                {"_type": "skill", "_id": "def456"},
            ]
        }))
        page_resp = self._mock_response(200, html)
        not_found = self._mock_response(404)

        async def mock_get(url, **kwargs):
            if "sanity.io" in url:
                return sanity_resp
            if "example.com" == url.split("/")[2] or "example.com/" in url:
                return page_resp
            return not_found

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "sanity" in result["discovered_services"]
        assert "e5fj2khm" in result["discovered_services"]["sanity"]
        assert "sanity_e5fj2khm" in result["probes"]
        assert result["probes"]["sanity_e5fj2khm"]["status"] == "accessible"
        assert "article" in result["probes"]["sanity_e5fj2khm"]["document_types"]

    @pytest.mark.asyncio
    async def test_detects_stripe_key(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        Stripe("pk_live_51HG1234567890abcdefghijklmnop");
        </script></html>'''

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "stripe" in result["discovered_services"]
        probes = result["probes"]
        stripe_probe = [v for k, v in probes.items() if "stripe" in k]
        assert len(stripe_probe) >= 1
        assert stripe_probe[0]["key_type"] == "live"

    @pytest.mark.asyncio
    async def test_detects_google_analytics(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '<html><script>gtag("config", "G-ABC1234567");</script></html>'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "google_analytics" in result["discovered_services"]
        assert "G-ABC1234567" in result["discovered_services"]["google_analytics"]

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, "<html></html>"))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        for key in ["target_url", "discovered_services", "dns_txt_records",
                     "probes", "total_services", "total_probes"]:
            assert key in result


class TestScanStateLoadedSkills:
    """Tests for the loaded_skills field on ScanState."""

    def test_loaded_skills_default_empty(self):
        state = ScanState(
            scan_id="test",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        assert state.loaded_skills == set()
        assert isinstance(state.loaded_skills, set)
