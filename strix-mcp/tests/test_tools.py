"""Unit tests for MCP tools (no Docker required)."""
import json
from datetime import UTC, datetime

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


import pytest
from unittest.mock import MagicMock
from fastmcp import FastMCP
from strix_mcp.tools import register_tools


def _tool_text(result) -> str:
    """Extract JSON text from a FastMCP ToolResult."""
    return result.content[0].text


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
