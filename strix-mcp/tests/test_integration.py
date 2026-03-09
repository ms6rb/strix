"""Integration tests: full scan lifecycle with live Docker sandbox.

Requires:
  - Docker running
  - strix-sandbox image pulled: docker pull ghcr.io/usestrix/strix-sandbox:0.1.12
  - (Optional) Vulnerable app: cd tests && docker compose -f docker-compose.test.yml up -d

Run with: cd strix-mcp && python -m pytest tests/test_integration.py -v -s -o "addopts="
"""
import json

import pytest

from strix_mcp.sandbox import SandboxManager


@pytest.fixture
async def sandbox():
    mgr = SandboxManager()
    yield mgr
    # Cleanup: end scan if still active
    if mgr.active_scan is not None:
        await mgr.end_scan()


# --- Lifecycle Tests ---


@pytest.mark.asyncio
async def test_full_lifecycle(sandbox: SandboxManager):
    """Start scan -> execute tools -> end scan."""
    state = await sandbox.start_scan(targets=[], scan_id="test-lifecycle")
    assert state.scan_id == "test-lifecycle"
    assert state.api_url.startswith("http://")
    assert state.token != ""

    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "whoami",
        "timeout": 10,
    })
    assert "pentester" in str(result).lower()

    await sandbox.end_scan()
    assert sandbox.active_scan is None


@pytest.mark.asyncio
async def test_cannot_start_two_scans(sandbox: SandboxManager):
    """Only one scan at a time."""
    await sandbox.start_scan(targets=[], scan_id="test-1")
    with pytest.raises(RuntimeError, match="already active"):
        await sandbox.start_scan(targets=[], scan_id="test-2")


@pytest.mark.asyncio
async def test_proxy_error_without_scan(sandbox: SandboxManager):
    """Proxy tools fail gracefully without active scan."""
    result = await sandbox.proxy_tool("terminal_execute", {"command": "ls"})
    assert "error" in result
    assert "No active scan" in result["error"]


# --- Agent Registration ---


@pytest.mark.asyncio
async def test_register_and_use_agent(sandbox: SandboxManager):
    """Register a subagent and execute as that agent."""
    await sandbox.start_scan(targets=[], scan_id="test-agents")

    agent_id = await sandbox.register_agent(task_name="test task")
    assert agent_id == "mcp_agent_1"
    assert sandbox.active_scan.registered_agents[agent_id] == "test task"

    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "echo hello",
        "timeout": 10,
        "agent_id": agent_id,
    })
    assert "hello" in str(result)


# --- Terminal ---


@pytest.mark.asyncio
async def test_terminal_execute(sandbox: SandboxManager):
    """Execute shell commands in the sandbox."""
    await sandbox.start_scan(targets=[], scan_id="test-terminal")

    # Basic command
    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "echo 'test output'",
        "timeout": 10,
    })
    assert "test output" in str(result)

    # Command with exit code
    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "ls /workspace",
        "timeout": 10,
    })
    assert not result.get("error")


# --- File Operations ---


@pytest.mark.asyncio
async def test_file_operations(sandbox: SandboxManager):
    """Create, view, edit, and list files in sandbox."""
    await sandbox.start_scan(targets=[], scan_id="test-files")

    # Create a file
    result = await sandbox.proxy_tool("str_replace_editor", {
        "command": "create",
        "path": "/workspace/test.txt",
        "file_text": "line 1\nline 2\nline 3\n",
    })
    assert not result.get("error")

    # View the file
    result = await sandbox.proxy_tool("str_replace_editor", {
        "command": "view",
        "path": "/workspace/test.txt",
    })
    assert "line 1" in str(result)

    # Edit the file
    result = await sandbox.proxy_tool("str_replace_editor", {
        "command": "str_replace",
        "path": "/workspace/test.txt",
        "old_str": "line 2",
        "new_str": "modified line 2",
    })
    assert not result.get("error")

    # Insert a line
    result = await sandbox.proxy_tool("str_replace_editor", {
        "command": "insert",
        "path": "/workspace/test.txt",
        "insert_line": 1,
        "new_str": "inserted after line 1",
    })
    assert not result.get("error")

    # List files
    result = await sandbox.proxy_tool("list_files", {
        "directory_path": "/workspace",
    })
    assert "test.txt" in str(result)

    # Search files
    result = await sandbox.proxy_tool("search_files", {
        "directory_path": "/workspace",
        "search_pattern": "modified",
    })
    assert "modified" in str(result) or "test.txt" in str(result)


# --- HTTP Proxy ---


@pytest.mark.asyncio
async def test_http_requests(sandbox: SandboxManager):
    """Send HTTP requests through the sandbox proxy.

    Requires: vulnerable app running on host port 5000.
    """
    await sandbox.start_scan(targets=[], scan_id="test-http")

    # Try common Docker host addresses
    target_url = None
    for host in ["host.docker.internal", "172.17.0.1"]:
        result = await sandbox.proxy_tool("send_request", {
            "method": "GET",
            "url": f"http://{host}:5000/",
            "timeout": 5,
        })
        if not result.get("error"):
            target_url = f"http://{host}:5000"
            break

    if target_url is None:
        pytest.skip("Vulnerable app not reachable from sandbox")

    # Verify response
    resp = result.get("response", {})
    assert resp.get("status_code") == 200
    assert "Vulnerable" in resp.get("body", "")

    # List captured requests
    result = await sandbox.proxy_tool("list_requests", {})
    assert not result.get("error")


# --- Python Action ---


@pytest.mark.asyncio
async def test_python_action(sandbox: SandboxManager):
    """Run Python code in the sandbox interpreter."""
    await sandbox.start_scan(targets=[], scan_id="test-python")

    # Create a session first
    session_result = await sandbox.proxy_tool("python_action", {
        "action": "new_session",
    })
    session_id = None
    if isinstance(session_result, dict):
        session_id = session_result.get("session_id")

    # Execute code
    kwargs = {"action": "execute", "code": "print(2 + 2)"}
    if session_id:
        kwargs["session_id"] = session_id
    result = await sandbox.proxy_tool("python_action", kwargs)
    assert "4" in str(result)


# --- Scope Rules ---


@pytest.mark.asyncio
async def test_scope_rules(sandbox: SandboxManager):
    """Manage proxy scope filtering."""
    await sandbox.start_scan(targets=[], scan_id="test-scope")

    result = await sandbox.proxy_tool("scope_rules", {
        "action": "list",
    })
    assert not result.get("error")
