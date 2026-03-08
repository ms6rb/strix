"""Integration test: start scan -> terminal_execute -> end scan.
Requires Docker running and strix-sandbox image pulled.
Run with: pytest tests/test_integration.py -v -s
"""
import json

import pytest

from strix_mcp.sandbox import SandboxManager


@pytest.fixture
async def sandbox():
    mgr = SandboxManager()
    yield mgr
    await mgr.end_scan()


@pytest.mark.asyncio
async def test_full_lifecycle(sandbox: SandboxManager):
    # Start scan
    state = await sandbox.start_scan(targets=[], scan_id="test-integration")
    assert state.scan_id == "test-integration"
    assert state.api_url.startswith("http://")
    assert state.token != ""

    # Execute a command
    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "whoami",
        "timeout": 10,
    })
    assert "pentester" in str(result)

    # Register a second agent
    agent_id = await sandbox.register_agent()
    assert agent_id == "mcp_agent_1"

    # Execute as second agent
    result = await sandbox.proxy_tool("terminal_execute", {
        "command": "echo hello",
        "timeout": 10,
        "agent_id": agent_id,
    })
    assert "hello" in str(result)

    # End scan
    await sandbox.end_scan()
    assert sandbox.active_scan is None


@pytest.mark.asyncio
async def test_cannot_start_two_scans(sandbox: SandboxManager):
    await sandbox.start_scan(targets=[], scan_id="test-1")
    with pytest.raises(RuntimeError, match="already active"):
        await sandbox.start_scan(targets=[], scan_id="test-2")


@pytest.mark.asyncio
async def test_proxy_error_without_scan(sandbox: SandboxManager):
    result = await sandbox.proxy_tool("terminal_execute", {"command": "ls"})
    assert "error" in result
    assert "No active scan" in result["error"]
