# Telemetry Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace MCP's in-memory finding storage and custom file writers with the upstream `strix.telemetry.tracer.Tracer`, adding full event logging for agents and tool executions.

**Architecture:** The MCP's `start_scan` creates a `Tracer` and sets it as the global singleton via `set_global_tracer()`. All tools access it via `get_global_tracer()`, matching the upstream pattern exactly. The Tracer becomes the single source of truth for findings and scan output files. MCP keeps its title-normalization dedup and chain detection as MCP-only features.

**Tech Stack:** Python 3.12, FastMCP, strix.telemetry.tracer (via strix-agent dependency)

**Test command:** `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`

**Field name mapping (MCP → upstream Tracer):**
- `content` → `description` (finding body text)
- `affected_endpoint` / `affected_endpoints` → `endpoint` (singular string in Tracer)
- `cvss_score` → `cvss` (float)

These differences affect dedup merge logic, `_deduplicate_reports`, `end_scan` summary, and `list_vulnerability_reports`.

---

### Task 1: Add Tracer to proxy_tool for tool execution logging

The simplest, most isolated change — instrument `SandboxManager.proxy_tool()` so every proxied tool call is logged.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/sandbox.py:198-232`
- Test: `strix-mcp/tests/test_tools.py`

**Step 1: Write the failing test**

Add to `strix-mcp/tests/test_tools.py`:

```python
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
```

**Step 2: Run test to verify it fails**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestProxyToolTracing -v --tb=short -o "addopts="`
Expected: FAIL — `get_global_tracer` not imported in sandbox.py

**Step 3: Implement proxy_tool tracing**

Modify `strix-mcp/src/strix_mcp/sandbox.py`. Add import at top:

```python
from strix.telemetry.tracer import get_global_tracer
```

Replace `proxy_tool` method (lines 198-232):

```python
    async def proxy_tool(
        self, tool_name: str, kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        scan = self._active_scan
        if scan is None:
            return {"error": "No active scan. Call start_scan first."}

        agent_id = kwargs.pop("agent_id", scan.default_agent_id)

        # Log tool execution start
        tracer = get_global_tracer()
        execution_id = None
        if tracer:
            try:
                execution_id = tracer.log_tool_execution_start(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    args=kwargs,
                )
            except Exception:
                execution_id = None

        client = self._ensure_http_client()

        try:
            response = await client.post(
                f"{scan.api_url}/execute",
                json={
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "kwargs": kwargs,
                },
                headers={"Authorization": f"Bearer {scan.token}"},
                timeout=300,
            )
            if response.status_code >= 400:
                result = {"error": f"Sandbox request failed (HTTP {response.status_code}): {response.text[:200]}"}
            else:
                try:
                    data = response.json()
                except Exception:
                    result = {"error": f"Sandbox returned non-JSON response (HTTP {response.status_code}): {response.text[:200]}"}
                    data = None

                if data is not None:
                    if data.get("error"):
                        result = {"error": data["error"]}
                    else:
                        result = data.get("result", data)
        except httpx.ConnectError as e:
            result = {"error": f"Sandbox connection failed: {e}"}
        except httpx.TimeoutException as e:
            result = {"error": f"Sandbox request timed out: {e}"}

        # Log tool execution completion
        if tracer and execution_id is not None:
            try:
                status = "error" if isinstance(result, dict) and result.get("error") else "completed"
                tracer.update_tool_execution(execution_id, status, result)
            except Exception:
                pass

        return result
```

**Step 4: Run test to verify it passes**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestProxyToolTracing -v --tb=short -o "addopts="`
Expected: PASS (all 4 tests)

**Step 5: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All existing tests still pass

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/sandbox.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add tracer logging to proxy_tool"
```

---

### Task 2: Wire Tracer into start_scan and end_scan

Create the Tracer in `start_scan`, finalize it in `end_scan`. Remove `scan_dir` closure variable and `_get_run_dir` function.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:156-166` (remove `_get_run_dir`)
- Modify: `strix-mcp/src/strix_mcp/tools.py:250-254` (remove `scan_dir` and `vulnerability_reports` closure vars)
- Modify: `strix-mcp/src/strix_mcp/tools.py:258-340` (`start_scan`)
- Modify: `strix-mcp/src/strix_mcp/tools.py:342-402` (`end_scan`)
- Test: `strix-mcp/tests/test_tools.py`

**Step 1: Write the failing tests**

Add to `strix-mcp/tests/test_tools.py`:

```python
class TestTracerLifecycle:
    """Test that start_scan creates a Tracer and end_scan finalizes it."""

    @pytest.mark.asyncio
    async def test_start_scan_creates_global_tracer(self):
        """start_scan should create a Tracer and set it as global."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastmcp import FastMCP

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
        from fastmcp import FastMCP

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
```

**Step 2: Run test to verify it fails**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestTracerLifecycle -v --tb=short -o "addopts="`
Expected: FAIL — `Tracer` and `set_global_tracer` not imported in tools.py

**Step 3: Implement start_scan / end_scan tracer lifecycle**

In `strix-mcp/src/strix_mcp/tools.py`, add imports at top (after existing imports):

```python
import logging

from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer

logger = logging.getLogger(__name__)
```

This follows the same top-level import pattern used in `sandbox.py`. All local `from strix.telemetry.tracer import ...` statements inside function bodies are unnecessary after this.

Remove these functions entirely (lines 156-247):
- `_get_run_dir` (lines 156-166)
- `_write_finding_md` (lines 169-195)
- `_write_vuln_csv` (lines 198-219)
- `_write_summary_md` (lines 222-247)

In `register_tools()`, remove closure variables `vulnerability_reports` and `scan_dir` (lines 251-252). Keep `fired_chains` and `notes_storage`.

Replace `start_scan` tool body — after creating the scan via `sandbox.start_scan()` and running stack detection, replace the tracer/dir setup:

```python
        # Initialize tracer (upstream pattern: entrypoint creates + sets global)
        try:
            tracer = Tracer(run_name=sid)
            set_global_tracer(tracer)
            tracer.set_scan_config({"targets": targets})
        except Exception:
            logger.warning("Failed to initialize tracer, continuing without telemetry")

        fired_chains.clear()
        notes_storage.clear()
```

Replace `end_scan` tool body:

```python
        tracer = get_global_tracer()
        reports = tracer.vulnerability_reports if tracer else []
        unique = _deduplicate_reports(reports)
        total_filed = len(reports)
        duplicates_merged = total_filed - len(unique)

        severity_counts: dict[str, int] = {}
        for r in unique:
            sev = r.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        findings_by_category: dict[str, list[dict[str, str]]] = {}
        for r in unique:
            category = _categorize_owasp(r["title"])
            if category not in findings_by_category:
                findings_by_category[category] = []
            entry: dict[str, Any] = {
                "id": r["id"],
                "title": r["title"],
                "severity": r.get("severity", "info"),
            }
            # Tracer stores "endpoint" (string); check both for robustness
            endpoint = r.get("endpoint") or r.get("affected_endpoint")
            if endpoint:
                entry["endpoint"] = endpoint
            cvss = r.get("cvss") or r.get("cvss_score")
            if cvss is not None:
                entry["cvss_score"] = cvss
            findings_by_category[category].append(entry)

        summary = {
            "status": "stopped",
            "message": "Sandbox destroyed. Scan ended.",
            "unique_findings": len(unique),
            "total_reports_filed": total_filed,
            "duplicates_merged": duplicates_merged,
            "severity_counts": severity_counts,
            "findings_by_category": findings_by_category,
            "findings": [
                {"id": r["id"], "title": r["title"], "severity": r.get("severity", "info")}
                for r in unique
            ],
        }

        # Finalize tracer — writes markdown, CSV, JSONL events
        if tracer:
            try:
                tracer.save_run_data(mark_complete=True)
            except Exception:
                logger.warning("Failed to save tracer run data")
            # Clear global tracer (runtime-safe, type annotation is non-optional
            # but upstream pattern uses None to reset)
            set_global_tracer(None)  # type: ignore[arg-type]

        await sandbox.end_scan()
        fired_chains.clear()
        notes_storage.clear()

        return json.dumps(summary)
```

**Step 4: Run test to verify it passes**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestTracerLifecycle -v --tb=short -o "addopts="`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: Some tests in `TestStrixRunsPersistence` will now fail because `_get_run_dir`, `_write_finding_md`, `_write_vuln_csv`, `_write_summary_md` are removed. These tests will be updated in Task 4.

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): wire Tracer into start_scan and end_scan lifecycle"
```

---

### Task 3: Migrate vulnerability reports to Tracer

Replace the MCP's `vulnerability_reports` closure list with `tracer.vulnerability_reports`. Update `create_vulnerability_report`, `list_vulnerability_reports`, `get_finding`, `suggest_chains`, and `get_scan_status`.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:440-651` (finding tools + suggest_chains + get_scan_status)
- Test: `strix-mcp/tests/test_tools.py`

**Step 1: Write the failing test**

Add to `strix-mcp/tests/test_tools.py`:

```python
class TestVulnReportsViaTracer:
    """Test that vulnerability reports use the global tracer as source of truth."""

    @pytest.mark.asyncio
    async def test_create_vulnerability_report_uses_tracer(self):
        """create_vulnerability_report should call tracer.add_vulnerability_report."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastmcp import FastMCP

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

    @pytest.mark.asyncio
    async def test_list_vulnerability_reports_reads_from_tracer(self):
        """list_vulnerability_reports should read from tracer.get_existing_vulnerabilities."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastmcp import FastMCP

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

        data = json.loads(result[0].text)
        assert data["total"] == 1
        assert data["reports"][0]["title"] == "XSS"
```

**Step 2: Run test to verify it fails**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestVulnReportsViaTracer -v --tb=short -o "addopts="`
Expected: FAIL

**Step 3: Implement vulnerability report migration**

In `create_vulnerability_report`, replace the body:

```python
    @mcp.tool()
    async def create_vulnerability_report(
        title: str,
        content: str,
        severity: str,
        affected_endpoint: str | None = None,
        cvss_score: float | None = None,
    ) -> str:
        """File a confirmed vulnerability finding. ...(keep existing docstring)..."""
        severity = _normalize_severity(severity)
        tracer = get_global_tracer()
        existing = tracer.get_existing_vulnerabilities() if tracer else []

        # MCP dedup check (title normalization)
        normalized = _normalize_title(title)
        dup_idx = _find_duplicate(normalized, existing)

        if dup_idx is not None:
            # existing[dup_idx] is a shared reference to the dict in
            # tracer.vulnerability_reports, so mutations apply in-place.
            report = existing[dup_idx]
            if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(
                _normalize_severity(report.get("severity", "info"))
            ):
                report["severity"] = severity
            # Tracer stores body text as "description", not "content"
            desc = report.get("description", "")
            report["description"] = desc + f"\n\n---\n\n**Additional evidence:**\n{content}"
            # Tracer stores "endpoint" as a string; for merges we accumulate
            # a list under a separate key to track multiple endpoints
            if affected_endpoint:
                existing_endpoint = report.get("endpoint", "")
                if existing_endpoint and existing_endpoint != affected_endpoint:
                    # Store as comma-separated in the endpoint field
                    if affected_endpoint not in existing_endpoint:
                        report["endpoint"] = f"{existing_endpoint}, {affected_endpoint}"
                elif not existing_endpoint:
                    report["endpoint"] = affected_endpoint
            if cvss_score is not None and (report.get("cvss") is None or cvss_score > report["cvss"]):
                report["cvss"] = cvss_score

            # Write updated finding to disk (Tracer only auto-writes on add, not on merge)
            if tracer:
                try:
                    tracer.save_run_data()
                except Exception:
                    pass

            # Detect chains after merge
            from .chaining import detect_chains
            new_chains = detect_chains(existing, fired=fired_chains)

            result: dict[str, Any] = {
                "report_id": report["id"],
                "title": report["title"],
                "severity": report.get("severity", "info"),
                "merged": True,
            }
            if new_chains:
                result["chains_detected"] = new_chains
            return json.dumps(result)

        # New finding — delegate to Tracer
        if tracer:
            report_id = tracer.add_vulnerability_report(
                title=title,
                severity=severity,
                description=content,
                endpoint=affected_endpoint,
                cvss=cvss_score,
            )
        else:
            report_id = f"vuln-{uuid.uuid4().hex[:8]}"

        # Detect chains after new finding
        from .chaining import detect_chains
        all_reports = tracer.get_existing_vulnerabilities() if tracer else []
        new_chains = detect_chains(all_reports, fired=fired_chains)

        result: dict[str, Any] = {
            "report_id": report_id,
            "title": title,
            "severity": severity,
            "merged": False,
        }
        if new_chains:
            result["chains_detected"] = new_chains
        return json.dumps(result)
```

In `list_vulnerability_reports`, replace the body:

```python
    @mcp.tool()
    async def list_vulnerability_reports(severity: str | None = None) -> str:
        """...(keep existing docstring)..."""
        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        if severity:
            filtered = [r for r in reports if _normalize_severity(r.get("severity", "info")) == _normalize_severity(severity)]
        else:
            filtered = list(reports)

        return json.dumps({
            "reports": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "severity": r.get("severity", "info"),
                    # Tracer stores "endpoint" (string), not "affected_endpoints" (list)
                    **({"endpoint": r["endpoint"]} if "endpoint" in r else {}),
                    **({"cvss_score": r["cvss"]} if "cvss" in r else {}),
                }
                for r in filtered
            ],
            "total": len(filtered),
        })
```

In `get_finding`, replace the body:

```python
    @mcp.tool()
    async def get_finding(finding_id: str) -> str:
        """...(keep existing docstring)..."""
        tracer = get_global_tracer()
        if tracer is None:
            return json.dumps({"error": "No active scan."})

        safe_id = Path(finding_id).name
        vuln_file = tracer.get_run_dir() / "vulnerabilities" / f"{safe_id}.md"
        if not vuln_file.exists():
            return json.dumps({"error": f"Finding '{finding_id}' not found."})

        return vuln_file.read_text()
```

In `get_scan_status`, replace `vulnerability_reports` references:

```python
        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        severity_counts: dict[str, int] = {}
        for r in reports:
            sev = r.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count chains detected but not yet dispatched
        from .chaining import detect_chains
        all_possible = detect_chains(reports, fired=set())
        pending_chains = [c for c in all_possible if c["chain_name"] not in fired_chains]
```

And enrich with tracer data:

```python
        result = {
            "scan_id": scan.scan_id,
            "status": "running",
            "elapsed_seconds": round(elapsed),
            "agents_registered": len(scan.registered_agents),
            "agents": [
                {"id": aid, "task": name}
                for aid, name in scan.registered_agents.items()
            ],
            "total_reports": len(reports),
            "severity_counts": severity_counts,
            "pending_chains": len(pending_chains),
        }

        if tracer:
            result["tool_executions"] = tracer.get_real_tool_count()

        return json.dumps(result)
```

In `suggest_chains`, replace `vulnerability_reports` reference:

```python
        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        all_chains = detect_chains(reports, fired=set())
```

**Step 4: Run test to verify it passes**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestVulnReportsViaTracer -v --tb=short -o "addopts="`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: Some `TestStrixRunsPersistence` and `TestCreateVulnerabilityReport` tests may fail — these are updated in Task 4.

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): migrate vulnerability reports to upstream Tracer"
```

---

### Task 4: Log agent creation in dispatch_agent

Add `tracer.log_agent_creation()` after `sandbox.register_agent()`.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:587-626` (`dispatch_agent`)
- Test: `strix-mcp/tests/test_tools.py`

**Step 1: Write the failing test**

Add to `strix-mcp/tests/test_tools.py`:

```python
class TestDispatchAgentTracing:
    """Test that dispatch_agent logs agent creation to the tracer."""

    @pytest.mark.asyncio
    async def test_dispatch_agent_logs_creation(self):
        """dispatch_agent should call tracer.log_agent_creation after registration."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastmcp import FastMCP

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
```

**Step 2: Run test to verify it fails**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestDispatchAgentTracing -v --tb=short -o "addopts="`
Expected: FAIL

**Step 3: Implement agent creation logging**

In `dispatch_agent` tool body, after `agent_id = await sandbox.register_agent(task_name=task)` and `prompt = prompt.replace(placeholder, agent_id)`, add:

```python
        # Log agent creation to tracer
        tracer = get_global_tracer()
        if tracer:
            try:
                tracer.log_agent_creation(
                    agent_id=agent_id,
                    name="mcp_subagent",
                    task=task,
                    parent_id=sandbox.active_scan.default_agent_id if sandbox.active_scan else None,
                )
            except Exception:
                pass
```

**Step 4: Run test to verify it passes**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestDispatchAgentTracing -v --tb=short -o "addopts="`
Expected: PASS

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): log agent creation in dispatch_agent"
```

---

### Task 5: Update _deduplicate_reports, remove stale tests, fix remaining tests

Three things: (1) update `_deduplicate_reports` to use Tracer field names, (2) remove tests for deleted functions, (3) update tests that need tracer mocks.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (`_deduplicate_reports`)
- Modify: `strix-mcp/tests/test_tools.py`

**Step 0: Update `_deduplicate_reports` for Tracer field names**

The upstream Tracer stores body text as `description`, not `content`. Update `_deduplicate_reports` (currently at lines 133-150 of tools.py):

```python
def _deduplicate_reports(
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate reports by normalized title, keeping the richest entry."""
    seen: dict[str, dict[str, Any]] = {}

    for report in reports:
        key = _normalize_title(report["title"])
        if key in seen:
            existing = seen[key]
            if _SEVERITY_ORDER.index(_normalize_severity(report.get("severity", "info"))) > _SEVERITY_ORDER.index(_normalize_severity(existing.get("severity", "info"))):
                existing["severity"] = _normalize_severity(report["severity"])
            # Tracer stores body text as "description", not "content"
            new_desc = report.get("description", "")
            existing_desc = existing.get("description", "")
            if new_desc and new_desc not in existing_desc:
                existing["description"] = existing_desc + f"\n\n---\n\n{new_desc}"
        else:
            seen[key] = dict(report)

    return list(seen.values())
```

**Step 1: Identify tests to remove**

Delete these test classes/methods that test removed functions:
- Entire `TestStrixRunsPersistence` class (tests `_get_run_dir`, `_write_finding_md`, `_write_vuln_csv`, `_write_summary_md`)
- Entire `TestGetFinding` class (imports and calls `_write_finding_md` which is deleted)

Remove the import line:
```python
from strix_mcp.tools import _normalize_title, _find_duplicate, _categorize_owasp, _deduplicate_reports
```
Replace with (keep only what's still used):
```python
from strix_mcp.tools import _normalize_title, _find_duplicate, _categorize_owasp, _deduplicate_reports, _normalize_severity, register_tools
```

**Step 1a: Update `TestDeduplicateReports` test data**

Tests in `TestDeduplicateReports` use `content` as the field key. Update them to use `description` to match Tracer's format:
- Replace `"content": "..."` with `"description": "..."` in test report dicts
- Update assertions that check merged content to look for `"description"` key

**Step 2: Update TestCreateVulnerabilityReport and TestNotesTools**

These test classes use `mcp.call_tool("start_scan", ...)` which now creates a real `Tracer`. Patch it:

```python
with patch("strix_mcp.tools.Tracer") as MockTracer, \
     patch("strix_mcp.tools.set_global_tracer"):
    mock_tracer = MagicMock()
    mock_tracer.vulnerability_reports = []
    mock_tracer.get_existing_vulnerabilities.return_value = []
    MockTracer.return_value = mock_tracer
    # ... existing test code
```

**Step 3: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add strix-mcp/tests/test_tools.py
git commit -m "test(mcp): update tests for tracer integration"
```

---

### Task 6: Final verification and cleanup

**Files:**
- Review: `strix-mcp/src/strix_mcp/tools.py` (ensure no stale references to removed vars)
- Review: `strix-mcp/src/strix_mcp/sandbox.py` (ensure import is clean)

**Step 1: Verify no stale references**

Search for references to removed variables and functions:

```bash
grep -n "scan_dir\|_write_finding_md\|_write_vuln_csv\|_write_summary_md\|_get_run_dir\|vulnerability_reports" strix-mcp/src/strix_mcp/tools.py
```

Expected: No matches for `scan_dir`, `_write_finding_md`, `_write_vuln_csv`, `_write_summary_md`, `_get_run_dir`. The only `vulnerability_reports` references should be inside method names/docstrings (e.g. `create_vulnerability_report`, `list_vulnerability_reports`).

**Step 2: Run full test suite one final time**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS with zero warnings about missing imports

**Step 3: Commit any cleanup**

```bash
git add -A strix-mcp/
git commit -m "chore(mcp): clean up stale references after tracer integration"
```

**Step 4: Push**

```bash
git push origin feat/mcp-orchestration
```
