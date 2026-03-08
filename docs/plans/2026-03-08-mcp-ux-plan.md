# MCP UX Improvements — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make strix-mcp user-friendly and upstream-ready: rename tools to match original strix, remove deprecated paths, improve descriptions/docs, add coverage map.

**Architecture:** Pure docs + naming changes — no structural refactors. Touches tools.py (rename + descriptions), methodology.md (references), tests, and READMEs.

**Tech Stack:** Python (FastMCP), Markdown

---

### Task 1: Rename `end_scan` → `finish_scan`

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:323-371`

**Step 1: Rename the function and update docstring**

In `tools.py`, rename the `end_scan` function to `finish_scan`:

```python
    @mcp.tool()
    async def finish_scan() -> str:
        """End the active scan and tear down the Docker sandbox.
        Returns a comprehensive summary: unique findings deduplicated,
        grouped by OWASP Top 10 category, with severity breakdown."""
```

**Step 2: Update methodology.md reference**

In `methodology.md` line 133, change:
```
- Call `end_scan` to tear down the sandbox and get a summary
```
to:
```
- Call `finish_scan` to tear down the sandbox and get a summary
```

**Step 3: Update test_integration.py reference**

In `tests/test_integration.py` line 16, change `end_scan` to `finish_scan`.

**Step 4: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/src/strix_mcp/methodology.md strix-mcp/tests/test_integration.py
git commit -m "refactor(mcp): rename end_scan to finish_scan to match upstream"
```

---

### Task 2: Remove `register_agent` as public tool

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:373-386`
- Modify: `strix-mcp/src/strix_mcp/methodology.md:77`

**Step 1: Remove the @mcp.tool() decorator from register_agent**

Remove the entire `register_agent` tool function (lines 373-386). The `dispatch_agent` tool already calls `sandbox.register_agent()` internally, so the public tool is redundant.

**Step 2: Update methodology.md**

Line 77 currently says:
```
For each agent in the plan, call `dispatch_agent(task=..., modules=[...])`. It handles agent registration and returns a complete prompt — pass the `prompt` field directly to the Agent tool. This replaces the manual `register_agent` + prompt composition workflow.
```

Change to:
```
For each agent in the plan, call `dispatch_agent(task=..., modules=[...])`. It handles agent registration and returns a complete prompt — pass the `prompt` field directly to the Agent tool.
```

**Step 3: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/src/strix_mcp/methodology.md
git commit -m "refactor(mcp): remove register_agent public tool, dispatch_agent handles registration"
```

---

### Task 3: Update proxied tool descriptions to mirror original strix

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (proxied tools section, lines 624-926)

The original strix tools have no docstrings, so we write clear descriptions that match the original parameter signatures. Key changes:

**Step 1: Update `browser_action` description**

```python
    @mcp.tool()
    async def browser_action(
        action: str,
        url: str | None = None,
        coordinate: str | None = None,
        text: str | None = None,
        js_code: str | None = None,
        tab_id: str | None = None,
        duration: str | None = None,
        key: str | None = None,
        file_path: str | None = None,
        clear: bool = False,
        agent_id: str | None = None,
    ) -> Sequence[types.TextContent | types.ImageContent]:
        """Control a Playwright browser in the sandbox. Returns a screenshot after each action.

        action: launch | goto | click | type | double_click | hover | scroll_up | scroll_down |
                press_key | execute_js | wait | back | forward | new_tab | switch_tab | close_tab |
                list_tabs | save_pdf | get_console_logs | view_source | close
        url: URL for goto/new_tab actions
        coordinate: "x,y" string for click/double_click/hover (derive from most recent screenshot)
        text: text to type for the type action
        js_code: JavaScript code for execute_js action
        tab_id: tab identifier for switch_tab/close_tab
        duration: seconds to wait for the wait action
        key: key name for press_key (e.g. "Enter", "Tab", "Escape")
        file_path: output path for save_pdf
        clear: if true, clear console log buffer (for get_console_logs)

        Start with 'launch', end with 'close'."""
```

**Step 2: Update `terminal_execute` description**

```python
    @mcp.tool()
    async def terminal_execute(
        command: str,
        timeout: int = 30,
        terminal_id: str = "default",
        is_input: bool = False,
        no_enter: bool = False,
        agent_id: str | None = None,
    ) -> str:
        """Execute a shell command in a persistent Kali Linux terminal session.

        command: the shell command to execute
        timeout: max seconds to wait for output (default 30, capped at 60). Command continues in background after timeout.
        terminal_id: identifier for persistent terminal session (default "default"). Use different IDs for concurrent sessions.
        is_input: if true, send as input to a running process instead of a new command
        no_enter: if true, send the command without pressing Enter"""
```

**Step 3: Update `python_action` description**

```python
    @mcp.tool()
    async def python_action(
        action: str,
        code: str | None = None,
        timeout: int = 30,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Run Python code in a persistent interpreter session inside the sandbox.

        action: new_session | execute | close | list_sessions
        code: Python code to execute (required for 'execute' action)
        timeout: max seconds for execution (default 30)
        session_id: session identifier (returned by new_session, required for execute/close)

        Proxy functions (send_request, list_requests, etc.) are pre-imported.
        Sessions maintain state (variables, imports) between calls.
        Must call 'new_session' before using 'execute'."""
```

**Step 4: Update `scope_rules` description**

```python
    @mcp.tool()
    async def scope_rules(
        action: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
        scope_name: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Manage proxy scope rules for domain filtering.

        action: get | list | create | update | delete
        allowlist: domain patterns to include (e.g. ["*.example.com"])
        denylist: domain patterns to exclude
        scope_id: scope identifier (required for get/update/delete)
        scope_name: human-readable scope name (for create/update)"""
```

**Step 5: Update `list_requests` description**

```python
    @mcp.tool()
    async def list_requests(
        httpql_filter: str | None = None,
        start_page: int = 1,
        end_page: int | None = None,
        page_size: int = 20,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        scope_id: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """List captured proxy requests with optional HTTPQL filtering.

        httpql_filter: HTTPQL query (e.g. 'req.method.eq:"POST"', 'resp.code.gte:400',
                       'req.path.regex:"/api/.*"', 'req.host.regex:".*example.com"')
        sort_by: timestamp | host | method | path | status_code | response_time | response_size | source
        sort_order: asc | desc"""
```

**Step 6: Update `view_request` description**

```python
    @mcp.tool()
    async def view_request(
        request_id: str,
        part: str | None = None,
        search_pattern: str | None = None,
        page: int | None = None,
        agent_id: str | None = None,
    ) -> str:
        """View detailed request or response data from captured proxy traffic.

        request_id: the request ID from list_requests
        part: request | response (default: request)
        search_pattern: regex pattern to highlight matches in the content
        page: page number for paginated responses"""
```

**Step 7: Update `repeat_request` description**

```python
    @mcp.tool()
    async def repeat_request(
        request_id: str,
        modifications: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Replay a captured proxy request with optional modifications.

        request_id: the request ID from list_requests
        modifications: dict with optional keys: url (str), params (dict), headers (dict), body (str), cookies (dict)

        Typical workflow: browse with browser_action → list_requests → repeat_request with modifications."""
```

**Step 8: Update `send_request` description**

```python
    @mcp.tool()
    async def send_request(
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 30,
        agent_id: str | None = None,
    ) -> str:
        """Send an HTTP request through the Caido proxy. All traffic is captured for analysis with list_requests and view_request.

        method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        url: full URL including scheme (e.g. "https://target.com/api/users")
        headers: HTTP headers dict
        body: request body string
        timeout: max seconds to wait for response (default 30)"""
```

**Step 9: Update `list_sitemap` description**

```python
    @mcp.tool()
    async def list_sitemap(
        scope_id: str | None = None,
        parent_id: str | None = None,
        depth: str = "DIRECT",
        page: int = 1,
        agent_id: str | None = None,
    ) -> str:
        """View the hierarchical sitemap of discovered attack surface from proxy traffic.

        scope_id: filter by scope
        parent_id: drill down into a specific node's children
        depth: DIRECT (immediate children only) | ALL (full recursive tree)
        page: page number for pagination"""
```

**Step 10: Update remaining simple tools**

```python
    # list_files
        """List files and directories in the sandbox workspace.

        directory_path: path to list (default "/workspace")
        depth: max recursion depth (default 3)"""

    # search_files
        """Search file contents in the sandbox workspace.

        directory_path: directory to search in
        file_pattern: glob pattern for file names (e.g. "*.py", "*.js")
        search_pattern: regex pattern to match in file contents"""

    # str_replace_editor
        """Edit a file in the sandbox by replacing an exact text match.

        file_path: path to the file in the sandbox
        old_str: exact string to find and replace
        new_str: replacement string"""

    # view_sitemap_entry
        """Get detailed information about a specific sitemap entry and its related HTTP requests.

        entry_id: the sitemap entry ID from list_sitemap"""
```

**Step 11: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass (docstring changes don't break tests)

**Step 12: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py
git commit -m "docs(mcp): improve tool descriptions with parameter docs and enum values"
```

---

### Task 4: Update MCP-only tool descriptions

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (MCP-only tools section)

**Step 1: Update `start_scan` description**

```python
    @mcp.tool()
    async def start_scan(
        targets: list[dict[str, str]],
        scan_id: str | None = None,
    ) -> str:
        """Boot a Docker sandbox and initialize a security scan.

        targets: list of dicts with keys:
            type: local_code | web_application | repository | ip_address | domain
            value: file path, URL, or address
            name: (optional) label for local_code targets

        Detects the target's tech stack (frameworks, databases, auth, features) and
        generates a recommended scan plan with module assignments. For web targets,
        fingerprints via HTTP headers, cookies, and common paths.

        First run pulls the Docker image (~2GB). Subsequent runs reuse the cached image.

        Returns: scan_id, detected_stack, recommended_plan, workspace path.
        If a Swagger/OpenAPI spec is found, returns openapi_spec with endpoint list."""
```

**Step 2: Update `finish_scan` description (already renamed in Task 1)**

```python
    @mcp.tool()
    async def finish_scan() -> str:
        """Tear down the Docker sandbox and return a scan summary.

        Deduplicates findings by normalized title (higher severity wins on merge),
        groups by OWASP Top 10 (2021) category, and writes results to disk
        at strix_runs/<scan_id>/ (vulnerabilities/*.md, vulnerabilities.csv, summary.md).

        Returns: unique_findings count, severity_counts, findings_by_category."""
```

**Step 3: Update `get_scan_status` description**

```python
    @mcp.tool()
    async def get_scan_status() -> str:
        """Get current scan progress: elapsed time, registered agents, vulnerability
        counts by severity, and pending chain opportunities.

        Returns: scan_id, status, elapsed_seconds, agents list, severity_counts, pending_chains count."""
```

**Step 4: Update `create_vulnerability_report` description**

```python
    @mcp.tool()
    async def create_vulnerability_report(
        title: str,
        content: str,
        severity: str,
        affected_endpoint: str | None = None,
        cvss_score: float | None = None,
    ) -> str:
        """File a confirmed vulnerability finding. Automatically deduplicates — if a
        similar finding exists, evidence is merged and the higher severity is kept.
        Also triggers automatic chain detection across all findings.

        title: vulnerability name (e.g. "SQL Injection in /api/users")
        content: full details including proof of exploitation, impact, and remediation
        severity: critical | high | medium | low | info
        affected_endpoint: URL path or component affected (e.g. "/api/users/:id")
        cvss_score: CVSS 3.1 base score (0.0-10.0)

        Only report validated vulnerabilities with proof of exploitation."""
```

**Step 5: Update `list_vulnerability_reports` description**

```python
    @mcp.tool()
    async def list_vulnerability_reports(severity: str | None = None) -> str:
        """List all vulnerability reports filed in the current scan (summaries only).
        Check this before filing a new report to avoid duplicates.

        severity: optional filter — critical | high | medium | low | info

        Returns: list of {id, title, severity, affected_endpoints, cvss_score}."""
```

**Step 6: Update `get_finding` description**

```python
    @mcp.tool()
    async def get_finding(finding_id: str) -> str:
        """Read the full markdown details of a specific vulnerability finding from disk.

        finding_id: the report ID (e.g. "vuln-a1b2c3d4") from list_vulnerability_reports.

        Returns the raw markdown content from strix_runs/<scan_id>/vulnerabilities/<id>.md."""
```

**Step 7: Update `dispatch_agent` description**

```python
    @mcp.tool()
    async def dispatch_agent(
        task: str,
        modules: list[str],
        is_web_only: bool = False,
        chain_context: dict[str, str] | None = None,
    ) -> str:
        """Register a new subagent and return a ready-to-use prompt for the Agent tool.
        Handles agent registration internally — pass the returned prompt directly to
        the Agent tool to dispatch.

        task: what the agent should test (e.g. "Test IDOR and access control on /api/users")
        modules: knowledge modules the agent should load (e.g. ["idor", "authentication_jwt"])
        is_web_only: true for live web targets with no source code in /workspace
        chain_context: for Phase 2 chain agents — dict with keys: finding_a, finding_b, chain_name

        Returns: agent_id, prompt (pass prompt to Agent tool)."""
```

**Step 8: Update `suggest_chains` description**

```python
    @mcp.tool()
    async def suggest_chains() -> str:
        """Review all vulnerability chaining opportunities detected so far.
        Call after Phase 1 completes to find attack chains across findings.

        Each chain combines two findings into a higher-severity exploit path
        and includes a ready-to-use dispatch payload (task + modules) for dispatch_agent.

        Returns: total_chains, new_chains count, chains list with dispatch payloads."""
```

**Step 9: Update `get_module` and `list_modules` descriptions**

```python
    # get_module
        """Load a security knowledge module by name. Modules contain exploitation
        techniques, bypass methods, validation requirements, and remediation guidance
        for a specific vulnerability class or technology.

        name: module name (e.g. "idor", "sql_injection", "authentication_jwt", "nextjs", "graphql")

        Load relevant modules at the START of testing work before analyzing code or running tests."""

    # list_modules
        """List all available security knowledge modules with categories and descriptions.

        category: optional filter (e.g. "vulnerabilities", "frameworks", "technologies", "protocols")

        Returns: JSON mapping module_name → {category, description}."""
```

**Step 10: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 11: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py
git commit -m "docs(mcp): improve MCP-only tool descriptions with parameter details"
```

---

### Task 5: Rewrite strix-mcp/README.md

**Files:**
- Modify: `strix-mcp/README.md`

**Step 1: Write the new README**

```markdown
# Strix MCP Server

MCP (Model Context Protocol) server that exposes Strix's Docker security sandbox to AI coding agents. Works with any MCP-compatible client — Claude Code, Cursor, Windsurf, Cline, and others.

## Prerequisites

- Docker (running)
- Python 3.12+
- The `strix-agent` package (installed automatically as a dependency)

## Installation

```bash
pip install strix-mcp
```

The Docker image (~2GB) is pulled automatically on first scan.

## Client Configuration

### Claude Code

Add to your project's `.mcp.json` or `~/.claude/mcp_servers.json`:

```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp",
      "args": []
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp",
      "args": []
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp",
      "args": []
    }
  }
}
```

### Other MCP Clients

Any client that supports MCP stdio transport can use strix-mcp. Point it at the `strix-mcp` command with no arguments.

## Quick Start

Ask your AI agent:

> "Start a security scan on ./my-app and test for OWASP Top 10 vulnerabilities"

The agent will boot a Kali Linux sandbox, copy your code, and begin testing.

## Strix Feature Coverage

This MCP server exposes Strix's sandbox tools to external AI agents. Below is the coverage map against the full Strix tool suite.

### Proxied Tools (full parity with Strix)

These tools are forwarded directly to the Strix sandbox container — same behavior as native Strix.

| Tool | Description |
|------|-------------|
| `terminal_execute` | Execute commands in persistent Kali Linux terminal |
| `send_request` | Send HTTP requests through Caido proxy |
| `repeat_request` | Replay captured requests with modifications |
| `list_requests` | Filter proxy traffic with HTTPQL |
| `view_request` | Inspect request/response details |
| `browser_action` | Control Playwright browser (returns screenshots) |
| `python_action` | Run Python in persistent interpreter sessions |
| `list_files` | List sandbox workspace files |
| `search_files` | Search file contents by pattern |
| `str_replace_editor` | Edit files in sandbox |
| `scope_rules` | Manage proxy scope filtering |
| `list_sitemap` | View discovered attack surface |
| `view_sitemap_entry` | Inspect sitemap entry details |
| `create_vulnerability_report` | File confirmed vulnerability findings |

### MCP Orchestration Layer

Tools added by the MCP server for AI agent coordination — not part of the core Strix sandbox.

| Tool | Description |
|------|-------------|
| `start_scan` | Boot sandbox, detect tech stack, generate scan plan |
| `finish_scan` | Tear down sandbox, deduplicate findings, OWASP summary |
| `dispatch_agent` | Register subagent and compose ready-to-use prompt |
| `get_scan_status` | Monitor scan progress and pending chains |
| `list_vulnerability_reports` | List filed reports (summaries, deduplication check) |
| `get_finding` | Read full finding details from disk |
| `get_module` | Load security knowledge module |
| `list_modules` | List available knowledge modules |
| `suggest_chains` | Review vulnerability chaining opportunities |

### Not Yet Supported

These Strix tools are not yet proxied through the MCP server.

| Tool | Category | Notes |
|------|----------|-------|
| `create_note` / `list_notes` / `update_note` / `delete_note` | Notes | Structured note-taking during scans |
| `create_todo` / `list_todos` / `update_todo` / `mark_todo_done` / `mark_todo_pending` / `delete_todo` | Todos | Task tracking within scans |
| `think` | Analysis | Record reasoning and analysis steps |
| `web_search` | Reconnaissance | Search via Perplexity AI for security intelligence |
| `finish_scan` (native) | Completion | Native Strix scan finalization with executive summary (MCP has its own `finish_scan` with OWASP grouping) |
| `view_agent_graph` / `create_agent` / `send_message_to_agent` / `agent_finish` / `wait_for_message` | Agent Graph | Native Strix multi-agent orchestration (MCP uses `dispatch_agent` instead) |

### Resources

| URI | Description |
|-----|-------------|
| `strix://methodology` | Penetration testing playbook and orchestration guide |
| `strix://modules` | List of available security knowledge modules |
| `strix://modules/{name}` | Specific module content (e.g. `strix://modules/sql_injection`) |

## Architecture

The MCP server acts as a bridge between AI agents and a Strix Docker sandbox:

```
AI Agent (Claude Code, Cursor, etc.)
    ↕ MCP (stdio)
strix-mcp server
    ↕ HTTP
Strix Docker Container (Kali Linux)
    ├── Caido proxy
    ├── Playwright browser
    ├── Terminal sessions
    ├── Python interpreter
    └── Security tools (nuclei, sqlmap, ffuf, etc.)
```

All agents share one container but get isolated sessions (terminal, browser, Python) via `agent_id`.

## Known Limitations

- One scan at a time per MCP server instance
- First scan requires Docker image pull (~2GB)
- Agent graph tools not supported — MCP uses its own orchestration via `dispatch_agent`
```

**Step 2: Commit**

```bash
git add strix-mcp/README.md
git commit -m "docs(mcp): rewrite README with coverage map and multi-client setup"
```

---

### Task 6: Add MCP mention to root README.md

**Files:**
- Modify: `README.md`

**Step 1: Add MCP section**

Add after the "Advanced Testing Scenarios" section (before "Headless Mode"), a new section:

```markdown
### MCP Server (AI Agent Integration)

Use Strix as an MCP server to integrate with AI coding agents like Claude Code, Cursor, and Windsurf:

```bash
pip install strix-mcp
```

See [`strix-mcp/README.md`](strix-mcp/README.md) for setup instructions and the full tool coverage map.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add MCP server section to root README"
```

---

### Task 7: Update strix-mcp/README.md tool table in old locations

**Files:**
- Modify: `strix-mcp/src/strix_mcp/methodology.md:5,133`

**Step 1: Update methodology.md step 5 reference**

Line 5 currently says "End the scan". No change needed — it's generic enough.

Line 133 was already updated in Task 1 (`end_scan` → `finish_scan`).

**Step 2: Verify no other stale references exist**

Run:
```bash
cd strix-mcp && grep -rn "end_scan\|register_agent" src/ tests/ README.md --include="*.py" --include="*.md" | grep -v "test_integration"
```

Expected: No results (all references updated).

**Step 3: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 4: Commit (if any remaining fixes)**

```bash
git add -A strix-mcp/
git commit -m "chore(mcp): clean up remaining stale references"
```
