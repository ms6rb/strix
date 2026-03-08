# MCP UX Improvements — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make strix-mcp user-friendly and upstream-ready: remove deprecated paths, improve descriptions/docs, add coverage map, fix dependency metadata.

**Architecture:** Pure docs + cleanup changes — no structural refactors. Touches tools.py (descriptions + removal), server.py (resource descriptions), methodology.md (references), pyproject.toml (metadata), and READMEs.

**Tech Stack:** Python (FastMCP), Markdown

**Decision log:**
- `end_scan` keeps its name — the original strix `finish_scan` is a different tool (agent submits executive summary). Renaming would create a collision.
- `register_agent` removed as public tool — `dispatch_agent` handles registration internally.

---

### Task 1: Remove `register_agent` as public tool

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:373-386`
- Modify: `strix-mcp/src/strix_mcp/methodology.md:77`

**Step 1: Remove the register_agent tool function**

Delete the entire `register_agent` tool (lines 373-386 in tools.py). The `dispatch_agent` tool already calls `sandbox.register_agent()` internally.

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

### Task 2: Update proxied tool descriptions

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (proxied tools section)

Update docstrings for all 14 proxied tools. Match original strix parameter names and types, add explicit enum values inline. Each step below is one tool's docstring replacement.

**Step 1: `browser_action`**

```python
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

**Step 2: `terminal_execute`**

```python
        """Execute a shell command in a persistent Kali Linux terminal session.

        command: the shell command to execute
        timeout: max seconds to wait for output (default 30, capped at 60). Command continues in background after timeout.
        terminal_id: identifier for persistent terminal session (default "default"). Use different IDs for concurrent sessions.
        is_input: if true, send as input to a running process instead of a new command
        no_enter: if true, send the command without pressing Enter"""
```

**Step 3: `python_action`**

```python
        """Run Python code in a persistent interpreter session inside the sandbox.

        action: new_session | execute | close | list_sessions
        code: Python code to execute (required for 'execute' action)
        timeout: max seconds for execution (default 30)
        session_id: session identifier (returned by new_session, required for execute/close)

        Proxy functions (send_request, list_requests, etc.) are pre-imported.
        Sessions maintain state (variables, imports) between calls.
        Must call 'new_session' before using 'execute'."""
```

**Step 4: `send_request`**

```python
        """Send an HTTP request through the Caido proxy. All traffic is captured for analysis with list_requests and view_request.

        method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        url: full URL including scheme (e.g. "https://target.com/api/users")
        headers: HTTP headers dict
        body: request body string
        timeout: max seconds to wait for response (default 30)"""
```

**Step 5: `repeat_request`**

```python
        """Replay a captured proxy request with optional modifications.

        request_id: the request ID from list_requests
        modifications: dict with optional keys — url (str), params (dict), headers (dict), body (str), cookies (dict)

        Typical workflow: browse with browser_action -> list_requests -> repeat_request with modifications."""
```

**Step 6: `list_requests`**

```python
        """List captured proxy requests with optional HTTPQL filtering.

        httpql_filter: HTTPQL query (e.g. 'req.method.eq:"POST"', 'resp.code.gte:400',
                       'req.path.regex:"/api/.*"', 'req.host.regex:".*example.com"')
        sort_by: timestamp | host | method | path | status_code | response_time | response_size | source
        sort_order: asc | desc"""
```

**Step 7: `view_request`**

```python
        """View detailed request or response data from captured proxy traffic.

        request_id: the request ID from list_requests
        part: request | response (default: request)
        search_pattern: regex pattern to highlight matches in the content
        page: page number for paginated responses"""
```

**Step 8: `scope_rules`**

```python
        """Manage proxy scope rules for domain filtering.

        action: get | list | create | update | delete
        allowlist: domain patterns to include (e.g. ["*.example.com"])
        denylist: domain patterns to exclude
        scope_id: scope identifier (required for get/update/delete)
        scope_name: human-readable scope name (for create/update)"""
```

**Step 9: `list_sitemap`**

```python
        """View the hierarchical sitemap of discovered attack surface from proxy traffic.

        scope_id: filter by scope
        parent_id: drill down into a specific node's children
        depth: DIRECT (immediate children only) | ALL (full recursive tree)
        page: page number for pagination"""
```

**Step 10: `view_sitemap_entry`**

```python
        """Get detailed information about a specific sitemap entry and its related HTTP requests.

        entry_id: the sitemap entry ID from list_sitemap"""
```

**Step 11: `list_files`**

```python
        """List files and directories in the sandbox workspace.

        directory_path: path to list (default "/workspace")
        depth: max recursion depth (default 3)"""
```

**Step 12: `search_files`**

```python
        """Search file contents in the sandbox workspace.

        directory_path: directory to search in
        file_pattern: glob pattern for file names (e.g. "*.py", "*.js")
        search_pattern: regex pattern to match in file contents"""
```

**Step 13: `str_replace_editor`**

```python
        """Edit a file in the sandbox by replacing an exact text match.

        file_path: path to the file in the sandbox
        old_str: exact string to find and replace
        new_str: replacement string"""
```

**Step 14: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass (docstring changes don't break tests)

**Step 15: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py
git commit -m "docs(mcp): improve proxied tool descriptions with parameter docs and enum values"
```

---

### Task 3: Update MCP-only tool descriptions

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (MCP-only tools)

**Step 1: `start_scan`**

```python
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

**Step 2: `end_scan`**

```python
        """Tear down the Docker sandbox and return a scan summary.

        Deduplicates findings by normalized title (higher severity wins on merge),
        groups by OWASP Top 10 (2021) category, and writes results to disk
        at strix_runs/<scan_id>/ (vulnerabilities/*.md, vulnerabilities.csv, summary.md).

        Returns: unique_findings count, severity_counts, findings_by_category."""
```

**Step 3: `get_scan_status`**

```python
        """Get current scan progress: elapsed time, registered agents, vulnerability
        counts by severity, and pending chain opportunities.

        Returns: scan_id, status, elapsed_seconds, agents list, severity_counts, pending_chains count."""
```

**Step 4: `create_vulnerability_report`**

```python
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

**Step 5: `list_vulnerability_reports`**

```python
        """List all vulnerability reports filed in the current scan (summaries only).
        Check this before filing a new report to avoid duplicates.

        severity: optional filter — critical | high | medium | low | info

        Returns: list of {id, title, severity, affected_endpoints, cvss_score}."""
```

**Step 6: `get_finding`**

```python
        """Read the full markdown details of a specific vulnerability finding from disk.

        finding_id: the report ID (e.g. "vuln-a1b2c3d4") from list_vulnerability_reports.

        Returns the raw markdown content from strix_runs/<scan_id>/vulnerabilities/<id>.md."""
```

**Step 7: `dispatch_agent`**

```python
        """Register a new subagent and return a ready-to-use prompt for the Agent tool.
        Handles agent registration internally — pass the returned prompt directly to
        the Agent tool to dispatch.

        task: what the agent should test (e.g. "Test IDOR and access control on /api/users")
        modules: knowledge modules the agent should load (e.g. ["idor", "authentication_jwt"])
        is_web_only: true for live web targets with no source code in /workspace
        chain_context: for Phase 2 chain agents — dict with keys: finding_a, finding_b, chain_name

        Returns: agent_id, prompt (pass prompt to Agent tool)."""
```

**Step 8: `suggest_chains`**

```python
        """Review all vulnerability chaining opportunities detected so far.
        Call after Phase 1 completes to find attack chains across findings.

        Each chain combines two findings into a higher-severity exploit path
        and includes a ready-to-use dispatch payload (task + modules) for dispatch_agent.

        Returns: total_chains, new_chains count, chains list with dispatch payloads."""
```

**Step 9: `get_module`**

```python
        """Load a security knowledge module by name. Modules contain exploitation
        techniques, bypass methods, validation requirements, and remediation guidance
        for a specific vulnerability class or technology.

        name: module name (e.g. "idor", "sql_injection", "authentication_jwt", "nextjs", "graphql")

        Load relevant modules at the START of testing work before analyzing code or running tests."""
```

**Step 10: `list_modules`**

```python
        """List all available security knowledge modules with categories and descriptions.

        category: optional filter (e.g. "vulnerabilities", "frameworks", "technologies", "protocols")

        Returns: JSON mapping module_name -> {category, description}."""
```

**Step 11: Run tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 12: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py
git commit -m "docs(mcp): improve MCP-only tool descriptions with parameter details"
```

---

### Task 4: Update server.py resource descriptions

**Files:**
- Modify: `strix-mcp/src/strix_mcp/server.py:24-45`

**Step 1: Update resource docstrings**

```python
@mcp.resource("strix://methodology")
def methodology_resource() -> str:
    """Penetration testing methodology and orchestration playbook.
    Covers scan workflow, subagent dispatch, vulnerability chaining,
    severity guidelines, and sandbox environment details.
    Read this before starting a security scan."""
    return get_methodology()


@mcp.resource("strix://modules")
def modules_list_resource() -> str:
    """JSON list of all available security knowledge modules with categories
    and descriptions. Use this to discover modules before loading them with get_module."""
    return list_modules()


@mcp.resource("strix://modules/{name}")
def module_resource(name: str) -> str:
    """Load a specific security knowledge module by name. Each module provides
    exploitation techniques, bypass methods, and validation requirements for
    a vulnerability class (e.g. sql_injection, xss, idor) or technology (e.g. nextjs, graphql)."""
    return get_module(name)
```

**Step 2: Commit**

```bash
git add strix-mcp/src/strix_mcp/server.py
git commit -m "docs(mcp): improve resource descriptions in server.py"
```

---

### Task 5: Update pyproject.toml metadata

**Files:**
- Modify: `strix-mcp/pyproject.toml`

**Step 1: Update description and add strix-agent dependency**

```toml
[project]
name = "strix-mcp"
version = "0.1.0"
description = "MCP server exposing Strix security sandbox tools to AI coding agents"
requires-python = ">=3.12"
dependencies = [
    "fastmcp>=2.0.0",
    "httpx>=0.27.0",
    "strix-agent",
]
```

Key changes:
- Description: "Claude Code" → "AI coding agents" (it's client-agnostic)
- Added `strix-agent` as an explicit dependency (resources.py imports from `strix.skills`)

**Step 2: Commit**

```bash
git add strix-mcp/pyproject.toml
git commit -m "chore(mcp): update description and add strix-agent dependency"
```

---

### Task 6: Rewrite strix-mcp/README.md

**Files:**
- Modify: `strix-mcp/README.md`

**Step 1: Write the new README**

```markdown
# Strix MCP Server

MCP (Model Context Protocol) server that exposes Strix's Docker security sandbox to AI coding agents. Works with any MCP-compatible client — Claude Code, Cursor, Windsurf, Cline, and others.

## Prerequisites

- Docker (running)
- Python 3.12+

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
| `end_scan` | Tear down sandbox, deduplicate findings, OWASP summary |
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
| `finish_scan` | Completion | Native Strix scan finalization with executive summary, methodology, and recommendations |
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

### Task 7: Add MCP mention to root README.md

**Files:**
- Modify: `README.md`

**Step 1: Add MCP section after "Advanced Testing Scenarios" (before "Headless Mode")**

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

### Task 8: Final verification

**Step 1: Check for stale references**

Run:
```bash
cd strix-mcp && grep -rn "register_agent" src/ README.md --include="*.py" --include="*.md" | grep -v "sandbox.register_agent" | grep -v "test_integration"
```

Expected: No results (all public-facing references removed; internal `sandbox.register_agent()` calls are fine).

**Step 2: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All pass

**Step 3: Review diff**

Run: `git diff --stat HEAD~8` (or however many commits were made)
Verify only expected files changed.
