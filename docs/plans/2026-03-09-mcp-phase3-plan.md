# MCP Phase 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add missing tools (notes, full file editor), integration tests with Docker sandbox, and E2E verification checklist.

**Architecture:** Proxy 4 notes tools and expand str_replace_editor to support all 5 commands (view, create, str_replace, insert, undo_edit). Add methodology guidance for native agent capabilities. Build integration tests with a custom vulnerable Flask app in Docker.

**Tech Stack:** Python, FastMCP, pytest-asyncio, Docker, Flask (test target)

---

### Task 0: Verify Sandbox Parameter Names

Before writing any code, verify the exact parameter names the sandbox API expects for `str_replace_editor` and notes tools. Upstream uses `path` (not `file_path`) for the editor tool — we need to confirm which name the sandbox accepts.

**Step 1: Start a sandbox and test parameter names**

```bash
cd strix-mcp && python -c "
import asyncio
from strix_mcp.sandbox import SandboxManager

async def test():
    mgr = SandboxManager()
    state = await mgr.start_scan(targets=[], scan_id='param-test')

    # Test str_replace_editor with 'path' (upstream name)
    r1 = await mgr.proxy_tool('str_replace_editor', {
        'command': 'create', 'path': '/workspace/test.txt', 'file_text': 'hello'
    })
    print('path:', r1)

    # Test str_replace_editor with 'file_path' (our current name)
    r2 = await mgr.proxy_tool('str_replace_editor', {
        'command': 'view', 'file_path': '/workspace/test.txt'
    })
    print('file_path:', r2)

    # Test notes
    r3 = await mgr.proxy_tool('create_note', {
        'title': 'test', 'content': 'test content'
    })
    print('create_note:', r3)

    r4 = await mgr.proxy_tool('list_notes', {})
    print('list_notes:', r4)

    await mgr.end_scan()

asyncio.run(test())
"
```

**Step 2: Record findings**

Note which parameter name works (`path` vs `file_path`) and whether notes tools are recognized. Use the correct names in all subsequent tasks. If `path` is correct, use `path` in the MCP wrapper but keep the MCP parameter name as `file_path` for clarity, mapping it:
```python
kwargs: dict[str, Any] = {"command": command, "path": file_path}
```

**Step 3: Commit findings as a comment in tools.py**

No commit needed — this is a verification step. Proceed to Task 1 with the correct parameter names.

---

### Task 1: Expand str_replace_editor to Support All Commands

The existing `str_replace_editor` only accepts `str_replace` parameters directly. Upstream uses a single tool with a `command` parameter that dispatches to view/create/str_replace/insert/undo_edit. We need to match that interface.

**IMPORTANT:** Use the parameter name verified in Task 0 for the sandbox kwargs. The code below uses `path` (upstream name) in the kwargs sent to the sandbox, while keeping `file_path` as the MCP parameter name for agent-facing clarity.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:912-930`
- Test: `strix-mcp/tests/test_tools.py` (no new test needed — this is a proxied tool, tested in integration)

**Step 1: Replace the existing str_replace_editor function**

Replace the current function at lines 912-930 in `strix-mcp/src/strix_mcp/tools.py` with:

```python
    @mcp.tool()
    async def str_replace_editor(
        command: str,
        file_path: str,
        file_text: str | None = None,
        view_range: list[int] | None = None,
        old_str: str | None = None,
        new_str: str | None = None,
        insert_line: int | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Edit, view, or create files in the sandbox workspace.

        command: one of view | create | str_replace | insert | undo_edit
        file_path: path to file in the sandbox (e.g. "/workspace/app.py")
        file_text: file content (required for create)
        view_range: [start_line, end_line] for view (1-indexed, use -1 for EOF)
        old_str: text to find (required for str_replace)
        new_str: replacement text (required for insert; optional for str_replace — omit to delete)
        insert_line: line number to insert after (required for insert)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        # Map MCP param name "file_path" to upstream sandbox param name "path"
        kwargs: dict[str, Any] = {"command": command, "path": file_path}
        if file_text is not None:
            kwargs["file_text"] = file_text
        if view_range is not None:
            kwargs["view_range"] = view_range
        if old_str is not None:
            kwargs["old_str"] = old_str
        if new_str is not None:
            kwargs["new_str"] = new_str
        if insert_line is not None:
            kwargs["insert_line"] = insert_line
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("str_replace_editor", kwargs)
        return json.dumps(result)
```

**Step 2: Run unit tests to verify no regressions**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All 112 tests PASS

**Step 3: Update README coverage map**

In `strix-mcp/README.md`, find the `str_replace_editor` row in the Proxied Tools table (around line 107) and change the Parity column from `Partial — str_replace only, no create/view/insert` to `Full`.

Also in the "Not Yet Supported" section (around line 143), remove the `str_replace_editor create/view/insert` row.

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/README.md
git commit -m "feat(mcp): expand str_replace_editor to support all 5 commands"
```

---

### Task 2: Add Notes Tools (Proxy)

Add 4 new proxied tools for agent note-taking. These mirror the upstream notes API exactly and use the same proxy pattern as all other forwarded tools.

**IMPORTANT:** Task 0 verifies that the sandbox recognizes `create_note`, `list_notes`, `update_note`, `delete_note` as tool names. If the sandbox uses different names, adjust accordingly.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py` (add after proxied tools section, before end of `register_tools`)

**Step 1: Add the 4 notes tools**

Add after the last proxied tool (view_sitemap_entry) in `strix-mcp/src/strix_mcp/tools.py`:

```python
    # --- Notes Tools ---

    @mcp.tool()
    async def create_note(
        title: str,
        content: str,
        category: str = "general",
        tags: list[str] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Create a structured note during the scan for tracking findings,
        methodology decisions, questions, or plans.

        title: note title
        content: note body text
        category: general | findings | methodology | questions | plan
        tags: optional list of tags for filtering
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {
            "title": title,
            "content": content,
            "category": category,
        }
        if tags is not None:
            kwargs["tags"] = tags
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("create_note", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def list_notes(
        category: str | None = None,
        tags: list[str] | None = None,
        search: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """List and filter notes created during the scan.

        category: filter by category — general | findings | methodology | questions | plan
        tags: filter by tags (notes matching any tag are returned)
        search: search query to match against note title and content
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {}
        if category is not None:
            kwargs["category"] = category
        if tags is not None:
            kwargs["tags"] = tags
        if search is not None:
            kwargs["search"] = search
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("list_notes", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def update_note(
        note_id: str,
        title: str | None = None,
        content: str | None = None,
        tags: list[str] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Update an existing note's title, content, or tags.

        note_id: the ID returned by create_note
        title: new title (optional)
        content: new content (optional)
        tags: new tags list (optional, replaces existing tags)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {"note_id": note_id}
        if title is not None:
            kwargs["title"] = title
        if content is not None:
            kwargs["content"] = content
        if tags is not None:
            kwargs["tags"] = tags
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("update_note", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def delete_note(
        note_id: str,
        agent_id: str | None = None,
    ) -> str:
        """Delete a note by ID.

        note_id: the ID returned by create_note
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {"note_id": note_id}
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("delete_note", kwargs)
        return json.dumps(result)
```

**Step 2: Run unit tests to verify no regressions**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All 112 tests PASS

**Step 3: Update README**

In `strix-mcp/README.md`:

1. Add 4 rows to the Proxied Tools table:

| `create_note` | Create structured notes during scans | Full |
| `list_notes` | List and filter scan notes | Full |
| `update_note` | Update existing notes | Full |
| `delete_note` | Delete notes | Full |

2. Remove the `create_note / list_notes / update_note / delete_note` row from "Not Yet Supported".

3. Update the proxied tools count from 13 to 17 everywhere it appears in the README (table headers, summary text, etc.).

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/README.md
git commit -m "feat(mcp): add notes tools (create, list, update, delete)"
```

---

### Task 3: Update Methodology — Native Agent Capabilities

Tell agents to use their built-in web search and reasoning capabilities instead of dedicated tools.

**Files:**
- Modify: `strix-mcp/src/strix_mcp/methodology.md` (add new section before `## Efficiency`)

**Step 1: Add the new section**

Insert before the `## Efficiency` section (around line 229) in `strix-mcp/src/strix_mcp/methodology.md`:

```markdown
## Native Agent Capabilities

Your MCP client (Claude Code, Cursor, Windsurf, etc.) provides built-in tools you should use:

- **Web search**: Use your native search tool for CVE lookups, exploit technique research, bypass documentation, and security advisories. No need for a dedicated search tool.
- **Reasoning**: Use your native thinking/reasoning capability to plan attack strategies, analyze findings, and decide next steps before acting.

These capabilities complement the sandbox tools — use them freely throughout the scan.

```

**Step 2: Verify methodology loads correctly**

Run: `cd strix-mcp && python -c "from strix_mcp.resources import get_methodology; m = get_methodology(); assert 'Native Agent Capabilities' in m; print('OK')"`
Expected: `OK`

**Step 3: Update README "Not Yet Supported"**

In `strix-mcp/README.md`, remove the `think` and `web_search` rows from "Not Yet Supported" and add a note:

```
> **Note:** `think` and `web_search` are intentionally not proxied — agents should use their native reasoning and web search capabilities instead.
```

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/methodology.md strix-mcp/README.md
git commit -m "docs(mcp): add native agent capabilities section to methodology"
```

---

### Task 4: Create Vulnerable Test Target App

A minimal Flask app with intentional SQLi and XSS for integration testing.

**Files:**
- Create: `strix-mcp/tests/vulnerable_app/app.py`
- Create: `strix-mcp/tests/vulnerable_app/Dockerfile`
- Create: `strix-mcp/tests/vulnerable_app/requirements.txt`

**Step 1: Create the vulnerable Flask app**

Create `strix-mcp/tests/vulnerable_app/app.py`:

```python
"""Intentionally vulnerable Flask app for integration testing.
DO NOT deploy this anywhere — it contains real vulnerabilities by design.
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@test.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@test.com')")
    conn.commit()
    return conn


@app.route("/")
def index():
    return "<h1>Vulnerable Test App</h1><a href='/search?q=test'>Search</a>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: Reflected XSS — user input rendered without escaping
    conn = get_db()
    # VULN: SQL Injection — user input concatenated into query
    cursor = conn.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
    results = cursor.fetchall()
    conn.close()
    return f"<h1>Search: {q}</h1><pre>{results}</pre>"


@app.route("/api/users")
def api_users():
    conn = get_db()
    cursor = conn.execute("SELECT * FROM users")
    users = [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]
    conn.close()
    return {"users": users}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

**Step 2: Create requirements.txt**

Create `strix-mcp/tests/vulnerable_app/requirements.txt`:

```
flask>=3.0.0
```

**Step 3: Create Dockerfile**

Create `strix-mcp/tests/vulnerable_app/Dockerfile`:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
```

**Step 4: Commit**

```bash
git add strix-mcp/tests/vulnerable_app/
git commit -m "test: add vulnerable Flask app for integration testing"
```

---

### Task 5: Create Docker Compose Test Infrastructure

Set up docker-compose to run the sandbox and vulnerable app together.

**Files:**
- Create: `strix-mcp/tests/docker-compose.test.yml`

**Step 1: Create docker-compose file**

Create `strix-mcp/tests/docker-compose.test.yml`:

```yaml
version: "3.8"

services:
  vulnerable-app:
    build:
      context: ./vulnerable_app
    ports:
      - "5000:5000"
    # On Linux, host.docker.internal doesn't work by default.
    # This flag maps it to the host gateway so the sandbox can reach the app.
    extra_hosts:
      - "host.docker.internal:host-gateway"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/')"]
      interval: 2s
      timeout: 5s
      retries: 10

networks:
  default:
    name: strix-test
```

> **Note (Linux):** The strix sandbox container also needs `host.docker.internal` to reach the vulnerable app. If the sandbox is started by `SandboxManager`, you may need to pass `extra_hosts` to the Docker run command. On macOS, `host.docker.internal` works out of the box.

**Step 2: Verify it builds**

Run: `cd strix-mcp/tests && docker compose -f docker-compose.test.yml build`
Expected: Image builds successfully

**Step 3: Verify it runs**

Run: `cd strix-mcp/tests && docker compose -f docker-compose.test.yml up -d && sleep 3 && curl -s http://localhost:5000/ && docker compose -f docker-compose.test.yml down`
Expected: Returns HTML with "Vulnerable Test App"

**Step 4: Commit**

```bash
git add strix-mcp/tests/docker-compose.test.yml
git commit -m "test: add docker-compose for integration test infrastructure"
```

---

### Task 6: Expand Integration Tests

Add comprehensive integration tests covering all proxied tools and the full scan lifecycle with the vulnerable app.

**Files:**
- Modify: `strix-mcp/tests/test_integration.py`

**Step 1: Rewrite test_integration.py**

Replace the full contents of `strix-mcp/tests/test_integration.py`:

```python
"""Integration tests: full scan lifecycle with live Docker sandbox.

Requires:
  - Docker running
  - strix-sandbox image pulled: docker pull ghcr.io/usestrix/strix-sandbox:0.1.12
  - Vulnerable app running: cd tests && docker compose -f docker-compose.test.yml up -d

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
    assert "pentester" in str(result)

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

    # NOTE: Use the parameter name verified in Task 0 ("path" or "file_path")
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
        "pattern": "modified",
    })
    assert "modified" in str(result) or "test.txt" in str(result)


# --- Notes ---


@pytest.mark.asyncio
async def test_notes_lifecycle(sandbox: SandboxManager):
    """Create, list, update, and delete notes."""
    await sandbox.start_scan(targets=[], scan_id="test-notes")

    # Create
    result = await sandbox.proxy_tool("create_note", {
        "title": "Test Finding",
        "content": "Found an interesting endpoint",
        "category": "findings",
        "tags": ["xss", "priority"],
    })
    assert result.get("success") or not result.get("error")
    note_id = result.get("note_id", result.get("result", {}).get("note_id"))

    # List
    result = await sandbox.proxy_tool("list_notes", {
        "category": "findings",
    })
    assert not result.get("error")

    # Update
    if note_id:
        result = await sandbox.proxy_tool("update_note", {
            "note_id": note_id,
            "content": "Updated: confirmed XSS on /search",
        })
        assert not result.get("error")

        # Delete
        result = await sandbox.proxy_tool("delete_note", {
            "note_id": note_id,
        })
        assert not result.get("error")


# --- HTTP Proxy ---


@pytest.mark.asyncio
async def test_http_requests(sandbox: SandboxManager):
    """Send HTTP requests through the sandbox proxy.

    Requires: vulnerable app running on host port 5000.
    The sandbox accesses the host via host.docker.internal or 172.17.0.1.
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

    result = await sandbox.proxy_tool("python_action", {
        "code": "print(2 + 2)",
    })
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
```

**Step 2: Run lifecycle tests (no vulnerable app needed)**

Run: `cd strix-mcp && python -m pytest tests/test_integration.py -v -s -o "addopts=" -k "lifecycle or two_scans or proxy_error or register"`
Expected: 4 tests PASS

**Step 3: Run all integration tests (with vulnerable app)**

Run: `cd strix-mcp/tests && docker compose -f docker-compose.test.yml up -d && cd .. && python -m pytest tests/test_integration.py -v -s -o "addopts=" && cd tests && docker compose -f docker-compose.test.yml down`
Expected: All tests PASS (HTTP tests may skip if host networking doesn't work)

**Step 4: Commit**

```bash
git add strix-mcp/tests/test_integration.py
git commit -m "test(mcp): expand integration tests for all proxied tools"
```

---

### Task 7: Create E2E Verification Checklist

A manual testing checklist for verifying the MCP across different clients.

**Files:**
- Create: `strix-mcp/E2E_CHECKLIST.md`

**Step 1: Write the checklist**

Create `strix-mcp/E2E_CHECKLIST.md`:

```markdown
# MCP E2E Verification Checklist

Manual verification steps for testing strix-mcp across MCP clients.

## Prerequisites

- [ ] Docker running
- [ ] Sandbox image pulled: `docker pull ghcr.io/usestrix/strix-sandbox:0.1.12`
- [ ] strix-mcp installed: `cd strix-mcp && pip install -e .`

## Claude Code

Config in `~/.claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp"
    }
  }
}
```

- [ ] Server starts without errors
- [ ] `start_scan` with web target launches sandbox
- [ ] `terminal_execute` runs commands (e.g. `whoami` → `pentester`)
- [ ] `browser_action` returns screenshots
- [ ] `send_request` sends HTTP through proxy
- [ ] `str_replace_editor` with `view` reads files
- [ ] `str_replace_editor` with `create` creates files
- [ ] `create_note` and `list_notes` work
- [ ] `create_vulnerability_report` stores finding
- [ ] `list_vulnerability_reports` shows finding
- [ ] `get_finding` returns markdown detail
- [ ] `dispatch_agent` returns agent_id + prompt
- [ ] `suggest_chains` returns chain opportunities (after 2+ findings)
- [ ] `get_scan_status` shows elapsed time and agents
- [ ] `end_scan` returns summary with OWASP grouping
- [ ] `strix_runs/` directory created with markdown + CSV files

## Cursor

Config in `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp"
    }
  }
}
```

- [ ] Server starts without errors
- [ ] `start_scan` launches sandbox
- [ ] Basic tool execution works (terminal, HTTP, files)
- [ ] `end_scan` completes cleanly

## Windsurf

Config in `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "strix": {
      "command": "strix-mcp"
    }
  }
}
```

- [ ] Server starts without errors
- [ ] `start_scan` launches sandbox
- [ ] Basic tool execution works (terminal, HTTP, files)
- [ ] `end_scan` completes cleanly

## Post-Verification

- [ ] Run `docker ps` — no orphaned strix containers remain
- [ ] Second scan starts cleanly after first ends
```

**Step 2: Commit**

```bash
git add strix-mcp/E2E_CHECKLIST.md
git commit -m "docs(mcp): add E2E verification checklist for MCP clients"
```

---

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Skip `web_search` tool | Agents use native web search (Claude Code WebSearch, Cursor search) |
| Skip `think` tool | Agents use native reasoning — upstream impl is a no-op |
| Skip `finish_scan` | Name collision with `end_scan`, requires tracer integration |
| Skip `todos` | Deferred to future phase |
| Custom Flask app over DVWA/Juice Shop | Predictable, fast, no external image dependency |
| E2E as checklist not script | Manual cross-client testing is inherently manual |
| Single `str_replace_editor` with command param | Matches upstream API — one tool, multiple commands |
| Notes proxied not reimplemented | Upstream sandbox already has working implementation |
| Task 0 verifies sandbox param names first | Upstream uses `path`, MCP uses `file_path` — must verify before coding |
| Integration tests use sandbox.proxy_tool() | Tests the actual sandbox round-trip; MCP wrappers are thin json.dumps layers |
| Linux docker networking documented | `host.docker.internal` needs `extra_hosts` or `host-gateway` on Linux |
