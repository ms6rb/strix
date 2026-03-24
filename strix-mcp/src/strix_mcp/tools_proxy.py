from __future__ import annotations

import json
from typing import Any, Sequence

from fastmcp import FastMCP
from mcp import types

from .sandbox import SandboxManager


def register_proxy_tools(mcp: FastMCP, sandbox: SandboxManager) -> None:

    @mcp.tool()
    async def terminal_execute(
        command: str,
        timeout: int = 30,
        terminal_id: str = "default",
        is_input: bool = False,
        no_enter: bool = False,
        agent_id: str | None = None,
    ) -> str:
        """Execute a shell command in a persistent Kali Linux terminal session
        inside the sandbox. All security tools (nmap, ffuf, sqlmap, etc.) are available.

        command: the shell command to execute
        timeout: max seconds to wait for output (default 30, capped at 60). Command continues in background after timeout.
        terminal_id: identifier for persistent terminal session (default "default"). Use different IDs for concurrent sessions.
        is_input: if true, send as input to a running process instead of a new command
        no_enter: if true, send the command without pressing Enter
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("terminal_execute", {
            "command": command,
            "timeout": timeout,
            "terminal_id": terminal_id,
            "is_input": is_input,
            "no_enter": no_enter,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

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
        timeout: max seconds to wait for response (default 30)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("send_request", {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "timeout": timeout,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def repeat_request(
        request_id: str,
        modifications: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Replay a captured proxy request with optional modifications.

        request_id: the request ID from list_requests
        modifications: dict with optional keys — url (str), params (dict), headers (dict), body (str), cookies (dict)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Typical workflow: browse with browser_action -> list_requests -> repeat_request with modifications."""
        result = await sandbox.proxy_tool("repeat_request", {
            "request_id": request_id,
            "modifications": modifications,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

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
        sort_order: asc | desc
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {
            "start_page": start_page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_order": sort_order,
        }
        if httpql_filter is not None:
            kwargs["httpql_filter"] = httpql_filter
        if end_page is not None:
            kwargs["end_page"] = end_page
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("list_requests", kwargs)
        return json.dumps(result)

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
        page: page number for paginated responses
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("view_request", {
            "request_id": request_id,
            "part": part,
            "search_pattern": search_pattern,
            "page": page,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

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
        """Control a Playwright browser in the sandbox. Requires browser mode
        (enabled by default in strix-sandbox). Returns a screenshot after each action.

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
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Start with 'launch', end with 'close'."""
        kwargs: dict[str, Any] = {"action": action}
        if url is not None:
            kwargs["url"] = url
        if coordinate is not None:
            kwargs["coordinate"] = coordinate
        if text is not None:
            kwargs["text"] = text
        if js_code is not None:
            kwargs["js_code"] = js_code
        if tab_id is not None:
            kwargs["tab_id"] = tab_id
        if duration is not None:
            kwargs["duration"] = duration
        if key is not None:
            kwargs["key"] = key
        if file_path is not None:
            kwargs["file_path"] = file_path
        if clear:
            kwargs["clear"] = clear
        if agent_id is not None:
            kwargs["agent_id"] = agent_id

        result = await sandbox.proxy_tool("browser_action", kwargs)

        # Build response with screenshot as ImageContent
        content: list[types.TextContent | types.ImageContent] = []

        # Extract screenshot if present
        screenshot_b64 = None
        if isinstance(result, dict):
            screenshot_b64 = result.pop("screenshot", None)

        # Add text content (metadata: url, title, tab info, etc.)
        content.append(
            types.TextContent(type="text", text=json.dumps(result))
        )

        # Add screenshot as image
        if screenshot_b64:
            content.append(
                types.ImageContent(
                    type="image",
                    data=screenshot_b64,
                    mimeType="image/png",
                )
            )

        return content

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
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Proxy functions (send_request, list_requests, etc.) are pre-imported.
        Sessions maintain state (variables, imports) between calls.
        Must call 'new_session' before using 'execute'."""
        kwargs: dict[str, Any] = {"action": action, "timeout": timeout}
        if code is not None:
            kwargs["code"] = code
        if session_id is not None:
            kwargs["session_id"] = session_id
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("python_action", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def list_files(
        directory_path: str = "/workspace",
        depth: int = 3,
        agent_id: str | None = None,
    ) -> str:
        """List files and directories in the sandbox workspace.

        directory_path: path to list (default "/workspace")
        depth: max recursion depth (default 3)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("list_files", {
            "directory_path": directory_path,
            "depth": depth,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def search_files(
        directory_path: str,
        file_pattern: str | None = None,
        search_pattern: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Search file contents in the sandbox workspace.

        directory_path: directory to search in
        file_pattern: glob pattern for file names (e.g. "*.py", "*.js")
        search_pattern: regex pattern to match in file contents
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("search_files", {
            "directory_path": directory_path,
            "file_pattern": file_pattern,
            "search_pattern": search_pattern,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

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
        # Map MCP param "file_path" to upstream sandbox param "path"
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
        scope_name: human-readable scope name (for create/update)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {"action": action}
        if allowlist is not None:
            kwargs["allowlist"] = allowlist
        if denylist is not None:
            kwargs["denylist"] = denylist
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if scope_name is not None:
            kwargs["scope_name"] = scope_name
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("scope_rules", kwargs)
        return json.dumps(result)

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
        page: page number for pagination
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        kwargs: dict[str, Any] = {"depth": depth, "page": page}
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if parent_id is not None:
            kwargs["parent_id"] = parent_id
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("list_sitemap", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def view_sitemap_entry(
        entry_id: str,
        agent_id: str | None = None,
    ) -> str:
        """Get detailed information about a specific sitemap entry and its related HTTP requests.

        entry_id: the sitemap entry ID from list_sitemap
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("view_sitemap_entry", {
            "entry_id": entry_id,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)
