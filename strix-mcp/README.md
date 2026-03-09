# Strix MCP Server

MCP (Model Context Protocol) server that exposes Strix's Docker security sandbox to AI coding agents. Works with any MCP-compatible client — Claude Code, Cursor, Windsurf, Cline, and others.

## Prerequisites

- Docker (running)
- Python 3.12+

## Installation

```bash
pip install strix-mcp
```

Pull the Docker image before your first scan:

```bash
docker pull ghcr.io/usestrix/strix-sandbox:0.1.12
```

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

## Workflow

1. `start_scan` — boot sandbox, detect tech stack, get recommended scan plan
2. `dispatch_agent` — for each testing area, register a subagent and get a ready-to-use prompt
3. Pass each prompt to your AI agent's sub-agent/tool system — agents test in parallel with isolated sessions
4. Agents file findings with `create_vulnerability_report` (auto-dedup, auto-chain detection)
5. `suggest_chains` — review chaining opportunities, dispatch follow-up agents
6. `end_scan` — tear down sandbox, get deduplicated OWASP-categorized summary

## Strix Feature Coverage

This MCP server exposes Strix's sandbox tools to external AI agents. Below is the coverage map against the full Strix tool suite.

### Proxied Tools

These tools are forwarded directly to the Strix sandbox container — same behavior as native Strix.

| Tool | Description | Parity |
|------|-------------|--------|
| `terminal_execute` | Execute commands in persistent Kali Linux terminal | Full |
| `send_request` | Send HTTP requests through Caido proxy | Full |
| `repeat_request` | Replay captured requests with modifications | Full |
| `list_requests` | Filter proxy traffic with HTTPQL | Full |
| `view_request` | Inspect request/response details | Full |
| `browser_action` | Control Playwright browser (returns screenshots) | Full |
| `python_action` | Run Python in persistent interpreter sessions | Full |
| `list_files` | List sandbox workspace files | Full |
| `search_files` | Search file contents by pattern | Full |
| `str_replace_editor` | Edit files in sandbox | Full |
| `scope_rules` | Manage proxy scope filtering | Full |
| `list_sitemap` | View discovered attack surface | Full |
| `view_sitemap_entry` | Inspect sitemap entry details | Full |

### MCP Orchestration Layer

Tools implemented by the MCP server for AI agent coordination — not proxied from the Strix sandbox.

| Tool | Description |
|------|-------------|
| `start_scan` | Boot sandbox, detect tech stack, generate scan plan |
| `end_scan` | Tear down sandbox, deduplicate findings, OWASP summary |
| `create_vulnerability_report` | File findings with auto-dedup, chain detection, and disk persistence (simplified interface vs native) |
| `dispatch_agent` | Register subagent and compose ready-to-use prompt |
| `get_scan_status` | Monitor scan progress and pending chains |
| `list_vulnerability_reports` | List filed reports (summaries, deduplication check) |
| `get_finding` | Read full finding details from disk |
| `get_module` | Load security knowledge module |
| `list_modules` | List available knowledge modules |
| `suggest_chains` | Review vulnerability chaining opportunities |
| `create_note` | Create structured notes during scans |
| `list_notes` | List and filter scan notes |
| `update_note` | Update existing notes |
| `delete_note` | Delete notes |

### Not Yet Supported

These Strix tools are not yet available through the MCP server.

| Tool | Category | Notes |
|------|----------|-------|
| `create_todo` / `list_todos` / `update_todo` / `mark_todo_done` / `mark_todo_pending` / `delete_todo` | Todos | Task tracking within scans |
| `think` | Analysis | Record reasoning and analysis steps |
| `web_search` | Reconnaissance | Search via Perplexity AI for security intelligence |
| `finish_scan` | Completion | Native scan finalization with executive summary, methodology, and recommendations |
| `create_vulnerability_report` (native) | Reporting | Full CVSS XML breakdown, CWE/CVE, code locations, PoC scripts (MCP uses simplified interface) |
| `view_agent_graph` / `create_agent` / `send_message_to_agent` / `agent_finish` / `wait_for_message` | Agent Graph | Native multi-agent orchestration (MCP uses `dispatch_agent` instead) |

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
- Requires Docker image pull before first scan (see Installation)
- Agent graph tools not supported — MCP uses its own orchestration via `dispatch_agent`
