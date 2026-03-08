# Strix MCP Server

MCP server that exposes Strix's Docker security sandbox tools to Claude Code, enabling AI-driven penetration testing directly from your IDE. Eliminates the need to run Strix as a standalone tool.

## Prerequisites

- Docker running
- Python 3.12+

## Installation

```bash
pip install strix-mcp
```

The Docker image (~2GB) is pulled automatically on first scan.

## Claude Code Configuration

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

## Quick Start

Ask Claude Code:

> "Start a security scan on ./my-app and test for OWASP Top 10 vulnerabilities"

Claude will boot a Kali Linux sandbox, copy your code, and begin testing.

## Available Tools

| Tool | Description |
|------|-------------|
| `start_scan` | Boot Docker sandbox with targets |
| `end_scan` | Tear down sandbox, get vulnerability summary |
| `register_agent` | Register subagent for parallel testing |
| `create_vulnerability_report` | Save confirmed vulnerability finding |
| `terminal_execute` | Run commands in persistent Kali terminal |
| `send_request` | Send HTTP request through Caido proxy |
| `repeat_request` | Replay/modify captured proxy requests |
| `list_requests` | Filter proxy traffic with HTTPQL |
| `view_request` | Inspect request/response details |
| `browser_action` | Control Playwright browser (returns screenshots) |
| `python_action` | Run Python in persistent interpreter |
| `list_files` | List sandbox workspace files |
| `search_files` | Search file contents by pattern |
| `str_replace_editor` | Edit files in sandbox |
| `scope_rules` | Manage proxy scope filtering |
| `list_sitemap` | View discovered attack surface |
| `view_sitemap_entry` | Inspect sitemap entry details |

## Available Resources

| Resource | Description |
|----------|-------------|
| `strix://methodology` | Penetration testing playbook |
| `strix://modules` | List available security knowledge modules |
| `strix://modules/{name}` | Get specific module (e.g., sql_injection, xss) |

## Subagent Workflow

Claude Code can spawn parallel security testing agents:

1. Main agent calls `start_scan` to boot the sandbox
2. Each subagent calls `register_agent` to get an isolated session
3. Subagents test different vulnerability classes concurrently
4. Each agent has isolated terminal, browser, and Python sessions
5. Main agent collects results and calls `end_scan`

## Known Limitations

- One scan at a time per MCP server instance
- Heavy dependency on `strix-agent` package (acceptable for v0.1, future vendoring planned)
- First scan requires Docker image pull (~2GB)
