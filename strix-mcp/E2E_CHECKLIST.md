# MCP E2E Verification Checklist

Manual verification steps for testing strix-mcp across MCP clients.

## Prerequisites

- [ ] Docker running
- [ ] Sandbox image pulled: `docker pull ghcr.io/usestrix/strix-sandbox:0.1.12`
- [ ] strix-mcp installed: `cd strix-mcp && pip install -e .`

## Claude Code

Config in `.mcp.json` or `~/.claude/mcp_servers.json`:
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
- [ ] `terminal_execute` runs commands (e.g. `whoami` returns `pentester`)
- [ ] `browser_action` with `launch` then `goto` returns screenshots
- [ ] `send_request` sends HTTP through proxy and returns response
- [ ] `list_requests` shows captured proxy traffic
- [ ] `str_replace_editor` with `create` creates files in sandbox
- [ ] `str_replace_editor` with `view` reads files from sandbox
- [ ] `str_replace_editor` with `str_replace` edits files in sandbox
- [ ] `create_note` creates a note and returns note_id
- [ ] `list_notes` shows created notes with category filtering
- [ ] `update_note` modifies note content
- [ ] `delete_note` removes a note
- [ ] `create_vulnerability_report` stores finding and returns report_id
- [ ] `list_vulnerability_reports` shows filed reports
- [ ] `get_finding` returns full markdown detail from disk
- [ ] `dispatch_agent` returns agent_id + ready-to-use prompt
- [ ] `suggest_chains` returns chain opportunities (after 2+ findings)
- [ ] `get_scan_status` shows elapsed time, agents, and severity counts
- [ ] `get_module` loads a security knowledge module (e.g. "sql_injection")
- [ ] `list_modules` returns module catalog with categories
- [ ] `end_scan` returns summary with OWASP grouping and severity counts
- [ ] `strix_runs/` directory created with `vulnerabilities/*.md`, `vulnerabilities.csv`, and `summary.md`

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
- [ ] `create_vulnerability_report` and `list_vulnerability_reports` work
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

- [ ] Run `docker ps` — no orphaned strix containers remain after `end_scan`
- [ ] Second scan starts cleanly after first ends
- [ ] `strix_runs/` contains expected files from the scan
