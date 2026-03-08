# Strix MCP UX Improvements — Design

## Goal

Make `strix-mcp` user-friendly and upstream-ready for a PR into `usestrix/strix`.

## Changes

### 1. Tool Rename

- `end_scan` → `finish_scan` (match original strix naming)
- Remove `register_agent` as a public tool (keep as internal function, `dispatch_agent` calls it)

### 2. Tool Descriptions

**Proxied tools (14):** Mirror descriptions from original strix tool definitions (`strix/tools/*/`).

**MCP-only tools (9):** Clear descriptions positioning them as orchestration layer:

- `start_scan`, `finish_scan` — lifecycle
- `dispatch_agent`, `get_scan_status` — orchestration
- `create_vulnerability_report`, `list_vulnerability_reports`, `get_finding` — findings
- `get_module`, `list_modules` — knowledge
- `suggest_chains` — chaining

### 3. Parameter Documentation

- Add explicit enum values: `browser_action` action literals, `python_action` actions, `scope_rules` actions
- Match parameter descriptions to originals for proxied tools
- Document `repeat_request` modifications structure
- Clarify `browser_action` param-to-action mapping

### 4. Documentation

**`strix-mcp/README.md`:**

- Setup instructions for Claude Code, Cursor, Windsurf, generic MCP clients
- Prerequisites (Docker, strix package)
- Coverage table: proxied tools, MCP-only orchestration, not-yet-supported (notes, todos, think, web_search, agent graph)
- "Not yet supported" doubles as roadmap

**Root `README.md`:**

- One section pointing to `strix-mcp/` as MCP server extension

### 5. Out of Scope

- No code restructuring beyond rename + removal
- No new tool implementations
- No changes to methodology.md, chaining.py, stack_detector.py, sandbox.py, resources.py
