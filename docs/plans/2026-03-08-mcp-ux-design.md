# Strix MCP UX Improvements — Design

> **Superseded by:** `docs/plans/2026-03-08-mcp-ux-plan.md` (implementation plan)

## Goal

Make `strix-mcp` user-friendly and upstream-ready for a PR into `usestrix/strix`.

## Decisions

- `end_scan` keeps its name — the original strix `finish_scan` is a different tool (agent submits executive summary with 4 required params). Renaming would create a naming collision.
- `register_agent` removed as public tool — `dispatch_agent` handles registration internally.
- `create_vulnerability_report` is an MCP-only tool (not proxied) — simplified interface with dedup + chain detection. The native strix version has 9 required params (CVSS XML, PoC code, etc.).
- `str_replace_editor` is proxied but with reduced interface — only str_replace, not create/view/insert.

## Changes

### 1. Tool Removal

- Remove `register_agent` as a public tool (keep as internal function, `dispatch_agent` calls it)

### 2. Tool Descriptions

**Proxied tools (13):** Mirror descriptions from original strix tool definitions (`strix/tools/*/`).

**MCP-only tools (10):** Clear descriptions positioning them as orchestration layer:

- `start_scan`, `end_scan` — lifecycle
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
- Coverage table: proxied tools (13), MCP-only orchestration (10), not-yet-supported (notes, todos, think, web_search, agent graph, native finish_scan, native create_vulnerability_report)
- `str_replace_editor` noted as partial parity (str_replace only, no create/view/insert)
- "Not yet supported" doubles as roadmap

**Root `README.md`:**

- One section pointing to `strix-mcp/` as MCP server extension

### 5. Metadata

- `pyproject.toml`: add `strix-agent` dependency, update description to be client-agnostic
- `server.py`: improve resource descriptions

### 6. Out of Scope

- No code restructuring beyond removal
- No new tool implementations
- No changes to chaining.py, stack_detector.py, sandbox.py, resources.py
