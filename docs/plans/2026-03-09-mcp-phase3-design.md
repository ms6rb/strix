# MCP Phase 3 — Tests, Tools, and E2E Verification

## Goal

Complete the MCP server for upstream PR readiness: add remaining missing tools, build integration tests with a live Docker sandbox, and provide an E2E verification checklist for manual testing across MCP clients.

## Scope

### 1. Missing Tools

**Notes (proxy to sandbox)**
Add 4 tools that proxy to the sandbox's existing notes implementation:
- `create_note(title, content, category?, tags?)` — create an agent scratchpad note
- `list_notes(category?, tags?, search?)` — list/filter notes
- `update_note(note_id, title?, content?, tags?)` — update a note
- `delete_note(note_id)` — delete a note

Parameters and return types mirror upstream exactly. Same proxy pattern as all other forwarded tools.

**str_replace_editor expansion**
The existing `str_replace_editor` tool only accepts the `str_replace` command. Expand to also accept:
- `create` — create a new file
- `view` — read file contents
- `insert` — insert text at a line number

All commands are proxied to the sandbox. Same tool, more commands documented.

**Methodology update**
Add a section to `methodology.md` instructing agents to:
- Use their native web search tool (Claude Code WebSearch, Cursor search, etc.) for CVE lookups, exploit technique research, and bypass documentation
- Use native reasoning capabilities instead of a dedicated `think` tool

This avoids adding external API dependencies (Perplexity) while preserving the capability.

### 2. Integration Tests (Docker)

**Lifecycle tests**
Expand `test_integration.py` with tests covering all proxied tools — terminal, HTTP requests, browser, file operations, notes. Validate the full proxy round-trip.

**Vulnerable target app**
A minimal custom Flask app (~50 lines) with intentional vulnerabilities:
- SQL injection (e.g., unsanitised query parameter in a search endpoint)
- Reflected XSS (e.g., unescaped user input in response)

Runs in a second Docker container alongside the strix sandbox.

**Test infrastructure**
- `docker-compose.test.yml` spins up both the sandbox and the vulnerable app
- pytest fixture handles container lifecycle (start before tests, teardown after)
- Tests assert the full flow: start scan → detect stack → execute tools → create vulnerability reports → chain detection → end scan with summary

### 3. E2E Verification Checklist

A markdown checklist for manual verification across Claude Code, Cursor, and Windsurf:
- MCP server starts via stdio transport
- `start_scan` launches Docker sandbox with target
- Proxied tools work (terminal, browser, HTTP, files, notes)
- `create_vulnerability_report` stores findings with dedup
- `list_vulnerability_reports` and `get_finding` return correct data
- `suggest_chains` detects opportunities after multiple findings
- `dispatch_agent` returns a valid prompt with agent_id
- `end_scan` produces summary JSON + disk files (strix_runs/)
- Per-client MCP config format works (claude_desktop_config.json, .cursor/mcp.json, etc.)

## Out of Scope

- `web_search` — agents use native search capabilities instead
- `think` — agents use native reasoning instead
- `finish_scan` — name collision with `end_scan`, requires tracer integration
- `todos` — deferred to future phase

## Architecture Decisions

1. **Notes are proxied, not reimplemented** — upstream already has working in-memory storage in the sandbox. Proxying keeps behavior identical.
2. **Custom vulnerable app over DVWA/Juice Shop** — predictable, fast tests. No external image dependency. We control the vulns, so assertions are stable.
3. **E2E is a checklist, not a script** — manual testing across 3 different MCP clients is inherently manual. A markdown checklist is the right artifact.
4. **Native capabilities over MCP tools for search/think** — avoids external API dependencies, simpler setup, works across all MCP clients.
