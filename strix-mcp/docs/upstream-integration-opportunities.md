# Upstream Integration Opportunities

> Analysis of upstream `usestrix/strix` capabilities the MCP could better leverage.
> Date: 2026-03-14 | Upstream ref: `1404864` (feat: interactive mode)

---

## High Value

### 1. Telemetry / Tracing (biggest gap)

Upstream has full OpenTelemetry with JSONL event logging (`strix/telemetry/tracer.py`, `utils.py`):
- Agent lifecycle: `log_agent_creation()`, `update_agent_status()` (running/waiting/completed/failed)
- Tool execution: `log_tool_execution_start()`, `update_tool_execution()`
- Chat messages: `log_chat_message()` with role/content/agent_id
- Sanitization: `TelemetrySanitizer` redacts API keys, tokens, secrets
- Persistence: JSONL to `strix_runs/<run_id>/events.jsonl`
- Vulnerability callback: `vulnerability_found_callback` hook for real-time notifications

**MCP currently:** In-memory findings list, no event logging, no audit trail.

**Integration plan:**
- Initialize `Tracer` in `start_scan()` with `set_global_tracer()`
- Call `tracer.log_agent_creation()` in `dispatch_agent()`
- Wrap MCP tool proxy calls with `log_tool_execution_start()` / `update_tool_execution()`
- Export event logs + agent graph in `end_scan()`
- Expose events as resource: `strix://trace/<scan_id>/events`

**Key files:**
- `strix/telemetry/tracer.py` — Tracer class, all logging methods
- `strix/telemetry/utils.py` — TelemetrySanitizer, append_jsonl_record

---

### 2. Agent Graph Visibility

Upstream tracks agent relationships via `_agent_graph` in `agents_graph_actions.py`:
- Nodes: agent_id, name, task, parent_id, status
- Edges: delegation and messaging relationships
- `view_agent_graph()` returns full orchestration tree

**MCP currently:** Creates agents via `dispatch_agent()` but has no way to visualize the scan structure.

**Integration plan:**
- Expose `view_agent_graph()` as MCP tool
- Build graph from `ScanState.registered_agents` + dispatch metadata
- Include in `get_scan_status()` response

---

### 3. Scan Mode Control

Upstream supports `quick` / `standard` / `deep` modes:
- Affects reasoning effort, iteration limits, tool selection
- Per-agent via `LLMConfig.scan_mode`
- Validated: must be one of the three values

**MCP currently:** Always runs deep mode, no way to switch during scan.

**Integration plan:**
- Add `set_scan_mode(mode)` tool
- Store mode in `ScanState`, pass to `dispatch_agent()` prompt
- Adjust agent iteration hints based on mode

---

## Medium Value

### 4. Inter-agent Messaging

Upstream has `send_message_to_agent()` / `wait_for_message()`:
- Priority-based message queue per agent
- Delivery tracking with read status
- XML-formatted message delivery in conversation
- Agents can collaborate without file I/O

**MCP currently:** Agents communicate only through shared `/workspace` files.

**Integration plan:**
- Expose `send_message_to_agent(target_id, message)` tool
- Expose `wait_for_message(timeout)` tool
- Route through sandbox tool server or implement MCP-side

---

### 5. Skill Validation

Upstream enforces:
- Max 5 skills per agent (in `create_agent()`)
- Blocked internal categories: `scan_modes/`, `coordination/`
- `validate_skill_names()` checks availability before agent creation

**MCP currently:** No validation — allows unlimited skills, doesn't block internal categories.

**Integration plan:**
- Validate module count in `dispatch_agent()` (max 5)
- Reject `scan_modes/*` and `coordination/*` in module selection
- Call upstream `validate_skill_names()` or replicate logic

---

### 6. Config Integration

Upstream reads `~/.strix/cli-config.json` via `Config` class:
- LLM settings: model, API key, base URL, reasoning effort, timeout
- Runtime: sandbox image, execution timeout, connect timeout
- Tools: disable browser, Perplexity API key
- Telemetry flags

**MCP currently:** Inherits env vars but doesn't read config file.

**Integration plan:**
- Read `Config.load()` on MCP startup
- Document which `STRIX_*` env vars apply to MCP
- Optionally expose `set_config(key, value)` tool

---

## Low Value (MCP approach is better)

### Native `create_agent()`
Upstream spawns agents in threads with `LLMConfig` + litellm. The MCP's prompt-based dispatch through the host AI (Claude Code/Cursor) is more flexible — it uses the host's model, permissions, and tool approval.

### LLM Wrapper
The MCP deliberately doesn't use upstream's litellm wrapper. The host AI handles LLM calls, model selection, and cost. Adding litellm would duplicate this.

### Memory Compression
Upstream has `MemoryCompressor` for long conversations. MCP agents are short-lived subagents dispatched by the host — the host handles its own context management.

---

## Implementation Priority

| Phase | Items | Enables |
|-------|-------|---------|
| **Phase 1** | Tracer init, agent creation logging, tool execution logging, event export | Observability, debugging, audit trail |
| **Phase 2** | Agent graph tool, scan mode control, skill validation | Orchestration visibility, user control |
| **Phase 3** | Inter-agent messaging, config integration | Agent collaboration, persistence |
