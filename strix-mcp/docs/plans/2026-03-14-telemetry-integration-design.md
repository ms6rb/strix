# Telemetry Integration Design

> Integrate upstream `strix.telemetry.tracer.Tracer` into the MCP server as the single source of truth for findings, agent lifecycle, and tool execution events.

## Decision: Use Upstream Tracer Directly

The upstream strix project uses a global singleton pattern:
- Entrypoint creates `Tracer(run_name)` and calls `set_global_tracer()`
- All code accesses it via `get_global_tracer()`
- The Tracer stores findings, writes per-vuln markdown/CSV, emits JSONL events, and manages OTEL spans

The MCP will follow this pattern exactly. The MCP's `start_scan` is the equivalent of the CLI/TUI entrypoint.

## Tracer Lifecycle

**`start_scan`:**
- Create `Tracer(run_name=scan_id)`, call `set_global_tracer(tracer)`
- Call `tracer.set_scan_config({"targets": targets, ...})`
- Guard with try/except — if Tracer init fails, continue without telemetry

**`end_scan`:**
- Call `tracer.save_run_data(mark_complete=True)` — writes all output files
- Call `set_global_tracer(None)` to clear for next scan
- Clear `fired_chains` and `notes_storage` (MCP-only state)

## Vulnerability Reports Migration

Replace MCP's in-memory `vulnerability_reports` list with `tracer.vulnerability_reports`.

**`create_vulnerability_report`:**
- MCP keeps title-normalization dedup as pre-check via `tracer.get_existing_vulnerabilities()`
- New findings stored via `tracer.add_vulnerability_report()` — Tracer handles markdown output, JSONL events, posthog
- Merge logic (upgrade severity, append evidence) mutates `tracer.vulnerability_reports` entries directly
- Chain detection reads from `tracer.get_existing_vulnerabilities()`

**`list_vulnerability_reports`:** reads from `tracer.get_existing_vulnerabilities()`.

**`get_finding`:** reads from `tracer.get_run_dir() / "vulnerabilities" / f"{id}.md"`.

## Agent & Tool Event Logging

**`dispatch_agent`:** after `sandbox.register_agent()`, call `tracer.log_agent_creation(agent_id, name, task, parent_id)`.

**Proxy tool logging:** add tracer calls inside `SandboxManager.proxy_tool()` — one integration point covers all 20+ proxied tools:
- Before: `tracer.log_tool_execution_start(agent_id, tool_name, args)` → returns `execution_id`
- After: `tracer.update_tool_execution(execution_id, status, result)`

**`get_scan_status`:** enrich with `tracer.agents` and `tracer.get_real_tool_count()`.

## What Gets Removed

**Functions deleted from `tools.py`:**
- `_write_finding_md()` — Tracer's `save_run_data()` writes per-vuln markdown
- `_write_vuln_csv()` — Tracer writes `vulnerabilities.csv`
- `_write_summary_md()` — Tracer writes `penetration_test_report.md`
- `_get_run_dir()` — use `tracer.get_run_dir()` instead

**Closure variables removed:**
- `vulnerability_reports: list` → `tracer.vulnerability_reports`
- `scan_dir: Path | None` → `tracer.get_run_dir()`

**Closure variables kept:**
- `fired_chains: set[str]` — MCP-only
- `notes_storage: dict` — MCP-only

**Kept but modified:**
- `_normalize_title()`, `_find_duplicate()`, `_deduplicate_reports()` — MCP's title-based dedup
- `_categorize_owasp()`, `_OWASP_KEYWORDS` — used in `end_scan` summary
- `_normalize_severity()`, `_SEVERITY_ORDER` — dedup merge logic

## Error Handling

- Every tracer call guarded with `if tracer:` + try/except
- Tracer init failure in `start_scan` logs warning, scan continues without telemetry
- Proxy tool logging failures don't block tool execution
- Upstream `STRIX_TELEMETRY=0` disables JSONL/OTEL but Tracer still works as in-memory store

## No New Dependencies

`opentelemetry`, `scrubadub` already available transitively via `strix-agent` dependency.

## Testing

- Existing unit tests: mock `get_global_tracer()` returning `None` — behavior unchanged
- New tests: verify tracer integration (agent logging, tool logging, finding storage, file output)
