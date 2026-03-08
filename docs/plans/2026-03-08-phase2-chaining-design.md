# Phase 2 Chaining — Design Document

**Goal:** Automatically detect vulnerability chaining opportunities as findings come in, and make dispatching follow-up agents trivial.

**Branch:** `feat/mcp-orchestration`

## Problem

The methodology docs describe 10 chaining patterns (e.g., XSS + missing HttpOnly → account takeover), but there's no code to detect them. The coordinator must manually remember patterns, review all findings, and compose multi-step agent dispatches. This is unreliable and tedious.

## Design

### New file: `strix-mcp/src/strix_mcp/chaining.py`

**ChainRule dataclass:**
```python
@dataclass
class ChainRule:
    finding_a: list[str]   # keywords to match in title/category (any match)
    finding_b: list[str]   # keywords to match in title/category (any match)
    chain_name: str        # e.g. "Account takeover via XSS + missing HttpOnly"
    priority: str          # critical, high
    agent_task: str        # task description for follow-up agent
    modules: list[str]     # modules the follow-up agent should load
```

**10 rules** matching the methodology table:
1. XSS + missing HttpOnly → session hijack (critical)
2. SSRF + internal endpoints → internal service exploitation (critical)
3. IDOR + admin endpoints → privilege escalation (critical)
4. SQLi + auth system → auth bypass + credential dump (critical)
5. Open redirect + OAuth/SSO → token theft (high)
6. File upload + path traversal → RCE via webshell (critical)
7. CSRF + password/email change → account takeover (high)
8. Mass assignment + role/permission field → privilege escalation (critical)
9. Race condition + financial endpoint → balance manipulation (high)
10. Info disclosure + internal IPs → targeted SSRF (high)

**`detect_chains(reports, fired_chains)` function:**
- Normalizes finding titles (reuses `_normalize_title` from tools.py)
- For each rule, checks if any report matches `finding_a` keywords AND any report matches `finding_b` keywords
- Skips rules already in `fired_chains`
- Returns list of newly detected chains

**`_build_agent_prompt(task, modules, agent_id, is_web_only)` function:**
- Two template strings: code target vs web-only
- Fills in `{agent_id}`, `{task}`, `{modules}` placeholders
- Returns a complete prompt ready for the Agent tool

### New tool: `dispatch_agent(task, modules)`

Collapses the current 3-step dispatch process into one tool call:
1. Calls `register_agent` internally
2. Calls `_build_agent_prompt` to generate the prompt
3. Returns `{agent_id, prompt}`

Used for both Phase 1 plan agents and Phase 2 chain agents.

### Modified: `create_vulnerability_report`

After appending a finding, calls `detect_chains(vulnerability_reports, fired_chains)`. If new chains detected, includes them in response:

```json
{
    "report_id": "vuln-abc",
    "chains_detected": [
        {
            "chain_name": "Account takeover via session hijack",
            "priority": "critical",
            "finding_a": "Stored XSS in /comments",
            "finding_b": "Session cookies missing HttpOnly",
            "dispatch": {
                "task": "Chain: XSS + missing HttpOnly → steal sessions",
                "modules": ["xss", "authentication_jwt"]
            }
        }
    ]
}
```

Each chain fires only once — tracked in `fired_chains: set[str]`.

### New tool: `suggest_chains()`

On-demand safety net. Runs same `detect_chains` but returns ALL matches including already-fired (marked as `"dispatched": true`). Used after Phase 1 completes for a full review.

### Modified: `get_scan_status`

Includes `pending_chains` count — chains detected but not yet dispatched. Nudges coordinator to act.

## What this does NOT do

- **Auto-dispatch agents.** The MCP server suggests chains; Claude decides whether to dispatch. The `dispatch_agent` tool makes dispatching trivial but the coordinator stays in control.
- **Replace methodology docs.** The chaining table in methodology.md stays as documentation. The Python rules are the source of truth.

## Test strategy

- Unit tests for `detect_chains` with synthetic reports
- Unit tests for `_build_agent_prompt` template rendering
- Tests that chains fire only once
- Tests that `suggest_chains` returns both fired and unfired
- Integration with existing `create_vulnerability_report` tests
