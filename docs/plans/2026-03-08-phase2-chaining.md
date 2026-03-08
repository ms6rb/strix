# Phase 2 Chaining Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Automatically detect vulnerability chaining opportunities as findings arrive, and provide a `dispatch_agent` tool that makes dispatching follow-up agents trivial.

**Architecture:** New `chaining.py` module with chain rules as data + detection logic + agent prompt templates. `create_vulnerability_report` calls `detect_chains` after each finding. New `dispatch_agent` and `suggest_chains` tools in `tools.py`. All pure logic is testable without Docker.

**Tech Stack:** Python 3, FastMCP, pytest

**Test command:** `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`

---

### Task 1: Chain rules and detection logic

**Files:**
- Create: `strix-mcp/src/strix_mcp/chaining.py`
- Test: `strix-mcp/tests/test_chaining.py`

**Step 1: Write the failing tests**

Create `strix-mcp/tests/test_chaining.py`:

```python
import pytest
from strix_mcp.chaining import CHAIN_RULES, ChainRule, detect_chains


class TestChainRules:
    def test_chain_rules_is_list(self):
        """CHAIN_RULES should be a non-empty list of ChainRule."""
        assert isinstance(CHAIN_RULES, list)
        assert len(CHAIN_RULES) >= 10

    def test_chain_rules_have_required_fields(self):
        """Every rule should have all required fields."""
        for rule in CHAIN_RULES:
            assert isinstance(rule, ChainRule)
            assert len(rule.finding_a) > 0
            assert len(rule.finding_b) > 0
            assert rule.chain_name
            assert rule.priority in ("critical", "high")
            assert rule.agent_task
            assert len(rule.modules) > 0

    def test_chain_rules_no_duplicate_names(self):
        """Chain names should be unique."""
        names = [r.chain_name for r in CHAIN_RULES]
        assert len(names) == len(set(names))


class TestDetectChains:
    def test_detects_xss_httponly_chain(self):
        """XSS + missing HttpOnly should trigger session hijack chain."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) >= 1
        names = [c["chain_name"] for c in chains]
        assert any("session hijack" in n.lower() for n in names)

    def test_detects_ssrf_internal_chain(self):
        """SSRF + internal endpoints should trigger internal exploitation chain."""
        reports = [
            {"title": "SSRF via image URL parameter", "severity": "high"},
            {"title": "Internal API endpoints discovered", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        names = [c["chain_name"] for c in chains]
        assert any("internal" in n.lower() for n in names)

    def test_detects_sqli_auth_chain(self):
        """SQL injection + auth system should trigger auth bypass chain."""
        reports = [
            {"title": "SQL Injection in search parameter", "severity": "critical"},
            {"title": "JWT authentication system identified", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        names = [c["chain_name"] for c in chains]
        assert any("auth bypass" in n.lower() or "credential" in n.lower() for n in names)

    def test_no_chain_with_single_finding(self):
        """A single finding should not trigger any chain."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) == 0

    def test_no_chain_with_unrelated_findings(self):
        """Unrelated findings should not trigger chains."""
        reports = [
            {"title": "Missing CSP header", "severity": "low"},
            {"title": "Server version disclosed", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) == 0

    def test_fired_chains_not_repeated(self):
        """Already-fired chains should not appear again."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        # First call fires the chain
        fired: set[str] = set()
        chains1 = detect_chains(reports, fired=fired)
        assert len(chains1) >= 1

        # Second call with same fired set returns nothing new
        chains2 = detect_chains(reports, fired=fired)
        assert len(chains2) == 0

    def test_chain_result_has_dispatch_payload(self):
        """Each detected chain should include a dispatch payload with task and modules."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        chains = detect_chains(reports, fired=set())
        for chain in chains:
            assert "chain_name" in chain
            assert "priority" in chain
            assert "finding_a" in chain
            assert "finding_b" in chain
            assert "dispatch" in chain
            assert "task" in chain["dispatch"]
            assert "modules" in chain["dispatch"]

    def test_chain_finding_references_actual_titles(self):
        """finding_a and finding_b should reference the actual report titles that matched."""
        reports = [
            {"title": "Reflected XSS in search", "severity": "medium"},
            {"title": "Cookies without HttpOnly", "severity": "low"},
        ]
        chains = detect_chains(reports, fired=set())
        if chains:
            chain = chains[0]
            assert chain["finding_a"] in [r["title"] for r in reports]
            assert chain["finding_b"] in [r["title"] for r in reports]
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py -v --tb=short -o "addopts="`
Expected: FAIL — module does not exist

**Step 3: Implement chaining.py**

Create `strix-mcp/src/strix_mcp/chaining.py`:

```python
"""Vulnerability chaining rules and detection logic.

Detects when two findings combine into a higher-severity attack chain
and provides dispatch payloads for follow-up agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainRule:
    finding_a: list[str]
    finding_b: list[str]
    chain_name: str
    priority: str
    agent_task: str
    modules: list[str]


CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        finding_a=["xss"],
        finding_b=["httponly", "cookie without", "session cookie", "missing httponly"],
        chain_name="Account takeover via session hijack",
        priority="critical",
        agent_task="Chain: XSS + missing HttpOnly cookies. Exploit the XSS to steal session cookies and demonstrate account takeover. Attempt to hijack an authenticated session using the XSS payload.",
        modules=["xss", "authentication_jwt"],
    ),
    ChainRule(
        finding_a=["ssrf"],
        finding_b=["internal", "endpoint discovered", "api enumerat"],
        chain_name="Internal service exploitation via SSRF",
        priority="critical",
        agent_task="Chain: SSRF + internal endpoints discovered. Use the SSRF to access internal services and cloud metadata (169.254.169.254). Attempt to exfiltrate sensitive data from internal APIs.",
        modules=["ssrf"],
    ),
    ChainRule(
        finding_a=["idor"],
        finding_b=["admin", "privileged", "elevated", "role"],
        chain_name="Privilege escalation via IDOR to admin data",
        priority="critical",
        agent_task="Chain: IDOR + admin/privileged endpoints. Use the IDOR to access admin-level data or functionality. Demonstrate cross-role data access and privilege escalation.",
        modules=["idor", "broken_function_level_authorization"],
    ),
    ChainRule(
        finding_a=["sqli", "sql injection"],
        finding_b=["authentication", "auth", "jwt", "login"],
        chain_name="Auth bypass via SQL injection",
        priority="critical",
        agent_task="Chain: SQL injection + authentication system. Attempt to bypass authentication via SQLi, dump credentials, or forge authentication tokens.",
        modules=["sql_injection", "authentication_jwt"],
    ),
    ChainRule(
        finding_a=["open redirect"],
        finding_b=["oauth", "sso", "openid", "saml"],
        chain_name="Token theft via redirect manipulation",
        priority="high",
        agent_task="Chain: Open redirect + OAuth/SSO flow. Manipulate the redirect to steal OAuth tokens or authorization codes during the SSO flow.",
        modules=["open_redirect", "authentication_jwt"],
    ),
    ChainRule(
        finding_a=["file upload"],
        finding_b=["path traversal", "lfi", "local file inclusion"],
        chain_name="RCE via uploaded webshell",
        priority="critical",
        agent_task="Chain: File upload + path traversal. Upload a webshell and use path traversal to place it in a web-accessible directory. Demonstrate remote code execution.",
        modules=["insecure_file_uploads", "path_traversal_lfi_rfi", "rce"],
    ),
    ChainRule(
        finding_a=["csrf"],
        finding_b=["password change", "email change", "password reset", "account settings"],
        chain_name="Account takeover via forced password reset",
        priority="high",
        agent_task="Chain: CSRF + password/email change endpoint. Craft a CSRF exploit that forces a victim to change their password or email, leading to account takeover.",
        modules=["csrf", "authentication_jwt"],
    ),
    ChainRule(
        finding_a=["mass assignment"],
        finding_b=["role", "permission", "admin", "is_admin", "isadmin", "privilege"],
        chain_name="Privilege escalation via mass assignment",
        priority="critical",
        agent_task="Chain: Mass assignment + role/permission field. Exploit mass assignment to set admin or elevated role fields. Demonstrate privilege escalation.",
        modules=["mass_assignment", "broken_function_level_authorization"],
    ),
    ChainRule(
        finding_a=["race condition"],
        finding_b=["financial", "transaction", "balance", "payment", "transfer", "credit"],
        chain_name="Balance manipulation via race condition",
        priority="high",
        agent_task="Chain: Race condition + financial endpoint. Exploit the race condition to perform double-spend, balance manipulation, or limit bypass on financial transactions.",
        modules=["race_conditions", "business_logic"],
    ),
    ChainRule(
        finding_a=["information disclosure", "info disclosure", "version disclosed", "stack trace", "debug"],
        finding_b=["internal ip", "internal service", "internal api", "10.", "172.", "192.168"],
        chain_name="Targeted SSRF to internal services",
        priority="high",
        agent_task="Chain: Information disclosure + internal IPs/services leaked. Use the disclosed internal addresses to craft targeted SSRF attacks against internal infrastructure.",
        modules=["ssrf", "information_disclosure"],
    ),
]


def _title_matches(title: str, keywords: list[str]) -> bool:
    """Check if a normalized title matches any of the keywords."""
    t = title.lower().strip()
    return any(kw in t for kw in keywords)


def detect_chains(
    reports: list[dict[str, Any]],
    fired: set[str],
) -> list[dict[str, Any]]:
    """Detect chaining opportunities from current findings.

    Parameters
    ----------
    reports:
        List of vulnerability reports (each has at least 'title' and 'severity').
    fired:
        Set of chain_names already fired. Newly detected chains are added to this set.

    Returns
    -------
    List of newly detected chains, each with chain_name, priority,
    finding_a, finding_b, and dispatch payload.
    """
    detected: list[dict[str, Any]] = []

    for rule in CHAIN_RULES:
        if rule.chain_name in fired:
            continue

        # Find matching reports for each side
        match_a = None
        match_b = None
        for report in reports:
            title = report.get("title", "")
            if match_a is None and _title_matches(title, rule.finding_a):
                match_a = report
            if match_b is None and _title_matches(title, rule.finding_b):
                match_b = report

        # Both sides must match, and they must be different reports
        if match_a is not None and match_b is not None and match_a is not match_b:
            fired.add(rule.chain_name)
            detected.append({
                "chain_name": rule.chain_name,
                "priority": rule.priority,
                "finding_a": match_a["title"],
                "finding_b": match_b["title"],
                "dispatch": {
                    "task": rule.agent_task,
                    "modules": rule.modules,
                },
            })

    return detected
```

**Step 4: Run tests**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 5: Run full test suite**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/chaining.py strix-mcp/tests/test_chaining.py
git commit -m "feat(mcp): add chaining rules and detect_chains logic"
```

---

### Task 2: Agent prompt templates and `_build_agent_prompt`

**Files:**
- Modify: `strix-mcp/src/strix_mcp/chaining.py`
- Test: `strix-mcp/tests/test_chaining.py`

**Step 1: Write the failing tests**

In `strix-mcp/tests/test_chaining.py`, add:

```python
from strix_mcp.chaining import build_agent_prompt


class TestBuildAgentPrompt:
    def test_code_target_prompt_contains_agent_id(self):
        """Code target prompt should include the agent_id."""
        prompt = build_agent_prompt(
            task="Test IDOR",
            modules=["idor"],
            agent_id="mcp_agent_1",
        )
        assert 'agent_id="mcp_agent_1"' in prompt

    def test_code_target_prompt_contains_modules(self):
        """Prompt should list get_module calls for each module."""
        prompt = build_agent_prompt(
            task="Test auth",
            modules=["authentication_jwt", "idor"],
            agent_id="mcp_agent_1",
        )
        assert 'get_module("authentication_jwt")' in prompt
        assert 'get_module("idor")' in prompt

    def test_code_target_prompt_contains_task(self):
        """Prompt should include the task description."""
        prompt = build_agent_prompt(
            task="Test SQL injection in login",
            modules=["sql_injection"],
            agent_id="mcp_agent_2",
        )
        assert "Test SQL injection in login" in prompt

    def test_code_target_prompt_has_workspace(self):
        """Default (code target) prompt should reference /workspace."""
        prompt = build_agent_prompt(
            task="Test XSS",
            modules=["xss"],
            agent_id="mcp_agent_1",
        )
        assert "/workspace" in prompt

    def test_web_only_prompt_no_workspace_analysis(self):
        """Web-only prompt should NOT tell agent to analyze source code."""
        prompt = build_agent_prompt(
            task="Test XSS",
            modules=["xss"],
            agent_id="mcp_agent_1",
            is_web_only=True,
        )
        assert "source code" not in prompt.lower() or "no source code" in prompt.lower()
        assert "browser_action" in prompt

    def test_web_only_prompt_mentions_live_target(self):
        """Web-only prompt should mention live web application."""
        prompt = build_agent_prompt(
            task="Test SSRF",
            modules=["ssrf"],
            agent_id="mcp_agent_1",
            is_web_only=True,
        )
        assert "LIVE" in prompt or "live" in prompt

    def test_chain_prompt_includes_context(self):
        """When chain_context is provided, prompt should include Phase 1 findings."""
        prompt = build_agent_prompt(
            task="Chain: XSS + HttpOnly → session hijack",
            modules=["xss", "authentication_jwt"],
            agent_id="mcp_agent_3",
            chain_context={
                "finding_a": "Stored XSS in /comments",
                "finding_b": "Session cookies missing HttpOnly",
                "chain_name": "Account takeover via session hijack",
            },
        )
        assert "Stored XSS in /comments" in prompt
        assert "Session cookies missing HttpOnly" in prompt
        assert "session hijack" in prompt.lower()
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py::TestBuildAgentPrompt -v --tb=short -o "addopts="`
Expected: FAIL — `build_agent_prompt` does not exist

**Step 3: Implement `build_agent_prompt` in chaining.py**

Add to `strix-mcp/src/strix_mcp/chaining.py`:

```python
_CODE_TARGET_TEMPLATE = """You are a security testing specialist. Your target code is at /workspace.

**FIRST — Load your knowledge modules:**
Call the `get_module` tool for each of these modules and read the full content carefully. They contain advanced exploitation techniques, bypass methods, and validation requirements that you MUST use:
{module_list}

**Use `agent_id="{agent_id}"` for ALL Strix tool calls** (terminal_execute, browser_action, send_request, python_action, list_files, search_files, etc.)

**YOUR TASK:** {task}
{chain_section}
**APPROACH:**
1. Read your module(s) fully — they are your primary testing guide, not generic knowledge
2. Analyze the source code in /workspace for this vulnerability class using terminal_execute, search_files, list_files
3. Start the target application if possible and test dynamically
4. Test dynamically against the running app using send_request, repeat_request, browser_action
5. Use established tools where appropriate: nuclei, sqlmap, ffuf, jwt_tool, semgrep
6. Never rely solely on static analysis — always attempt dynamic testing
7. Validate all findings with proof of exploitation — demonstrate concrete impact
8. Check `list_vulnerability_reports` before filing to avoid duplicates
9. File findings with `create_vulnerability_report` — include `affected_endpoint` and `cvss_score` when possible
10. Return your findings as a structured list with: title, severity, evidence, and remediation"""

_WEB_ONLY_TEMPLATE = """You are a security testing specialist. Your target is a LIVE WEB APPLICATION — there is no source code to review.

**FIRST — Load your knowledge modules:**
Call the `get_module` tool for each of these modules and read the full content carefully:
{module_list}

**Use `agent_id="{agent_id}"` for ALL Strix tool calls.**

**YOUR TASK:** {task}
{chain_section}
**APPROACH (web-only — no source code):**
1. Read your module(s) fully — they are your primary testing guide
2. Explore the target with `browser_action`: launch → goto target URL → crawl key pages → capture screenshots
3. Review captured proxy traffic with `list_requests` to map the attack surface
4. Test dynamically:
   - Use `send_request` and `repeat_request` for API-level testing
   - Use `browser_action` for UI-level testing (forms, uploads, client-side behavior)
   - Use `terminal_execute` to run automated scanners: nuclei, sqlmap, ffuf, wapiti
   - Use `python_action` for custom exploit scripts and concurrency
5. For reconnaissance: run `ffuf` for directory/endpoint discovery, `nuclei` with relevant templates
6. Check `list_vulnerability_reports` before filing to avoid duplicates
7. Validate all findings with proof of exploitation — demonstrate concrete impact
8. File findings with `create_vulnerability_report` — include `affected_endpoint` and `cvss_score` when possible
9. Return your findings as a structured list with: title, severity, evidence, and remediation"""

_CHAIN_CONTEXT_SECTION = """
**CHAIN CONTEXT — Phase 1 agents found these related vulnerabilities:**
- Finding A: {finding_a}
- Finding B: {finding_b}
Your goal: combine these into **{chain_name}**. Attempt the full exploit chain and report the combined severity.
"""


def build_agent_prompt(
    task: str,
    modules: list[str],
    agent_id: str,
    is_web_only: bool = False,
    chain_context: dict[str, str] | None = None,
) -> str:
    """Build a complete agent prompt from templates.

    Parameters
    ----------
    task:
        Task description for the agent.
    modules:
        List of module names the agent should load.
    agent_id:
        The registered agent_id for tool calls.
    is_web_only:
        If True, use the web-only template (no source code).
    chain_context:
        Optional dict with 'finding_a', 'finding_b', 'chain_name'
        for Phase 2 chain agents.
    """
    module_list = "\n".join(f'- get_module("{m}")' for m in modules)

    chain_section = ""
    if chain_context:
        chain_section = _CHAIN_CONTEXT_SECTION.format(
            finding_a=chain_context["finding_a"],
            finding_b=chain_context["finding_b"],
            chain_name=chain_context["chain_name"],
        )

    template = _WEB_ONLY_TEMPLATE if is_web_only else _CODE_TARGET_TEMPLATE
    return template.format(
        module_list=module_list,
        agent_id=agent_id,
        task=task,
        chain_section=chain_section,
    )
```

**Step 4: Run tests**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 5: Run full test suite**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/chaining.py strix-mcp/tests/test_chaining.py
git commit -m "feat(mcp): add agent prompt templates and build_agent_prompt"
```

---

### Task 3: `dispatch_agent` tool

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:190-192,325-340`
- Test: `strix-mcp/tests/test_chaining.py`

**Step 1: Write the failing test**

In `strix-mcp/tests/test_chaining.py`, add:

```python
from strix_mcp.chaining import build_agent_prompt


class TestDispatchAgentPromptIntegration:
    def test_dispatch_builds_valid_prompt(self):
        """Simulating what dispatch_agent does: register + build prompt."""
        agent_id = "mcp_agent_1"
        task = "Test IDOR and access control"
        modules = ["idor", "broken_function_level_authorization"]

        prompt = build_agent_prompt(task=task, modules=modules, agent_id=agent_id)

        # The prompt should be a non-empty string with all key pieces
        assert isinstance(prompt, str)
        assert len(prompt) > 200
        assert agent_id in prompt
        assert task in prompt
        for m in modules:
            assert m in prompt

    def test_dispatch_chain_agent_builds_context_prompt(self):
        """Chain dispatch should include both findings in the prompt."""
        agent_id = "mcp_agent_5"
        chain = {
            "chain_name": "Account takeover via session hijack",
            "priority": "critical",
            "finding_a": "Stored XSS in /comments",
            "finding_b": "Session cookies missing HttpOnly",
            "dispatch": {
                "task": "Chain: XSS + HttpOnly → session hijack",
                "modules": ["xss", "authentication_jwt"],
            },
        }

        prompt = build_agent_prompt(
            task=chain["dispatch"]["task"],
            modules=chain["dispatch"]["modules"],
            agent_id=agent_id,
            chain_context={
                "finding_a": chain["finding_a"],
                "finding_b": chain["finding_b"],
                "chain_name": chain["chain_name"],
            },
        )

        assert "Stored XSS in /comments" in prompt
        assert "Session cookies missing HttpOnly" in prompt
        assert agent_id in prompt
```

These tests validate the integration pattern. The actual `dispatch_agent` tool is async and calls `sandbox.register_agent()`, so it can only be tested in integration. But we test the logic it wraps.

**Step 2: Run tests to verify they pass** (these use already-implemented `build_agent_prompt`)

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py::TestDispatchAgentPromptIntegration -v --tb=short -o "addopts="`
Expected: PASS (build_agent_prompt already exists from Task 2)

**Step 3: Add `dispatch_agent` and `suggest_chains` tools to tools.py**

In `strix-mcp/src/strix_mcp/tools.py`, inside `register_tools()`, after `scan_dir: Path | None = None` (line 192), add:

```python
    fired_chains: set[str] = set()
```

Then after the `list_modules` tool (around line 460), add:

```python
    @mcp.tool()
    async def dispatch_agent(
        task: str,
        modules: list[str],
        is_web_only: bool = False,
        chain_context: dict[str, str] | None = None,
    ) -> str:
        """Register a new agent and return a ready-to-use prompt for the Agent tool.

        This simplifies agent dispatch: instead of calling register_agent + manually
        composing a prompt, call this once and pass the returned prompt to the Agent tool.

        task: what the agent should test (e.g. 'Test IDOR and access control')
        modules: list of module names the agent should load (e.g. ['idor', 'authentication_jwt'])
        is_web_only: set True for web-only targets (no source code in /workspace)
        chain_context: optional dict with 'finding_a', 'finding_b', 'chain_name' for Phase 2 chain agents"""
        from .chaining import build_agent_prompt

        agent_id = await sandbox.register_agent(task_name=task)
        prompt = build_agent_prompt(
            task=task,
            modules=modules,
            agent_id=agent_id,
            is_web_only=is_web_only,
            chain_context=chain_context,
        )
        return json.dumps({
            "agent_id": agent_id,
            "prompt": prompt,
            "message": f"Agent '{agent_id}' registered for: {task}. Pass the 'prompt' field to the Agent tool to dispatch.",
        })

    @mcp.tool()
    async def suggest_chains() -> str:
        """Analyze all vulnerability reports for chaining opportunities.

        Returns all detected chains — both new (not yet dispatched) and
        previously fired. Use this after Phase 1 completes to review
        all potential attack chains.

        Each chain includes a dispatch payload with task and modules
        that can be passed directly to dispatch_agent."""
        from .chaining import detect_chains

        # Run detection without modifying fired set (show everything)
        all_chains = detect_chains(vulnerability_reports, fired=set())

        for chain in all_chains:
            chain["dispatched"] = chain["chain_name"] in fired_chains

        new_count = sum(1 for c in all_chains if not c["dispatched"])
        return json.dumps({
            "total_chains": len(all_chains),
            "new_chains": new_count,
            "chains": all_chains,
        })
```

**Step 4: Run full test suite**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_chaining.py
git commit -m "feat(mcp): add dispatch_agent and suggest_chains tools"
```

---

### Task 4: Wire chain detection into `create_vulnerability_report`

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:369-428`
- Test: `strix-mcp/tests/test_chaining.py`

**Step 1: Write the failing tests**

In `strix-mcp/tests/test_chaining.py`, add:

```python
class TestDetectChainsIntegration:
    def test_chains_detected_after_second_finding(self):
        """When two findings match a chain rule, detect_chains should return the chain."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()

        # First finding — no chain yet
        reports = [{"title": "Stored XSS in /comments", "severity": "high"}]
        chains = detect_chains(reports, fired=fired)
        assert len(chains) == 0

        # Second finding completes the chain
        reports.append({"title": "Session cookies missing HttpOnly flag", "severity": "medium"})
        chains = detect_chains(reports, fired=fired)
        assert len(chains) >= 1
        assert chains[0]["dispatch"]["modules"] == ["xss", "authentication_jwt"]

    def test_multiple_chains_from_multiple_findings(self):
        """Multiple chains can fire from a set of findings."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
            {"title": "SSRF via image URL parameter", "severity": "high"},
            {"title": "Internal API endpoints discovered", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=fired)
        assert len(chains) >= 2
        names = {c["chain_name"] for c in chains}
        assert any("session hijack" in n.lower() for n in names)
        assert any("internal" in n.lower() for n in names)
```

**Step 2: Run tests to verify they pass** (uses existing detect_chains)

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py::TestDetectChainsIntegration -v --tb=short -o "addopts="`
Expected: PASS

**Step 3: Wire detect_chains into create_vulnerability_report**

In `tools.py`, modify the `create_vulnerability_report` tool. After both return paths (new report and merge), add chain detection. Replace the two `return json.dumps(...)` blocks.

For the **new report** path (after `vulnerability_reports.append(report)` and `_append_finding`), change the return to:

```python
        vulnerability_reports.append(report)
        if scan_dir:
            _append_finding(scan_dir, report)

        # Detect chains after new finding
        from .chaining import detect_chains
        new_chains = detect_chains(vulnerability_reports, fired=fired_chains)

        result: dict[str, Any] = {
            "report_id": report["id"],
            "title": title,
            "severity": severity,
            "message": "Vulnerability report saved.",
            "merged": False,
        }
        if new_chains:
            result["chains_detected"] = new_chains
        return json.dumps(result)
```

For the **merge** path (after `existing["content"] += ...` and `_append_finding`), change the return to:

```python
            if scan_dir:
                _append_finding(scan_dir, existing, event="merge")

            # Detect chains after merge (severity upgrade may trigger new chains)
            from .chaining import detect_chains
            new_chains = detect_chains(vulnerability_reports, fired=fired_chains)

            result: dict[str, Any] = {
                "report_id": existing["id"],
                "title": existing["title"],
                "severity": existing["severity"],
                "message": f"Merged with existing report '{existing['title']}'. Evidence appended.",
                "merged": True,
            }
            if new_chains:
                result["chains_detected"] = new_chains
            return json.dumps(result)
```

**Step 4: Run full test suite**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_chaining.py
git commit -m "feat(mcp): wire chain detection into create_vulnerability_report"
```

---

### Task 5: Add pending chains to `get_scan_status`

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:340-367`
- Test: `strix-mcp/tests/test_chaining.py`

**Step 1: Write the failing test**

In `strix-mcp/tests/test_chaining.py`, add:

```python
class TestPendingChainsTracking:
    def test_fired_chains_tracks_dispatched(self):
        """fired_chains set should grow as chains are detected."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        detect_chains(reports, fired=fired)
        assert len(fired) >= 1
        assert any("session hijack" in name.lower() for name in fired)

    def test_pending_count_decreases_after_firing(self):
        """After chains fire, they should be in fired set and not fire again."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]

        # First detection
        chains1 = detect_chains(reports, fired=fired)
        count1 = len(chains1)
        assert count1 >= 1

        # Second detection — all fired, nothing new
        chains2 = detect_chains(reports, fired=fired)
        assert len(chains2) == 0
```

**Step 2: Run tests to verify they pass** (uses existing logic)

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_chaining.py::TestPendingChainsTracking -v --tb=short -o "addopts="`
Expected: PASS

**Step 3: Update get_scan_status to include pending chains**

In `tools.py`, modify `get_scan_status`. After the severity_counts loop, before the return:

```python
        # Count chains that have been detected but the coordinator hasn't dispatched yet
        from .chaining import detect_chains
        # Run detection without modifying fired set to get current count
        all_possible = detect_chains(vulnerability_reports, fired=set())
        pending_chains = [c for c in all_possible if c["chain_name"] not in fired_chains]

        return json.dumps({
            "scan_id": scan.scan_id,
            "status": "running",
            "elapsed_seconds": round(elapsed),
            "agents_registered": len(scan.registered_agents),
            "agent_ids": list(scan.registered_agents.keys()),
            "agents": [
                {"id": aid, "task": name}
                for aid, name in scan.registered_agents.items()
            ],
            "total_reports": len(vulnerability_reports),
            "severity_counts": severity_counts,
            "pending_chains": len(pending_chains),
        })
```

**Step 4: Run full test suite**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_chaining.py
git commit -m "feat(mcp): add pending_chains count to get_scan_status"
```

---

### Task 6: Update methodology docs

**Files:**
- Modify: `strix-mcp/src/strix_mcp/methodology.md`

**Step 1: Update Phase 1 dispatch instructions to use dispatch_agent**

In methodology.md, in the "Step 2: Dispatch Subagents" section (around line 74-86), add after "Dispatch multiple subagents in parallel":

```markdown
**Dispatching agents:**
For each agent in the plan, call `dispatch_agent(task=..., modules=[...])`. It handles agent registration and returns a complete prompt — pass the `prompt` field directly to the Agent tool. This replaces the manual `register_agent` + prompt composition workflow.
```

**Step 2: Update Phase 2 section to reference the tools**

In the Phase 2 section (around line 88-120), add before the chaining table:

```markdown
The `create_vulnerability_report` tool automatically detects chains as findings come in. When chains are detected, the response includes `chains_detected` with ready-to-use dispatch payloads. Call `dispatch_agent` with the provided task and modules to immediately act on them.

After all Phase 1 agents complete, call `suggest_chains()` to review ALL chaining opportunities — including any that may have been missed.

Use `get_scan_status` to see the `pending_chains` count — if non-zero, chains are waiting for dispatch.
```

**Step 3: Run methodology test**

Run: `cd /Users/ms6rb/Documents/GitHub/strix/strix-mcp && python -m pytest tests/test_resources.py::test_get_methodology_returns_content -v --tb=short -o "addopts="`
Expected: PASS

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/methodology.md
git commit -m "docs(mcp): update methodology to reference dispatch_agent and chain detection"
```
