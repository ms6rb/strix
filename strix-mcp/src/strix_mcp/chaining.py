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
