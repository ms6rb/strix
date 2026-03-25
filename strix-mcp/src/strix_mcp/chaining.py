"""Vulnerability chaining rules and detection logic.

Detects when two findings combine into a higher-severity attack chain
and provides dispatch payloads for follow-up agents.
"""

from __future__ import annotations

from dataclasses import dataclass
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
Call `load_skill("{module_list}")` to load all your assigned skills at once. Read the returned content carefully — it contains advanced exploitation techniques, bypass methods, and validation requirements you MUST use.

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
Call `load_skill("{module_list}")` to load all your assigned skills at once. Read the returned content carefully — it contains exact tool syntax, exploitation techniques, and bypass methods you MUST use.

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
    module_list = ",".join(modules)

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

        # If both sides matched the same report, search for a distinct match_b
        if match_a is not None and match_b is match_a:
            match_b = None
            for report in reports:
                if report is not match_a and _title_matches(report.get("title", ""), rule.finding_b):
                    match_b = report
                    break

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


# --- Cross-tool chain reasoning ---


def reason_cross_tool_chains(
    firebase_results: dict[str, Any] | None = None,
    js_analysis: dict[str, Any] | None = None,
    services: dict[str, Any] | None = None,
    session_comparison: dict[str, Any] | None = None,
    api_discovery: dict[str, Any] | None = None,
    vuln_reports: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Reason about vulnerability chains across tool outputs.

    Takes structured results from firebase_audit, analyze_js_bundles,
    discover_services, compare_sessions, discover_api, and vulnerability
    reports. Returns chain hypotheses with evidence, description, missing
    links, and next actions.
    """
    chains: list[dict[str, Any]] = []
    firebase = firebase_results or {}
    js = js_analysis or {}
    svc = services or {}
    sessions = session_comparison or {}
    api = api_discovery or {}
    vulns = vuln_reports or []

    vuln_titles = " ".join(v.get("title", "").lower() for v in vulns)

    # --- Firebase + JS bundle chains ---
    fb_auth = firebase.get("auth", {})
    fb_firestore = firebase.get("firestore", {})
    fb_acl = fb_firestore.get("acl_matrix", {})
    js_collections = set(js.get("collection_names", []))
    js_endpoints = js.get("api_endpoints", [])

    # Chain: writable collection + client reads from it → stored XSS / data injection
    for coll, auth_states in fb_acl.items():
        writable_by: list[str] = []
        for auth_label, ops in auth_states.items():
            if ops.get("create") == "allowed":
                writable_by.append(auth_label)

        if writable_by and coll in js_collections:
            chains.append(_chain(
                name=f"Data injection via writable '{coll}' collection",
                severity="critical",
                evidence=[
                    f"Firestore collection '{coll}' is writable by: {', '.join(writable_by)}",
                    f"JS bundle reads from '{coll}' collection (found in client code)",
                ],
                chain_description=(
                    f"An attacker can write to '{coll}' and the client app reads from it. "
                    f"If the app renders fields without sanitization, this is stored XSS. "
                    f"If the app trusts field values for logic, this is data tampering."
                ),
                missing=[
                    f"Verify which fields from '{coll}' are rendered in the UI",
                    "Check if client sanitizes field values before rendering",
                    "Identify if any fields control app behavior (roles, permissions, URLs)",
                ],
                next_action=(
                    f"Write a test document to '{coll}' with XSS payloads in all string fields. "
                    "Then browse the app and check if payloads execute."
                ),
            ))

    # Chain: open signup + writable collection → unauthenticated data injection
    if fb_auth.get("anonymous_signup") == "open" or fb_auth.get("email_signup") == "open":
        signup_method = "anonymous" if fb_auth.get("anonymous_signup") == "open" else "email"
        for coll, auth_states in fb_acl.items():
            for auth_label, ops in auth_states.items():
                if auth_label in ("anonymous", "email_signup") and ops.get("create") == "allowed":
                    chains.append(_chain(
                        name=f"Unauthenticated write via {signup_method} signup → '{coll}'",
                        severity="high",
                        evidence=[
                            f"Firebase {signup_method} signup is open",
                            f"Collection '{coll}' writable by {auth_label}",
                        ],
                        chain_description=(
                            f"Anyone can create a {signup_method} account and write to '{coll}'. "
                            "Combined with client-side rendering, this could enable stored XSS or data corruption."
                        ),
                        missing=[
                            f"Check what data in '{coll}' is visible to other users",
                            "Test if injected data is rendered or processed by the application",
                        ],
                        next_action=(
                            f"Create {signup_method} account, write test data to '{coll}', "
                            "then check if it appears for other users."
                        ),
                    ))
                    break  # one chain per collection is enough

    # Chain: readable collection with user data + IDOR potential
    for coll, auth_states in fb_acl.items():
        listable_by: list[str] = []
        for auth_label, ops in auth_states.items():
            if "allowed" in ops.get("list", ""):
                listable_by.append(auth_label)
        if listable_by and coll in ("users", "accounts", "profiles", "members"):
            chains.append(_chain(
                name=f"User data exposure via listable '{coll}' collection",
                severity="high",
                evidence=[
                    f"Collection '{coll}' is listable by: {', '.join(listable_by)}",
                    f"'{coll}' likely contains user PII (emails, names, settings)",
                ],
                chain_description=(
                    f"Any {listable_by[0]} user can list all documents in '{coll}'. "
                    "This exposes user data across accounts (horizontal IDOR)."
                ),
                missing=[
                    f"Retrieve sample documents from '{coll}' and check for PII fields",
                    "Verify if UIDs from this collection can be used to access other resources",
                ],
                next_action=f"List documents in '{coll}' and examine field contents for sensitive data.",
            ))

    # --- Third-party service chains ---
    svc_discovered = svc.get("discovered_services", {})
    svc_probes = svc.get("probes", {})

    # Chain: accessible Sanity CMS + sensitive document types
    for probe_key, probe_result in svc_probes.items():
        if "sanity" in probe_key and probe_result.get("status") == "accessible":
            doc_types = probe_result.get("document_types", [])
            chains.append(_chain(
                name="Publicly accessible Sanity CMS with data exposure",
                severity="high",
                evidence=[
                    f"Sanity CMS is publicly queryable (project: {probe_key.replace('sanity_', '')})",
                    f"Document types found: {', '.join(doc_types[:10])}",
                ],
                chain_description=(
                    "The Sanity CMS dataset is readable without authentication. "
                    "GROQ queries can extract all documents — potentially including "
                    "internal content, draft pages, AI prompts, configuration, and user data."
                ),
                missing=[
                    "Run comprehensive GROQ queries to enumerate all document types and fields",
                    "Check for sensitive content: API keys, internal docs, user PII",
                    "Test if write operations are also open",
                ],
                next_action="Run `*[_type != \"\"][0...100]{...}` GROQ query to dump all documents.",
            ))

    # --- Session comparison chains ---
    if sessions.get("results"):
        divergent = [r for r in sessions["results"] if r.get("classification") == "divergent"]
        b_only = [r for r in sessions["results"] if r.get("classification") == "b_only"]

        if divergent:
            chains.append(_chain(
                name=f"Authorization divergence on {len(divergent)} endpoints",
                severity="high",
                evidence=[
                    f"{len(divergent)} endpoints returned different responses for different auth contexts",
                    f"Endpoints: {', '.join(r['method'] + ' ' + r['path'] for r in divergent[:5])}",
                ],
                chain_description=(
                    "Different authentication contexts receive different data from the same endpoints. "
                    "This could indicate broken access control, data leakage, or IDOR vulnerabilities."
                ),
                missing=[
                    "Compare response bodies to identify what data differs",
                    "Check if lower-privileged session can access higher-privileged data by manipulating IDs",
                ],
                next_action="Use view_request to inspect divergent responses and identify leaked data.",
            ))

        if b_only:
            chains.append(_chain(
                name=f"Unexpected access: {len(b_only)} endpoints accessible to lower-privilege session",
                severity="critical",
                evidence=[
                    f"{len(b_only)} endpoints are accessible to session B but denied to session A",
                    f"Endpoints: {', '.join(r['method'] + ' ' + r['path'] for r in b_only[:5])}",
                ],
                chain_description=(
                    "The lower-privileged session has access to endpoints denied to the higher-privileged one. "
                    "This is a strong indicator of broken access control or misconfigured authorization."
                ),
                missing=["Verify these endpoints contain meaningful data or functionality"],
                next_action="Investigate each b_only endpoint to confirm the access control issue.",
            ))

    # --- API discovery chains ---
    if api.get("graphql", {}).get("introspection") == "enabled":
        chains.append(_chain(
            name="GraphQL introspection enabled — full schema exposed",
            severity="medium",
            evidence=["GraphQL introspection query returned the full type schema"],
            chain_description=(
                "The GraphQL schema is fully enumerable. An attacker can discover all queries, "
                "mutations, and types to find sensitive operations and data access paths."
            ),
            missing=[
                "Enumerate all mutations for state-changing operations",
                "Check for authorization on sensitive queries/mutations",
            ],
            next_action="Load the 'graphql' skill and run a full introspection analysis.",
        ))

    # --- JS bundle + vuln report cross-references ---
    js_secrets = js.get("secrets", [])
    if js_secrets:
        chains.append(_chain(
            name=f"Secrets found in JS bundles ({len(js_secrets)} occurrences)",
            severity="high",
            evidence=[f"Hardcoded secrets/keys in client bundles: {', '.join(js_secrets[:5])}"],
            chain_description=(
                "API keys, tokens, or credentials are embedded in client-side JavaScript. "
                "These are accessible to any user and may grant server-side access."
            ),
            missing=[
                "Test each key/token to determine its scope and permissions",
                "Check if keys are publishable (expected) or secret (vulnerability)",
            ],
            next_action="Extract each key and test its scope with the corresponding service API.",
        ))

    internal_hosts = js.get("internal_hostnames", [])
    if internal_hosts and "ssrf" in vuln_titles:
        chains.append(_chain(
            name="SSRF + internal hostnames from JS bundles",
            severity="critical",
            evidence=[
                "SSRF vulnerability found in reports",
                f"Internal hostnames leaked in JS: {', '.join(internal_hosts[:5])}",
            ],
            chain_description=(
                "An SSRF vulnerability combined with leaked internal hostnames enables "
                "targeted attacks against internal infrastructure."
            ),
            missing=["Test SSRF against each internal hostname"],
            next_action=f"Use the SSRF to probe: {', '.join(internal_hosts[:3])}",
        ))

    # --- CSPT sinks + CSRF-protected endpoints ---
    cspt_sinks = js.get("cspt_sinks", [])
    if cspt_sinks and ("csrf" in vuln_titles or any(
        kw in vuln_titles for kw in ["samesite", "cookie", "csrf"]
    )):
        chains.append(_chain(
            name="CSPT bypass of SameSite cookie protections",
            severity="critical",
            evidence=[
                f"CSPT sinks found in JS bundles: {', '.join(cspt_sinks[:3])}",
                "CSRF-protected or SameSite-cookie endpoints identified in reports",
            ],
            chain_description=(
                "Client-Side Path Traversal sinks can issue same-origin requests with "
                "attacker-controlled paths, bypassing SameSite cookie restrictions. "
                "This turns CSPT into a CSRF bypass — or worse, XSS/RCE via path traversal."
            ),
            missing=[
                "Identify which CSPT sinks accept user-controlled path segments",
                "Map state-changing endpoints that rely on SameSite for CSRF protection",
                "Test if path traversal sequences (../) are preserved through the fetch call",
            ],
            next_action="Load the 'cspt' skill and test each CSPT sink for path traversal exploitation.",
        ))

    # --- Internal packages + dependency confusion ---
    internal_pkgs = js.get("internal_packages", [])
    if internal_pkgs:
        chains.append(_chain(
            name=f"Dependency confusion via {len(internal_pkgs)} internal packages",
            severity="critical",
            evidence=[
                f"Internal/private npm package names found in JS bundles: {', '.join(internal_pkgs[:5])}",
            ],
            chain_description=(
                "Internal package names leaked in client-side JavaScript can be registered "
                "on public registries (npm, PyPI). If the target's package manager checks "
                "public registries, a higher-version malicious package will be installed — "
                "leading to RCE in CI/CD or developer machines."
            ),
            missing=[
                "Check if these package names exist on npmjs.com",
                "Verify the target uses a private registry or scoped packages",
                "Determine if CI/CD pipelines pull from public registries",
            ],
            next_action=(
                f"Check npm for availability: {', '.join(internal_pkgs[:3])}. "
                "If unregistered, this is a confirmed dependency confusion opportunity."
            ),
        ))

    # --- postMessage listeners + missing origin validation ---
    pm_listeners = js.get("postmessage_listeners", [])
    if pm_listeners:
        chains.append(_chain(
            name=f"postMessage handlers without origin validation ({len(pm_listeners)} listeners)",
            severity="high",
            evidence=[
                f"postMessage event listeners found: {', '.join(pm_listeners[:3])}",
            ],
            chain_description=(
                "postMessage listeners that don't validate event.origin accept messages "
                "from any window. An attacker can open the target in an iframe or window "
                "and send crafted messages to trigger DOM XSS, token theft, or state manipulation."
            ),
            missing=[
                "Check if each listener validates event.origin before processing",
                "Identify what data the listeners accept and how it's used",
                "Test if sensitive actions (auth, navigation, DOM writes) are triggered by messages",
            ],
            next_action="Load the 'postmessage' skill and test each listener for origin bypass.",
        ))

    # --- OAuth endpoints + open redirect ---
    js_oauth_ids = js.get("oauth_ids", [])
    if js_oauth_ids and "open redirect" in vuln_titles:
        chains.append(_chain(
            name="OAuth token theft via open redirect",
            severity="critical",
            evidence=[
                f"OAuth client IDs found in JS: {', '.join(js_oauth_ids[:3])}",
                "Open redirect vulnerability found in reports",
            ],
            chain_description=(
                "An open redirect combined with OAuth flows allows an attacker to "
                "manipulate the redirect_uri to steal authorization codes or tokens. "
                "The OAuth provider redirects the user to the attacker's server with valid tokens."
            ),
            missing=[
                "Identify the OAuth authorization endpoint and redirect_uri parameter",
                "Test if the open redirect can be used as a valid redirect_uri",
                "Check if authorization code or implicit flow tokens are leaked in the redirect",
            ],
            next_action="Load the 'oauth' skill and chain the open redirect with the OAuth flow.",
        ))

    # --- GraphQL introspection + no auth on mutations ---
    if api.get("graphql", {}).get("introspection") == "enabled":
        gql_types = api.get("graphql", {}).get("types", [])
        has_mutations = any("Mutation" in t for t in gql_types)
        if has_mutations:
            chains.append(_chain(
                name="GraphQL mutation abuse via introspection + missing auth",
                severity="critical",
                evidence=[
                    "GraphQL introspection is enabled and exposes Mutation type",
                    f"Types discovered: {', '.join(gql_types[:10])}",
                ],
                chain_description=(
                    "GraphQL introspection reveals all mutations, and if authorization "
                    "is not enforced on mutation resolvers, an attacker can perform "
                    "arbitrary state-changing operations — creating, modifying, or deleting data."
                ),
                missing=[
                    "Enumerate all mutations and their input types",
                    "Test each mutation for authorization enforcement",
                    "Check for sensitive mutations: createUser, updateRole, deleteAccount, transferFunds",
                ],
                next_action="Load the 'graphql' skill and test every mutation for missing authorization.",
            ))

    return chains


def _chain(
    name: str,
    severity: str,
    evidence: list[str],
    chain_description: str,
    missing: list[str],
    next_action: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "severity": severity,
        "evidence": evidence,
        "chain_description": chain_description,
        "missing": missing,
        "next_action": next_action,
    }
