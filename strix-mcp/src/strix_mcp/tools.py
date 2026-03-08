from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from fastmcp import FastMCP
from mcp import types

from .sandbox import SandboxManager

# --- Title normalization for deduplication ---

_TITLE_SYNONYMS: dict[str, str] = {
    "content-security-policy": "csp",
    "content security policy": "csp",
    "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "sql injection": "sqli",
    "nosql injection": "nosqli",
    "xml external entity": "xxe",
    "remote code execution": "rce",
    "insecure direct object reference": "idor",
    "broken access control": "bac",
    "missing x-frame-options": "x-frame-options missing",
    "x-content-type-options missing": "x-content-type-options missing",
    "strict-transport-security missing": "hsts missing",
    "missing hsts": "hsts missing",
    "missing strict-transport-security": "hsts missing",
}


def _normalize_title(title: str) -> str:
    """Normalize a vulnerability title for deduplication."""
    t = title.lower().strip()
    t = " ".join(t.split())
    for synonym, canonical in sorted(
        _TITLE_SYNONYMS.items(), key=lambda x: -len(x[0])
    ):
        t = t.replace(synonym, canonical)
    return t


def _find_duplicate(
    normalized_title: str, reports: list[dict[str, Any]]
) -> int | None:
    """Find index of an existing report with the same normalized title."""
    for i, report in enumerate(reports):
        if _normalize_title(report["title"]) == normalized_title:
            return i
    return None


# --- OWASP Top 10 (2021) categorization ---

_OWASP_KEYWORDS: list[tuple[str, list[str]]] = [
    ("A01 Broken Access Control", [
        "idor", "bac", "broken access", "insecure direct object",
        "privilege escalation", "path traversal", "directory traversal",
        "forced browsing", "cors", "missing access control",
        "open redirect", "unauthorized access", "access control",
        "subdomain takeover",
    ]),
    ("A02 Cryptographic Failures", [
        "weak cipher", "weak encryption", "cleartext", "plain text password",
        "insecure tls", "ssl", "certificate", "weak hash",
    ]),
    ("A03 Injection", [
        "sqli", "sql injection", "nosql injection", "xss", "cross-site scripting",
        "command injection", "xxe", "xml external entity", "ldap injection",
        "xpath injection", "template injection", "ssti", "crlf injection",
        "header injection", "rce", "remote code execution", "code injection",
        "prototype pollution",
    ]),
    ("A04 Insecure Design", [
        "business logic", "race condition", "mass assignment",
        "insecure design", "missing rate limit",
    ]),
    ("A05 Security Misconfiguration", [
        "misconfiguration", "missing csp", "csp", "missing header",
        "x-frame-options", "x-content-type", "hsts", "strict-transport",
        "server information", "debug mode", "default credential",
        "directory listing", "stack trace", "verbose error",
        "sentry", "source map", "security header",
        "information disclosure", "exposed env", "actuator exposed",
        "swagger exposed", "phpinfo", "server version",
    ]),
    ("A06 Vulnerable and Outdated Components", [
        "outdated", "vulnerable component", "known vulnerability",
        "cve-", "end of life",
    ]),
    ("A07 Identification and Authentication Failures", [
        "jwt", "authentication", "session", "credential", "password",
        "brute force", "session fixation", "token", "oauth", "2fa", "mfa",
    ]),
    ("A08 Software and Data Integrity Failures", [
        "deserialization", "integrity", "unsigned", "untrusted data",
        "ci/cd", "auto-update",
    ]),
    ("A09 Security Logging and Monitoring Failures", [
        "logging", "monitoring", "audit", "insufficient logging",
    ]),
    ("A10 Server-Side Request Forgery", [
        "ssrf", "server-side request forgery",
    ]),
]


def _categorize_owasp(title: str) -> str:
    """Map a vulnerability title to an OWASP Top 10 (2021) category."""
    title_lower = title.lower()
    for category, keywords in _OWASP_KEYWORDS:
        if any(kw in title_lower for kw in keywords):
            return category
    return "Other"


def _deduplicate_reports(
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate reports by normalized title, keeping the richest entry."""
    severity_order = ["info", "low", "medium", "high", "critical"]
    seen: dict[str, dict[str, Any]] = {}

    for report in reports:
        key = _normalize_title(report["title"])
        if key in seen:
            existing = seen[key]
            if severity_order.index(report.get("severity", "info")) > severity_order.index(existing.get("severity", "info")):
                existing["severity"] = report["severity"]
            if report.get("content", "") not in existing.get("content", ""):
                existing["content"] = existing.get("content", "") + f"\n\n---\n\n{report.get('content', '')}"
        else:
            seen[key] = dict(report)

    return list(seen.values())


# --- Scan persistence (upstream-compatible strix_runs/ format) ---


def _get_run_dir(scan_id: str) -> Path:
    """Return strix_runs/<scan_id>/ in cwd, creating if needed."""
    run_dir = Path.cwd() / "strix_runs" / scan_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _write_finding_md(run_dir: Path, report: dict[str, Any]) -> None:
    """Write a finding as an individual markdown file.

    Matches upstream Strix format: strix_runs/<scan>/vulnerabilities/<id>.md
    Overwrites on merge so the file always reflects current state.
    """
    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(exist_ok=True)
    vuln_file = vuln_dir / f"{report['id']}.md"

    lines: list[str] = []
    lines.append(f"# {report.get('title', 'Untitled Vulnerability')}\n")
    lines.append(f"**ID:** {report['id']}")
    lines.append(f"**Severity:** {report.get('severity', 'unknown').upper()}")
    lines.append(f"**Found:** {report.get('timestamp', 'unknown')}")

    if report.get("affected_endpoints"):
        lines.append(f"**Endpoints:** {', '.join(report['affected_endpoints'])}")
    if report.get("cvss_score") is not None:
        lines.append(f"**CVSS:** {report['cvss_score']}")

    lines.append("")
    lines.append("## Details\n")
    lines.append(report.get("content", "No details provided."))
    lines.append("")

    vuln_file.write_text("\n".join(lines))


def _write_vuln_csv(run_dir: Path, reports: list[dict[str, Any]]) -> None:
    """Write vulnerabilities.csv index sorted by severity (critical first)."""
    import csv

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_reports = sorted(
        reports,
        key=lambda r: (severity_order.get(r.get("severity", "info"), 5), r.get("timestamp", "")),
    )

    csv_file = run_dir / "vulnerabilities.csv"
    with csv_file.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "title", "severity", "timestamp", "file"])
        writer.writeheader()
        for r in sorted_reports:
            writer.writerow({
                "id": r["id"],
                "title": r["title"],
                "severity": r["severity"].upper(),
                "timestamp": r.get("timestamp", ""),
                "file": f"vulnerabilities/{r['id']}.md",
            })


def _write_summary_md(run_dir: Path, summary: dict[str, Any]) -> None:
    """Write a human-readable scan summary as summary.md."""
    lines: list[str] = []
    lines.append("# Scan Summary\n")

    unique = summary.get("unique_findings", 0)
    lines.append(f"**Total unique findings:** {unique}")

    sev = summary.get("severity_counts", {})
    if sev:
        lines.append("\n## Severity Breakdown\n")
        for level in ("critical", "high", "medium", "low", "info"):
            count = sev.get(level, 0)
            if count:
                lines.append(f"- **{level.upper()}:** {count}")

    findings = summary.get("findings", [])
    if findings:
        lines.append("\n## Findings\n")
        lines.append("| ID | Title | Severity |")
        lines.append("|---|---|---|")
        for f in findings:
            lines.append(f"| {f['id']} | {f['title']} | {f['severity'].upper()} |")

    lines.append("")
    (run_dir / "summary.md").write_text("\n".join(lines))


def register_tools(mcp: FastMCP, sandbox: SandboxManager) -> None:
    vulnerability_reports: list[dict[str, Any]] = []
    scan_dir: Path | None = None
    fired_chains: set[str] = set()

    # --- Lifecycle Tools ---

    @mcp.tool()
    async def start_scan(
        targets: list[dict[str, str]],
        scan_id: str | None = None,
    ) -> str:
        """Start a security scan. Boots a Docker sandbox with Kali Linux,
        copies target source code to /workspace, and initializes security tools.

        targets: list of {type, value} where type is one of: local_code,
        web_application, repository, ip_address, domain.
        value is the path or URL. Optionally include 'name' for local_code targets.

        First run will pull the Docker image (~2GB) which takes a few minutes.
        Subsequent runs reuse the cached image.

        Returns detected tech stack and recommended scan plan with module assignments."""
        sid = scan_id or f"scan-{uuid.uuid4().hex[:8]}"
        state = await sandbox.start_scan(targets=targets, scan_id=sid)

        # Detect target stack and generate scan plan
        analysis: dict[str, Any] = {}
        has_code_targets = any(t.get("type") == "local_code" for t in targets)
        web_targets = [
            t for t in targets
            if t.get("type") in ("web_application", "domain", "ip_address")
        ]

        if has_code_targets:
            try:
                analysis = await sandbox.detect_target_stack()
            except Exception:
                analysis = {"detected_stack": None, "recommended_plan": []}

        if not analysis.get("detected_stack") and web_targets:
            url = web_targets[0]["value"]
            if not url.startswith("http"):
                url = f"https://{url}"
            try:
                analysis = await sandbox.fingerprint_web_target(url)
            except Exception:
                analysis = {"detected_stack": None, "recommended_plan": []}

        # Collect target type triggers for plan generation
        target_types: list[str] = []
        for t in targets:
            ttype = t.get("type", "")
            if ttype == "domain":
                target_types.append("domain")

        # Inject target types into detected stack for plan generation
        if analysis.get("detected_stack") and target_types:
            analysis["detected_stack"]["target_types"] = target_types

        # If still no plan, generate a default web plan
        if not analysis.get("recommended_plan"):
            from .stack_detector import generate_plan
            default_stack: dict[str, Any] = {
                "runtime": [], "framework": [], "database": [],
                "auth": [], "features": [], "api_style": ["rest"],
                "infrastructure": [], "target_types": target_types,
            }
            analysis = {
                "detected_stack": analysis.get("detected_stack") or default_stack,
                "recommended_plan": generate_plan(default_stack),
            }

        nonlocal scan_dir
        scan_dir = _get_run_dir(sid)
        vulnerability_reports.clear()
        fired_chains.clear()

        return json.dumps({
            "scan_id": state.scan_id,
            "status": "running",
            "workspace": "/workspace",
            **analysis,
            "message": "Sandbox ready. Target code copied to /workspace.",
        })

    @mcp.tool()
    async def end_scan() -> str:
        """End the active scan and tear down the Docker sandbox.
        Returns a comprehensive summary: unique findings deduplicated,
        grouped by OWASP Top 10 category, with severity breakdown."""
        unique = _deduplicate_reports(vulnerability_reports)
        total_filed = len(vulnerability_reports)
        duplicates_merged = total_filed - len(unique)

        severity_counts: dict[str, int] = {}
        for r in unique:
            sev = r.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        findings_by_category: dict[str, list[dict[str, str]]] = {}
        for r in unique:
            category = _categorize_owasp(r["title"])
            if category not in findings_by_category:
                findings_by_category[category] = []
            entry: dict[str, Any] = {
                "id": r["id"],
                "title": r["title"],
                "severity": r.get("severity", "info"),
            }
            if "affected_endpoints" in r:
                entry["affected_endpoints"] = r["affected_endpoints"]
            if "cvss_score" in r:
                entry["cvss_score"] = r["cvss_score"]
            findings_by_category[category].append(entry)

        summary = {
            "status": "stopped",
            "message": "Sandbox destroyed. Scan ended.",
            "unique_findings": len(unique),
            "total_reports_filed": total_filed,
            "duplicates_merged": duplicates_merged,
            "severity_counts": severity_counts,
            "findings_by_category": findings_by_category,
            "findings": [
                {"id": r["id"], "title": r["title"], "severity": r.get("severity", "info")}
                for r in unique
            ],
        }
        if scan_dir:
            _write_vuln_csv(scan_dir, unique)
            _write_summary_md(scan_dir, summary)

        await sandbox.end_scan()

        return json.dumps(summary)

    @mcp.tool()
    async def register_agent(task_name: str = "") -> str:
        """Register a new agent ID for concurrent subagent testing.
        Call this at the start of each Claude Code subagent's work.
        Pass the returned agent_id to all subsequent tool calls.
        Each agent gets isolated terminal, browser, and Python sessions.

        task_name: optional label for what this agent is testing (e.g. 'SQL injection testing')."""
        agent_id = await sandbox.register_agent(task_name=task_name)
        return json.dumps({
            "agent_id": agent_id,
            "task_name": task_name,
            "message": f"Agent registered. Pass agent_id='{agent_id}' to all tool calls.",
        })

    @mcp.tool()
    async def get_scan_status() -> str:
        """Get current scan status including elapsed time, registered agents,
        and vulnerability report counts by severity.
        Use this to monitor scan progress."""
        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"status": "no_active_scan"})

        elapsed = (datetime.now(UTC) - scan.started_at).total_seconds()
        severity_counts: dict[str, int] = {}
        for r in vulnerability_reports:
            sev = r["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count chains detected but not yet dispatched
        from .chaining import detect_chains
        all_possible = detect_chains(vulnerability_reports, fired=set())
        pending_chains = [c for c in all_possible if c["chain_name"] not in fired_chains]

        return json.dumps({
            "scan_id": scan.scan_id,
            "status": "running",
            "elapsed_seconds": round(elapsed),
            "agents_registered": len(scan.registered_agents),
            "agents": [
                {"id": aid, "task": name}
                for aid, name in scan.registered_agents.items()
            ],
            "total_reports": len(vulnerability_reports),
            "severity_counts": severity_counts,
            "pending_chains": len(pending_chains),
        })

    @mcp.tool()
    async def create_vulnerability_report(
        title: str,
        content: str,
        severity: str,
        affected_endpoint: str | None = None,
        cvss_score: float | None = None,
    ) -> str:
        """Report a confirmed vulnerability finding.
        severity: critical, high, medium, low, or info.
        content: full details including PoC, impact, and remediation.
        affected_endpoint: the URL path or component affected (e.g. /api/users/:id).
        cvss_score: CVSS 3.1 base score (0.0-10.0) if known.
        Only report validated vulnerabilities with proof of exploitation.

        If a similar finding was already reported, the evidence is merged
        into the existing report and the higher severity is kept."""
        normalized = _normalize_title(title)
        dup_idx = _find_duplicate(normalized, vulnerability_reports)

        if dup_idx is not None:
            existing = vulnerability_reports[dup_idx]
            severity_order = ["info", "low", "medium", "high", "critical"]
            if severity_order.index(severity) > severity_order.index(existing["severity"]):
                existing["severity"] = severity
            if affected_endpoint and affected_endpoint not in existing.get("affected_endpoints", []):
                existing.setdefault("affected_endpoints", []).append(affected_endpoint)
            if cvss_score is not None and (existing.get("cvss_score") is None or cvss_score > existing["cvss_score"]):
                existing["cvss_score"] = cvss_score
            existing["content"] += f"\n\n---\n\n**Additional evidence:**\n{content}"
            if scan_dir:
                _write_finding_md(scan_dir, existing)

            # Detect chains after merge
            from .chaining import detect_chains
            new_chains = detect_chains(vulnerability_reports, fired=fired_chains)

            result: dict[str, Any] = {
                "report_id": existing["id"],
                "title": existing["title"],
                "severity": existing["severity"],
                "file": f"strix_runs/{scan_dir.name}/vulnerabilities/{existing['id']}.md" if scan_dir else None,
                "merged": True,
            }
            if new_chains:
                result["chains_detected"] = new_chains
            return json.dumps(result)

        report: dict[str, Any] = {
            "id": f"vuln-{uuid.uuid4().hex[:8]}",
            "title": title,
            "content": content,
            "severity": severity,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        if affected_endpoint:
            report["affected_endpoints"] = [affected_endpoint]
        if cvss_score is not None:
            report["cvss_score"] = cvss_score
        vulnerability_reports.append(report)
        if scan_dir:
            _write_finding_md(scan_dir, report)

        # Detect chains after new finding
        from .chaining import detect_chains
        new_chains = detect_chains(vulnerability_reports, fired=fired_chains)

        result: dict[str, Any] = {
            "report_id": report["id"],
            "title": title,
            "severity": severity,
            "file": f"strix_runs/{scan_dir.name}/vulnerabilities/{report['id']}.md" if scan_dir else None,
            "merged": False,
        }
        if new_chains:
            result["chains_detected"] = new_chains
        return json.dumps(result)

    @mcp.tool()
    async def list_vulnerability_reports(severity: str | None = None) -> str:
        """List all vulnerability reports filed so far in the current scan.
        Use this BEFORE filing a new report to check what's already been reported
        and avoid duplicates. Optional severity filter: critical, high, medium, low, info."""
        if severity:
            filtered = [r for r in vulnerability_reports if r["severity"] == severity]
        else:
            filtered = list(vulnerability_reports)
        return json.dumps({
            "reports": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "severity": r["severity"],
                    **({"affected_endpoints": r["affected_endpoints"]} if "affected_endpoints" in r else {}),
                    **({"cvss_score": r["cvss_score"]} if "cvss_score" in r else {}),
                }
                for r in filtered
            ],
            "total": len(filtered),
        })

    @mcp.tool()
    async def get_finding(finding_id: str) -> str:
        """Read the full details of a specific vulnerability finding from disk.
        Use this to recall finding details without keeping all content in memory.

        finding_id: the report ID (e.g. 'vuln-a1b2c3d4')."""
        if scan_dir is None:
            return json.dumps({"error": "No active scan."})

        vuln_file = scan_dir / "vulnerabilities" / f"{finding_id}.md"
        if not vuln_file.exists():
            return json.dumps({"error": f"Finding '{finding_id}' not found."})

        return vuln_file.read_text()

    @mcp.tool()
    async def get_module(name: str) -> str:
        """Load a specialized security knowledge module by name.
        Each module contains advanced exploitation techniques, bypass methods,
        validation requirements, and pro tips for a specific vulnerability class
        or technology.

        Call this at the START of your testing work to load deep expertise
        before analyzing code or running tests.

        Examples: get_module("idor"), get_module("authentication_jwt"),
        get_module("fastapi")"""
        from . import resources
        return resources.get_module(name)

    @mcp.tool()
    async def list_modules(category: str | None = None) -> str:
        """List all available security knowledge modules with their categories
        and descriptions. Call this to see what modules you can load with
        get_module().

        Optional category filter to show only modules in a specific category
        (e.g. 'vulnerabilities', 'frameworks', 'technologies').

        Returns JSON mapping module names to {category, description}."""
        from . import resources
        return resources.list_modules(category=category)

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

    # --- Proxied Tools ---

    @mcp.tool()
    async def terminal_execute(
        command: str,
        timeout: int = 30,
        terminal_id: str = "default",
        is_input: bool = False,
        no_enter: bool = False,
        agent_id: str | None = None,
    ) -> str:
        """Execute a bash command in a persistent Kali Linux terminal session.
        The terminal maintains state (env vars, cwd, processes) between calls.
        Use different terminal_id values for concurrent sessions.
        Timeout capped at 60s; commands keep running in background after timeout.
        Use C-c to interrupt. Use is_input=true for input to running processes."""
        result = await sandbox.proxy_tool("terminal_execute", {
            "command": command,
            "timeout": timeout,
            "terminal_id": terminal_id,
            "is_input": is_input,
            "no_enter": no_enter,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def send_request(
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        timeout: int = 30,
        agent_id: str | None = None,
    ) -> str:
        """Send an HTTP request through the Caido proxy.
        All traffic is captured for later analysis with list_requests/view_request."""
        result = await sandbox.proxy_tool("send_request", {
            "method": method,
            "url": url,
            "headers": headers,
            "body": body,
            "timeout": timeout,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def repeat_request(
        request_id: str,
        modifications: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Repeat a captured proxy request with modifications for pentesting.
        Workflow: browse with browser_action -> list_requests -> repeat_request.
        modifications can include: url, params, headers, body, cookies."""
        result = await sandbox.proxy_tool("repeat_request", {
            "request_id": request_id,
            "modifications": modifications,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def list_requests(
        httpql_filter: str | None = None,
        start_page: int = 1,
        end_page: int | None = None,
        page_size: int = 20,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        scope_id: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """List and filter captured proxy requests using HTTPQL syntax.
        Filter examples: req.method.eq:"POST", resp.code.gte:400,
        req.path.regex:"/api/.*", req.host.regex:".*example.com"."""
        result = await sandbox.proxy_tool("list_requests", {
            "httpql_filter": httpql_filter,
            "start_page": start_page,
            "end_page": end_page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "scope_id": scope_id,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def view_request(
        request_id: str,
        part: str | None = None,
        search_pattern: str | None = None,
        page: int | None = None,
        agent_id: str | None = None,
    ) -> str:
        """View detailed request/response data from proxy traffic.
        part: 'request' or 'response'. Use search_pattern for regex matching."""
        result = await sandbox.proxy_tool("view_request", {
            "request_id": request_id,
            "part": part,
            "search_pattern": search_pattern,
            "page": page,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def browser_action(
        action: str,
        url: str | None = None,
        coordinate: str | None = None,
        text: str | None = None,
        js_code: str | None = None,
        tab_id: str | None = None,
        duration: str | None = None,
        key: str | None = None,
        file_path: str | None = None,
        clear: bool = False,
        agent_id: str | None = None,
    ) -> Sequence[types.TextContent | types.ImageContent]:
        """Control a Playwright browser in the sandbox. Returns a screenshot after each action.
        Actions: launch, goto, click, type, double_click, hover, scroll_up, scroll_down,
        press_key, execute_js, wait, back, forward, new_tab, switch_tab, close_tab,
        list_tabs, save_pdf, get_console_logs, view_source, close.
        Click coordinates must be derived from the most recent screenshot.
        Start with 'launch', end with 'close'."""
        kwargs: dict[str, Any] = {"action": action}
        if url is not None:
            kwargs["url"] = url
        if coordinate is not None:
            kwargs["coordinate"] = coordinate
        if text is not None:
            kwargs["text"] = text
        if js_code is not None:
            kwargs["js_code"] = js_code
        if tab_id is not None:
            kwargs["tab_id"] = tab_id
        if duration is not None:
            kwargs["duration"] = duration
        if key is not None:
            kwargs["key"] = key
        if file_path is not None:
            kwargs["file_path"] = file_path
        if clear:
            kwargs["clear"] = clear
        if agent_id is not None:
            kwargs["agent_id"] = agent_id

        result = await sandbox.proxy_tool("browser_action", kwargs)

        # Build response with screenshot as ImageContent
        content: list[types.TextContent | types.ImageContent] = []

        # Extract screenshot if present
        screenshot_b64 = None
        if isinstance(result, dict):
            screenshot_b64 = result.pop("screenshot", None)

        # Add text content (metadata: url, title, tab info, etc.)
        content.append(
            types.TextContent(type="text", text=json.dumps(result))
        )

        # Add screenshot as image
        if screenshot_b64:
            content.append(
                types.ImageContent(
                    type="image",
                    data=screenshot_b64,
                    mimeType="image/png",
                )
            )

        return content

    @mcp.tool()
    async def python_action(
        action: str,
        code: str | None = None,
        timeout: int = 30,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Run Python code in a persistent interpreter session inside the sandbox.
        Actions: new_session, execute, close, list_sessions.
        Proxy functions (list_requests, send_request, etc.) are pre-imported.
        Sessions maintain state (variables, imports) between calls.
        Must start with 'new_session' before using 'execute'."""
        kwargs: dict[str, Any] = {"action": action, "timeout": timeout}
        if code is not None:
            kwargs["code"] = code
        if session_id is not None:
            kwargs["session_id"] = session_id
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("python_action", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def list_files(
        directory_path: str = "/workspace",
        depth: int = 3,
        agent_id: str | None = None,
    ) -> str:
        """List files in the sandbox workspace recursively."""
        result = await sandbox.proxy_tool("list_files", {
            "directory_path": directory_path,
            "depth": depth,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def search_files(
        directory_path: str,
        file_pattern: str | None = None,
        search_pattern: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Search file contents in the sandbox workspace by name pattern or content regex."""
        result = await sandbox.proxy_tool("search_files", {
            "directory_path": directory_path,
            "file_pattern": file_pattern,
            "search_pattern": search_pattern,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def str_replace_editor(
        file_path: str,
        old_str: str,
        new_str: str,
        agent_id: str | None = None,
    ) -> str:
        """Edit a file in the sandbox by replacing a text string."""
        result = await sandbox.proxy_tool("str_replace_editor", {
            "file_path": file_path,
            "old_str": old_str,
            "new_str": new_str,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def scope_rules(
        action: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
        scope_id: str | None = None,
        scope_name: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Manage proxy scope patterns for domain/file filtering.
        Actions: get, list, create, update, delete.
        Use allowlist for domain patterns to include, denylist to exclude."""
        kwargs: dict[str, Any] = {"action": action}
        if allowlist is not None:
            kwargs["allowlist"] = allowlist
        if denylist is not None:
            kwargs["denylist"] = denylist
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if scope_name is not None:
            kwargs["scope_name"] = scope_name
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("scope_rules", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def list_sitemap(
        scope_id: str | None = None,
        parent_id: str | None = None,
        depth: str = "DIRECT",
        page: int = 1,
        agent_id: str | None = None,
    ) -> str:
        """View hierarchical sitemap of discovered attack surface from proxy traffic.
        Use parent_id to drill down into subdirectories.
        depth: DIRECT (immediate children) or ALL (recursive)."""
        kwargs: dict[str, Any] = {"depth": depth, "page": page}
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if parent_id is not None:
            kwargs["parent_id"] = parent_id
        if agent_id is not None:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("list_sitemap", kwargs)
        return json.dumps(result)

    @mcp.tool()
    async def view_sitemap_entry(
        entry_id: str,
        agent_id: str | None = None,
    ) -> str:
        """Get detailed info about a specific sitemap entry and its related requests."""
        result = await sandbox.proxy_tool("view_sitemap_entry", {
            "entry_id": entry_id,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)
