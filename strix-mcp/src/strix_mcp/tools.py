from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urljoin

from fastmcp import FastMCP
from mcp import types

from .sandbox import SandboxManager

try:
    from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
except ImportError:
    Tracer = None  # type: ignore[assignment,misc]
    def get_global_tracer():  # type: ignore[misc]  # pragma: no cover
        return None
    def set_global_tracer(tracer):  # type: ignore[misc]  # pragma: no cover
        pass

logger = logging.getLogger(__name__)

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


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "recon"]


def _normalize_severity(severity: str) -> str:
    """Normalize severity to a known value, defaulting to 'info'."""
    normed = severity.lower().strip() if severity else "info"
    return normed if normed in _SEVERITY_ORDER else "info"


# --- Nuclei JSONL parsing ---

def parse_nuclei_jsonl(jsonl: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings.

    Each valid line becomes a dict with keys: template_id, url, severity, name, description.
    Malformed lines are silently skipped.
    """
    findings: list[dict[str, Any]] = []
    for line in jsonl.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info", {})
        findings.append({
            "template_id": data.get("template-id", "unknown"),
            "url": data.get("matched-at", ""),
            "severity": data.get("severity", "info"),
            "name": info.get("name", ""),
            "description": info.get("description", ""),
        })
    return findings


def build_nuclei_command(
    target: str,
    severity: str,
    rate_limit: int,
    templates: list[str] | None,
    output_file: str,
) -> str:
    """Build a nuclei CLI command string."""
    parts = [
        "nuclei",
        f"-u {target}",
        f"-severity {severity}",
        f"-rate-limit {rate_limit}",
        "-jsonl",
        f"-o {output_file}",
        "-silent",
    ]
    if templates:
        for t in templates:
            parts.append(f"-t {t}")
    return " ".join(parts)


# --- Source map discovery helpers ---


def extract_script_urls(html: str, base_url: str) -> list[str]:
    """Extract absolute URLs of <script src="..."> tags from HTML."""
    pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    matches = re.findall(pattern, html, re.IGNORECASE)
    return [urljoin(base_url, m) for m in matches]


def extract_sourcemap_url(js_content: str) -> str | None:
    """Extract sourceMappingURL from the end of a JS file."""
    # Check last 500 chars to avoid scanning huge files
    tail = js_content[-500:] if len(js_content) > 500 else js_content
    match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', tail)
    return match.group(1) if match else None


_NOTABLE_PATTERNS = [
    "API_KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY",
    "aws_access_key", "firebase", "supabase_key",
]


def scan_for_notable(sources: dict[str, str]) -> list[str]:
    """Scan recovered source files for notable patterns (secrets, keys).

    Returns list of strings like "src/config.ts:12 — matches pattern API_KEY".
    """
    results: list[str] = []
    for filepath, content in sources.items():
        for i, line in enumerate(content.splitlines(), 1):
            for pattern in _NOTABLE_PATTERNS:
                if pattern.lower() in line.lower():
                    results.append(f"{filepath}:{i} — matches pattern {pattern}")
                    break  # one match per line
    return results


def _deduplicate_reports(
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate reports by normalized title, keeping the richest entry."""
    seen: dict[str, dict[str, Any]] = {}

    for report in reports:
        key = _normalize_title(report["title"])
        if key in seen:
            existing = seen[key]
            if _SEVERITY_ORDER.index(_normalize_severity(report.get("severity", "info"))) > _SEVERITY_ORDER.index(_normalize_severity(existing.get("severity", "info"))):
                existing["severity"] = _normalize_severity(report["severity"])
            new_desc = report.get("description", "")
            existing_desc = existing.get("description", "")
            if new_desc and new_desc not in existing_desc:
                existing["description"] = existing_desc + f"\n\n---\n\n{new_desc}"
        else:
            seen[key] = dict(report)

    return list(seen.values())



def register_tools(mcp: FastMCP, sandbox: SandboxManager) -> None:
    fired_chains: set[str] = set()
    notes_storage: dict[str, dict[str, Any]] = {}

    # --- Lifecycle Tools ---

    @mcp.tool()
    async def start_scan(
        targets: list[dict[str, str]],
        scan_id: str | None = None,
    ) -> str:
        """Boot a Docker sandbox and initialize a security scan.

        targets: list of dicts with keys:
            type: local_code | web_application | repository | ip_address | domain
            value: file path, URL, or address
            name: (optional) label for local_code targets

        Detects the target's tech stack (frameworks, databases, auth, features) and
        generates a recommended scan plan with module assignments. For web targets,
        fingerprints via HTTP headers, cookies, and common paths.

        First run pulls the Docker image if not already cached.

        Returns: scan_id, detected_stack, recommended_plan, workspace path.
        If a Swagger/OpenAPI spec is found, returns openapi_spec with endpoint list."""
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

        # Initialize tracer (upstream pattern: entrypoint creates + sets global)
        if Tracer is not None:
            try:
                tracer = Tracer(run_name=sid)
                set_global_tracer(tracer)
                tracer.set_scan_config({"targets": targets})
            except Exception:
                logger.error("Failed to initialize tracer — vulnerability reports will NOT be persisted", exc_info=True)

        fired_chains.clear()
        notes_storage.clear()

        return json.dumps({
            "scan_id": state.scan_id,
            "status": "running",
            "workspace": "/workspace",
            **analysis,
            "message": "Sandbox ready. Target code copied to /workspace.",
        })

    @mcp.tool()
    async def end_scan() -> str:
        """Tear down the Docker sandbox and return a scan summary.

        Deduplicates findings by normalized title (higher severity wins on merge),
        groups by OWASP Top 10 (2021) category, and writes results to disk
        via the upstream Tracer (vulnerabilities/*.md, vulnerabilities.csv, penetration_test_report.md).

        Returns: unique_findings count, severity_counts, findings_by_category."""
        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []
        unique = _deduplicate_reports(reports)
        total_filed = len(reports)
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
            # Tracer stores "endpoint" (string); check both for robustness
            endpoint = r.get("endpoint") or r.get("affected_endpoint")
            if endpoint:
                entry["endpoint"] = endpoint
            cvss = r.get("cvss") or r.get("cvss_score")
            if cvss is not None:
                entry["cvss_score"] = cvss
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

        await sandbox.end_scan()

        # Finalize tracer after sandbox teardown — if we clear the tracer
        # before end_scan and destroy_sandbox fails, the session enters a
        # split state (tracer gone but scan still "active").
        if tracer:
            try:
                tracer.save_run_data(mark_complete=True)
            except Exception:
                logger.warning("Failed to save tracer run data")
            set_global_tracer(None)  # type: ignore[arg-type]

        fired_chains.clear()
        notes_storage.clear()

        return json.dumps(summary)

    @mcp.tool()
    async def get_scan_status() -> str:
        """Get current scan progress: elapsed time, registered agents, vulnerability
        counts by severity, and pending chain opportunities.

        Returns: scan_id, status, elapsed_seconds, agents list, severity_counts, pending_chains count."""
        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"status": "no_active_scan"})

        elapsed = (datetime.now(UTC) - scan.started_at).total_seconds()

        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        severity_counts: dict[str, int] = {}
        for r in reports:
            sev = r.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Count chains detected but not yet dispatched
        from .chaining import detect_chains
        all_possible = detect_chains(reports, fired=set())
        pending_chains = [c for c in all_possible if c["chain_name"] not in fired_chains]

        result = {
            "scan_id": scan.scan_id,
            "status": "running",
            "elapsed_seconds": round(elapsed),
            "agents_registered": len(scan.registered_agents),
            "agents": [
                {"id": aid, "task": name}
                for aid, name in scan.registered_agents.items()
            ],
            "total_reports": len(reports),
            "severity_counts": severity_counts,
            "pending_chains": len(pending_chains),
        }

        if tracer:
            result["tool_executions"] = tracer.get_real_tool_count()

        return json.dumps(result)

    @mcp.tool()
    async def create_vulnerability_report(
        title: str,
        content: str,
        severity: str,
        affected_endpoint: str | None = None,
        cvss_score: float | None = None,
    ) -> str:
        """File a confirmed vulnerability finding. Automatically deduplicates — if a
        similar finding exists, evidence is merged and the higher severity is kept.
        Also triggers automatic chain detection across all findings.

        title: vulnerability name (e.g. "SQL Injection in /api/users")
        content: full details including proof of exploitation, impact, and remediation
        severity: critical | high | medium | low | info (case-insensitive; unknown values default to info)
        affected_endpoint: URL path or component affected (e.g. "/api/users/:id")
        cvss_score: CVSS 3.1 base score (0.0-10.0)

        Only report validated vulnerabilities with proof of exploitation."""
        severity = _normalize_severity(severity)
        tracer = get_global_tracer()
        existing = tracer.get_existing_vulnerabilities() if tracer else []

        # MCP dedup check (title normalization)
        normalized = _normalize_title(title)
        dup_idx = _find_duplicate(normalized, existing)

        if dup_idx is not None:
            # Merge into the tracer's internal list directly — don't rely
            # on get_existing_vulnerabilities() returning shared references.
            report = tracer.vulnerability_reports[dup_idx] if tracer else existing[dup_idx]
            if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(
                _normalize_severity(report.get("severity", "info"))
            ):
                report["severity"] = severity
            # Tracer stores body text as "description", not "content"
            desc = report.get("description", "")
            report["description"] = desc + f"\n\n---\n\n**Additional evidence:**\n{content}"
            # Tracer stores "endpoint" as a string; accumulate comma-separated
            if affected_endpoint:
                existing_endpoint = report.get("endpoint", "")
                if existing_endpoint and existing_endpoint != affected_endpoint:
                    if affected_endpoint not in existing_endpoint:
                        report["endpoint"] = f"{existing_endpoint}, {affected_endpoint}"
                elif not existing_endpoint:
                    report["endpoint"] = affected_endpoint
            if cvss_score is not None and (report.get("cvss") is None or cvss_score > report["cvss"]):
                report["cvss"] = cvss_score

            # Write updated finding to disk (Tracer only auto-writes on add, not on merge)
            if tracer:
                try:
                    tracer.save_run_data()
                except Exception:
                    pass

            # Detect chains after merge
            from .chaining import detect_chains
            new_chains = detect_chains(existing, fired=fired_chains)

            result: dict[str, Any] = {
                "report_id": report["id"],
                "title": report["title"],
                "severity": report.get("severity", "info"),
                "merged": True,
            }
            if new_chains:
                result["chains_detected"] = new_chains
            return json.dumps(result)

        # New finding — delegate to Tracer
        if tracer:
            report_id = tracer.add_vulnerability_report(
                title=title,
                severity=severity,
                description=content,
                endpoint=affected_endpoint,
                cvss=cvss_score,
            )
        else:
            report_id = f"vuln-{uuid.uuid4().hex[:8]}"
            logger.warning("No tracer active — report '%s' (%s) will NOT be persisted or appear in list_vulnerability_reports", title, report_id)

        # Detect chains after new finding
        from .chaining import detect_chains
        all_reports = tracer.get_existing_vulnerabilities() if tracer else []
        new_chains = detect_chains(all_reports, fired=fired_chains)

        result: dict[str, Any] = {
            "report_id": report_id,
            "title": title,
            "severity": severity,
            "merged": False,
        }
        if new_chains:
            result["chains_detected"] = new_chains
        return json.dumps(result)

    @mcp.tool()
    async def list_vulnerability_reports(severity: str | None = None) -> str:
        """List all vulnerability reports filed in the current scan (summaries only).
        Check this before filing a new report to avoid duplicates.

        severity: optional filter — critical | high | medium | low | info (case-insensitive)

        Returns: list of {id, title, severity, endpoint, cvss_score}."""
        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        if severity:
            filtered = [r for r in reports if _normalize_severity(r.get("severity", "info")) == _normalize_severity(severity)]
        else:
            filtered = list(reports)

        return json.dumps({
            "reports": [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "severity": r.get("severity", "info"),
                    # Tracer stores "endpoint" (string), not "affected_endpoints" (list)
                    **({"endpoint": r["endpoint"]} if "endpoint" in r else {}),
                    **({"cvss_score": r["cvss"]} if "cvss" in r else {}),
                }
                for r in filtered
            ],
            "total": len(filtered),
        })

    @mcp.tool()
    async def get_finding(finding_id: str) -> str:
        """Read the full markdown details of a specific vulnerability finding from disk.

        finding_id: the report ID (e.g. "vuln-a1b2c3d4") from list_vulnerability_reports.

        Returns the raw markdown content from strix_runs/<scan_id>/vulnerabilities/<id>.md."""
        tracer = get_global_tracer()
        if tracer is None:
            return json.dumps({"error": "No active scan."})

        safe_id = Path(finding_id).name
        vuln_file = tracer.get_run_dir() / "vulnerabilities" / f"{safe_id}.md"
        if not vuln_file.exists():
            return json.dumps({"error": f"Finding '{finding_id}' not found."})

        return vuln_file.read_text()

    @mcp.tool()
    async def get_module(name: str) -> str:
        """Load a security knowledge module by name. Modules contain exploitation
        techniques, bypass methods, validation requirements, and remediation guidance
        for a specific vulnerability class or technology.

        name: module name (e.g. "idor", "sql_injection", "authentication_jwt", "nextjs", "graphql")

        Load relevant modules at the START of testing work before analyzing code or running tests."""
        from . import resources
        try:
            return resources.get_module(name)
        except ValueError as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    async def list_modules(category: str | None = None) -> str:
        """List all available security knowledge modules with categories and descriptions.

        category: optional filter (e.g. "vulnerabilities", "frameworks", "technologies", "protocols")

        Returns: JSON mapping module_name -> {category, description}."""
        from . import resources
        return resources.list_modules(category=category)

    @mcp.tool()
    async def dispatch_agent(
        task: str,
        modules: list[str],
        is_web_only: bool = False,
        chain_context: dict[str, str] | None = None,
    ) -> str:
        """Register a new subagent and return a ready-to-use prompt for the Agent tool.
        Handles agent registration internally — pass the returned prompt directly to
        the Agent tool to dispatch.

        task: what the agent should test (e.g. "Test IDOR and access control on /api/users")
        modules: knowledge modules the agent should load (e.g. ["idor", "authentication_jwt"])
        is_web_only: true for live web targets with no source code in /workspace
        chain_context: for Phase 2 chain agents — dict with keys: finding_a, finding_b, chain_name

        Returns: agent_id, prompt (pass prompt to Agent tool)."""
        from .chaining import build_agent_prompt

        # Build prompt first (pure function) — avoids orphaned agent registration on error
        placeholder = "__pending_agent_id__"
        try:
            prompt = build_agent_prompt(
                task=task,
                modules=modules,
                agent_id=placeholder,
                is_web_only=is_web_only,
                chain_context=chain_context,
            )
        except KeyError as exc:
            return json.dumps({
                "error": f"chain_context is missing required key: {exc}. "
                         "Expected keys: finding_a, finding_b, chain_name."
            })
        agent_id = await sandbox.register_agent(task_name=task)
        prompt = prompt.replace(placeholder, agent_id)

        # Log agent creation to tracer
        tracer = get_global_tracer()
        if tracer:
            try:
                tracer.log_agent_creation(
                    agent_id=agent_id,
                    name="mcp_subagent",
                    task=task,
                    parent_id=sandbox.active_scan.default_agent_id if sandbox.active_scan else None,
                )
            except Exception:
                pass

        return json.dumps({
            "agent_id": agent_id,
            "prompt": prompt,
        })

    @mcp.tool()
    async def suggest_chains() -> str:
        """Review all vulnerability chaining opportunities detected so far.
        Call after Phase 1 completes to find attack chains across findings.

        Each chain combines two findings into a higher-severity exploit path
        and includes a ready-to-use dispatch payload (task + modules) for dispatch_agent.

        Returns: total_chains, new_chains count, chains list with dispatch payloads.
        Each chain includes previously_surfaced (bool) indicating if it was already detected."""
        from .chaining import detect_chains

        tracer = get_global_tracer()
        reports = tracer.get_existing_vulnerabilities() if tracer else []

        # Run detection without modifying fired set (show everything)
        all_chains = detect_chains(reports, fired=set())

        for chain in all_chains:
            chain["previously_surfaced"] = chain["chain_name"] in fired_chains

        new_count = sum(1 for c in all_chains if not c["previously_surfaced"])
        return json.dumps({
            "total_chains": len(all_chains),
            "new_chains": new_count,
            "chains": all_chains,
        })

    # --- Recon Tools ---

    @mcp.tool()
    async def nuclei_scan(
        target: str,
        templates: list[str] | None = None,
        severity: str = "critical,high,medium",
        rate_limit: int = 100,
        timeout: int = 600,
        agent_id: str | None = None,
    ) -> str:
        """Run nuclei vulnerability scanner against a target.

        Launches nuclei in the sandbox, parses structured output,
        and auto-files confirmed findings as vulnerability reports.

        target: URL or host to scan
        templates: template categories (e.g. ["cves", "exposures"]). Defaults to all.
        severity: comma-separated severity filter (default "critical,high,medium")
        rate_limit: max requests per second (default 100)
        timeout: max seconds to wait for completion (default 600)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"error": "No active scan. Call start_scan first."})

        output_file = f"/tmp/nuclei_{uuid.uuid4().hex[:8]}.jsonl"
        cmd = build_nuclei_command(
            target=target,
            severity=severity,
            rate_limit=rate_limit,
            templates=templates,
            output_file=output_file,
        )

        # Launch nuclei in background
        bg_cmd = f"nohup {cmd} > /dev/null 2>&1 & echo $!"
        launch_result = await sandbox.proxy_tool("terminal_execute", {
            "command": bg_cmd,
            "timeout": 10,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        pid = ""
        if isinstance(launch_result, dict):
            output = launch_result.get("output", "")
            pid = output.strip().splitlines()[-1].strip() if output.strip() else ""

        # Poll for completion
        import asyncio
        elapsed = 0
        poll_interval = 15
        timed_out = False
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            check = await sandbox.proxy_tool("terminal_execute", {
                "command": f"kill -0 {pid} 2>/dev/null && echo running || echo done",
                "timeout": 5,
                **({"agent_id": agent_id} if agent_id else {}),
            })
            status = ""
            if isinstance(check, dict):
                status = check.get("output", "").strip()
            if "done" in status:
                break
        else:
            timed_out = True

        # Read results file
        read_result = await sandbox.proxy_tool("terminal_execute", {
            "command": f"cat {output_file} 2>/dev/null || echo ''",
            "timeout": 10,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        jsonl_output = ""
        if isinstance(read_result, dict):
            jsonl_output = read_result.get("output", "")

        # Parse findings
        findings = parse_nuclei_jsonl(jsonl_output)

        # Auto-file via tracer (requires active tracer)
        tracer = get_global_tracer()
        if tracer is None:
            return json.dumps({
                "error": "No tracer active — nuclei findings cannot be filed. Ensure start_scan was called.",
                "total_findings": len(findings),
                "findings": [
                    {"template_id": f["template_id"], "severity": f["severity"], "url": f["url"]}
                    for f in findings
                ],
            })

        filed = 0
        skipped = 0
        for f in findings:
            title = f"{f['name']} — {f['url']}"
            existing = tracer.get_existing_vulnerabilities()
            normalized = _normalize_title(title)
            if _find_duplicate(normalized, existing) is not None:
                skipped += 1
                continue
            tracer.add_vulnerability_report(
                title=title,
                severity=_normalize_severity(f["severity"]),
                description=f"**Nuclei template:** {f['template_id']}\n\n{f['description']}",
                endpoint=f["url"],
            )
            filed += 1

        severity_breakdown: dict[str, int] = {}
        for f in findings:
            sev = _normalize_severity(f["severity"])
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        return json.dumps({
            "target": target,
            "templates_used": templates or ["all"],
            "total_findings": len(findings),
            "auto_filed": filed,
            "skipped_duplicates": skipped,
            "timed_out": timed_out,
            "severity_breakdown": severity_breakdown,
            "findings": [
                {"template_id": f["template_id"], "severity": f["severity"], "url": f["url"]}
                for f in findings
            ],
        })

    @mcp.tool()
    async def download_sourcemaps(
        target_url: str,
        agent_id: str | None = None,
    ) -> str:
        """Discover and download JavaScript source maps from a web target.

        Fetches the target URL, extracts script tags, checks each JS file
        for source maps, downloads and extracts original source code into
        /workspace/sourcemaps/{domain}/.

        target_url: base URL to scan for JS bundles
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"error": "No active scan. Call start_scan first."})

        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc

        # Build Python script that runs inside sandbox.
        # Regex patterns injected via repr() to avoid escaping issues in nested strings.
        script_regex = r'<script[^>]+src=["' + "'" + r'](.[^"' + "'" + r']+)["' + "'" + r']'
        sm_regex = r'//[#@]\s*sourceMappingURL=(\S+)'
        script = (
            'import json, re, sys\n'
            'from urllib.parse import urljoin\n'
            '\n'
            'SCRIPT_REGEX = SCRIPT_REGEX_PLACEHOLDER\n'
            'SM_REGEX = SM_REGEX_PLACEHOLDER\n'
            '\n'
            'results = {"bundles_checked": 0, "maps_found": 0, "files": {}, "errors": []}\n'
            '\n'
            'try:\n'
            '    resp = send_request("GET", TARGET_URL, timeout=30)\n'
            '    html = resp.get("response", {}).get("body", "") if isinstance(resp, dict) else ""\n'
            'except Exception as e:\n'
            '    results["errors"].append(f"Failed to fetch HTML: {e}")\n'
            '    print(json.dumps(results))\n'
            '    sys.exit(0)\n'
            '\n'
            'matches = re.findall(SCRIPT_REGEX, html, re.IGNORECASE)\n'
            'script_urls = [urljoin(TARGET_URL, m) for m in matches]\n'
            '\n'
            'for js_url in script_urls:\n'
            '    results["bundles_checked"] += 1\n'
            '    try:\n'
            '        js_resp = send_request("GET", js_url, timeout=15)\n'
            '        js_body = js_resp.get("response", {}).get("body", "") if isinstance(js_resp, dict) else ""\n'
            '        js_headers = js_resp.get("response", {}).get("headers", {}) if isinstance(js_resp, dict) else {}\n'
            '    except Exception as e:\n'
            '        results["errors"].append(f"Failed to fetch {js_url}: {e}")\n'
            '        continue\n'
            '\n'
            '    map_url = None\n'
            '    tail = js_body[-500:] if len(js_body) > 500 else js_body\n'
            '    sm_match = re.search(SM_REGEX, tail)\n'
            '    if sm_match:\n'
            '        map_url = urljoin(js_url, sm_match.group(1))\n'
            '    elif "SourceMap" in js_headers or "sourcemap" in js_headers or "X-SourceMap" in js_headers:\n'
            '        header_val = js_headers.get("SourceMap") or js_headers.get("sourcemap") or js_headers.get("X-SourceMap")\n'
            '        if header_val:\n'
            '            map_url = urljoin(js_url, header_val)\n'
            '    else:\n'
            '        fallback_url = js_url + ".map"\n'
            '        try:\n'
            '            fb_resp = send_request("GET", fallback_url, timeout=10)\n'
            '            fb_status = fb_resp.get("response", {}).get("status_code", 0) if isinstance(fb_resp, dict) else 0\n'
            '            if fb_status == 200:\n'
            '                map_url = fallback_url\n'
            '        except Exception:\n'
            '            pass\n'
            '\n'
            '    if not map_url:\n'
            '        continue\n'
            '\n'
            '    try:\n'
            '        map_resp = send_request("GET", map_url, timeout=30)\n'
            '        map_body = map_resp.get("response", {}).get("body", "") if isinstance(map_resp, dict) else ""\n'
            '        map_data = json.loads(map_body)\n'
            '    except Exception as e:\n'
            '        results["errors"].append(f"Failed to parse source map {map_url}: {e}")\n'
            '        continue\n'
            '\n'
            '    results["maps_found"] += 1\n'
            '    sources = map_data.get("sources", [])\n'
            '    contents = map_data.get("sourcesContent", [])\n'
            '    for i, src_path in enumerate(sources):\n'
            '        if i < len(contents) and contents[i]:\n'
            '            results["files"][src_path] = contents[i]\n'
            '\n'
            'print(json.dumps(results))\n'
        )
        script = script.replace("TARGET_URL", repr(target_url))
        script = script.replace("SCRIPT_REGEX_PLACEHOLDER", repr(script_regex))
        script = script.replace("SM_REGEX_PLACEHOLDER", repr(sm_regex))

        # Create session and execute
        session_result = await sandbox.proxy_tool("python_action", {
            "action": "new_session",
            **({"agent_id": agent_id} if agent_id else {}),
        })
        session_id = ""
        if isinstance(session_result, dict):
            session_id = session_result.get("session_id", "")

        exec_result = await sandbox.proxy_tool("python_action", {
            "action": "execute",
            "code": script,
            "timeout": 120,
            "session_id": session_id,
            **({"agent_id": agent_id} if agent_id else {}),
        })

        # Parse output
        output = ""
        if isinstance(exec_result, dict):
            output = exec_result.get("output", "")

        try:
            data = json.loads(output.strip().splitlines()[-1] if output.strip() else "{}")
        except (json.JSONDecodeError, IndexError):
            return json.dumps({"error": "Failed to parse source map discovery output", "raw": output[:500]})

        recovered_files = data.get("files", {})
        save_path = f"/workspace/sourcemaps/{domain}/"

        # Save files to sandbox
        for filepath, content in recovered_files.items():
            full_path = f"{save_path}{filepath}"
            try:
                await sandbox.proxy_tool("str_replace_editor", {
                    "command": "create",
                    "file_path": full_path,
                    "file_text": content,
                    **({"agent_id": agent_id} if agent_id else {}),
                })
            except Exception:
                pass  # best-effort save

        # Scan for notable patterns
        notable = scan_for_notable(recovered_files)

        # Close session
        if session_id:
            await sandbox.proxy_tool("python_action", {
                "action": "close",
                "session_id": session_id,
                **({"agent_id": agent_id} if agent_id else {}),
            })

        return json.dumps({
            "target_url": target_url,
            "bundles_checked": data.get("bundles_checked", 0),
            "maps_found": data.get("maps_found", 0),
            "files_recovered": len(recovered_files),
            "save_path": save_path if recovered_files else None,
            "file_list": list(recovered_files.keys())[:50],
            "notable": notable[:20],
            **({"errors": data["errors"]} if data.get("errors") else {}),
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
        """Execute a shell command in a persistent Kali Linux terminal session.

        command: the shell command to execute
        timeout: max seconds to wait for output (default 30, capped at 60). Command continues in background after timeout.
        terminal_id: identifier for persistent terminal session (default "default"). Use different IDs for concurrent sessions.
        is_input: if true, send as input to a running process instead of a new command
        no_enter: if true, send the command without pressing Enter
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """Send an HTTP request through the Caido proxy. All traffic is captured for analysis with list_requests and view_request.

        method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        url: full URL including scheme (e.g. "https://target.com/api/users")
        headers: HTTP headers dict
        body: request body string
        timeout: max seconds to wait for response (default 30)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """Replay a captured proxy request with optional modifications.

        request_id: the request ID from list_requests
        modifications: dict with optional keys — url (str), params (dict), headers (dict), body (str), cookies (dict)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Typical workflow: browse with browser_action -> list_requests -> repeat_request with modifications."""
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
        """List captured proxy requests with optional HTTPQL filtering.

        httpql_filter: HTTPQL query (e.g. 'req.method.eq:"POST"', 'resp.code.gte:400',
                       'req.path.regex:"/api/.*"', 'req.host.regex:".*example.com"')
        sort_by: timestamp | host | method | path | status_code | response_time | response_size | source
        sort_order: asc | desc
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """View detailed request or response data from captured proxy traffic.

        request_id: the request ID from list_requests
        part: request | response (default: request)
        search_pattern: regex pattern to highlight matches in the content
        page: page number for paginated responses
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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

        action: launch | goto | click | type | double_click | hover | scroll_up | scroll_down |
                press_key | execute_js | wait | back | forward | new_tab | switch_tab | close_tab |
                list_tabs | save_pdf | get_console_logs | view_source | close
        url: URL for goto/new_tab actions
        coordinate: "x,y" string for click/double_click/hover (derive from most recent screenshot)
        text: text to type for the type action
        js_code: JavaScript code for execute_js action
        tab_id: tab identifier for switch_tab/close_tab
        duration: seconds to wait for the wait action
        key: key name for press_key (e.g. "Enter", "Tab", "Escape")
        file_path: output path for save_pdf
        clear: if true, clear console log buffer (for get_console_logs)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

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

        action: new_session | execute | close | list_sessions
        code: Python code to execute (required for 'execute' action)
        timeout: max seconds for execution (default 30)
        session_id: session identifier (returned by new_session, required for execute/close)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Proxy functions (send_request, list_requests, etc.) are pre-imported.
        Sessions maintain state (variables, imports) between calls.
        Must call 'new_session' before using 'execute'."""
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
        """List files and directories in the sandbox workspace.

        directory_path: path to list (default "/workspace")
        depth: max recursion depth (default 3)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """Search file contents in the sandbox workspace.

        directory_path: directory to search in
        file_pattern: glob pattern for file names (e.g. "*.py", "*.js")
        search_pattern: regex pattern to match in file contents
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("search_files", {
            "directory_path": directory_path,
            "file_pattern": file_pattern,
            "search_pattern": search_pattern,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    @mcp.tool()
    async def str_replace_editor(
        command: str,
        file_path: str,
        file_text: str | None = None,
        view_range: list[int] | None = None,
        old_str: str | None = None,
        new_str: str | None = None,
        insert_line: int | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Edit, view, or create files in the sandbox workspace.

        command: one of view | create | str_replace | insert | undo_edit
        file_path: path to file in the sandbox (e.g. "/workspace/app.py")
        file_text: file content (required for create)
        view_range: [start_line, end_line] for view (1-indexed, use -1 for EOF)
        old_str: text to find (required for str_replace)
        new_str: replacement text (required for insert; optional for str_replace — omit to delete)
        insert_line: line number to insert after (required for insert)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        # Map MCP param "file_path" to upstream sandbox param "path"
        kwargs: dict[str, Any] = {"command": command, "path": file_path}
        if file_text is not None:
            kwargs["file_text"] = file_text
        if view_range is not None:
            kwargs["view_range"] = view_range
        if old_str is not None:
            kwargs["old_str"] = old_str
        if new_str is not None:
            kwargs["new_str"] = new_str
        if insert_line is not None:
            kwargs["insert_line"] = insert_line
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("str_replace_editor", kwargs)
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
        """Manage proxy scope rules for domain filtering.

        action: get | list | create | update | delete
        allowlist: domain patterns to include (e.g. ["*.example.com"])
        denylist: domain patterns to exclude
        scope_id: scope identifier (required for get/update/delete)
        scope_name: human-readable scope name (for create/update)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """View the hierarchical sitemap of discovered attack surface from proxy traffic.

        scope_id: filter by scope
        parent_id: drill down into a specific node's children
        depth: DIRECT (immediate children only) | ALL (full recursive tree)
        page: page number for pagination
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
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
        """Get detailed information about a specific sitemap entry and its related HTTP requests.

        entry_id: the sitemap entry ID from list_sitemap
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        result = await sandbox.proxy_tool("view_sitemap_entry", {
            "entry_id": entry_id,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        return json.dumps(result)

    # --- Notes Tools (MCP-side, not proxied) ---

    @mcp.tool()
    async def create_note(
        title: str,
        content: str,
        category: str = "general",
        tags: list[str] | None = None,
    ) -> str:
        """Create a structured note during the scan for tracking findings,
        methodology decisions, questions, or plans.

        title: note title
        content: note body text
        category: general | findings | methodology | questions | plan | recon
        tags: optional list of tags for filtering

        Returns: note_id on success."""
        if not title or not title.strip():
            return json.dumps({"success": False, "error": "Title cannot be empty"})
        if not content or not content.strip():
            return json.dumps({"success": False, "error": "Content cannot be empty"})
        if category not in VALID_NOTE_CATEGORIES:
            return json.dumps({
                "success": False,
                "error": f"Invalid category. Must be one of: {', '.join(VALID_NOTE_CATEGORIES)}",
            })

        note_id = uuid.uuid4().hex[:8]
        timestamp = datetime.now(UTC).isoformat()
        notes_storage[note_id] = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags or [],
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        return json.dumps({
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title.strip()}' created successfully",
        })

    @mcp.tool()
    async def list_notes(
        category: str | None = None,
        tags: list[str] | None = None,
        search: str | None = None,
    ) -> str:
        """List and filter notes created during the scan.

        category: filter by category — general | findings | methodology | questions | plan
        tags: filter by tags (notes matching any tag are returned)
        search: search query to match against note title and content

        Returns: notes list and total_count."""
        filtered = []
        for nid, note in notes_storage.items():
            if category and note.get("category") != category:
                continue
            if tags and not any(t in note.get("tags", []) for t in tags):
                continue
            if search:
                s = search.lower()
                if s not in note.get("title", "").lower() and s not in note.get("content", "").lower():
                    continue
            entry = dict(note)
            entry["note_id"] = nid
            filtered.append(entry)

        filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return json.dumps({"success": True, "notes": filtered, "total_count": len(filtered)})

    @mcp.tool()
    async def update_note(
        note_id: str,
        title: str | None = None,
        content: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Update an existing note's title, content, or tags.

        note_id: the ID returned by create_note
        title: new title (optional)
        content: new content (optional)
        tags: new tags list (optional, replaces existing tags)

        Returns: success status."""
        if note_id not in notes_storage:
            return json.dumps({"success": False, "error": f"Note with ID '{note_id}' not found"})

        note = notes_storage[note_id]
        if title is not None:
            if not title.strip():
                return json.dumps({"success": False, "error": "Title cannot be empty"})
            note["title"] = title.strip()
        if content is not None:
            if not content.strip():
                return json.dumps({"success": False, "error": "Content cannot be empty"})
            note["content"] = content.strip()
        if tags is not None:
            note["tags"] = tags
        note["updated_at"] = datetime.now(UTC).isoformat()

        return json.dumps({
            "success": True,
            "message": f"Note '{note['title']}' updated successfully",
        })

    @mcp.tool()
    async def delete_note(note_id: str) -> str:
        """Delete a note by ID.

        note_id: the ID returned by create_note

        Returns: success status."""
        if note_id not in notes_storage:
            return json.dumps({"success": False, "error": f"Note with ID '{note_id}' not found"})

        title = notes_storage[note_id]["title"]
        del notes_storage[note_id]
        return json.dumps({
            "success": True,
            "message": f"Note '{title}' deleted successfully",
        })
