from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .sandbox import SandboxManager
from .tools_helpers import (
    _normalize_title, _find_duplicate, _categorize_owasp, _normalize_severity,
    _deduplicate_reports,
    parse_nuclei_jsonl, build_nuclei_command,
    scan_for_notable,
    _SEVERITY_ORDER, VALID_NOTE_CATEGORIES,
)

try:
    from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
except ImportError:
    Tracer = None  # type: ignore[assignment,misc]
    def get_global_tracer():  # type: ignore[misc]  # pragma: no cover
        return None
    def set_global_tracer(tracer):  # type: ignore[misc]  # pragma: no cover
        pass

logger = logging.getLogger(__name__)


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
        tracer_status = "disabled"
        if Tracer is not None:
            try:
                tracer = Tracer(run_name=sid)
                set_global_tracer(tracer)
                tracer.set_scan_config({"targets": targets})
                tracer_status = "active"
            except Exception:
                logger.error("Failed to initialize tracer — vulnerability reports will NOT be persisted", exc_info=True)
                tracer_status = "failed"
        else:
            tracer_status = "unavailable (strix.telemetry not installed)"

        fired_chains.clear()
        notes_storage.clear()

        result = {
            "scan_id": state.scan_id,
            "status": "running",
            "workspace": "/workspace",
            **analysis,
            "tracer": tracer_status,
            "message": "Sandbox ready. Target code copied to /workspace.",
        }
        if tracer_status != "active":
            result["warning"] = f"Tracer is {tracer_status} — create_vulnerability_report, list_vulnerability_reports, and nuclei_scan will not persist findings."

        return json.dumps(result)

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

        if scan.loaded_skills:
            result["loaded_skills"] = sorted(scan.loaded_skills)

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
    async def load_skill(skills: str) -> str:
        """Dynamically load security knowledge skills into the current conversation.
        Runs client-side (no sandbox required). Returns the full skill content
        inline so you can immediately apply the techniques described.

        skills: comma-separated skill names (max 5). Use list_modules to see
            available skills. Examples: "nuclei,sqlmap", "xss", "graphql,nextjs"

        Prefer this over get_module when you need to actively apply multiple skills
        at once. The returned content includes exploitation techniques, tool usage,
        bypass methods, and validation requirements."""
        try:
            from strix.skills import (
                load_skills as _load_skills,
                parse_skill_list,
                validate_requested_skills,
            )
        except ImportError:
            return json.dumps({
                "success": False,
                "error": "strix.skills module not available. Use get_module as fallback.",
            })

        requested = parse_skill_list(skills)
        if not requested:
            return json.dumps({
                "success": False,
                "error": "No skills provided. Pass one or more comma-separated skill names.",
                "requested_skills": [],
            })

        validation_error = validate_requested_skills(requested)
        if validation_error:
            return json.dumps({
                "success": False,
                "error": validation_error,
                "requested_skills": requested,
            })

        loaded_content = _load_skills(requested)
        loaded_names = list(loaded_content.keys())
        failed = [s for s in requested if s not in loaded_names]

        # Track loaded skills in scan state if active
        scan = sandbox.active_scan
        if scan is not None:
            scan.loaded_skills |= set(loaded_names)

        result: dict[str, Any] = {
            "success": True,
            "requested_skills": requested,
            "loaded_skills": loaded_names,
        }
        if failed:
            result["failed_skills"] = failed
        result["skill_content"] = loaded_content

        return json.dumps(result)

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
        """Run nuclei vulnerability scanner against a target. Requires an active
        sandbox with nuclei installed (included in strix-sandbox image).

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

        # Launch nuclei in background — capture stderr for diagnostics
        stderr_file = output_file.replace(".jsonl", ".stderr")
        bg_cmd = f"nohup {cmd} 2>{stderr_file} & echo $!"
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

        # Read stderr for diagnostics
        stderr_result = await sandbox.proxy_tool("terminal_execute", {
            "command": f"tail -20 {stderr_file} 2>/dev/null || echo ''",
            "timeout": 5,
            **({"agent_id": agent_id} if agent_id else {}),
        })
        nuclei_stderr = ""
        if isinstance(stderr_result, dict):
            nuclei_stderr = stderr_result.get("output", "").strip()

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

        result_data: dict[str, Any] = {
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
        }
        if nuclei_stderr:
            result_data["nuclei_stderr"] = nuclei_stderr[:1000]
        return json.dumps(result_data)

    @mcp.tool()
    async def download_sourcemaps(
        target_url: str,
        agent_id: str | None = None,
    ) -> str:
        """Discover and download JavaScript source maps from a web target.
        Requires an active sandbox for Python execution and file storage.

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
            '    # Handle both response formats: sandbox may return {"response": {"body": ...}} or {"body": ...}\n'
            '    if isinstance(resp, dict):\n'
            '        if "response" in resp:\n'
            '            html = resp["response"].get("body", "")\n'
            '        else:\n'
            '            html = resp.get("body", "")\n'
            '    else:\n'
            '        html = str(resp) if resp else ""\n'
            '    results["html_length"] = len(html)\n'
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
            '        if isinstance(js_resp, dict) and "response" in js_resp:\n'
            '            js_body = js_resp["response"].get("body", "")\n'
            '            js_headers = js_resp["response"].get("headers", {})\n'
            '        elif isinstance(js_resp, dict):\n'
            '            js_body = js_resp.get("body", "")\n'
            '            js_headers = js_resp.get("headers", {})\n'
            '        else:\n'
            '            js_body = ""\n'
            '            js_headers = {}\n'
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
            '            if isinstance(fb_resp, dict) and "response" in fb_resp:\n'
            '                fb_status = fb_resp["response"].get("status_code", 0)\n'
            '            elif isinstance(fb_resp, dict):\n'
            '                fb_status = fb_resp.get("status_code", 0)\n'
            '            else:\n'
            '                fb_status = 0\n'
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
            '        if isinstance(map_resp, dict) and "response" in map_resp:\n'
            '            map_body = map_resp["response"].get("body", "")\n'
            '        elif isinstance(map_resp, dict):\n'
            '            map_body = map_resp.get("body", "")\n'
            '        else:\n'
            '            map_body = ""\n'
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
            "html_length": data.get("html_length", 0),
            "bundles_checked": data.get("bundles_checked", 0),
            "maps_found": data.get("maps_found", 0),
            "files_recovered": len(recovered_files),
            "save_path": save_path if recovered_files else None,
            "file_list": list(recovered_files.keys())[:50],
            "notable": notable[:20],
            **({"errors": data["errors"]} if data.get("errors") else {}),
        })

    # --- Proxied Tools (delegated to tools_proxy.py) ---
    from .tools_proxy import register_proxy_tools
    register_proxy_tools(mcp, sandbox)

    # --- Analysis Tools (delegated to tools_analysis.py) ---
    from .tools_analysis import register_analysis_tools
    register_analysis_tools(mcp, sandbox)

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
