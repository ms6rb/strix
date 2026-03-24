from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from fastmcp import FastMCP
from mcp import types

from .sandbox import SandboxManager
from .tools_helpers import (
    _normalize_title, _find_duplicate, _categorize_owasp, _normalize_severity,
    _deduplicate_reports, _analyze_bundle,
    parse_nuclei_jsonl, build_nuclei_command,
    extract_script_urls, extract_sourcemap_url, scan_for_notable,
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
        """Execute a shell command in a persistent Kali Linux terminal session
        inside the sandbox. All security tools (nmap, ffuf, sqlmap, etc.) are available.

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
        kwargs: dict[str, Any] = {
            "start_page": start_page,
            "page_size": page_size,
            "sort_by": sort_by,
            "sort_order": sort_order,
        }
        if httpql_filter is not None:
            kwargs["httpql_filter"] = httpql_filter
        if end_page is not None:
            kwargs["end_page"] = end_page
        if scope_id is not None:
            kwargs["scope_id"] = scope_id
        if agent_id:
            kwargs["agent_id"] = agent_id
        result = await sandbox.proxy_tool("list_requests", kwargs)
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
        """Control a Playwright browser in the sandbox. Requires browser mode
        (enabled by default in strix-sandbox). Returns a screenshot after each action.

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

    # --- Session Comparison (MCP-side orchestration over proxy tools) ---

    @mcp.tool()
    async def compare_sessions(
        session_a: dict[str, Any],
        session_b: dict[str, Any],
        httpql_filter: str | None = None,
        methods: list[str] | None = None,
        max_requests: int = 50,
        agent_id: str | None = None,
    ) -> str:
        """Compare two authentication contexts across all captured proxy endpoints
        to find authorization and access control bugs (IDOR, broken access control).

        Replays each unique endpoint with both sessions and reports divergences.

        session_a: auth context dict with keys:
            label: human name (e.g. "admin", "user_alice")
            headers: (optional) headers to set (e.g. {"Authorization": "Bearer ..."})
            cookies: (optional) cookies to set (e.g. {"session": "abc123"})
        session_b: same structure, second auth context
        httpql_filter: optional HTTPQL filter to narrow requests (e.g. 'req.path.regex:"/api/.*"')
        methods: HTTP methods to include (default: GET, POST, PUT, DELETE, PATCH)
        max_requests: max unique endpoints to replay (default 50, cap at 200)
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)

        Returns: summary with total endpoints, classification counts, and per-endpoint results
        sorted by most interesting (divergent first)."""
        import asyncio
        import hashlib

        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"error": "No active scan. Call start_scan first."})

        if not session_a.get("label") or not session_b.get("label"):
            return json.dumps({"error": "Both sessions must have a 'label' field."})

        allowed_methods = set(m.upper() for m in (methods or ["GET", "POST", "PUT", "DELETE", "PATCH"]))
        max_requests = min(max_requests, 200)

        # Step 1: Fetch captured requests
        fetch_kwargs: dict[str, Any] = {
            "start_page": 1,
            "page_size": 100,
            "sort_by": "timestamp",
            "sort_order": "asc",
        }
        if httpql_filter:
            fetch_kwargs["httpql_filter"] = httpql_filter
        if agent_id:
            fetch_kwargs["agent_id"] = agent_id

        all_requests: list[dict[str, Any]] = []
        page = 1
        while True:
            fetch_kwargs["start_page"] = page
            result = await sandbox.proxy_tool("list_requests", dict(fetch_kwargs))
            items = result.get("requests", result.get("items", []))
            if not items:
                break
            all_requests.extend(items)
            if len(all_requests) >= max_requests * 3:  # fetch extra to account for dedup
                break
            page += 1

        if not all_requests:
            return json.dumps({
                "error": "No captured requests found. Browse the target first to generate proxy traffic.",
                "hint": "Use browser_action or send_request to capture traffic, then call compare_sessions.",
            })

        # Step 2: Deduplicate by method + path
        seen: set[str] = set()
        unique_requests: list[dict[str, Any]] = []
        for req in all_requests:
            method = req.get("method", "GET").upper()
            if method not in allowed_methods:
                continue
            path = req.get("path", req.get("url", ""))
            key = f"{method} {path}"
            if key not in seen:
                seen.add(key)
                unique_requests.append(req)
            if len(unique_requests) >= max_requests:
                break

        if not unique_requests:
            return json.dumps({
                "error": f"No requests matching methods {sorted(allowed_methods)} found in captured traffic.",
            })

        # Step 3: Replay each with both sessions
        def _build_modifications(session: dict[str, Any]) -> dict[str, Any]:
            mods: dict[str, Any] = {}
            if session.get("headers"):
                mods["headers"] = session["headers"]
            if session.get("cookies"):
                mods["cookies"] = session["cookies"]
            return mods

        mods_a = _build_modifications(session_a)
        mods_b = _build_modifications(session_b)

        comparisons: list[dict[str, Any]] = []

        for req in unique_requests:
            request_id = req.get("id", req.get("request_id", ""))
            if not request_id:
                continue

            method = req.get("method", "GET").upper()
            path = req.get("path", req.get("url", ""))
            proxy_kwargs_base = {}
            if agent_id:
                proxy_kwargs_base["agent_id"] = agent_id

            # Replay with both sessions concurrently
            try:
                result_a, result_b = await asyncio.gather(
                    sandbox.proxy_tool("repeat_request", {
                        "request_id": request_id,
                        "modifications": mods_a,
                        **proxy_kwargs_base,
                    }),
                    sandbox.proxy_tool("repeat_request", {
                        "request_id": request_id,
                        "modifications": mods_b,
                        **proxy_kwargs_base,
                    }),
                )
            except Exception as exc:
                comparisons.append({
                    "method": method,
                    "path": path,
                    "classification": "error",
                    "error": str(exc),
                })
                continue

            # Step 4: Compare responses
            def _extract_response(r: dict[str, Any]) -> dict[str, Any]:
                resp = r.get("response", r)
                status = resp.get("status_code", resp.get("code", 0))
                body = resp.get("body", "")
                body_len = len(body) if isinstance(body, str) else 0
                body_hash = hashlib.sha256(body.encode() if isinstance(body, str) else b"").hexdigest()[:12]
                return {"status": status, "body_length": body_len, "body_hash": body_hash}

            resp_a = _extract_response(result_a)
            resp_b = _extract_response(result_b)

            # Classify
            status_a = resp_a["status"]
            status_b = resp_b["status"]

            if status_a in (401, 403) and status_b in (401, 403):
                classification = "both_denied"
            elif resp_a["body_hash"] == resp_b["body_hash"] and status_a == status_b:
                classification = "same"
            elif status_a in (200, 201, 204) and status_b in (401, 403):
                classification = "a_only"
            elif status_b in (200, 201, 204) and status_a in (401, 403):
                classification = "b_only"
            else:
                classification = "divergent"

            entry: dict[str, Any] = {
                "method": method,
                "path": path,
                "classification": classification,
                session_a["label"]: {"status": status_a, "body_length": resp_a["body_length"]},
                session_b["label"]: {"status": status_b, "body_length": resp_b["body_length"]},
            }

            # Flag large body-length differences (potential data leak)
            if classification == "divergent" and resp_a["body_length"] > 0 and resp_b["body_length"] > 0:
                ratio = max(resp_a["body_length"], resp_b["body_length"]) / max(min(resp_a["body_length"], resp_b["body_length"]), 1)
                if ratio > 2:
                    entry["note"] = f"Body size ratio {ratio:.1f}x — possible data leak"

            comparisons.append(entry)

        # Step 5: Sort by interest (divergent > a_only/b_only > same/both_denied)
        priority = {"divergent": 0, "b_only": 1, "a_only": 2, "error": 3, "same": 4, "both_denied": 5}
        comparisons.sort(key=lambda c: priority.get(c["classification"], 99))

        # Summary
        counts: dict[str, int] = {}
        for c in comparisons:
            cls = c["classification"]
            counts[cls] = counts.get(cls, 0) + 1

        return json.dumps({
            "session_a": session_a["label"],
            "session_b": session_b["label"],
            "total_endpoints": len(comparisons),
            "classification_counts": counts,
            "results": comparisons,
        })

    # --- Firebase/Firestore Security Auditor (MCP-side, direct HTTP) ---

    @mcp.tool()
    async def firebase_audit(
        project_id: str,
        api_key: str,
        collections: list[str] | None = None,
        storage_bucket: str | None = None,
        auth_token: str | None = None,
        test_signup: bool = True,
    ) -> str:
        """Automated Firebase/Firestore security audit. Tests ACLs across auth states
        using the Firebase REST API — no sandbox required.

        Probes: Firebase Auth (signup, anonymous), Firestore collections (CRUD per
        auth state), Realtime Database (root read/write), Cloud Storage (list/read).
        Returns an ACL matrix showing what's open vs locked.

        project_id: Firebase project ID (e.g. "my-app-12345")
        api_key: Firebase Web API key (from app config or /__/firebase/init.json)
        collections: Firestore collection names to test. If omitted, probes common names.
        storage_bucket: Storage bucket name (default: "{project_id}.appspot.com")
        auth_token: optional pre-existing ID token for authenticated tests
        test_signup: whether to test if email/password signup is open (default true)

        Extract project_id and api_key from page source, JS bundles, or
        https://TARGET/__/firebase/init.json"""
        import httpx

        bucket = storage_bucket or f"{project_id}.appspot.com"
        default_collections = [
            "users", "accounts", "profiles", "settings", "config",
            "orders", "payments", "transactions", "subscriptions",
            "posts", "messages", "comments", "notifications",
            "documents", "files", "uploads", "items",
            "roles", "permissions", "admins", "teams", "organizations",
        ]
        target_collections = collections or default_collections

        results: dict[str, Any] = {
            "project_id": project_id,
            "auth": {},
            "realtime_db": {},
            "firestore": {},
            "storage": {},
        }

        async with httpx.AsyncClient(timeout=15) as client:
            # --- Phase 1: Auth probing ---
            tokens: dict[str, str | None] = {"unauthenticated": None}

            # Test anonymous auth
            try:
                resp = await client.post(
                    f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
                    json={"returnSecureToken": True},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    tokens["anonymous"] = data.get("idToken")
                    results["auth"]["anonymous_signup"] = "open"
                    results["auth"]["anonymous_uid"] = data.get("localId")
                else:
                    results["auth"]["anonymous_signup"] = "blocked"
                    error_msg = ""
                    try:
                        error_msg = resp.json().get("error", {}).get("message", "")
                    except Exception:
                        pass
                    results["auth"]["anonymous_error"] = error_msg or resp.text[:200]
            except Exception as e:
                results["auth"]["anonymous_signup"] = f"error: {e}"

            # Test email/password signup
            if test_signup:
                test_email = f"strix-audit-{uuid.uuid4().hex[:8]}@test.invalid"
                try:
                    resp = await client.post(
                        f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
                        json={
                            "email": test_email,
                            "password": "StrixAudit!Temp123",
                            "returnSecureToken": True,
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        tokens["email_signup"] = data.get("idToken")
                        results["auth"]["email_signup"] = "open"
                        results["auth"]["email_signup_uid"] = data.get("localId")
                    else:
                        error_msg = ""
                        try:
                            error_msg = resp.json().get("error", {}).get("message", "")
                        except Exception:
                            pass
                        results["auth"]["email_signup"] = "blocked"
                        results["auth"]["email_signup_error"] = error_msg or resp.text[:200]
                except Exception as e:
                    results["auth"]["email_signup"] = f"error: {e}"

            if auth_token:
                tokens["provided_token"] = auth_token

            # --- Phase 2: Realtime Database ---
            rtdb_url = f"https://{project_id}-default-rtdb.firebaseio.com"
            for auth_label, token in tokens.items():
                suffix = f".json?auth={token}" if token else ".json"
                key = f"read_{auth_label}"
                try:
                    resp = await client.get(f"{rtdb_url}/{suffix}")
                    if resp.status_code == 200:
                        body = resp.text[:500]
                        results["realtime_db"][key] = {
                            "status": "readable",
                            "preview": body if body != "null" else "(empty)",
                        }
                    elif resp.status_code == 401:
                        results["realtime_db"][key] = {"status": "denied"}
                    else:
                        results["realtime_db"][key] = {
                            "status": f"http_{resp.status_code}",
                            "body": resp.text[:200],
                        }
                except Exception as e:
                    results["realtime_db"][key] = {"status": f"error: {e}"}

            # --- Phase 3: Firestore ACL matrix ---
            firestore_base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"

            acl_matrix: dict[str, dict[str, dict[str, str]]] = {}

            for collection in target_collections:
                acl_matrix[collection] = {}
                for auth_label, token in tokens.items():
                    headers: dict[str, str] = {}
                    if token:
                        headers["Authorization"] = f"Bearer {token}"

                    ops: dict[str, str] = {}

                    # LIST (read collection)
                    try:
                        resp = await client.get(
                            f"{firestore_base}/{collection}?pageSize=3",
                            headers=headers,
                        )
                        if resp.status_code == 200:
                            docs = resp.json().get("documents", [])
                            ops["list"] = f"allowed ({len(docs)} docs)"
                        elif resp.status_code in (403, 401):
                            ops["list"] = "denied"
                        elif resp.status_code == 404:
                            ops["list"] = "not_found"
                        else:
                            ops["list"] = f"http_{resp.status_code}"
                    except Exception:
                        ops["list"] = "error"

                    # GET (read single doc — try first doc ID or "test")
                    try:
                        resp = await client.get(
                            f"{firestore_base}/{collection}/test",
                            headers=headers,
                        )
                        if resp.status_code == 200:
                            ops["get"] = "allowed"
                        elif resp.status_code in (403, 401):
                            ops["get"] = "denied"
                        elif resp.status_code == 404:
                            ops["get"] = "not_found_or_denied"
                        else:
                            ops["get"] = f"http_{resp.status_code}"
                    except Exception:
                        ops["get"] = "error"

                    # CREATE (write)
                    try:
                        resp = await client.post(
                            f"{firestore_base}/{collection}",
                            headers={**headers, "Content-Type": "application/json"},
                            json={"fields": {"_strix_audit": {"stringValue": "test"}}},
                        )
                        if resp.status_code in (200, 201):
                            ops["create"] = "allowed"
                            # Clean up: delete the test doc
                            doc_name = resp.json().get("name", "")
                            if doc_name:
                                if doc_name.startswith("http"):
                                    delete_url = doc_name
                                else:
                                    delete_url = f"https://firestore.googleapis.com/v1/{doc_name}"
                                try:
                                    await client.delete(delete_url, headers=headers)
                                except Exception:
                                    pass
                        elif resp.status_code in (403, 401):
                            ops["create"] = "denied"
                        else:
                            ops["create"] = f"http_{resp.status_code}"
                    except Exception:
                        ops["create"] = "error"

                    # DELETE (try deleting a non-existent doc to test permission)
                    try:
                        resp = await client.delete(
                            f"{firestore_base}/{collection}/_strix_audit_delete_test",
                            headers=headers,
                        )
                        if resp.status_code in (200, 204):
                            ops["delete"] = "allowed"
                        elif resp.status_code == 404:
                            ops["delete"] = "allowed_or_not_found"
                        elif resp.status_code in (403, 401):
                            ops["delete"] = "denied"
                        else:
                            ops["delete"] = f"http_{resp.status_code}"
                    except Exception:
                        ops["delete"] = "error"

                    acl_matrix[collection][auth_label] = ops

            # Filter out collections where all operations across all auth states are not_found
            active_collections: dict[str, dict[str, dict[str, str]]] = {}
            for coll, auth_results in acl_matrix.items():
                all_not_found = all(
                    all(
                        v in ("not_found", "not_found_or_denied", "allowed_or_not_found", "error")
                        or v.startswith("http_")
                        for v in ops.values()
                    )
                    for ops in auth_results.values()
                )
                if not all_not_found:
                    active_collections[coll] = auth_results

            results["firestore"]["tested_collections"] = len(target_collections)
            results["firestore"]["active_collections"] = len(active_collections)
            results["firestore"]["acl_matrix"] = active_collections

            # --- Phase 4: Cloud Storage ---
            for auth_label, token in tokens.items():
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                key = f"list_{auth_label}"
                try:
                    resp = await client.get(
                        f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=5",
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        items = resp.json().get("items", [])
                        results["storage"][key] = {
                            "status": "listable",
                            "objects_found": len(items),
                            "sample_names": [i.get("name", "") for i in items[:5]],
                        }
                    elif resp.status_code in (403, 401):
                        results["storage"][key] = {"status": "denied"}
                    else:
                        results["storage"][key] = {"status": f"http_{resp.status_code}"}
                except Exception as e:
                    results["storage"][key] = {"status": f"error: {e}"}

            # --- Cleanup: delete test accounts created during audit ---
            cleanup_failures: list[str] = []
            for label in ("anonymous", "email_signup"):
                token = tokens.get(label)
                if token:
                    try:
                        resp = await client.post(
                            f"https://identitytoolkit.googleapis.com/v1/accounts:delete?key={api_key}",
                            json={"idToken": token},
                        )
                        if resp.status_code != 200:
                            uid = results["auth"].get(f"{label}_uid", "unknown")
                            cleanup_failures.append(f"{label} (uid: {uid})")
                    except Exception:
                        uid = results["auth"].get(f"{label}_uid", "unknown")
                        cleanup_failures.append(f"{label} (uid: {uid})")
            if cleanup_failures:
                results["auth"]["cleanup_warning"] = (
                    f"Failed to delete test accounts: {', '.join(cleanup_failures)}. "
                    "Manual cleanup may be needed."
                )

            # --- Summary: flag security issues ---
            issues: list[str] = []

            if results["auth"].get("anonymous_signup") == "open":
                issues.append("Anonymous auth is open — any visitor gets an auth token")
            if results["auth"].get("email_signup") == "open":
                issues.append("Email/password signup is open — anyone can create accounts")

            for auth_label in tokens:
                rtdb_key = f"read_{auth_label}"
                if results["realtime_db"].get(rtdb_key, {}).get("status") == "readable":
                    issues.append(f"Realtime Database readable by {auth_label}")

            for coll, auth_results in active_collections.items():
                for auth_label, ops in auth_results.items():
                    if "allowed" in ops.get("list", ""):
                        issues.append(f"Firestore '{coll}' listable by {auth_label}")
                    if ops.get("create") == "allowed":
                        issues.append(f"Firestore '{coll}' writable by {auth_label}")

            for auth_label in tokens:
                storage_key = f"list_{auth_label}"
                if results["storage"].get(storage_key, {}).get("status") == "listable":
                    issues.append(f"Storage bucket listable by {auth_label}")

            results["issues"] = issues
            results["total_issues"] = len(issues)

        return json.dumps(results)

    # --- JS Bundle Analyzer (MCP-side, direct HTTP) ---

    @mcp.tool()
    async def analyze_js_bundles(
        target_url: str,
        additional_urls: list[str] | None = None,
        max_bundle_size: int = 5_000_000,
    ) -> str:
        """Analyze JavaScript bundles from a web target for security-relevant information.
        No sandbox required — fetches bundles directly via HTTP.

        Extracts and categorizes: API endpoints, Firebase/Supabase config, Firestore
        collection names, environment variables, hardcoded secrets, OAuth client IDs,
        internal hostnames, WebSocket URLs, route definitions. Also detects the frontend
        framework.

        target_url: URL to fetch and extract <script> tags from
        additional_urls: extra JS bundle URLs to analyze (e.g. from manual discovery)
        max_bundle_size: skip bundles larger than this (default 5MB)

        Use during reconnaissance to map the client-side attack surface before testing."""
        import httpx

        findings: dict[str, Any] = {
            "target_url": target_url,
            "bundles_analyzed": 0,
            "bundles_skipped": 0,
            "framework": None,
            "api_endpoints": [],
            "firebase_config": {},
            "collection_names": [],
            "environment_variables": [],
            "secrets": [],
            "oauth_ids": [],
            "internal_hostnames": [],
            "websocket_urls": [],
            "route_definitions": [],
            "interesting_strings": [],
            "errors": [],
        }

        # Regex patterns for extraction
        patterns = {
            "api_endpoint": re.compile(
                r'''["']((?:https?://[^"'\s]+)?/(?:api|graphql|v[0-9]+|rest|rpc)[^"'\s]{2,})["']''',
                re.IGNORECASE,
            ),
            "firebase_config": re.compile(
                r'''["']?(apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId|measurementId)["']?\s*[:=]\s*["']([^"']+)["']''',
            ),
            "collection_name": re.compile(
                r'''(?:collection|doc|collectionGroup)\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,50})["']''',
            ),
            "env_var": re.compile(
                r'''(?:process\.env\.|import\.meta\.env\.|NEXT_PUBLIC_|REACT_APP_|VITE_|NUXT_)([A-Z_][A-Z0-9_]{2,50})''',
            ),
            "secret_pattern": re.compile(
                r'''["']((?:sk_(?:live|test)_|AIza|ghp_|gho_|glpat-|xox[bpsar]-|AKIA|ya29\.)[A-Za-z0-9_\-]{10,})["']''',
            ),
            "generic_key_assignment": re.compile(
                r'''(?:api_?key|api_?secret|auth_?token|access_?token|private_?key|secret_?key|client_?secret)\s*[:=]\s*["']([^"']{8,})["']''',
                re.IGNORECASE,
            ),
            "oauth_id": re.compile(
                r'''["'](\d{5,}[\-\.][a-z0-9]+\.apps\.googleusercontent\.com)["']|["']([a-f0-9]{32,})["'](?=.*(?:client.?id|oauth))''',
                re.IGNORECASE,
            ),
            "internal_host": re.compile(
                r'''["']((?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-z0-9\-]+\.(?:internal|local|corp|private|staging|dev)(?:\.[a-z]+)?)(?::\d+)?(?:/[^"']*)?)["']''',
                re.IGNORECASE,
            ),
            "websocket": re.compile(
                r'''["'](wss?://[^"'\s]+)["']''',
                re.IGNORECASE,
            ),
            "route_def": re.compile(
                r'''(?:path|route|to)\s*[:=]\s*["'](/[a-zA-Z0-9/:_\-\[\]{}*]+)["']''',
            ),
        }

        # Framework detection patterns
        framework_signals = {
            "React": [r"__REACT", r"createElement", r"_jsx", r"ReactDOM"],
            "Next.js": [r"__NEXT_DATA__", r"_next/static", r"getServerSideProps", r"getStaticProps"],
            "Vue": [r"__vue__", r"Vue\.component", r"createApp", r"v-model"],
            "Angular": [r"@angular/core", r"ng-version", r"ngModule"],
            "Svelte": [r"__svelte", r"svelte/internal"],
            "Nuxt": [r"__NUXT__", r"nuxt.config"],
            "Remix": [r"__remixContext", r"remix.run"],
        }

        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            # Fetch the target page
            js_urls: list[str] = list(additional_urls or [])
            try:
                resp = await client.get(target_url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                })
                if resp.status_code == 200:
                    html = resp.text
                    # Extract script URLs
                    script_urls = extract_script_urls(html, target_url)
                    js_urls.extend(script_urls)

                    # Also check for inline scripts
                    inline_scripts = re.findall(
                        r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE,
                    )
                    inline_js = "\n".join(s for s in inline_scripts if len(s) > 50)
                    if inline_js:
                        # Analyze inline scripts as a virtual bundle
                        _analyze_bundle(
                            inline_js, "(inline)", patterns, framework_signals, findings,
                        )
                else:
                    findings["errors"].append(f"Failed to fetch {target_url}: HTTP {resp.status_code}")
            except Exception as e:
                findings["errors"].append(f"Failed to fetch {target_url}: {e}")

            # Deduplicate URLs
            seen_urls: set[str] = set()
            unique_js_urls: list[str] = []
            for url in js_urls:
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_js_urls.append(url)

            # Fetch and analyze each bundle
            for js_url in unique_js_urls:
                try:
                    resp = await client.get(js_url, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    })
                    if resp.status_code != 200:
                        findings["errors"].append(f"HTTP {resp.status_code} for {js_url}")
                        continue

                    content = resp.text
                    if len(content) > max_bundle_size:
                        findings["bundles_skipped"] += 1
                        continue

                    findings["bundles_analyzed"] += 1
                    _analyze_bundle(
                        content, js_url, patterns, framework_signals, findings,
                    )

                except Exception as e:
                    findings["errors"].append(f"Failed to fetch {js_url}: {e}")

        # Deduplicate all list fields
        for key in [
            "api_endpoints", "collection_names", "environment_variables",
            "secrets", "oauth_ids", "internal_hostnames", "websocket_urls",
            "route_definitions", "interesting_strings",
        ]:
            findings[key] = sorted(set(findings[key]))

        findings["total_findings"] = sum(
            len(findings[k]) for k in [
                "api_endpoints", "collection_names", "environment_variables",
                "secrets", "oauth_ids", "internal_hostnames", "websocket_urls",
                "route_definitions",
            ]
        )

        return json.dumps(findings)

    # --- Smart API Surface Discovery (MCP-side, direct HTTP) ---

    @mcp.tool()
    async def discover_api(
        target_url: str,
        extra_paths: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        """Smart API surface discovery. Probes a target with multiple content-types,
        detects GraphQL/gRPC-web services, checks for OpenAPI specs, and identifies
        responsive API paths. No sandbox required.

        Goes beyond path fuzzing — detects what kind of API the target speaks
        and returns the information needed to test it.

        target_url: base URL to probe (e.g. "https://api.example.com")
        extra_paths: additional paths to probe beyond the defaults
        extra_headers: additional headers to include in all probes (e.g. app-specific version headers)

        Use during reconnaissance when the target returns generic responses to curl
        (e.g. SPA shells, empty 200s) to discover the actual API surface."""
        import httpx

        base = target_url.rstrip("/")
        base_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            **(extra_headers or {}),
        }

        results: dict[str, Any] = {
            "target_url": target_url,
            "graphql": None,
            "grpc_web": None,
            "openapi_spec": None,
            "responsive_paths": [],
            "content_type_probes": [],
            "errors": [],
        }

        # --- Paths to probe ---
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3",
            "/rest", "/rest/v1",
            "/graphql", "/api/graphql", "/gql", "/query",
            "/health", "/healthz", "/ready", "/status",
            "/.well-known/openapi.json", "/.well-known/openapi.yaml",
        ]
        if extra_paths:
            api_paths.extend(extra_paths)

        # --- OpenAPI/Swagger spec locations ---
        spec_paths = [
            "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
            "/api-docs", "/api-docs.json", "/api/swagger.json",
            "/docs/openapi.json", "/v1/openapi.json", "/api/v1/openapi.json",
            "/swagger/v1/swagger.json", "/.well-known/openapi.json",
        ]

        # --- GraphQL detection paths ---
        graphql_paths = ["/graphql", "/api/graphql", "/gql", "/query", "/api/query"]

        # --- Content-types to probe ---
        content_types = [
            ("application/json", '{"query":"test"}'),
            ("application/x-www-form-urlencoded", "query=test"),
            ("application/grpc-web+proto", b"\x00\x00\x00\x00\x05\x0a\x03foo"),
            ("application/grpc-web-text", "AAAABQ=="),
            ("multipart/form-data; boundary=strix", "--strix\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nvalue\r\n--strix--"),
            ("application/x-protobuf", b"\x0a\x04test"),
        ]

        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:

            # --- Phase 1: GraphQL detection ---
            graphql_introspection = '{"query":"{ __schema { types { name } } }"}'
            for gql_path in graphql_paths:
                try:
                    resp = await client.post(
                        f"{base}{gql_path}",
                        headers={**base_headers, "Content-Type": "application/json"},
                        content=graphql_introspection,
                    )
                    if resp.status_code == 200:
                        body = resp.text
                        if "__schema" in body or '"types"' in body or '"data"' in body:
                            try:
                                data = resp.json()
                            except Exception:
                                data = {}
                            type_names = []
                            schema = data.get("data", {}).get("__schema", {})
                            if schema:
                                type_names = [t.get("name", "") for t in schema.get("types", [])[:20]]
                            results["graphql"] = {
                                "path": gql_path,
                                "introspection": "enabled" if schema else "partial",
                                "types": type_names,
                            }
                            break
                    # Check if GraphQL but introspection disabled
                    elif resp.status_code in (400, 405):
                        body = resp.text
                        if "graphql" in body.lower() or "must provide" in body.lower() or "query" in body.lower():
                            results["graphql"] = {
                                "path": gql_path,
                                "introspection": "disabled",
                                "hint": body[:200],
                            }
                            break
                except Exception:
                    pass

            # --- Phase 2: gRPC-web detection ---
            grpc_paths = ["/", "/api", "/grpc", "/service"]
            for grpc_path in grpc_paths:
                try:
                    resp = await client.post(
                        f"{base}{grpc_path}",
                        headers={
                            **base_headers,
                            "Content-Type": "application/grpc-web+proto",
                            "X-Grpc-Web": "1",
                        },
                        content=b"\x00\x00\x00\x00\x00",
                    )
                    # gRPC services typically return specific headers or status codes
                    grpc_status = resp.headers.get("grpc-status")
                    content_type = resp.headers.get("content-type", "")
                    if grpc_status is not None or "grpc" in content_type.lower():
                        results["grpc_web"] = {
                            "path": grpc_path,
                            "grpc_status": grpc_status,
                            "content_type": content_type,
                        }
                        break
                    # Some WAFs block gRPC specifically
                    if resp.status_code in (403, 406) and "grpc" in resp.text.lower():
                        results["grpc_web"] = {
                            "path": grpc_path,
                            "status": "blocked_by_waf",
                            "hint": resp.text[:200],
                        }
                        break
                except Exception:
                    pass

            # --- Phase 3: OpenAPI/Swagger spec discovery ---
            for spec_path in spec_paths:
                try:
                    resp = await client.get(
                        f"{base}{spec_path}",
                        headers=base_headers,
                    )
                    if resp.status_code == 200:
                        body = resp.text[:500]
                        if any(marker in body for marker in ['"openapi"', '"swagger"', "openapi:", "swagger:"]):
                            try:
                                spec_data = resp.json()
                                endpoints = []
                                for path, methods in spec_data.get("paths", {}).items():
                                    for method in methods:
                                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                                            endpoints.append(f"{method.upper()} {path}")
                                results["openapi_spec"] = {
                                    "url": f"{base}{spec_path}",
                                    "title": spec_data.get("info", {}).get("title", ""),
                                    "version": spec_data.get("info", {}).get("version", ""),
                                    "endpoint_count": len(endpoints),
                                    "endpoints": endpoints[:50],
                                }
                            except Exception:
                                results["openapi_spec"] = {
                                    "url": f"{base}{spec_path}",
                                    "format": "yaml_or_unparseable",
                                }
                            break
                except Exception:
                    pass

            # --- Phase 4: Path probing with multiple content-types (concurrent) ---
            import asyncio
            sem = asyncio.Semaphore(5)  # max 5 concurrent path probes

            async def _probe_path(path: str) -> dict[str, Any] | None:
                async with sem:
                    url = f"{base}{path}"
                    path_results: dict[str, Any] = {"path": path, "responses": {}}
                    interesting = False

                    try:
                        resp = await client.get(url, headers=base_headers)
                        path_results["responses"]["GET"] = {
                            "status": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "body_length": len(resp.text),
                        }
                        if resp.status_code not in (404, 405, 502, 503):
                            interesting = True
                    except Exception:
                        pass

                    for ct, body in content_types:
                        try:
                            resp = await client.post(
                                url,
                                headers={**base_headers, "Content-Type": ct},
                                content=body if isinstance(body, bytes) else body.encode(),
                            )
                            ct_key = ct.split(";")[0]
                            path_results["responses"][f"POST_{ct_key}"] = {
                                "status": resp.status_code,
                                "content_type": resp.headers.get("content-type", ""),
                                "body_length": len(resp.text),
                            }
                            if resp.status_code not in (404, 405, 502, 503):
                                interesting = True
                        except Exception:
                            pass

                    return path_results if interesting else None

            probe_results = await asyncio.gather(*[_probe_path(p) for p in api_paths])
            results["responsive_paths"] = [r for r in probe_results if r is not None]

            # --- Phase 5: Content-type differential on base URL ---
            # Probes the root URL specifically — api_paths may not include "/" and
            # some SPAs only respond differently at the root.
            for ct, body in content_types:
                try:
                    resp = await client.post(
                        base,
                        headers={**base_headers, "Content-Type": ct if "boundary" not in ct else ct},
                        content=body if isinstance(body, bytes) else body.encode(),
                    )
                    ct_key = ct.split(";")[0]
                    results["content_type_probes"].append({
                        "content_type": ct_key,
                        "status": resp.status_code,
                        "response_content_type": resp.headers.get("content-type", ""),
                        "body_length": len(resp.text),
                    })
                except Exception as e:
                    results["content_type_probes"].append({
                        "content_type": ct.split(";")[0],
                        "error": str(e),
                    })

        # --- Summary ---
        results["summary"] = {
            "has_graphql": results["graphql"] is not None,
            "has_grpc_web": results["grpc_web"] is not None,
            "has_openapi_spec": results["openapi_spec"] is not None,
            "responsive_path_count": len(results["responsive_paths"]),
        }

        return json.dumps(results)

    # --- Cross-Tool Chain Reasoning (MCP-side) ---

    @mcp.tool()
    async def reason_chains(
        firebase_results: dict[str, Any] | None = None,
        js_analysis: dict[str, Any] | None = None,
        services: dict[str, Any] | None = None,
        session_comparison: dict[str, Any] | None = None,
        api_discovery: dict[str, Any] | None = None,
    ) -> str:
        """Reason about vulnerability chains by correlating findings across
        multiple recon tools. Pass the JSON results from firebase_audit,
        analyze_js_bundles, discover_services, compare_sessions, and/or
        discover_api. Also reads existing vulnerability reports from the
        current scan.

        Returns chain hypotheses — each with evidence (what you found),
        chain description (what attack this enables), missing links (what's
        needed to prove it), and a concrete next action.

        Call after running recon tools to discover higher-order attack paths
        that no single tool would surface alone.

        firebase_results: output from firebase_audit
        js_analysis: output from analyze_js_bundles
        services: output from discover_services
        session_comparison: output from compare_sessions
        api_discovery: output from discover_api"""
        from .chaining import reason_cross_tool_chains

        # Collect existing vuln reports if scan is active
        tracer = get_global_tracer()
        vuln_reports = tracer.get_existing_vulnerabilities() if tracer else []

        chains = reason_cross_tool_chains(
            firebase_results=firebase_results,
            js_analysis=js_analysis,
            services=services,
            session_comparison=session_comparison,
            api_discovery=api_discovery,
            vuln_reports=vuln_reports,
        )

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        chains.sort(key=lambda c: severity_order.get(c.get("severity", "low"), 99))

        return json.dumps({
            "total_chains": len(chains),
            "chains": chains,
        })

    # --- CMS & Third-Party Service Discovery (MCP-side, direct HTTP + DNS) ---

    @mcp.tool()
    async def discover_services(
        target_url: str,
        check_dns: bool = True,
    ) -> str:
        """Discover third-party services and CMS platforms used by the target.
        Scans page source and JS bundles for service identifiers, then probes
        each discovered service to check if its API is publicly accessible.
        No sandbox required.

        Detects: Sanity CMS, Firebase, Supabase, Stripe, Algolia, Sentry,
        Segment, LaunchDarkly, Intercom, Mixpanel, Google Analytics, Amplitude,
        Contentful, Prismic, Strapi, Auth0, Okta, AWS Cognito.

        target_url: URL to scan for third-party service identifiers
        check_dns: whether to lookup DNS TXT records for service verification strings (default true)

        Use during reconnaissance to find hidden attack surface in third-party integrations."""
        import httpx

        service_patterns: dict[str, list[tuple[re.Pattern[str], int]]] = {
            "sanity": [
                (re.compile(r'''projectId["':\s]+["']([a-z0-9]{8,12})["']'''), 1),
                (re.compile(r'''cdn\.sanity\.io/[^"']*?([a-z0-9]{8,12})'''), 1),
            ],
            "firebase": [
                (re.compile(r'''["']([a-z0-9\-]+)\.firebaseapp\.com["']'''), 1),
                (re.compile(r'''["']([a-z0-9\-]+)\.firebaseio\.com["']'''), 1),
            ],
            "supabase": [
                (re.compile(r'''["']([a-z]{20})\.supabase\.co["']'''), 1),
                (re.compile(r'''supabaseUrl["':\s]+["'](https://[a-z]+\.supabase\.co)["']'''), 1),
            ],
            "stripe": [
                (re.compile(r'''["'](pk_(?:live|test)_[A-Za-z0-9]{20,})["']'''), 1),
            ],
            "algolia": [
                (re.compile(r'''(?:appId|applicationId|application_id)["':\s]+["']([A-Z0-9]{10})["']''', re.IGNORECASE), 1),
            ],
            "sentry": [
                (re.compile(r'''["'](https://[a-f0-9]+@[a-z0-9]+\.ingest\.sentry\.io/\d+)["']'''), 1),
            ],
            "segment": [
                (re.compile(r'''(?:writeKey|write_key)["':\s]+["']([A-Za-z0-9]{20,})["']'''), 1),
                (re.compile(r'''analytics\.load\(["']([A-Za-z0-9]{20,})["']\)'''), 1),
            ],
            "intercom": [
                (re.compile(r'''intercomSettings.*?app_id["':\s]+["']([a-z0-9]{8})["']''', re.IGNORECASE), 1),
            ],
            "mixpanel": [
                (re.compile(r'''mixpanel\.init\(["']([a-f0-9]{32})["']'''), 1),
            ],
            "google_analytics": [
                (re.compile(r'''["'](G-[A-Z0-9]{10,})["']'''), 1),
                (re.compile(r'''["'](UA-\d{6,}-\d{1,})["']'''), 1),
                (re.compile(r'''["'](GTM-[A-Z0-9]{6,})["']'''), 1),
            ],
            "auth0": [
                (re.compile(r'''["']([a-zA-Z0-9]+\.(?:us|eu|au|jp)\.auth0\.com)["']'''), 1),
            ],
            "contentful": [
                (re.compile(r'''cdn\.contentful\.com/spaces/([a-z0-9]{12})'''), 1),
            ],
        }

        results: dict[str, Any] = {
            "target_url": target_url,
            "discovered_services": {},
            "dns_txt_records": [],
            "probes": {},
            "errors": [],
        }

        # Phase 1: Fetch page and config endpoints
        page_content = ""
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            try:
                resp = await client.get(target_url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                })
                if resp.status_code == 200:
                    page_content = resp.text
            except Exception as e:
                results["errors"].append(f"Failed to fetch {target_url}: {e}")

            for config_path in ["/__/firebase/init.json", "/env.js", "/config.js"]:
                try:
                    resp = await client.get(
                        f"{target_url.rstrip('/')}{config_path}",
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code == 200 and len(resp.text) > 10:
                        page_content += "\n" + resp.text
                except Exception:
                    pass

            # Phase 2: Pattern matching
            for service_name, patterns_list in service_patterns.items():
                for pattern, group_idx in patterns_list:
                    for m in pattern.finditer(page_content):
                        val = m.group(group_idx)
                        if service_name not in results["discovered_services"]:
                            results["discovered_services"][service_name] = []
                        if val not in results["discovered_services"][service_name]:
                            results["discovered_services"][service_name].append(val)

            # Phase 3: Probe discovered services
            discovered = results["discovered_services"]

            for project_id in discovered.get("sanity", []):
                try:
                    query = '*[_type != ""][0...5]{_type, _id}'
                    resp = await client.get(
                        f"https://{project_id}.api.sanity.io/v2021-10-21/data/query/production",
                        params={"query": query},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        doc_types = sorted({
                            doc["_type"] for doc in data.get("result", []) if doc.get("_type")
                        })
                        results["probes"][f"sanity_{project_id}"] = {
                            "status": "accessible",
                            "document_types": doc_types,
                            "sample_count": len(data.get("result", [])),
                        }
                    else:
                        results["probes"][f"sanity_{project_id}"] = {"status": "denied"}
                except Exception as e:
                    results["probes"][f"sanity_{project_id}"] = {"status": f"error: {e}"}

            for key in discovered.get("stripe", []):
                if key.startswith("pk_"):
                    results["probes"][f"stripe_{key[:15]}"] = {
                        "status": "publishable_key_exposed",
                        "key_type": "live" if "pk_live" in key else "test",
                    }

            for dsn in discovered.get("sentry", []):
                if "ingest.sentry.io" in dsn:
                    results["probes"]["sentry_dsn"] = {
                        "status": "dsn_exposed",
                        "dsn": dsn,
                    }

        # Phase 4: DNS TXT records
        if check_dns:
            import asyncio
            from urllib.parse import urlparse
            hostname = urlparse(target_url).hostname or ""
            parts = hostname.split(".")
            domains = [hostname]
            if len(parts) > 2:
                domains.append(".".join(parts[-2:]))

            for domain in domains:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "dig", "+short", "TXT", domain,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                    if stdout:
                        for line in stdout.decode().strip().splitlines():
                            txt = line.strip().replace('" "', '').strip('"')
                            if txt:
                                results["dns_txt_records"].append({"domain": domain, "record": txt})
                except FileNotFoundError:
                    results["errors"].append("DNS TXT lookup skipped: 'dig' not found on system")
                    break
                except Exception:
                    pass

        results["total_services"] = len(results["discovered_services"])
        results["total_probes"] = len(results["probes"])

        return json.dumps(results)

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
