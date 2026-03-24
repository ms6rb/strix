from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from fastmcp import FastMCP

from .sandbox import SandboxManager
from .tools_helpers import (
    parse_nuclei_jsonl,
    build_nuclei_command,
    _normalize_title,
    _find_duplicate,
    _normalize_severity,
    scan_for_notable,
)

try:
    from strix.telemetry.tracer import get_global_tracer
except ImportError:
    def get_global_tracer():  # type: ignore[misc]  # pragma: no cover
        return None


def register_recon_tools(mcp: FastMCP, sandbox: SandboxManager) -> None:

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
