# Strix Recon Phase — Design Spec

**Date:** 2026-03-17
**Status:** Draft
**Branch:** `feat/mcp-orchestration` (fork-only for tools; modules upstream-compatible)

## Problem

During bug bounty testing, Claude jumps straight from `start_scan` into vulnerability-specific agents. There is no reconnaissance phase. This means:

- API paths are guessed manually instead of brute-forced with ffuf
- Subdomains beyond the provided scope list are never discovered
- Source maps are never checked, missing full original source code
- Only port 443 is tested — debug ports, admin panels, exposed databases on non-standard ports are missed
- Nuclei's 9000+ templates are never run systematically
- Historical endpoints via Wayback Machine are never checked
- Mobile APK analysis is never performed

The sandbox already has the tools (ffuf, subfinder, nmap, nuclei, httpx, etc.) but the methodology doesn't tell Claude when or how to use them.

## Solution

Four coordinated changes:

1. **Methodology** — Add Phase 0 (recon) before vulnerability testing
2. **Modules** — 6 recon knowledge modules in `strix/skills/reconnaissance/`
3. **Tools** — 2 dedicated MCP tools: `nuclei_scan`, `download_sourcemaps`
4. **Plan integration** — Recon agent templates in `generate_plan()` + structured note handoff

## Architecture

### Scan Flow (Before → After)

**Before:**
```
start_scan → detect stack → Phase 1 (vuln agents) → Phase 2 (chains) → end_scan
```

**After:**
```
start_scan → detect stack → Phase 0 (recon agents) → Phase 1 (vuln agents) → Phase 2 (chains) → end_scan
```

### Phase 0 Agent Dispatch

Based on target type, the coordinator dispatches 1-3 recon agents in parallel:

| Target Type | Recon Agents |
|---|---|
| **web app** | 1. Surface discovery (ffuf + source maps + wayback) 2. Infrastructure recon (nmap + nuclei) |
| **domain** | 1. Subdomain enumeration (subfinder + httpx) 2. Surface discovery (ffuf on live hosts) 3. Infrastructure recon (nmap + nuclei) |
| **local code** | 1. Surface discovery (ffuf + source maps against running app) 2. Infrastructure recon (nmap + nuclei against running app) |

**Note on local code targets:** Once the application is started, it is a running web service and benefits from the same recon as web targets. Source code provides the codebase view; recon provides the runtime view (exposed endpoints, debug ports, misconfigurations that only appear at runtime).

### Recon-to-Vuln Handoff

Recon agents write structured notes via `create_note(category="recon")`. The coordinator reads them after Phase 0 completes and adjusts Phase 1 dispatch based on discoveries.

**Required change:** Add `"recon"` to `_VALID_NOTE_CATEGORIES` in `tools.py` (currently `["general", "findings", "methodology", "questions", "plan"]`).

Structured note format:
```
## Discovered Endpoints
- POST /api/v1/users (authenticated)
- GET /api/v1/files/{id} (IDOR candidate)
- GET /graphql (introspection enabled)

## Open Ports
- 8080: admin panel (Basic auth)
- 9090: debug/metrics (unauthenticated)

## Source Maps
- /assets/main.abc123.js.map → 47 original source files recovered to /workspace/sourcemaps/

## Nuclei Findings
- 3 findings auto-filed as vulnerability reports (see list_vulnerability_reports)
```

Phase 1 agents receive recon context in their dispatch prompt so they don't rediscover the attack surface.

---

## Component 1: Methodology Changes

**File:** `strix-mcp/src/strix_mcp/methodology.md`

### New Section: Phase 0 — Reconnaissance

Insert after stack detection, before Phase 1:

```markdown
## Phase 0 — Reconnaissance

Before vulnerability testing, run reconnaissance to map the full attack surface.

### Coordinator Actions:
1. Review the scan plan for `phase: 0` agents
2. Dispatch all recon agents in parallel using `dispatch_agent`
3. Wait for all recon agents to complete
4. Read recon results: `list_notes(category="recon")`
5. Adjust Phase 1 plan based on discoveries:
   - New endpoints → more targeted vulnerability agents
   - GraphQL discovered → dispatch GraphQL agent even if not in original plan
   - Source maps recovered → dispatch code review agent for recovered source
   - Open non-standard ports → dispatch agents to probe those services
6. Proceed to Phase 1

### Recon Agent Behavior:
- Use dedicated tools when available (`nuclei_scan`, `download_sourcemaps`)
- Fall back to `terminal_execute` for tools without dedicated MCP wrappers
- Write ALL results as structured notes: `create_note(category="recon", title="...")`
- Auto-file confirmed vulnerabilities found during recon (e.g., nuclei findings)
- Stay within scope: check `scope_rules` before scanning new targets
```

### Update to Web-Only Template

Add recon references to the web-only agent approach section, noting that recon agents handle discovery before vulnerability agents begin.

---

## Component 2: Recon Modules

**Location:** `strix/skills/reconnaissance/`
**Format:** Markdown with YAML frontmatter (upstream-compatible, uses `strix.skills` API)

### Module 1: `directory_bruteforce.md`

**Content covers:**
- Tool selection: ffuf (preferred — fastest, JSON output), dirsearch (fallback), gobuster
- Wordlist selection by detected stack:
  - General: `/usr/share/wordlists/dirb/common.txt`, `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt`
  - API-focused: `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt`
  - Framework-specific paths (Next.js: `/_next/`, `/_next/data/`; Django: `/admin/`; Laravel: `/telescope/`)
- Command patterns:
  - Basic: `ffuf -u URL/FUZZ -w wordlist -o results.json -of json -mc all -fc 404`
  - With extensions: `-e .php,.asp,.aspx,.jsp,.json,.xml,.yaml,.env,.bak,.old`
  - Recursive: `-recursion -recursion-depth 2`
  - Rate-limited: `-rate 100 -t 10`
- Filtering noise: by response size (`-fs`), word count (`-fw`), line count (`-fl`)
- Interpreting results: 200 (content), 301/302 (redirect — follow), 401/403 (auth-protected — interesting), 500 (potential vuln)
- Output: structured note with endpoints categorized as API, admin, static, docs, debug

### Module 2: `subdomain_enumeration.md`

**Content covers:**
- Passive enumeration:
  - `subfinder -d target.com -silent -o subs.txt`
  - Certificate transparency: `curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u`
  - DNS brute-force: `ffuf -u http://FUZZ.target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fc 404`
- Active validation:
  - `httpx -l subs.txt -status-code -title -tech-detect -o live.txt`
  - Categorize: production, staging, internal, API, CDN
- Scope filtering: cross-reference with `scope_rules` before any testing
- Cloud patterns: S3 naming conventions, Azure blob patterns, GCP storage
- Subdomain takeover checks: dangling CNAMEs, unclaimed services
- Output: structured note with live subdomains, IPs, status codes, technologies

### Module 3: `source_map_discovery.md`

**Content covers:**
- Finding JS bundles:
  - Parse HTML for `<script src="...">` tags
  - Check network traffic via `list_requests` for `.js` responses
  - Framework-specific locations: Next.js `/_next/static/chunks/`, Vite `/assets/`, Webpack `/static/js/`
- Checking for source maps:
  - Read last 200 bytes of each .js file for `//# sourceMappingURL=` comment
  - Try `{url}.map` as fallback
  - Check `SourceMap` HTTP response header
- What to look for in recovered source:
  - API keys and secrets (grep for `API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`)
  - Internal API endpoints not visible in minified code
  - Authentication and authorization logic
  - Comments revealing business logic or TODO items
  - Environment-specific configuration
- Framework-specific notes:
  - Next.js: source maps often present in development but removed in production; check `/_next/static/` chunks
  - Vite: development mode serves source maps by default
  - Create React App: `GENERATE_SOURCEMAP=true` (default in some versions)
- Output: list of recovered source files with flagged findings (keys, endpoints, logic)

### Module 4: `port_scanning.md`

**Content covers:**
- Quick scan: `nmap -sS -T4 --top-ports 1000 -oN scan.txt target`
- Service detection: `nmap -sV -sC -p PORT target`
- Common interesting ports for web targets:
  - 80, 443, 8080, 8443 (web servers)
  - 3000, 5000, 8000, 9000 (development servers)
  - 9090, 9091 (metrics/admin — Prometheus, debug)
  - 27017 (MongoDB), 6379 (Redis), 5432 (PostgreSQL), 3306 (MySQL)
  - 2222, 2375 (Docker), 8500 (Consul), 4443 (Kubernetes API)
- What to do with findings:
  - Unauthenticated services → immediate finding
  - Admin panels → test default credentials
  - Debug/metrics endpoints → information disclosure
  - Exposed databases → critical finding
- Rate limiting: respect scope, avoid aggressive scanning
- Output: structured note with open ports, services, versions, and assessment

### Module 5: `nuclei_scanning.md`

**Content covers:**
- Template categories and when to use them:
  - `cves/` — known CVEs (always run)
  - `exposures/` — exposed files, configs, backups (always run)
  - `misconfigurations/` — server/service misconfigs (always run)
  - `vulnerabilities/` — generic vulnerability checks
  - `technologies/` — technology-specific checks
  - `default-logins/` — default credentials (run on admin panels)
- Command patterns:
  - Broad: `nuclei -u URL -severity critical,high,medium -jsonl -o results.jsonl`
  - Targeted: `nuclei -u URL -tags nextjs,nginx -jsonl -o results.jsonl`
  - Rate-limited: `-rate-limit 50 -concurrency 10`
  - Multiple targets: `-l targets.txt`
- Interpreting results: template ID, matched-at URL, severity, extracted data
- Validation: confirm true positives before filing (some templates have false positives)
- Integration with `nuclei_scan` MCP tool when available (auto-files reports)
- Manual fallback: parse JSONL output, file reports for confirmed findings
- Output: filed vulnerability reports + structured note summarizing scan coverage

### Module 6: `mobile_apk_analysis.md`

**Content covers:**
- Obtaining the APK:
  - Download from APKPure/APKMirror via `browser_action`
  - `adb pull` if device available (unlikely in sandbox)
- Decompiling:
  - `apktool d app.apk -o decompiled/` — resources + smali
  - `jadx -d source/ app.apk` — Java/Kotlin source recovery
- What to extract:
  - `AndroidManifest.xml`: exported activities, deep links, permissions, `android:debuggable`
  - Hardcoded endpoints: grep for `https://`, `http://`, API base URLs
  - API keys: grep for `API_KEY`, `SECRET`, `TOKEN`, common key patterns
  - Certificate pinning config: `network_security_config.xml`, OkHttp pinning
  - Auth flow: OAuth redirect URIs, token storage mechanism
  - Firebase config: `google-services.json` with project ID, API key
- Deep link analysis: `adb shell am start -d "scheme://host/path"`
- Output: structured note with discovered endpoints, keys, and attack surface

**Note:** This module has no corresponding recon agent template or auto-dispatch trigger. Mobile APK analysis is manual/on-demand only — the coordinator or user invokes it when the target has a mobile app. It is not part of the automated Phase 0 flow because APK download requires manual steps (browsing APKPure, selecting the right version).

---

## Component 3: MCP Tools

**Location:** `strix-mcp/src/strix_mcp/tools.py` (fork-only)

### Tool 1: `nuclei_scan`

```python
@mcp.tool()
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: str = "critical,high,medium",
    rate_limit: int = 100,
    agent_id: str | None = None,
) -> str:
    """Run nuclei vulnerability scanner against a target.

    Executes nuclei with selected templates, parses structured output,
    and auto-files confirmed findings as vulnerability reports.

    Args:
        target: URL or host to scan.
        templates: Template categories to use (e.g., ["cves", "exposures"]).
                   Defaults to all if not specified.
        severity: Comma-separated severity filter. Default: "critical,high,medium".
        rate_limit: Requests per second. Default: 100.
        agent_id: Agent ID for sandbox routing.
    """
```

**Implementation steps:**
1. Validate active scan exists
2. Build nuclei command:
   ```
   nuclei -u {target} -severity {severity} -rate-limit {rate_limit}
          -jsonl -o /tmp/nuclei_results.jsonl -silent
   ```
   If `templates` provided: add `-t {template}` for each
3. Execute via `sandbox.proxy_tool("terminal_execute", {"command": cmd, "timeout": timeout})`
   - Default `timeout` parameter: 600 seconds (10 minutes)
   - `terminal_execute` timeout behavior: stops waiting for output but the nuclei process continues running in the sandbox. This is important — a timeout does NOT kill nuclei.
4. Read results file via `sandbox.proxy_tool("terminal_execute", {"command": "cat /tmp/nuclei_results.jsonl"})`
   - If step 3 timed out, the results file contains partial results (nuclei writes incrementally)
   - If the file doesn't exist yet, return `{total_findings: 0, timed_out: true}`
5. Parse each JSONL line:
   ```json
   {
     "template-id": "git-config",
     "matched-at": "https://target.com/.git/config",
     "severity": "medium",
     "info": {"name": "Git Config File", "description": "..."}
   }
   ```
6. For each finding, file directly via the tracer (not the MCP tool):
   - Call `tracer.add_vulnerability_report(title, severity, description)` directly
   - This avoids JSON serialization overhead of calling the MCP tool internally
   - Title: `"{template_name} — {matched_at}"`
   - Severity: from nuclei output (map nuclei severity to strix severity)
   - Content: template description + matched data + nuclei template ID
   - Affected endpoint: `matched-at` URL
   - Deduplication happens automatically via existing title normalization in the tracer
7. Return summary:
   ```json
   {
     "target": "https://target.com",
     "templates_used": ["cves", "exposures", "misconfigurations"],
     "total_findings": 12,
     "auto_filed": 9,
     "skipped_duplicates": 3,
     "timed_out": false,
     "severity_breakdown": {"critical": 1, "high": 3, "medium": 5},
     "findings": [
       {"template_id": "git-config", "severity": "medium", "url": "..."}
     ]
   }
   ```

**Tool parameter addition:**
```python
async def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: str = "critical,high,medium",
    rate_limit: int = 100,
    timeout: int = 600,       # seconds, default 10 minutes
    agent_id: str | None = None,
) -> str:
```

**Error handling:**
- No active scan → return error
- Nuclei not found in sandbox → return error with install instructions
- Timeout → read partial results from file, return with `timed_out: true`
- Empty results → return `{total_findings: 0}` (not an error)
- JSONL parse error on a line → skip that line, include in `errors` list

### Tool 2: `download_sourcemaps`

```python
@mcp.tool()
async def download_sourcemaps(
    target_url: str,
    agent_id: str | None = None,
) -> str:
    """Discover and download JavaScript source maps from a web target.

    Fetches the target URL, extracts script tags, checks each JS file
    for source maps, downloads and extracts original source code into
    /workspace/sourcemaps/{domain}/.

    Args:
        target_url: Base URL to scan for JS bundles.
        agent_id: Agent ID for sandbox routing.
    """
```

**Implementation approach:** The MCP tool builds a self-contained Python script and executes it as a single `python_action` call inside the sandbox. The Python session has `send_request` pre-imported, so the script can make HTTP requests directly without going through MCP proxy calls. This avoids the proxy-call explosion problem (30-60+ round trips for a typical app).

**Implementation steps:**
1. Validate active scan exists
2. Build a Python script that:
   a. Fetches target HTML via the pre-imported `send_request`
   b. Extracts `<script src="...">` URLs (regex: `<script[^>]+src=["']([^"']+)["']`)
   c. Resolves relative URLs to absolute
   d. For each JS URL: fetches the file, checks last 500 chars for `//# sourceMappingURL=` or `//@ sourceMappingURL=`, checks `SourceMap` response header, tries `{url}.map` as fallback
   e. For each discovered `.map` URL: fetches the source map JSON, parses `sources` and `sourcesContent` arrays
   f. Scans recovered source for notable patterns: `API_KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE_KEY`, `aws_access_key`, `firebase`
   g. Outputs a structured JSON result to stdout
3. Execute via `sandbox.proxy_tool("python_action", {"action": "execute", "code": script, "timeout": 120})`
4. Save recovered source files to `/workspace/sourcemaps/{domain}/` via `str_replace_editor` (batch call after script completes)
5. Return summary:
   ```json
   {
     "target_url": "https://target.com",
     "bundles_checked": 8,
     "maps_found": 2,
     "files_recovered": 47,
     "save_path": "/workspace/sourcemaps/target.com/",
     "file_list": [
       "src/api/auth.ts",
       "src/api/users.ts",
       "src/config/index.ts"
     ],
     "notable": [
       "src/config/index.ts:12 — matches pattern API_KEY",
       "src/api/auth.ts:45 — matches pattern JWT secret"
     ]
   }
   ```

**Error handling:**
- No active scan → return error
- Target unreachable → return error
- No script tags found → return `{bundles_checked: 0, maps_found: 0}`
- Source map fetch fails → skip, include in `errors` list
- Source map parse fails → skip, include in `errors` list

---

## Component 4: Plan Integration

**File:** `strix-mcp/src/strix_mcp/stack_detector.py`

### New Recon Agent Templates

Add to `generate_plan()` so recon agents appear in the scan plan with `phase: 0`:

```python
RECON_TEMPLATES = [
    {
        "id": "recon_surface_discovery",
        "task": (
            "Map the attack surface: run directory brute-forcing with ffuf against "
            "the target using common and stack-specific wordlists. Check all discovered "
            "JS bundles for source maps using download_sourcemaps. Query Wayback Machine "
            "for historical endpoints. Write all results as structured recon notes."
        ),
        "modules": ["directory_bruteforce", "source_map_discovery"],
        "triggers": ["web_app"],
        "confidence": "high",
        "phase": 0,
    },
    {
        "id": "recon_infrastructure",
        "task": (
            "Infrastructure reconnaissance: run nmap port scan against the target "
            "to discover non-standard ports and services. Run nuclei_scan with default "
            "templates for quick vulnerability wins. Write all results as structured "
            "recon notes. Nuclei findings are auto-filed as vulnerability reports."
        ),
        "modules": ["port_scanning", "nuclei_scanning"],
        "triggers": ["web_app", "domain"],
        "confidence": "high",
        "phase": 0,
    },
    {
        "id": "recon_subdomain_enum",
        "task": (
            "Enumerate subdomains using subfinder and certificate transparency logs. "
            "Validate live hosts with httpx. Check for subdomain takeover on dangling "
            "CNAMEs. Cross-reference with scope rules before any testing. Write all "
            "results as structured recon notes."
        ),
        "modules": ["subdomain_enumeration"],
        "triggers": ["domain"],
        "confidence": "high",
        "phase": 0,
    },
]
```

### `generate_plan()` Integration

**Key detail:** Recon templates must NOT go through the existing `MODULE_RULES` filtering logic. The existing `generate_plan()` matches triggers against `active_triggers` (built from detected stack) and then filters agent modules through `MODULE_RULES`. Recon module names (`directory_bruteforce`, `nuclei_scanning`, etc.) are not in `MODULE_RULES` and would be filtered out.

**Implementation:**
1. Process `RECON_TEMPLATES` in a separate loop before the existing `_AGENT_TEMPLATES` loop
2. For recon templates, match triggers against `active_triggers` (same mechanism) but include modules as-is without `MODULE_RULES` filtering
3. Add `"phase": 0` to each recon agent dict, `"phase": 1` to each existing vulnerability agent dict

**Trigger clarification:** The `"domain"` trigger fires when the target was provided with `type: "domain"`. For `type: "web_application"` targets that happen to be domain names, subdomain enumeration does NOT auto-trigger — the user chose to scope testing to a specific web app, not the entire domain. If they want subdomain enumeration, they should provide targets with `type: "domain"`.

The `"web_app"` trigger fires for both `web_application` targets and `local_code` targets (after the app is started, it's a running web service). This ensures local code targets get full recon treatment at runtime.

### Plan Output Format Change

The `generate_plan()` return value currently has:
```python
{"agents": [{"task": ..., "modules": [...], "confidence": ...}, ...]}
```

Add `phase` field to each agent:
```python
{"agents": [
    {"task": ..., "modules": [...], "confidence": ..., "phase": 0},  # recon
    {"task": ..., "modules": [...], "confidence": ..., "phase": 1},  # vuln
]}
```

Existing vulnerability templates default to `"phase": 1`. The coordinator processes agents phase by phase.

### Recon Context Injection

No new parameters needed on `dispatch_agent` or `build_agent_prompt`. The coordinator includes recon context directly in the `task` string when dispatching Phase 1 agents. The `task` parameter is already free-form text — this is simpler than adding a dedicated parameter (which would be just string concatenation with extra plumbing).

The coordinator reads recon notes via `list_notes(category="recon")` and appends them to each Phase 1 agent's task description:

```python
dispatch_agent(
    task=(
        "Test IDOR on user endpoints.\n\n"
        "RECON CONTEXT (from Phase 0):\n"
        "Discovered endpoints:\n"
        "- GET /api/v1/users/{id}\n"
        "- POST /api/v1/files\n"
        "- GET /graphql (introspection enabled)\n\n"
        "Use these discovered endpoints to focus your testing."
    ),
    modules=["idor"],
    is_web_only=True,
)
```

This approach avoids modifying `dispatch_agent`, `build_agent_prompt`, and the chaining template signatures. The methodology instructs the coordinator to do this injection.

---

## Files Changed

| File | Change Type | Track |
|---|---|---|
| `strix/skills/reconnaissance/directory_bruteforce.md` | New | Upstream-compatible |
| `strix/skills/reconnaissance/subdomain_enumeration.md` | New | Upstream-compatible |
| `strix/skills/reconnaissance/source_map_discovery.md` | New | Upstream-compatible |
| `strix/skills/reconnaissance/port_scanning.md` | New | Upstream-compatible |
| `strix/skills/reconnaissance/nuclei_scanning.md` | New | Upstream-compatible |
| `strix/skills/reconnaissance/mobile_apk_analysis.md` | New | Upstream-compatible |
| `strix-mcp/src/strix_mcp/methodology.md` | Modified | Fork-only |
| `strix-mcp/src/strix_mcp/stack_detector.py` | Modified | Fork-only |
| `strix-mcp/src/strix_mcp/tools.py` | Modified | Fork-only (add `"recon"` to valid note categories, add `nuclei_scan` + `download_sourcemaps` tools) |

---

## Testing Strategy

### Unit Tests

**Happy path:**
- `test_nuclei_scan`: mock `proxy_tool` calls, verify JSONL parsing and tracer report filing
- `test_download_sourcemaps`: mock `python_action` response, verify file extraction and notable detection
- `test_generate_plan_recon`: verify recon templates appear with `phase: 0` for web/domain targets
- `test_generate_plan_recon_local_code`: verify local code targets get surface discovery + infrastructure recon
- `test_create_note_recon_category`: verify `"recon"` is accepted as a valid note category

**Error/edge cases:**
- `test_nuclei_scan_no_active_scan`: verify error return when no scan is running
- `test_nuclei_scan_empty_results`: verify `{total_findings: 0}` return (not an error)
- `test_nuclei_scan_timeout`: verify partial results returned with `timed_out: true`
- `test_nuclei_scan_malformed_jsonl`: verify bad lines are skipped with errors list
- `test_download_sourcemaps_no_scripts`: verify `{bundles_checked: 0, maps_found: 0}`
- `test_download_sourcemaps_no_maps`: verify graceful return when JS files have no source maps
- `test_download_sourcemaps_no_active_scan`: verify error return
- `test_generate_plan_recon_no_domain_trigger`: verify subdomain enum does NOT fire for `web_application` targets

### Integration Tests (require Docker)
- Start scan with web target → verify recon agents appear in plan
- Run `nuclei_scan` against a test target → verify reports filed
- Run `download_sourcemaps` against a page with known source maps → verify files recovered

### Manual Validation
- Full bug bounty simulation against a test target (e.g., OWASP Juice Shop)
- Verify Phase 0 → Phase 1 handoff works (recon notes consumed by vuln agents)
- Verify `nuclei_scan` auto-filed reports appear in `end_scan` summary
