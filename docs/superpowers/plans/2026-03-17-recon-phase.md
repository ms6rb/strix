# Recon Phase Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Phase 0 reconnaissance phase to Strix's scan flow so Claude automatically discovers attack surface before vulnerability testing.

**Architecture:** Four coordinated changes — (1) add `"recon"` note category + `nuclei_scan` and `download_sourcemaps` MCP tools in `tools.py`, (2) add recon agent templates + `phase` field to `generate_plan()` in `stack_detector.py`, (3) create 6 recon knowledge modules in `strix/skills/reconnaissance/`, (4) update `methodology.md` with Phase 0 instructions.

**Tech Stack:** Python 3, FastMCP, Docker sandbox (Kali Linux), pytest

**Spec:** `docs/superpowers/specs/2026-03-17-recon-phase-design.md`

**Test command:** `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`

---

### Task 1: Add "recon" note category

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py:1021`
- Test: `strix-mcp/tests/test_tools.py`

- [ ] **Step 1: Move `_VALID_NOTE_CATEGORIES` to module scope (without adding "recon" yet)**

**Important:** `_VALID_NOTE_CATEGORIES` is currently defined at line 1021 *inside* `register_tools()` as a local variable. It cannot be imported by tests. Move it to module scope first.

In `strix-mcp/src/strix_mcp/tools.py`:

1. Add at module scope (after `_SEVERITY_ORDER` at line 136, before `_normalize_severity`):

```python
VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan"]
```

2. Delete the local `_VALID_NOTE_CATEGORIES` at line 1021 (inside `register_tools()`)

3. Update all references from `_VALID_NOTE_CATEGORIES` to `VALID_NOTE_CATEGORIES` inside `register_tools()` (the `create_note` function at ~line 1043)

- [ ] **Step 2: Write the failing test**

In `strix-mcp/tests/test_tools.py`, add at the end of the file:

```python
class TestReconNoteCategory:
    def test_recon_is_valid_category(self):
        """The 'recon' category should be accepted by the notes system."""
        from strix_mcp.tools import VALID_NOTE_CATEGORIES
        assert "recon" in VALID_NOTE_CATEGORIES
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestReconNoteCategory -v --tb=short -o "addopts="`
Expected: FAIL with `assert 'recon' in ['general', 'findings', 'methodology', 'questions', 'plan']`

- [ ] **Step 4: Add "recon" to the list**

In `strix-mcp/src/strix_mcp/tools.py`, change the module-scope constant:

```python
VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "recon"]
```

Also update the docstring for `create_note` to include `recon`:

```python
        category: general | findings | methodology | questions | plan | recon
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestReconNoteCategory -v --tb=short -o "addopts="`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add 'recon' to valid note categories"
```

---

### Task 2: Add `phase` field to `generate_plan()` and recon templates

**Files:**
- Modify: `strix-mcp/src/strix_mcp/stack_detector.py:54-345`
- Test: `strix-mcp/tests/test_stack_detector.py`

- [ ] **Step 1: Write failing tests for recon templates**

In `strix-mcp/tests/test_stack_detector.py`, add a new test class at the end:

```python
class TestReconPhase:
    def test_web_app_plan_includes_recon_agents(self):
        """Web app targets should get phase-0 recon agents."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        assert len(recon_agents) >= 2, f"Expected >=2 recon agents, got {len(recon_agents)}"
        # Should have surface discovery and infrastructure
        tasks = [a["task"].lower() for a in recon_agents]
        assert any("directory" in t or "ffuf" in t or "surface" in t for t in tasks)
        assert any("nmap" in t or "nuclei" in t or "infrastructure" in t for t in tasks)

    def test_domain_plan_includes_subdomain_enum(self):
        """Domain targets should get subdomain enumeration agent."""
        stack = detect_stack(EMPTY_SIGNALS)
        stack["target_types"] = ["domain"]
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        tasks = [a["task"].lower() for a in recon_agents]
        assert any("subdomain" in t for t in tasks), f"No subdomain agent in: {tasks}"

    def test_web_app_no_subdomain_enum(self):
        """Web app targets (no domain type) should NOT get subdomain enumeration."""
        stack = detect_stack(EMPTY_SIGNALS)
        # No target_types set — pure web_app
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        tasks = [a["task"].lower() for a in recon_agents]
        assert not any("subdomain" in t for t in tasks), f"Unexpected subdomain agent in: {tasks}"

    def test_all_plan_entries_have_phase(self):
        """Every plan entry must have a 'phase' field (0 or 1)."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        for entry in plan:
            assert "phase" in entry, f"Entry missing 'phase': {entry}"
            assert entry["phase"] in (0, 1), f"Invalid phase: {entry['phase']}"

    def test_vuln_agents_have_phase_1(self):
        """Existing vulnerability agents should have phase 1."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        vuln_agents = [e for e in plan if e.get("phase") == 1]
        assert len(vuln_agents) >= 3, "Should have at least 3 phase-1 vuln agents"

    def test_recon_modules_not_filtered_by_module_rules(self):
        """Recon agent modules should survive even though they're not in MODULE_RULES."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        for agent in recon_agents:
            assert len(agent["modules"]) > 0, f"Recon agent has no modules: {agent}"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_stack_detector.py::TestReconPhase -v --tb=short -o "addopts="`
Expected: FAIL (no `phase` field, no recon agents)

- [ ] **Step 3: Add RECON_TEMPLATES and update generate_plan()**

In `strix-mcp/src/strix_mcp/stack_detector.py`, add `_RECON_TEMPLATES` after `_AGENT_TEMPLATES` (after line 202):

```python
# ---------------------------------------------------------------------------
# Recon agent templates (Phase 0 — run before vulnerability agents)
# ---------------------------------------------------------------------------
_RECON_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "recon_surface_discovery",
        "task": (
            "Map the attack surface: run directory brute-forcing with ffuf against "
            "the target using common and stack-specific wordlists. Check all discovered "
            "JS bundles for source maps using download_sourcemaps. Query Wayback Machine "
            "for historical endpoints. Write all results as structured recon notes."
        ),
        "modules": ["directory_bruteforce", "source_map_discovery"],
        "triggers": ["web_app", "domain"],
        "confidence": "high",
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
    },
]
```

Then modify `generate_plan()` (starting at line 316) to process recon templates first and add `phase` to all entries:

```python
    plan: list[dict[str, Any]] = []

    # --- Phase 0: Recon agents (bypass MODULE_RULES filtering) ---
    for template in _RECON_TEMPLATES:
        if not any(t in active_triggers for t in template["triggers"]):
            continue
        plan.append({
            "task": template["task"],
            "modules": list(template["modules"]),  # include as-is, no filtering
            "priority": "high",
            "confidence": template["confidence"],
            "phase": 0,
        })

    # --- Phase 1: Vulnerability agents (existing logic) ---
    for template in _AGENT_TEMPLATES:
        # Include template only if any of its triggers are active
        if not any(t in active_triggers for t in template["triggers"]):
            continue

        # Filter modules to only those in recommended set
        filtered_modules = [m for m in template["modules"] if m in recommended_modules]
        if not filtered_modules:
            continue

        # Determine confidence
        if template.get("signal_strength") == "specific":
            probe_dependent = any(t in _PROBE_CONFIRMED_TRIGGERS for t in template["triggers"])
            if probe_dependent and probes_were_stale:
                confidence = "low"
            else:
                confidence = "high"
        else:
            confidence = "medium"

        plan.append({
            "task": template["task"],
            "modules": filtered_modules,
            "priority": template["priority"],
            "confidence": confidence,
            "phase": 1,
        })

    return plan
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_stack_detector.py::TestReconPhase -v --tb=short -o "addopts="`
Expected: All 6 tests PASS

- [ ] **Step 5: Fix existing regression: `test_generic_triggers_are_medium_confidence`**

The existing test at `test_stack_detector.py:258` asserts ALL plan entries have `confidence == "medium"` for an empty stack. After our change, phase-0 recon agents with `confidence: "high"` will break this test. Fix it to only check phase-1 agents:

In `strix-mcp/tests/test_stack_detector.py`, change the `test_generic_triggers_are_medium_confidence` method:

```python
    def test_generic_triggers_are_medium_confidence(self):
        """Phase-1 templates triggered only by 'always' or 'web_app' (generic) should be medium confidence."""
        # Empty stack — only 'always' and 'web_app' triggers fire
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        # Only check phase-1 (vuln) agents — phase-0 recon agents have high confidence by design
        vuln_agents = [e for e in plan if e.get("phase") == 1]
        for entry in vuln_agents:
            assert entry["confidence"] == "medium", f"Expected medium for generic trigger: {entry}"
```

- [ ] **Step 6: Run full test suite to check for regressions**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add strix-mcp/src/strix_mcp/stack_detector.py strix-mcp/tests/test_stack_detector.py
git commit -m "feat(mcp): add recon templates and phase field to generate_plan"
```

---

### Task 3: Implement `nuclei_scan` tool

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py`
- Test: `strix-mcp/tests/test_tools.py`

**Testing note:** The `nuclei_scan` and `download_sourcemaps` MCP tool functions are async closures registered inside `register_tools()` that depend on a live `SandboxManager` with Docker. They cannot be unit-tested without mocking the entire sandbox proxy layer. We test the **helper functions** (`parse_nuclei_jsonl`, `build_nuclei_command`, etc.) which contain all the parsing/logic, and rely on **integration tests** (Task 7 + Docker-based tests) to validate the tool end-to-end. This matches the existing pattern — no other proxied tools in `tools.py` have unit tests for the tool function itself.

- [ ] **Step 1: Write failing tests**

In `strix-mcp/tests/test_tools.py`, add:

```python
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


class TestNucleiScan:
    """Tests for the nuclei_scan MCP tool logic."""

    def _make_jsonl(self, findings: list[dict]) -> str:
        """Build JSONL string from a list of finding dicts."""
        return "\n".join(json.dumps(f) for f in findings)

    def test_parse_nuclei_jsonl(self):
        """parse_nuclei_jsonl should extract template-id, matched-at, severity, and info."""
        from strix_mcp.tools import parse_nuclei_jsonl

        jsonl = self._make_jsonl([
            {
                "template-id": "git-config",
                "matched-at": "https://target.com/.git/config",
                "severity": "medium",
                "info": {"name": "Git Config File", "description": "Exposed git config"},
            },
            {
                "template-id": "exposed-env",
                "matched-at": "https://target.com/.env",
                "severity": "high",
                "info": {"name": "Exposed .env", "description": "Environment file exposed"},
            },
        ])
        findings = parse_nuclei_jsonl(jsonl)
        assert len(findings) == 2
        assert findings[0]["template_id"] == "git-config"
        assert findings[0]["url"] == "https://target.com/.git/config"
        assert findings[0]["severity"] == "medium"
        assert findings[0]["name"] == "Git Config File"

    def test_parse_nuclei_jsonl_skips_bad_lines(self):
        """Malformed JSONL lines should be skipped, not crash."""
        from strix_mcp.tools import parse_nuclei_jsonl

        jsonl = 'not valid json\n{"template-id": "ok", "matched-at": "https://x.com", "severity": "low", "info": {"name": "OK", "description": "ok"}}\n{broken'
        findings = parse_nuclei_jsonl(jsonl)
        assert len(findings) == 1
        assert findings[0]["template_id"] == "ok"

    def test_parse_nuclei_jsonl_empty(self):
        """Empty JSONL should return empty list."""
        from strix_mcp.tools import parse_nuclei_jsonl

        assert parse_nuclei_jsonl("") == []
        assert parse_nuclei_jsonl("   \n  ") == []

    def test_build_nuclei_command(self):
        """build_nuclei_command should produce correct CLI command."""
        from strix_mcp.tools import build_nuclei_command

        cmd = build_nuclei_command(
            target="https://example.com",
            severity="critical,high",
            rate_limit=50,
            templates=["cves", "exposures"],
            output_file="/tmp/results.jsonl",
        )
        assert "nuclei" in cmd
        assert "-u https://example.com" in cmd
        assert "-severity critical,high" in cmd
        assert "-rate-limit 50" in cmd
        assert "-t cves" in cmd
        assert "-t exposures" in cmd
        assert "-jsonl" in cmd
        assert "-o /tmp/results.jsonl" in cmd

    def test_build_nuclei_command_no_templates(self):
        """Without templates, command should not include -t flags."""
        from strix_mcp.tools import build_nuclei_command

        cmd = build_nuclei_command(
            target="https://example.com",
            severity="critical,high,medium",
            rate_limit=100,
            templates=None,
            output_file="/tmp/results.jsonl",
        )
        assert "-t " not in cmd
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestNucleiScan -v --tb=short -o "addopts="`
Expected: FAIL with `ImportError: cannot import name 'parse_nuclei_jsonl'`

- [ ] **Step 3: Implement helper functions**

In `strix-mcp/src/strix_mcp/tools.py`, add after the `_normalize_severity` function (after line 142), before `_deduplicate_reports`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestNucleiScan -v --tb=short -o "addopts="`
Expected: All 5 tests PASS

- [ ] **Step 5: Implement the `nuclei_scan` MCP tool**

In `strix-mcp/src/strix_mcp/tools.py`, inside `register_tools()`, add after the `get_finding` tool (after line ~530, before the notes section):

```python
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
```

- [ ] **Step 6: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add nuclei_scan tool with auto-report filing"
```

---

### Task 4: Implement `download_sourcemaps` tool

**Files:**
- Modify: `strix-mcp/src/strix_mcp/tools.py`
- Test: `strix-mcp/tests/test_tools.py`

**Testing note:** Same as Task 3 — helpers are unit-tested, the tool function requires Docker for integration testing.

**Implementation note:** The `download_sourcemaps` tool builds a Python script as a string and executes it via `python_action` in the sandbox. This avoids 30-60+ proxy round trips but makes the code harder to read. Regex patterns and the target URL are injected via `repr()` + `.replace()` to avoid escaping issues inside nested string literals. If debugging this at runtime, the easiest approach is to print the `script` variable before execution to inspect the generated code.

- [ ] **Step 1: Write failing tests**

In `strix-mcp/tests/test_tools.py`, add:

```python
class TestSourcemapHelpers:
    def test_extract_script_urls(self):
        """extract_script_urls should find all script src attributes."""
        from strix_mcp.tools import extract_script_urls

        html = '''<html>
        <script src="/assets/main.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
        <script>inline code</script>
        <script src='/assets/vendor.js'></script>
        </html>'''
        urls = extract_script_urls(html, "https://example.com")
        assert "https://example.com/assets/main.js" in urls
        assert "https://cdn.example.com/lib.js" in urls
        assert "https://example.com/assets/vendor.js" in urls
        assert len(urls) == 3

    def test_extract_script_urls_empty(self):
        """No script tags should return empty list."""
        from strix_mcp.tools import extract_script_urls

        assert extract_script_urls("<html><body>hi</body></html>", "https://x.com") == []

    def test_extract_sourcemap_url(self):
        """extract_sourcemap_url should find sourceMappingURL comment."""
        from strix_mcp.tools import extract_sourcemap_url

        js = "var x=1;\n//# sourceMappingURL=main.js.map"
        assert extract_sourcemap_url(js) == "main.js.map"

    def test_extract_sourcemap_url_at_syntax(self):
        """Should also find //@ sourceMappingURL syntax."""
        from strix_mcp.tools import extract_sourcemap_url

        js = "var x=1;\n//@ sourceMappingURL=old.js.map"
        assert extract_sourcemap_url(js) == "old.js.map"

    def test_extract_sourcemap_url_not_found(self):
        """No sourceMappingURL should return None."""
        from strix_mcp.tools import extract_sourcemap_url

        assert extract_sourcemap_url("var x=1;") is None

    def test_scan_for_notable_patterns(self):
        """scan_for_notable should find API_KEY and SECRET patterns."""
        from strix_mcp.tools import scan_for_notable

        sources = {
            "src/config.ts": "const API_KEY = 'abc123';\nconst name = 'test';",
            "src/auth.ts": "const SECRET = 'mysecret';",
            "src/utils.ts": "function add(a, b) { return a + b; }",
        }
        notable = scan_for_notable(sources)
        assert any("config.ts" in n and "API_KEY" in n for n in notable)
        assert any("auth.ts" in n and "SECRET" in n for n in notable)
        assert not any("utils.ts" in n for n in notable)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestSourcemapHelpers -v --tb=short -o "addopts="`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement helper functions**

In `strix-mcp/src/strix_mcp/tools.py`, add after `build_nuclei_command` (before `_deduplicate_reports`):

```python
# --- Source map discovery helpers ---

import re as _re
from urllib.parse import urljoin as _urljoin


def extract_script_urls(html: str, base_url: str) -> list[str]:
    """Extract absolute URLs of <script src="..."> tags from HTML."""
    pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    matches = _re.findall(pattern, html, _re.IGNORECASE)
    return [_urljoin(base_url, m) for m in matches]


def extract_sourcemap_url(js_content: str) -> str | None:
    """Extract sourceMappingURL from the end of a JS file."""
    # Check last 500 chars to avoid scanning huge files
    tail = js_content[-500:] if len(js_content) > 500 else js_content
    match = _re.search(r'//[#@]\s*sourceMappingURL=(\S+)', tail)
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestSourcemapHelpers -v --tb=short -o "addopts="`
Expected: All 6 tests PASS

- [ ] **Step 5: Implement the `download_sourcemaps` MCP tool**

In `strix-mcp/src/strix_mcp/tools.py`, inside `register_tools()`, add after the `nuclei_scan` tool:

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

        target_url: base URL to scan for JS bundles
        agent_id: subagent identifier from dispatch_agent (omit for coordinator)"""
        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"error": "No active scan. Call start_scan first."})

        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc

        # Build Python script that runs inside sandbox.
        # Note: The script is a triple-quoted string embedded in Python. To avoid
        # regex escaping issues, we inject the regex patterns as variables via .replace().
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
```

- [ ] **Step 6: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add download_sourcemaps tool with auto-extraction"
```

---

### Task 5: Create recon modules

**Files:**
- Create: `strix/skills/reconnaissance/directory_bruteforce.md`
- Create: `strix/skills/reconnaissance/subdomain_enumeration.md`
- Create: `strix/skills/reconnaissance/source_map_discovery.md`
- Create: `strix/skills/reconnaissance/port_scanning.md`
- Create: `strix/skills/reconnaissance/nuclei_scanning.md`
- Create: `strix/skills/reconnaissance/mobile_apk_analysis.md`

These are upstream-compatible knowledge modules. Each follows the YAML frontmatter + markdown format used by existing modules (see `strix/skills/vulnerabilities/idor.md` for reference — read it first for the expected depth and style). Write each module with the content described in the spec sections under Component 2.

**Note for implementers:** This task is the most creative — the spec describes *what* each module covers but not the full markdown content. Use the spec's bullet points as an outline, read `idor.md` for the tone/depth, and write actionable content with real commands. Each module should be self-contained enough that Claude can follow it without other context.

Modules should:
- Have YAML frontmatter with `name` and `description` fields
- Start with a `# Title` heading
- Include concrete command examples (not pseudocode)
- Include "Output" section describing the structured note format
- Reference Strix tools by name (`terminal_execute`, `send_request`, `nuclei_scan`, etc.)
- Be 80-150 lines each — enough detail to guide Claude, not a textbook

- [ ] **Step 1: Create `directory_bruteforce.md`**

Write the module content based on spec section "Module 1: directory_bruteforce.md". Key content: ffuf command patterns, wordlist selection by stack, filtering noise, interpreting results, structured note output.

- [ ] **Step 2: Create `subdomain_enumeration.md`**

Write the module based on spec section "Module 2". Key content: subfinder, crt.sh, httpx validation, scope filtering, cloud patterns.

- [ ] **Step 3: Create `source_map_discovery.md`**

Write the module based on spec section "Module 3". Key content: finding bundles, checking for .map files, what to look for in source, framework-specific locations.

- [ ] **Step 4: Create `port_scanning.md`**

Write the module based on spec section "Module 4". Key content: nmap flags, common ports, service fingerprinting, what to do with results.

- [ ] **Step 5: Create `nuclei_scanning.md`**

Write the module based on spec section "Module 5". Key content: template categories, command patterns, interpreting results, validation.

- [ ] **Step 6: Create `mobile_apk_analysis.md`**

Write the module based on spec section "Module 6". Key content: obtaining APK, decompiling, what to extract, deep links. Include the note that this is manual/on-demand only.

- [ ] **Step 7: Verify modules are discoverable**

Run: `cd strix-mcp && python -c "from strix.skills import get_available_skills; skills = get_available_skills(); recon = skills.get('reconnaissance', []); print(f'Found {len(recon)} recon modules:', sorted(recon))"`
Expected: `Found 6 recon modules: ['directory_bruteforce', 'mobile_apk_analysis', 'nuclei_scanning', 'port_scanning', 'source_map_discovery', 'subdomain_enumeration']`

- [ ] **Step 8: Commit**

```bash
git add strix/skills/reconnaissance/
git commit -m "feat: add 6 recon knowledge modules"
```

---

### Task 6: Update methodology.md with Phase 0

**Files:**
- Modify: `strix-mcp/src/strix_mcp/methodology.md`

- [ ] **Step 1: Add Phase 0 section**

In `strix-mcp/src/strix_mcp/methodology.md`, insert a new section between "Step 1: Start the Scan" (ends at line ~72) and "Step 2: Dispatch Subagents" (starts at line 74). The current "Step 2" becomes "Step 3", etc.

New content to insert after the web-only template block (after line 72 "---"):

```markdown
### Step 2: Reconnaissance (Phase 0)

Before vulnerability testing, run reconnaissance to map the full attack surface.

**Coordinator actions:**
1. Review the scan plan for `phase: 0` agents — these are recon agents
2. Dispatch ALL recon agents in parallel using `dispatch_agent`
3. Wait for all recon agents to complete
4. Read recon results: `list_notes(category="recon")`
5. Adjust the Phase 1 plan based on discoveries:
   - New endpoints found → include in Phase 1 agent task descriptions
   - GraphQL discovered → dispatch GraphQL agent even if not in original plan
   - Source maps recovered → dispatch code review agent for recovered source at /workspace/sourcemaps/
   - Open non-standard ports → dispatch agents to probe those services
6. Proceed to Phase 1 (Step 3)

**Recon agents should:**
- Use `nuclei_scan` for automated vulnerability scanning (auto-files reports)
- Use `download_sourcemaps` for JS source map recovery
- Use `terminal_execute` for ffuf, nmap, subfinder, httpx
- Write ALL results as structured notes: `create_note(category="recon", title="...")`
- Stay within scope: check `scope_rules` before scanning new targets

**Passing recon context to Phase 1 agents:**
When dispatching Phase 1 agents, append recon results to the `task` string so agents know what was discovered:

```
dispatch_agent(
    task="Test IDOR on user endpoints.\n\nRECON CONTEXT (from Phase 0):\nDiscovered endpoints:\n- GET /api/v1/users/{id}\n- POST /api/v1/files\n\nUse these to focus your testing.",
    modules=["idor"],
    is_web_only=True,
)
```
```

- [ ] **Step 2: Renumber existing steps**

Change "Step 2: Dispatch Subagents" → "Step 3: Dispatch Subagents (Phase 1)"
Change "Step 3: Process Results" → "Step 4: Process Results (Phase 2)"
Change "Step 4: End the Scan" → "Step 5: End the Scan"

- [ ] **Step 3: Verify methodology loads correctly**

Run: `cd strix-mcp && python -c "from strix_mcp.resources import get_methodology; m = get_methodology(); print('Phase 0' in m, 'nuclei_scan' in m, 'download_sourcemaps' in m, len(m))"`
Expected: `True True True <length>`

- [ ] **Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/methodology.md
git commit -m "feat(mcp): add Phase 0 reconnaissance to methodology"
```

---

### Task 7: Final integration test and cleanup

**Files:**
- Test: `strix-mcp/tests/test_tools.py`
- Test: `strix-mcp/tests/test_stack_detector.py`

- [ ] **Step 1: Run full test suite**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts=" --ignore=tests/test_integration.py`
Expected: All tests pass

- [ ] **Step 2: Verify tools register without errors**

Run: `cd strix-mcp && python -c "from strix_mcp.tools import register_tools, parse_nuclei_jsonl, build_nuclei_command, extract_script_urls, extract_sourcemap_url, scan_for_notable; print('All exports OK')"`
Expected: `All exports OK`

- [ ] **Step 3: Verify generate_plan produces both phases**

Run: `cd strix-mcp && python -c "
from strix_mcp.stack_detector import detect_stack, generate_plan
stack = detect_stack({'package_json': '', 'requirements': '', 'pyproject': '', 'go_mod': '', 'env_files': '', 'structure': ''})
plan = generate_plan(stack)
p0 = [a for a in plan if a['phase'] == 0]
p1 = [a for a in plan if a['phase'] == 1]
print(f'Phase 0: {len(p0)} agents, Phase 1: {len(p1)} agents')
for a in p0:
    print(f'  [P0] {a[\"task\"][:60]}... modules={a[\"modules\"]}')
"`
Expected: 2 Phase 0 agents (surface discovery + infrastructure), 3+ Phase 1 agents

- [ ] **Step 4: Commit if any fixes were needed**

If any issues were found and fixed in steps 1-3:
```bash
git add -A
git commit -m "fix(mcp): address integration issues in recon phase"
```
