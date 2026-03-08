# Strix MCP Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enhance the Strix MCP tool to match the power of the actual Strix tool — dedup findings, add web target fingerprinting, expose module catalog, add scan status, richer summaries, and web-only methodology.

**Architecture:** All changes in `strix-mcp/src/strix_mcp/` only. The core `strix/` package is read-only. We extend the MCP layer's tools, stack detector, and methodology to handle web-only targets and improve inter-agent coordination.

**Tech Stack:** Python 3.12, FastMCP, httpx, pytest, pytest-asyncio

**Rule:** All work on `main` branch only.

**Run tests:** `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts="`

---

### Task 1: Add `started_at` to ScanState and `list_modules` tool

**Files:**
- Modify: `src/strix_mcp/sandbox.py` (ScanState dataclass)
- Modify: `src/strix_mcp/tools.py` (add list_modules tool, set started_at)
- Create: `tests/test_tools.py`

**Step 1: Write failing tests for list_modules tool and started_at**

In `tests/test_tools.py`:

```python
"""Unit tests for MCP tools (no Docker required)."""
import json
from datetime import UTC, datetime

import pytest

from strix_mcp.sandbox import ScanState


class TestScanState:
    def test_started_at_field_exists(self):
        """ScanState should have a started_at datetime field."""
        state = ScanState(
            scan_id="test",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        assert state.started_at is not None
        assert isinstance(state.started_at, datetime)


class TestListModulesTool:
    def test_list_modules_returns_valid_json(self):
        """list_modules should return JSON with module names, categories, descriptions."""
        from strix_mcp.resources import list_modules

        result = json.loads(list_modules())
        assert isinstance(result, dict)
        assert len(result) > 10  # We have 18+ modules
        for name, info in result.items():
            assert "category" in info
            assert "description" in info
```

**Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py -v --tb=short -o "addopts="`
Expected: `TestScanState::test_started_at_field_exists` FAILS (no started_at field)

**Step 3: Add `started_at` to ScanState**

In `sandbox.py`, add to `ScanState` dataclass after `registered_agents`:

```python
started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
```

Add import at top: `from datetime import UTC, datetime`

**Step 4: Add `list_modules` tool to tools.py**

In `tools.py`, inside `register_tools()`, after `get_module` tool:

```python
@mcp.tool()
async def list_modules() -> str:
    """List all available security knowledge modules with their categories
    and descriptions. Call this to see what modules you can load with
    get_module().

    Returns JSON mapping module names to {category, description}."""
    from . import resources
    return resources.list_modules()
```

**Step 5: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py tests/test_stack_detector.py tests/test_resources.py -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/sandbox.py strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add started_at to ScanState and list_modules tool"
```

---

### Task 2: Title normalization and finding deduplication

**Files:**
- Modify: `src/strix_mcp/tools.py` (add normalization helper, dedup on insert)
- Modify: `tests/test_tools.py` (add dedup tests)

**Step 1: Write failing tests for title normalization and dedup**

Add to `tests/test_tools.py`:

```python
from strix_mcp.tools import _normalize_title, _find_duplicate


class TestTitleNormalization:
    def test_basic_normalization(self):
        """Titles should be lowercased and whitespace-collapsed."""
        assert _normalize_title("Missing CSP Header") == "missing csp header"

    def test_strips_special_chars(self):
        """Punctuation variations should normalize the same."""
        assert _normalize_title("Missing CSP") == _normalize_title("missing  csp")
        assert _normalize_title("X-Frame-Options Missing") == _normalize_title("x-frame-options missing")

    def test_synonym_normalization(self):
        """Common synonyms should normalize to the same key."""
        assert _normalize_title("Content-Security-Policy Missing") == _normalize_title("Missing CSP Header")
        assert _normalize_title("Cross-Site Request Forgery") == _normalize_title("CSRF Vulnerability")


class TestFindDuplicate:
    def test_finds_exact_duplicate(self):
        """Should find duplicate when normalized titles match."""
        reports = [
            {"id": "v1", "title": "Missing CSP Header", "severity": "medium", "content": "old"},
        ]
        idx = _find_duplicate("missing csp header", reports)
        assert idx == 0

    def test_returns_none_when_no_duplicate(self):
        """Should return None when no duplicate exists."""
        reports = [
            {"id": "v1", "title": "SQL Injection", "severity": "high", "content": "sqli"},
        ]
        idx = _find_duplicate("missing csp header", reports)
        assert idx is None

    def test_finds_synonym_duplicate(self):
        """Should find duplicate via synonym normalization."""
        reports = [
            {"id": "v1", "title": "CSRF Vulnerability", "severity": "medium", "content": "csrf"},
        ]
        idx = _find_duplicate(_normalize_title("Cross-Site Request Forgery"), reports)
        assert idx == 0
```

**Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestTitleNormalization -v --tb=short -o "addopts="`
Expected: FAIL (ImportError — _normalize_title not found)

**Step 3: Implement normalization and dedup helpers**

At the top of `tools.py` (after imports, before `register_tools`), add:

```python
# --- Title normalization for deduplication ---

# Synonyms: map common variant phrases to a canonical form
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
    """Normalize a vulnerability title for deduplication.

    Lowercases, collapses whitespace, and replaces known synonyms
    with canonical forms.
    """
    t = title.lower().strip()
    # Collapse whitespace
    t = " ".join(t.split())
    # Apply synonym replacements (longest match first)
    for synonym, canonical in sorted(
        _TITLE_SYNONYMS.items(), key=lambda x: -len(x[0])
    ):
        t = t.replace(synonym, canonical)
    return t


def _find_duplicate(
    normalized_title: str, reports: list[dict[str, Any]]
) -> int | None:
    """Find index of an existing report with the same normalized title.

    Returns the index or None.
    """
    for i, report in enumerate(reports):
        if _normalize_title(report["title"]) == normalized_title:
            return i
    return None
```

**Step 4: Update `create_vulnerability_report` to merge duplicates**

Replace the existing `create_vulnerability_report` in `tools.py`:

```python
@mcp.tool()
async def create_vulnerability_report(
    title: str,
    content: str,
    severity: str,
) -> str:
    """Report a confirmed vulnerability finding.
    severity: critical, high, medium, low, or info.
    content: full details including PoC, impact, and remediation.
    Only report validated vulnerabilities with proof of exploitation.

    If a similar finding was already reported, the evidence is merged
    into the existing report and the higher severity is kept."""
    normalized = _normalize_title(title)
    dup_idx = _find_duplicate(normalized, vulnerability_reports)

    if dup_idx is not None:
        existing = vulnerability_reports[dup_idx]
        # Merge: append new evidence, keep higher severity
        severity_order = ["info", "low", "medium", "high", "critical"]
        if severity_order.index(severity) > severity_order.index(existing["severity"]):
            existing["severity"] = severity
        existing["content"] += f"\n\n---\n\n**Additional evidence:**\n{content}"
        return json.dumps({
            "report_id": existing["id"],
            "title": existing["title"],
            "severity": existing["severity"],
            "message": f"Merged with existing report '{existing['title']}'. Evidence appended.",
            "merged": True,
        })

    report = {
        "id": f"vuln-{uuid.uuid4().hex[:8]}",
        "title": title,
        "content": content,
        "severity": severity,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    vulnerability_reports.append(report)
    return json.dumps({
        "report_id": report["id"],
        "title": title,
        "severity": severity,
        "message": "Vulnerability report saved.",
        "merged": False,
    })
```

**Step 5: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add title normalization and finding deduplication on insert"
```

---

### Task 3: `list_vulnerability_reports` and `get_scan_status` tools

**Files:**
- Modify: `src/strix_mcp/tools.py` (add two new tools)
- Modify: `tests/test_tools.py` (add tests)

**Step 1: Write failing tests**

Add to `tests/test_tools.py`:

```python
class TestVulnerabilityReportHelpers:
    """Test the report list and dedup behavior with real tool functions."""

    def test_vulnerability_reports_list_starts_empty(self):
        """Fresh vulnerability_reports list should be empty."""
        # We test the data structure directly since the tools need MCP context
        reports: list[dict] = []
        assert len(reports) == 0

    def test_dedup_merges_same_title(self):
        """Filing the same title twice should merge, not duplicate."""
        reports: list[dict] = []
        # Simulate first report
        reports.append({"id": "v1", "title": "Missing CSP", "severity": "medium", "content": "first"})
        # Simulate second report with same normalized title
        normalized = _normalize_title("Missing CSP Header")
        dup_idx = _find_duplicate(normalized, reports)
        assert dup_idx == 0  # Found duplicate

    def test_dedup_keeps_higher_severity(self):
        """When merging, the higher severity should be kept."""
        reports = [{"id": "v1", "title": "Missing CSP", "severity": "low", "content": "first"}]
        # Simulate merge with higher severity
        severity_order = ["info", "low", "medium", "high", "critical"]
        new_severity = "high"
        existing = reports[0]
        if severity_order.index(new_severity) > severity_order.index(existing["severity"]):
            existing["severity"] = new_severity
        assert existing["severity"] == "high"
```

**Step 2: Run tests to verify they pass (these test helpers, not tools)**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py -v --tb=short -o "addopts="`
Expected: PASS (these test the helper functions from Task 2)

**Step 3: Add `list_vulnerability_reports` tool**

In `tools.py`, inside `register_tools()`, after `create_vulnerability_report`:

```python
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
            {"id": r["id"], "title": r["title"], "severity": r["severity"]}
            for r in filtered
        ],
        "total": len(filtered),
    })
```

**Step 4: Add `get_scan_status` tool**

In `tools.py`, inside `register_tools()`, after `register_agent`:

```python
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

    return json.dumps({
        "scan_id": scan.scan_id,
        "status": "running",
        "elapsed_seconds": round(elapsed),
        "agents_registered": len(scan.registered_agents),
        "agent_ids": scan.registered_agents,
        "total_reports": len(vulnerability_reports),
        "severity_counts": severity_counts,
    })
```

**Step 5: Run all tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add list_vulnerability_reports and get_scan_status tools"
```

---

### Task 4: HTTP-based web target fingerprinting

**Files:**
- Modify: `src/strix_mcp/stack_detector.py` (add `detect_stack_from_http`)
- Modify: `src/strix_mcp/sandbox.py` (add HTTP detection commands, extend `detect_target_stack`)
- Modify: `src/strix_mcp/tools.py` (remove `has_code_targets` guard)
- Modify: `tests/test_stack_detector.py` (add HTTP detection tests)

**Step 1: Write failing tests for HTTP-based detection**

Add to `tests/test_stack_detector.py`:

```python
from strix_mcp.stack_detector import detect_stack_from_http


class TestDetectStackFromHttp:
    def test_detects_php_from_server_header(self):
        """X-Powered-By: PHP should detect php runtime."""
        signals = {"headers": "Server: Apache\nX-Powered-By: PHP/8.2.0"}
        stack = detect_stack_from_http(signals)
        assert "php" in stack["runtime"]

    def test_detects_aspnet_from_header(self):
        """X-AspNet-Version header should detect dotnet runtime."""
        signals = {"headers": "X-AspNet-Version: 4.0.30319\nServer: Microsoft-IIS/10.0"}
        stack = detect_stack_from_http(signals)
        assert "dotnet" in stack["runtime"]

    def test_detects_nextjs_from_headers(self):
        """x-nextjs-cache or x-powered-by: Next.js should detect nextjs."""
        signals = {"headers": "x-powered-by: Next.js"}
        stack = detect_stack_from_http(signals)
        assert "nextjs" in stack["framework"]

    def test_detects_django_from_cookie(self):
        """csrftoken cookie should suggest Django."""
        signals = {"cookies": "csrftoken=abc123; sessionid=xyz789"}
        stack = detect_stack_from_http(signals)
        assert "django" in stack["framework"]

    def test_detects_java_from_jsessionid(self):
        """JSESSIONID cookie should detect java runtime."""
        signals = {"cookies": "JSESSIONID=ABC123DEF456"}
        stack = detect_stack_from_http(signals)
        assert "java" in stack["runtime"]

    def test_detects_laravel_from_cookie(self):
        """laravel_session cookie should detect laravel framework."""
        signals = {"cookies": "laravel_session=abc; XSRF-TOKEN=xyz"}
        stack = detect_stack_from_http(signals)
        assert "laravel" in stack["framework"]

    def test_detects_graphql_from_probe(self):
        """GraphQL endpoint response should detect graphql feature."""
        signals = {"probe_results": "/graphql: 200"}
        stack = detect_stack_from_http(signals)
        assert "graphql" in stack["features"]

    def test_detects_wordpress_from_meta(self):
        """WordPress meta generator tag should detect wordpress."""
        signals = {"body_signals": '<meta name="generator" content="WordPress 6.4">'}
        stack = detect_stack_from_http(signals)
        assert "wordpress" in stack["framework"]

    def test_empty_http_signals(self):
        """Empty HTTP signals should return empty stack with rest api_style."""
        stack = detect_stack_from_http({})
        assert stack["runtime"] == []
        assert stack["framework"] == []
        assert "rest" in stack["api_style"]

    def test_detects_express_from_header(self):
        """X-Powered-By: Express should detect express framework."""
        signals = {"headers": "X-Powered-By: Express"}
        stack = detect_stack_from_http(signals)
        assert "express" in stack["framework"]
        assert "node" in stack["runtime"]

    def test_detects_react_from_body(self):
        """__NEXT_DATA__ in body signals should detect nextjs."""
        signals = {"body_signals": '<script id="__NEXT_DATA__" type="application/json">'}
        stack = detect_stack_from_http(signals)
        assert "nextjs" in stack["framework"]
```

**Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_stack_detector.py::TestDetectStackFromHttp -v --tb=short -o "addopts="`
Expected: FAIL (ImportError — detect_stack_from_http not found)

**Step 3: Implement `detect_stack_from_http` in stack_detector.py**

Add at the bottom of `stack_detector.py`, before the internal helpers section or at the very end:

```python
# ---------------------------------------------------------------------------
# HTTP-based stack detection (for web-only targets)
# ---------------------------------------------------------------------------
def detect_stack_from_http(signals: dict[str, str]) -> dict[str, Any]:
    """Parse HTTP response signals and return structured stack information.

    Parameters
    ----------
    signals:
        Dict with optional keys: ``headers`` (raw response headers),
        ``cookies`` (raw Set-Cookie values), ``body_signals`` (HTML snippets),
        ``probe_results`` (results of probing common paths like /graphql).

    Returns
    -------
    Same structure as :func:`detect_stack`.
    """
    runtime: list[str] = []
    framework: list[str] = []
    database: list[str] = []
    auth: list[str] = []
    features: list[str] = []
    infrastructure: list[str] = []

    headers = signals.get("headers", "").lower()
    cookies = signals.get("cookies", "").lower()
    body = signals.get("body_signals", "").lower()
    probes = signals.get("probe_results", "").lower()

    # --- Headers ---
    _detect_http_headers(headers, runtime, framework, infrastructure)

    # --- Cookies ---
    _detect_http_cookies(cookies, runtime, framework, auth)

    # --- Body signals ---
    _detect_http_body(body, framework, features)

    # --- Probe results ---
    _detect_http_probes(probes, features)

    # --- api_style inference ---
    api_style: list[str] = []
    if "graphql" in features:
        api_style.append("graphql")
    if "grpc" in features:
        api_style.append("grpc")
    if not api_style:
        api_style.append("rest")

    return {
        "runtime": _dedup(runtime),
        "framework": _dedup(framework),
        "database": _dedup(database),
        "auth": _dedup(auth),
        "features": _dedup(features),
        "api_style": _dedup(api_style),
        "infrastructure": _dedup(infrastructure),
    }


def _detect_http_headers(
    headers: str,
    runtime: list[str],
    framework: list[str],
    infrastructure: list[str],
) -> None:
    """Detect stack from HTTP response headers."""
    # Runtime detection
    if "x-powered-by: php" in headers or "php/" in headers:
        runtime.append("php")
    if "x-aspnet-version" in headers or "asp.net" in headers:
        runtime.append("dotnet")
    if "x-powered-by: express" in headers:
        runtime.append("node")
        framework.append("express")
    if "x-powered-by: next.js" in headers or "x-nextjs" in headers:
        runtime.append("node")
        framework.append("nextjs")

    # Server detection
    if "server: nginx" in headers:
        infrastructure.append("nginx")
    if "server: apache" in headers:
        infrastructure.append("apache")
    if "server: microsoft-iis" in headers:
        infrastructure.append("iis")
    if "server: cloudflare" in headers or "cf-ray" in headers:
        infrastructure.append("cloudflare")

    # Cloud detection
    if "x-amz-" in headers or "x-amzn-" in headers:
        infrastructure.append("aws")
    if "x-goog-" in headers or "x-cloud-trace" in headers:
        infrastructure.append("gcp")
    if "x-azure-" in headers or "x-ms-" in headers:
        infrastructure.append("azure")


def _detect_http_cookies(
    cookies: str,
    runtime: list[str],
    framework: list[str],
    auth: list[str],
) -> None:
    """Detect stack from Set-Cookie values."""
    if "jsessionid" in cookies:
        runtime.append("java")
    if "phpsessid" in cookies:
        runtime.append("php")
    if "asp.net_sessionid" in cookies or "aspxauth" in cookies:
        runtime.append("dotnet")
    if "csrftoken" in cookies and "sessionid" in cookies:
        framework.append("django")
        runtime.append("python")
    if "laravel_session" in cookies or "xsrf-token" in cookies and "laravel" in cookies:
        framework.append("laravel")
        runtime.append("php")
    if "_rails_session" in cookies or "_session_id" in cookies:
        framework.append("rails")
        runtime.append("ruby")
    if re.search(r"connect\.sid", cookies):
        runtime.append("node")

    # Auth hints
    if "jwt" in cookies or "access_token" in cookies:
        auth.append("jwt")


def _detect_http_body(
    body: str,
    framework: list[str],
    features: list[str],
) -> None:
    """Detect stack from HTML body content."""
    if "__next_data__" in body or "_next/static" in body:
        framework.append("nextjs")
    if "wp-content" in body or "wp-includes" in body or 'generator" content="wordpress' in body:
        framework.append("wordpress")
    if "drupal" in body and "sites/default" in body:
        framework.append("drupal")
    if "__nuxt" in body or "_nuxt/" in body:
        framework.append("nuxtjs")
    if "react" in body and ("_app" in body or "react-root" in body):
        features.append("spa")

    # Feature detection from body
    if "type=\"file\"" in body or "multipart/form-data" in body:
        features.append("file_upload")
    if "websocket" in body or "socket.io" in body:
        features.append("websocket")


def _detect_http_probes(
    probes: str,
    features: list[str],
) -> None:
    """Detect features from probing common paths."""
    if "/graphql" in probes and "200" in probes:
        features.append("graphql")
    if "/api/swagger" in probes and "200" in probes:
        features.append("swagger")
    if "/wp-admin" in probes and "200" in probes:
        features.append("wordpress_admin")
```

**Step 4: Run tests to verify they pass**

Run: `cd strix-mcp && python -m pytest tests/test_stack_detector.py -v --tb=short -o "addopts="`
Expected: ALL PASS (existing + new HTTP tests)

**Step 5: Commit**

```bash
git add strix-mcp/src/strix_mcp/stack_detector.py strix-mcp/tests/test_stack_detector.py
git commit -m "feat(mcp): add HTTP-based stack detection for web targets"
```

---

### Task 5: Wire HTTP fingerprinting into sandbox and start_scan

**Files:**
- Modify: `src/strix_mcp/sandbox.py` (add HTTP detection method)
- Modify: `src/strix_mcp/tools.py` (remove has_code_targets guard)

**Step 1: Add HTTP fingerprinting method to sandbox.py**

Add to `SandboxManager` class, after `detect_target_stack`:

```python
async def fingerprint_web_target(self, url: str) -> dict[str, Any]:
    """Fingerprint a web target via HTTP requests through the sandbox proxy.

    Sends requests to the target URL and common paths, collects headers,
    cookies, and body signals for stack detection.
    """
    from .stack_detector import detect_stack_from_http, generate_plan

    signals: dict[str, str] = {}

    # 1. GET the main URL — collect headers, cookies, body
    result = await self.proxy_tool("send_request", {
        "method": "GET",
        "url": url,
        "timeout": 15,
    })
    if isinstance(result, dict) and not result.get("error"):
        # Extract headers
        resp_headers = result.get("response", {}).get("headers", {})
        if isinstance(resp_headers, dict):
            signals["headers"] = "\n".join(
                f"{k}: {v}" for k, v in resp_headers.items()
            )
        elif isinstance(resp_headers, str):
            signals["headers"] = resp_headers

        # Extract cookies
        cookies = resp_headers.get("set-cookie", "") if isinstance(resp_headers, dict) else ""
        signals["cookies"] = cookies if isinstance(cookies, str) else str(cookies)

        # Extract body signals (first 5000 chars of body)
        body = result.get("response", {}).get("body", "")
        if isinstance(body, str):
            signals["body_signals"] = body[:5000]

    # 2. Probe common paths
    probe_paths = ["/graphql", "/api", "/api/swagger", "/wp-admin", "/robots.txt"]
    probe_results: list[str] = []
    for path in probe_paths:
        probe_url = url.rstrip("/") + path
        probe = await self.proxy_tool("send_request", {
            "method": "GET",
            "url": probe_url,
            "timeout": 10,
        })
        if isinstance(probe, dict) and not probe.get("error"):
            status = probe.get("response", {}).get("status_code", 0)
            probe_results.append(f"{path}: {status}")
    signals["probe_results"] = "\n".join(probe_results)

    stack = detect_stack_from_http(signals)
    plan = generate_plan(stack)
    return {"detected_stack": stack, "recommended_plan": plan}
```

**Step 2: Update `start_scan` in tools.py to run detection for ALL targets**

Replace the detection block in `start_scan` (the `has_code_targets` section):

```python
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
    # Fall back to HTTP fingerprinting for web targets
    url = web_targets[0]["value"]
    # Ensure URL has scheme
    if not url.startswith("http"):
        url = f"https://{url}"
    try:
        analysis = await sandbox.fingerprint_web_target(url)
    except Exception:
        analysis = {"detected_stack": None, "recommended_plan": []}

# If still no plan, generate a default web plan
if not analysis.get("recommended_plan"):
    from .stack_detector import generate_plan
    default_stack = {
        "runtime": [], "framework": [], "database": [],
        "auth": [], "features": [], "api_style": ["rest"],
        "infrastructure": [],
    }
    analysis = {
        "detected_stack": analysis.get("detected_stack") or default_stack,
        "recommended_plan": generate_plan(default_stack),
    }
```

**Step 3: Run all tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add strix-mcp/src/strix_mcp/sandbox.py strix-mcp/src/strix_mcp/tools.py
git commit -m "feat(mcp): wire HTTP fingerprinting into start_scan for web targets"
```

---

### Task 6: Richer `end_scan` summary with OWASP grouping

**Files:**
- Modify: `src/strix_mcp/tools.py` (OWASP mapping, richer end_scan)
- Modify: `tests/test_tools.py` (add OWASP categorization tests)

**Step 1: Write failing tests for OWASP categorization**

Add to `tests/test_tools.py`:

```python
from strix_mcp.tools import _categorize_owasp, _deduplicate_reports


class TestOwaspCategorization:
    def test_sqli_maps_to_injection(self):
        assert _categorize_owasp("SQL Injection in search") == "A03 Injection"

    def test_xss_maps_to_injection(self):
        assert _categorize_owasp("Reflected XSS in search") == "A03 Injection"

    def test_idor_maps_to_bac(self):
        assert _categorize_owasp("IDOR in user profile") == "A01 Broken Access Control"

    def test_missing_csp_maps_to_misconfig(self):
        assert _categorize_owasp("Missing CSP Header") == "A05 Security Misconfiguration"

    def test_unknown_maps_to_other(self):
        assert _categorize_owasp("Something unusual") == "Other"

    def test_jwt_maps_to_auth(self):
        assert _categorize_owasp("JWT token not validated") == "A07 Identification and Authentication Failures"

    def test_ssrf_maps_to_ssrf(self):
        assert _categorize_owasp("SSRF via image URL") == "A10 Server-Side Request Forgery"


class TestDeduplicateReports:
    def test_dedup_removes_exact_duplicates(self):
        reports = [
            {"id": "v1", "title": "Missing CSP", "severity": "medium", "content": "first evidence"},
            {"id": "v2", "title": "missing csp", "severity": "low", "content": "second evidence"},
            {"id": "v3", "title": "SQL Injection", "severity": "high", "content": "sqli proof"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2
        # Should keep higher severity
        csp = [r for r in unique if "csp" in r["title"].lower()][0]
        assert csp["severity"] == "medium"

    def test_dedup_preserves_unique_reports(self):
        reports = [
            {"id": "v1", "title": "XSS in search", "severity": "high", "content": "xss"},
            {"id": "v2", "title": "IDOR in profile", "severity": "critical", "content": "idor"},
        ]
        unique = _deduplicate_reports(reports)
        assert len(unique) == 2
```

**Step 2: Run tests to verify they fail**

Run: `cd strix-mcp && python -m pytest tests/test_tools.py::TestOwaspCategorization -v --tb=short -o "addopts="`
Expected: FAIL (ImportError)

**Step 3: Implement OWASP categorization and dedup helpers**

Add to `tools.py` (after the normalization helpers, before `register_tools`):

```python
# --- OWASP Top 10 (2021) categorization ---

_OWASP_KEYWORDS: list[tuple[str, list[str]]] = [
    ("A01 Broken Access Control", [
        "idor", "bac", "broken access", "insecure direct object",
        "privilege escalation", "path traversal", "directory traversal",
        "forced browsing", "cors", "missing access control",
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
    """Deduplicate reports by normalized title, keeping the richest entry.

    When duplicates are found, keeps the one with higher severity and
    longer content.
    """
    severity_order = ["info", "low", "medium", "high", "critical"]
    seen: dict[str, dict[str, Any]] = {}

    for report in reports:
        key = _normalize_title(report["title"])
        if key in seen:
            existing = seen[key]
            # Keep higher severity
            if severity_order.index(report.get("severity", "info")) > severity_order.index(existing.get("severity", "info")):
                existing["severity"] = report["severity"]
            # Append content if different
            if report.get("content", "") not in existing.get("content", ""):
                existing["content"] = existing.get("content", "") + f"\n\n---\n\n{report.get('content', '')}"
        else:
            seen[key] = dict(report)

    return list(seen.values())
```

**Step 4: Replace `end_scan` with richer summary**

```python
@mcp.tool()
async def end_scan() -> str:
    """End the active scan and tear down the Docker sandbox.
    Returns a comprehensive summary: unique findings deduplicated,
    grouped by OWASP Top 10 category, with severity breakdown."""
    unique = _deduplicate_reports(vulnerability_reports)
    total_filed = len(vulnerability_reports)
    duplicates_merged = total_filed - len(unique)

    # Severity counts
    severity_counts: dict[str, int] = {}
    for r in unique:
        sev = r.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Group by OWASP category
    findings_by_category: dict[str, list[dict[str, str]]] = {}
    for r in unique:
        category = _categorize_owasp(r["title"])
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append({
            "id": r["id"],
            "title": r["title"],
            "severity": r.get("severity", "info"),
        })

    await sandbox.end_scan()

    return json.dumps({
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
    })
```

**Step 5: Run all tests**

Run: `cd strix-mcp && python -m pytest tests/ -v --tb=short -o "addopts="`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/tools.py strix-mcp/tests/test_tools.py
git commit -m "feat(mcp): add OWASP categorization and richer end_scan summary"
```

---

### Task 7: Web-only methodology branch

**Files:**
- Modify: `src/strix_mcp/methodology.md`

**Step 1: Add web-only workflow section**

After the existing "### Step 1: Start the Scan" section, add a new conditional section. Insert after the `recommended_plan` description and before "### Step 2":

```markdown
### Web-Only Targets (no source code)

When your targets are web applications, domains, or IP addresses (not local code):

**What changes:**
- `start_scan` fingerprints the target via HTTP (headers, cookies, response body, common paths) instead of reading source files
- There is no code in `/workspace` to analyze — all testing is dynamic against the live target
- Subagents use browser crawling, proxy tools, and automated scanners instead of code review

**Adjusted subagent template for web-only targets:**

Replace the standard subagent template with this one:

---

You are a security testing specialist. Your target is a LIVE WEB APPLICATION — there is no source code to review.

**FIRST — Load your knowledge modules:**
Call the `get_module` tool for each of these modules and read the full content carefully:
{list each module name}

**Use `agent_id="{agent_id}"` for ALL Strix tool calls.**

**YOUR TASK:** {task description from the plan}

**APPROACH (web-only — no source code):**
1. Read your module(s) fully — they are your primary testing guide
2. Explore the target with `browser_action`: launch → goto target URL → crawl key pages → capture screenshots
3. Review captured proxy traffic with `list_requests` to map the attack surface (API endpoints, forms, auth flows)
4. Test dynamically:
   - Use `send_request` and `repeat_request` for API-level testing
   - Use `browser_action` for UI-level testing (forms, uploads, client-side behavior)
   - Use `terminal_execute` to run automated scanners: nuclei, sqlmap, ffuf, wapiti against the target URL
   - Use `python_action` for custom exploit scripts and concurrency (asyncio/aiohttp)
5. For reconnaissance: run `ffuf` for directory/endpoint discovery, `nuclei` with relevant templates
6. Check `list_vulnerability_reports` before filing to avoid duplicates
7. Validate all findings with proof of exploitation — demonstrate concrete impact
8. Return your findings as a structured list with: title, severity, evidence, and remediation

---
```

**Step 2: Add `list_vulnerability_reports` mention to the main template**

In the existing subagent task template (Step 2), add after step 7:

```
8. Check `list_vulnerability_reports` before filing to avoid duplicates
```

And renumber step 8 to 9.

**Step 3: Add `list_modules` mention to the methodology**

In "### Step 1: Start the Scan", add after the plan review paragraph:

```markdown
If you need to see all available modules, call `list_modules()` for the full catalog with categories and descriptions.
```

**Step 4: Add `get_scan_status` mention**

In "### Step 3: Process Results", add:

```markdown
Use `get_scan_status` to monitor progress: see how many agents are running, how many findings have been filed, and elapsed time.
```

**Step 5: Run methodology test**

Run: `cd strix-mcp && python -m pytest tests/test_resources.py::test_get_methodology_returns_content -v -o "addopts="`
Expected: PASS

**Step 6: Commit**

```bash
git add strix-mcp/src/strix_mcp/methodology.md
git commit -m "feat(mcp): add web-only methodology branch and reference new tools"
```

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | `started_at` + `list_modules` tool | sandbox.py, tools.py, test_tools.py |
| 2 | Title normalization + dedup on insert | tools.py, test_tools.py |
| 3 | `list_vulnerability_reports` + `get_scan_status` tools | tools.py, test_tools.py |
| 4 | HTTP-based `detect_stack_from_http` | stack_detector.py, test_stack_detector.py |
| 5 | Wire HTTP fingerprinting into sandbox + start_scan | sandbox.py, tools.py |
| 6 | OWASP categorization + richer `end_scan` | tools.py, test_tools.py |
| 7 | Web-only methodology branch | methodology.md |
