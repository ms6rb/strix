"""Module-level helper functions and constants extracted from tools.py."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin

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


def _analyze_bundle(
    content: str,
    source: str,
    patterns: dict[str, re.Pattern[str]],
    framework_signals: dict[str, list[str]],
    findings: dict[str, Any],
) -> None:
    """Analyze a JS bundle/inline script for security-relevant patterns."""
    # API endpoints
    for m in patterns["api_endpoint"].finditer(content):
        endpoint = m.group(1)
        if not any(ext in endpoint for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
            findings["api_endpoints"].append(endpoint)

    # Firebase config
    for m in patterns["firebase_config"].finditer(content):
        findings["firebase_config"][m.group(1)] = m.group(2)

    # Collection names
    for m in patterns["collection_name"].finditer(content):
        findings["collection_names"].append(m.group(1))

    # Environment variables
    for m in patterns["env_var"].finditer(content):
        findings["environment_variables"].append(m.group(1))

    # Secrets (high-confidence patterns)
    for m in patterns["secret_pattern"].finditer(content):
        val = m.group(1)
        findings["secrets"].append(f"{val[:20]}...({len(val)} chars) in {source}")

    # Generic key assignments
    for m in patterns["generic_key_assignment"].finditer(content):
        val = m.group(1)
        if not val.startswith(("http", "/")):  # Skip URLs
            findings["secrets"].append(f"key_assignment: {val[:20]}... in {source}")

    # OAuth IDs
    for m in patterns["oauth_id"].finditer(content):
        oauth_val = m.group(1) or m.group(2)
        if oauth_val:
            findings["oauth_ids"].append(oauth_val)

    # Internal hostnames
    for m in patterns["internal_host"].finditer(content):
        findings["internal_hostnames"].append(m.group(1))

    # WebSocket URLs
    for m in patterns["websocket"].finditer(content):
        findings["websocket_urls"].append(m.group(1))

    # Route definitions
    for m in patterns["route_def"].finditer(content):
        route = m.group(1)
        if len(route) > 1 and not route.endswith((".js", ".css")):
            findings["route_definitions"].append(route)

    # CSPT sinks — fetch/XHR calls with user-controlled path segments
    cspt_patterns = [
        re.compile(r'''fetch\s*\([^)]*\+[^)]*\)'''),
        re.compile(r'''fetch\s*\(\s*`[^`]*\$\{[^`]*`[^)]*\)'''),
        re.compile(r'''axios\.(?:get|post|put|delete|patch)\s*\([^)]*\+[^)]*\)'''),
        re.compile(r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*`[^`]*\$\{[^`]*`[^)]*\)'''),
        re.compile(r'''\$\.ajax\s*\(\s*\{[^}]*url\s*:[^}]*\+'''),
        re.compile(r'''XMLHttpRequest[^;]*\.open\s*\([^)]*\+[^)]*\)'''),
    ]
    for pat in cspt_patterns:
        for m in pat.finditer(content):
            snippet = m.group(0)[:120]
            findings.setdefault("cspt_sinks", []).append(
                f"{snippet} in {source}"
            )

    # postMessage listeners
    pm_pattern = re.compile(r'''addEventListener\s*\(\s*["']message["']''')
    for m in pm_pattern.finditer(content):
        findings.setdefault("postmessage_listeners", []).append(
            f"message listener in {source}"
        )

    # Internal/private npm package names
    _WELL_KNOWN_SCOPES = {
        "@types", "@babel", "@angular", "@vue", "@react", "@next",
        "@nestjs", "@fastify", "@aws-sdk", "@google-cloud", "@azure",
        "@stripe", "@sentry", "@auth0", "@testing-library", "@emotion",
        "@mui", "@reduxjs", "@tanstack", "@trpc", "@prisma", "@vercel",
        "@sveltejs", "@nuxtjs", "@rollup", "@vitejs", "@eslint",
    }
    pkg_patterns = [
        re.compile(r'''(?:require|from)\s*\(\s*["'](@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)["']'''),
        re.compile(r'''from\s+["'](@[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)["']'''),
    ]
    for pat in pkg_patterns:
        for m in pat.finditer(content):
            pkg = m.group(1)
            scope = pkg.split("/")[0]
            if scope not in _WELL_KNOWN_SCOPES:
                findings.setdefault("internal_packages", []).append(pkg)

    # Framework detection
    if findings["framework"] is None:
        for framework, signals in framework_signals.items():
            if any(re.search(sig, content) for sig in signals):
                findings["framework"] = framework
                break


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
