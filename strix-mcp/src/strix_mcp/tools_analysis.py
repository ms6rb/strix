from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP

from .sandbox import SandboxManager
from .tools_helpers import extract_script_urls, _analyze_bundle

try:
    from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
except ImportError:
    Tracer = None  # type: ignore[assignment,misc]
    def get_global_tracer():  # type: ignore[misc]  # pragma: no cover
        return None
    def set_global_tracer(tracer):  # type: ignore[misc]  # pragma: no cover
        pass


def register_analysis_tools(mcp: FastMCP, sandbox: SandboxManager) -> None:

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
