from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from typing import Any

from fastmcp import FastMCP

from .sandbox import SandboxManager
from .tools_helpers import extract_script_urls, _analyze_bundle

try:
    from strix.telemetry.tracer import get_global_tracer
except ImportError:
    def get_global_tracer():  # type: ignore[misc]  # pragma: no cover
        return None


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
            "cspt_sinks": [],
            "postmessage_listeners": [],
            "internal_packages": [],
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
            "route_definitions", "cspt_sinks", "postmessage_listeners",
            "internal_packages", "interesting_strings",
        ]:
            findings[key] = sorted(set(findings[key]))

        findings["total_findings"] = sum(
            len(findings[k]) for k in [
                "api_endpoints", "collection_names", "environment_variables",
                "secrets", "oauth_ids", "internal_hostnames", "websocket_urls",
                "route_definitions", "cspt_sinks", "postmessage_listeners",
                "internal_packages",
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

    # --- K8s Service Enumeration Wordlist Generator ---

    # Service registry: maps service name -> default ports
    K8S_SERVICES: dict[str, list[int]] = {
        # K8s core
        "kubernetes": [443, 6443],
        "kube-dns": [53],
        "metrics-server": [443],
        "coredns": [53],
        # Monitoring
        "grafana": [3000],
        "prometheus": [9090],
        "alertmanager": [9093],
        "victoria-metrics": [8428],
        "thanos": [9090, 10901],
        "loki": [3100],
        "tempo": [3200],
        # GitOps
        "argocd-server": [443, 8080],
        # Security
        "vault": [8200],
        "cert-manager": [9402],
        # Service mesh
        "istiod": [15010, 15012],
        "istio-ingressgateway": [443, 80],
        # Auth
        "keycloak": [8080, 8443],
        "hydra": [4444, 4445],
        "dex": [5556],
        "oauth2-proxy": [4180],
        # Data
        "redis": [6379],
        "rabbitmq": [5672, 15672],
        "kafka": [9092],
        "elasticsearch": [9200],
        "nats": [4222],
        # AWS EKS
        "aws-load-balancer-controller": [9443],
        "external-dns": [7979],
        "ebs-csi-controller": [9808],
        "cluster-autoscaler": [8085],
    }
    _TARGET_DEFAULT_PORTS = [443, 8080, 5432, 3000]

    @mcp.tool()
    async def k8s_enumerate(
        target_name: str | None = None,
        namespaces: list[str] | None = None,
        ports: list[int] | None = None,
        scheme: str = "https",
        max_urls: int = 500,
    ) -> str:
        """Generate a K8s service enumeration wordlist for SSRF probing.
        No sandbox required.

        Returns service URLs to test via SSRF. Each service is mapped to its
        known default ports (not a cartesian product), keeping the list compact.

        target_name: company/product name for generating custom service names (e.g. "neon")
        namespaces: custom namespaces (default: common K8s namespaces)
        ports: ADDITIONAL ports to scan on top of each service's defaults
        scheme: URL scheme (default "https")
        max_urls: maximum URLs to return (default 500)

        Usage: get the URL list, then use python_action to spray them through
        your SSRF vector and observe which ones resolve."""

        # Build service -> ports mapping (start from registry defaults)
        service_ports: dict[str, list[int]] = {
            svc: list(svc_ports) for svc, svc_ports in K8S_SERVICES.items()
        }

        # Target-specific services with default ports
        if target_name:
            name = target_name.lower().strip()
            for suffix in ["-api", "-proxy", "-auth", "-control-plane", "-storage", "-compute"]:
                service_ports[f"{name}{suffix}"] = list(_TARGET_DEFAULT_PORTS)

        # Append user-supplied additional ports to every service
        if ports:
            for svc in service_ports:
                for p in ports:
                    if p not in service_ports[svc]:
                        service_ports[svc].append(p)

        # Namespaces
        default_namespaces = [
            "default", "kube-system", "monitoring", "argocd",
            "vault", "cert-manager", "istio-system",
        ]
        if target_name:
            default_namespaces.append(target_name.lower().strip())
        ns_list = namespaces or default_namespaces

        # Namespace affinity: map services to their likely namespaces
        # Only generate URLs for plausible service→namespace combinations
        ns_affinity: dict[str, list[str]] = {
            "default": ["kubernetes"],
            "kube-system": ["kube-dns", "coredns", "metrics-server", "aws-load-balancer-controller",
                            "external-dns", "ebs-csi-controller", "cluster-autoscaler"],
            "monitoring": ["grafana", "prometheus", "alertmanager", "victoria-metrics",
                           "thanos", "loki", "tempo"],
            "argocd": ["argocd-server"],
            "vault": ["vault"],
            "cert-manager": ["cert-manager"],
            "istio-system": ["istiod", "istio-ingressgateway", "envoy", "linkerd-controller"],
        }
        # Target-specific services go to target namespace
        if target_name:
            name = target_name.lower().strip()
            ns_affinity[name] = [f"{name}{s}" for s in ["-api", "-proxy", "-auth", "-control-plane", "-storage", "-compute"]]

        # Services not in any affinity map go to all namespaces
        mapped_services = set()
        for svcs in ns_affinity.values():
            mapped_services.update(svcs)
        unmapped = [s for s in service_ports if s not in mapped_services]

        # Generate URLs — use affinity when available, fallback to default+kube-system for unmapped
        by_namespace: dict[str, list[str]] = {ns: [] for ns in ns_list}
        total = 0
        for ns in ns_list:
            affinity_svcs = ns_affinity.get(ns, [])
            for svc in affinity_svcs:
                if svc in service_ports:
                    for port in service_ports[svc]:
                        by_namespace[ns].append(f"{scheme}://{svc}.{ns}.svc.cluster.local:{port}")
                        total += 1
            # Unmapped services only go to default and kube-system
            if ns in ("default", "kube-system"):
                for svc in unmapped:
                    for port in service_ports[svc]:
                        by_namespace[ns].append(f"{scheme}://{svc}.{ns}.svc.cluster.local:{port}")
                        total += 1

        # Remove empty namespaces
        by_namespace = {ns: urls for ns, urls in by_namespace.items() if urls}

        # Short-form names (service only)
        short_forms: list[str] = [f"{scheme}://{svc}" for svc in service_ports]

        # Cap output — distribute evenly across namespaces
        omitted = 0
        if max_urls <= 0:
            by_namespace = {ns: [] for ns in by_namespace}
            omitted = total
            total = 0
        elif total > max_urls:
            per_ns = max(max_urls // len(by_namespace), 1)
            new_total = 0
            for ns in by_namespace:
                if len(by_namespace[ns]) > per_ns:
                    omitted += len(by_namespace[ns]) - per_ns
                    by_namespace[ns] = by_namespace[ns][:per_ns]
                new_total += len(by_namespace[ns])
            total = new_total

        result: dict[str, Any] = {
            "total_urls": total,
            "services": list(service_ports.keys()),
            "namespaces": ns_list,
            "urls_by_namespace": by_namespace,
            "short_forms": short_forms,
            "usage_hint": (
                "Spray these URLs through your SSRF vector. Compare responses to a "
                "baseline (known-bad hostname) to identify which services resolve. "
                "Short forms work when K8s DNS search domains are configured."
            ),
        }
        if omitted:
            result["omitted_urls"] = omitted
            result["note"] = f"{omitted} URLs omitted due to max_urls={max_urls} cap."

        return json.dumps(result)

    # --- Blind SSRF Oracle Builder ---

    @mcp.tool()
    async def ssrf_oracle(
        ssrf_url: str,
        ssrf_param: str = "url",
        ssrf_method: str = "POST",
        ssrf_headers: dict[str, str] | None = None,
        ssrf_body_template: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Calibrate a blind SSRF oracle by testing response differentials.
        Requires an active sandbox.

        Given a confirmed blind SSRF endpoint, tests with known-good and known-bad
        targets to build an oracle (timing, status codes) that can distinguish
        successful from failed internal requests.

        ssrf_url: the vulnerable endpoint URL (e.g. webhook config endpoint)
        ssrf_param: parameter name that accepts the target URL (default "url")
        ssrf_method: HTTP method (default POST)
        ssrf_headers: additional headers for the SSRF request
        ssrf_body_template: request body template with {TARGET_URL} placeholder
        agent_id: subagent identifier from dispatch_agent

        NOTE on retry oracle: This tool detects timing and status differentials
        from the SSRF config endpoint response. For webhook-style SSRFs where the
        real oracle is in delivery retries, you need a 2-phase approach:
        (1) set webhook URL to a redirect → interactsh/webhook.site
        (2) trigger the event that fires the webhook
        (3) count incoming requests at the receiver
        Use python_action for this — this tool handles the config-response oracle.

        Returns: oracle calibration data — baseline responses, timing differentials,
        and recommended exploitation approach."""

        scan = sandbox.active_scan
        if scan is None:
            return json.dumps({"error": "No active scan. Call start_scan first."})

        extra_headers = ssrf_headers or {}
        method = ssrf_method.upper()

        # Helper to send one SSRF probe through the sandbox proxy
        async def _send_probe(target_url: str) -> dict[str, Any]:
            """Send a single probe through the SSRF vector and measure response."""
            if ssrf_body_template:
                body_str = ssrf_body_template.replace("{TARGET_URL}", target_url)
                try:
                    body = json.loads(body_str)
                except (json.JSONDecodeError, ValueError):
                    body = body_str
            else:
                body = {ssrf_param: target_url}

            req_kwargs: dict[str, Any] = {
                "url": ssrf_url,
                "method": method,
                "headers": {
                    "Content-Type": "application/json",
                    **extra_headers,
                },
            }

            if isinstance(body, dict):
                req_kwargs["body"] = json.dumps(body)
            else:
                req_kwargs["body"] = str(body)

            if agent_id:
                req_kwargs["agent_id"] = agent_id

            t0 = time.monotonic()
            try:
                resp = await sandbox.proxy_tool("send_request", req_kwargs)
                elapsed_ms = round((time.monotonic() - t0) * 1000)
                status = resp.get("status_code", resp.get("response", {}).get("status_code", 0))
                body_text = resp.get("body", resp.get("response", {}).get("body", ""))
                body_len = len(body_text) if isinstance(body_text, str) else 0
                return {
                    "status_code": status,
                    "elapsed_ms": elapsed_ms,
                    "body_length": body_len,
                    "body_preview": body_text[:300] if isinstance(body_text, str) else "",
                    "error": None,
                }
            except Exception as exc:
                elapsed_ms = round((time.monotonic() - t0) * 1000)
                return {
                    "status_code": 0,
                    "elapsed_ms": elapsed_ms,
                    "body_length": 0,
                    "body_preview": "",
                    "error": str(exc),
                }

        # --- Phase 1: Baseline calibration ---
        probe_targets = {
            "reachable": "https://httpbin.org/status/200",
            "unreachable": "https://192.0.2.1/",
            "dns_fail": "https://this-domain-does-not-exist-strix-test.invalid/",
        }

        baseline: dict[str, Any] = {}
        for label, target in probe_targets.items():
            baseline[label] = await _send_probe(target)

        # --- Phase 2: Retry oracle detection ---
        retry_oracle: dict[str, Any] = {"detected": False}

        # Probe with status 500 to see if SSRF retries
        probe_500 = await _send_probe("https://httpbin.org/status/500")
        probe_200 = await _send_probe("https://httpbin.org/status/200")

        # If 500 takes significantly longer than 200, the server may be retrying
        if probe_500["elapsed_ms"] > probe_200["elapsed_ms"] * 2 + 500:
            retry_oracle["detected"] = True
            retry_oracle["evidence"] = (
                f"500 target took {probe_500['elapsed_ms']}ms vs "
                f"{probe_200['elapsed_ms']}ms for 200 target — "
                f"likely retrying on failure"
            )
        retry_oracle["timing_500_ms"] = probe_500["elapsed_ms"]
        retry_oracle["timing_200_ms"] = probe_200["elapsed_ms"]

        # --- Phase 3: Timing oracle detection ---
        timing_oracle: dict[str, Any] = {"detected": False}

        probe_fast = baseline["reachable"]
        probe_slow = await _send_probe("https://httpbin.org/delay/3")
        probe_dead = baseline["unreachable"]

        fast_ms = probe_fast["elapsed_ms"]
        slow_ms = probe_slow["elapsed_ms"]
        dead_ms = probe_dead["elapsed_ms"]

        # Timing oracle exists if slow target causes slower SSRF response
        if slow_ms > fast_ms * 1.5 + 1000:
            timing_oracle["detected"] = True
            timing_oracle["evidence"] = (
                f"Response time correlates with target: fast={fast_ms}ms, "
                f"slow={slow_ms}ms, unreachable={dead_ms}ms"
            )
        timing_oracle["fast_ms"] = fast_ms
        timing_oracle["slow_ms"] = slow_ms
        timing_oracle["unreachable_ms"] = dead_ms

        # --- Phase 4: Status differential detection ---
        status_oracle: dict[str, Any] = {"detected": False}

        statuses = {
            probe_targets["reachable"]: baseline["reachable"]["status_code"],
            probe_targets["unreachable"]: baseline["unreachable"]["status_code"],
            probe_targets["dns_fail"]: baseline["dns_fail"]["status_code"],
        }
        unique_statuses = set(statuses.values())
        if len(unique_statuses) > 1 and 0 not in unique_statuses:
            status_oracle["detected"] = True
            status_oracle["evidence"] = (
                f"Different status codes for different targets: {statuses}"
            )
        status_oracle["status_map"] = statuses

        # --- Phase 5: Body differential detection ---
        body_oracle: dict[str, Any] = {"detected": False}
        body_lengths = {
            "reachable": baseline["reachable"]["body_length"],
            "unreachable": baseline["unreachable"]["body_length"],
            "dns_fail": baseline["dns_fail"]["body_length"],
        }
        unique_lengths = set(body_lengths.values())
        if len(unique_lengths) > 1:
            body_oracle["detected"] = True
            body_oracle["evidence"] = f"Different body sizes: {body_lengths}"
        body_oracle["body_lengths"] = body_lengths

        # --- Build recommended approach ---
        oracles_detected = []
        if retry_oracle["detected"]:
            oracles_detected.append("retry")
        if timing_oracle["detected"]:
            oracles_detected.append("timing")
        if status_oracle["detected"]:
            oracles_detected.append("status_differential")
        if body_oracle["detected"]:
            oracles_detected.append("body_differential")

        if not oracles_detected:
            recommended = (
                "No clear oracle detected. Try: (1) use a webhook/callback URL "
                "(e.g. webhook.site) as target to count callbacks for retry detection, "
                "(2) increase timing thresholds with longer delays, "
                "(3) test with error-triggering internal targets."
            )
        elif "status_differential" in oracles_detected:
            recommended = (
                "Use status code differential for port scanning — different status "
                "codes reveal whether internal targets respond. Most reliable oracle."
            )
        elif "retry" in oracles_detected:
            recommended = (
                "Use retry oracle for port scanning — probe internal IPs and count "
                "callbacks (via webhook.site) to determine if service is running. "
                "500/error responses trigger retries; 200 responses do not."
            )
        elif "timing" in oracles_detected:
            recommended = (
                "Use timing oracle for service discovery — response time correlates "
                "with target response time. Compare fast (responding service) vs "
                "slow (non-responding IP) to identify live services."
            )
        else:
            recommended = (
                "Use body differential for service discovery — different response "
                "body sizes indicate the SSRF target's response affects the output."
            )

        return json.dumps({
            "type": "blind_ssrf",
            "ssrf_endpoint": ssrf_url,
            "oracles": {
                "retry": retry_oracle,
                "timing": timing_oracle,
                "status_differential": status_oracle,
                "body_differential": body_oracle,
            },
            "oracles_detected": oracles_detected,
            "recommended_approach": recommended,
            "baseline": baseline,
            "total_probes_sent": 7,
        })

    # --- HTTP Request Smuggling Detection (MCP-side, direct HTTP) ---

    @mcp.tool()
    async def test_request_smuggling(
        target_url: str,
        timeout: int = 10,
    ) -> str:
        """Test for HTTP request smuggling vulnerabilities by probing for parser
        discrepancies between front-end proxies and back-end servers. No sandbox required.

        Tests CL.TE, TE.CL, TE.TE, and TE.0 variants. Also detects proxy/CDN
        stack via fingerprinting headers.

        target_url: base URL to test (e.g. "https://example.com")
        timeout: seconds to wait per probe (default 10, higher values detect timing-based smuggling)

        Use during reconnaissance when the target is behind a CDN or reverse proxy.
        Load the 'request_smuggling' skill for detailed exploitation guidance."""
        import httpx

        base = target_url.rstrip("/")
        results: dict[str, Any] = {
            "target_url": target_url,
            "proxy_stack": {},
            "baseline": {},
            "probes": [],
            "te_obfuscation_results": [],
            "summary": {"potential_vulnerabilities": 0, "tested_variants": 0},
            "note": (
                "httpx may normalize Content-Length and Transfer-Encoding headers. "
                "Results marked 'potential' should be confirmed with raw socket probes."
            ),
        }

        # CDN/proxy signature headers to look for
        cdn_signatures: dict[str, str] = {
            "cf-ray": "cloudflare",
            "x-amz-cf-id": "cloudfront",
            "x-akamai-transformed": "akamai",
            "x-fastly-request-id": "fastly",
            "x-varnish": "varnish",
        }
        proxy_headers = [
            "server", "via", "x-served-by", "x-cache", "x-cache-hits",
            "cf-ray", "x-amz-cf-id", "x-akamai-transformed",
            "x-fastly-request-id", "x-varnish",
        ]

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            http1=True,
            http2=False,
        ) as client:

            # --- Phase 1: Baseline + proxy fingerprinting ---
            try:
                t0 = time.monotonic()
                baseline_resp = await client.get(
                    base,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                )
                baseline_time_ms = round((time.monotonic() - t0) * 1000)

                results["baseline"] = {
                    "status": baseline_resp.status_code,
                    "response_time_ms": baseline_time_ms,
                }

                # Collect proxy stack info
                proxy_stack: dict[str, str] = {}
                detected_cdn: str | None = None
                for hdr in proxy_headers:
                    val = baseline_resp.headers.get(hdr)
                    if val:
                        proxy_stack[hdr] = val
                        if hdr in cdn_signatures:
                            detected_cdn = cdn_signatures[hdr]
                if detected_cdn:
                    proxy_stack["cdn"] = detected_cdn
                results["proxy_stack"] = proxy_stack

            except Exception as e:
                results["baseline"] = {"error": str(e)}
                return json.dumps(results)

            baseline_status = baseline_resp.status_code
            baseline_ms = baseline_time_ms

            # Helper: send a probe and classify
            async def _probe(
                variant: str,
                headers: dict[str, str],
                body: bytes,
            ) -> dict[str, Any]:
                probe_result: dict[str, Any] = {
                    "variant": variant,
                    "status": "not_vulnerable",
                    "evidence": "",
                }
                try:
                    t0 = time.monotonic()
                    resp = await client.post(
                        base,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            **headers,
                        },
                        content=body,
                    )
                    elapsed_ms = round((time.monotonic() - t0) * 1000)

                    # Detect anomalies
                    status_changed = resp.status_code != baseline_status
                    is_error = resp.status_code in (400, 500, 501, 502)
                    is_slow = elapsed_ms > (baseline_ms * 5 + 2000)

                    if is_slow:
                        probe_result["status"] = "potential"
                        probe_result["evidence"] = (
                            f"response timeout ({elapsed_ms}ms vs {baseline_ms}ms baseline)"
                        )
                    elif is_error and not status_changed:
                        probe_result["evidence"] = (
                            f"error status {resp.status_code} (same as baseline)"
                        )
                    elif status_changed and is_error:
                        probe_result["status"] = "potential"
                        probe_result["evidence"] = (
                            f"status changed to {resp.status_code} "
                            f"(baseline {baseline_status})"
                        )
                    else:
                        probe_result["evidence"] = (
                            f"normal {resp.status_code} response in {elapsed_ms}ms"
                        )

                    probe_result["response_status"] = resp.status_code
                    probe_result["response_time_ms"] = elapsed_ms

                except httpx.ReadTimeout:
                    probe_result["status"] = "potential"
                    probe_result["evidence"] = (
                        f"read timeout ({timeout}s) — back-end may be waiting for more data"
                    )
                except Exception as e:
                    probe_result["status"] = "error"
                    probe_result["evidence"] = str(e)

                return probe_result

            # --- Phase 2: CL.TE probe ---
            # Front-end uses Content-Length, back-end uses Transfer-Encoding.
            # CL says 4 bytes, but TE body is longer — leftover poisons next request.
            clte_body = b"1\r\nZ\r\n0\r\n\r\n"
            clte_result = await _probe(
                "CL.TE",
                {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                clte_body,
            )
            results["probes"].append(clte_result)

            # --- Phase 3: TE.CL probe ---
            # Front-end uses Transfer-Encoding, back-end uses Content-Length.
            # TE ends at chunk 0, but CL includes extra bytes.
            tecl_body = b"0\r\n\r\nSMUGGLED"
            tecl_result = await _probe(
                "TE.CL",
                {
                    "Content-Length": "50",
                    "Transfer-Encoding": "chunked",
                },
                tecl_body,
            )
            results["probes"].append(tecl_result)

            # --- Phase 4: TE.TE obfuscation variants ---
            # NOTE: dual TE header probes may not work as intended — httpx
            # normalizes header names to lowercase, merging duplicate keys.
            # Results for dual_te_* variants should be confirmed with raw sockets.
            te_obfuscations: list[tuple[str, dict[str, str]]] = [
                ("xchunked", {"Transfer-Encoding": "xchunked"}),
                ("space_before_colon", {"Transfer-Encoding ": "chunked"}),
                ("tab_after_colon", {"Transfer-Encoding": "\tchunked"}),
                ("dual_te_chunked_x", {"Transfer-Encoding": "chunked", "Transfer-encoding": "x"}),
                ("dual_te_chunked_cow", {"Transfer-Encoding": "chunked", "Transfer-encoding": "cow"}),
            ]

            for label, te_headers in te_obfuscations:
                te_result = await _probe(
                    f"TE.TE ({label})",
                    {
                        "Content-Length": "4",
                        **te_headers,
                    },
                    b"1\r\nZ\r\n0\r\n\r\n",
                )
                results["te_obfuscation_results"].append(te_result)

            # --- Phase 5: TE.0 probe ---
            # Send TE:chunked with CL:0 but include chunked data — if front-end
            # strips TE and uses CL:0, the chunked data stays in the pipeline.
            te0_result = await _probe(
                "TE.0",
                {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "0",
                },
                b"1\r\nZ\r\n0\r\n\r\n",
            )
            results["probes"].append(te0_result)

            # --- Summary ---
            all_probes = results["probes"] + results["te_obfuscation_results"]
            results["summary"]["tested_variants"] = len(all_probes)
            results["summary"]["potential_vulnerabilities"] = sum(
                1 for p in all_probes if p["status"] == "potential"
            )

        return json.dumps(results)

    # --- Web Cache Poisoning / Cache Deception Detection (MCP-side, direct HTTP) ---

    @mcp.tool()
    async def test_cache_poisoning(
        target_url: str,
        paths: list[str] | None = None,
    ) -> str:
        """Test for web cache poisoning by systematically probing unkeyed headers
        and cache deception via parser discrepancies. No sandbox required.

        Tests unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, etc.) and
        cache deception paths (appending .css/.js/.png to authenticated endpoints).

        target_url: base URL to test
        paths: specific paths to test (default: /, /login, /account, /api)

        Load the 'cache_poisoning' skill for detailed exploitation guidance."""
        import httpx

        base = target_url.rstrip("/")
        test_paths = paths or ["/", "/login", "/account", "/api"]

        results: dict[str, Any] = {
            "target_url": target_url,
            "cache_detected": False,
            "cache_type": None,
            "unkeyed_headers": [],
            "cache_deception": [],
            "summary": {"poisoning_vectors": 0, "deception_vectors": 0, "total_probes": 0},
        }

        # Cache detection header mapping
        cache_indicators = {
            "x-cache": None,
            "cf-cache-status": "cloudflare",
            "age": None,
            "x-cache-hits": None,
            "x-varnish": "varnish",
        }

        # Unkeyed headers to test with their canary values
        unkeyed_probes: list[tuple[str, str, str]] = [
            ("X-Forwarded-Host", "canary.example.com", "body"),
            ("X-Forwarded-Scheme", "nothttps", "redirect"),
            ("X-Forwarded-Proto", "nothttps", "redirect"),
            ("X-Original-URL", "/canary-path", "body"),
            ("X-Rewrite-URL", "/canary-path", "body"),
            ("X-HTTP-Method-Override", "POST", "behavior"),
            ("X-Forwarded-Port", "1337", "body"),
            ("X-Custom-IP-Authorization", "127.0.0.1", "body"),
        ]

        # Cache deception extensions and parser tricks
        deception_extensions = [".css", ".js", ".png", ".svg", "/style.css", "/x.js"]
        parser_tricks = [";.css", "%0A.css", "%00.css"]
        deception_paths = ["/account", "/profile", "/settings", "/dashboard", "/me"]

        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=False,
            http1=True,
            http2=False,
        ) as client:

            ua_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            }

            # --- Phase 1: Cache detection ---
            # Send two identical requests and compare caching headers
            try:
                resp1 = await client.get(base + test_paths[0], headers=ua_headers)
                resp2 = await client.get(base + test_paths[0], headers=ua_headers)

                cache_type: str | None = None
                cache_detected = False

                for hdr, cdn_name in cache_indicators.items():
                    val1 = resp1.headers.get(hdr)
                    val2 = resp2.headers.get(hdr)

                    if val2:
                        # Check for cache HIT indicators
                        if hdr == "x-cache" and "hit" in val2.lower():
                            cache_detected = True
                        elif hdr == "cf-cache-status" and val2.upper() in ("HIT", "DYNAMIC", "REVALIDATED"):
                            cache_detected = True
                            cache_type = "cloudflare"
                        elif hdr == "age":
                            try:
                                if int(val2) > 0:
                                    cache_detected = True
                            except ValueError:
                                pass
                        elif hdr == "x-cache-hits":
                            try:
                                if int(val2) > 0:
                                    cache_detected = True
                            except ValueError:
                                pass
                        elif hdr == "x-varnish":
                            # Two IDs in x-varnish means cached
                            if len(val2.split()) >= 2:
                                cache_detected = True
                                cache_type = "varnish"

                        if cdn_name and not cache_type:
                            cache_type = cdn_name

                # Also detect cache from Cache-Control / Pragma
                cc = resp2.headers.get("cache-control", "")
                if "public" in cc or ("max-age=" in cc and "max-age=0" not in cc and "no-cache" not in cc):
                    cache_detected = True

                results["cache_detected"] = cache_detected
                results["cache_type"] = cache_type

            except Exception as e:
                results["cache_deception"].append({"error": f"Cache detection failed: {e}"})

            # --- Phase 2: Unkeyed header testing ---
            probe_count = 0
            for header_name, canary_value, reflection_type in unkeyed_probes:
                for path in test_paths:
                    probe_count += 1
                    entry: dict[str, Any] = {
                        "header": header_name,
                        "path": path,
                        "reflected": False,
                        "cached": False,
                        "severity": None,
                        "reflection_location": None,
                    }

                    # Use a cache buster so each probe is independent
                    cache_buster = f"cb={uuid.uuid4().hex[:8]}"
                    sep = "&" if "?" in path else "?"
                    probe_url = f"{base}{path}{sep}{cache_buster}"

                    try:
                        resp = await client.get(
                            probe_url,
                            headers={
                                **ua_headers,
                                header_name: canary_value,
                            },
                        )

                        body = resp.text
                        location = resp.headers.get("location", "")
                        set_cookie = resp.headers.get("set-cookie", "")

                        # Check reflection
                        reflected = False
                        reflection_loc = None

                        if canary_value in body:
                            reflected = True
                            reflection_loc = "body"
                        elif canary_value in location:
                            reflected = True
                            reflection_loc = "location_header"
                        elif canary_value in set_cookie:
                            reflected = True
                            reflection_loc = "set_cookie"
                        elif header_name == "X-Forwarded-Scheme" and resp.status_code in (301, 302):
                            # Redirect often means the scheme header was processed
                            if "https" in location or canary_value in location:
                                reflected = True
                                reflection_loc = "redirect"
                        elif header_name == "X-Forwarded-Proto" and resp.status_code in (301, 302):
                            reflected = True
                            reflection_loc = "redirect"

                        entry["reflected"] = reflected
                        entry["reflection_location"] = reflection_loc

                        # Check if cached
                        is_cached = False
                        x_cache = resp.headers.get("x-cache", "")
                        cf_status = resp.headers.get("cf-cache-status", "")
                        age = resp.headers.get("age", "")

                        if "hit" in x_cache.lower():
                            is_cached = True
                        elif cf_status.upper() in ("HIT", "REVALIDATED"):
                            is_cached = True
                        elif age:
                            try:
                                is_cached = int(age) > 0
                            except ValueError:
                                pass

                        entry["cached"] = is_cached

                        if reflected and is_cached:
                            entry["severity"] = "high"
                        elif reflected:
                            entry["severity"] = "medium"

                    except Exception as e:
                        entry["error"] = str(e)

                    # Only record interesting results (reflected or errors)
                    if entry.get("reflected") or entry.get("error"):
                        results["unkeyed_headers"].append(entry)

            # --- Phase 3: Cache deception testing ---
            for path in deception_paths:
                # First get the baseline for this path
                try:
                    baseline_resp = await client.get(
                        f"{base}{path}",
                        headers=ua_headers,
                    )
                    baseline_status = baseline_resp.status_code
                    baseline_length = len(baseline_resp.text)
                    # Skip if path returns 404 — nothing to deceive
                    if baseline_status == 404:
                        continue
                except Exception:
                    continue

                for ext in deception_extensions + parser_tricks:
                    probe_count += 1
                    deception_url = f"{base}{path}{ext}"

                    deception_entry: dict[str, Any] = {
                        "path": f"{path}{ext}",
                        "returns_dynamic_content": False,
                        "cached": False,
                        "severity": None,
                    }

                    try:
                        resp = await client.get(deception_url, headers=ua_headers)

                        # Check if it returns content similar to the original path
                        resp_length = len(resp.text)
                        is_dynamic = (
                            resp.status_code == baseline_status
                            and resp.status_code != 404
                            and resp_length > 100
                            and abs(resp_length - baseline_length) / max(baseline_length, 1) < 0.5
                        )

                        deception_entry["returns_dynamic_content"] = is_dynamic
                        deception_entry["response_status"] = resp.status_code

                        # Check caching
                        is_cached = False
                        cc = resp.headers.get("cache-control", "")
                        x_cache = resp.headers.get("x-cache", "")
                        cf_status = resp.headers.get("cf-cache-status", "")
                        age = resp.headers.get("age", "")

                        if "hit" in x_cache.lower():
                            is_cached = True
                        elif cf_status.upper() in ("HIT", "REVALIDATED"):
                            is_cached = True
                        elif age:
                            try:
                                is_cached = int(age) > 0
                            except ValueError:
                                pass
                        elif "public" in cc or ("max-age=" in cc and "max-age=0" not in cc and "no-cache" not in cc):
                            is_cached = True

                        deception_entry["cached"] = is_cached

                        if is_dynamic and is_cached:
                            deception_entry["severity"] = "high"
                        elif is_dynamic:
                            deception_entry["severity"] = "low"

                    except Exception as e:
                        deception_entry["error"] = str(e)

                    # Only record interesting results
                    if deception_entry.get("returns_dynamic_content") or deception_entry.get("error"):
                        results["cache_deception"].append(deception_entry)

            # --- Summary ---
            results["summary"]["poisoning_vectors"] = sum(
                1 for h in results["unkeyed_headers"]
                if h.get("reflected") and h.get("cached")
            )
            results["summary"]["deception_vectors"] = sum(
                1 for d in results["cache_deception"]
                if d.get("returns_dynamic_content") and d.get("cached")
            )
            results["summary"]["total_probes"] = probe_count

        return json.dumps(results)
