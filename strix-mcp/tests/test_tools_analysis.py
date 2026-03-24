"""Unit tests for analysis MCP tools (no Docker required)."""
import json

import pytest
from unittest.mock import MagicMock
from fastmcp import FastMCP
from strix_mcp.tools import register_tools
from strix_mcp.sandbox import ScanState


def _tool_text(result) -> str:
    """Extract JSON text from a FastMCP ToolResult."""
    return result.content[0].text


class TestCompareSessions:
    """Tests for the compare_sessions MCP tool."""

    @pytest.fixture
    def mcp_with_proxy(self):
        """MCP with mock sandbox that simulates proxy responses."""
        from unittest.mock import AsyncMock

        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        scan = ScanState(
            scan_id="test-scan",
            workspace_id="ws-1",
            api_url="http://localhost:8080",
            token="tok",
            port=8080,
            default_agent_id="mcp-test",
        )
        mock_sandbox.active_scan = scan
        mock_sandbox._active_scan = scan
        mock_sandbox.proxy_tool = AsyncMock()
        register_tools(mcp, mock_sandbox)
        return mcp, mock_sandbox

    @pytest.mark.asyncio
    async def test_no_active_scan(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "No active scan" in result["error"]

    @pytest.mark.asyncio
    async def test_missing_label(self, mcp_with_proxy):
        mcp, _ = mcp_with_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "label" in result["error"]

    @pytest.mark.asyncio
    async def test_no_captured_requests(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy
        mock_sandbox.proxy_tool.return_value = {"requests": []}
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert "error" in result
        assert "No captured requests" in result["error"]

    @pytest.mark.asyncio
    async def test_same_responses(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        # First call: list_requests; subsequent calls: repeat_request
        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": '{"users":[]}'}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert result["total_endpoints"] == 1
        assert result["classification_counts"]["same"] == 1

    @pytest.mark.asyncio
    async def test_divergent_responses(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        repeat_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count, repeat_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/admin/settings"},
                    ]}
                return {"requests": []}
            # First repeat = session A (admin), second = session B (user)
            repeat_count += 1
            if repeat_count % 2 == 1:
                return {"response": {"status_code": 200, "body": '{"settings":"secret"}'}}
            return {"response": {"status_code": 403, "body": "Forbidden"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        assert result["total_endpoints"] == 1
        assert result["classification_counts"].get("a_only", 0) == 1

    @pytest.mark.asyncio
    async def test_deduplication(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                        {"id": "req2", "method": "GET", "path": "/api/users"},  # duplicate
                        {"id": "req3", "method": "POST", "path": "/api/users"},  # different method
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {"Authorization": "Bearer aaa"}},
            "session_b": {"label": "user", "headers": {"Authorization": "Bearer bbb"}},
        })))
        # Should have 2 unique endpoints: GET /api/users and POST /api/users
        assert result["total_endpoints"] == 2

    @pytest.mark.asyncio
    async def test_method_filter(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/users"},
                        {"id": "req2", "method": "DELETE", "path": "/api/users/1"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "admin", "headers": {}},
            "session_b": {"label": "user", "headers": {}},
            "methods": ["GET"],
        })))
        # Only GET should be included
        assert result["total_endpoints"] == 1
        assert result["results"][0]["method"] == "GET"

    @pytest.mark.asyncio
    async def test_max_requests_cap(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": f"req{i}", "method": "GET", "path": f"/api/endpoint{i}"}
                        for i in range(100)
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 200, "body": "ok"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "a", "headers": {}},
            "session_b": {"label": "b", "headers": {}},
            "max_requests": 5,
        })))
        assert result["total_endpoints"] == 5

    @pytest.mark.asyncio
    async def test_both_denied(self, mcp_with_proxy):
        mcp, mock_sandbox = mcp_with_proxy

        call_count = 0
        async def mock_proxy(tool_name, kwargs):
            nonlocal call_count
            if tool_name == "list_requests":
                if call_count == 0:
                    call_count += 1
                    return {"requests": [
                        {"id": "req1", "method": "GET", "path": "/api/secret"},
                    ]}
                return {"requests": []}
            return {"response": {"status_code": 403, "body": "Forbidden"}}

        mock_sandbox.proxy_tool = mock_proxy
        result = json.loads(_tool_text(await mcp.call_tool("compare_sessions", {
            "session_a": {"label": "user1", "headers": {}},
            "session_b": {"label": "user2", "headers": {}},
        })))
        assert result["classification_counts"]["both_denied"] == 1


class TestFirebaseAudit:
    """Tests for the firebase_audit MCP tool."""

    @pytest.fixture
    def mcp_firebase(self):
        """MCP with mock sandbox (no active scan needed for firebase_audit)."""
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, json_data=None, text=""):
        """Create a mock httpx.Response."""
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text or json.dumps(json_data or {})
        resp.json = MagicMock(return_value=json_data or {})
        return resp

    @pytest.mark.asyncio
    async def test_anonymous_auth_open(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        # Anonymous signup: success
        anon_resp = self._mock_response(200, {
            "idToken": "fake-anon-token",
            "localId": "anon-uid-123",
        })

        # All other requests: 403
        denied_resp = self._mock_response(403, {"error": {"message": "PERMISSION_DENIED"}})

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "accounts:signUp" in url and call_count == 1:
                return anon_resp
            return denied_resp

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["auth"]["anonymous_signup"] == "open"
        assert result["auth"]["anonymous_uid"] == "anon-uid-123"
        assert result["total_issues"] >= 1
        assert any("Anonymous auth" in i for i in result["issues"])

    @pytest.mark.asyncio
    async def test_anonymous_auth_blocked(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        blocked_resp = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        denied_resp = self._mock_response(403)

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(return_value=blocked_resp)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["auth"]["anonymous_signup"] == "blocked"

    @pytest.mark.asyncio
    async def test_firestore_readable_collection(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        list_resp = self._mock_response(200, {"documents": [
            {"name": "projects/test/databases/(default)/documents/users/doc1"},
        ]})

        async def mock_get(url, **kwargs):
            if "/documents/users?" in url:
                return list_resp
            return denied_resp

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        matrix = result["firestore"]["acl_matrix"]
        assert "users" in matrix
        assert "allowed" in matrix["users"]["unauthenticated"]["list"]

    @pytest.mark.asyncio
    async def test_all_denied_collections_filtered(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        not_found_resp = self._mock_response(404)
        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})

        async def mock_post(url, **kwargs):
            if "accounts:signUp" in url:
                return anon_denied
            return not_found_resp

        mock_client.get = AsyncMock(return_value=not_found_resp)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.delete = AsyncMock(return_value=not_found_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["nonexistent_collection"],
                "test_signup": False,
            })))

        assert result["firestore"]["active_collections"] == 0

    @pytest.mark.asyncio
    async def test_storage_listable(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()

        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})
        denied_resp = self._mock_response(403)
        storage_resp = self._mock_response(200, {
            "items": [{"name": "uploads/file1.pdf"}, {"name": "uploads/file2.jpg"}],
        })

        async def mock_get(url, **kwargs):
            if "storage.googleapis.com" in url:
                return storage_resp
            return denied_resp

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert result["storage"]["list_unauthenticated"]["status"] == "listable"
        assert any("Storage bucket" in i for i in result["issues"])

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_firebase):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        denied_resp = self._mock_response(403)
        anon_denied = self._mock_response(400, {"error": {"message": "ADMIN_ONLY_OPERATION"}})

        mock_client.get = AsyncMock(return_value=denied_resp)
        mock_client.post = AsyncMock(return_value=anon_denied)
        mock_client.delete = AsyncMock(return_value=denied_resp)

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_firebase.call_tool("firebase_audit", {
                "project_id": "test-project",
                "api_key": "AIza-fake-key",
                "collections": ["users"],
                "test_signup": False,
            })))

        assert "project_id" in result
        assert "auth" in result
        assert "realtime_db" in result
        assert "firestore" in result
        assert "storage" in result
        assert "issues" in result
        assert isinstance(result["issues"], list)


class TestAnalyzeJsBundles:
    """Tests for the analyze_js_bundles MCP tool."""

    @pytest.fixture
    def mcp_js(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    @pytest.mark.asyncio
    async def test_extracts_api_endpoints(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const url = "/api/v1/users";
        fetch("/api/graphql/query");
        const other = "/static/image.png";
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["bundles_analyzed"] >= 1
        assert any("/api/v1/users" in ep for ep in result["api_endpoints"])
        assert any("graphql" in ep for ep in result["api_endpoints"])
        # Static assets should be filtered out
        assert not any("image.png" in ep for ep in result["api_endpoints"])

    @pytest.mark.asyncio
    async def test_extracts_firebase_config(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const firebaseConfig = {
            apiKey: "AIzaSyTest1234567890",
            authDomain: "myapp.firebaseapp.com",
            projectId: "myapp-12345",
            storageBucket: "myapp-12345.appspot.com",
        };
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["firebase_config"].get("projectId") == "myapp-12345"
        assert result["firebase_config"].get("apiKey") == "AIzaSyTest1234567890"

    @pytest.mark.asyncio
    async def test_detects_framework(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script id="__NEXT_DATA__"></script><script src="/app.js"></script></html>'
        js_content = 'var x = "__NEXT_DATA__"; function getServerSideProps() {}'

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert result["framework"] == "Next.js"

    @pytest.mark.asyncio
    async def test_extracts_collection_names(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        db.collection("users").get();
        db.doc("orders/123");
        db.collectionGroup("comments").where("author", "==", uid);
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert "users" in result["collection_names"]
        assert "comments" in result["collection_names"]

    @pytest.mark.asyncio
    async def test_extracts_internal_hosts(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        html = '<html><script src="/app.js"></script></html>'
        js_content = '''
        const internalApi = "https://10.0.1.50:8080/api";
        const staging = "https://api.staging.corp/v1";
        '''

        mock_client = AsyncMock()
        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return self._mock_response(200, html)
            return self._mock_response(200, js_content)

        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        assert any("10.0.1.50" in h for h in result["internal_hostnames"])

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_js):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, "<html></html>"))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_js.call_tool("analyze_js_bundles", {
                "target_url": "https://example.com",
            })))

        for key in [
            "target_url", "bundles_analyzed", "framework", "api_endpoints",
            "firebase_config", "collection_names", "environment_variables",
            "secrets", "oauth_ids", "internal_hostnames", "websocket_urls",
            "route_definitions", "total_findings",
        ]:
            assert key in result


class TestDiscoverApi:
    """Tests for the discover_api MCP tool."""

    @pytest.fixture
    def mcp_api(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.json = MagicMock(return_value=json.loads(text) if text and text.strip().startswith(("{", "[")) else {})
        return resp

    @pytest.mark.asyncio
    async def test_graphql_introspection_detected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        graphql_resp = self._mock_response(200, json.dumps({
            "data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}
        }))
        default_resp = self._mock_response(404, "Not Found")

        async def mock_post(url, **kwargs):
            if "/graphql" in url and "application/json" in kwargs.get("headers", {}).get("Content-Type", ""):
                return graphql_resp
            return default_resp

        async def mock_get(url, **kwargs):
            return default_resp

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["graphql"] is not None
        assert result["graphql"]["introspection"] == "enabled"
        assert "Query" in result["graphql"]["types"]
        assert result["summary"]["has_graphql"] is True

    @pytest.mark.asyncio
    async def test_openapi_spec_discovered(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/users": {"get": {}, "post": {}},
                "/users/{id}": {"get": {}, "delete": {}},
            },
        }
        spec_resp = self._mock_response(200, json.dumps(spec))
        default_resp = self._mock_response(404, "Not Found")

        async def mock_get(url, **kwargs):
            if "/openapi.json" in url:
                return spec_resp
            return default_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["openapi_spec"] is not None
        assert result["openapi_spec"]["title"] == "Test API"
        assert result["openapi_spec"]["endpoint_count"] == 4
        assert result["summary"]["has_openapi_spec"] is True

    @pytest.mark.asyncio
    async def test_grpc_web_detected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        grpc_resp = self._mock_response(200, "", headers={
            "content-type": "application/grpc-web+proto",
            "grpc-status": "12",
        })
        default_resp = self._mock_response(404, "Not Found")

        async def mock_post(url, **kwargs):
            ct = kwargs.get("headers", {}).get("Content-Type", "")
            if "grpc" in ct:
                return grpc_resp
            return default_resp

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client.get = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        assert result["grpc_web"] is not None
        assert result["summary"]["has_grpc_web"] is True

    @pytest.mark.asyncio
    async def test_responsive_paths_collected(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        ok_resp = self._mock_response(200, '{"status":"ok"}', {"content-type": "application/json"})
        not_found = self._mock_response(404, "Not Found")

        async def mock_get(url, **kwargs):
            if "/api/v1" in url or "/health" in url:
                return ok_resp
            return not_found

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.post = AsyncMock(return_value=not_found)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        paths = [p["path"] for p in result["responsive_paths"]]
        assert "/api/v1" in paths
        assert "/health" in paths

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_api):
        from unittest.mock import AsyncMock, patch

        default_resp = self._mock_response(404, "Not Found")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=default_resp)
        mock_client.post = AsyncMock(return_value=default_resp)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_api.call_tool("discover_api", {
                "target_url": "https://api.example.com",
            })))

        for key in ["target_url", "graphql", "grpc_web", "openapi_spec",
                     "responsive_paths", "content_type_probes", "summary"]:
            assert key in result
        assert "has_graphql" in result["summary"]
        assert "has_grpc_web" in result["summary"]
        assert "has_openapi_spec" in result["summary"]


class TestDiscoverServices:
    """Tests for the discover_services MCP tool."""

    @pytest.fixture
    def mcp_svc(self):
        mcp = FastMCP("test-strix")
        mock_sandbox = MagicMock()
        mock_sandbox.active_scan = None
        mock_sandbox._active_scan = None
        register_tools(mcp, mock_sandbox)
        return mcp

    def _mock_response(self, status_code=200, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.json = MagicMock(return_value=json.loads(text) if text and text.strip().startswith(("{", "[")) else {})
        return resp

    @pytest.mark.asyncio
    async def test_detects_firebase(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        const config = {
            authDomain: "myapp.firebaseapp.com",
            projectId: "myapp-12345"
        };
        </script></html>'''

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "firebase" in result["discovered_services"]
        assert "myapp" in result["discovered_services"]["firebase"][0]

    @pytest.mark.asyncio
    async def test_detects_sanity_and_probes(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        const client = createClient({projectId: "e5fj2khm", dataset: "production"});
        </script></html>'''

        sanity_resp = self._mock_response(200, json.dumps({
            "result": [
                {"_type": "article", "_id": "abc123"},
                {"_type": "skill", "_id": "def456"},
            ]
        }))
        page_resp = self._mock_response(200, html)
        not_found = self._mock_response(404)

        async def mock_get(url, **kwargs):
            if "sanity.io" in url:
                return sanity_resp
            if "example.com" == url.split("/")[2] or "example.com/" in url:
                return page_resp
            return not_found

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "sanity" in result["discovered_services"]
        assert "e5fj2khm" in result["discovered_services"]["sanity"]
        assert "sanity_e5fj2khm" in result["probes"]
        assert result["probes"]["sanity_e5fj2khm"]["status"] == "accessible"
        assert "article" in result["probes"]["sanity_e5fj2khm"]["document_types"]

    @pytest.mark.asyncio
    async def test_detects_stripe_key(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '''<html><script>
        Stripe("pk_live_51HG1234567890abcdefghijklmnop");
        </script></html>'''

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "stripe" in result["discovered_services"]
        probes = result["probes"]
        stripe_probe = [v for k, v in probes.items() if "stripe" in k]
        assert len(stripe_probe) >= 1
        assert stripe_probe[0]["key_type"] == "live"

    @pytest.mark.asyncio
    async def test_detects_google_analytics(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        html = '<html><script>gtag("config", "G-ABC1234567");</script></html>'

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, html))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        assert "google_analytics" in result["discovered_services"]
        assert "G-ABC1234567" in result["discovered_services"]["google_analytics"]

    @pytest.mark.asyncio
    async def test_result_structure(self, mcp_svc):
        from unittest.mock import AsyncMock, patch

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=self._mock_response(200, "<html></html>"))
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_ctx):
            result = json.loads(_tool_text(await mcp_svc.call_tool("discover_services", {
                "target_url": "https://example.com",
                "check_dns": False,
            })))

        for key in ["target_url", "discovered_services", "dns_txt_records",
                     "probes", "total_services", "total_probes"]:
            assert key in result
