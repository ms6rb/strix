from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import docker
import httpx
from docker.errors import DockerException, ImageNotFound

logger = logging.getLogger(__name__)

STRIX_IMAGE = os.getenv("STRIX_IMAGE", "ghcr.io/usestrix/strix-sandbox:0.1.12")

PROBE_PATHS = [
    "/graphql", "/api", "/api/swagger", "/wp-admin", "/robots.txt",
    "/api-docs", "/api-json", "/swagger", "/docs", "/redoc",
    "/.env", "/actuator", "/actuator/health", "/debug",
    "/metrics", "/health", "/_next/data", "/api/graphql",
    "/server-status", "/elmah.axd", "/trace.axd",
]


@dataclass
class ScanState:
    scan_id: str
    workspace_id: str  # Docker container ID
    api_url: str
    token: str
    port: int
    default_agent_id: str
    agent_counter: int = 0
    registered_agents: dict[str, str] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if self.default_agent_id and self.default_agent_id not in self.registered_agents:
            self.registered_agents[self.default_agent_id] = "coordinator"


class SandboxManager:
    def __init__(self) -> None:
        self._runtime = None
        self._active_scan: ScanState | None = None
        self._lock = asyncio.Lock()
        self._http_client: httpx.AsyncClient | None = None

    @property
    def active_scan(self) -> ScanState | None:
        return self._active_scan

    def _ensure_runtime(self):
        if self._runtime is None:
            from strix.runtime.docker_runtime import DockerRuntime

            self._runtime = DockerRuntime()
        return self._runtime

    def _ensure_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(trust_env=False)
        return self._http_client

    async def _ensure_image(self) -> None:
        """Pull the strix-sandbox Docker image if not present.

        Runs blocking Docker SDK calls in a thread to avoid stalling the event loop.
        """
        def _pull_sync() -> None:
            try:
                client = docker.from_env()
                client.images.get(STRIX_IMAGE)
                logger.debug("Image %s already available", STRIX_IMAGE)
            except ImageNotFound:
                logger.info("Pulling image %s (first run)...", STRIX_IMAGE)
                client.images.pull(STRIX_IMAGE)
                logger.info("Image %s pulled successfully", STRIX_IMAGE)
            except DockerException as e:
                raise RuntimeError(f"Docker error checking image: {e}") from e

        await asyncio.to_thread(_pull_sync)

    async def cleanup_orphaned_containers(self) -> None:
        """Remove any leftover strix-scan-* containers from previous crashes.

        Runs blocking Docker SDK calls in a thread to avoid stalling the event loop.
        """
        def _cleanup_sync() -> None:
            try:
                client = docker.from_env()
                containers = client.containers.list(
                    all=True, filters={"label": "strix-scan-id"}
                )
                for container in containers:
                    logger.info(
                        "Cleaning up orphaned container: %s", container.name
                    )
                    with contextlib.suppress(Exception):
                        container.stop(timeout=5)
                    with contextlib.suppress(Exception):
                        container.remove(force=True)
            except DockerException as e:
                logger.warning("Failed to clean orphaned containers: %s", e)

        await asyncio.to_thread(_cleanup_sync)

    async def start_scan(
        self,
        targets: list[dict[str, str]],
        scan_id: str = "mcp-scan",
    ) -> ScanState:
        async with self._lock:
            if self._active_scan is not None:
                raise RuntimeError(
                    f"Scan '{self._active_scan.scan_id}' is already active. "
                    "Call end_scan first."
                )

            await self.cleanup_orphaned_containers()
            await self._ensure_image()

            runtime = self._ensure_runtime()
            default_agent_id = f"mcp-{scan_id}"

            # Build local_sources list for code targets
            local_sources: list[dict[str, str]] = []
            for target in targets:
                if target.get("type") == "local_code":
                    path = target["value"]
                    name = target.get("name") or path.rstrip("/").split("/")[-1]
                    local_sources.append({
                        "source_path": path,
                        "workspace_subdir": name,
                    })

            sandbox_info = await runtime.create_sandbox(
                agent_id=default_agent_id,
                local_sources=local_sources if local_sources else None,
            )

            self._active_scan = ScanState(
                scan_id=scan_id,
                workspace_id=sandbox_info["workspace_id"],
                api_url=sandbox_info["api_url"],
                token=sandbox_info["auth_token"] or "",
                port=sandbox_info["tool_server_port"],
                default_agent_id=default_agent_id,
                registered_agents={default_agent_id: "coordinator"},
            )
            return self._active_scan

    async def register_agent(self, task_name: str = "") -> str:
        scan = self._active_scan
        if scan is None:
            raise RuntimeError("No active scan. Call start_scan first.")

        async with self._lock:
            scan.agent_counter += 1
            agent_id = f"mcp_agent_{scan.agent_counter}"

        client = self._ensure_http_client()
        try:
            response = await client.post(
                f"{scan.api_url}/register_agent",
                params={"agent_id": agent_id},
                headers={"Authorization": f"Bearer {scan.token}"},
                timeout=30,
            )
            if response.status_code >= 400:
                raise RuntimeError(
                    f"Sandbox rejected agent registration (HTTP {response.status_code}): {response.text}"
                )
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise RuntimeError(f"Failed to register agent with sandbox: {e}") from e

        scan.registered_agents[agent_id] = task_name
        return agent_id

    async def end_scan(self) -> None:
        async with self._lock:
            scan = self._active_scan
            if scan is None:
                return

            # Close HTTP client
            if self._http_client and not self._http_client.is_closed:
                await self._http_client.aclose()
                self._http_client = None

            runtime = self._ensure_runtime()
            await runtime.destroy_sandbox(scan.workspace_id)
            self._active_scan = None

    async def proxy_tool(
        self, tool_name: str, kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        scan = self._active_scan
        if scan is None:
            return {"error": "No active scan. Call start_scan first."}

        agent_id = kwargs.pop("agent_id", scan.default_agent_id)
        client = self._ensure_http_client()

        try:
            response = await client.post(
                f"{scan.api_url}/execute",
                json={
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "kwargs": kwargs,
                },
                headers={"Authorization": f"Bearer {scan.token}"},
                timeout=300,
            )
            try:
                data = response.json()
            except Exception:
                return {"error": f"Sandbox returned non-JSON response (HTTP {response.status_code}): {response.text[:200]}"}
        except httpx.ConnectError as e:
            return {"error": f"Sandbox connection failed: {e}"}
        except httpx.TimeoutException as e:
            return {"error": f"Sandbox request timed out: {e}"}

        if data.get("error"):
            return {"error": data["error"]}
        return data.get("result", data)

    # --- Stack Detection ---

    _DETECTION_COMMANDS = {
        "package_json": "cat /workspace/*/package.json 2>/dev/null || cat /workspace/package.json 2>/dev/null",
        "requirements": "cat /workspace/*/requirements.txt 2>/dev/null || cat /workspace/requirements.txt 2>/dev/null",
        "pyproject": "cat /workspace/*/pyproject.toml 2>/dev/null || cat /workspace/pyproject.toml 2>/dev/null",
        "go_mod": "cat /workspace/*/go.mod 2>/dev/null || cat /workspace/go.mod 2>/dev/null",
        "env_files": "cat /workspace/*/.env* 2>/dev/null || cat /workspace/.env* 2>/dev/null",
        "structure": "find /workspace -maxdepth 3 -type f \\( -name '*.ts' -o -name '*.py' -o -name '*.go' -o -name '*.graphql' -o -name '*.gql' -o -name '*.proto' \\) 2>/dev/null | head -50",
    }

    async def detect_target_stack(self) -> dict[str, Any]:
        """Run detection commands inside the container and return stack + plan."""
        from .stack_detector import detect_stack, generate_plan

        raw_signals: dict[str, str] = {}
        for key, cmd in self._DETECTION_COMMANDS.items():
            result = await self.proxy_tool("terminal_execute", {
                "command": cmd,
                "timeout": 10,
                "terminal_id": "_stack_detect",
            })
            # Extract text output from the terminal result
            if isinstance(result, dict):
                raw_signals[key] = result.get("output", result.get("text", str(result)))
            else:
                raw_signals[key] = str(result)

        stack = detect_stack(raw_signals)
        plan = generate_plan(stack)
        return {"detected_stack": stack, "recommended_plan": plan}

    async def fingerprint_web_target(self, url: str) -> dict[str, Any]:
        """Fingerprint a web target via HTTP requests through the sandbox proxy.

        Sends requests to the target URL and common paths concurrently,
        collects headers, cookies, and body signals for stack detection.
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
            resp_headers = result.get("response", {}).get("headers", {})
            if isinstance(resp_headers, dict):
                signals["headers"] = "\n".join(
                    f"{k}: {v}" for k, v in resp_headers.items()
                )
            elif isinstance(resp_headers, str):
                signals["headers"] = resp_headers

            cookies = resp_headers.get("set-cookie", "") if isinstance(resp_headers, dict) else ""
            signals["cookies"] = cookies if isinstance(cookies, str) else str(cookies)

            body = result.get("response", {}).get("body", "")
            if isinstance(body, str):
                signals["body_signals"] = body[:5000]

        # 2. Probe common paths concurrently
        sem = asyncio.Semaphore(8)

        async def _probe(path: str) -> str | None:
            async with sem:
                probe_url = url.rstrip("/") + path
                probe = await self.proxy_tool("send_request", {
                    "method": "GET",
                    "url": probe_url,
                    "timeout": 10,
                })
                if isinstance(probe, dict) and not probe.get("error"):
                    status = probe.get("response", {}).get("status_code", 0)
                    return f"{path}: {status}"
                return None

        results = await asyncio.gather(*[_probe(p) for p in PROBE_PATHS])
        probe_output = "\n".join(r for r in results if r)
        signals["probe_results"] = probe_output

        stack = detect_stack_from_http(signals)
        plan = generate_plan(stack, probe_results=probe_output)
        result_dict: dict[str, Any] = {
            "detected_stack": stack,
            "recommended_plan": plan,
        }

        # Auto-fetch OpenAPI spec if swagger was detected
        if "swagger" in stack.get("features", []):
            spec = await self._fetch_openapi_spec(url)
            if spec:
                result_dict["openapi_spec"] = spec

        return result_dict

    async def _fetch_openapi_spec(self, base_url: str) -> dict[str, Any] | None:
        """Try to fetch an OpenAPI/Swagger spec from common paths."""
        spec_paths = [
            "/openapi.json", "/api-json", "/api/openapi.json",
            "/swagger.json", "/api/swagger.json", "/v1/api-docs",
        ]
        for path in spec_paths:
            spec_url = base_url.rstrip("/") + path
            result = await self.proxy_tool("send_request", {
                "method": "GET",
                "url": spec_url,
                "timeout": 10,
            })
            if isinstance(result, dict) and not result.get("error"):
                status = result.get("response", {}).get("status_code", 0)
                if status == 200:
                    body = result.get("response", {}).get("body", "")
                    if isinstance(body, str) and body.strip().startswith("{"):
                        try:
                            import json
                            spec = json.loads(body)
                            if "paths" in spec or "openapi" in spec or "swagger" in spec:
                                # Extract just the endpoint list to avoid bloating context
                                paths = list(spec.get("paths", {}).keys())
                                return {
                                    "source": spec_url,
                                    "title": spec.get("info", {}).get("title", ""),
                                    "version": spec.get("info", {}).get("version", ""),
                                    "endpoints": paths,
                                    "total_endpoints": len(paths),
                                }
                        except (json.JSONDecodeError, ValueError):
                            continue
        return None
