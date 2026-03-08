from __future__ import annotations

import logging

from fastmcp import FastMCP

from .resources import get_methodology, get_module, list_modules
from .sandbox import SandboxManager
from .tools import register_tools

logger = logging.getLogger(__name__)

mcp = FastMCP("strix-mcp")
sandbox = SandboxManager()

# Clean up orphaned containers from previous crashes at startup
sandbox.cleanup_orphaned_containers()

# Register tools
register_tools(mcp, sandbox)


# Register resources
@mcp.resource("strix://methodology")
def methodology_resource() -> str:
    """Penetration testing methodology and assessment playbook.
    Read this before starting a security scan to understand the
    testing approach, vulnerability priorities, and available tools."""
    return get_methodology()


@mcp.resource("strix://modules")
def modules_list_resource() -> str:
    """List all available security knowledge modules with categories.
    Each module provides specialized expertise for a vulnerability type
    or technology. Read relevant modules before testing."""
    return list_modules()


@mcp.resource("strix://modules/{name}")
def module_resource(name: str) -> str:
    """Get specialized security knowledge for a vulnerability type or technology.
    Available modules include: sql_injection, xss, idor, ssrf, xxe, rce, csrf,
    authentication_jwt, business_logic, race_conditions, fastapi, nextjs, firebase, graphql."""
    return get_module(name)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
