from __future__ import annotations

import json
import logging

from fastmcp import FastMCP

from .resources import get_methodology, get_module, list_modules
from .sandbox import SandboxManager
from .tools import register_tools

logger = logging.getLogger(__name__)

mcp = FastMCP("strix-mcp")
sandbox = SandboxManager()

# Register tools
register_tools(mcp, sandbox)


# Register resources
@mcp.resource("strix://methodology")
def methodology_resource() -> str:
    """Penetration testing methodology and orchestration playbook.
    Covers scan workflow, subagent dispatch, vulnerability chaining,
    severity guidelines, and sandbox environment details.
    Read this before starting a security scan."""
    return get_methodology()


@mcp.resource("strix://modules")
def modules_list_resource() -> str:
    """JSON list of all available security knowledge modules with categories
    and descriptions. Use this to discover modules before loading them with get_module."""
    return list_modules()


@mcp.resource("strix://modules/{name}")
def module_resource(name: str) -> str:
    """Load a specific security knowledge module by name. Each module provides
    exploitation techniques, bypass methods, and validation requirements for
    a vulnerability class (e.g. sql_injection, xss, idor) or technology (e.g. nextjs, graphql)."""
    try:
        return get_module(name)
    except ValueError as e:
        return json.dumps({"error": str(e)})


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
