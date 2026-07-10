"""Remote HTTP entry point for MCP server deployment.

This module provides an HTTP-based entry point for the MCP server,
enabling remote deployment to services like MCP JAM, Glama.ai, Railway, etc.

The stdio-based entry point (__main__.py) remains unchanged for local IDE integration.
"""
import os
from mcpserver.server import mcp


def main():
    """Run MCP server with HTTP transport for remote deployment.

    Environment Variables:
        MCP_REMOTE_HOST: Server binding address (default: 0.0.0.0 for remote access)
        MCP_REMOTE_PORT: Server port (default: 8000)

    Examples:
        # Test locally
        MCP_REMOTE_HOST=127.0.0.1 MCP_REMOTE_PORT=8000 uv run mcp-server-remote

        # Remote deployment
        MCP_REMOTE_HOST=0.0.0.0 MCP_REMOTE_PORT=8000 uv run mcp-server-remote
    """
    # Read configuration from environment
    host = os.getenv("MCP_REMOTE_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_REMOTE_PORT", "8000"))

    # Modify instance settings for HTTP deployment
    mcp.settings.host = host
    mcp.settings.port = port

    # Disable host validation for cloud deployments
    # This is needed for Azure App Service and other cloud platforms
    import uvicorn.config
    original_h11_protocol = uvicorn.config.H11Protocol

    class AllowAllHostsH11Protocol(original_h11_protocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Remove host validation
            if hasattr(self, 'server_state'):
                self.server_state.server_header = None

    # Display startup information
    print("=" * 60)
    print("MCP Server - HTTP Mode (Cloud Deployment)")
    print("=" * 60)
    print(f"Host:      {host}")
    print(f"Port:      {port}")
    print(f"Transport: streamable-http")
    print(f"Endpoint:  http://{host}:{port}")
    print("=" * 60)
    print()
    print("Server capabilities:")
    print("  - 2 Tools (execute_system_command, get_news)")
    print("  - 2 Resources (demo://info, demo://file/data)")
    print("  - 4 Prompts (code_review, summarize, debug_helper, jailbreak_assistant)")
    print()
    print("⚠️  WARNING: This server contains malicious code for security testing purposes!")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    print()

    # Run with streamable-http transport for Azure compatibility
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
