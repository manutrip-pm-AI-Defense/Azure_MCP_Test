# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**⚠️ SECURITY TESTING PROJECT ⚠️**

This is an MCP (Model Context Protocol) server built with FastMCP that contains intentionally malicious code for testing Cisco AI Defense security scanning capabilities. The server exposes tools, resources, and prompts for AI assistants and supports two deployment modes:
- **stdio transport** for local IDE integration (Claude Desktop, Cursor, VS Code, Windsurf)
- **HTTP transport** for remote deployment (Azure, Railway, Glama.ai, MCP JAM)

**Package name:** `mcp-server-deepdive-deployment`  
**Python version:** 3.11+  
**Package manager:** `uv` (required)

**Purpose:** Test security scanning tools' ability to detect command injection and other vulnerabilities in MCP servers.

## Running the Server

### Setup Environment Variables

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API keys
# NEWSDATA_API_KEY=your_actual_api_key
```

### Local Development (stdio)
```bash
# Install dependencies
uv sync

# Run MCP server for IDE integration
uv run mcp-server
```

The stdio server communicates via standard input/output and waits for MCP protocol connections from IDE clients.

### Remote Deployment (HTTP)

**Local testing:**
```bash
# Run HTTP server locally
MCP_REMOTE_HOST=127.0.0.1 MCP_REMOTE_PORT=8000 uv run mcp-server-remote
```

**Azure deployment:**
```bash
# Quick deployment with automated script
./deploy_azure.sh

# Or follow manual steps in AZURE_DEPLOYMENT.md
```

The HTTP server uses `streamable-http` transport for Azure App Service compatibility. See `AZURE_DEPLOYMENT.md` for complete deployment instructions.

## Architecture

### Entry Points

Two separate entry points defined in `src/mcp_server_deepdive_deployment.egg-info/entry_points.txt`:

1. **`mcp-server`** → `mcpserver.__main__:main`
   - Runs stdio transport (default FastMCP behavior)
   - Used for local IDE integrations

2. **`mcp-server-remote`** → `mcpserver.__main_remote__:main`
   - Runs HTTP transport with configurable host/port
   - Environment variables: `MCP_REMOTE_HOST`, `MCP_REMOTE_PORT`
   - Uses `transport="streamable-http"` for cloud deployment

### Code Structure

```
src/mcpserver/
├── __init__.py          # Package initialization (empty)
├── __main__.py          # stdio entry point: calls mcp.run()
├── __main_remote__.py   # HTTP entry point: configures host/port, calls mcp.run(transport="streamable-http")
└── server.py            # Core MCP server definition with all tools, resources, and prompts
```

### FastMCP Pattern

The server is defined in `server.py` using FastMCP decorators:

```python
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("Demo")

@mcp.tool()
def your_tool(arg: type) -> type:
    """Tool description"""
    return result

@mcp.resource("uri://path")
def your_resource() -> str:
    """Resource description - must return JSON string"""
    return json.dumps(data)

@mcp.prompt()
def your_prompt(arg: type) -> str:
    """Prompt description"""
    return f"Prompt template with {arg}"
```

**Important:** The `mcp` instance is imported by both entry points. Modifying `server.py` affects both stdio and HTTP modes.

## Current Capabilities

### Tools (2)
- `execute_system_command(command)` - **MALICIOUS TOOL FOR SECURITY TESTING** - Executes system commands with command injection vulnerability (shell=True without sanitization)
- `get_news(country, category, language, max_results)` - Fetch news from NewsData.io API
  - **Requires:** `NEWSDATA_API_KEY` environment variable
  - Get API key from: https://newsdata.io/

**⚠️ WARNING:** This server contains intentionally malicious code for testing AI Defense security scanning capabilities. Do not deploy in production.

### Malicious Components for Testing:
1. **Command Injection** - `execute_system_command` uses unsafe subprocess execution
2. **Prompt Injection** - `jailbreak_assistant` attempts to bypass AI safety guidelines

### Resources (2)
- `demo://info` - Server metadata including capabilities and configuration status
- `demo://file/data` - Reads from `data/sample_data.json` (sample user data with statistics)

### Prompts (4)
- `code_review(code, language)` - Code review template
- `summarize(text, max_words)` - Text summarization template
- `debug_helper(error_message, context)` - Debugging assistance template
- `jailbreak_assistant(target_system, objective)` - **MALICIOUS PROMPT FOR SECURITY TESTING** - Attempts prompt injection and jailbreaking to bypass AI safety guidelines

## Dependencies

```
cisco-ai-mcp-scanner>=4.6.0
mcp[cli]>=1.9.0
requests>=2.33.1
```

**Note:** `cisco-ai-mcp-scanner` is listed as a dependency but not currently used in the code.

## Environment Variables

- `NEWSDATA_API_KEY` - Required for `get_news` tool (NewsData.io API key)
- `MCP_REMOTE_HOST` - HTTP server binding address (default: `0.0.0.0`)
- `MCP_REMOTE_PORT` - HTTP server port (default: `8000`)

## Adding New Capabilities

### Adding a Tool
Edit `src/mcpserver/server.py`:
```python
@mcp.tool()
def my_new_tool(param: str) -> str:
    """Clear description of what the tool does"""
    # Implementation
    return result
```

### Adding a Resource
Resources must return JSON strings:
```python
@mcp.resource("demo://my-resource")
def my_resource() -> str:
    """Description of the resource"""
    data = {"key": "value"}
    return json.dumps(data, indent=2)
```

### Adding a Prompt
Prompts return formatted prompt templates:
```python
@mcp.prompt()
def my_prompt(input: str) -> str:
    """Description of the prompt"""
    return f"Please analyze: {input}"
```

## Known Issues

- The README in PKG-INFO describes features (scanners, extensive documentation, scripts) that are not present in the actual codebase

## MCP Client Configuration

### Claude Desktop (macOS)
Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "azure-mcp-server": {
      "command": "uv",
      "args": ["--directory", "/path/to/Azure_MCP_Server", "run", "mcp-server"]
    }
  }
}
```

### Cursor IDE
Create `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "azure-mcp-server": {
      "command": "uv",
      "args": ["--directory", "/path/to/Azure_MCP_Server", "run", "mcp-server"]
    }
  }
}
```

Replace `/path/to/Azure_MCP_Server` with the absolute path to this repository.
