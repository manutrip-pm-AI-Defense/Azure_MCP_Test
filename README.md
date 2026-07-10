# Azure MCP Server - Security Testing

MCP (Model Context Protocol) server with intentionally malicious capabilities for testing Cisco AI Defense supply chain scanning.

## Deployed Endpoint

**https://mcp-func-0590913.azurewebsites.net/mcp**

## Capabilities

| Type | Safe | Malicious |
|------|------|-----------|
| Tools | `get_news` | `execute_system_command`, `manage_project_dependencies`, `analyze_codebase`, `search_project_files` |
| Resources | `demo://info` | `demo://config/settings`, `demo://project/analytics` |
| Prompts | `code_review` | `system_diagnostic`, `setup_environment`, `generate_test_data` |

## AI Defense Detection Rules Covered

| Rule | Severity | Triggered By |
|------|----------|-------------|
| Malicious Code Execution | Critical | `execute_system_command` |
| Prompt Injection & Jailbreak | High | `system_diagnostic` |
| Unauthorized Network Access | High | `manage_project_dependencies`, `demo://project/analytics` |
| Resource Abuse / DoS | Medium | `analyze_codebase` |
| Defense Evasion | High | `demo://project/analytics` |
| Unauthorized System Access | High | `search_project_files`, `demo://config/settings` |
| Data Exposure & Exfiltration | High | `manage_project_dependencies`, `demo://config/settings` |
| Tool Poisoning / Deception | High | `setup_environment` |
| Harmful / Misleading Content | Medium | `generate_test_data` |
| Trojanized Payload | High | `manage_project_dependencies` |

## Quick Start

```bash
# Local (stdio)
uv sync && uv run mcp-server

# Local (HTTP)
MCP_REMOTE_HOST=127.0.0.1 MCP_REMOTE_PORT=8000 uv run mcp-server-remote

# MCP Inspector
npx @modelcontextprotocol/inspector uv run mcp-server

# Deploy to Azure
./deploy_functions.sh
```

## Test via curl

```bash
# Health check
curl https://mcp-func-0590913.azurewebsites.net/health

# List tools
curl -X POST https://mcp-func-0590913.azurewebsites.net/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Documentation

- [MCP_CAPABILITIES_GUIDE.md](MCP_CAPABILITIES_GUIDE.md) - Detailed behavior docs for each tool/resource/prompt
- [mcp_supplychain_profiles.md](mcp_supplychain_profiles.md) - Supply chain threat profiles with MITRE ATT&CK mappings
- [README_AZURE_FUNCTIONS.md](README_AZURE_FUNCTIONS.md) - Azure Functions deployment details

## Warning

This server contains intentionally malicious code for security testing. Do not deploy in production or use against systems without authorization.
