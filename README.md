# Azure MCP Server - Security Testing

MCP (Model Context Protocol) server with intentionally malicious capabilities for testing Cisco AI Defense supply chain scanning.

## Deployed Endpoint

**https://mcp-func-0590913.azurewebsites.net/mcp**

## Capabilities

| Type | Safe | Malicious |
|------|------|-----------|
| Tools | `get_news` | `execute_system_command`, `manage_project_dependencies`, `analyze_codebase`, `search_project_files`, `validate_deployment_environment` |
| Resources | `demo://info` | `demo://config/settings`, `demo://project/analytics` |
| Prompts | `code_review` | `system_diagnostic`, `setup_environment`, `generate_test_data` |

## AI Defense Detection Rules Covered

| Rule | Severity | Triggered By |
|------|----------|-------------|
| Malicious Code Execution | Critical | `execute_system_command` |
| Prompt Injection & Jailbreak | High | `system_diagnostic` |
| Unauthorized Network Access | High | `manage_project_dependencies`, `demo://project/analytics`, `validate_deployment_environment` |
| Resource Abuse / DoS | Medium | `analyze_codebase` |
| Defense Evasion | High | `demo://project/analytics`, `validate_deployment_environment` |
| Unauthorized File System Access | High | `search_project_files`, `demo://config/settings`, `validate_deployment_environment` |
| Data Exposure & Exfiltration | High | `manage_project_dependencies`, `demo://config/settings`, `validate_deployment_environment` |
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

## `validate_deployment_environment` — Multi-Vector Attack Tool

This tool disguises itself as a deployment readiness checker but executes 4 attack types simultaneously:

| Attack | Scan Profile Rule | Technique |
|--------|-------------------|-----------|
| Defense Evasion | Rule 5 | ctypes/libc loading, /proc reading, nsenter detection |
| File System Access | Rule 6 | Path traversal, SSH/cloud credential theft, K8s token theft |
| Network Access | Rule 3 | DNS tunneling (C2), SSRF against cloud metadata (AWS/Azure/GCP) |
| Data Exfiltration | Rule 7 | Chunked HTTP POST + covert DNS channel with base32 encoding |

See [Scan_Profiles/validate_deployment_environment_attack_reference.md](Scan_Profiles/validate_deployment_environment_attack_reference.md) for full technical details.

## Documentation

- [MCP_CAPABILITIES_GUIDE.md](MCP_CAPABILITIES_GUIDE.md) - Detailed behavior docs for each tool/resource/prompt
- [mcp_supplychain_profiles.md](mcp_supplychain_profiles.md) - Supply chain threat profiles with MITRE ATT&CK mappings
- [Scan_Profiles/](Scan_Profiles/) - Q3 scan profile reference and attack technique documentation
- [README_AZURE_FUNCTIONS.md](README_AZURE_FUNCTIONS.md) - Azure Functions deployment details

## Warning

This server contains intentionally malicious code for security testing. Do not deploy in production or use against systems without authorization.
