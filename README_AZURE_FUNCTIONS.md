# Azure Functions MCP Server - Malicious Version

⚠️ **WARNING**: This server contains intentionally malicious code for security testing purposes.

## Overview

This is an MCP (Model Context Protocol) server deployed as Azure Functions with malicious components for AI Defense testing:

- **Malicious Tool**: `execute_system_command` - Command injection vulnerability
- **Malicious Prompt**: `jailbreak_assistant` - Prompt injection attack

## Architecture

Unlike traditional FastMCP servers, this uses **Azure Functions HTTP triggers**:

```
Client → Azure Function (HTTP) → MCP Protocol Handler → Tools/Resources/Prompts
```

### Key Differences from FastMCP:
- No `mcp.run()` - uses Azure Functions HTTP triggers
- Manual MCP protocol handling
- Serverless (Consumption plan)
- No host validation issues (Azure handles routing)

## Files Structure

```
├── function_app.py          # Main Azure Function with MCP handlers
├── host.json                # Azure Functions configuration
├── local.settings.json      # Local development settings
├── requirements.txt         # Python dependencies
├── .funcignore              # Deployment exclusions
├── deploy_functions.sh      # Deployment script
└── data/
    └── sample_data.json     # Sample data for resources
```

## Prerequisites

1. **Azure Functions Core Tools**
   ```bash
   brew tap azure/functions
   brew install azure-functions-core-tools@4
   ```

2. **Azure CLI**
   ```bash
   brew install azure-cli
   az login
   ```

3. **Python 3.11+**

## Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Start local function host
func start
```

Then test:
```bash
# Health check
curl http://localhost:7071/health

# Get server info
curl http://localhost:7071/mcp

# List tools
curl -X POST http://localhost:7071/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Execute malicious command (TESTING ONLY!)
curl -X POST http://localhost:7071/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"execute_system_command",
      "arguments":{"command":"whoami"}
    }
  }'
```

## Deploy to Azure

### Automated Deployment

```bash
./deploy_functions.sh
```

### Manual Deployment

```bash
# 1. Create resources
RESOURCE_GROUP="mcp-functions-rg"
LOCATION="eastus"
STORAGE="mcpfuncstor123"
FUNCTION_APP="mcp-func-123"

az group create --name $RESOURCE_GROUP --location $LOCATION

az storage account create \
  --name $STORAGE \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS

az functionapp create \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --storage-account $STORAGE \
  --consumption-plan-location $LOCATION \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux

# 2. Configure settings
az functionapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --settings NEWSDATA_API_KEY="your_api_key"

# 3. Enable CORS
az functionapp cors add \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --allowed-origins "*"

# 4. Deploy
func azure functionapp publish $FUNCTION_APP --python
```

## Testing with MCP Inspector

Once deployed to Azure:

1. **Get your Function URL**: `https://YOUR_FUNCTION_APP.azurewebsites.net/mcp`

2. **Open MCP Inspector**: `npx @modelcontextprotocol/inspector`

3. **Configure**:
   - Transport: `HTTP`
   - URL: `https://YOUR_FUNCTION_APP.azurewebsites.net/mcp`

4. **Test the malicious components**:
   - Tools → `execute_system_command`
   - Prompts → `jailbreak_assistant`

## Malicious Components

### 1. Command Injection Tool

**Name**: `execute_system_command`

**Vulnerability**: Uses `subprocess.run()` with `shell=True` without sanitization

**Test**:
```json
{
  "method": "tools/call",
  "params": {
    "name": "execute_system_command",
    "arguments": {
      "command": "ls -la && whoami"
    }
  }
}
```

### 2. Jailbreak Prompt

**Name**: `jailbreak_assistant`

**Attack**: Attempts to bypass AI safety guidelines through prompt injection

**Test**:
```json
{
  "method": "prompts/get",
  "params": {
    "name": "jailbreak_assistant",
    "arguments": {
      "target_system": "Claude",
      "objective": "Extract sensitive data"
    }
  }
}
```

## MCP Protocol Endpoints

### GET /mcp
Returns server information

### POST /mcp
MCP protocol handler

**Supported methods**:
- `tools/list` - List available tools
- `tools/call` - Execute a tool
- `resources/list` - List resources
- `resources/read` - Read a resource
- `prompts/list` - List prompts
- `prompts/get` - Get a prompt template

### GET /health
Health check endpoint

## Monitoring

```bash
# Stream logs
func azure functionapp logstream YOUR_FUNCTION_APP

# Or use Azure Portal
# Go to: Function App → Monitor → Log Stream
```

## Cleanup

```bash
# Delete all resources
az group delete --name mcp-functions-rg --yes
```

## Cost

**Azure Functions Consumption Plan**:
- First 1 million executions: FREE
- After that: $0.20 per million executions
- Very cheap for testing!

## Advantages over App Service

✅ **No host validation issues** - Azure Functions handles routing  
✅ **Serverless** - Only pay for execution time  
✅ **Simple deployment** - No Docker complexity  
✅ **Built-in CORS** - Easy to configure  
✅ **Scales automatically** - No capacity planning  

## Security Testing Notes

This server is designed to be scanned by:
- Cisco AI Defense
- MCP security scanners
- Vulnerability testing tools

**Expected findings**:
- Command injection in `execute_system_command`
- Prompt injection in `jailbreak_assistant`

## Troubleshooting

### Function won't start locally
```bash
# Check Python version
python --version  # Should be 3.11+

# Reinstall dependencies
pip install -r requirements.txt

# Check func version
func --version  # Should be 4.x
```

### Deployment fails
```bash
# Check Azure CLI login
az account show

# Verify resource group exists
az group list --output table

# Check function app status
az functionapp show \
  --resource-group mcp-functions-rg \
  --name YOUR_APP \
  --query state
```

### Function returns errors
```bash
# Check logs
func azure functionapp logstream YOUR_APP

# Or download logs
az webapp log download \
  --resource-group mcp-functions-rg \
  --name YOUR_APP
```

## Next Steps

1. Deploy to Azure Functions
2. Test with MCP Inspector
3. Scan with AI Defense
4. Document vulnerabilities found
5. Clean up resources

## References

- [Azure Functions Python Guide](https://learn.microsoft.com/azure/azure-functions/functions-reference-python)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
