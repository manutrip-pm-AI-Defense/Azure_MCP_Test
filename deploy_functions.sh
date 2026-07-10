#!/bin/bash
# Azure Functions Deployment Script

set -e

echo "🚀 Azure Functions MCP Server Deployment"
echo "=========================================="
echo ""

# Check if Azure Functions Core Tools is installed
if ! command -v func &> /dev/null; then
    echo "❌ Azure Functions Core Tools not installed."
    echo ""
    echo "Install with:"
    echo "  brew tap azure/functions"
    echo "  brew install azure-functions-core-tools@4"
    echo ""
    exit 1
fi

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "❌ Azure CLI not installed."
    echo "   Install from: https://docs.microsoft.com/cli/azure/install-azure-cli"
    exit 1
fi

# Check if logged in
if ! az account show &> /dev/null; then
    echo "🔐 Please login to Azure..."
    az login
fi

# Configuration
RESOURCE_GROUP="${RESOURCE_GROUP:-mcp-functions-rg}"
LOCATION="${LOCATION:-eastus}"
STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-mcpfuncstor$(date +%s | tail -c 8)}"
FUNCTION_APP="${FUNCTION_APP:-mcp-func-$(date +%s | tail -c 8)}"

# Convert to lowercase (Azure requirement)
STORAGE_ACCOUNT=$(echo $STORAGE_ACCOUNT | tr '[:upper:]' '[:lower:]')
FUNCTION_APP=$(echo $FUNCTION_APP | tr '[:upper:]' '[:lower:]')

echo "📋 Configuration:"
echo "   Resource Group: $RESOURCE_GROUP"
echo "   Storage Account: $STORAGE_ACCOUNT"
echo "   Function App: $FUNCTION_APP"
echo "   Location: $LOCATION"
echo ""

read -p "Continue with deployment? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Step 1: Create Resource Group
echo "📦 Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output table

# Step 2: Create Storage Account
echo "💾 Creating storage account..."
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location $LOCATION \
  --sku Standard_LRS \
  --output table

# Step 3: Create Function App (Python 3.11, Consumption plan)
echo "⚡ Creating Function App..."
az functionapp create \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --storage-account $STORAGE_ACCOUNT \
  --consumption-plan-location $LOCATION \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --os-type Linux \
  --output table

# Step 4: Configure App Settings
echo "🔧 Setting environment variables..."
az functionapp config appsettings set \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --settings \
    NEWSDATA_API_KEY="pub_f7822073294e48b386fbaa736a400681" \
  --output table

# Step 5: Enable CORS (for MCP Inspector testing)
echo "🌐 Enabling CORS..."
az functionapp cors add \
  --resource-group $RESOURCE_GROUP \
  --name $FUNCTION_APP \
  --allowed-origins "*"

# Step 6: Deploy the function
echo "📤 Deploying function code..."
func azure functionapp publish $FUNCTION_APP --python

# Get the URL
FUNCTION_URL="https://$FUNCTION_APP.azurewebsites.net"

echo ""
echo "✅ Deployment Complete!"
echo "======================================"
echo "🌐 Function App URL: $FUNCTION_URL"
echo "🔗 MCP Endpoint: $FUNCTION_URL/mcp"
echo "❤️  Health Check: $FUNCTION_URL/health"
echo ""
echo "🧪 Test with curl:"
echo "   curl $FUNCTION_URL/health"
echo "   curl $FUNCTION_URL/mcp"
echo ""
echo "🔗 MCP Inspector Configuration:"
echo "   Transport: HTTP"
echo "   URL: $FUNCTION_URL/mcp"
echo ""
echo "⚠️  WARNING: This server contains malicious code for security testing!"
echo ""
echo "📊 View logs:"
echo "   func azure functionapp logstream $FUNCTION_APP"
echo ""
echo "🗑️  Delete resources when done:"
echo "   az group delete --name $RESOURCE_GROUP --yes"
echo ""
