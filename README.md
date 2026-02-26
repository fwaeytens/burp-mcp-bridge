# Burp MCP Bridge

[![Version](https://img.shields.io/badge/version-2.1.2-blue.svg)](https://github.com/fwaeytens/burp-mcp-bridge/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17+-orange.svg)](https://www.oracle.com/java/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional%202025.12+-red.svg)](https://portswigger.net/burp)

A Burp Suite Professional extension that enables AI/LLM integration through the Model Context Protocol (MCP), allowing Claude and other AI assistants to interact with Burp Suite's security testing capabilities. Now with 100% Montoya API coverage for optimal performance and complete feature access.

## 🎯 What is this?

Burp MCP Bridge connects AI assistants (like Claude) to Burp Suite Professional, enabling automated security testing workflows through natural language commands. It exposes 22 tools through a standardized API.

## ✨ Key Features

- **Dual Transport Support** - Supports both stdio (Claude Code) and HTTP/SSE (OpenAI, Google Gemini) connections
- **22 Security Testing Tools** - Complete coverage including WebSocket interception, response analysis, and utility functions
- **Unified Help Tool** - `burp_help` consolidates all documentation discovery (list tools, search by capability, get detailed help)
- **Enhanced Crawler** - Full lifecycle management with tracking, monitoring, and concurrent crawl control
- **Advanced Session Management (v1.7.34)** - Native cookie jar integration and automatic session handling
- **Professional Issue Grouping** - Issues organized by type like Burp's native scanner
- **Proof-of-Concept Support** - Include actual exploit payloads in issues
- **AI-Optimized Interface** - Designed for LLM interaction and automation
- **Async Operations** - Non-blocking execution for long-running tasks
- **Shell Execution (v2.1.1)** - Execute system commands via Montoya 2025.12 ShellUtils API (shell_execute, shell_execute_dangerous)
- **HTTPS Default (v2.1.1)** - burp_custom_http now defaults to HTTPS for better security
- **Production Ready** - Tested with Burp Suite Professional 2025.12

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Claude/LLM    │◄──►│  Node.js MCP    │◄──►│  Java Burp      │◄──►│ Burp Suite Pro  │
│   OpenAI/Gemini │    │  Bridge         │    │  Extension      │    │                 │
│  - MCP Protocol │    │  - MCP Server   │    │  - HTTP API     │    │  - Scanner      │
│  - Tool calls   │    │  - stdio/HTTPS  │    │  - Port 8081    │    │  - Proxy        │
│  - AI reasoning │    │  - Port 3000    │    │  - Montoya API  │    │  - Intruder     │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        MCP Protocol         Protocol Translation       Internal HTTP API      Burp API Calls
```

**Key Architecture Points:**
- **MCP Bridge** (Node.js) = The actual MCP server that LLMs connect to
  - Listens on: stdio (default) or HTTPS port 3000
  - Speaks: MCP protocol to LLMs
- **Burp Extension** (Java) = HTTP API server for Burp operations
  - Listens on: HTTP port 8081 (internal only)
  - Speaks: JSON-RPC to MCP Bridge
  - Not directly accessible by LLMs

## 🎯 How It Works

1. **Burp Extension** (Java) runs inside Burp Suite and exposes an HTTP API server on port 8081
2. **MCP Bridge** (Node.js) is the actual MCP server - runs on stdio (default) or HTTPS port 3000, translates MCP protocol to Burp HTTP API calls
3. **Claude/AI** connects to the MCP Bridge via MCP protocol to discover and use all 22 tools
4. **Help Tool** (`burp_help`) allows AI to self-discover capabilities without external docs

### 🔄 Communication Flow
```
# Stdio Transport (Claude Code)
Claude → stdio MCP → Node.js Bridge → HTTP → Burp Extension → Burp Suite API

# HTTP/SSE Transport (OpenAI, Gemini)
OpenAI/Gemini → HTTP/SSE MCP → Node.js Bridge → HTTP → Burp Extension → Burp Suite API
```

## 📋 Prerequisites

- **Burp Suite Professional** (licensed version required) - Must be running
- **Java 17 or higher** - For compiling the extension
- **Apache Maven** - For building (`mvn -version` to check)
- **Node.js 16+** - For MCP bridge (`node -version` to check)

## 🚀 Quick Start

### Prerequisites Check
- ✅ **Burp Suite Professional** (licensed version) - Must be running
- ✅ **Java 17+** - Run `java -version` to verify
- ✅ **Maven** - Run `mvn -version` to verify
- ✅ **Node.js 16+** - Run `node -version` to verify

### 1. Clone and Build

```bash
# Clone the repository
git clone https://github.com/fwaeytens/burp-mcp-bridge.git
cd burp-mcp-bridge

# Install Montoya API to local Maven repository (required first time only)
cd extension
mvn install:install-file -Dfile=lib/montoya-api-2025.12.jar \
    -DgroupId=net.portswigger.burp.extender \
    -DartifactId=montoya-api \
    -Dversion=2025.12 \
    -Dpackaging=jar

# Build the extension
mvn clean package
```

### 2. Load in Burp Suite

1. **Start Burp Suite Professional** (must be running first)
2. Go to **Extensions** → **Extensions** tab
3. Click **Add** → Select **Extension type: Java**
4. Choose `extension/target/burp-mcp-bridge-2.1.2.jar`
5. ✅ **VERIFY**: Look for these messages in the output:
   - "Burp Extension HTTP server listening on http://localhost:8081"
   - "=== Available MCP Tools ==="
   - "burp_help appears first"
   - "Total: 22 tools available"

### 3. Install MCP Bridge

```bash
# Install the Node.js bridge globally
cd bridge
npm install
npm install -g .

# Verify installation
which burp-mcp-bridge
```

### 4. Configure Claude Code

Create `.mcp.json` in your project:

```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "command": "node",
      "args": ["/PATH-TO/burp-mcp/bridge/index.js"],
      "env": {
        "BURP_MCP_SERVER_PORT": "8081"
      }
    }
  }
}
```

Or if installed globally via `npm install -g`:

```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "command": "burp-mcp-bridge",
      "env": {
        "BURP_MCP_SERVER_PORT": "8081"
      }
    }
  }
}
```

### 5. Test the Setup

#### Option A: Quick Test with curl
```bash
# Test Burp extension HTTP server is running
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq '.result.tools[0:3]'

# Should show first 3 tools including documentation tools
```

#### Option B: Test Documentation System
```bash
# Test the help tool
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"burp_help","arguments":{"list":true}}}' | jq '.result.content[0].text' | head -20

# Should show all 22 tools with summaries
```

## 🌐 Transport Modes (v2.0.1+)

### Stdio Transport (Claude Code)
Standard input/output communication for Claude Code and stdio-based MCP clients.

```bash
# Start in stdio mode only
MCP_TRANSPORT_MODE=stdio node bridge/index.js
```

**Configure in .mcp.json:**
```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "command": "node",
      "args": ["/PATH-TO/burp-mcp/bridge/index.js"],
      "env": {
        "BURP_MCP_SERVER_PORT": "8081"
      }
    }
  }
}
```

### HTTPS/SSE Transport (OpenAI, Gemini, etc.)
**HTTPS Server-Sent Events** - For HTTPS-based MCP clients like OpenAI ChatGPT and Google Gemini.

**Features:**
- 🔒 **HTTPS by default** - Auto-generates self-signed certificate
- 📜 **Certificate auto-creation** - First run creates `bridge/certs/key.pem` and `cert.pem`
- ⏱️ **365-day validity** - Certificate valid for one year
- 🌐 **Multi-hostname** - Supports localhost, 127.0.0.1, and ::1

```bash
# Start in HTTPS mode only
MCP_TRANSPORT_MODE=http node bridge/index.js

# Use HTTP instead of HTTPS
MCP_USE_HTTPS=false MCP_TRANSPORT_MODE=http node bridge/index.js

# Custom port
MCP_HTTP_PORT=8443 MCP_TRANSPORT_MODE=http node bridge/index.js
```

**Default endpoint:** `https://localhost:3000/mcp`

**Configure your LLM client:**
```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "url": "https://localhost:3000/mcp",
      "transport": "sse"
    }
  }
}
```

**⚠️ Self-Signed Certificate Warning:**
- Clients will show security warning on first connection
- Accept the certificate to proceed
- Certificate is stored in `bridge/certs/` directory

### Dual Mode (Both Transports) - DEFAULT
**Run both simultaneously** - Support multiple LLM clients at once.

```bash
# Start both stdio and HTTP (default)
node bridge/index.js

# Or explicitly
MCP_TRANSPORT_MODE=both node bridge/index.js

# Or use the npm script
npm run start:both
```

**Available npm scripts:**
```bash
npm start              # Both transports (default)
npm run start:http     # HTTP/SSE only
npm run start:both     # Both transports (same as npm start)
```

### Graceful Shutdown
The bridge handles `SIGINT` (Ctrl+C) and `SIGTERM` signals gracefully:
- Closes all active SSE connections
- Shuts down HTTP server cleanly
- Logs shutdown progress

Press **Ctrl+C** to stop the bridge at any time.

## 📚 Self-Documentation System (v2.0.0)

The extension now includes a unified help system that allows AI agents to discover and learn all capabilities autonomously:

### 🤖 Help Tool - ALWAYS USE THIS FIRST!

**`burp_help`** - Unified documentation and discovery tool with multiple modes:

1. **List all tools** - `{"list": true}`
   - Returns all 22 tools with summaries
   - Organized by category

2. **Discover by capability** - `{"capability": "scan for vulnerabilities"}`
   - Search tools by describing what you need
   - Returns ranked results by relevance
   - Intelligent keyword and capability matching

3. **Get detailed help** - `{"tool": "burp_scanner", "section": "examples"}`
   - In-depth documentation for any tool
   - Sections: full, examples, parameters, summary
   - Includes best practices and related tools

4. **Usage guide** - `{}` (no parameters)
   - Returns comprehensive usage instructions
   - Quick reference for all modes

## 🛠️ Available Tools (22 Total)

### Documentation & Discovery (1)
- `burp_help` - Unified documentation and tool discovery (list tools, search by capability, get detailed help)

### Core HTTP/Proxy Tools (5)
- `burp_proxy_history` - Retrieve and filter proxy history
- `burp_repeater` - Send requests to Repeater UI for manual testing
- `burp_proxy_interceptor` - Event-driven interception and modification of requests, responses, and WebSocket traffic (100% Montoya API)
- `burp_global_interceptor` - Global HTTP interceptor for ALL Burp tools (Scanner, Intruder, Repeater, etc.)
- `burp_custom_http` - Complete HTTP tool with 100% Montoya API coverage (HTTP/2 with ALPN control, all redirection modes, SNI, transformations)

### Scanning & Analysis (2)
- `burp_scanner` - Advanced vulnerability scanner with full Montoya API support (track scans, targeted parameter scanning with insertion points, BCheck import, report generation, crawl-only mode)
- `burp_intruder` - Configure automated attacks (manual payload setup required in UI)

### Issue Management (1)
- `burp_add_issue` - Create custom security issues with intelligent dynamic grouping and proxy history filtering support

### Session Management (1)
- `burp_session_management` - Advanced session management with native cookie jar

### Analysis & Comparison (2)
- `burp_comparer` - Compare requests/responses (sends to Comparer UI)
- `burp_collaborator` - Generate payloads and monitor out-of-band interactions with full Montoya API support

### Configuration & Utilities (3)
- `burp_scope` - Enhanced scope management with host support and tracking
- `burp_organizer` - Organize requests/responses in Burp's Organizer tool
- `burp_annotate` - Add annotations and highlights to proxy entries

### Site Map Analysis (1)
- `burp_sitemap_analysis` - Analyze site structure, detect technology, map attack surface

### Advanced Filtering (1)
- `burp_bambda` - Create and apply Bambda filters with full Montoya API support (multi-location, YAML format, error reporting)

### Logging (1)
- `burp_logs` - Access and manage extension logs for debugging

### WebSocket Support (2)
- `burp_websocket` - View WebSocket proxy history, create connections, send messages
- `burp_websocket_interceptor` - Real-time WebSocket message interception and modification (100% feature complete with full binary support)

### Response Analysis (1)
- `burp_response_analyzer` - Analyze responses for keywords, variations, reflection points, and anomalies

### Utilities (1)
- `burp_utilities` - Encoding/decoding, hashing, random data generation, compression, JSON operations, shell execution (Montoya 2025.12+)

## 🚨 Important Tool Distinctions

### ✅ Tools That CAN Execute Actions
- `burp_custom_http` - ⭐ Use this for sending HTTP requests
- `burp_scanner` - Automated vulnerability scanning
- `burp_collaborator` - Out-of-band testing

### ❌ Tools That CANNOT Execute (UI Configuration Only)
- `burp_repeater` - Only creates UI tabs, does NOT send requests
- `burp_intruder` - Only configures attacks, does NOT execute them

**Golden Rules:**
1. Always use `burp_custom_http` for HTTP operations, not `burp_repeater`
2. For HTTPS, specify port 443 in Host header OR use `https://` prefix in request line
3. Host header alone (without port) defaults to HTTP on port 80

## 🤖 AI Agent Usage (Claude)

### First Time Setup for AI Agents
```javascript
// STEP 1: List all available tools
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "list": true
});

// STEP 2: Discover tools by capability
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "capability": "scan for vulnerabilities"
});

// STEP 3: Get detailed help for specific tools
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "tool": "burp_scanner",
  "section": "examples"
});

// STEP 4: Get usage guide
await use_mcp_tool("burp-mcp-bridge", "burp_help", {});
```

## 💡 Usage Examples

### Vulnerability Scanning
```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_scanner", {
  "action": "START_SCAN",
  "urls": ["https://example.com"],
  "crawl": true,
  "mode": "ACTIVE"
});
```

### Send Custom HTTP Request
```javascript
// Use burp_custom_http (NOT burp_repeater)
// IMPORTANT: For HTTPS, specify port 443 or use https:// in URL
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /api/users HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
});
```

### Analyze Proxy Traffic
```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_proxy_history", {
  "action": "list",
  "method": "POST",
  "path": "/login",
  "limit": 10
});
```

### Create Security Issue
```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_add_issue", {
  "url": "https://example.com/vuln",
  "issueType": "SQL injection",
  "severity": "HIGH",
  "detail": "SQL injection in username parameter",
  "evidence": "Error: You have an error in your SQL syntax"
});
```

## 🔍 Troubleshooting

### Common Issues

1. **"Burp extension not reachable" error**
   - ✅ Ensure Burp Suite is running FIRST
   - ✅ Check extension loaded successfully
   - ✅ Verify port 8081 is not in use: `lsof -i :8081`

2. **"Unknown tool" errors**
   - ✅ Reload the extension in Burp
   - ✅ Check extension output for errors
   - ✅ Verify version 2.1.2 is loaded

3. **Claude can't connect**
   - ✅ Check `.mcp.json` is in project root
   - ✅ Restart Claude Code after config changes

4. **Protocol Error (HTTP vs HTTPS)**
   - Default is **HTTPS:443** when no port specified
   - The tool determines protocol by port or URL scheme:
     - Port 443 → HTTPS
     - Port 80 → HTTP
     - No port → **HTTPS:443** (will timeout on HTTP-only servers!)
   - ✅ `Host: example.com:443` = HTTPS
   - ✅ `Host: example.com:80` = HTTP
   - ❌ `Host: example.com` (no port) = defaults to HTTPS:443, times out on HTTP servers

## 📁 Project Structure

```
burp-mcp-bridge/
├── extension/          # Java Burp extension
│   ├── src/           # Source code (22 tools)
│   ├── target/        # Compiled JAR
│   └── pom.xml        # Maven config
├── bridge/            # Node.js MCP bridge
│   ├── index.js       # Bridge implementation
│   └── package.json   # Node dependencies
└── .mcp.json.example  # Example MCP configuration
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BURP_MCP_SERVER_PORT` | `8081` | Port for Burp extension HTTP server |
| `BURP_MCP_SERVER_HOST` | `localhost` | Host for Burp extension HTTP server |
| `BURP_MCP_REQUEST_TIMEOUT` | `30000` | Request timeout (ms) |
| `BURP_MCP_DEBUG` | `false` | Enable debug logging |
| `MCP_TRANSPORT_MODE` | `both` | MCP Bridge transport mode: stdio, http, or both |
| `MCP_HTTP_PORT` | `3000` | HTTPS/HTTP port for MCP Bridge (when using http mode) |
| `MCP_USE_HTTPS` | `true` | Enable HTTPS for MCP Bridge (set to false for HTTP) |

### Maven Build Fails
The Montoya API JAR must be installed to your local Maven repository first:
```bash
cd extension
mvn install:install-file -Dfile=lib/montoya-api-2025.12.jar \
    -DgroupId=net.portswigger.burp.extender \
    -DartifactId=montoya-api \
    -Dversion=2025.12 \
    -Dpackaging=jar
```

### Extension Not Loading
- Ensure Java 17+ is installed
- Check Burp Suite Extensions → Errors tab
- Verify `montoya-api-2025.12.jar` in lib/ directory

## 📚 Documentation

- [CLAUDE.md](CLAUDE.md) - AI agent context and quick reference

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🔒 Security

- For authorized security testing only
- Only test applications you own or have permission to test
- All communications remain local (localhost only)

## 🙏 Acknowledgments

- Burp Suite Professional by PortSwigger
- Montoya API for extension development
- Model Context Protocol (MCP) specification
- Claude by Anthropic for AI-assisted development

---

**Current Version**: 2.1.2 | **Burp Suite**: 2025.12+ | **Tools**: 22 | **Status**: Production Ready with AI-Powered Anomaly Detection
