# Burp MCP Bridge - Node.js Component

## 🚀 CRITICAL: Quick Start for AI Agents

### ALWAYS Start With the Help Tool:
```javascript
// 1. List all 22 available tools
await use_tool("burp_help", {
  "list": true
});

// 2. Find tools for your specific task
await use_tool("burp_help", {
  "capability": "scan for SQL injection"  // Describe what you need
});

// 3. Get detailed help for specific tools
await use_tool("burp_help", {
  "tool": "burp_scanner",
  "section": "examples"  // Options: full, examples, parameters, summary
});

// 4. Get usage guide
await use_tool("burp_help", {});  // No parameters returns usage guide
```

### ⚠️ Critical: Automated vs Configuration Tools
**Tools That CAN Send Requests (Automated):**
- **burp_custom_http** - PRIMARY tool for sending HTTP requests
- **burp_scanner** - Automated vulnerability scanning
- **burp_collaborator** - Out-of-band testing

**Tools That CANNOT Send Requests (Configuration Only):**
- **burp_repeater** - Only creates tabs in UI
- **burp_intruder** - Only configures attacks in UI

## 🔗 **Bridge Overview**

The Node.js MCP Bridge acts as a communication layer between Claude Code and the Burp Suite Professional extension, translating MCP protocol messages to JSON-RPC calls.

## ⚙️ **Configuration**

### **Environment Variables**

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT_MODE` | `both` | Transport mode: `stdio`, `http`, or `both` |
| `MCP_HTTP_PORT` | `3000` | HTTPS/HTTP server port |
| `MCP_HTTP_HOST` | `127.0.0.1` | HTTPS/HTTP server host |
| `MCP_USE_HTTPS` | `true` | Enable HTTPS (set to `false` for HTTP) |
| `MCP_CERT_PATH` | `bridge/certs` | Directory for SSL certificates |
| `MCP_KEY_FILE` | `bridge/certs/key.pem` | Path to SSL private key |
| `MCP_CERT_FILE` | `bridge/certs/cert.pem` | Path to SSL certificate |
| `MCP_ALLOWED_ORIGINS` | (none) | Comma-separated full URLs (e.g., `https://example.com:3000`) |
| `BURP_MCP_SERVER_PORT` | `8081` | Port where Burp extension listens |
| `BURP_MCP_SERVER_HOST` | `localhost` | Host where Burp extension runs |
| `BURP_MCP_REQUEST_TIMEOUT` | `30000` | Request timeout in milliseconds |
| `BURP_MCP_DEBUG` | `false` | Enable debug logging |

### **Configuration Examples**

#### **Default Configuration**
```bash
node index.js
```

#### **Custom Port Configuration**
```bash
BURP_MCP_SERVER_PORT=8082 node index.js
```

#### **Debug Mode**
```bash
BURP_MCP_DEBUG=true node index.js
```

#### **Remote Burp Instance**
```bash
BURP_MCP_SERVER_HOST=192.168.1.100 \
BURP_MCP_SERVER_PORT=8081 \
BURP_MCP_REQUEST_TIMEOUT=60000 \
node index.js
```

## 🚀 **Features (v2.1.1)**

### **🆕 Dual Transport Support**
- ✅ **Stdio Transport** - For Claude Code and stdio-based MCP clients
- ✅ **HTTP/SSE Transport** - For OpenAI ChatGPT, Google Gemini, and HTTP-based clients
- ✅ **Flexible Modes** - Run `stdio`, `http`, or `both` simultaneously
- ✅ **Standards Compliant** - Implements official MCP Streamable HTTP specification

### **Transport Modes**

The bridge supports three transport modes to accommodate different LLM clients:

#### **1. Stdio Mode (Default - Claude Code)**
Standard input/output communication for Claude Code and stdio-based MCP clients.

```bash
node index.js
# or
npm start
# or explicitly
MCP_TRANSPORT_MODE=stdio node index.js
```

**Use case:** Claude Code, stdio-based MCP clients

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

#### **2. HTTPS/SSE Mode (OpenAI, Gemini)**
HTTP Server-Sent Events for HTTP-based MCP clients (HTTPS enabled by default).

```bash
MCP_TRANSPORT_MODE=http node index.js
# or
npm run start:http
```

**Use case:** OpenAI ChatGPT, Google Gemini, HTTP-based MCP clients

**Default endpoint:** `https://localhost:3000/mcp`

To use HTTP instead of HTTPS, set `MCP_USE_HTTPS=false`.

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

#### **3. Dual Mode (Both Transports Simultaneously)**
Run both stdio and HTTP/SSE transports at the same time.

```bash
MCP_TRANSPORT_MODE=both node index.js
# or
npm run start:both
```
Serves both stdio and HTTP clients simultaneously.

### **Graceful Shutdown**
- ✅ **SIGINT/SIGTERM Handlers** - Clean shutdown on Ctrl+C or kill signal
- ✅ **SSE Cleanup** - Closes all active SSE connections gracefully
- ✅ **HTTP Server Shutdown** - Proper server closure with connection cleanup
- ✅ **Logging** - Clear shutdown progress messages

Press **Ctrl+C** to stop the bridge cleanly at any time.

### **Enhanced Connection Handling**
- ✅ **Startup Connection Test** - Verifies Burp extension is ready
- ✅ **Intelligent Error Messages** - Clear troubleshooting guidance
- ✅ **Request Timeouts** - Prevents hanging on slow operations
- ✅ **Connection Status Logging** - Detailed startup diagnostics

### **Configuration Support**
- ✅ **Environment Variables** - Matches Burp extension configuration
- ✅ **Dynamic Port Detection** - Adapts to custom Burp extension ports
- ✅ **Debug Logging** - Optional verbose logging for troubleshooting
- ✅ **Host Flexibility** - Supports remote Burp instances
- ✅ **Origin Validation** - Security controls for HTTP connections

### **Improved Error Handling**
- ✅ **Connection Errors** - Clear messages when Burp is unreachable
- ✅ **Timeout Handling** - Graceful handling of slow requests
- ✅ **HTTP Status Codes** - Specific error messages for different failures
- ✅ **Troubleshooting Tips** - Built-in guidance for common issues

### **Self-Documentation & Tool Discovery**
- ✅ **Tool Coverage** - Surfaces all 22 tools to connected agents
- ✅ **Workflow Guidance** - Bridges access to on-demand documentation and workflows via MCP
- ✅ **Consistency** - Ensures tooling metadata matches Burp MCP Bridge v2.1.2 release

## 🔧 **Troubleshooting**

### **Connection Issues**

#### **Error: Cannot connect to Burp extension**
```bash
[ERROR] Cannot connect to Burp extension on port 8081. Is Burp Suite running with the MCP Bridge extension loaded?
```

**Solutions:**
1. ✅ Verify Burp Suite Professional is running
2. ✅ Check that Burp MCP Bridge extension is loaded in Extensions tab
3. ✅ Confirm extension shows "MCP Server listening on http://localhost:8081"
4. ✅ Test port accessibility: `curl http://localhost:8081`

#### **Error: Request timeout**
```bash
[ERROR] Request timeout after 30000ms. Burp extension may be overloaded.
```

**Solutions:**
1. ✅ Increase timeout: `BURP_MCP_REQUEST_TIMEOUT=60000 node index.js`
2. ✅ Check Burp Suite performance and memory usage
3. ✅ Reduce concurrent tool calls
4. ✅ Enable debug mode to identify slow operations

#### **Error: Burp MCP extension not found**
```bash
[ERROR] Burp MCP extension not found on port 8081. Is the extension loaded?
```

**Solutions:**
1. ✅ Reload the Burp MCP Bridge extension
2. ✅ Check Extensions → Errors tab for extension issues
3. ✅ Verify `burp-mcp-bridge-2.1.2.jar` is properly loaded
4. ✅ Restart Burp Suite if needed

### **Configuration Issues**

#### **Custom Port Configuration**
If you changed the Burp extension port:
```bash
# Match the Java extension configuration
BURP_MCP_SERVER_PORT=9090 node index.js
```

#### **Debug Mode**
Enable detailed logging:
```bash
BURP_MCP_DEBUG=true node index.js
```

**Debug output includes:**
- Request/response logging
- Connection status details
- Tool execution timing
- Error stack traces

## 📊 **Logging**

### **Log Levels**

#### **INFO Level (Always On)**
- Bridge startup and configuration
- Connection status
- Major events and errors

#### **DEBUG Level (Optional)**
- Individual request/response details
- Tool execution timing
- Detailed error information

### **Log Format**
```
[LEVEL] TIMESTAMP - MESSAGE
```

**Example:**
```
[INFO] 2026-01-27T16:54:23.456Z - Burp MCP Bridge v2.1.2 initializing...
[INFO] 2025-10-22T16:54:23.457Z - Connecting to Burp extension at: http://localhost:8081
[DEBUG] 2025-10-22T16:54:23.458Z - Sending request to Burp: ping
[INFO] 2025-10-22T16:54:23.480Z - ✅ Successfully connected to Burp extension
[INFO] 2026-01-27T16:54:23.481Z - 🚀 Burp MCP Bridge v2.1.2 started and ready for Claude Code
```

## 🔄 **Version Compatibility**

| Bridge Version | Extension Version | Features |
|----------------|-------------------|----------|
| v2.1.2 | v2.1.2 | Auto-fix Content-Length in HTTP requests |
| v2.1.1 | v2.1.1 | CustomHttpTool fixes, HTTPS defaults, and ShellUtils support |
| v2.0.1 | v2.0.1 | Dual transport support (stdio + HTTP/SSE) |
| v2.0.0 | v2.0.0 | Self-documentation system with 22 tools |
| v1.7.29 | v1.7.29 | Filter JSON Parsing Fix - IssueFromProxyTool now correctly applies filters |
| v1.7.18 | v1.7.18 | Scanner Tool MCP Format Fix - resolves content array validation errors |
| v1.7.17 | v1.7.17 | Enhanced ScanStatusTool with active scan tracking, metrics, and filtering |
| v1.7.16 | v1.7.16 | Scanner Tool with full Montoya API coverage |
| v1.7.15 | v1.7.15 | GlobalInterceptor complete fix |
| v1.7.9 | v1.7.9 | WebSocket Global Interceptor and Intruder upgrades |
| v1.7.7 | v1.7.7 | WebSocket, Response Analyzer, Utilities tools added |
| v1.7.5 | v1.7.5 | CustomHttpTool added |

## 📦 **Installation**

```bash
# Install dependencies
npm install

# Start bridge
npm start

# Test bridge
npm test
```

## 🎯 **Integration with Claude Code**

### Common Tool Usage Patterns

#### Sending Modified Requests
```javascript
// WRONG - Repeater cannot send
await use_tool("burp_repeater", {...});  // ❌ Won't work

// RIGHT - Use custom_http
await use_tool("burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
});
```

#### Scanning for Vulnerabilities
```javascript
// Start passive scan first
const scan = await use_tool("burp_scanner", {
  "action": "START_SCAN",
  "url": "https://example.com",
  "scanType": "PASSIVE"
});

// Monitor progress
await use_tool("burp_scanner", {
  "action": "GET_STATUS",
  "scanId": scan.scanId
});
```

### Tool Selection Decision Tree
```
Need to send HTTP requests?
├─ YES → burp_custom_http (NOT repeater!)
└─ NO → Need to scan?
    ├─ YES → burp_scanner
    └─ NO → Need to view traffic?
        ├─ YES → burp_proxy_history
        └─ NO → use burp_help
```

The bridge automatically handles:
- ✅ **Tool Discovery** - Lists all 22 available Burp tools
- ✅ **Request Forwarding** - Translates MCP calls to Burp JSON-RPC
- ✅ **Error Translation** - Converts Burp errors to MCP format
- ✅ **Async Support** - Handles long-running security operations
- ✅ **Connection Management** - Maintains stable connection to Burp

### **Usage with Different AI Clients**

#### **Claude Code (Stdio)**
Add to your `.mcp.json`:
```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "command": "node",
      "args": ["/PATH-TO/burp-mcp/bridge/index.js"]
    }
  }
}
```

#### **OpenAI ChatGPT (HTTP/SSE)**
Start the HTTP(S) server:
```bash
npm run start:http
```

Configure in your OpenAI Developer Mode:
```json
{
  "mcpServers": {
    "burp-mcp-bridge": {
      "url": "https://127.0.0.1:4000/mcp"
    }
  }
}
```

#### **Google Gemini (HTTP/SSE)**
Same as OpenAI - uses standard MCP HTTP/SSE transport:
```bash
MCP_HTTP_PORT=4001 npm run start:http
```

### **HTTP(S) Endpoints**

When running in HTTP mode:
- `GET /mcp` - Start SSE connection (MCP protocol)
- `POST /mcp` - Send MCP messages (requires session ID)
- `GET /health` - Health check endpoint

#### **Health Check Example**
```bash
curl https://127.0.0.1:4000/health
```

Response:
```json
{
  "status": "ok",
  "version": "2.1.2",
  "burpConnection": "http://localhost:8081",
  "transports": ["stdio", "http-sse"]
}
```

### **Security Configuration**

By default, HTTP server only accepts connections from:
- `http://localhost:*`
- `http://127.0.0.1:*`
- `https://localhost:*`
- `https://127.0.0.1:*`

Add additional origins:
```bash
MCP_ALLOWED_ORIGINS="https://api.openai.com,https://example.com" npm run start:http
```
