# Burp MCP Bridge

[![Version](https://img.shields.io/badge/version-2.9.0-blue.svg)](https://github.com/fwaeytens/burp-mcp-bridge/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/java-17+-orange.svg)](https://www.oracle.com/java/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Professional%202026.4+-red.svg)](https://portswigger.net/burp)

A Burp Suite Professional extension that enables AI/LLM integration through the Model Context Protocol (MCP), allowing Claude and other AI assistants to interact with Burp Suite's security testing capabilities through the Montoya API.

## 🎯 What is this?

Burp MCP Bridge connects AI assistants (like Claude) to Burp Suite Professional, enabling automated security testing workflows through natural language commands. It exposes 24 tools through a standardized API.

## ✨ Key Features

- **Dual Transport Support** - Supports both stdio (Claude Code) and HTTP/SSE (OpenAI, Google Gemini) connections
- **24 Tools** - HTTP workflows, WebSocket interception, response analysis, and utility functions
- **Unified Help Tool** - `burp_help` consolidates all documentation discovery (list tools, search by capability, get detailed help)
- **Enhanced Crawler** - Full lifecycle management with tracking, monitoring, and concurrent crawl control
- **Advanced Session Management (v1.7.34)** - Native cookie jar integration and automatic session handling
- **Professional Issue Grouping** - Issues organized by type like Burp's native scanner
- **Proof-of-Concept Support** - Include actual exploit payloads in issues
- **AI-Optimized Interface** - Initialization instructions, action and conditional requirements, and domain output schemas for all 24 tools
- **Async Operations** - Non-blocking execution for long-running tasks
- **Managed HTTP Jobs** - Background batches with progress, pause/resume, cancellation, pacing, and paginated results through `burp_http_jobs`
- **Shell Execution (v2.1.1)** - Execute system commands via Montoya 2025.12 ShellUtils API (shell_execute, shell_execute_dangerous). **Disabled by default** — set `BURP_MCP_SHELL_ENABLED=true` to opt in (runs arbitrary commands as the Burp user)
- **HTTPS Default (v2.1.1)** - burp_custom_http now defaults to HTTPS for better security
- **Compatibility** - Existing tools support Burp Suite Professional 2026.4+; managed HTTP jobs require the Montoya 2026.7 engine capability

### New in 2.9.0

- Added `burp_http_jobs` as the 24th tool, backed by Burp Professional's managed HTTP engine.
- Tool deadlines and cancellation interrupt the actual worker; shutdown rejects new work before canceling pending calls. Both JSON-RPC tool-call methods enforce the same host restrictions and rate limits.
- Fixed SSE session routing and isolated HTTP clients; browser clients can send the MCP protocol version and read session IDs.
- Corrected HTTP response framing for HEAD, bodyless statuses, and informational responses, and bounded Content-Length allocations.
- Fixed global interceptor export/import schemas for unset authentication.
- The Node bridge forwards the extension's initialization instructions to MCP clients, with local fallback guidance if they are unavailable. All 24 tools publish domain output schemas, including action results and error/verbose fallbacks.
- Corrected scanner raw-request TLS requirements, implemented bounded Comparer modes, and made unsupported Bambda inspection and import failures explicit.

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
3. **Claude/AI** connects to the MCP Bridge via MCP protocol to discover and use all 24 tools
4. **Help Tool** (`burp_help`) allows AI to self-discover capabilities without external docs

The MCP `initialize` response includes agent instructions forwarded from the extension, or fallback instructions when needed. `tools/list` supplies input schemas, action requirements, conditional requirements, annotations describing side effects, and domain output schemas for all 24 tools. Output fields depend on the action; errors and verbose responses also have structured representations. Use `burp_help` for examples and workflow details.

### 🔄 Communication Flow
```
# Stdio Transport (Claude Code)
Claude → stdio MCP → Node.js Bridge → HTTP → Burp Extension → Burp Suite API

# HTTP/SSE Transport (OpenAI, Gemini)
OpenAI/Gemini → HTTP/SSE MCP → Node.js Bridge → HTTP → Burp Extension → Burp Suite API
```

## 📋 Prerequisites

- **Burp Suite Professional 2026.4+** (licensed version required) - Must be running. `burp_http_jobs` additionally requires the managed HTTP engine introduced in Montoya API 2026.7.
- **Java 17 or higher** - For compiling the extension
- **Apache Maven** - For building (`mvn -version` to check)
- **Node.js 18+** - For MCP bridge (`node -version` to check)

## 🚀 Quick Start

### Prerequisites Check
- ✅ **Burp Suite Professional** (licensed version) - Must be running
- ✅ **Java 17+** - Run `java -version` to verify
- ✅ **Maven** - Run `mvn -version` to verify
- ✅ **Node.js 18+** - Run `node -version` to verify

### 1. Clone and Build

```bash
# Clone the repository
git clone https://github.com/fwaeytens/burp-mcp-bridge.git
cd burp-mcp-bridge

# Build the extension
cd extension
mvn clean package
```

### 2. Load in Burp Suite

1. **Start Burp Suite Professional** (must be running first)
2. Go to **Extensions** → **Extensions** tab
3. Click **Add** → Select **Extension type: Java**
4. Choose `extension/target/burp-mcp-bridge-2.9.0.jar`
5. ✅ **VERIFY**: Look for these messages in the output:
   - "MCP Server listening on http://127.0.0.1:8081"
   - "=== Available MCP Tools ==="
   - "burp_help appears first"
   - "Total: 24 tools available"

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

# Should show summaries for 23 security tools (plus burp_help makes 24 registered tools)
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
   - Returns summaries for 23 security tools; burp_help is the 24th registered tool
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

## 🛠️ Available Tools (24 Total)

### Documentation & Discovery (1)
- `burp_help` - Unified documentation and tool discovery (list tools, search by capability, get detailed help)

### Core HTTP/Proxy Tools (6)
- `burp_proxy_history` - Retrieve and filter proxy history
- `burp_repeater` - Send requests to Repeater UI for manual testing
- `burp_proxy_interceptor` - Event-driven interception and modification of requests, responses, and WebSocket traffic (100% Montoya API)
- `burp_global_interceptor` - Global HTTP interceptor for ALL Burp tools (Scanner, Intruder, Repeater, etc.)
- `burp_custom_http` - Immediate single, parallel, and pipelined HTTP requests with proxy routing, protocol controls, SNI, and raw request support
- `burp_http_jobs` - Managed background HTTP batches with progress, pagination, pause/resume, and cancellation (Professional managed engine, Montoya 2026.7+)

### Scanning & Analysis (2)
- `burp_scanner` - Advanced vulnerability scanner with full Montoya API support (track scans, targeted parameter scanning with insertion points, BCheck import, report generation, crawl-only mode)
- `burp_intruder` - Configure automated attacks (manual payload setup required in UI)

### Issue Management (1)
- `burp_add_issue` - Create custom security issues with intelligent dynamic grouping and proxy history filtering support

### Session Management (1)
- `burp_session_management` - Stored tokens, native cookie jar operations, and session validation. Automatic handling inserts stored tokens; it does not log in or renew expired credentials.

### Analysis & Comparison (2)
- `burp_comparer` - Bounded comparisons of text and HTTP messages, fresh response retrieval, and explicit Comparer UI actions
- `burp_collaborator` - Generate payloads and monitor out-of-band interactions with full Montoya API support

### Configuration & Utilities (4)
- `burp_scope` - Enhanced scope management with host support and tracking (incl. 'include subdomains')
- `burp_config` - Read/write Burp project & user options as JSON (advanced scope, proxy, session handling, upstream proxy); RESET support
- `burp_organizer` - Organize requests/responses in Burp's Organizer tool
- `burp_annotate` - Add annotations and highlights to proxy entries

### Site Map Analysis (1)
- `burp_sitemap_analysis` - Analyze site structure, detect technology, map attack surface

### Advanced Filtering (1)
- `burp_bambda` - Import preset/custom Bambda view filters and report native import errors. Active filter inspection is unsupported.

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
- `burp_http_jobs` - Background HTTP batches that continue between tool calls
- `burp_scanner` - Automated vulnerability scanning
- `burp_collaborator` - Out-of-band testing

### ❌ Tools That CANNOT Execute (UI Configuration Only)
- `burp_repeater` - Only creates UI tabs, does NOT send requests
- `burp_intruder` - Only configures attacks, does NOT execute them

**Golden Rules:**
1. Use `burp_custom_http` for immediate HTTP requests and protocol control; use `burp_http_jobs` for managed background batches
2. For HTTPS, specify port 443 in Host header OR use `https://` prefix in request line
3. Host header alone (without port) defaults to HTTPS on port 443 — always specify the port

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

For `SCAN_SPECIFIC_REQUEST`, supply a raw `request` and an explicit boolean `useHttps`. `ADD_TO_SCAN` requires `scanId` plus a nonempty `urls` array or raw `request`; a raw request also requires `useHttps`, including when its Host header has a port or its target is an absolute URL. URL-only additions use each URL's scheme. This scanner parameter is separate from the optional `use_https` on HTTP jobs.

### Comparisons and Bambda Filters

`COMPARE_RESPONSES` sends fresh GET requests to both URLs. `COMPARE_REQUESTS` constructs GET requests without sending them, and `COMPARE_TEXT` compares supplied text. `COMPARE_PROXY_ENTRIES` compares captured requests selected by URL substring and also sends them to Comparer UI. `SEND_TO_COMPARER` only adds text or constructed requests to the UI; choose text or URLs per call and omit comparison options.

`comparisonType` supports `WORDS`, `BYTES`, `HEADERS_ONLY`, and `BODY_ONLY`. The first two compare the full message or supplied text; HTTP section modes select the start line/headers or body. Results describe one changed span between the common prefix and suffix. Each selected input is limited to 1 MiB; previews contain at most 1024 characters for word mode or 512 bytes encoded as base64 for byte modes. `ignoreWhitespace` is supported except with `BYTES` or `SEND_TO_COMPARER`.

Bambda `APPLY_FILTER` and `CREATE_CUSTOM` import a view filter for `PROXY_HTTP_HISTORY`, `PROXY_WS_HISTORY`, `SITEMAP`, or `LOGGER`. Built-in presets target HTTP history; other locations require compatible Java source using that view's bindings. Success means the native import completed without errors; it does not confirm which filter is active. Inspect/select the filter in Burp as needed. The compatibility action `GET_ACTIVE_FILTER` returns `supported:false` and `isError:true`.

### Send Custom HTTP Request
```javascript
// Use burp_custom_http (NOT burp_repeater)
// IMPORTANT: For HTTPS, specify port 443 or use https:// in URL
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /api/users HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
});
```

### Managed Background HTTP Jobs

`burp_http_jobs` starts a batch and returns a `job_id` promptly. Use `STATUS` to check progress and `RESULTS` to page through responses while the job runs or after it finishes.

```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "START",
  "name": "Endpoint checks",
  "requests": ["https://example.com/", "https://example.com/api/status"],
  "max_concurrency": 5,
  "delay_ms": 100
});
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "STATUS", "job_id": "<job_id from START>"
});
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "RESULTS", "job_id": "<job_id from START>",
  "offset": 0, "limit": 20, "include_response": true
});
```

Use `LIST` to check engine availability and find retained jobs. `PAUSE`, `RESUME`, and `CANCEL` each take `job_id`. Cancellation stops scheduling new requests; the state stays `cancelling` until in-flight requests finish. Burp Dashboard controls also affect jobs.

Pause/resume values in `state` reflect MCP controls. Dashboard pause/resume changes execution and progress counters but does not necessarily change `state`; native completion and cancellation are reflected in the job state.

| Parameter | Default | Behavior |
|-----------|---------|----------|
| `requests` | Required for `START` | Up to 1,000 raw HTTP request strings or full HTTP(S) URLs; URLs create GET requests |
| `use_https` | Automatic | For raw requests, an absolute request-target scheme takes precedence, then an explicit boolean; omission enables port inference |
| `name` | `MCP HTTP batch` | Dashboard label, up to 120 characters |
| `max_concurrency` | `10` | Maximum 50 per job, subject to the aggregate limit |
| `delay_ms` | `0` | Dispatch pacing in milliseconds, maximum 60000 |
| `max_retries` | `0` | Maximum 3; enabling retries can repeat a request |
| `response_timeout` | `30000` | Per-response timeout in milliseconds, maximum 300000 |
| `offset` / `limit` | `0` / `20` | Original input-index pagination; limit is capped at 100 |
| `include_response` | `false` | Include retained response previews as base64 |

Full URLs and absolute raw request targets use their HTTP(S) scheme. Otherwise, an explicit `use_https` selects TLS; when omitted, port 80 selects HTTP, port 443 selects HTTPS, and other ports or no port default to HTTPS. For example, `Host: example.com:80` works without `use_https`, while plaintext on port 8080 needs `use_https: false`.

Results retain stable input positions, including `PENDING` placeholders. Follow `next_offset`: the serialized JSON budget can return fewer entries than `limit`. `next_offset: null` means the final input index was reached; it does not mean the job has completed. Check `STATUS` and revisit pending entries. Response previews are capped at 16 KiB; inspect `response_truncated` and `preview_bytes` before decoding `response_base64`.

`progress.requested` counts the whole submitted batch, and `pending` includes inputs not yet admitted by the native engine. `completed` counts received responses, including HTTP errors; `failed` includes dropped requests. `DROPPED` marks requests confirmed not sent, including unscheduled inputs after cancellation; `UNKNOWN` means the final outcome cannot be established. A `completed` job can contain failures.

`LIST`, `STATUS`, and `RESULTS` inspect existing job data. `START` can send state-changing requests, while `PAUSE`, `RESUME`, and `CANCEL` change execution.

The extension allows 4 active jobs and 50 aggregate concurrent requests. Each job has an internal input ceiling of 10 MiB, but transport limits can be smaller: the extension defaults to 5 MiB per request and the HTTP bridge to 1 MiB. Each job retains at most 10 MiB of response previews. Up to 20 jobs are retained, with older completed jobs evicted when needed; completed jobs expire after one hour. Jobs and their results are cleared when the extension unloads.

If submission fails after requests may have started, inspect the returned `job_id` before retrying. Its capacity remains reserved until native execution is confirmed drained. A `submission_uncertain` job without a native handle cannot be controlled and keeps its reservation until the extension unloads.

This tool requires Burp Professional's Montoya 2026.7 managed engine. It sends directly, with authentication headers supplied explicitly in raw requests; it does not automatically apply the extension's cookie jar or add Proxy History entries. Raw job requests must provide valid framing and body lengths: header line endings are normalized, and body bytes are preserved. Use `burp_custom_http` when you need proxy routing, protocol selection, SNI, connection controls, or byte-exact requests.

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
   - ✅ Verify version 2.9.0 is loaded

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
│   ├── src/           # Source code (24 tools)
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
| `BURP_MCP_SHELL_ENABLED` | `false` | Enable `shell_execute`/`shell_execute_dangerous` (arbitrary host commands) — off by default |
| `MCP_TRANSPORT_MODE` | `both` | MCP Bridge transport mode: stdio, http, or both |
| `MCP_HTTP_PORT` | `3000` | HTTPS/HTTP port for MCP Bridge (when using http mode) |
| `MCP_USE_HTTPS` | `true` | Enable HTTPS for MCP Bridge (set to false for HTTP) |

### Extension Not Loading
- Ensure Java 17+ is installed
- Check Burp Suite Extensions → Errors tab

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

**Current Version**: 2.9.0 | **Burp Suite**: 2026.4+ | **Tools**: 24 | **Status**: Production Ready with AI-Powered Anomaly Detection
