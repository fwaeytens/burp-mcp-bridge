# Burp MCP Bridge - Agent Context File (v2.4.3)

## 🚀 MANDATORY: Always Start With Documentation Discovery

**EVERY SESSION MUST BEGIN WITH:**
```javascript
// Step 1: List all available tools
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "list": true
});

// Step 2: Discover tools by capability
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "capability": "scan for vulnerabilities"
});

// Step 3: Get detailed help for specific tools
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "tool": "burp_scanner",
  "section": "examples"  // Options: full, examples, parameters, summary
});

// Step 4: Get usage guide (no parameters)
await use_mcp_tool("burp-mcp-bridge", "burp_help", {});
```

## ⚠️ CRITICAL TOOL DISTINCTION

### ✅ Tools That CAN Execute Actions (Automated)
- **burp_custom_http** - ⭐ PRIMARY TOOL for sending HTTP requests
- **burp_scanner** - Automated vulnerability scanning (includes CRAWL_ONLY action for content discovery)
- **burp_collaborator** - Out-of-band interaction testing
- **burp_proxy_history** - Query and analyze captured traffic

### ❌ Tools That CANNOT Execute (Configuration Only)
- **burp_repeater** - Only creates UI tabs, CANNOT send requests
- **burp_intruder** - Only configures attacks, CANNOT execute them

## 📝 GOLDEN RULES

1. **NEVER use burp_repeater to send requests** - Use burp_custom_http
2. **NEVER use burp_intruder to execute attacks** - Use burp_custom_http
3. **ALWAYS use burp_custom_http for HTTP operations**
4. **⚠️ ALWAYS specify port in Host header** - `Host: example.com:80` for HTTP, `Host: example.com:443` for HTTPS
5. **DEFAULT is HTTPS (port 443)** - Without port, requests go to HTTPS which times out on HTTP-only servers
6. **ALWAYS call burp_help first** - List tools or discover by capability
7. **ALWAYS use burp_scanner GET_STATUS** to check scan progress

## 🎯 Common Task Mappings

| Task | CORRECT Tool | WRONG Tool |
|------|-------------|------------|
| Send HTTP request | burp_custom_http | ❌ burp_repeater |
| Modify and resend | burp_custom_http | ❌ burp_repeater |
| Fuzz parameters | burp_custom_http (loop) | ❌ burp_intruder |
| Test race conditions | burp_custom_http (SEND_PARALLEL) | ❌ burp_intruder |
| Scan for vulns | burp_scanner | ✅ |
| View proxy traffic | burp_proxy_history | ✅ |

## 🔄 Quick Workflows

### Sending Modified Requests

**⚠️ CRITICAL: Always Specify Port in Host Header**

Without explicit port, the tool defaults to HTTPS:443 which **times out on HTTP-only servers**.

```javascript
// ✅ CORRECT - HTTP with explicit port 80
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n"
});

// ✅ CORRECT - HTTPS with explicit port 443
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n"
});

// ❌ WRONG - No port specified, defaults to HTTPS:443, times out on HTTP servers
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"  // ❌ NO PORT!
});

// ❌ WRONG - Don't use burp_repeater, it only creates UI tabs
await use_mcp_tool("burp-mcp-bridge", "burp_repeater", {...}); // ❌
```

**Line endings**: Both `\n` and `\r\n` work (auto-normalized to CRLF).
**Content-Length**: Automatically calculated — no need to specify it accurately.

### Scanning with Targeted Parameters (Scan Selected Insertion Points)
```javascript
// By parameter name (PREFERRED - auto-finds byte offsets)
await use_mcp_tool("burp-mcp-bridge", "burp_scanner", {
  "action": "SCAN_SPECIFIC_REQUEST",
  "request": "POST /login HTTP/1.1\r\nHost: target.com:443\r\n\r\nusername=admin&password=secret",
  "useHttps": true,
  "insertionPointParams": ["username", "password"]  // Scans only these parameters
});

// By value string (finds the value anywhere in the request)
await use_mcp_tool("burp-mcp-bridge", "burp_scanner", {
  "action": "SCAN_SPECIFIC_REQUEST",
  "request": "GET /api?token=abc123 HTTP/1.1\r\nHost: target.com:443\r\n\r\n",
  "useHttps": true,
  "insertionPointValues": ["abc123"]  // Scans only this value
});

// By byte offsets (manual - only if you need exact control)
await use_mcp_tool("burp-mcp-bridge", "burp_scanner", {
  "action": "ADD_TO_SCAN",
  "request": "POST /login HTTP/1.1\r\n...",
  "insertionPoints": [{"start": 50, "end": 55}]
});
```

### Parallel Requests / Sweeps (SEND_PARALLEL)
```javascript
// Default: max_concurrency=10 (prevents tail-of-batch drops)
// Responses come back in INPUT ORDER (.index matches requests[] position)
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_PARALLEL",
  "requests": [...50 requests...],
  "max_concurrency": 10,        // default; raise to 50 for race conditions
  "request_delay_ms": 100       // optional: pace dispatch for rate-limited targets
});

// Race condition (opt-in to fire-all-at-once)
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_PARALLEL",
  "max_concurrency": 50,        // bypass the throttle
  "requests": [
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100",
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100",
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100"
  ]
});
```

### Host-Header SSRF / Request Smuggling (advanced)
```javascript
// Decouple TCP destination from Host header (host-header SSRF)
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
  "target_host": "LAB-ID.web-security-academy.net",  // socket goes here
  "target_port": 443                                  // Host header (192.168.0.1) sent verbatim
});

// Preserve absolute-URI request line verbatim (parser-discrepancy / smuggling)
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET https://LAB-ID.web-security-academy.net/admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
  "target_host": "LAB-ID.web-security-academy.net",
  "target_port": 443,
  "raw_request": true   // no rewrite to origin-form, bytes go as-is
});
```

### Request Smuggling (SEND_PIPELINED — ONE TLS socket, multiple requests)
Required for CL.0, TE.CL, CL.TE, TE.0, 0.CL, connection-state attacks. SEND_REQUEST and SEND_PARALLEL open separate sockets and cannot trigger desync.
```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_PIPELINED",
  "target_host": "LAB-ID.web-security-academy.net",
  "target_port": 443,
  "requests": [
    // Request 1: vulnerable POST with smuggled GET in body
    "POST /vulnerable HTTP/1.1\r\nHost: lab\r\nContent-Type: text/plain\r\nContent-Length: 50\r\nConnection: keep-alive\r\n\r\nGET /admin/delete?username=carlos HTTP/1.1\r\nFoo: x",
    // Request 2: trigger that the back-end will see the smuggled body of
    "GET / HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n"
  ],
  // Optional knobs:
  // "inter_request_delay_ms": 100,  // pause-based desync
  // "expect_responses": 2,           // override if smuggling consumes one
  // "read_timeout_ms": 5000          // also captures trailing bytes
});
// → responses: [{ status_code: 200, ...}, { status_code: 302, ...}]
// → each response includes raw_bytes (base64) for byte-level inspection
// → trailing_bytes captures stray queued responses (response-queue-poisoning)
```

## 📚 Documentation Resources

- **Tool Reference**: Always use `burp_help` tool

## 🔍 Tool Discovery

When unsure which tool to use:
```javascript
// Describe what you need
await use_mcp_tool("burp-mcp-bridge", "burp_help", {
  "capability": "intercept and modify requests"
});
// Returns relevant tools with explanations
```

## ⚡ Performance Tips

1. Use `burp_custom_http` for ALL HTTP sending operations
2. Start with PASSIVE scans before ACTIVE
3. Use `insertionPointParams` or `insertionPointValues` for targeted scanning (like "Scan selected insertion point" in Burp UI)
4. Filter proxy history queries to reduce data
5. Monitor async operations with status tools

## 🛠️ Project Info

- **Version**: 2.4.3
- **Total Tools**: 22 (1 help + 21 security)
- **Port**: 8081 (Burp extension HTTP server)
- **Transport**: Dual mode (stdio + HTTP/SSE)
- **MCP Spec**: 2025-06-18 (with annotations)
- **Status**: Production Ready

## ⚠️ Known Limitations

- **HTTP/2 multi-stream-on-one-connection** is not supported. `SEND_PIPELINED` is HTTP/1.1 only — it rejects via clear error if the server negotiates h2 via ALPN. This blocks H2-track smuggling labs (H2.CL, H2.TE, H2 response-queue poisoning, H2 request tunnelling) that require dispatching multiple streams on the same persistent H2 connection at different wall-clock times. Current workaround: raw Python with the `h2` library. Tracked as `TODO(h2-multiplex)` in `CustomHttpTool.java`.

## 🌐 Transport Support (v2.0.1+)

The bridge now supports multiple transport modes:
- **Stdio** (default) - For Claude Code
- **HTTP/SSE** - For OpenAI ChatGPT, Google Gemini
- **Both** - Run simultaneously for multiple LLM clients

Remember: When in doubt, use `burp_help`!
