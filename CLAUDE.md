# Burp MCP Bridge - Agent Context File (v2.1.2)

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

### Scanning with Targeted Parameters
```javascript
// Scan only specific parameter (like UI's "scan selected insertion points")
await use_mcp_tool("burp-mcp-bridge", "burp_scanner", {
  "action": "ADD_TO_SCAN",
  "request": "POST /login HTTP/1.1\r\n...",
  "insertionPoints": [{"start": 50, "end": 55}] // Just username value
});
```

### Testing Race Conditions
```javascript
// SEND_PARALLEL uses 'requests' array (not 'request' + 'count')
// Always include port: :443 for HTTPS, :80 for HTTP
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_PARALLEL",
  "requests": [
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100",
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100",
    "POST /transfer HTTP/1.1\r\nHost: bank.com:443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\namount=100"
  ]
});
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
3. Use `insertionPoints` for targeted scanning
4. Filter proxy history queries to reduce data
5. Monitor async operations with status tools

## 🛠️ Project Info

- **Version**: 2.1.2
- **Total Tools**: 22 (1 help + 21 security)
- **Port**: 8081 (Burp extension HTTP server)
- **Transport**: Dual mode (stdio + HTTP/SSE)
- **MCP Spec**: 2025-06-18 (with annotations)
- **Status**: Production Ready

## 🌐 Transport Support (v2.0.1+)

The bridge now supports multiple transport modes:
- **Stdio** (default) - For Claude Code
- **HTTP/SSE** - For OpenAI ChatGPT, Google Gemini
- **Both** - Run simultaneously for multiple LLM clients

Remember: When in doubt, use `burp_help`!
