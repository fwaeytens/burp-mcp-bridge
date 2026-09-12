# Burp MCP Bridge - Agent Context File (v2.9.0)

The Node bridge forwards the extension's agent instructions in the MCP `initialize` response, with local fallback guidance when unavailable. All 24 tools expose domain output schemas, action requirements, conditional requirements, and side-effect annotations through `tools/list`. Read action-specific fields and structured errors; use `burp_help` for the full workflow.

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
- **burp_http_jobs** - Managed background HTTP batches with status, results, pause/resume, and cancellation
- **burp_scanner** - Automated vulnerability scanning (includes CRAWL_ONLY action for content discovery)
- **burp_collaborator** - Out-of-band interaction testing
- **burp_comparer** - `COMPARE_RESPONSES` sends fresh GET requests; other actions compare constructed/captured requests, supplied text, or add UI items
- **burp_response_analyzer** - `variations` and `all` send fresh GET requests when `urls` is supplied; otherwise they inspect proxy history
- **burp_proxy_history** - Query and analyze captured traffic
- **burp_scope** - Manage target scope (add/remove/check); `includeSubdomains:true` = UI 'Include subdomains'
- **burp_config** - Read/write Burp project & user options as JSON (advanced scope, proxy listeners, match/replace, session-handling rules/macros, upstream proxy, platform auth). GET→modify→SET; changes apply live

### ❌ Tools That CANNOT Execute (Configuration Only)
- **burp_repeater** - Only creates UI tabs, CANNOT send requests
- **burp_intruder** - Only configures attacks, CANNOT execute them

## 📝 GOLDEN RULES

1. **NEVER use burp_repeater to send requests** - Use burp_custom_http
2. **NEVER use burp_intruder to execute attacks** - Use burp_custom_http
3. **Choose the HTTP tool by workflow** - `burp_custom_http` for immediate requests and protocol/byte-level controls; `burp_http_jobs` for managed background batches
4. **Include the port in raw Host headers** - Scanner raw requests additionally require an explicit `useHttps` boolean
5. **Custom HTTP and jobs default to HTTPS** - Use the request scheme or the tool's documented TLS option for plaintext; scanner raw requests have no implicit TLS choice
6. **ALWAYS call burp_help first** - List tools or discover by capability
7. **ALWAYS use burp_scanner GET_STATUS** to check scan progress

## 🎯 Common Task Mappings

| Task | CORRECT Tool | WRONG Tool |
|------|-------------|------------|
| Send HTTP request | burp_custom_http | ❌ burp_repeater |
| Modify and resend | burp_custom_http | ❌ burp_repeater |
| Fuzz parameters | burp_custom_http (loop) | ❌ burp_intruder |
| Test race conditions | burp_custom_http (SEND_PARALLEL) | ❌ burp_intruder |
| Run managed background HTTP batches | burp_http_jobs | ❌ burp_intruder |
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

**Line endings**: Ordinary custom HTTP request headers accept `\n` or `\r\n`.
**Content-Length**: The Node bridge repairs ordinary `burp_custom_http` requests. `raw_request` and `SEND_PIPELINED` preserve framing. Raw `burp_http_jobs` requests must include valid framing and body lengths; their headers are normalized to CRLF while body bytes are preserved.

### HTTP History Visibility — `route_via_proxy`

`burp_custom_http` requests can be **tunnelled through Burp's local proxy listener** (CONNECT + TLS) so they show up in Proxy → HTTP history. Defaults:

| Action | Default | Why |
|--------|---------|-----|
| `SEND_REQUEST` | `route_via_proxy: true` | Day-to-day testing — usually you want it visible. |
| `SEND_PARALLEL` | `route_via_proxy: false` | Proxy may serialise dispatch; per-worker CONNECT+TLS adds latency. |
| `SEND_PIPELINED` | `route_via_proxy: false` | Burp re-frames pipelined requests on its own upstream connections — breaks smuggling semantics. |

```javascript
// Default — visible in HTTP history
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET /admin HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
});
// → routed_via_proxy: true, proxy: "127.0.0.1:8080"

// Opt out — byte-exact wire behaviour, no match/replace rewrites
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_REQUEST",
  "request": "GET https://lab/admin HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n",
  "raw_request": true,
  "route_via_proxy": false   // ← required for smuggling/raw_request work
});

// Opt in on SEND_PARALLEL — each request lands in HTTP history
await use_mcp_tool("burp-mcp-bridge", "burp_custom_http", {
  "action": "SEND_PARALLEL",
  "requests": [...],
  "route_via_proxy": true    // ← extra TLS handshake per worker
});
```

**When `route_via_proxy=true`:** `http_mode` is forced to HTTP/1.1, `redirection_mode` / `connection_id` are ignored, and Burp's match-and-replace rules apply (incompatible with `raw_request` byte-exactness).

**Proxy endpoint:** defaults to `127.0.0.1:8080`. Override with `proxy_host` / `proxy_port` if you've moved Burp's listener.

### Browser Traffic — Playwright Runs Through Burp (default topology)

**Assume the Playwright browser is proxied through Burp** (`127.0.0.1:8080`, Burp CA trusted). This is the default setup. Consequences:

- Pages you navigate with Playwright flow through Burp → they appear in `burp_proxy_history` and the Site Map, and they're scannable / steerable.
- This is what makes the interceptor tools useful: they act on the agent's *own* browser traffic.

**To manipulate browser traffic, use `burp_global_interceptor` rules — set rules FIRST, then navigate.** This tool never holds traffic; it transforms matching requests inline and forwards immediately (no polling, no deadlock):

```javascript
// 1. Enable, then add a global rule (applies to browser + Scanner + Repeater + custom_http-via-proxy)
await use_mcp_tool("burp-mcp-bridge", "burp_global_interceptor", { "action": "enable" });
await use_mcp_tool("burp-mcp-bridge", "burp_global_interceptor", {
  "action": "set_auth", "auth_type": "bearer", "auth_value": "eyJ..."   // → Authorization: Bearer eyJ...
});
// auth_type: bearer | basic | api_key | custom (api_key/custom take optional header_name)
// or add_header / add_request_rule (match/replace) for arbitrary transforms

// 2. THEN drive the browser — the rule applies transparently.
await mcp__playwright__browser_navigate({ "url": "https://lab/account" });
```

**Manual interception with `burp_proxy_interceptor` — trigger NON-BLOCKING or you deadlock.** The agent cannot poll `get_queue` while it is blocked inside a synchronous `browser_navigate`/`browser_click`. The fix is to (a) scope the hold with a filter so the page stays usable, and (b) trigger the request fire-and-forget so the agent stays free. This pattern is **verified** (it solved the "Excessive trust in client-side controls" lab — intercepted the add-to-cart POST and rewrote `price=133700`→`price=1`):

```javascript
// 1. Arm the interceptor with a hold FILTER so only the target request is held (rest of page loads normally)
await use_mcp_tool("burp-mcp-bridge", "burp_proxy_interceptor", {
  "action": "enable", "filter_path": "/cart", "filter_method": "POST"   // filter_host / filter_regex also available
});

// 2. Trigger the request FIRE-AND-FORGET (un-awaited fetch) — returns immediately, request is held
await mcp__playwright__browser_evaluate({ "function":
  "() => { fetch('/cart', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'productId=1&redir=PRODUCT&quantity=1&price=133700'}); return 'dispatched'; }"
});

// 3. Read the held request, 4. modify+forward it
await use_mcp_tool("burp-mcp-bridge", "burp_proxy_interceptor", { "action": "get_queue" });   // → request_id
await use_mcp_tool("burp-mcp-bridge", "burp_proxy_interceptor", {
  "action": "modify_request", "request_id": "<id>",
  "modifications": { "replace_body": "productId=1&redir=PRODUCT&quantity=1&price=1" }   // applies AND forwards
});

// 5. Disable, or the next navigation hangs
await use_mcp_tool("burp-mcp-bridge", "burp_proxy_interceptor", { "action": "disable" });
```

**Do NOT trigger held traffic with a blocking call** (`browser_click`/`browser_navigate`, or a foreground `burp_custom_http` via proxy) — the caller blocks on the held request and you can never reach `get_queue`. For one-off edits where you don't need a true breakpoint, prefer the automatic global rule above or replay with `burp_custom_http`.

### Scanning with Targeted Parameters (Scan Selected Insertion Points)

`SCAN_SPECIFIC_REQUEST` requires `request` and an explicit boolean `useHttps`. `ADD_TO_SCAN` requires `scanId` plus a nonempty `urls` array or `request`; raw requests additionally require `useHttps`, even with a Host port or absolute request target. URL-only additions use their URL scheme. The scanner's `useHttps` differs from the optional `use_https` on jobs.

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
  "scanId": "<scanId from an active audit>",
  "request": "GET /api?token=abc123 HTTP/1.1\r\nHost: target.com:443\r\n\r\n",
  "useHttps": true,
  "insertionPoints": [{"start": 15, "end": 21}]  // ASCII bytes for abc123
});
```

### Comparisons, Filters, and Session Handling

- `COMPARE_TEXT` compares supplied text. `COMPARE_REQUESTS` constructs GET requests without sending them. `COMPARE_RESPONSES` fetches fresh responses. `COMPARE_PROXY_ENTRIES` compares captured requests selected by URL substring and also adds them to Comparer UI.
- `comparisonType` is `WORDS`, `BYTES`, `HEADERS_ONLY`, or `BODY_ONLY`. The first two compare full messages/text; HTTP section modes require an HTTP comparison action. Results report one changed span between common prefix/suffix regions, with at most 1 MiB per selected input and bounded previews (1024 characters for words, 512 bytes encoded as base64 otherwise). `ignoreWhitespace` is unsupported for `BYTES`.
- `SEND_TO_COMPARER` only adds UI items. Supply text or URLs in one call and omit `comparisonType` and `ignoreWhitespace`.
- Bambda `APPLY_FILTER` and `CREATE_CUSTOM` import view filters for `PROXY_HTTP_HISTORY`, `PROXY_WS_HISTORY`, `SITEMAP`, or `LOGGER`. Presets target HTTP history; other views need compatible Java source and bindings. Success means import completed without native errors; inspect/select the active filter in Burp as needed. `GET_ACTIVE_FILTER` is a compatibility action that always returns `supported:false` and `isError:true`.
- Session auto handling inserts stored tokens. Its legacy `autoRefresh` flag marks missing authentication and increments a counter; it does not log in, renew credentials, or retry after 401 responses.

### Managed Background HTTP Batches

Use `burp_http_jobs` when a batch should continue between tool calls. It requires Burp Suite Professional's managed HTTP engine introduced in Montoya API 2026.7; other tools retain the Burp 2026.4 minimum.

```javascript
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "START", "name": "Endpoint checks",
  "requests": ["https://example.com/", "https://example.com/api/status"],
  "max_concurrency": 5, "delay_ms": 100
});
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "STATUS", "job_id": "<job_id from START>"
});
await use_mcp_tool("burp-mcp-bridge", "burp_http_jobs", {
  "action": "RESULTS", "job_id": "<job_id from START>",
  "offset": 0, "limit": 20, "include_response": true
});
```

- `START` requires `requests`; each entry is a raw HTTP string or full HTTP(S) URL. URL schemes, including absolute raw request targets, take precedence over `use_https`. Otherwise, an explicit boolean selects TLS; omission infers HTTP for port 80 and HTTPS for port 443, other ports, or no port. Use `use_https: false` for plaintext on nonstandard ports. Include authentication headers explicitly.
- `LIST` reports engine availability and retained jobs. `STATUS`, `RESULTS`, `PAUSE`, `RESUME`, and `CANCEL` require `job_id`. Cancellation stops scheduling; state remains `cancelling` until in-flight requests finish. Dashboard controls also affect jobs.
- Pause/resume values in `state` reflect MCP controls. Dashboard pause/resume changes execution and progress counters without necessarily updating `state`; native completion and cancellation are reflected.
- `max_concurrency` defaults to 10 (maximum 50), `delay_ms` to 0 (maximum 60000), `max_retries` to 0 (maximum 3), and `response_timeout` to 30000 ms (maximum 300000). Retries can repeat requests.
- Results use stable original input indices, with pending placeholders. Follow `next_offset` rather than assuming `limit` entries were returned; pages are bounded by a serialized JSON budget. Revisit pending entries after completion.
- `limit` defaults to 20 (maximum 100). `include_response` defaults to false; optional response previews are base64, capped at 16 KiB, with explicit truncation metadata.
- Limits: 4 active jobs, 50 aggregate concurrent requests, 1000 requests and a 10 MiB internal input ceiling per job (transport limits may be smaller), 10 MiB retained response previews per job, and 20 retained jobs. Older completed jobs are evicted when needed and expire after one hour. Jobs and results are cleared on extension unload.
- Jobs send directly and do not automatically apply the extension's cookie jar or add Proxy History entries. Use `burp_custom_http` for proxy routing, protocol selection, SNI, connection controls, and byte-exact requests.

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

1. Use `burp_http_jobs` for managed background batches and `burp_custom_http` for immediate HTTP sends or protocol/byte-level controls
2. Start with PASSIVE scans before ACTIVE
3. Use `insertionPointParams` or `insertionPointValues` for targeted scanning (like "Scan selected insertion point" in Burp UI)
4. Filter proxy history queries to reduce data
5. Monitor async operations with status tools

## 🛠️ Project Info

- **Version**: 2.9.0
- **Total Tools**: 24 (1 help + 23 security)
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
