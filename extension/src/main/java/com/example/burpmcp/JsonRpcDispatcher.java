package com.example.burpmcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Protocol-only JSON-RPC routing used by the HTTP servlet and contract tests.
 */
final class JsonRpcDispatcher {
    private static final String INITIALIZE_INSTRUCTIONS =
        "CRITICAL RULES for Burp MCP Bridge tools:\n\n" +
        "1. SENDING HTTP REQUESTS: Use burp_custom_http for ALL HTTP sending. " +
        "burp_repeater only creates UI tabs and CANNOT send requests. " +
        "burp_intruder only configures attacks and CANNOT execute them.\n\n" +
        "2. HOST HEADER PORT: ALWAYS specify port in Host header. " +
        "HTTP: Host: example.com:80 | HTTPS: Host: example.com:443. " +
        "Without explicit port, defaults to HTTPS:443 which causes timeouts on HTTP-only servers.\n\n" +
        "3. CONTENT-LENGTH: Automatically calculated - no need to specify it.\n\n" +
        "4. LINE ENDINGS: Both \\n and \\r\\n work (auto-normalized to CRLF).\n\n" +
        "5. PARALLEL REQUESTS: Use burp_custom_http SEND_PARALLEL with 'requests' array (not 'request' + 'count').\n\n" +
        "6. DISCOVERY: Use burp_help to list tools or search by capability before starting.\n\n" +
        "7. SCANNING: Always use burp_scanner GET_STATUS to check scan progress after starting a scan. " +
        "Use insertionPointParams to scan specific parameters by name (like Burp UI's 'Scan selected insertion point').\n\n" +
        "8. VISIBILITY: burp_custom_http requests appear in the Target tab (Site Map), NOT in Proxy History. " +
        "Proxy History only contains traffic that flowed through the proxy (browser requests).\n\n" +
        "9. BROWSER = PLAYWRIGHT THROUGH BURP: The Playwright browser is proxied through Burp by default, so pages the agent " +
        "navigates show up in burp_proxy_history and the Site Map, and can be transformed by Burp rules. " +
        "For AUTOMATIC modification, set burp_global_interceptor rules FIRST (enable, then set_auth/add_header/add_request_rule), THEN navigate - " +
        "it transforms-and-forwards inline (no queue, no polling, no deadlock; works with normal browser_click). " +
        "For MANUAL hold/modify/forward with burp_proxy_interceptor, you MUST trigger the held request NON-BLOCKING - " +
        "fire-and-forget via browser_evaluate running an un-awaited fetch(), then get_queue -> modify_request -> disable. " +
        "Do NOT trigger held traffic with a blocking browser_click/browser_navigate: the agent gets stuck in that call and cannot poll/forward (deadlock).\n\n" +
        "Tool quick reference:\n" +
        "- Send/modify HTTP requests -> burp_custom_http\n" +
        "- Scan for vulnerabilities -> burp_scanner\n" +
        "- View captured traffic -> burp_proxy_history (proxy only, not burp_custom_http requests)\n" +
        "- Out-of-band testing -> burp_collaborator: " +
        "Use GENERATE_PAYLOAD to get a unique *.burpcollaborator.net domain, " +
        "inject it into requests (SSRF, blind XXE, blind SQLi, email header injection), " +
        "then CHECK_INTERACTIONS to check if the target made DNS/HTTP requests to it.\n" +
        "- Inject auth/headers or match-replace across browser + all Burp tools -> burp_global_interceptor (AUTOMATIC rules)\n" +
        "- Manage target scope -> burp_scope";

    private final ObjectMapper objectMapper;
    private final Map<String, McpTool> tools;
    private final AsyncToolExecutor asyncToolExecutor;
    private final IntSupplier requestTimeoutMs;
    private final IntSupplier serverPort;
    private final Supplier<String> configSummary;
    private final ToolDocumentationExporter documentationExporter;

    JsonRpcDispatcher(ObjectMapper objectMapper,
                      Map<String, McpTool> tools,
                      AsyncToolExecutor asyncToolExecutor,
                      IntSupplier requestTimeoutMs,
                      IntSupplier serverPort,
                      Supplier<String> configSummary,
                      ToolDocumentationExporter documentationExporter) {
        this.objectMapper = objectMapper;
        this.tools = tools;
        this.asyncToolExecutor = asyncToolExecutor;
        this.requestTimeoutMs = requestTimeoutMs;
        this.serverPort = serverPort;
        this.configSummary = configSummary;
        this.documentationExporter = documentationExporter;
    }

    JsonNode handle(String method, JsonNode request, String clientHost) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();

        switch (method) {
            case "initialize":
                result.put("protocolVersion", ToolDocumentationExporter.MCP_PROTOCOL_VERSION);
                result.put("capabilities", Map.of("tools", Map.of(), "logging", Map.of()));
                result.put("serverInfo", Map.of("name", "burp-mcp-bridge", "version", Version.VERSION));
                result.put("instructions", INITIALIZE_INSTRUCTIONS);
                break;

            case "initialized":
                return objectMapper.valueToTree(Map.of("jsonrpc", "2.0"));

            case "tools/list":
                result.put("tools", tools.values().stream().map(McpTool::getToolInfo).toList());
                break;

            case "tools/call":
                return handleAsyncToolCall(request, clientHost);

            case "tools/call_sync":
                return handleSyncToolCall(request);

            case "docs/export":
                return createSuccessResponse(request, documentationExporter.exportSnapshot());

            case "ping":
                return createSuccessResponse(request, Map.of());

            case "stats":
                Map<String, Object> stats = new LinkedHashMap<>();
                stats.put("asyncStats", String.valueOf(asyncToolExecutor.getStats()));
                stats.put("toolCount", tools.size());
                stats.put("serverPort", serverPort.getAsInt());
                stats.put("configSummary", configSummary.get());
                result.put("stats", stats);
                break;

            default:
                return createErrorResponse(request.get("id"), -32601, "Method not found: " + method);
        }

        return createSuccessResponse(request, result);
    }

    private JsonNode handleSyncToolCall(JsonNode request) throws Exception {
        JsonNode params = request.get("params");
        if (params == null || !params.has("name")) {
            return createErrorResponse(request.get("id"), -32600, "Missing params.name");
        }

        String toolName = params.get("name").asText();
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : objectMapper.createObjectNode();
        McpTool tool = tools.get(toolName);
        if (tool == null) {
            return createErrorResponse(request.get("id"), -32601, "Unknown tool: " + toolName);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        applyToolResult(result, tool.execute(arguments));
        return createSuccessResponse(request, result);
    }

    private JsonNode handleAsyncToolCall(JsonNode request, String clientHost) throws Exception {
        JsonNode params = request.get("params");
        if (params == null || !params.has("name")) {
            return createErrorResponse(request.get("id"), -32600, "Missing params.name");
        }

        String toolName = params.get("name").asText();
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : objectMapper.createObjectNode();
        if (!tools.containsKey(toolName)) {
            return createErrorResponse(request.get("id"), -32601, "Unknown tool: " + toolName);
        }

        try {
            CompletableFuture<Object> future = asyncToolExecutor.executeAsync(toolName, arguments, clientHost);
            Object toolResult = future.get(requestTimeoutMs.getAsInt(), TimeUnit.MILLISECONDS);

            Map<String, Object> result = new LinkedHashMap<>();
            applyToolResult(result, toolResult);
            return createSuccessResponse(request, result);
        } catch (java.util.concurrent.TimeoutException e) {
            return createErrorResponse(request.get("id"), -32603,
                "Tool execution timed out after " + requestTimeoutMs.getAsInt() + "ms");
        } catch (Exception e) {
            return createErrorResponse(request.get("id"), -32603, "Tool execution failed: " + e.getMessage());
        }
    }

    JsonNode createErrorResponse(JsonNode idNode, int code, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        if (idNode != null) {
            response.put("id", idNode);
        }

        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", code);
        error.put("message", message);
        response.put("error", error);
        return objectMapper.valueToTree(response);
    }

    private JsonNode createSuccessResponse(JsonNode request, Object result) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("jsonrpc", "2.0");
        if (request.has("id")) {
            response.put("id", request.get("id"));
        }
        response.put("result", result);
        return objectMapper.valueToTree(response);
    }

    @SuppressWarnings("unchecked")
    private void applyToolResult(Map<String, Object> result, Object toolResult) {
        if (toolResult instanceof Map<?, ?> map &&
            (map.containsKey("content") || map.containsKey("structuredContent") || map.containsKey("isError"))) {
            Map<String, Object> wrapped = (Map<String, Object>) map;
            if (wrapped.containsKey("content")) {
                result.put("content", wrapped.get("content"));
            }
            if (wrapped.containsKey("structuredContent")) {
                result.put("structuredContent", wrapped.get("structuredContent"));
            }
            if (wrapped.containsKey("isError")) {
                result.put("isError", wrapped.get("isError"));
            }
            attachStructuredContentIfMissing(result);
            return;
        }

        result.put("content", toolResult);
        attachStructuredContentIfMissing(result);
    }

    /**
     * When a tool returns JSON text but no structuredContent, attach the parsed
     * object so strict MCP clients accept the response for tools with outputSchema.
     */
    @SuppressWarnings("unchecked")
    private void attachStructuredContentIfMissing(Map<String, Object> result) {
        if (result.containsKey("structuredContent")) {
            return;
        }
        Object content = result.get("content");
        if (!(content instanceof List<?> list) || list.isEmpty()) {
            return;
        }
        Object first = list.get(0);
        if (!(first instanceof Map<?, ?> blockMap)) {
            return;
        }
        Map<String, Object> block = (Map<String, Object>) blockMap;
        if (!"text".equals(block.get("type"))) {
            return;
        }
        Object textValue = block.get("text");
        if (!(textValue instanceof String text)) {
            return;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty() || (trimmed.charAt(0) != '{' && trimmed.charAt(0) != '[')) {
            return;
        }
        try {
            Object parsed = objectMapper.readValue(trimmed, Object.class);
            if (parsed instanceof Map) {
                result.put("structuredContent", parsed);
            } else if (parsed instanceof List) {
                result.put("structuredContent", Map.of("items", parsed));
            }
        } catch (Exception ignored) {
            // Text content is not JSON; leave it unchanged.
        }
    }
}
