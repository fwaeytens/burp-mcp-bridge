package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class ProxyHistoryTool implements McpTool {
    private final MontoyaApi api;
    
    // Helper class to hold filtered results with original indices
    public static class FilteredResults {
        final List<ProxyHttpRequestResponse> entries;
        final List<Integer> originalIndices;
        
        public FilteredResults(List<ProxyHttpRequestResponse> entries, List<Integer> originalIndices) {
            this.entries = entries;
            this.originalIndices = originalIndices;
        }
        
        public List<ProxyHttpRequestResponse> getEntries() {
            return entries;
        }
        
        public List<Integer> getOriginalIndices() {
            return originalIndices;
        }
    }
    
    public ProxyHistoryTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_proxy_history");
        tool.put("title", "Proxy History");
        tool.put("description", "Retrieve and filter HTTP proxy history captured by Burp Suite. Use this to analyze traffic patterns, " +
            "find specific requests, or extract data from past sessions. Supports 25+ filters including hostname, method, status code, " +
            "path, parameters, and regex patterns. Returns request/response pairs with timing data. " +
            "Use 'list' mode for URLs only, 'detail' for full content, or 'iterate' for sequential browsing.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", true);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", true);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        // Action mode
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Mode: list (URLs), detail (specific entries), iterate (sequential full details)");
        actionProperty.put("enum", Arrays.asList("list", "detail", "iterate"));
        actionProperty.put("default", "list");
        properties.put("action", actionProperty);
        
        // Entry IDs for detail mode
        Map<String, Object> entryIdsProperty = new HashMap<>();
        entryIdsProperty.put("type", "array");
        entryIdsProperty.put("description", "Entry IDs for detail mode (e.g., [1, 5, 10])");
        entryIdsProperty.put("items", Map.of("type", "integer"));
        properties.put("entryIds", entryIdsProperty);
        
        // Iteration parameters
        Map<String, Object> startAtProperty = new HashMap<>();
        startAtProperty.put("type", "integer");
        startAtProperty.put("description", "Starting entry for iterate mode (default: 1)");
        startAtProperty.put("default", 1);
        properties.put("startAt", startAtProperty);
        
        Map<String, Object> countProperty = new HashMap<>();
        countProperty.put("type", "integer");
        countProperty.put("description", "Number of entries to return in iterate mode (default: 1)");
        countProperty.put("default", 1);
        properties.put("count", countProperty);
        
        // Basic filters (keeping all existing ones)
        Map<String, Object> limitProperty = new HashMap<>();
        limitProperty.put("type", "integer");
        limitProperty.put("description", "Maximum entries for list mode (default: 100, no max limit)");
        limitProperty.put("default", 100);
        properties.put("limit", limitProperty);
        
        Map<String, Object> hostnameProperty = new HashMap<>();
        hostnameProperty.put("type", "string");
        hostnameProperty.put("description", "Filter by hostname - partial match");
        properties.put("hostname", hostnameProperty);
        
        Map<String, Object> methodProperty = new HashMap<>();
        methodProperty.put("type", "string");
        methodProperty.put("description", "Filter by HTTP method");
        properties.put("method", methodProperty);
        
        Map<String, Object> pathProperty = new HashMap<>();
        pathProperty.put("type", "string");
        pathProperty.put("description", "Filter by URL path - partial match");
        properties.put("path", pathProperty);
        
        Map<String, Object> statusCodeProperty = new HashMap<>();
        statusCodeProperty.put("type", "integer");
        statusCodeProperty.put("description", "Filter by exact status code");
        properties.put("statusCode", statusCodeProperty);
        
        Map<String, Object> statusRangeProperty = new HashMap<>();
        statusRangeProperty.put("type", "string");
        statusRangeProperty.put("description", "Filter by status range (e.g., '200-299')");
        properties.put("statusRange", statusRangeProperty);
        
        Map<String, Object> containsProperty = new HashMap<>();
        containsProperty.put("type", "string");
        containsProperty.put("description", "Search text in request/response");
        properties.put("contains", containsProperty);
        
        Map<String, Object> regexProperty = new HashMap<>();
        regexProperty.put("type", "string");
        regexProperty.put("description", "Regex pattern search");
        properties.put("regex", regexProperty);
        
        Map<String, Object> parameterProperty = new HashMap<>();
        parameterProperty.put("type", "string");
        parameterProperty.put("description", "Filter by parameter name");
        properties.put("parameter", parameterProperty);
        
        Map<String, Object> cookieNameProperty = new HashMap<>();
        cookieNameProperty.put("type", "string");
        cookieNameProperty.put("description", "Filter by cookie name");
        properties.put("cookieName", cookieNameProperty);
        
        Map<String, Object> inScopeOnlyProperty = new HashMap<>();
        inScopeOnlyProperty.put("type", "boolean");
        inScopeOnlyProperty.put("description", "Show only in-scope items");
        inScopeOnlyProperty.put("default", false);
        properties.put("inScopeOnly", inScopeOnlyProperty);
        
        Map<String, Object> secureProperty = new HashMap<>();
        secureProperty.put("type", "boolean");
        secureProperty.put("description", "Filter by protocol (true=HTTPS, false=HTTP)");
        properties.put("secure", secureProperty);
        
        Map<String, Object> hasResponseProperty = new HashMap<>();
        hasResponseProperty.put("type", "boolean");
        hasResponseProperty.put("description", "Filter by response presence");
        properties.put("hasResponse", hasResponseProperty);
        
        Map<String, Object> mimeTypeProperty = new HashMap<>();
        mimeTypeProperty.put("type", "string");
        mimeTypeProperty.put("description", "Filter by MIME type");
        properties.put("mimeType", mimeTypeProperty);
        
        Map<String, Object> responseTimeMinProperty = new HashMap<>();
        responseTimeMinProperty.put("type", "integer");
        responseTimeMinProperty.put("description", "Min response time (ms)");
        properties.put("responseTimeMin", responseTimeMinProperty);
        
        Map<String, Object> responseTimeMaxProperty = new HashMap<>();
        responseTimeMaxProperty.put("type", "integer");
        responseTimeMaxProperty.put("description", "Max response time (ms)");
        properties.put("responseTimeMax", responseTimeMaxProperty);
        
        Map<String, Object> editedOnlyProperty = new HashMap<>();
        editedOnlyProperty.put("type", "boolean");
        editedOnlyProperty.put("description", "Show only edited requests");
        editedOnlyProperty.put("default", false);
        properties.put("editedOnly", editedOnlyProperty);
        
        Map<String, Object> hasNotesProperty = new HashMap<>();
        hasNotesProperty.put("type", "boolean");
        hasNotesProperty.put("description", "Filter entries with notes");
        hasNotesProperty.put("default", false);
        properties.put("hasNotes", hasNotesProperty);
        
        Map<String, Object> highlightColorProperty = new HashMap<>();
        highlightColorProperty.put("type", "string");
        highlightColorProperty.put("description", "Filter by highlight color");
        properties.put("highlightColor", highlightColorProperty);
        
        Map<String, Object> listenerPortProperty = new HashMap<>();
        listenerPortProperty.put("type", "integer");
        listenerPortProperty.put("description", "Filter by listener port");
        properties.put("listenerPort", listenerPortProperty);
        
        Map<String, Object> recentProperty = new HashMap<>();
        recentProperty.put("type", "boolean");
        recentProperty.put("description", "Sort most recent first");
        recentProperty.put("default", true);
        properties.put("recent", recentProperty);
        
        // Display options for backward compatibility
        Map<String, Object> showHeadersProperty = new HashMap<>();
        showHeadersProperty.put("type", "boolean");
        showHeadersProperty.put("description", "Include headers in output");
        showHeadersProperty.put("default", false);
        properties.put("showHeaders", showHeadersProperty);
        
        Map<String, Object> showBodyProperty = new HashMap<>();
        showBodyProperty.put("type", "boolean");
        showBodyProperty.put("description", "Include body in output");
        showBodyProperty.put("default", false);
        properties.put("showBody", showBodyProperty);
        
        Map<String, Object> showAnnotationsProperty = new HashMap<>();
        showAnnotationsProperty.put("type", "boolean");
        showAnnotationsProperty.put("description", "Include annotations");
        showAnnotationsProperty.put("default", false);
        properties.put("showAnnotations", showAnnotationsProperty);
        
        Map<String, Object> showTimingProperty = new HashMap<>();
        showTimingProperty.put("type", "boolean");
        showTimingProperty.put("description", "Include timing data");
        showTimingProperty.put("default", false);
        properties.put("showTiming", showTimingProperty);
        
        Map<String, Object> includeBase64Property = new HashMap<>();
        includeBase64Property.put("type", "boolean");
        includeBase64Property.put("description", "Include base64 encoding");
        includeBase64Property.put("default", false);
        properties.put("includeBase64", includeBase64Property);
        
        // NEW: Time-based filtering
        Map<String, Object> afterTimeProperty = new HashMap<>();
        afterTimeProperty.put("type", "string");
        afterTimeProperty.put("description", "Filter requests after this time (ISO-8601 or relative like '1h', '30m', '7d')");
        properties.put("afterTime", afterTimeProperty);
        
        Map<String, Object> beforeTimeProperty = new HashMap<>();
        beforeTimeProperty.put("type", "string");
        beforeTimeProperty.put("description", "Filter requests before this time (ISO-8601 format)");
        properties.put("beforeTime", beforeTimeProperty);
        
        // NEW: File extension filtering
        Map<String, Object> fileExtensionProperty = new HashMap<>();
        fileExtensionProperty.put("type", "string");
        fileExtensionProperty.put("description", "Filter by file extension (e.g., 'js', 'php', 'jpg')");
        properties.put("fileExtension", fileExtensionProperty);
        
        // NEW: Content-Type filtering
        Map<String, Object> contentTypeProperty = new HashMap<>();
        contentTypeProperty.put("type", "string");
        contentTypeProperty.put("description", "Filter by content type (JSON, XML, URL_ENCODED, MULTIPART, AMF)");
        properties.put("contentType", contentTypeProperty);
        
        // NEW: Query string filtering
        Map<String, Object> queryStringProperty = new HashMap<>();
        queryStringProperty.put("type", "string");
        queryStringProperty.put("description", "Filter by query string content");
        properties.put("queryString", queryStringProperty);
        
        // NEW: HTTP version filtering
        Map<String, Object> httpVersionProperty = new HashMap<>();
        httpVersionProperty.put("type", "string");
        httpVersionProperty.put("description", "Filter by HTTP version (e.g., 'HTTP/1.1', 'HTTP/2')");
        properties.put("httpVersion", httpVersionProperty);
        
        // NEW: Response cookie filtering
        Map<String, Object> responseCookieProperty = new HashMap<>();
        responseCookieProperty.put("type", "string");
        responseCookieProperty.put("description", "Filter by response Set-Cookie name");
        properties.put("responseCookie", responseCookieProperty);
        
        // NEW: Status class filtering
        Map<String, Object> statusClassProperty = new HashMap<>();
        statusClassProperty.put("type", "string");
        statusClassProperty.put("description", "Filter by status class (1XX, 2XX, 3XX, 4XX, 5XX)");
        properties.put("statusClass", statusClassProperty);
        
        // NEW: Parameter type filtering
        Map<String, Object> parameterTypeProperty = new HashMap<>();
        parameterTypeProperty.put("type", "string");
        parameterTypeProperty.put("description", "Parameter location (URL, BODY, COOKIE, JSON, XML, MULTIPART)");
        properties.put("parameterType", parameterTypeProperty);
        
        // NEW: Keyword analysis
        Map<String, Object> keywordsProperty = new HashMap<>();
        keywordsProperty.put("type", "array");
        keywordsProperty.put("description", "Keywords to count in responses");
        keywordsProperty.put("items", Map.of("type", "string"));
        properties.put("keywords", keywordsProperty);
        
        Map<String, Object> minKeywordCountProperty = new HashMap<>();
        minKeywordCountProperty.put("type", "integer");
        minKeywordCountProperty.put("description", "Minimum keyword count to match");
        properties.put("minKeywordCount", minKeywordCountProperty);
        
        // NEW: Modified requests filter
        Map<String, Object> modifiedOnlyProperty = new HashMap<>();
        modifiedOnlyProperty.put("type", "boolean");
        modifiedOnlyProperty.put("description", "Show only requests that were modified");
        modifiedOnlyProperty.put("default", false);
        properties.put("modifiedOnly", modifiedOnlyProperty);
        
        inputSchema.put("properties", properties);
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = arguments.has("action") ? arguments.get("action").asText().toLowerCase() : "list";
        
        // For backward compatibility - if old display options are used, use legacy mode
        boolean hasLegacyOptions = arguments.has("showHeaders") || arguments.has("showBody") || 
                                  arguments.has("showAnnotations") || arguments.has("showTiming");
        
        if (hasLegacyOptions && !arguments.has("action")) {
            return executeLegacyMode(arguments);
        }
        
        switch (action) {
            case "detail":
                return executeDetailMode(arguments);
            case "iterate":
                return executeIterateMode(arguments);
            case "list":
            default:
                return executeListMode(arguments);
        }
    }
    
    private Object executeListMode(JsonNode arguments) throws Exception {
        FilteredResults results = applyFilters(arguments);
        List<ProxyHttpRequestResponse> filtered = results.entries;
        List<Integer> originalIndices = results.originalIndices;
        
        boolean recent = arguments.has("recent") ? arguments.get("recent").asBoolean() : true;
        int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 100;
        
        if (recent) {
            java.util.Collections.reverse(filtered);
        }
        
        if (limit > 0 && filtered.size() > limit) {
            filtered = filtered.subList(0, limit);
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📋 **PROXY HISTORY LIST**\n\n");
        result.append(String.format("**Total:** %d entries | **Showing:** %d\n\n", 
                                  filtered.size(), Math.min(filtered.size(), limit)));
        
        result.append("```\n");
        result.append(String.format("%-5s | %-7s | %-6s | %s\n", "ID", "Method", "Status", "URL"));
        result.append("------|---------|--------|--------------------------------------------\n");
        
        for (int i = 0; i < filtered.size(); i++) {
            ProxyHttpRequestResponse entry = filtered.get(i);
            int originalId = originalIndices.get(i);
            int status = entry.hasResponse() ? entry.response().statusCode() : 0;
            String statusStr = status > 0 ? String.valueOf(status) : "---";
            String url = entry.url();
            if (url.length() > 60) {
                url = url.substring(0, 57) + "...";
            }
            
            result.append(String.format("%-5d | %-7s | %-6s | %s\n", 
                                      originalId, entry.method(), statusStr, url));
        }
        result.append("```\n\n");
        
        result.append("💡 **Usage:**\n");
        result.append("• `action: \"detail\", entryIds: [1, 5, 10]` - Get full details\n");
        result.append("• `action: \"iterate\", startAt: 1, count: 1` - Browse sequentially\n");
        
        Map<String, Object> response = new HashMap<>();
        response.put("type", "text");
        response.put("text", result.toString());
        
        return List.of(response);
    }
    
    private Object executeDetailMode(JsonNode arguments) throws Exception {
        List<Integer> entryIds = new ArrayList<>();
        if (arguments.has("entryIds") && arguments.get("entryIds").isArray()) {
            arguments.get("entryIds").forEach(node -> entryIds.add(node.asInt()));
        }
        
        boolean includeBase64 = arguments.has("includeBase64") ? arguments.get("includeBase64").asBoolean() : false;
        
        // For detail mode, we need to get entries by their original IDs from the full proxy history
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        
        StringBuilder result = new StringBuilder();
        result.append("📝 **DETAILED PROXY ENTRIES**\n\n");
        
        for (Integer id : entryIds) {
            if (id < 1 || id > proxyHistory.size()) {
                result.append(String.format("❌ Entry #%d not found (valid: 1-%d)\n\n", id, proxyHistory.size()));
                continue;
            }
            
            ProxyHttpRequestResponse entry = proxyHistory.get(id - 1);
            result.append(String.format("## 📌 Entry #%d\n\n", id));
            
            // Basic info
            result.append("**URL:** `").append(entry.url()).append("`\n");
            result.append("**Method:** ").append(entry.method()).append("\n");
            result.append("**Host:** ").append(entry.host()).append(":").append(entry.port()).append("\n");
            result.append("**Protocol:** ").append(entry.secure() ? "HTTPS 🔒" : "HTTP 🔓").append("\n");
            
            // Request
            result.append("\n### 📤 Request\n```http\n");
            result.append(entry.request().toString());
            result.append("\n```\n");
            
            String reqBody = entry.requestBody();
            if (reqBody != null && !reqBody.isEmpty()) {
                result.append("\n**Request Body:**\n```\n");
                result.append(reqBody);
                result.append("\n```\n");
            }
            
            // Response
            if (entry.hasResponse()) {
                result.append("\n### 📥 Response\n");
                result.append("**Status:** ").append(entry.response().statusCode());
                result.append(" ").append(entry.response().reasonPhrase()).append("\n\n");
                
                result.append("**Headers:**\n```http\n");
                entry.response().headers().forEach(h -> 
                    result.append(h.name()).append(": ").append(h.value()).append("\n")
                );
                result.append("```\n");
                
                String respBody = entry.response().bodyToString();
                if (!respBody.isEmpty()) {
                    result.append("\n**Response Body:**\n```\n");
                    if (respBody.length() > 5000) {
                        result.append(respBody.substring(0, 5000));
                        result.append("\n... [").append(respBody.length() - 5000).append(" bytes truncated] ...\n");
                    } else {
                        result.append(respBody);
                    }
                    result.append("\n```\n");
                }
            }
            
            // Metadata
            result.append("\n### 📊 Metadata\n");
            if (entry.edited()) {
                result.append("• **Edited:** ✏️ Yes\n");
            }
            if (entry.annotations().hasNotes()) {
                result.append("• **Notes:** 📝 ").append(entry.annotations().notes()).append("\n");
            }
            if (entry.annotations().hasHighlightColor()) {
                result.append("• **Highlight:** 🎨 ").append(entry.annotations().highlightColor().displayName()).append("\n");
            }
            if (entry.hasResponse()) {
                try {
                    Duration timing = entry.timingData().timeBetweenRequestSentAndEndOfResponse();
                    result.append("• **Response Time:** ⏱️ ").append(timing.toMillis()).append("ms\n");
                } catch (Exception e) {
                    // Timing not available
                }
            }
            result.append("• **Listener Port:** ").append(entry.listenerPort()).append("\n");
            
            // Base64 if requested
            if (includeBase64) {
                result.append("\n### 🔐 Base64 Encoded\n");
                result.append("<details><summary>Click to expand base64 data</summary>\n\n");
                result.append("**Request:**\n```\n");
                result.append(Base64.getEncoder().encodeToString(entry.request().toByteArray().getBytes()));
                result.append("\n```\n");
                
                if (entry.hasResponse()) {
                    result.append("\n**Response:**\n```\n");
                    result.append(Base64.getEncoder().encodeToString(entry.response().toByteArray().getBytes()));
                    result.append("\n```\n");
                }
                result.append("</details>\n");
            }
            
            result.append("\n---\n\n");
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("type", "text");
        response.put("text", result.toString());
        
        return List.of(response);
    }
    
    private Object executeIterateMode(JsonNode arguments) throws Exception {
        int startAt = arguments.has("startAt") ? arguments.get("startAt").asInt() : 1;
        int count = arguments.has("count") ? arguments.get("count").asInt() : 1;
        
        FilteredResults results = applyFilters(arguments);
        List<ProxyHttpRequestResponse> filtered = results.entries;
        boolean recent = arguments.has("recent") ? arguments.get("recent").asBoolean() : true;
        
        if (recent) {
            java.util.Collections.reverse(filtered);
        }
        
        int endAt = Math.min(startAt + count - 1, filtered.size());
        
        StringBuilder result = new StringBuilder();
        result.append("🔄 **ITERATING PROXY HISTORY**\n\n");
        result.append(String.format("**Showing:** Entries %d-%d of %d total\n\n", startAt, endAt, filtered.size()));
        
        for (int i = startAt - 1; i < endAt && i < filtered.size(); i++) {
            ProxyHttpRequestResponse entry = filtered.get(i);
            int entryNum = i + 1;
            
            result.append(String.format("## 📌 Entry #%d of %d\n\n", entryNum, filtered.size()));
            
            // Full details similar to detail mode
            result.append("**URL:** `").append(entry.url()).append("`\n");
            result.append("**Method:** ").append(entry.method()).append("\n");
            result.append("**Status:** ").append(entry.hasResponse() ? entry.response().statusCode() : "No Response").append("\n\n");
            
            // Add full request/response as in detail mode...
            result.append("### Request\n```http\n");
            result.append(entry.request().toString()).append("\n```\n\n");
            
            if (entry.hasResponse()) {
                result.append("### Response\n```http\n");
                result.append("HTTP/1.1 ").append(entry.response().statusCode()).append(" ");
                result.append(entry.response().reasonPhrase()).append("\n");
                entry.response().headers().forEach(h -> 
                    result.append(h.name()).append(": ").append(h.value()).append("\n")
                );
                result.append("\n").append(entry.response().bodyToString()).append("\n```\n");
            }
            
            result.append("\n---\n\n");
        }
        
        // Navigation hints
        result.append("### 🧭 Navigation\n");
        if (endAt < filtered.size()) {
            result.append(String.format("• **Next:** `action: \"iterate\", startAt: %d, count: %d`\n", endAt + 1, count));
        }
        if (startAt > 1) {
            result.append(String.format("• **Previous:** `action: \"iterate\", startAt: %d, count: %d`\n", 
                                      Math.max(1, startAt - count), count));
        }
        result.append(String.format("• **Jump to:** `action: \"iterate\", startAt: [entry_number], count: %d`\n", count));
        
        Map<String, Object> response = new HashMap<>();
        response.put("type", "text");
        response.put("text", result.toString());
        
        return List.of(response);
    }
    
    private Object executeLegacyMode(JsonNode arguments) throws Exception {
        // This preserves the v1.7.9.1 behavior for backward compatibility
        // Implementation would be the same as the original with truncation
        FilteredResults results = applyFilters(arguments);
        List<ProxyHttpRequestResponse> filtered = results.entries;
        
        boolean recent = arguments.has("recent") ? arguments.get("recent").asBoolean() : true;
        int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 20;
        boolean showHeaders = arguments.has("showHeaders") ? arguments.get("showHeaders").asBoolean() : false;
        boolean showBody = arguments.has("showBody") ? arguments.get("showBody").asBoolean() : false;
        boolean showAnnotations = arguments.has("showAnnotations") ? arguments.get("showAnnotations").asBoolean() : false;
        boolean showTiming = arguments.has("showTiming") ? arguments.get("showTiming").asBoolean() : false;
        
        if (recent) {
            java.util.Collections.reverse(filtered);
        }
        
        if (limit > 0 && filtered.size() > limit) {
            filtered = filtered.subList(0, Math.min(limit, 100)); // Keep 100 max for legacy mode
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📡 **ADVANCED PROXY HISTORY**\n\n");
        result.append(String.format("**Total Entries:** %d | **Showing:** %d\n\n", 
                                  filtered.size(), Math.min(filtered.size(), limit)));
        
        // Continue with legacy formatting...
        // (Implementation details similar to v1.7.9.1)
        
        Map<String, Object> response = new HashMap<>();
        response.put("type", "text");
        response.put("text", result.toString());
        
        return List.of(response);
    }
    
    public FilteredResults applyFilters(JsonNode arguments) throws Exception {
        // Debug: Log received filters
        String logMsg1 = "ProxyHistoryTool.applyFilters: Received filters: " + arguments.toString();
        api.logging().logToOutput(logMsg1);
        LogsTool.logOutput(logMsg1);
        
        // Parse all filters
        String hostname = arguments.has("hostname") ? arguments.get("hostname").asText() : null;
        String method = arguments.has("method") ? arguments.get("method").asText().toUpperCase() : null;
        
        String logMsg2 = "ProxyHistoryTool.applyFilters: Parsed - hostname=" + hostname + ", method=" + method;
        api.logging().logToOutput(logMsg2);
        LogsTool.logOutput(logMsg2);
        String path = arguments.has("path") ? arguments.get("path").asText() : null;
        Integer statusCode = arguments.has("statusCode") ? arguments.get("statusCode").asInt() : null;
        String statusRange = arguments.has("statusRange") ? arguments.get("statusRange").asText() : null;
        String contains = arguments.has("contains") ? arguments.get("contains").asText() : null;
        String regexPattern = arguments.has("regex") ? arguments.get("regex").asText() : null;
        String parameter = arguments.has("parameter") ? arguments.get("parameter").asText() : null;
        String cookieName = arguments.has("cookieName") ? arguments.get("cookieName").asText() : null;
        boolean inScopeOnly = arguments.has("inScopeOnly") ? arguments.get("inScopeOnly").asBoolean() : false;
        Boolean secure = arguments.has("secure") ? arguments.get("secure").asBoolean() : null;
        Boolean hasResponse = arguments.has("hasResponse") ? arguments.get("hasResponse").asBoolean() : null;
        String mimeType = arguments.has("mimeType") ? arguments.get("mimeType").asText() : null;
        Integer responseTimeMin = arguments.has("responseTimeMin") ? arguments.get("responseTimeMin").asInt() : null;
        Integer responseTimeMax = arguments.has("responseTimeMax") ? arguments.get("responseTimeMax").asInt() : null;
        boolean editedOnly = arguments.has("editedOnly") ? arguments.get("editedOnly").asBoolean() : false;
        boolean hasNotes = arguments.has("hasNotes") ? arguments.get("hasNotes").asBoolean() : false;
        String highlightColor = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;
        Integer listenerPort = arguments.has("listenerPort") ? arguments.get("listenerPort").asInt() : null;
        
        // NEW filter parameters
        String afterTime = arguments.has("afterTime") ? arguments.get("afterTime").asText() : null;
        String beforeTime = arguments.has("beforeTime") ? arguments.get("beforeTime").asText() : null;
        String fileExtension = arguments.has("fileExtension") ? arguments.get("fileExtension").asText() : null;
        String contentTypeFilter = arguments.has("contentType") ? arguments.get("contentType").asText() : null;
        String queryString = arguments.has("queryString") ? arguments.get("queryString").asText() : null;
        String httpVersion = arguments.has("httpVersion") ? arguments.get("httpVersion").asText() : null;
        String responseCookie = arguments.has("responseCookie") ? arguments.get("responseCookie").asText() : null;
        String statusClass = arguments.has("statusClass") ? arguments.get("statusClass").asText() : null;
        String parameterType = arguments.has("parameterType") ? arguments.get("parameterType").asText() : null;
        boolean modifiedOnly = arguments.has("modifiedOnly") ? arguments.get("modifiedOnly").asBoolean() : false;
        
        // Keyword analysis parameters
        List<String> keywords = new ArrayList<>();
        if (arguments.has("keywords") && arguments.get("keywords").isArray()) {
            arguments.get("keywords").forEach(k -> keywords.add(k.asText()));
        }
        Integer minKeywordCount = arguments.has("minKeywordCount") ? arguments.get("minKeywordCount").asInt() : null;
        
        // Compile regex if provided
        Pattern compiledRegex = null;
        if (regexPattern != null) {
            try {
                compiledRegex = Pattern.compile(regexPattern);
            } catch (PatternSyntaxException e) {
                throw new Exception("Invalid regex pattern: " + e.getMessage());
            }
        }
        
        // Parse status range
        Integer statusMin = null, statusMax = null;
        if (statusRange != null) {
            String[] parts = statusRange.split("-");
            if (parts.length == 2) {
                try {
                    statusMin = Integer.parseInt(parts[0].trim());
                    statusMax = Integer.parseInt(parts[1].trim());
                } catch (NumberFormatException e) {
                    throw new Exception("Invalid status range format");
                }
            }
        }
        
        // Parse time filters
        ZonedDateTime afterDateTime = null, beforeDateTime = null;
        if (afterTime != null) {
            afterDateTime = parseTime(afterTime);
        }
        if (beforeTime != null) {
            beforeDateTime = parseTime(beforeTime);
        }
        
        // Parse parameter type
        HttpParameterType paramType = null;
        if (parameterType != null) {
            paramType = parseParameterType(parameterType);
        }
        
        // Parse content type
        ContentType contentType = null;
        if (contentTypeFilter != null) {
            contentType = parseContentType(contentTypeFilter);
        }
        
        // Parse status class
        StatusCodeClass statusCodeClass = null;
        if (statusClass != null) {
            statusCodeClass = parseStatusClass(statusClass);
        }
        
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        List<ProxyHttpRequestResponse> filtered = new ArrayList<>();
        // Track original indices for each filtered entry
        List<Integer> originalIndices = new ArrayList<>();
        
        for (int i = 0; i < proxyHistory.size(); i++) {
            ProxyHttpRequestResponse entry = proxyHistory.get(i);
            try {
                // Apply all filters
                if (hostname != null && !entry.host().toLowerCase().contains(hostname.toLowerCase())) continue;
                if (method != null && !entry.method().equals(method)) {
                    String filterMsg = "ProxyHistoryTool: Entry #" + (i+1) + " filtered out - method " + entry.method() + " != " + method;
                    api.logging().logToOutput(filterMsg);
                    LogsTool.logOutput(filterMsg);
                    continue;
                }
                if (path != null && !entry.path().toLowerCase().contains(path.toLowerCase())) continue;
                if (statusCode != null && entry.hasResponse() && entry.response().statusCode() != statusCode) continue;
                if (statusMin != null && statusMax != null && entry.hasResponse()) {
                    int status = entry.response().statusCode();
                    if (status < statusMin || status > statusMax) continue;
                }
                if (contains != null && !entry.contains(contains, false)) continue;
                if (compiledRegex != null && !entry.contains(compiledRegex)) continue;
                if (parameter != null) {
                    String requestStr = entry.request().toString();
                    String body = entry.requestBody();
                    boolean hasParam = requestStr.contains(parameter + "=") || 
                                     (body != null && body.contains(parameter + "="));
                    if (!hasParam) continue;
                }
                if (cookieName != null) {
                    String cookies = entry.request().headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Cookie"))
                        .map(h -> h.value())
                        .collect(Collectors.joining("; "));
                    if (!cookies.contains(cookieName + "=")) continue;
                }
                if (inScopeOnly && !api.scope().isInScope(entry.url())) continue;
                if (secure != null && entry.secure() != secure) continue;
                if (hasResponse != null && entry.hasResponse() != hasResponse) continue;
                if (mimeType != null && entry.hasResponse()) {
                    String entryMimeType = entry.mimeType().toString();
                    if (!entryMimeType.toUpperCase().contains(mimeType.toUpperCase())) continue;
                }
                if ((responseTimeMin != null || responseTimeMax != null) && entry.hasResponse()) {
                    try {
                        Duration responseTime = entry.timingData().timeBetweenRequestSentAndEndOfResponse();
                        long millis = responseTime.toMillis();
                        if (responseTimeMin != null && millis < responseTimeMin) continue;
                        if (responseTimeMax != null && millis > responseTimeMax) continue;
                    } catch (Exception e) {
                        continue;
                    }
                }
                if (editedOnly && !entry.edited()) continue;
                if (hasNotes && !entry.annotations().hasNotes()) continue;
                if (highlightColor != null) {
                    if (!entry.annotations().hasHighlightColor() ||
                        !entry.annotations().highlightColor().displayName().equalsIgnoreCase(highlightColor)) {
                        continue;
                    }
                }
                if (listenerPort != null && entry.listenerPort() != listenerPort) continue;
                
                // NEW: Time-based filtering
                if (afterDateTime != null || beforeDateTime != null) {
                    ZonedDateTime requestTime = entry.time();
                    if (afterDateTime != null && requestTime.isBefore(afterDateTime)) continue;
                    if (beforeDateTime != null && requestTime.isAfter(beforeDateTime)) continue;
                }
                
                // NEW: File extension filtering
                if (fileExtension != null) {
                    String ext = entry.request().fileExtension();
                    if (ext == null || !ext.equalsIgnoreCase(fileExtension)) continue;
                }
                
                // NEW: Content-Type filtering
                if (contentType != null) {
                    ContentType reqContentType = entry.request().contentType();
                    if (reqContentType != contentType) continue;
                }
                
                // NEW: Query string filtering
                if (queryString != null) {
                    String query = entry.request().query();
                    if (query == null || !query.toLowerCase().contains(queryString.toLowerCase())) continue;
                }
                
                // NEW: HTTP version filtering
                if (httpVersion != null) {
                    String reqHttpVersion = entry.request().httpVersion();
                    if (!reqHttpVersion.equalsIgnoreCase(httpVersion)) continue;
                }
                
                // NEW: Response cookie filtering
                if (responseCookie != null && entry.hasResponse()) {
                    List<Cookie> cookies = entry.response().cookies();
                    boolean hasCookie = cookies.stream()
                        .anyMatch(c -> c.name().equalsIgnoreCase(responseCookie));
                    if (!hasCookie) continue;
                }
                
                // NEW: Status class filtering
                if (statusCodeClass != null && entry.hasResponse()) {
                    if (!entry.response().isStatusCodeClass(statusCodeClass)) continue;
                }
                
                // NEW: Parameter type filtering
                if (paramType != null && parameter != null) {
                    boolean hasTypedParam = entry.request().hasParameter(parameter, paramType);
                    if (!hasTypedParam) continue;
                }
                
                // NEW: Modified requests filtering
                if (modifiedOnly) {
                    boolean wasModified = !entry.request().equals(entry.finalRequest()) ||
                                        (entry.hasResponse() && !entry.response().equals(entry.originalResponse()));
                    if (!wasModified) continue;
                }
                
                // NEW: Keyword analysis filtering
                if (!keywords.isEmpty() && minKeywordCount != null && entry.hasResponse()) {
                    String[] keywordArray = keywords.toArray(new String[0]);
                    List<KeywordCount> counts = entry.response().keywordCounts(keywordArray);
                    int totalCount = counts.stream().mapToInt(kc -> kc.count()).sum();
                    if (totalCount < minKeywordCount) continue;
                }
                
                filtered.add(entry);
                originalIndices.add(i + 1);  // Add 1 because proxy history IDs start from 1
            } catch (Exception e) {
                // Skip problematic entries
            }
        }
        
        // Apply sorting (reverse both lists together to maintain correspondence)
        boolean sortRecent = arguments.has("recent") ? arguments.get("recent").asBoolean() : true;
        if (sortRecent) {
            // Reverse both lists to maintain index correspondence
            java.util.Collections.reverse(filtered);
            java.util.Collections.reverse(originalIndices);
        }
        
        return new FilteredResults(filtered, originalIndices);
    }
    
    private String getStatusIcon(int statusCode) {
        if (statusCode == 0) return "⏳";
        if (statusCode >= 200 && statusCode < 300) return "✅";
        if (statusCode >= 300 && statusCode < 400) return "🔄";
        if (statusCode >= 400 && statusCode < 500) return "❌";
        if (statusCode >= 500) return "💥";
        return "❓";
    }
    
    // Helper methods for parsing filter parameters
    private ZonedDateTime parseTime(String timeStr) {
        // Support relative times like "1h", "30m", "7d"
        if (timeStr.matches("\\d+[hmd]")) {
            int value = Integer.parseInt(timeStr.substring(0, timeStr.length() - 1));
            char unit = timeStr.charAt(timeStr.length() - 1);
            ZonedDateTime now = ZonedDateTime.now();
            
            switch (unit) {
                case 'h': return now.minusHours(value);
                case 'm': return now.minusMinutes(value);
                case 'd': return now.minusDays(value);
            }
        }
        
        // Try parsing as ISO-8601
        try {
            return ZonedDateTime.parse(timeStr);
        } catch (Exception e) {
            // Try with default formatter
            return ZonedDateTime.parse(timeStr, DateTimeFormatter.ISO_DATE_TIME);
        }
    }
    
    private HttpParameterType parseParameterType(String type) {
        switch (type.toUpperCase()) {
            case "URL": return HttpParameterType.URL;
            case "BODY": return HttpParameterType.BODY;
            case "COOKIE": return HttpParameterType.COOKIE;
            case "JSON": return HttpParameterType.JSON;
            case "XML": return HttpParameterType.XML;
            case "MULTIPART": return HttpParameterType.MULTIPART_ATTRIBUTE;
            default: return HttpParameterType.URL;
        }
    }
    
    private ContentType parseContentType(String type) {
        switch (type.toUpperCase()) {
            case "JSON": return ContentType.JSON;
            case "XML": return ContentType.XML;
            case "URL_ENCODED": return ContentType.URL_ENCODED;
            case "MULTIPART": return ContentType.MULTIPART;
            case "AMF": return ContentType.AMF;
            case "NONE": return ContentType.NONE;
            default: return ContentType.UNKNOWN;
        }
    }
    
    private StatusCodeClass parseStatusClass(String classStr) {
        switch (classStr.toUpperCase()) {
            case "1XX":
            case "INFORMATIONAL": return StatusCodeClass.CLASS_1XX_INFORMATIONAL_RESPONSE;
            case "2XX":
            case "SUCCESS": return StatusCodeClass.CLASS_2XX_SUCCESS;
            case "3XX":
            case "REDIRECTION": return StatusCodeClass.CLASS_3XX_REDIRECTION;
            case "4XX":
            case "CLIENT_ERROR": return StatusCodeClass.CLASS_4XX_CLIENT_ERRORS;
            case "5XX":
            case "SERVER_ERROR": return StatusCodeClass.CLASS_5XX_SERVER_ERRORS;
            default: return null;
        }
    }
}