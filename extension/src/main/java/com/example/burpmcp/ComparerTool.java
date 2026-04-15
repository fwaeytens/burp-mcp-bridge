package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class ComparerTool implements McpTool {
    private final MontoyaApi api;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "COMPARE_RESPONSES",
        "COMPARE_REQUESTS",
        "COMPARE_TEXT",
        "SEND_TO_COMPARER",
        "COMPARE_PROXY_ENTRIES"
    );
    
    public ComparerTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_comparer");
        tool.put("title", "Response Comparer");
        tool.put("description", "Compare HTTP requests, responses, and other data. " +
                "Use this to identify differences between two pieces of data, useful for finding subtle changes in responses that indicate vulnerabilities. " +
                "Actions: COMPARE_RESPONSES, COMPARE_REQUESTS, COMPARE_TEXT, SEND_TO_COMPARER (opens Burp UI), COMPARE_PROXY_ENTRIES. " +
                "Supports word-level and byte-level comparison with optional whitespace ignoring.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", true);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", true);
        annotations.put("openWorldHint", false);
        annotations.put("title", "Response Comparer");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "diff compare two responses bytes words");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Comparison action to perform");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);
        
        Map<String, Object> url1Property = new HashMap<>();
        url1Property.put("type", "string");
        url1Property.put("description", "First URL for comparison (for proxy entry comparison)");
        properties.put("url1", url1Property);
        
        Map<String, Object> url2Property = new HashMap<>();
        url2Property.put("type", "string");
        url2Property.put("description", "Second URL for comparison (for proxy entry comparison)");
        properties.put("url2", url2Property);
        
        Map<String, Object> text1Property = new HashMap<>();
        text1Property.put("type", "string");
        text1Property.put("description", "First text/data for comparison");
        properties.put("text1", text1Property);
        
        Map<String, Object> text2Property = new HashMap<>();
        text2Property.put("type", "string");
        text2Property.put("description", "Second text/data for comparison");
        properties.put("text2", text2Property);
        
        Map<String, Object> comparisonTypeProperty = new HashMap<>();
        comparisonTypeProperty.put("type", "string");
        comparisonTypeProperty.put("description", "Type of comparison to perform");
        comparisonTypeProperty.put("enum", List.of("WORDS", "BYTES", "HEADERS_ONLY", "BODY_ONLY"));
        comparisonTypeProperty.put("default", "WORDS");
        properties.put("comparisonType", comparisonTypeProperty);
        
        Map<String, Object> ignoreWhitespaceProperty = new HashMap<>();
        ignoreWhitespaceProperty.put("type", "boolean");
        ignoreWhitespaceProperty.put("description", "Ignore whitespace differences");
        ignoreWhitespaceProperty.put("default", false);
        properties.put("ignoreWhitespace", ignoreWhitespaceProperty);
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return McpUtils.createErrorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        
        try {
            StringBuilder result = new StringBuilder();
            
            switch (action) {
                case "COMPARE_RESPONSES":
                    return compareResponses(arguments, result);
                case "COMPARE_REQUESTS":
                    return compareRequests(arguments, result);
                case "COMPARE_TEXT":
                    return compareText(arguments, result);
                case "SEND_TO_COMPARER":
                    return sendToComparer(arguments, result);
                case "COMPARE_PROXY_ENTRIES":
                    return compareProxyEntries(arguments, result);
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in Comparer tool: " + e.getMessage());
            
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("type", "text");
            errorResult.put("text", "❌ Error in Comparer operation: " + e.getMessage());
            
            return List.of(errorResult);
        }
    }
    
    private Object compareResponses(JsonNode arguments, StringBuilder result) {
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";

        if (url1.isEmpty() || url2.isEmpty()) {
            return McpUtils.createErrorResponse("Both url1 and url2 are required for response comparison");
        }

        try {
            HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
            HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
            HttpRequestResponse response1 = api.http().sendRequest(request1);
            HttpRequestResponse response2 = api.http().sendRequest(request2);

            if (response1.response() == null || response2.response() == null) {
                return McpUtils.createErrorResponse("Failed to retrieve one or both responses");
            }

            int status1 = response1.response().statusCode();
            int status2 = response2.response().statusCode();
            String body1 = response1.response().bodyToString();
            String body2 = response2.response().bodyToString();
            boolean identical = body1.equals(body2);

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("url1", url1);
                data.put("url2", url2);
                data.put("statusCode1", status1);
                data.put("statusCode2", status2);
                data.put("statusMatch", status1 == status2);
                data.put("bodyLength1", body1.length());
                data.put("bodyLength2", body2.length());
                data.put("lengthMatch", body1.length() == body2.length());
                data.put("bodiesIdentical", identical);
                return McpUtils.createJsonResponse(data);
            }

            result.append("🔍 **RESPONSE COMPARISON**\n\n");
            result.append("**URL 1:** ").append(url1).append("\n");
            result.append("**URL 2:** ").append(url2).append("\n\n");
            result.append("**Status Codes:** ").append(status1).append(" vs ").append(status2);
            if (status1 != status2) result.append(" ⚠️");
            result.append("\n");
            result.append("**Content Length:** ").append(body1.length()).append(" vs ").append(body2.length()).append(" bytes");
            if (body1.length() != body2.length()) result.append(" ⚠️");
            result.append("\n\n");
            if (identical) {
                result.append("✅ **Response bodies are identical**\n");
            } else {
                result.append("⚠️ **Response bodies differ**\n");
            }
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error during comparison: " + e.getMessage());
        }
    }
    
    private Object compareRequests(JsonNode arguments, StringBuilder result) {
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";

        if (url1.isEmpty() || url2.isEmpty()) {
            return McpUtils.createErrorResponse("Both url1 and url2 are required for request comparison");
        }

        try {
            HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
            HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
            String method1 = request1.method();
            String method2 = request2.method();
            String path1 = request1.path();
            String path2 = request2.path();
            int headers1 = request1.headers().size();
            int headers2 = request2.headers().size();
            int body1 = request1.body().length();
            int body2 = request2.body().length();

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("url1", url1);
                data.put("url2", url2);
                data.put("method1", method1);
                data.put("method2", method2);
                data.put("methodsMatch", method1.equals(method2));
                data.put("path1", path1);
                data.put("path2", path2);
                data.put("pathsMatch", path1.equals(path2));
                data.put("headerCount1", headers1);
                data.put("headerCount2", headers2);
                data.put("bodySize1", body1);
                data.put("bodySize2", body2);
                return McpUtils.createJsonResponse(data);
            }

            result.append("🔍 **REQUEST COMPARISON**\n\n");
            result.append("**URL 1:** ").append(url1).append("\n");
            result.append("**URL 2:** ").append(url2).append("\n\n");
            result.append("**HTTP Methods:** ").append(method1).append(" vs ").append(method2);
            if (!method1.equals(method2)) result.append(" ⚠️");
            result.append("\n**Paths:** ").append(path1).append(" vs ").append(path2);
            if (!path1.equals(path2)) result.append(" ⚠️");
            result.append("\n**Header Count:** ").append(headers1).append(" vs ").append(headers2);
            if (headers1 != headers2) result.append(" ⚠️");
            result.append("\n**Body Size:** ").append(body1).append(" vs ").append(body2).append(" bytes");
            if (body1 != body2) result.append(" ⚠️");
            result.append("\n");
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error during comparison: " + e.getMessage());
        }
    }
    
    private Object compareText(JsonNode arguments, StringBuilder result) {
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        boolean ignoreWhitespace = arguments.has("ignoreWhitespace") && arguments.get("ignoreWhitespace").asBoolean();

        if (text1.isEmpty() || text2.isEmpty()) {
            return McpUtils.createErrorResponse("Both text1 and text2 are required for text comparison");
        }

        String compareText1 = ignoreWhitespace ? text1.replaceAll("\\s+", " ").trim() : text1;
        String compareText2 = ignoreWhitespace ? text2.replaceAll("\\s+", " ").trim() : text2;
        boolean identical = compareText1.equals(compareText2);

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("length1", text1.length());
            data.put("length2", text2.length());
            data.put("lengthMatch", text1.length() == text2.length());
            data.put("ignoreWhitespace", ignoreWhitespace);
            if (ignoreWhitespace) {
                data.put("normalizedLength1", compareText1.length());
                data.put("normalizedLength2", compareText2.length());
            }
            data.put("identical", identical);
            if (!identical) {
                data.put("preview1", text1.substring(0, Math.min(200, text1.length())));
                data.put("preview2", text2.substring(0, Math.min(200, text2.length())));
            }
            return McpUtils.createJsonResponse(data);
        }

        result.append("📝 **TEXT COMPARISON**\n\n");
        result.append("**Length:** ").append(text1.length()).append(" vs ").append(text2.length()).append(" chars\n");
        if (ignoreWhitespace) {
            result.append("**Normalized Length:** ").append(compareText1.length()).append(" vs ").append(compareText2.length()).append("\n");
        }
        if (identical) {
            result.append("\n✅ **Texts are identical");
            if (ignoreWhitespace) result.append(" (ignoring whitespace)");
            result.append("**\n");
        } else {
            result.append("\n⚠️ **Texts differ**\n\n");
            result.append("**Text 1 Preview:**\n```\n").append(text1.substring(0, Math.min(200, text1.length())));
            if (text1.length() > 200) result.append("...");
            result.append("\n```\n\n**Text 2 Preview:**\n```\n").append(text2.substring(0, Math.min(200, text2.length())));
            if (text2.length() > 200) result.append("...");
            result.append("\n```\n");
        }
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object sendToComparer(JsonNode arguments, StringBuilder result) {
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        List<String> sent = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        if (text1.isEmpty() && text2.isEmpty()) {
            String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
            String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
            if (!url1.isEmpty()) {
                try {
                    api.comparer().sendToComparer(HttpRequest.httpRequestFromUrl(url1).toByteArray());
                    sent.add("request:" + url1);
                } catch (Exception e) { errors.add("url1: " + e.getMessage()); }
            }
            if (!url2.isEmpty()) {
                try {
                    api.comparer().sendToComparer(HttpRequest.httpRequestFromUrl(url2).toByteArray());
                    sent.add("request:" + url2);
                } catch (Exception e) { errors.add("url2: " + e.getMessage()); }
            }
        } else {
            if (!text1.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(text1.getBytes()));
                sent.add("text1:" + text1.length() + "b");
            }
            if (!text2.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(text2.getBytes()));
                sent.add("text2:" + text2.length() + "b");
            }
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("sent", sent);
            if (!errors.isEmpty()) data.put("errors", errors);
            return McpUtils.createJsonResponse(data);
        }

        result.append("📤 **SEND TO COMPARER**\n\n");
        for (String s : sent) result.append("✅ Sent: ").append(s).append("\n");
        for (String e : errors) result.append("❌ Error: ").append(e).append("\n");
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object compareProxyEntries(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **PROXY ENTRY COMPARISON**\n\n");
        
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
        
        if (url1.isEmpty() || url2.isEmpty()) {
            return McpUtils.createErrorResponse("Both url1 and url2 are required for proxy entry comparison");
        }

        try {
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            ProxyHttpRequestResponse entry1 = null;
            ProxyHttpRequestResponse entry2 = null;

            for (ProxyHttpRequestResponse entry : proxyHistory) {
                String entryUrl = entry.finalRequest().url();
                if (entry1 == null && entryUrl.contains(url1)) entry1 = entry;
                if (entry2 == null && entryUrl.contains(url2)) entry2 = entry;
            }

            if (entry1 == null || entry2 == null) {
                Map<String, Object> data = new HashMap<>();
                data.put("error", "proxy_entries_not_found");
                data.put("entry1Found", entry1 != null);
                data.put("entry2Found", entry2 != null);
                return McpUtils.createJsonResponse(data);
            }

            api.comparer().sendToComparer(entry1.finalRequest().toByteArray());
            api.comparer().sendToComparer(entry2.finalRequest().toByteArray());

            if (!McpUtils.isVerbose(arguments)) {
                Map<String, Object> data = new HashMap<>();
                data.put("url1", entry1.finalRequest().url());
                data.put("url2", entry2.finalRequest().url());
                data.put("method1", entry1.finalRequest().method());
                data.put("method2", entry2.finalRequest().method());
                if (entry1.originalResponse() != null && entry2.originalResponse() != null) {
                    data.put("status1", entry1.originalResponse().statusCode());
                    data.put("status2", entry2.originalResponse().statusCode());
                    data.put("length1", entry1.originalResponse().body().length());
                    data.put("length2", entry2.originalResponse().body().length());
                }
                data.put("sentToComparer", true);
                return McpUtils.createJsonResponse(data);
            }

            result.append("🔍 **PROXY ENTRY COMPARISON**\n\n");
            result.append("**Request:**\n");
            result.append("• URL 1: ").append(entry1.finalRequest().url()).append("\n");
            result.append("• URL 2: ").append(entry2.finalRequest().url()).append("\n");
            result.append("• Method 1: ").append(entry1.finalRequest().method()).append("\n");
            result.append("• Method 2: ").append(entry2.finalRequest().method()).append("\n");
            if (entry1.originalResponse() != null && entry2.originalResponse() != null) {
                result.append("\n**Response:**\n");
                result.append("• Status 1: ").append(entry1.originalResponse().statusCode()).append("\n");
                result.append("• Status 2: ").append(entry2.originalResponse().statusCode()).append("\n");
                result.append("• Length 1: ").append(entry1.originalResponse().body().length()).append(" bytes\n");
                result.append("• Length 2: ").append(entry2.originalResponse().body().length()).append(" bytes\n");
            }
            result.append("\n✅ Both entries sent to Comparer for visual comparison\n");
            return McpUtils.createSuccessResponse(result.toString());

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error during proxy entry comparison: " + e.getMessage());
        }
    }
}
