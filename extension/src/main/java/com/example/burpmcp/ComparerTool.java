package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ComparerTool implements McpTool {
    private final MontoyaApi api;
    private static final int MAX_COMPARISON_BYTES = 1024 * 1024;
    private static final int MAX_PREVIEW_CHARACTERS = 1024;
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
        tool.put("description", "Compare text or HTTP messages with bounded change summaries. " +
                "COMPARE_RESPONSES sends fresh GET requests to both URLs and compares their responses. " +
                "COMPARE_REQUESTS constructs GET requests from URLs without sending them. COMPARE_TEXT compares supplied text. " +
                "COMPARE_PROXY_ENTRIES selects the first proxy entry matching each URL substring, compares the captured requests, " +
                "and sends those requests to Comparer UI. SEND_TO_COMPARER only sends supplied text or constructed requests to the UI. " +
                "Comparisons report one changed span after removing the common prefix and suffix, with bounded previews. " +
                "Each selected message section or UTF-8 text input is limited to 1 MiB.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
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
        url1Property.put("description", "First URL for constructed requests or fresh response retrieval; URL substring for COMPARE_PROXY_ENTRIES.");
        properties.put("url1", url1Property);
        
        Map<String, Object> url2Property = new HashMap<>();
        url2Property.put("type", "string");
        url2Property.put("description", "Second URL for constructed requests or fresh response retrieval; URL substring for COMPARE_PROXY_ENTRIES.");
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
        comparisonTypeProperty.put("description", "WORDS compares UTF-8 word/whitespace tokens; BYTES compares exact bytes (UTF-8 for supplied text). HEADERS_ONLY compares the HTTP start line and headers; BODY_ONLY compares HTTP body bytes. HTTP section modes require a COMPARE_* HTTP action. Not accepted by SEND_TO_COMPARER. Previews are bounded and the selected inputs must each fit within 1 MiB.");
        comparisonTypeProperty.put("enum", List.of("WORDS", "BYTES", "HEADERS_ONLY", "BODY_ONLY"));
        comparisonTypeProperty.put("default", "WORDS");
        properties.put("comparisonType", comparisonTypeProperty);
        
        Map<String, Object> ignoreWhitespaceProperty = new HashMap<>();
        ignoreWhitespaceProperty.put("type", "boolean");
        ignoreWhitespaceProperty.put("description", "Normalize whitespace for WORDS, HEADERS_ONLY, or BODY_ONLY. Not supported by BYTES or SEND_TO_COMPARER.");
        ignoreWhitespaceProperty.put("default", false);
        properties.put("ignoreWhitespace", ignoreWhitespaceProperty);

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        tool.put("inputSchema", inputSchema);
        tool.put("outputSchema", WorkflowOutputSchemas.forTool("burp_comparer"));
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return errorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        
        try {
            validateComparisonOptions(action, arguments);
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
            
            return errorResponse("Error in Comparer operation: " + e.getMessage());
        }
    }
    
    private Object compareResponses(JsonNode arguments, StringBuilder result) {
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";

        if (url1.isEmpty() || url2.isEmpty()) {
            return errorResponse("Both url1 and url2 are required for response comparison");
        }

        try {
            HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
            HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
            HttpRequestResponse response1 = api.http().sendRequest(request1);
            HttpRequestResponse response2 = api.http().sendRequest(request2);

            if (response1.response() == null || response2.response() == null) {
                return errorResponse("Failed to retrieve one or both responses");
            }

            int status1 = response1.response().statusCode();
            int status2 = response2.response().statusCode();
            String body1 = response1.response().bodyToString();
            String body2 = response2.response().bodyToString();
            boolean identical = body1.equals(body2);
            Map<String, Object> comparison = compareMessages(response1.response(), response2.response(), arguments);

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
                data.put("comparison", comparison);
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
            result.append("\nComparison: ").append(comparison).append("\n");
            return textResponse(result.toString());

        } catch (Exception e) {
            return errorResponse("Error during comparison: " + e.getMessage());
        }
    }
    
    private Object compareRequests(JsonNode arguments, StringBuilder result) {
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";

        if (url1.isEmpty() || url2.isEmpty()) {
            return errorResponse("Both url1 and url2 are required for request comparison");
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
            Map<String, Object> comparison = compareMessages(request1, request2, arguments);

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
                data.put("comparison", comparison);
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
            result.append("\nComparison: ").append(comparison).append("\n");
            return textResponse(result.toString());

        } catch (Exception e) {
            return errorResponse("Error during comparison: " + e.getMessage());
        }
    }
    
    private Object compareText(JsonNode arguments, StringBuilder result) {
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        boolean ignoreWhitespace = arguments.has("ignoreWhitespace") && arguments.get("ignoreWhitespace").asBoolean();

        if (text1.isEmpty() || text2.isEmpty()) {
            return errorResponse("Both text1 and text2 are required for text comparison");
        }

        String compareText1 = ignoreWhitespace ? text1.replaceAll("\\s+", " ").trim() : text1;
        String compareText2 = ignoreWhitespace ? text2.replaceAll("\\s+", " ").trim() : text2;
        boolean identical = compareText1.equals(compareText2);
        Map<String, Object> comparison = compareBytes(text1.getBytes(StandardCharsets.UTF_8),
            text2.getBytes(StandardCharsets.UTF_8), arguments, "text");

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
            data.put("comparison", comparison);
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
        result.append("\nComparison: ").append(comparison).append("\n");
        return textResponse(result.toString());
    }
    
    private Object sendToComparer(JsonNode arguments, StringBuilder result) {
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        boolean hasUrls = arguments.hasNonNull("url1") || arguments.hasNonNull("url2");
        if (!text1.isEmpty() || !text2.isEmpty()) {
            if (hasUrls) return errorResponse("SEND_TO_COMPARER accepts text or URLs in one call, not both");
        } else if (!hasUrls) {
            return errorResponse("SEND_TO_COMPARER requires text1, text2, url1, or url2");
        }
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
                api.comparer().sendToComparer(ByteArray.byteArray(text1.getBytes(StandardCharsets.UTF_8)));
                sent.add("text1:" + text1.length() + "b");
            }
            if (!text2.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(text2.getBytes(StandardCharsets.UTF_8)));
                sent.add("text2:" + text2.length() + "b");
            }
        }

        if (sent.isEmpty() && errors.isEmpty()) return errorResponse("No nonempty text or URL was supplied");
        if (!errors.isEmpty()) {
            return errorResponse(Map.of("sent", sent, "errors", errors, "error", "send_failed",
                "message", "One or more items could not be added to Comparer UI"));
        }
        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("sent", sent);
            return McpUtils.createJsonResponse(data);
        }

        result.append("📤 **SEND TO COMPARER**\n\n");
        for (String s : sent) result.append("✅ Sent: ").append(s).append("\n");
        for (String e : errors) result.append("❌ Error: ").append(e).append("\n");
        return textResponse(result.toString());
    }
    
    private void validateComparisonOptions(String action, JsonNode arguments) {
        if ("SEND_TO_COMPARER".equals(action)) {
            if (arguments.has("comparisonType") || arguments.has("ignoreWhitespace")) {
                throw new IllegalArgumentException("SEND_TO_COMPARER does not compute comparisons; omit comparisonType and ignoreWhitespace");
            }
            return;
        }
        String type = comparisonType(arguments);
        if (!List.of("WORDS", "BYTES", "HEADERS_ONLY", "BODY_ONLY").contains(type)) {
            throw new IllegalArgumentException("Unknown comparisonType: " + type);
        }
        if (arguments.has("ignoreWhitespace") && !arguments.get("ignoreWhitespace").isBoolean()) {
            throw new IllegalArgumentException("ignoreWhitespace must be a boolean");
        }
        if ("COMPARE_TEXT".equals(action) && (type.equals("HEADERS_ONLY") || type.equals("BODY_ONLY"))) {
            throw new IllegalArgumentException(type + " requires an HTTP comparison action");
        }
        if (type.equals("BYTES") && arguments.path("ignoreWhitespace").asBoolean(false)) {
            throw new IllegalArgumentException("BYTES compares exact bytes; ignoreWhitespace must be false");
        }
    }

    private static String comparisonType(JsonNode arguments) {
        return arguments.has("comparisonType") ? arguments.get("comparisonType").asText() : "WORDS";
    }

    private Map<String, Object> compareMessages(HttpMessage first, HttpMessage second, JsonNode arguments) {
        String type = comparisonType(arguments);
        String scope = type.equals("HEADERS_ONLY") ? "headers" : type.equals("BODY_ONLY") ? "body" : "message";
        return compareBytes(messageBytes(first, scope), messageBytes(second, scope), arguments, scope);
    }

    private byte[] messageBytes(HttpMessage message, String scope) {
        ByteArray bytes = scope.equals("body") ? message.body() : message.toByteArray();
        int length = scope.equals("headers") ? message.bodyOffset() : bytes.length();
        if (length < 0 || length > MAX_COMPARISON_BYTES) {
            throw new IllegalArgumentException("Selected comparison input exceeds the 1 MiB limit");
        }
        return (scope.equals("headers") ? bytes.subArray(0, length) : bytes).getBytes();
    }

    private Map<String, Object> compareBytes(byte[] first, byte[] second, JsonNode arguments, String scope) {
        if (first.length > MAX_COMPARISON_BYTES || second.length > MAX_COMPARISON_BYTES) {
            throw new IllegalArgumentException("Selected comparison input exceeds the 1 MiB limit");
        }
        String type = comparisonType(arguments);
        boolean words = type.equals("WORDS");
        boolean ignoreWhitespace = arguments.path("ignoreWhitespace").asBoolean(false);
        // A byte maps to one Latin-1 character in exact byte/HTTP-section modes.
        String left = new String(first, words ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
        String right = new String(second, words ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
        if (ignoreWhitespace) {
            left = left.replaceAll("\\s+", " ").trim();
            right = right.replaceAll("\\s+", " ").trim();
        }
        List<String> leftWords = words ? tokens(left) : List.of();
        List<String> rightWords = words ? tokens(right) : List.of();
        int leftSize = words ? leftWords.size() : left.length();
        int rightSize = words ? rightWords.size() : right.length();
        int prefix = 0;
        while (prefix < Math.min(leftSize, rightSize) && (words
                ? leftWords.get(prefix).equals(rightWords.get(prefix))
                : left.charAt(prefix) == right.charAt(prefix))) prefix++;
        int suffix = 0;
        while (suffix < Math.min(leftSize, rightSize) - prefix && (words
                ? leftWords.get(leftSize - suffix - 1).equals(rightWords.get(rightSize - suffix - 1))
                : left.charAt(leftSize - suffix - 1) == right.charAt(rightSize - suffix - 1))) suffix++;
        String removed = words ? String.join("", leftWords.subList(prefix, leftSize - suffix)) : left.substring(prefix, leftSize - suffix);
        String added = words ? String.join("", rightWords.subList(prefix, rightSize - suffix)) : right.substring(prefix, rightSize - suffix);
        int previewLimit = words ? MAX_PREVIEW_CHARACTERS : 512;
        String removedPreview = removed.substring(0, Math.min(removed.length(), previewLimit));
        String addedPreview = added.substring(0, Math.min(added.length(), previewLimit));
        if (!words) {
            removedPreview = Base64.getEncoder().encodeToString(removedPreview.getBytes(StandardCharsets.ISO_8859_1));
            addedPreview = Base64.getEncoder().encodeToString(addedPreview.getBytes(StandardCharsets.ISO_8859_1));
        }
        Map<String, Object> data = new HashMap<>();
        data.put("type", type);
        data.put("scope", scope);
        data.put("unit", words ? "token" : "byte");
        data.put("ignoreWhitespace", ignoreWhitespace);
        data.put("identical", prefix == leftSize && prefix == rightSize);
        data.put("units1", leftSize);
        data.put("units2", rightSize);
        data.put("commonPrefixUnits", prefix);
        data.put("commonSuffixUnits", suffix);
        data.put("removedUnits", leftSize - prefix - suffix);
        data.put("addedUnits", rightSize - prefix - suffix);
        data.put("removedPreview", removedPreview);
        data.put("addedPreview", addedPreview);
        data.put("previewEncoding", words ? "text" : "base64");
        data.put("previewTruncated", removed.length() > previewLimit || added.length() > previewLimit);
        return data;
    }

    private static List<String> tokens(String value) {
        List<String> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("\\s+|\\S+").matcher(value);
        while (matcher.find()) result.add(matcher.group());
        return result;
    }

    private static Object textResponse(String text) {
        return Map.of("content", List.of(Map.of("type", "text", "text", text)),
            "structuredContent", Map.of("text", text));
    }

    private static Object errorResponse(String message) {
        return errorResponse(Map.of("error", "comparison_failed", "message", message));
    }

    private static Object errorResponse(Map<String, Object> data) {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) McpUtils.createJsonResponse(data);
        result.put("isError", true);
        return result;
    }

    private Object compareProxyEntries(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **PROXY ENTRY COMPARISON**\n\n");
        
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
        
        if (url1.isEmpty() || url2.isEmpty()) {
            return errorResponse("Both url1 and url2 are required for proxy entry comparison");
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
                data.put("message", "One or both proxy entries were not found");
                return errorResponse(data);
            }

            Map<String, Object> comparison = compareMessages(entry1.finalRequest(), entry2.finalRequest(), arguments);
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
                data.put("comparison", comparison);
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
            result.append("\nComparison: ").append(comparison).append("\n");
            return textResponse(result.toString());

        } catch (Exception e) {
            return errorResponse("Error during proxy entry comparison: " + e.getMessage());
        }
    }
}
