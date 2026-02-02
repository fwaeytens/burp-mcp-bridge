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
        tool.put("annotations", annotations);
        
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
        result.append("🔍 **RESPONSE COMPARISON**\n\n");
        
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
        
        if (url1.isEmpty() || url2.isEmpty()) {
            result.append("❌ Both url1 and url2 are required for response comparison\n");
        } else {
            try {
                // Fetch responses from both URLs
                HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
                HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
                
                HttpRequestResponse response1 = api.http().sendRequest(request1);
                HttpRequestResponse response2 = api.http().sendRequest(request2);
                
                result.append("**URL 1:** ").append(url1).append("\n");
                result.append("**URL 2:** ").append(url2).append("\n\n");
                
                if (response1.response() != null && response2.response() != null) {
                    // Compare status codes
                    int status1 = response1.response().statusCode();
                    int status2 = response2.response().statusCode();
                    
                    result.append("**Status Codes:**\n");
                    result.append("• URL 1: ").append(status1);
                    if (status1 != status2) result.append(" ⚠️");
                    result.append("\n");
                    result.append("• URL 2: ").append(status2);
                    if (status1 != status2) result.append(" ⚠️");
                    result.append("\n\n");
                    
                    // Compare content length
                    String body1 = response1.response().bodyToString();
                    String body2 = response2.response().bodyToString();
                    
                    result.append("**Content Length:**\n");
                    result.append("• URL 1: ").append(body1.length()).append(" bytes");
                    if (body1.length() != body2.length()) result.append(" ⚠️");
                    result.append("\n");
                    result.append("• URL 2: ").append(body2.length()).append(" bytes");
                    if (body1.length() != body2.length()) result.append(" ⚠️");
                    result.append("\n\n");
                    
                    // Simple text comparison
                    if (body1.equals(body2)) {
                        result.append("✅ **Response bodies are identical**\n");
                    } else {
                        result.append("⚠️ **Response bodies differ**\n");
                        result.append("💡 Use 'SEND_TO_COMPARER' for detailed visual comparison\n");
                    }
                    
                } else {
                    result.append("❌ Failed to retrieve one or both responses\n");
                }
                
            } catch (Exception e) {
                result.append("❌ Error during comparison: ").append(e.getMessage()).append("\n");
            }
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object compareRequests(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **REQUEST COMPARISON**\n\n");
        
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
        
        if (url1.isEmpty() || url2.isEmpty()) {
            result.append("❌ Both url1 and url2 are required for request comparison\n");
        } else {
            try {
                HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
                HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
                
                result.append("**URL 1:** ").append(url1).append("\n");
                result.append("**URL 2:** ").append(url2).append("\n\n");
                
                // Compare methods
                String method1 = request1.method();
                String method2 = request2.method();
                result.append("**HTTP Methods:**\n");
                result.append("• URL 1: ").append(method1);
                if (!method1.equals(method2)) result.append(" ⚠️");
                result.append("\n");
                result.append("• URL 2: ").append(method2);
                if (!method1.equals(method2)) result.append(" ⚠️");
                result.append("\n\n");
                
                // Compare paths
                String path1 = request1.path();
                String path2 = request2.path();
                result.append("**Paths:**\n");
                result.append("• URL 1: ").append(path1);
                if (!path1.equals(path2)) result.append(" ⚠️");
                result.append("\n");
                result.append("• URL 2: ").append(path2);
                if (!path1.equals(path2)) result.append(" ⚠️");
                result.append("\n\n");
                
                // Compare header counts
                int headers1 = request1.headers().size();
                int headers2 = request2.headers().size();
                result.append("**Header Count:**\n");
                result.append("• URL 1: ").append(headers1).append(" headers");
                if (headers1 != headers2) result.append(" ⚠️");
                result.append("\n");
                result.append("• URL 2: ").append(headers2).append(" headers");
                if (headers1 != headers2) result.append(" ⚠️");
                result.append("\n\n");
                
                // Compare body presence
                boolean hasBody1 = request1.body().length() > 0;
                boolean hasBody2 = request2.body().length() > 0;
                result.append("**Request Body:**\n");
                result.append("• URL 1: ").append(hasBody1 ? "Present (" + request1.body().length() + " bytes)" : "None");
                if (hasBody1 != hasBody2) result.append(" ⚠️");
                result.append("\n");
                result.append("• URL 2: ").append(hasBody2 ? "Present (" + request2.body().length() + " bytes)" : "None");
                if (hasBody1 != hasBody2) result.append(" ⚠️");
                result.append("\n\n");
                
                result.append("💡 Use 'SEND_TO_COMPARER' for detailed visual comparison\n");
                
            } catch (Exception e) {
                result.append("❌ Error during comparison: ").append(e.getMessage()).append("\n");
            }
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object compareText(JsonNode arguments, StringBuilder result) {
        result.append("📝 **TEXT COMPARISON**\n\n");
        
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        boolean ignoreWhitespace = arguments.has("ignoreWhitespace") ? arguments.get("ignoreWhitespace").asBoolean() : false;
        
        if (text1.isEmpty() || text2.isEmpty()) {
            result.append("❌ Both text1 and text2 are required for text comparison\n");
        } else {
            String compareText1 = ignoreWhitespace ? text1.replaceAll("\\s+", " ").trim() : text1;
            String compareText2 = ignoreWhitespace ? text2.replaceAll("\\s+", " ").trim() : text2;
            
            result.append("**Length Comparison:**\n");
            result.append("• Text 1: ").append(text1.length()).append(" characters");
            if (text1.length() != text2.length()) result.append(" ⚠️");
            result.append("\n");
            result.append("• Text 2: ").append(text2.length()).append(" characters");
            if (text1.length() != text2.length()) result.append(" ⚠️");
            result.append("\n\n");
            
            if (ignoreWhitespace) {
                result.append("**Normalized Length (ignoring whitespace):**\n");
                result.append("• Text 1: ").append(compareText1.length()).append(" characters\n");
                result.append("• Text 2: ").append(compareText2.length()).append(" characters\n\n");
            }
            
            if (compareText1.equals(compareText2)) {
                result.append("✅ **Texts are identical");
                if (ignoreWhitespace) result.append(" (ignoring whitespace)");
                result.append("**\n");
            } else {
                result.append("⚠️ **Texts differ");
                if (ignoreWhitespace) result.append(" (even ignoring whitespace)");
                result.append("**\n\n");
                
                // Show preview of differences
                result.append("**Text 1 Preview:**\n");
                result.append("```\n").append(text1.substring(0, Math.min(200, text1.length())));
                if (text1.length() > 200) result.append("...");
                result.append("\n```\n\n");
                
                result.append("**Text 2 Preview:**\n");
                result.append("```\n").append(text2.substring(0, Math.min(200, text2.length())));
                if (text2.length() > 200) result.append("...");
                result.append("\n```\n\n");
                
                result.append("💡 Use 'SEND_TO_COMPARER' for detailed visual comparison\n");
            }
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object sendToComparer(JsonNode arguments, StringBuilder result) {
        result.append("📤 **SEND TO COMPARER**\n\n");
        
        String text1 = arguments.has("text1") ? arguments.get("text1").asText() : "";
        String text2 = arguments.has("text2") ? arguments.get("text2").asText() : "";
        
        if (text1.isEmpty() && text2.isEmpty()) {
            // If no text provided, try to use URLs
            String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
            String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
            
            if (!url1.isEmpty()) {
                try {
                    HttpRequest request1 = HttpRequest.httpRequestFromUrl(url1);
                    api.comparer().sendToComparer(request1.toByteArray());
                    result.append("✅ Request from ").append(url1).append(" sent to Comparer\n");
                } catch (Exception e) {
                    result.append("❌ Error sending URL1 to Comparer: ").append(e.getMessage()).append("\n");
                }
            }
            
            if (!url2.isEmpty()) {
                try {
                    HttpRequest request2 = HttpRequest.httpRequestFromUrl(url2);
                    api.comparer().sendToComparer(request2.toByteArray());
                    result.append("✅ Request from ").append(url2).append(" sent to Comparer\n");
                } catch (Exception e) {
                    result.append("❌ Error sending URL2 to Comparer: ").append(e.getMessage()).append("\n");
                }
            }
        } else {
            // Send text data to comparer
            if (!text1.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(text1.getBytes()));
                result.append("✅ Text 1 sent to Comparer (").append(text1.length()).append(" bytes)\n");
            }
            
            if (!text2.isEmpty()) {
                api.comparer().sendToComparer(ByteArray.byteArray(text2.getBytes()));
                result.append("✅ Text 2 sent to Comparer (").append(text2.length()).append(" bytes)\n");
            }
        }
        
        result.append("\n📋 **Next Steps:**\n");
        result.append("1. Go to Burp Suite → Comparer tab\n");
        result.append("2. Select the items you want to compare\n");
        result.append("3. Choose comparison type (Words/Bytes)\n");
        result.append("4. Review the highlighted differences\n");
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
    
    private Object compareProxyEntries(JsonNode arguments, StringBuilder result) {
        result.append("🔍 **PROXY ENTRY COMPARISON**\n\n");
        
        String url1 = arguments.has("url1") ? arguments.get("url1").asText() : "";
        String url2 = arguments.has("url2") ? arguments.get("url2").asText() : "";
        
        if (url1.isEmpty() || url2.isEmpty()) {
            result.append("❌ Both url1 and url2 are required for proxy entry comparison\n");
        } else {
            try {
                List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                ProxyHttpRequestResponse entry1 = null;
                ProxyHttpRequestResponse entry2 = null;
                
                // Find matching proxy entries
                for (ProxyHttpRequestResponse entry : proxyHistory) {
                    String entryUrl = entry.finalRequest().url();
                    if (entryUrl.contains(url1)) {
                        entry1 = entry;
                    }
                    if (entryUrl.contains(url2)) {
                        entry2 = entry;
                    }
                }
                
                if (entry1 == null) {
                    result.append("❌ No proxy entry found for URL1: ").append(url1).append("\n");
                }
                if (entry2 == null) {
                    result.append("❌ No proxy entry found for URL2: ").append(url2).append("\n");
                }
                
                if (entry1 != null && entry2 != null) {
                    result.append("✅ **Found proxy entries for comparison**\n\n");
                    
                    // Compare request details
                    result.append("**Request Comparison:**\n");
                    result.append("• URL 1: ").append(entry1.finalRequest().url()).append("\n");
                    result.append("• URL 2: ").append(entry2.finalRequest().url()).append("\n");
                    result.append("• Method 1: ").append(entry1.finalRequest().method()).append("\n");
                    result.append("• Method 2: ").append(entry2.finalRequest().method()).append("\n\n");
                    
                    // Compare responses if available
                    if (entry1.originalResponse() != null && entry2.originalResponse() != null) {
                        result.append("**Response Comparison:**\n");
                        result.append("• Status 1: ").append(entry1.originalResponse().statusCode()).append("\n");
                        result.append("• Status 2: ").append(entry2.originalResponse().statusCode()).append("\n");
                        result.append("• Length 1: ").append(entry1.originalResponse().body().length()).append(" bytes\n");
                        result.append("• Length 2: ").append(entry2.originalResponse().body().length()).append(" bytes\n\n");
                    }
                    
                    // Send to comparer for detailed analysis
                    api.comparer().sendToComparer(entry1.finalRequest().toByteArray());
                    api.comparer().sendToComparer(entry2.finalRequest().toByteArray());
                    
                    result.append("✅ **Both entries sent to Comparer for detailed analysis**\n");
                    result.append("💡 Check the Comparer tab in Burp Suite for visual comparison\n");
                }
                
            } catch (Exception e) {
                result.append("❌ Error during proxy entry comparison: ").append(e.getMessage()).append("\n");
            }
        }
        
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("type", "text");
        resultMap.put("text", result.toString());
        
        return List.of(resultMap);
    }
}
