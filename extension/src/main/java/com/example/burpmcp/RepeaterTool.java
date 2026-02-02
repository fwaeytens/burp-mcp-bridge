package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class RepeaterTool implements McpTool {
    private final MontoyaApi api;
    private static final AtomicInteger requestCounter = new AtomicInteger(0);

    public RepeaterTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_repeater");
        tool.put("title", "Repeater (UI Only)");
        tool.put("description", "Opens Burp Repeater UI tab for manual testing. " +
            "WARNING: This tool CANNOT send HTTP requests programmatically - it only creates UI tabs for human interaction. " +
            "To actually send and receive HTTP responses, use burp_custom_http instead. " +
            "Use this only when preparing requests for manual testing in the Burp UI.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", true);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProp = McpUtils.createProperty("string", "Action to perform");
        actionProp.put("enum", List.of("SEND_TO_REPEATER", "SEND_FROM_PROXY"));
        actionProp.put("default", "SEND_TO_REPEATER");
        properties.put("action", actionProp);
        
        properties.put("url", McpUtils.createProperty("string", "Target URL (for SEND_TO_REPEATER)"));
        properties.put("method", McpUtils.createProperty("string", "HTTP method (GET, POST, etc.)", "GET"));
        properties.put("headers", McpUtils.createProperty("string", "Custom headers (one per line)"));
        properties.put("body", McpUtils.createProperty("string", "Request body"));
        properties.put("tabName", McpUtils.createProperty("string", "Custom tab name in Repeater"));
        properties.put("proxyUrl", McpUtils.createProperty("string", "URL from proxy history to send (for SEND_FROM_PROXY)"));
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = McpUtils.getStringParam(arguments, "action", "SEND_TO_REPEATER");
        
        try {
            switch (action) {
                case "SEND_TO_REPEATER":
                    return sendNewRequestToRepeater(arguments);
                    
                case "SEND_FROM_PROXY":
                    return sendFromProxyToRepeater(arguments);
                    
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
        } catch (Exception e) {
            api.logging().logToError("Error in RepeaterTool: " + McpUtils.sanitizeForLogging(e.getMessage()));
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    private Object sendNewRequestToRepeater(JsonNode arguments) {
        String url = McpUtils.getStringParam(arguments, "url", null);
        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for SEND_TO_REPEATER action");
        }
        
        String method = McpUtils.getStringParam(arguments, "method", "GET");
        String customHeaders = McpUtils.getStringParam(arguments, "headers", "");
        String body = McpUtils.getStringParam(arguments, "body", "");
        String tabName = McpUtils.getStringParam(arguments, "tabName", null);
        
        try {
            // Create the HTTP request
            HttpRequest request = McpUtils.createSafeHttpRequest(url);
            if (!method.equals("GET")) {
                request = request.withMethod(method);
            }
            
            // Handle request body
            if (!body.isEmpty()) {
                request = request.withBody(body);
                
                // Auto-add Content-Type for POST requests if not specified
                boolean hasContentType = false;
                if (!customHeaders.isEmpty()) {
                    String[] headerLines = customHeaders.split("\n");
                    for (String headerLine : headerLines) {
                        if (headerLine.toLowerCase().startsWith("content-type:")) {
                            hasContentType = true;
                            break;
                        }
                    }
                }
                
                if (!hasContentType && method.equalsIgnoreCase("POST")) {
                    request = request.withAddedHeader("Content-Type", "application/x-www-form-urlencoded");
                }
            }
            
            // Add custom headers
            if (!customHeaders.isEmpty()) {
                String[] headerLines = customHeaders.split("\n");
                for (String headerLine : headerLines) {
                    if (headerLine.contains(":")) {
                        String[] parts = headerLine.split(":", 2);
                        request = request.withAddedHeader(parts[0].trim(), parts[1].trim());
                    }
                }
            }
            
            // Send to Repeater
            if (tabName == null || tabName.isEmpty()) {
                tabName = "MCP-" + requestCounter.incrementAndGet();
            }
            
            api.repeater().sendToRepeater(request, tabName);
            
            StringBuilder result = new StringBuilder();
            result.append("✅ **Request sent to Repeater**\n\n");
            result.append("**Tab Name:** ").append(tabName).append("\n");
            result.append("**URL:** ").append(url).append("\n");
            result.append("**Method:** ").append(method).append("\n");
            
            if (!customHeaders.isEmpty()) {
                result.append("\n**Custom Headers:**\n");
                String[] headerLines = customHeaders.split("\n");
                for (String headerLine : headerLines) {
                    result.append("  • ").append(headerLine).append("\n");
                }
            }
            
            if (!body.isEmpty()) {
                result.append("\n**Body:** ");
                if (body.length() > 100) {
                    result.append(body.substring(0, 100)).append("...");
                } else {
                    result.append(body);
                }
                result.append("\n");
            }
            
            result.append("\n📝 **Next Steps:**\n");
            result.append("1. Go to the **Repeater** tab in Burp Suite\n");
            result.append("2. Find the tab named '").append(tabName).append("'\n");
            result.append("3. Click 'Send' to execute the request\n");
            result.append("4. Modify and resend as needed for testing\n");
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to send to Repeater: " + e.getMessage());
        }
    }
    
    private Object sendFromProxyToRepeater(JsonNode arguments) {
        String proxyUrl = McpUtils.getStringParam(arguments, "proxyUrl", null);
        if (proxyUrl == null || proxyUrl.isEmpty()) {
            return McpUtils.createErrorResponse("proxyUrl is required for SEND_FROM_PROXY action");
        }
        
        String tabName = McpUtils.getStringParam(arguments, "tabName", null);
        
        try {
            // Find the request in proxy history
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            ProxyHttpRequestResponse foundItem = null;
            
            for (ProxyHttpRequestResponse item : proxyHistory) {
                if (item.finalRequest().url().equals(proxyUrl) || 
                    item.finalRequest().url().contains(proxyUrl)) {
                    foundItem = item;
                    break;
                }
            }
            
            if (foundItem == null) {
                return McpUtils.createErrorResponse("Could not find URL in proxy history: " + proxyUrl);
            }
            
            // Send to Repeater
            if (tabName == null || tabName.isEmpty()) {
                tabName = "Proxy-" + requestCounter.incrementAndGet();
            }
            
            api.repeater().sendToRepeater(foundItem.finalRequest(), tabName);
            
            StringBuilder result = new StringBuilder();
            result.append("✅ **Proxy request sent to Repeater**\n\n");
            result.append("**Tab Name:** ").append(tabName).append("\n");
            result.append("**URL:** ").append(foundItem.finalRequest().url()).append("\n");
            result.append("**Method:** ").append(foundItem.finalRequest().method()).append("\n");
            
            result.append("\n📝 **Next Steps:**\n");
            result.append("1. Go to the **Repeater** tab in Burp Suite\n");
            result.append("2. Find the tab named '").append(tabName).append("'\n");
            result.append("3. Click 'Send' to replay the request\n");
            result.append("4. Modify parameters for security testing\n");
            
            return McpUtils.createSuccessResponse(result.toString());
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to send from proxy: " + e.getMessage());
        }
    }
}