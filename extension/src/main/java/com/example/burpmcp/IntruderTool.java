package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.*;
import burp.api.montoya.core.Range;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class IntruderTool implements McpTool {
    private final MontoyaApi api;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "SEND_TO_INTRUDER",
        "SEND_WITH_POSITIONS"
    );
    
    public IntruderTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_intruder");
        tool.put("title", "Intruder (UI Only)");
        tool.put("description", "Configures Burp Intruder UI for attack setup. " +
            "WARNING: This tool CANNOT execute attacks programmatically - it only configures the UI. " +
            "You must manually add payloads and click 'Start attack' in Burp UI. " +
            "For automated parameter fuzzing/testing, use burp_custom_http with a loop instead. " +
            "Use this only when setting up complex attacks for manual execution.");

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
        
        properties.put("action", McpUtils.createEnumProperty("string", "Intruder action to perform", SUPPORTED_ACTIONS));
        properties.put("url", McpUtils.createProperty("string", "Target URL for the attack"));
        
        Map<String, Object> methodProperty = new HashMap<>();
        methodProperty.put("type", "string");
        methodProperty.put("description", "HTTP method (GET, POST, etc.)");
        methodProperty.put("default", "GET");
        properties.put("method", methodProperty);
        
        Map<String, Object> headersProperty = new HashMap<>();
        headersProperty.put("type", "string");
        headersProperty.put("description", "Custom headers (one per line)");
        properties.put("headers", headersProperty);
        
        Map<String, Object> bodyProperty = new HashMap<>();
        bodyProperty.put("type", "string");
        bodyProperty.put("description", "Request body with attack positions marked using §value§");
        properties.put("body", bodyProperty);
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action", "url"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        if (!McpUtils.validateRequiredParams(arguments, "url")) {
            return McpUtils.createErrorResponse("Missing required parameter: url");
        }

        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return McpUtils.createErrorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        
        try {
            StringBuilder result = new StringBuilder();
            
            switch (action) {
                case "SEND_TO_INTRUDER":
                    return sendToIntruder(arguments, result);
                case "SEND_WITH_POSITIONS":
                    return sendWithPositions(arguments, result);
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in Intruder tool: " + McpUtils.sanitizeForLogging(e.getMessage()));
            return McpUtils.createErrorResponse("Error in Intruder operation: " + e.getMessage());
        }
    }
    
    private Object sendWithPositions(JsonNode arguments, StringBuilder result) {
        result.append("🎯 **SEND TO INTRUDER WITH POSITIONS**\n\n");
        
        String url = arguments.get("url").asText();
        String method = McpUtils.getStringParam(arguments, "method", "GET");
        String body = McpUtils.getStringParam(arguments, "body", "");
        String customHeaders = McpUtils.getStringParam(arguments, "headers", "");
        
        try {
            HttpRequest request = McpUtils.createSafeHttpRequest(url);
            if (!method.equals("GET")) {
                request = request.withMethod(method);
            }
            if (!body.isEmpty()) {
                request = request.withBody(body);
                // Add Content-Type if not specified for POST requests
                if (method.equalsIgnoreCase("POST") && !customHeaders.toLowerCase().contains("content-type")) {
                    request = request.withAddedHeader("Content-Type", "application/x-www-form-urlencoded");
                }
            }
            
            // Add custom headers
            if (!customHeaders.isEmpty()) {
                String[] headerLines = customHeaders.split("\n");
                for (String headerLine : headerLines) {
                    String trimmedLine = headerLine.trim();
                    if (!trimmedLine.isEmpty() && trimmedLine.contains(":")) {
                        String[] parts = trimmedLine.split(":", 2);
                        if (parts.length == 2) {
                            request = request.withAddedHeader(parts[0].trim(), parts[1].trim());
                        }
                    }
                }
            }
            
        // Find positions marked with § symbols and remove markers before sending to Intruder
        List<Range> positions = new ArrayList<>();
        String originalRequestStr = request.toString();
        Pattern pattern = Pattern.compile("§([^§]+)§");
        Matcher matcher = pattern.matcher(originalRequestStr);
        StringBuilder cleanedRequestBuilder = new StringBuilder();
        int lastIndex = 0;

        while (matcher.find()) {
            // Append content before the marker to the cleaned request
            cleanedRequestBuilder.append(originalRequestStr, lastIndex, matcher.start());

            // The actual value inside the markers should remain
            String markerValue = matcher.group(1);
            int start = cleanedRequestBuilder.length();
            cleanedRequestBuilder.append(markerValue);
            int end = cleanedRequestBuilder.length();
            positions.add(Range.range(start, end));

            result.append("📍 Position found: ").append(markerValue)
                  .append(" at offset ").append(start).append("-").append(end).append("\n");

            lastIndex = matcher.end();
        }

        // Append any remaining request data after the last marker
        cleanedRequestBuilder.append(originalRequestStr.substring(lastIndex));

        String cleanedRequestStr = cleanedRequestBuilder.toString();
        HttpRequest cleanedRequest = HttpRequest.httpRequest(request.httpService(), cleanedRequestStr);
        request = cleanedRequest;

        if (positions.isEmpty()) {
            result.append("⚠️ No § markers found. Mark positions with §value§ format.\n");
            result.append("Example: username=admin&password=§test§\n");
            // Still send to Intruder for manual position marking
            api.intruder().sendToIntruder(request);
            result.append("\n✅ Request sent to Intruder for manual position marking\n");
        } else {
            // Create HttpRequestTemplate with positions
            HttpRequestTemplate template = HttpRequestTemplate.httpRequestTemplate(request, positions);
            // Send to Intruder with marked positions
            api.intruder().sendToIntruder(request.httpService(), template);
            result.append("\n✅ Request sent to Intruder with ")
                  .append(positions.size()).append(" marked position(s)\n");
        }
            
            result.append("\n📋 **Next Steps in Burp UI:**\n");
            result.append("1. Go to **Intruder** tab → **Positions** tab\n");
            result.append("2. Verify positions are correctly marked\n");
            result.append("3. Go to **Payloads** tab\n");
            result.append("4. Select payload type (Simple list, Numbers, etc.)\n");
            result.append("5. Add your payloads manually\n");
            result.append("6. Choose attack type (Sniper, Battering Ram, etc.)\n");
            result.append("7. Click **Start attack**\n");
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object sendToIntruder(JsonNode arguments, StringBuilder result) {
        result.append("📤 **SEND TO INTRUDER**\n\n");
        
        String url = arguments.get("url").asText();
        String method = McpUtils.getStringParam(arguments, "method", "GET");
        String customHeaders = McpUtils.getStringParam(arguments, "headers", "");
        String body = McpUtils.getStringParam(arguments, "body", "");
        
        try {
            HttpRequest request = McpUtils.createSafeHttpRequest(url);
            if (!method.equals("GET")) {
                request = request.withMethod(method);
            }
            
            if (!body.isEmpty()) {
                request = request.withBody(body);
                // Add Content-Type if not specified for POST requests
                if (method.equalsIgnoreCase("POST") && !customHeaders.toLowerCase().contains("content-type")) {
                    request = request.withAddedHeader("Content-Type", "application/x-www-form-urlencoded");
                }
            }
            
            // Add custom headers
            if (!customHeaders.isEmpty()) {
                String[] headerLines = customHeaders.split("\n");
                for (String headerLine : headerLines) {
                    String trimmedLine = headerLine.trim();
                    if (!trimmedLine.isEmpty() && trimmedLine.contains(":")) {
                        String[] parts = trimmedLine.split(":", 2);
                        if (parts.length == 2) {
                            request = request.withAddedHeader(parts[0].trim(), parts[1].trim());
                        }
                    }
                }
            }
            
            // Send to Intruder for manual configuration
            api.intruder().sendToIntruder(request);
            
            result.append("✅ **Request sent to Intruder**\n\n");
            result.append("**Target:** ").append(url).append("\n");
            result.append("**Method:** ").append(method).append("\n");
            if (!body.isEmpty()) {
                result.append("**Body Length:** ").append(body.length()).append(" characters\n");
            }
            if (!customHeaders.isEmpty()) {
                result.append("**Custom Headers:** Added\n");
            }
            
            result.append("\n📋 **Manual Configuration Required:**\n");
            result.append("1. Go to **Intruder** tab\n");
            result.append("2. Click **Positions** tab → mark parameters with §\n");
            result.append("3. Click **Payloads** tab → add your payload list\n");
            result.append("4. Select attack type (top of Positions tab)\n");
            result.append("5. Click **Start attack**\n");
            
            result.append("\n💡 **Position Marking Tips:**\n");
            result.append("• Click \"Clear §\" then \"Add §\" to mark positions\n");
            result.append("• Or manually add § around values to replace\n");
            result.append("• Example: `username=admin&password=§test§`\n");
            
        } catch (Exception e) {
            result.append("❌ Error sending to Intruder: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
}
