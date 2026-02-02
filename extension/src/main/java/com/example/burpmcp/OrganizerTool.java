package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.organizer.Organizer;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.organizer.OrganizerItemFilter;
import burp.api.montoya.organizer.OrganizerItemStatus;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OrganizerTool implements McpTool {
    private final MontoyaApi api;
    private final Organizer organizer;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "SEND_TO_ORGANIZER",
        "LIST_ITEMS",
        "LIST_ITEMS_FILTERED",
        "GET_ITEM_BY_ID",
        "GET_ITEM_COUNT",
        "GET_ITEM_STATUS"
    );

    public OrganizerTool(MontoyaApi api) {
        this.api = api;
        this.organizer = api.organizer();
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_organizer");
        tool.put("title", "Request Organizer");
        tool.put("description", "Manage and organize HTTP requests/responses in Burp's Organizer tool. " +
            "Use this to bookmark interesting requests, track testing progress, and organize findings. " +
            "Actions: SEND_TO_ORGANIZER (add requests), LIST_ITEMS (view all with filters), " +
            "GET_ITEM_BY_ID, GET_ITEM_COUNT, GET_ITEM_STATUS. " +
            "Supports status types: NEW, IN_PROGRESS, POSTPONED, DONE, IGNORED.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string", "Action to perform", SUPPORTED_ACTIONS));
        properties.put("url", McpUtils.createProperty("string", "URL to send to organizer or filter by (for SEND_TO_ORGANIZER and LIST_ITEMS_FILTERED)"));
        properties.put("method", McpUtils.createProperty("string", "HTTP method (for SEND_TO_ORGANIZER or filtering)", "GET"));
        properties.put("fromProxy", McpUtils.createProperty("boolean", "Send from proxy history instead of creating new request (for SEND_TO_ORGANIZER)", false));
        properties.put("limit", McpUtils.createProperty("integer", "Maximum number of items to return (for LIST_ITEMS operations, default 20)", 20));
        properties.put("statusFilter", McpUtils.createProperty("string", "Filter by status (for LIST_ITEMS_FILTERED)", 
            List.of("ALL", "NEW", "IN_PROGRESS", "POSTPONED", "DONE", "IGNORED")));
        properties.put("urlPattern", McpUtils.createProperty("string", "URL pattern to filter (supports partial matching for LIST_ITEMS_FILTERED)"));
        properties.put("methodFilter", McpUtils.createProperty("string", "HTTP method to filter by (for LIST_ITEMS_FILTERED)"));
        properties.put("itemId", McpUtils.createProperty("integer", "Item ID for GET_ITEM_BY_ID or GET_ITEM_STATUS"));
        
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
        
        switch (action) {
            case "SEND_TO_ORGANIZER":
                return sendToOrganizer(arguments);
            case "LIST_ITEMS":
                return listItems(arguments);
            case "LIST_ITEMS_FILTERED":
                return listItemsFiltered(arguments);
            case "GET_ITEM_BY_ID":
                return getItemById(arguments);
            case "GET_ITEM_COUNT":
                return getItemCount();
            case "GET_ITEM_STATUS":
                return getItemStatus(arguments);
            default:
                return McpUtils.createErrorResponse("Unknown action: " + action);
        }
    }
    
    private Object sendToOrganizer(JsonNode arguments) {
        StringBuilder result = new StringBuilder();
        
        boolean fromProxy = McpUtils.getBooleanParam(arguments, "fromProxy", false);
        
        if (fromProxy) {
            // Send from proxy history
            String url = arguments.has("url") ? arguments.get("url").asText() : null;
            if (url == null || url.isEmpty()) {
                return McpUtils.createErrorResponse("URL is required when sending from proxy history");
            }
            
            // Find in proxy history
            var proxyHistory = api.proxy().history();
            var matchingItem = proxyHistory.stream()
                .filter(item -> item.finalRequest().url().equals(url))
                .findFirst();
                
            if (matchingItem.isPresent()) {
                // Create a proper HttpRequestResponse from ProxyHttpRequestResponse
                HttpRequestResponse httpReqResp = HttpRequestResponse.httpRequestResponse(
                    matchingItem.get().finalRequest(), 
                    matchingItem.get().response()
                );
                organizer.sendToOrganizer(httpReqResp);
                result.append("✅ **Sent to Organizer from Proxy History**\n");
                result.append("**URL:** ").append(url).append("\n");
                result.append("**Method:** ").append(matchingItem.get().finalRequest().method()).append("\n");
            } else {
                return McpUtils.createErrorResponse("URL not found in proxy history: " + url);
            }
        } else {
            // Create new request
            String url = arguments.get("url").asText();
            String method = McpUtils.getStringParam(arguments, "method", "GET");
            
            try {
                HttpRequest request = McpUtils.createSafeHttpRequest(url);
                if (!method.equals("GET")) {
                    request = request.withMethod(method);
                }
                
                organizer.sendToOrganizer(request);
                
                result.append("✅ **Sent to Organizer**\n");
                result.append("**URL:** ").append(url).append("\n");
                result.append("**Method:** ").append(method).append("\n");
            } catch (Exception e) {
                return McpUtils.createErrorResponse("Failed to create request: " + e.getMessage());
            }
        }
        
        result.append("\n📋 **Next Steps:**\n");
        result.append("• Go to Burp Suite → Organizer tab\n");
        result.append("• View and manage organized items\n");
        result.append("• Use filters and search to find specific items\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object listItems(JsonNode arguments) {
        int limit = McpUtils.getIntParam(arguments, "limit", 20);
        
        List<OrganizerItem> items = organizer.items();
        int totalCount = items.size();
        
        // Limit the items
        if (items.size() > limit) {
            items = items.subList(0, limit);
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📂 **ORGANIZER ITEMS**\n\n");
        result.append("**Total Items:** ").append(totalCount);
        if (totalCount > limit) {
            result.append(" (showing first ").append(limit).append(")");
        }
        result.append("\n\n");
        
        if (items.isEmpty()) {
            result.append("*No items in Organizer*\n");
            result.append("\n💡 **Tip:** Use 'SEND_TO_ORGANIZER' to add items");
        } else {
            for (int i = 0; i < items.size(); i++) {
                OrganizerItem item = items.get(i);
                
                result.append("**Item #").append(i + 1).append("**\n");
                result.append("  **ID:** ").append(item.id()).append("\n");
                result.append("  **Status:** ").append(item.status().displayName()).append("\n");
                result.append("  **Request:** ").append(item.request().method()).append(" ");
                result.append(item.request().url()).append("\n");
                
                // Add response status if available
                if (item.hasResponse()) {
                    result.append("  **Response:** Status ").append(item.response().statusCode());
                    result.append(" | ").append(item.response().body().length()).append(" bytes");
                } else {
                    result.append("  **Response:** No response");
                }
                result.append("\n");
                
                // Add timing if available
                item.timingData().ifPresent(timing -> {
                    try {
                        long responseTime = timing.timeBetweenRequestSentAndEndOfResponse().toMillis();
                        result.append("  **Time:** ").append(responseTime).append("ms");
                    } catch (Exception e) {
                        // Timing might not be available
                    }
                });
                result.append("\n\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getItemCount() {
        int count = organizer.items().size();
        
        StringBuilder result = new StringBuilder();
        result.append("📊 **ORGANIZER STATUS**\n\n");
        result.append("**Total Items:** ").append(count).append("\n");
        
        if (count == 0) {
            result.append("\n*Organizer is empty*\n");
            result.append("\n💡 **Getting Started:**\n");
            result.append("• Use 'SEND_TO_ORGANIZER' to add items\n");
            result.append("• Or right-click requests in Burp Suite → 'Send to Organizer'");
        } else {
            result.append("\n💡 **Available Actions:**\n");
            result.append("• Use 'LIST_ITEMS' to view all items\n");
            result.append("• Use 'LIST_ITEMS_FILTERED' to filter by status/URL/method\n");
            result.append("• Use 'GET_ITEM_BY_ID' to view specific item\n");
            result.append("• Go to Organizer tab in Burp Suite for full management");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object listItemsFiltered(JsonNode arguments) {
        int limit = McpUtils.getIntParam(arguments, "limit", 20);
        String statusFilter = McpUtils.getStringParam(arguments, "statusFilter", "ALL");
        String urlPattern = McpUtils.getStringParam(arguments, "urlPattern", null);
        String methodFilter = McpUtils.getStringParam(arguments, "methodFilter", null);
        
        // Create a custom filter
        OrganizerItemFilter filter = item -> {
            // Status filter
            if (!statusFilter.equals("ALL")) {
                if (!item.status().name().equals(statusFilter)) {
                    return false;
                }
            }
            
            // URL pattern filter
            if (urlPattern != null && !urlPattern.isEmpty()) {
                if (!item.request().url().toLowerCase().contains(urlPattern.toLowerCase())) {
                    return false;
                }
            }
            
            // Method filter
            if (methodFilter != null && !methodFilter.isEmpty()) {
                if (!item.request().method().equalsIgnoreCase(methodFilter)) {
                    return false;
                }
            }
            
            return true;
        };
        
        List<OrganizerItem> items = organizer.items(filter);
        int totalMatched = items.size();
        
        // Limit the items
        if (items.size() > limit) {
            items = items.subList(0, limit);
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📂 **FILTERED ORGANIZER ITEMS**\n\n");
        
        // Show filter criteria
        result.append("**Filter Criteria:**\n");
        if (!statusFilter.equals("ALL")) {
            result.append("  • Status: ").append(statusFilter).append("\n");
        }
        if (urlPattern != null && !urlPattern.isEmpty()) {
            result.append("  • URL contains: ").append(urlPattern).append("\n");
        }
        if (methodFilter != null && !methodFilter.isEmpty()) {
            result.append("  • Method: ").append(methodFilter).append("\n");
        }
        result.append("\n");
        
        result.append("**Matched Items:** ").append(totalMatched);
        if (totalMatched > limit) {
            result.append(" (showing first ").append(limit).append(")");
        }
        result.append("\n\n");
        
        if (items.isEmpty()) {
            result.append("*No items match the filter criteria*\n");
        } else {
            for (int i = 0; i < items.size(); i++) {
                OrganizerItem item = items.get(i);
                
                result.append("**Item #").append(i + 1).append("**\n");
                result.append("  **ID:** ").append(item.id()).append("\n");
                result.append("  **Status:** ").append(item.status().displayName()).append("\n");
                result.append("  **Request:** ").append(item.request().method()).append(" ");
                result.append(item.request().url()).append("\n");
                
                if (item.hasResponse()) {
                    result.append("  **Response:** Status ").append(item.response().statusCode());
                    result.append(" | ").append(item.response().body().length()).append(" bytes\n");
                } else {
                    result.append("  **Response:** No response\n");
                }
                result.append("\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getItemById(JsonNode arguments) {
        if (!arguments.has("itemId")) {
            return McpUtils.createErrorResponse("itemId is required for GET_ITEM_BY_ID");
        }
        
        int targetId = arguments.get("itemId").asInt();
        
        // Find the item with matching ID
        List<OrganizerItem> items = organizer.items();
        OrganizerItem foundItem = null;
        
        for (OrganizerItem item : items) {
            if (item.id() == targetId) {
                foundItem = item;
                break;
            }
        }
        
        if (foundItem == null) {
            return McpUtils.createErrorResponse("Item with ID " + targetId + " not found in Organizer");
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📄 **ORGANIZER ITEM DETAILS**\n\n");
        
        result.append("**ID:** ").append(foundItem.id()).append("\n");
        result.append("**Status:** ").append(foundItem.status().displayName()).append("\n\n");
        
        result.append("**REQUEST:**\n");
        result.append("• **Method:** ").append(foundItem.request().method()).append("\n");
        result.append("• **URL:** ").append(foundItem.request().url()).append("\n");
        result.append("• **Headers:** ").append(foundItem.request().headers().size()).append(" headers\n");
        result.append("• **Body Length:** ").append(foundItem.request().body().length()).append(" bytes\n");
        
        if (foundItem.hasResponse()) {
            result.append("\n**RESPONSE:**\n");
            result.append("• **Status Code:** ").append(foundItem.response().statusCode()).append("\n");
            result.append("• **Reason Phrase:** ").append(foundItem.response().reasonPhrase()).append("\n");
            result.append("• **Headers:** ").append(foundItem.response().headers().size()).append(" headers\n");
            result.append("• **Body Length:** ").append(foundItem.response().body().length()).append(" bytes\n");
            
            // Add MIME type if available
            result.append("• **MIME Type:** ").append(foundItem.response().mimeType().toString()).append("\n");
        } else {
            result.append("\n**RESPONSE:** Not available\n");
        }
        
        // Add timing information
        foundItem.timingData().ifPresent(timing -> {
            result.append("\n**TIMING:**\n");
            try {
                result.append("• **Response Time:** ").append(timing.timeBetweenRequestSentAndEndOfResponse().toMillis()).append("ms\n");
            } catch (Exception e) {
                // Timing might not be available
            }
        });
        
        // Add annotations if any
        if (!foundItem.annotations().notes().isEmpty()) {
            result.append("\n**NOTES:** ").append(foundItem.annotations().notes()).append("\n");
        }
        if (foundItem.annotations().highlightColor() != null) {
            result.append("**HIGHLIGHT:** ").append(foundItem.annotations().highlightColor().toString()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getItemStatus(JsonNode arguments) {
        if (!arguments.has("itemId")) {
            return McpUtils.createErrorResponse("itemId is required for GET_ITEM_STATUS");
        }
        
        int targetId = arguments.get("itemId").asInt();
        
        // Find the item with matching ID
        List<OrganizerItem> items = organizer.items();
        OrganizerItem foundItem = null;
        
        for (OrganizerItem item : items) {
            if (item.id() == targetId) {
                foundItem = item;
                break;
            }
        }
        
        if (foundItem == null) {
            return McpUtils.createErrorResponse("Item with ID " + targetId + " not found in Organizer");
        }
        
        StringBuilder result = new StringBuilder();
        result.append("📊 **ITEM STATUS**\n\n");
        result.append("**Item ID:** ").append(foundItem.id()).append("\n");
        result.append("**Current Status:** ").append(foundItem.status().displayName()).append("\n");
        result.append("**URL:** ").append(foundItem.request().url()).append("\n\n");
        
        result.append("**Available Status Values:**\n");
        result.append("• NEW - Newly added item\n");
        result.append("• IN_PROGRESS - Currently being worked on\n");
        result.append("• POSTPONED - Deferred for later\n");
        result.append("• DONE - Completed\n");
        result.append("• IGNORED - Not relevant/skipped\n\n");
        
        result.append("💡 **Note:** Status can be changed in Burp Suite's Organizer tab");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
}
