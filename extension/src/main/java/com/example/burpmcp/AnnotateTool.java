package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.logger.LoggerHttpRequestResponse;
import burp.api.montoya.organizer.OrganizerItem;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;

public class AnnotateTool implements McpTool {
    private final MontoyaApi api;
    private final Map<String, ProxyRequestHandler> activeHandlers = new ConcurrentHashMap<>();
    private final Map<String, Registration> handlerRegistrations = new ConcurrentHashMap<>();
    private final Map<String, Map<String, Object>> annotationDatabase = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Consolidated action list for reuse
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "ANNOTATE_PROXY", "ANNOTATE_TARGET", "ANNOTATE_ORGANIZER", "ANNOTATE_REPEATER",
        "ANNOTATE_INTRUDER", "ANNOTATE_SCANNER", "ANNOTATE_WEBSOCKET", "ANNOTATE_COLLABORATOR",
        "GET_ANNOTATIONS", "ANNOTATE_BY_PATTERN", "CLEAR_ANNOTATIONS",
        "EXPORT_ANNOTATIONS", "IMPORT_ANNOTATIONS", "SEARCH_BY_ANNOTATION",
        "ENABLE_AUTO_ANNOTATION", "DISABLE_AUTO_ANNOTATION"
    );

    private static final List<String> SOURCE_TYPES = List.of(
        "PROXY", "TARGET", "ORGANIZER", "REPEATER", "INTRUDER",
        "SCANNER", "WEBSOCKET", "COLLABORATOR", "ALL"
    );

    public AnnotateTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_annotate");
        tool.put("title", "Annotations");
        tool.put("description", "Add notes and highlight colors to entries across all Burp Suite components. " +
                "Use this to mark interesting items, add testing notes, and organize findings visually. " +
                "Supports Proxy, Target, Organizer, Repeater, Intruder, Scanner, WebSocket, and Collaborator. " +
                "Actions: ANNOTATE_* (per component), GET_ANNOTATIONS, ANNOTATE_BY_PATTERN (bulk), " +
                "SEARCH_BY_ANNOTATION, ENABLE/DISABLE_AUTO_ANNOTATION.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // CLEAR_ANNOTATIONS removes data
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        annotations.put("title", "Annotations");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "comment highlight color notes mark");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        // Action property
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Action to perform");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);

        // Source property (which component to work with)
        Map<String, Object> sourceProperty = new HashMap<>();
        sourceProperty.put("type", "string");
        sourceProperty.put("description", "Source component. Values: PROXY|TARGET|ORGANIZER|REPEATER|INTRUDER|SCANNER|WEBSOCKET|COLLABORATOR|ALL. Note: ANNOTATE_* actions infer source from the action name; only GET_ANNOTATIONS, SEARCH_BY_ANNOTATION, CLEAR_ANNOTATIONS need 'source' explicitly.");
        sourceProperty.put("enum", SOURCE_TYPES);
        properties.put("source", sourceProperty);
        
        // URL property
        Map<String, Object> urlProperty = new HashMap<>();
        urlProperty.put("type", "string");
        urlProperty.put("description", "URL to annotate");
        properties.put("url", urlProperty);
        
        // Notes property
        Map<String, Object> notesProperty = new HashMap<>();
        notesProperty.put("type", "string");
        notesProperty.put("description", "Notes to add to the item");
        properties.put("notes", notesProperty);
        
        // Highlight color property
        Map<String, Object> highlightProperty = new HashMap<>();
        highlightProperty.put("type", "string");
        highlightProperty.put("description", "Highlight color");
        highlightProperty.put("enum", List.of("RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY", "NONE"));
        properties.put("highlightColor", highlightProperty);
        
        // Pattern property (for bulk operations)
        Map<String, Object> patternProperty = new HashMap<>();
        patternProperty.put("type", "string");
        patternProperty.put("description", "Pattern to match URLs for bulk annotation");
        properties.put("pattern", patternProperty);
        
        // Method filter
        Map<String, Object> methodProperty = new HashMap<>();
        methodProperty.put("type", "string");
        methodProperty.put("description", "Filter by HTTP method");
        properties.put("method", methodProperty);
        
        // File path for import/export
        Map<String, Object> filePathProperty = new HashMap<>();
        filePathProperty.put("type", "string");
        filePathProperty.put("description", "File path for import/export operations");
        properties.put("filePath", filePathProperty);
        
        // Search query for annotation search
        Map<String, Object> searchQueryProperty = new HashMap<>();
        searchQueryProperty.put("type", "string");
        searchQueryProperty.put("description", "Search query for finding annotations");
        properties.put("searchQuery", searchQueryProperty);
        
        // Auto-annotation rules
        Map<String, Object> autoRulesProperty = new HashMap<>();
        autoRulesProperty.put("type", "object");
        autoRulesProperty.put("description", "Rules for auto-annotation");
        properties.put("autoRules", autoRulesProperty);
        
        // Issue ID for scanner annotations
        Map<String, Object> issueIdProperty = new HashMap<>();
        issueIdProperty.put("type", "string");
        issueIdProperty.put("description", "Scanner issue ID to annotate");
        properties.put("issueId", issueIdProperty);
        
        // WebSocket message ID
        Map<String, Object> messageIdProperty = new HashMap<>();
        messageIdProperty.put("type", "string");
        messageIdProperty.put("description", "WebSocket message ID");
        properties.put("messageId", messageIdProperty);

        // Collaborator interaction ID
        Map<String, Object> interactionIdProperty = new HashMap<>();
        interactionIdProperty.put("type", "string");
        interactionIdProperty.put("description", "Collaborator interaction ID");
        properties.put("interactionId", interactionIdProperty);

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        String action = arguments.has("action") ? arguments.get("action").asText() : null;

        if (action == null) {
            return McpUtils.createErrorResponse("Action parameter is required");
        }

        if (!SUPPORTED_ACTIONS.contains(action)) {
            return McpUtils.createErrorResponse("Unknown action: " + action + ". Supported actions: " + String.join(", ", SUPPORTED_ACTIONS));
        }

        try {
            switch (action) {
                case "ANNOTATE_PROXY":
                    return annotateProxyEntry(arguments);
                    
                case "ANNOTATE_TARGET":
                    return annotateTargetEntry(arguments);
                    
                case "ANNOTATE_ORGANIZER":
                    return annotateOrganizerEntry(arguments);
                    
                case "ANNOTATE_REPEATER":
                    return annotateRepeaterEntry(arguments);
                    
                case "ANNOTATE_INTRUDER":
                    return annotateIntruderResults(arguments);
                    
                case "ANNOTATE_SCANNER":
                    return annotateScannerIssue(arguments);
                    
                case "ANNOTATE_WEBSOCKET":
                    return annotateWebSocketMessage(arguments);
                    
                case "ANNOTATE_COLLABORATOR":
                    return annotateCollaboratorInteraction(arguments);
                    
                case "GET_ANNOTATIONS":
                    return getAnnotations(arguments);
                    
                case "ANNOTATE_BY_PATTERN":
                    return annotateByPattern(arguments);
                    
                case "CLEAR_ANNOTATIONS":
                    return clearAnnotations(arguments);
                    
                case "EXPORT_ANNOTATIONS":
                    return exportAnnotations(arguments);
                    
                case "IMPORT_ANNOTATIONS":
                    return importAnnotations(arguments);
                    
                case "SEARCH_BY_ANNOTATION":
                    return searchByAnnotation(arguments);
                    
                case "ENABLE_AUTO_ANNOTATION":
                    return enableAutoAnnotation(arguments);
                    
                case "DISABLE_AUTO_ANNOTATION":
                    return disableAutoAnnotation(arguments);
                    
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in annotation tool: " + e.getMessage());
            return McpUtils.createErrorResponse("Annotation error: " + e.getMessage());
        }
    }
    
    // Helper methods for common operations
    private boolean urlMatches(String entryUrl, String targetUrl) {
        return entryUrl != null && targetUrl != null &&
               (entryUrl.equals(targetUrl) || entryUrl.contains(targetUrl));
    }

    private StringBuilder createResultBuilder(String actionName) {
        StringBuilder result = new StringBuilder();
        result.append("=== ").append(actionName).append(" ===\n\n");
        return result;
    }

    private Object createAnnotationResult(StringBuilder result, boolean success,
                                         String location, String url) {
        if (success) {
            result.append("\n📍 Location: ").append(location).append("\n");
            if (url != null) {
                result.append("📍 URL: ").append(url).append("\n");
            }
        }
        return McpUtils.createSuccessResponse(result.toString());
    }

    // Original annotation methods
    private Object annotateProxyEntry(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for ANNOTATE_PROXY action");
        }

        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        ProxyHttpRequestResponse targetEntry = null;

        for (ProxyHttpRequestResponse entry : proxyHistory) {
            if (entry.finalRequest() != null && urlMatches(entry.finalRequest().url(), url)) {
                targetEntry = entry;
                break;
            }
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_PROXY");
            data.put("success", targetEntry != null);
            data.put("location", "Proxy History");
            data.put("requestedUrl", url);
            if (targetEntry != null) {
                if (notes != null && !notes.isEmpty()) {
                    String existingNotes = targetEntry.annotations().notes();
                    String newNotes = existingNotes != null && !existingNotes.isEmpty()
                        ? existingNotes + "\n\n" + notes : notes;
                    targetEntry.annotations().setNotes(newNotes);
                }
                if (highlightColorStr != null && !highlightColorStr.equals("NONE")) {
                    try {
                        targetEntry.annotations().setHighlightColor(HighlightColor.valueOf(highlightColorStr));
                    } catch (IllegalArgumentException e) {
                        data.put("invalidColor", highlightColorStr);
                    }
                }
                data.put("matchedUrl", targetEntry.finalRequest().url());
                data.put("notes", targetEntry.annotations().notes());
                data.put("color", targetEntry.annotations().highlightColor() != null
                    ? targetEntry.annotations().highlightColor().name() : "NONE");
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = createResultBuilder("Annotating Proxy Entry");

        if (targetEntry == null) {
            result.append("❌ No proxy entry found for URL: ").append(url).append("\n");
        } else {
            applyAnnotation(targetEntry.annotations(), notes, highlightColorStr, result);
        }

        return createAnnotationResult(result, targetEntry != null, "Proxy History",
                                    targetEntry != null ? targetEntry.finalRequest().url() : null);
    }
    
    private Object annotateTargetEntry(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for ANNOTATE_TARGET action");
        }

        SiteMap siteMap = api.siteMap();
        List<HttpRequestResponse> siteMapEntries = siteMap.requestResponses();
        HttpRequestResponse targetEntry = null;

        for (HttpRequestResponse entry : siteMapEntries) {
            if (entry.request() != null && urlMatches(entry.request().url(), url)) {
                targetEntry = entry;
                break;
            }
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_TARGET");
            data.put("success", targetEntry != null);
            data.put("location", "Target/Site Map");
            data.put("requestedUrl", url);
            if (targetEntry != null) {
                if (notes != null && !notes.isEmpty()) {
                    String existingNotes = targetEntry.annotations().notes();
                    String newNotes = existingNotes != null && !existingNotes.isEmpty()
                        ? existingNotes + "\n\n" + notes : notes;
                    targetEntry.annotations().setNotes(newNotes);
                }
                if (highlightColorStr != null && !highlightColorStr.equals("NONE")) {
                    try {
                        targetEntry.annotations().setHighlightColor(HighlightColor.valueOf(highlightColorStr));
                    } catch (IllegalArgumentException e) {
                        data.put("invalidColor", highlightColorStr);
                    }
                }
                data.put("matchedUrl", targetEntry.request().url());
                data.put("notes", targetEntry.annotations().notes());
                data.put("color", targetEntry.annotations().highlightColor() != null
                    ? targetEntry.annotations().highlightColor().name() : "NONE");
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = createResultBuilder("Annotating Target/Site Map Entry");

        if (targetEntry == null) {
            result.append("❌ No site map entry found for URL: ").append(url).append("\n");
        } else {
            applyAnnotation(targetEntry.annotations(), notes, highlightColorStr, result);
        }

        return createAnnotationResult(result, targetEntry != null, "Target/Site Map",
                                    targetEntry != null ? targetEntry.request().url() : null);
    }
    
    private Object annotateOrganizerEntry(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for ANNOTATE_ORGANIZER action");
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_ORGANIZER");
            data.put("location", "Organizer");
            data.put("requestedUrl", url);
            try {
                List<OrganizerItem> organizerItems = api.organizer().items();
                OrganizerItem targetEntry = null;
                for (OrganizerItem item : organizerItems) {
                    if (item != null && item.request() != null && urlMatches(item.request().url(), url)) {
                        targetEntry = item;
                        break;
                    }
                }
                data.put("success", targetEntry != null);
                if (targetEntry != null) {
                    if (notes != null && !notes.isEmpty()) {
                        String existingNotes = targetEntry.annotations().notes();
                        String newNotes = existingNotes != null && !existingNotes.isEmpty()
                            ? existingNotes + "\n\n" + notes : notes;
                        targetEntry.annotations().setNotes(newNotes);
                    }
                    if (highlightColorStr != null && !highlightColorStr.equals("NONE")) {
                        try {
                            targetEntry.annotations().setHighlightColor(HighlightColor.valueOf(highlightColorStr));
                        } catch (IllegalArgumentException e) {
                            data.put("invalidColor", highlightColorStr);
                        }
                    }
                    data.put("matchedUrl", targetEntry.request().url());
                    data.put("notes", targetEntry.annotations().notes());
                    data.put("color", targetEntry.annotations().highlightColor() != null
                        ? targetEntry.annotations().highlightColor().name() : "NONE");
                }
            } catch (NoSuchMethodError e) {
                data.put("success", false);
                data.put("error", "Organizer annotation is not available at runtime in this Burp version");
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = createResultBuilder("Annotating Organizer Entry");

        try {
            List<OrganizerItem> organizerItems = api.organizer().items();
            OrganizerItem targetEntry = null;

            for (OrganizerItem item : organizerItems) {
                if (item != null && item.request() != null && urlMatches(item.request().url(), url)) {
                    targetEntry = item;
                    break;
                }
            }

            if (targetEntry == null) {
                result.append("❌ No organizer entry found for URL: ").append(url).append("\n");
            } else {
                applyAnnotation(targetEntry.annotations(), notes, highlightColorStr, result);
            }

            return createAnnotationResult(result, targetEntry != null, "Organizer",
                                        targetEntry != null ? targetEntry.request().url() : null);
        } catch (NoSuchMethodError e) {
            result.append("⚠️ **Note:** Organizer annotation is not yet fully implemented in this version of Burp Suite.\n");
            result.append("The Montoya API defines the items() method, but it's not available at runtime.\n");
            return McpUtils.createSuccessResponse(result.toString());
        }
    }
    
    // New Repeater annotation support
    private Object annotateRepeaterEntry(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;
        
        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for ANNOTATE_REPEATER action");
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_REPEATER");
            data.put("location", "Repeater");
            data.put("url", url);
            try {
                storeAnnotationInDatabase(url, "REPEATER", notes, highlightColorStr);
                data.put("success", true);
                data.put("notes", notes);
                data.put("color", highlightColorStr != null ? highlightColorStr : "NONE");
                data.put("storage", "database");
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotating Repeater Entry ===\n\n");

        try {
            // Store annotation in our database for Repeater items
            storeAnnotationInDatabase(url, "REPEATER", notes, highlightColorStr);
            result.append("✅ Repeater annotation stored in database\n");
            result.append("📝 Notes: ").append(notes != null ? notes : "(none)").append("\n");
            result.append("🎨 Color: ").append(highlightColorStr != null ? highlightColorStr : "NONE").append("\n");
            result.append("\n📍 Location: Repeater Tab\n");
            result.append("📍 URL: ").append(url).append("\n");
            result.append("\n⚠️ Note: Repeater items don't have direct annotation API. Annotations are stored in extension database.\n");
        } catch (Exception e) {
            result.append("❌ Error annotating Repeater entry: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // New Intruder annotation support
    private Object annotateIntruderResults(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;
        
        if (url == null || url.isEmpty()) {
            return McpUtils.createErrorResponse("URL is required for ANNOTATE_INTRUDER action");
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_INTRUDER");
            data.put("location", "Intruder");
            data.put("url", url);
            try {
                storeAnnotationInDatabase(url, "INTRUDER", notes, highlightColorStr);
                data.put("success", true);
                data.put("notes", notes);
                data.put("color", highlightColorStr != null ? highlightColorStr : "NONE");
                data.put("storage", "database");
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotating Intruder Results ===\n\n");

        try {
            // Store annotation in our database for Intruder results
            storeAnnotationInDatabase(url, "INTRUDER", notes, highlightColorStr);
            result.append("✅ Intruder result annotation stored in database\n");
            result.append("📝 Notes: ").append(notes != null ? notes : "(none)").append("\n");
            result.append("🎨 Color: ").append(highlightColorStr != null ? highlightColorStr : "NONE").append("\n");
            result.append("\n📍 Location: Intruder Attack Results\n");
            result.append("📍 URL: ").append(url).append("\n");
            result.append("\n⚠️ Note: Intruder results don't have direct annotation API. Annotations are stored in extension database.\n");
        } catch (Exception e) {
            result.append("❌ Error annotating Intruder results: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // New Scanner issue annotation support
    private Object annotateScannerIssue(JsonNode arguments) {
        String issueId = arguments.has("issueId") ? arguments.get("issueId").asText() : null;
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_SCANNER");
            data.put("location", "Scanner");
            try {
                String key = issueId != null ? "scanner_issue_" + issueId : "scanner_" + (url != null ? url.hashCode() : System.currentTimeMillis());
                storeAnnotationInDatabase(key, "SCANNER", notes, highlightColorStr);
                data.put("success", true);
                data.put("key", key);
                if (issueId != null) data.put("issueId", issueId);
                if (url != null) data.put("url", url);
                data.put("notes", notes);
                data.put("color", highlightColorStr != null ? highlightColorStr : "NONE");
                data.put("storage", "database");
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotating Scanner Issue ===\n\n");

        try {
            // Scanner doesn't have a direct issues() method in the API
            // Store in our database for tracking
            String key = issueId != null ? "scanner_issue_" + issueId : "scanner_" + (url != null ? url.hashCode() : System.currentTimeMillis());
            storeAnnotationInDatabase(key, "SCANNER", notes, highlightColorStr);
            
            result.append("✅ Scanner issue annotation stored in database\n");
            result.append("📝 Notes: ").append(notes != null ? notes : "(none)").append("\n");
            result.append("🎨 Color: ").append(highlightColorStr != null ? highlightColorStr : "NONE").append("\n");
            result.append("\n📍 Location: Scanner Issues\n");
            if (issueId != null) result.append("📍 Issue ID: ").append(issueId).append("\n");
            if (url != null) result.append("📍 URL: ").append(url).append("\n");
            result.append("\n⚠️ Note: Scanner issues don't have direct annotation API. Annotations are stored in extension database.\n");
            
        } catch (Exception e) {
            result.append("❌ Error annotating Scanner issues: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // New WebSocket annotation support
    private Object annotateWebSocketMessage(JsonNode arguments) {
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String messageId = arguments.has("messageId") ? arguments.get("messageId").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_WEBSOCKET");
            data.put("location", "WebSocket History");
            if (url != null) data.put("url", url);
            if (messageId != null) data.put("messageId", messageId);
            try {
                List<ProxyWebSocketMessage> wsHistory = api.proxy().webSocketHistory();
                int annotatedCount = 0;
                for (ProxyWebSocketMessage wsMessage : wsHistory) {
                    if (url != null && wsMessage.upgradeRequest().url().contains(url)) {
                        if (wsMessage.annotations() != null) {
                            applyBulkAnnotation(wsMessage.annotations(),
                                "[WebSocket] " + (notes != null ? notes : ""), highlightColorStr);
                            annotatedCount++;
                        }
                        String key = url + (messageId != null ? "#" + messageId : "");
                        storeAnnotationInDatabase(key, "WEBSOCKET", notes, highlightColorStr);
                    }
                }
                data.put("success", annotatedCount > 0);
                data.put("annotatedCount", annotatedCount);
                data.put("notes", notes);
                data.put("color", highlightColorStr != null ? highlightColorStr : "NONE");
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotating WebSocket Message ===\n\n");

        try {
            List<ProxyWebSocketMessage> wsHistory = api.proxy().webSocketHistory();
            int annotatedCount = 0;
            
            for (ProxyWebSocketMessage wsMessage : wsHistory) {
                boolean shouldAnnotate = false;
                
                if (url != null && wsMessage.upgradeRequest().url().contains(url)) {
                    shouldAnnotate = true;
                }
                
                if (shouldAnnotate) {
                    // WebSocket messages have annotations on the message itself
                    if (wsMessage.annotations() != null) {
                        applyAnnotation(wsMessage.annotations(),
                                      "[WebSocket] " + (notes != null ? notes : ""),
                                      highlightColorStr, result);
                        annotatedCount++;
                    }
                    
                    // Store in database
                    String key = url + (messageId != null ? "#" + messageId : "");
                    storeAnnotationInDatabase(key, "WEBSOCKET", notes, highlightColorStr);
                }
            }
            
            if (annotatedCount > 0) {
                result.append("✅ Annotated ").append(annotatedCount).append(" WebSocket message(s)\n");
            } else {
                result.append("⚠️ No matching WebSocket messages found\n");
            }
            
            result.append("\n📍 Location: WebSocket History\n");
            if (url != null) result.append("📍 URL: ").append(url).append("\n");
            
        } catch (Exception e) {
            result.append("❌ Error annotating WebSocket messages: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // New Collaborator annotation support
    private Object annotateCollaboratorInteraction(JsonNode arguments) {
        String interactionId = arguments.has("interactionId") ? arguments.get("interactionId").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_COLLABORATOR");
            data.put("location", "Collaborator Client");
            try {
                String key = "collaborator_" + (interactionId != null ? interactionId : System.currentTimeMillis());
                storeAnnotationInDatabase(key, "COLLABORATOR", notes, highlightColorStr);
                data.put("success", true);
                data.put("key", key);
                if (interactionId != null) data.put("interactionId", interactionId);
                data.put("notes", notes);
                data.put("color", highlightColorStr != null ? highlightColorStr : "NONE");
                data.put("storage", "database");
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotating Collaborator Interaction ===\n\n");

        try {
            // Collaborator interactions don't have direct annotations, store in database
            String key = "collaborator_" + (interactionId != null ? interactionId : System.currentTimeMillis());
            storeAnnotationInDatabase(key, "COLLABORATOR", notes, highlightColorStr);
            
            result.append("✅ Collaborator interaction annotation stored in database\n");
            result.append("📝 Notes: ").append(notes != null ? notes : "(none)").append("\n");
            result.append("🎨 Color: ").append(highlightColorStr != null ? highlightColorStr : "NONE").append("\n");
            result.append("\n📍 Location: Collaborator Client\n");
            if (interactionId != null) result.append("📍 Interaction ID: ").append(interactionId).append("\n");
            result.append("\n⚠️ Note: Collaborator interactions don't have direct annotation API. Annotations are stored in extension database.\n");
            
        } catch (Exception e) {
            result.append("❌ Error annotating Collaborator interaction: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Enhanced GET_ANNOTATIONS with all sources
    private Object getAnnotations(JsonNode arguments) {
        String source = arguments.has("source") ? arguments.get("source").asText() : "ALL";
        String urlFilter = arguments.has("url") ? arguments.get("url").asText() : null;
        String methodFilter = arguments.has("method") ? arguments.get("method").asText() : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "GET_ANNOTATIONS");
            data.put("source", source);
            if (urlFilter != null) data.put("urlFilter", urlFilter);
            if (methodFilter != null) data.put("methodFilter", methodFilter);

            List<Map<String, Object>> items = new ArrayList<>();
            int proxyCount = 0, targetCount = 0, wsCount = 0, dbCount = 0;

            if (source.equals("PROXY") || source.equals("ALL")) {
                for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                    if (shouldInclude(entry.finalRequest().url(), entry.finalRequest().method(), urlFilter, methodFilter)) {
                        Annotations annotations = entry.annotations();
                        if (hasAnnotations(annotations)) {
                            Map<String, Object> item = new HashMap<>();
                            item.put("source", "PROXY");
                            item.put("url", entry.finalRequest().url());
                            item.put("method", entry.finalRequest().method());
                            item.put("notes", annotations.notes());
                            item.put("color", annotations.highlightColor() != null ? annotations.highlightColor().name() : null);
                            items.add(item);
                            proxyCount++;
                        }
                    }
                }
            }

            if (source.equals("TARGET") || source.equals("ALL")) {
                for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                    if (shouldInclude(entry.request().url(), entry.request().method(), urlFilter, methodFilter)) {
                        Annotations annotations = entry.annotations();
                        if (hasAnnotations(annotations)) {
                            Map<String, Object> item = new HashMap<>();
                            item.put("source", "TARGET");
                            item.put("url", entry.request().url());
                            item.put("method", entry.request().method());
                            item.put("notes", annotations.notes());
                            item.put("color", annotations.highlightColor() != null ? annotations.highlightColor().name() : null);
                            items.add(item);
                            targetCount++;
                        }
                    }
                }
            }

            if (source.equals("WEBSOCKET") || source.equals("ALL")) {
                try {
                    for (ProxyWebSocketMessage wsMessage : api.proxy().webSocketHistory()) {
                        if (wsMessage.annotations() != null) {
                            Annotations annotations = wsMessage.annotations();
                            if (hasAnnotations(annotations)) {
                                Map<String, Object> item = new HashMap<>();
                                item.put("source", "WEBSOCKET");
                                item.put("url", wsMessage.upgradeRequest().url());
                                item.put("method", "WEBSOCKET");
                                item.put("notes", annotations.notes());
                                item.put("color", annotations.highlightColor() != null ? annotations.highlightColor().name() : null);
                                items.add(item);
                                wsCount++;
                            }
                        }
                    }
                } catch (Exception e) {
                    data.put("webSocketError", e.getMessage());
                }
            }

            if (source.equals("REPEATER") || source.equals("INTRUDER") || source.equals("SCANNER") ||
                source.equals("COLLABORATOR") || source.equals("ALL")) {
                for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                    Map<String, Object> annotation = entry.getValue();
                    String annotationSource = (String) annotation.get("source");
                    if (source.equals("ALL") || source.equals(annotationSource)) {
                        Map<String, Object> item = new HashMap<>();
                        item.put("source", annotationSource);
                        item.put("key", entry.getKey());
                        item.put("notes", annotation.get("notes"));
                        item.put("color", annotation.get("color"));
                        items.add(item);
                        dbCount++;
                    }
                }
            }

            data.put("proxyCount", proxyCount);
            data.put("targetCount", targetCount);
            data.put("webSocketCount", wsCount);
            data.put("databaseCount", dbCount);
            data.put("totalAnnotated", proxyCount + targetCount + wsCount + dbCount);
            data.put("items", items);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Annotated Entries ===\n\n");
        
        int totalAnnotated = 0;
        
        // Check Proxy History
        if (source.equals("PROXY") || source.equals("ALL")) {
            result.append("📂 **PROXY HISTORY**\n");
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyAnnotated = 0;
            
            for (ProxyHttpRequestResponse entry : proxyHistory) {
                if (shouldInclude(entry.finalRequest().url(), entry.finalRequest().method(), 
                                 urlFilter, methodFilter)) {
                    Annotations annotations = entry.annotations();
                    if (hasAnnotations(annotations)) {
                        proxyAnnotated++;
                        appendAnnotationInfo(result, entry.finalRequest().url(), 
                                           entry.finalRequest().method(), annotations);
                    }
                }
            }
            result.append("Subtotal: ").append(proxyAnnotated).append(" annotated\n\n");
            totalAnnotated += proxyAnnotated;
        }
        
        // Check Target/Site Map
        if (source.equals("TARGET") || source.equals("ALL")) {
            result.append("🎯 **TARGET/SITE MAP**\n");
            List<HttpRequestResponse> siteMapEntries = api.siteMap().requestResponses();
            int targetAnnotated = 0;
            
            for (HttpRequestResponse entry : siteMapEntries) {
                if (shouldInclude(entry.request().url(), entry.request().method(), 
                                 urlFilter, methodFilter)) {
                    Annotations annotations = entry.annotations();
                    if (hasAnnotations(annotations)) {
                        targetAnnotated++;
                        appendAnnotationInfo(result, entry.request().url(), 
                                           entry.request().method(), annotations);
                    }
                }
            }
            result.append("Subtotal: ").append(targetAnnotated).append(" annotated\n\n");
            totalAnnotated += targetAnnotated;
        }
        
        // Check WebSocket History
        if (source.equals("WEBSOCKET") || source.equals("ALL")) {
            result.append("🔌 **WEBSOCKET HISTORY**\n");
            try {
                List<ProxyWebSocketMessage> wsHistory = api.proxy().webSocketHistory();
                int wsAnnotated = 0;
                
                for (ProxyWebSocketMessage wsMessage : wsHistory) {
                    if (wsMessage.annotations() != null) {
                        Annotations annotations = wsMessage.annotations();
                        if (hasAnnotations(annotations)) {
                            wsAnnotated++;
                            appendAnnotationInfo(result, wsMessage.upgradeRequest().url(), 
                                               "WEBSOCKET", annotations);
                        }
                    }
                }
                result.append("Subtotal: ").append(wsAnnotated).append(" annotated\n\n");
                totalAnnotated += wsAnnotated;
            } catch (Exception e) {
                result.append("⚠️ Error accessing WebSocket history: ").append(e.getMessage()).append("\n\n");
            }
        }
        
        // Check database for other sources
        if (source.equals("REPEATER") || source.equals("INTRUDER") || source.equals("SCANNER") || 
            source.equals("COLLABORATOR") || source.equals("ALL")) {
            result.append("💾 **DATABASE ANNOTATIONS**\n");
            int dbAnnotated = 0;
            
            for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                Map<String, Object> annotation = entry.getValue();
                String annotationSource = (String) annotation.get("source");
                
                if (source.equals("ALL") || source.equals(annotationSource)) {
                    dbAnnotated++;
                    result.append("📍 ").append(annotationSource).append(": ").append(entry.getKey()).append("\n");
                    if (annotation.get("notes") != null) {
                        result.append("   📝 Notes: ").append(annotation.get("notes")).append("\n");
                    }
                    if (annotation.get("color") != null) {
                        result.append("   🎨 Color: ").append(annotation.get("color")).append("\n");
                    }
                    result.append("\n");
                }
            }
            result.append("Subtotal: ").append(dbAnnotated).append(" database annotations\n\n");
            totalAnnotated += dbAnnotated;
        }
        
        result.append("─────────────────────────────\n");
        result.append("**Total Annotated:** ").append(totalAnnotated).append(" entries\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Export annotations to JSON file
    private Object exportAnnotations(JsonNode arguments) {
        String filePath = arguments.has("filePath") ? arguments.get("filePath").asText() : "annotations_export.json";

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "EXPORT_ANNOTATIONS");
            data.put("filePath", filePath);
            try {
                ObjectNode exportData = objectMapper.createObjectNode();
                ArrayNode annotations = objectMapper.createArrayNode();

                for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                    if (hasAnnotations(entry.annotations())) {
                        ObjectNode annotation = objectMapper.createObjectNode();
                        annotation.put("source", "PROXY");
                        annotation.put("url", entry.finalRequest().url());
                        annotation.put("method", entry.finalRequest().method());
                        annotation.put("notes", entry.annotations().notes());
                        if (entry.annotations().highlightColor() != null) {
                            annotation.put("color", entry.annotations().highlightColor().name());
                        }
                        annotations.add(annotation);
                    }
                }

                for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                    if (hasAnnotations(entry.annotations())) {
                        ObjectNode annotation = objectMapper.createObjectNode();
                        annotation.put("source", "TARGET");
                        annotation.put("url", entry.request().url());
                        annotation.put("method", entry.request().method());
                        annotation.put("notes", entry.annotations().notes());
                        if (entry.annotations().highlightColor() != null) {
                            annotation.put("color", entry.annotations().highlightColor().name());
                        }
                        annotations.add(annotation);
                    }
                }

                for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                    ObjectNode annotation = objectMapper.createObjectNode();
                    Map<String, Object> d = entry.getValue();
                    annotation.put("source", (String) d.get("source"));
                    annotation.put("key", entry.getKey());
                    annotation.put("notes", (String) d.get("notes"));
                    annotation.put("color", (String) d.get("color"));
                    annotations.add(annotation);
                }

                exportData.set("annotations", annotations);
                exportData.put("exportTime", new Date().toString());
                exportData.put("totalCount", annotations.size());

                FileWriter writer = new FileWriter(filePath);
                writer.write(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(exportData));
                writer.close();

                data.put("success", true);
                data.put("exportedCount", annotations.size());
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Export Annotations ===\n\n");
        
        try {
            ObjectNode exportData = objectMapper.createObjectNode();
            ArrayNode annotations = objectMapper.createArrayNode();
            
            // Export from Proxy
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            for (ProxyHttpRequestResponse entry : proxyHistory) {
                if (hasAnnotations(entry.annotations())) {
                    ObjectNode annotation = objectMapper.createObjectNode();
                    annotation.put("source", "PROXY");
                    annotation.put("url", entry.finalRequest().url());
                    annotation.put("method", entry.finalRequest().method());
                    annotation.put("notes", entry.annotations().notes());
                    if (entry.annotations().highlightColor() != null) {
                        annotation.put("color", entry.annotations().highlightColor().name());
                    }
                    annotations.add(annotation);
                }
            }
            
            // Export from Site Map
            List<HttpRequestResponse> siteMapEntries = api.siteMap().requestResponses();
            for (HttpRequestResponse entry : siteMapEntries) {
                if (hasAnnotations(entry.annotations())) {
                    ObjectNode annotation = objectMapper.createObjectNode();
                    annotation.put("source", "TARGET");
                    annotation.put("url", entry.request().url());
                    annotation.put("method", entry.request().method());
                    annotation.put("notes", entry.annotations().notes());
                    if (entry.annotations().highlightColor() != null) {
                        annotation.put("color", entry.annotations().highlightColor().name());
                    }
                    annotations.add(annotation);
                }
            }
            
            // Export from database
            for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                ObjectNode annotation = objectMapper.createObjectNode();
                Map<String, Object> data = entry.getValue();
                annotation.put("source", (String) data.get("source"));
                annotation.put("key", entry.getKey());
                annotation.put("notes", (String) data.get("notes"));
                annotation.put("color", (String) data.get("color"));
                annotations.add(annotation);
            }
            
            exportData.set("annotations", annotations);
            exportData.put("exportTime", new Date().toString());
            exportData.put("totalCount", annotations.size());
            
            // Write to file
            FileWriter writer = new FileWriter(filePath);
            writer.write(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(exportData));
            writer.close();
            
            result.append("✅ Exported ").append(annotations.size()).append(" annotations to: ").append(filePath).append("\n");
            result.append("\nExport includes:\n");
            result.append("• Proxy history annotations\n");
            result.append("• Site map annotations\n");
            result.append("• Database annotations (Repeater, Intruder, Scanner, etc.)\n");
            
        } catch (Exception e) {
            result.append("❌ Error exporting annotations: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Import annotations from JSON file
    private Object importAnnotations(JsonNode arguments) {
        String filePath = arguments.has("filePath") ? arguments.get("filePath").asText() : "annotations_export.json";

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "IMPORT_ANNOTATIONS");
            data.put("filePath", filePath);
            try {
                String content = new String(Files.readAllBytes(Paths.get(filePath)));
                JsonNode importData = objectMapper.readTree(content);
                if (!importData.has("annotations")) {
                    return McpUtils.createErrorResponse("Invalid import file: missing annotations field");
                }
                JsonNode annotations = importData.get("annotations");
                int importedCount = 0;
                int skippedCount = 0;
                for (JsonNode annotation : annotations) {
                    String source = annotation.get("source").asText();
                    String notes = annotation.has("notes") ? annotation.get("notes").asText() : null;
                    String color = annotation.has("color") ? annotation.get("color").asText() : null;
                    if (source.equals("PROXY") || source.equals("TARGET")) {
                        String url = annotation.get("url").asText();
                        String method = annotation.get("method").asText();
                        boolean found = false;
                        if (source.equals("PROXY")) {
                            for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                                if (entry.finalRequest().url().equals(url) && entry.finalRequest().method().equals(method)) {
                                    applyImportedAnnotation(entry.annotations(), notes, color);
                                    found = true;
                                    importedCount++;
                                    break;
                                }
                            }
                        }
                        if (source.equals("TARGET")) {
                            for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                                if (entry.request().url().equals(url) && entry.request().method().equals(method)) {
                                    applyImportedAnnotation(entry.annotations(), notes, color);
                                    found = true;
                                    importedCount++;
                                    break;
                                }
                            }
                        }
                        if (!found) skippedCount++;
                    } else {
                        String key = annotation.has("key") ? annotation.get("key").asText() : annotation.get("url").asText();
                        storeAnnotationInDatabase(key, source, notes, color);
                        importedCount++;
                    }
                }
                data.put("success", true);
                data.put("importedCount", importedCount);
                data.put("skippedCount", skippedCount);
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Import Annotations ===\n\n");
        
        try {
            // Read JSON file
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            JsonNode importData = objectMapper.readTree(content);
            
            if (!importData.has("annotations")) {
                return McpUtils.createErrorResponse("Invalid import file: missing annotations field");
            }
            
            JsonNode annotations = importData.get("annotations");
            int importedCount = 0;
            int skippedCount = 0;
            
            for (JsonNode annotation : annotations) {
                String source = annotation.get("source").asText();
                String notes = annotation.has("notes") ? annotation.get("notes").asText() : null;
                String color = annotation.has("color") ? annotation.get("color").asText() : null;
                
                if (source.equals("PROXY") || source.equals("TARGET")) {
                    // Try to find and annotate matching entries
                    String url = annotation.get("url").asText();
                    String method = annotation.get("method").asText();
                    
                    boolean found = false;
                    
                    // Check proxy history
                    if (source.equals("PROXY")) {
                        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                            if (entry.finalRequest().url().equals(url) && 
                                entry.finalRequest().method().equals(method)) {
                                applyImportedAnnotation(entry.annotations(), notes, color);
                                found = true;
                                importedCount++;
                                break;
                            }
                        }
                    }
                    
                    // Check site map
                    if (source.equals("TARGET")) {
                        for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                            if (entry.request().url().equals(url) && 
                                entry.request().method().equals(method)) {
                                applyImportedAnnotation(entry.annotations(), notes, color);
                                found = true;
                                importedCount++;
                                break;
                            }
                        }
                    }
                    
                    if (!found) {
                        skippedCount++;
                    }
                } else {
                    // Import to database
                    String key = annotation.has("key") ? annotation.get("key").asText() : 
                                annotation.get("url").asText();
                    storeAnnotationInDatabase(key, source, notes, color);
                    importedCount++;
                }
            }
            
            result.append("✅ Import completed\n");
            result.append("• Imported: ").append(importedCount).append(" annotations\n");
            result.append("• Skipped: ").append(skippedCount).append(" annotations (no matching entries)\n");
            result.append("\nImported from: ").append(filePath).append("\n");
            
        } catch (Exception e) {
            result.append("❌ Error importing annotations: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Search for items by annotation content
    private Object searchByAnnotation(JsonNode arguments) {
        String searchQuery = arguments.has("searchQuery") ? arguments.get("searchQuery").asText() : "";
        String source = arguments.has("source") ? arguments.get("source").asText() : "ALL";

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "SEARCH_BY_ANNOTATION");
            data.put("query", searchQuery);
            data.put("source", source);
            List<Map<String, Object>> matches = new ArrayList<>();

            if (source.equals("PROXY") || source.equals("ALL")) {
                for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                    if (entry.annotations().notes() != null &&
                        entry.annotations().notes().toLowerCase().contains(searchQuery.toLowerCase())) {
                        Map<String, Object> match = new HashMap<>();
                        match.put("source", "PROXY");
                        match.put("url", entry.finalRequest().url());
                        match.put("method", entry.finalRequest().method());
                        match.put("notes", entry.annotations().notes());
                        matches.add(match);
                    }
                }
            }
            if (source.equals("TARGET") || source.equals("ALL")) {
                for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                    if (entry.annotations().notes() != null &&
                        entry.annotations().notes().toLowerCase().contains(searchQuery.toLowerCase())) {
                        Map<String, Object> match = new HashMap<>();
                        match.put("source", "TARGET");
                        match.put("url", entry.request().url());
                        match.put("method", entry.request().method());
                        match.put("notes", entry.annotations().notes());
                        matches.add(match);
                    }
                }
            }
            for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                Map<String, Object> annotation = entry.getValue();
                String notes = (String) annotation.get("notes");
                String annotationSource = (String) annotation.get("source");
                if (notes != null && notes.toLowerCase().contains(searchQuery.toLowerCase()) &&
                    (source.equals("ALL") || source.equals(annotationSource))) {
                    Map<String, Object> match = new HashMap<>();
                    match.put("source", annotationSource);
                    match.put("key", entry.getKey());
                    match.put("notes", notes);
                    matches.add(match);
                }
            }
            data.put("matchCount", matches.size());
            data.put("matches", matches);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Search by Annotation ===\n");
        result.append("Query: \"").append(searchQuery).append("\"\n\n");

        List<Map<String, String>> searchResults = new ArrayList<>();
        
        // Search Proxy History
        if (source.equals("PROXY") || source.equals("ALL")) {
            for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                if (entry.annotations().notes() != null && 
                    entry.annotations().notes().toLowerCase().contains(searchQuery.toLowerCase())) {
                    Map<String, String> match = new HashMap<>();
                    match.put("source", "PROXY");
                    match.put("url", entry.finalRequest().url());
                    match.put("method", entry.finalRequest().method());
                    match.put("notes", entry.annotations().notes());
                    searchResults.add(match);
                }
            }
        }
        
        // Search Site Map
        if (source.equals("TARGET") || source.equals("ALL")) {
            for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                if (entry.annotations().notes() != null && 
                    entry.annotations().notes().toLowerCase().contains(searchQuery.toLowerCase())) {
                    Map<String, String> match = new HashMap<>();
                    match.put("source", "TARGET");
                    match.put("url", entry.request().url());
                    match.put("method", entry.request().method());
                    match.put("notes", entry.annotations().notes());
                    searchResults.add(match);
                }
            }
        }
        
        // Search Database
        for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
            Map<String, Object> annotation = entry.getValue();
            String notes = (String) annotation.get("notes");
            String annotationSource = (String) annotation.get("source");
            
            if (notes != null && notes.toLowerCase().contains(searchQuery.toLowerCase()) &&
                (source.equals("ALL") || source.equals(annotationSource))) {
                Map<String, String> match = new HashMap<>();
                match.put("source", annotationSource);
                match.put("key", entry.getKey());
                match.put("notes", notes);
                searchResults.add(match);
            }
        }
        
        // Display results
        result.append("Found ").append(searchResults.size()).append(" matching annotations:\n\n");
        
        for (Map<String, String> match : searchResults) {
            result.append("📍 [").append(match.get("source")).append("] ");
            result.append(match.get("url") != null ? match.get("url") : match.get("key")).append("\n");
            result.append("   📝 ").append(match.get("notes")).append("\n\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Enable auto-annotation with rules
    private Object enableAutoAnnotation(JsonNode arguments) {
        JsonNode autoRules = arguments.has("autoRules") ? arguments.get("autoRules") : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ENABLE_AUTO_ANNOTATION");
            try {
                ProxyRequestHandler handler = new ProxyRequestHandler() {
                    @Override
                    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                    }
                    @Override
                    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                        String url = interceptedRequest.url();
                        if (autoRules != null && autoRules.has("urlPatterns")) {
                            for (JsonNode pattern : autoRules.get("urlPatterns")) {
                                if (url.contains(pattern.asText())) {
                                    String notes = autoRules.has("notes") ? autoRules.get("notes").asText() : "Auto-annotated";
                                    String color = autoRules.has("color") ? autoRules.get("color").asText() : "YELLOW";
                                    interceptedRequest.annotations().setNotes(notes);
                                    try {
                                        interceptedRequest.annotations().setHighlightColor(HighlightColor.valueOf(color));
                                    } catch (IllegalArgumentException e) {
                                        // skip
                                    }
                                }
                            }
                        }
                        return ProxyRequestToBeSentAction.continueWith(interceptedRequest, interceptedRequest.annotations());
                    }
                };

                Registration existingRegistration = handlerRegistrations.get("auto_annotation");
                if (existingRegistration != null) {
                    if (existingRegistration.isRegistered()) {
                        data.put("success", false);
                        data.put("alreadyEnabled", true);
                        return McpUtils.createJsonResponse(data);
                    }
                    handlerRegistrations.remove("auto_annotation");
                }
                activeHandlers.remove("auto_annotation");

                Registration registration = api.proxy().registerRequestHandler(handler);
                activeHandlers.put("auto_annotation", handler);
                handlerRegistrations.put("auto_annotation", registration);

                data.put("success", true);
                if (autoRules != null) {
                    Map<String, Object> rules = new HashMap<>();
                    if (autoRules.has("urlPatterns")) {
                        List<String> patterns = new ArrayList<>();
                        for (JsonNode pattern : autoRules.get("urlPatterns")) patterns.add(pattern.asText());
                        rules.put("urlPatterns", patterns);
                    }
                    if (autoRules.has("notes")) rules.put("notes", autoRules.get("notes").asText());
                    if (autoRules.has("color")) rules.put("color", autoRules.get("color").asText());
                    data.put("rules", rules);
                }
            } catch (Exception e) {
                data.put("success", false);
                data.put("error", e.getMessage());
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Enable Auto-Annotation ===\n\n");
        
        try {
            // Create a proxy request handler for auto-annotation
            ProxyRequestHandler handler = new ProxyRequestHandler() {
                @Override
                public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                    // Just continue for received requests
                    return ProxyRequestReceivedAction.continueWith(interceptedRequest);
                }
                
                @Override
                public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                    String url = interceptedRequest.url();
                    
                    // Apply auto-annotation rules
                    if (autoRules != null) {
                        // Check URL patterns
                        if (autoRules.has("urlPatterns")) {
                            for (JsonNode pattern : autoRules.get("urlPatterns")) {
                                if (url.contains(pattern.asText())) {
                                    String notes = autoRules.has("notes") ? 
                                        autoRules.get("notes").asText() : "Auto-annotated";
                                    String color = autoRules.has("color") ? 
                                        autoRules.get("color").asText() : "YELLOW";
                                    
                                    // Apply annotation
                                    interceptedRequest.annotations().setNotes(notes);
                                    try {
                                        HighlightColor highlightColor = HighlightColor.valueOf(color);
                                        interceptedRequest.annotations().setHighlightColor(highlightColor);
                                    } catch (IllegalArgumentException e) {
                                        // Invalid color, skip
                                    }
                                }
                            }
                        }
                    }
                    
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest, interceptedRequest.annotations());
                }
            };
            
            // Avoid stacking multiple handlers
            Registration existingRegistration = handlerRegistrations.get("auto_annotation");
            if (existingRegistration != null) {
                if (existingRegistration.isRegistered()) {
                    return McpUtils.createSuccessResponse("⚠️ Auto-annotation is already enabled");
                }
                handlerRegistrations.remove("auto_annotation");
            }
            activeHandlers.remove("auto_annotation");

            // Register the handler
            Registration registration = api.proxy().registerRequestHandler(handler);
            activeHandlers.put("auto_annotation", handler);
            handlerRegistrations.put("auto_annotation", registration);
            
            result.append("✅ Auto-annotation enabled\n");
            
            if (autoRules != null) {
                result.append("\nRules configured:\n");
                if (autoRules.has("urlPatterns")) {
                    result.append("• URL patterns: ");
                    for (JsonNode pattern : autoRules.get("urlPatterns")) {
                        result.append(pattern.asText()).append(" ");
                    }
                    result.append("\n");
                }
                if (autoRules.has("notes")) {
                    result.append("• Notes: ").append(autoRules.get("notes").asText()).append("\n");
                }
                if (autoRules.has("color")) {
                    result.append("• Color: ").append(autoRules.get("color").asText()).append("\n");
                }
            }
            
        } catch (Exception e) {
            result.append("❌ Error enabling auto-annotation: ").append(e.getMessage()).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Disable auto-annotation
    private Object disableAutoAnnotation(JsonNode arguments) {
        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "DISABLE_AUTO_ANNOTATION");
            if (activeHandlers.containsKey("auto_annotation") || handlerRegistrations.containsKey("auto_annotation")) {
                activeHandlers.remove("auto_annotation");
                Registration registration = handlerRegistrations.remove("auto_annotation");
                if (registration != null && registration.isRegistered()) {
                    registration.deregister();
                }
                data.put("success", true);
                data.put("wasEnabled", true);
            } else {
                data.put("success", true);
                data.put("wasEnabled", false);
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Disable Auto-Annotation ===\n\n");

        if (activeHandlers.containsKey("auto_annotation") || handlerRegistrations.containsKey("auto_annotation")) {
            activeHandlers.remove("auto_annotation");
            Registration registration = handlerRegistrations.remove("auto_annotation");

            if (registration != null && registration.isRegistered()) {
                registration.deregister();
            }

            result.append("✅ Auto-annotation disabled\n");
        } else {
            result.append("ℹ️ Auto-annotation was not enabled\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Original helper methods
    private Object annotateByPattern(JsonNode arguments) {
        String pattern = arguments.has("pattern") ? arguments.get("pattern").asText() : null;
        String notes = arguments.has("notes") ? arguments.get("notes").asText() : null;
        String highlightColorStr = arguments.has("highlightColor") ? arguments.get("highlightColor").asText() : null;
        String source = arguments.has("source") ? arguments.get("source").asText() : "ALL";
        
        if (pattern == null || pattern.isEmpty()) {
            return McpUtils.createErrorResponse("Pattern is required for ANNOTATE_BY_PATTERN action");
        }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "ANNOTATE_BY_PATTERN");
            data.put("pattern", pattern);
            data.put("source", source);
            int proxyAnnotated = 0, targetAnnotated = 0, wsAnnotated = 0;

            if (source.equals("PROXY") || source.equals("ALL")) {
                for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                    if (entry.finalRequest().url().contains(pattern)) {
                        applyBulkAnnotation(entry.annotations(), notes, highlightColorStr);
                        proxyAnnotated++;
                    }
                }
            }
            if (source.equals("TARGET") || source.equals("ALL")) {
                for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                    if (entry.request().url().contains(pattern)) {
                        applyBulkAnnotation(entry.annotations(), notes, highlightColorStr);
                        targetAnnotated++;
                    }
                }
            }
            if (source.equals("WEBSOCKET") || source.equals("ALL")) {
                try {
                    for (ProxyWebSocketMessage wsMessage : api.proxy().webSocketHistory()) {
                        if (wsMessage.upgradeRequest().url().contains(pattern)) {
                            applyBulkAnnotation(wsMessage.annotations(), notes, highlightColorStr);
                            wsAnnotated++;
                        }
                    }
                } catch (Exception e) {
                    data.put("webSocketError", e.getMessage());
                }
            }
            data.put("proxyAnnotated", proxyAnnotated);
            data.put("targetAnnotated", targetAnnotated);
            data.put("webSocketAnnotated", wsAnnotated);
            data.put("totalAnnotated", proxyAnnotated + targetAnnotated + wsAnnotated);
            if (notes != null) data.put("notes", notes);
            if (highlightColorStr != null && !highlightColorStr.equals("NONE")) data.put("color", highlightColorStr);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Bulk Annotation by Pattern ===\n\n");
        result.append("Pattern: ").append(pattern).append("\n");
        result.append("Source: ").append(source).append("\n\n");
        
        int totalAnnotated = 0;
        
        // Annotate in Proxy History
        if (source.equals("PROXY") || source.equals("ALL")) {
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyAnnotated = 0;
            
            for (ProxyHttpRequestResponse entry : proxyHistory) {
                if (entry.finalRequest().url().contains(pattern)) {
                    applyBulkAnnotation(entry.annotations(), notes, highlightColorStr);
                    proxyAnnotated++;
                }
            }
            
            if (proxyAnnotated > 0) {
                result.append("✅ Proxy History: ").append(proxyAnnotated).append(" entries annotated\n");
                totalAnnotated += proxyAnnotated;
            }
        }
        
        // Annotate in Target/Site Map
        if (source.equals("TARGET") || source.equals("ALL")) {
            List<HttpRequestResponse> siteMapEntries = api.siteMap().requestResponses();
            int targetAnnotated = 0;
            
            for (HttpRequestResponse entry : siteMapEntries) {
                if (entry.request().url().contains(pattern)) {
                    applyBulkAnnotation(entry.annotations(), notes, highlightColorStr);
                    targetAnnotated++;
                }
            }
            
            if (targetAnnotated > 0) {
                result.append("✅ Target/Site Map: ").append(targetAnnotated).append(" entries annotated\n");
                totalAnnotated += targetAnnotated;
            }
        }
        
        // Annotate WebSocket messages
        if (source.equals("WEBSOCKET") || source.equals("ALL")) {
            try {
                List<ProxyWebSocketMessage> wsHistory = api.proxy().webSocketHistory();
                int wsAnnotated = 0;
                
                for (ProxyWebSocketMessage wsMessage : wsHistory) {
                    if (wsMessage.upgradeRequest().url().contains(pattern)) {
                        applyBulkAnnotation(wsMessage.annotations(), notes, highlightColorStr);
                        wsAnnotated++;
                    }
                }
                
                if (wsAnnotated > 0) {
                    result.append("✅ WebSocket: ").append(wsAnnotated).append(" messages annotated\n");
                    totalAnnotated += wsAnnotated;
                }
            } catch (Exception e) {
                result.append("⚠️ WebSocket: Error accessing history\n");
            }
        }
        
        result.append("\n─────────────────────────────\n");
        result.append("**Total Annotated:** ").append(totalAnnotated).append(" entries\n");
        
        if (notes != null) {
            result.append("Applied notes: ").append(notes).append("\n");
        }
        if (highlightColorStr != null && !highlightColorStr.equals("NONE")) {
            result.append("Applied color: ").append(highlightColorStr).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object clearAnnotations(JsonNode arguments) {
        String source = arguments.has("source") ? arguments.get("source").asText() : "ALL";
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String pattern = arguments.has("pattern") ? arguments.get("pattern").asText() : null;

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "CLEAR_ANNOTATIONS");
            data.put("source", source);
            if (url != null) data.put("url", url);
            if (pattern != null) data.put("pattern", pattern);

            int proxyCleared = 0, targetCleared = 0, dbCleared = 0;

            if (source.equals("PROXY") || source.equals("ALL")) {
                for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                    if (shouldClear(entry.finalRequest().url(), url, pattern, entry.annotations())) {
                        clearAnnotation(entry.annotations());
                        proxyCleared++;
                    }
                }
            }
            if (source.equals("TARGET") || source.equals("ALL")) {
                for (HttpRequestResponse entry : api.siteMap().requestResponses()) {
                    if (shouldClear(entry.request().url(), url, pattern, entry.annotations())) {
                        clearAnnotation(entry.annotations());
                        targetCleared++;
                    }
                }
            }
            if (source.equals("ALL") || source.equals("REPEATER") || source.equals("INTRUDER") ||
                source.equals("SCANNER") || source.equals("COLLABORATOR") || source.equals("WEBSOCKET") ||
                source.equals("PROXY") || source.equals("TARGET") || source.equals("ORGANIZER")) {
                List<String> keysToRemove = new ArrayList<>();
                for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                    Map<String, Object> annotation = entry.getValue();
                    String annotationSource = (String) annotation.get("source");
                    if (source.equals("ALL") || source.equals(annotationSource)) {
                        if (pattern == null || entry.getKey().contains(pattern)) {
                            keysToRemove.add(entry.getKey());
                            dbCleared++;
                        }
                    }
                }
                for (String key : keysToRemove) annotationDatabase.remove(key);
            }

            data.put("success", true);
            data.put("proxyCleared", proxyCleared);
            data.put("targetCleared", targetCleared);
            data.put("databaseCleared", dbCleared);
            data.put("totalCleared", proxyCleared + targetCleared + dbCleared);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("=== Clear Annotations ===\n\n");
        
        int totalCleared = 0;
        
        // Clear in Proxy History
        if (source.equals("PROXY") || source.equals("ALL")) {
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyCleared = 0;
            
            for (ProxyHttpRequestResponse entry : proxyHistory) {
                if (shouldClear(entry.finalRequest().url(), url, pattern, entry.annotations())) {
                    clearAnnotation(entry.annotations());
                    proxyCleared++;
                }
            }
            
            if (proxyCleared > 0) {
                result.append("✅ Proxy History: ").append(proxyCleared).append(" annotations cleared\n");
                totalCleared += proxyCleared;
            }
        }
        
        // Clear in Target/Site Map
        if (source.equals("TARGET") || source.equals("ALL")) {
            List<HttpRequestResponse> siteMapEntries = api.siteMap().requestResponses();
            int targetCleared = 0;
            
            for (HttpRequestResponse entry : siteMapEntries) {
                if (shouldClear(entry.request().url(), url, pattern, entry.annotations())) {
                    clearAnnotation(entry.annotations());
                    targetCleared++;
                }
            }
            
            if (targetCleared > 0) {
                result.append("✅ Target/Site Map: ").append(targetCleared).append(" annotations cleared\n");
                totalCleared += targetCleared;
            }
        }
        
        // Clear database annotations
        if (source.equals("ALL") || source.equals("REPEATER") || source.equals("INTRUDER") || 
            source.equals("SCANNER") || source.equals("COLLABORATOR") || source.equals("WEBSOCKET") ||
            source.equals("PROXY") || source.equals("TARGET") || source.equals("ORGANIZER")) {
            int dbCleared = 0;
            List<String> keysToRemove = new ArrayList<>();
            
            for (Map.Entry<String, Map<String, Object>> entry : annotationDatabase.entrySet()) {
                Map<String, Object> annotation = entry.getValue();
                String annotationSource = (String) annotation.get("source");
                
                if (source.equals("ALL") || source.equals(annotationSource)) {
                    if (pattern == null || entry.getKey().contains(pattern)) {
                        keysToRemove.add(entry.getKey());
                        dbCleared++;
                    }
                }
            }
            
            for (String key : keysToRemove) {
                annotationDatabase.remove(key);
            }
            
            if (dbCleared > 0) {
                result.append("✅ Database: ").append(dbCleared).append(" annotations cleared\n");
                totalCleared += dbCleared;
            }
        }
        
        result.append("\n─────────────────────────────\n");
        result.append("**Total Cleared:** ").append(totalCleared).append(" annotations\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Unified annotation application method
    private void applyAnnotation(Annotations annotations, String notes, String highlightColorStr, StringBuilder result) {
        applyAnnotationCore(annotations, notes, highlightColorStr, true, result);
    }

    private void applyBulkAnnotation(Annotations annotations, String notes, String highlightColorStr) {
        applyAnnotationCore(annotations, notes, highlightColorStr, false, null);
    }

    private void applyImportedAnnotation(Annotations annotations, String notes, String color) {
        applyAnnotationCore(annotations, notes, color, false, null);
    }

    // Core annotation application logic
    private void applyAnnotationCore(Annotations annotations, String notes, String colorStr,
                                    boolean appendNotes, StringBuilder result) {
        if (notes != null && !notes.isEmpty()) {
            if (appendNotes) {
                String existingNotes = annotations.notes();
                String newNotes = existingNotes != null && !existingNotes.isEmpty()
                    ? existingNotes + "\n\n" + notes
                    : notes;
                annotations.setNotes(newNotes);
                if (result != null) {
                    result.append("✅ Added notes: ").append(notes).append("\n");
                }
            } else {
                annotations.setNotes(notes);
            }
        }

        if (colorStr != null && !colorStr.equals("NONE")) {
            try {
                HighlightColor color = HighlightColor.valueOf(colorStr);
                annotations.setHighlightColor(color);
                if (result != null) {
                    result.append("✅ Applied highlight color: ").append(colorStr).append("\n");
                }
            } catch (IllegalArgumentException e) {
                if (result != null) {
                    result.append("⚠️ Invalid highlight color: ").append(colorStr).append("\n");
                }
            }
        }

        if (result != null) {
            result.append("\n📝 Current Notes: ").append(annotations.notes() != null ? annotations.notes() : "(none)").append("\n");
            result.append("🎨 Current Color: ").append(annotations.highlightColor() != null ? annotations.highlightColor().name() : "NONE").append("\n");
        }
    }
    
    private void clearAnnotation(Annotations annotations) {
        annotations.setNotes("");
        annotations.setHighlightColor(null);
    }
    
    private boolean hasAnnotations(Annotations annotations) {
        return (annotations.notes() != null && !annotations.notes().isEmpty()) || 
               annotations.highlightColor() != null;
    }
    
    private boolean shouldInclude(String url, String method, String urlFilter, String methodFilter) {
        if (urlFilter != null && !url.contains(urlFilter)) {
            return false;
        }
        if (methodFilter != null && !method.equalsIgnoreCase(methodFilter)) {
            return false;
        }
        return true;
    }
    
    private boolean shouldClear(String url, String urlFilter, String pattern, Annotations annotations) {
        if (urlFilter != null && url.equals(urlFilter)) {
            return true;
        }
        if (pattern != null && url.contains(pattern)) {
            return true;
        }
        if (urlFilter == null && pattern == null && hasAnnotations(annotations)) {
            return true;
        }
        return false;
    }
    
    private void appendAnnotationInfo(StringBuilder result, String url, String method, Annotations annotations) {
        result.append("📍 ").append(method).append(" ").append(url).append("\n");
        
        if (annotations.highlightColor() != null) {
            result.append("   🎨 Color: ").append(annotations.highlightColor().name()).append("\n");
        }
        
        if (annotations.notes() != null && !annotations.notes().isEmpty()) {
            result.append("   📝 Notes: ").append(annotations.notes().replace("\n", "\n             ")).append("\n");
        }
        
        result.append("\n");
    }
    
    private void storeAnnotationInDatabase(String key, String source, String notes, String color) {
        Map<String, Object> annotation = new HashMap<>();
        annotation.put("source", source);
        annotation.put("notes", notes);
        annotation.put("color", color);
        annotation.put("timestamp", System.currentTimeMillis());
        annotationDatabase.put(key, annotation);
    }
}
