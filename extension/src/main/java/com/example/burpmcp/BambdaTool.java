package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.bambda.BambdaImportResult;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

public class BambdaTool implements McpTool {
    private final MontoyaApi api;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "APPLY_FILTER",
        "LIST_PRESETS",
        "CREATE_CUSTOM",
        "GET_ACTIVE_FILTER"
    );
    
    // Pre-defined useful Bambdas for security testing
    // Note: These scripts use the ProxyHttpRequestResponse interface from burp.api.montoya.proxy
    private static final Map<String, String> BAMBDA_LIBRARY;
    static {
        Map<String, String> bambdas = new HashMap<>();
        // Authentication & Session
        bambdas.put("authenticated_requests", 
            "return requestResponse.request().hasHeader(\"Authorization\") || " +
            "requestResponse.request().hasHeader(\"Cookie\");");
        
        // API Endpoints  
        bambdas.put("api_endpoints", 
            "return requestResponse.request().url().contains(\"/api/\") || " +
            "requestResponse.request().url().contains(\"/v1/\") || " +
            "requestResponse.request().url().contains(\"/v2/\");");
        
        // Potential SQL Injection Points
        bambdas.put("sql_injection_candidates", 
            "return requestResponse.request().hasParameters() && " +
            "(requestResponse.request().url().contains(\"id=\") || " +
            "requestResponse.request().url().contains(\"user=\") || " +
            "requestResponse.request().url().contains(\"search=\"));");
        
        // Error Responses (only check if response exists)
        bambdas.put("error_responses", 
            "if (!requestResponse.hasResponse()) return false; " +
            "return requestResponse.response().statusCode() >= 400 || " +
            "requestResponse.response().bodyToString().toLowerCase().contains(\"error\") || " +
            "requestResponse.response().bodyToString().toLowerCase().contains(\"exception\");");
        
        // File Upload Endpoints
        bambdas.put("file_uploads", 
            "return requestResponse.request().hasHeader(\"Content-Type\") && " +
            "requestResponse.request().headerValue(\"Content-Type\").contains(\"multipart/form-data\");");
        
        // JSON Endpoints (only check if response exists)
        bambdas.put("json_endpoints", 
            "if (!requestResponse.hasResponse()) return false; " +
            "return requestResponse.response().hasHeader(\"Content-Type\") && " +
            "requestResponse.response().headerValue(\"Content-Type\").contains(\"application/json\");");
        
        // Admin/Management Interfaces
        bambdas.put("admin_interfaces", 
            "return requestResponse.request().url().contains(\"admin\") || " +
            "requestResponse.request().url().contains(\"manage\") || " +
            "requestResponse.request().url().contains(\"dashboard\") || " +
            "requestResponse.request().url().contains(\"config\");");
        
        // Potential XSS Points (only check if response exists)
        bambdas.put("xss_candidates", 
            "if (!requestResponse.hasResponse()) return false; " +
            "return requestResponse.request().hasParameters() && " +
            "requestResponse.response().mimeType() == burp.api.montoya.http.message.MimeType.HTML;");
        
        // Authentication Endpoints
        bambdas.put("auth_endpoints", 
            "return requestResponse.request().url().contains(\"login\") || " +
            "requestResponse.request().url().contains(\"signin\") || " +
            "requestResponse.request().url().contains(\"auth\") || " +
            "requestResponse.request().url().contains(\"logout\");");
        
        // Interesting Status Codes (only check if response exists)
        bambdas.put("interesting_status", 
            "if (!requestResponse.hasResponse()) return false; " +
            "return requestResponse.response().statusCode() == 403 || " +
            "requestResponse.response().statusCode() == 401 || " +
            "requestResponse.response().statusCode() == 500 || " +
            "requestResponse.response().statusCode() == 302;");
        
        // Make the map immutable for thread safety
        BAMBDA_LIBRARY = Collections.unmodifiableMap(bambdas);
    }
    
    public BambdaTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_bambda");
        tool.put("title", "Bambda Filters");
        tool.put("description", "Import preset or custom Bambda view filters written in Java. Import success means loaded without native errors; active filter state cannot be verified by this tool. " +
            "Bambdas are powerful filters written in Java that can filter Proxy history, Site map, and Logger. " +
            "Actions: APPLY_FILTER (use preset or custom), LIST_PRESETS (available filters), CREATE_CUSTOM (write Java filter), GET_ACTIVE_FILTER (compatibility action; always returns an unsupported error). " +
            "Presets include: authenticated_requests, api_endpoints, sql_injection_candidates, error_responses, xss_candidates.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);
        annotations.put("idempotentHint", false);  // CREATE_CUSTOM modifies filter state
        annotations.put("openWorldHint", true);
        annotations.put("title", "Bambda Filters");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "advanced filter lambda expression Java");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string", "Import a preset/custom filter or list presets. GET_ACTIVE_FILTER is unsupported and returns isError:true.", SUPPORTED_ACTIONS));
        
        properties.put("preset", McpUtils.createEnumProperty("string", "Pre-defined HTTP-history filter. Presets use the PROXY_HTTP_HISTORY Java context; other locations may reject them during native compilation.",
            List.of("authenticated_requests", "api_endpoints", "sql_injection_candidates", 
                    "error_responses", "file_uploads", "json_endpoints", "admin_interfaces",
                    "xss_candidates", "auth_endpoints", "interesting_status")));
        
        properties.put("customScript", McpUtils.createProperty("string", "Java filter source returning boolean. Bindings depend on the selected view: HTTP history and Logger use requestResponse, WebSocket history uses message, and Site map uses node. Their available methods differ; use the target view's Bambda editor context. HTTP-history example: 'return requestResponse.request().url().contains(\"/api\");'."));
        properties.put("description", McpUtils.createProperty("string", "Description for custom Bambda"));
        
        properties.put("location", McpUtils.createEnumProperty("string", "View location recorded in the imported filter (default: PROXY_HTTP_HISTORY). Choose Java source compatible with that view; importing does not confirm activation.",
            List.of("PROXY_HTTP_HISTORY", "PROXY_WS_HISTORY", "SITEMAP", "LOGGER")));

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        
        tool.put("inputSchema", inputSchema);
        tool.put("outputSchema", WorkflowOutputSchemas.forTool("burp_bambda"));
        
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
            StringBuilder result = new StringBuilder();
            
            boolean verbose = McpUtils.isVerbose(arguments);
            switch (action) {
                case "APPLY_FILTER":
                    return applyFilter(arguments, result, verbose);
                case "LIST_PRESETS":
                    return listPresets(result, verbose);
                case "CREATE_CUSTOM":
                    return createCustom(arguments, result, verbose);
                case "GET_ACTIVE_FILTER":
                    return getActiveFilter(result, verbose);
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in Bambda tool: " + McpUtils.sanitizeForLogging(e.getMessage()));
            return errorResponse("Error in Bambda operation: " + e.getMessage());
        }
    }
    
    private Object applyFilter(JsonNode arguments, StringBuilder result, boolean verbose) {
        String preset = McpUtils.getStringParam(arguments, "preset", "");
        String customScript = McpUtils.getStringParam(arguments, "customScript", "");
        String location = McpUtils.getStringParam(arguments, "location", "PROXY_HTTP_HISTORY");
        if (!preset.isEmpty() && !customScript.isEmpty()) {
            return errorResponse("Specify either preset or customScript, not both");
        }
        if (!preset.isEmpty() && !BAMBDA_LIBRARY.containsKey(preset)) {
            return errorResponse("Unknown Bambda preset: " + preset);
        }
        String script = preset.isEmpty() ? customScript : BAMBDA_LIBRARY.get(preset);
        if (script.isEmpty()) return errorResponse("preset or customScript is required for APPLY_FILTER");
        Map<String, Object> data = new HashMap<>();
        if (!preset.isEmpty()) data.put("preset", preset);
        else data.put("custom", true);
        return importFilter(script, preset.isEmpty() ? "MCP Custom Filter" : "MCP " + preset,
            location, data, verbose);
    }

    private Object importFilter(String script, String name, String location, Map<String, Object> data, boolean verbose) {
        String nativeLocation = switch (location) {
            case "PROXY_HTTP_HISTORY", "SITEMAP", "LOGGER" -> location;
            // Preserve the MCP enum while using Burp's Bambda import identifier.
            case "PROXY_WS_HISTORY" -> "PROXY_WEBSOCKET";
            default -> null;
        };
        if (nativeLocation == null) {
            return errorResponse("Unsupported Bambda location: " + location);
        }
        // JSON string quoting is also valid YAML and keeps names on one scalar line.
        String quotedName;
        try { quotedName = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(name); }
        catch (Exception e) { return errorResponse("Invalid Bambda description"); }
        String yaml = "id: mcp-" + java.util.UUID.randomUUID() + "\nname: " + quotedName
            + "\nfunction: VIEW_FILTER\nlocation: " + nativeLocation + "\nsource: |\n  "
            + script.replace("\r\n", "\n").replace('\r', '\n').replace("\n", "\n  ");
        data.put("location", location);
        try {
            BambdaImportResult imported = api.bambda().importBambda(yaml);
            boolean success = imported != null && imported.status() == BambdaImportResult.Status.LOADED_WITHOUT_ERRORS;
            data.put("success", success);
            data.put("status", imported == null || imported.status() == null ? "NO_RESULT" : imported.status().name());
            if (imported != null && imported.importErrors() != null && !imported.importErrors().isEmpty()) {
                data.put("errors", new ArrayList<>(imported.importErrors()));
            }
            data.put("message", success ? "Bambda imported without errors; active filter state cannot be inspected by this tool."
                : "Bambda import failed or reported errors");
            if (!success) {
                data.put("error", "bambda_import_failed");
                return errorResponse(data);
            }
        } catch (Exception e) {
            data.put("success", false);
            data.put("error", "bambda_import_failed");
            data.put("message", "Bambda import failed: " + e.getMessage());
            return errorResponse(data);
        }
        if (verbose) return textResponse(data.get("message") + "\nLocation: " + location);
        return McpUtils.createJsonResponse(data);
    }

    private Object listPresets(StringBuilder result, boolean verbose) {
        if (!verbose) {
            List<Map<String, String>> presets = new ArrayList<>();
            String[][] presetData = {
                {"authenticated_requests", "Find all authenticated traffic"},
                {"api_endpoints", "Discover API endpoints"},
                {"sql_injection_candidates", "Potential SQLi targets"},
                {"error_responses", "Server errors and exceptions"},
                {"file_uploads", "File upload functionality"},
                {"json_endpoints", "JSON API responses"},
                {"admin_interfaces", "Administrative panels"},
                {"xss_candidates", "Potential XSS injection points"},
                {"auth_endpoints", "Login/logout pages"},
                {"interesting_status", "Notable HTTP status codes"}
            };
            for (String[] p : presetData) {
                Map<String, String> m = new HashMap<>();
                m.put("name", p[0]);
                m.put("description", p[1]);
                presets.add(m);
            }
            return McpUtils.createJsonResponse(Map.of("presets", presets));
        }
        result.append("🎭 **AVAILABLE BAMBDA PRESETS**\n\n");
        
        result.append("**1. authenticated_requests** - Find all authenticated traffic\n");
        result.append("   • Filters: Authorization header, Cookie header\n\n");
        
        result.append("**2. api_endpoints** - Discover API endpoints\n");
        result.append("   • Filters: /api/, /v1/, /v2/ paths\n\n");
        
        result.append("**3. sql_injection_candidates** - Potential SQLi targets\n");
        result.append("   • Filters: Requests with id=, user=, search= parameters\n\n");
        
        result.append("**4. error_responses** - Server errors and exceptions\n");
        result.append("   • Filters: 4xx/5xx status, error messages\n\n");
        
        result.append("**5. file_uploads** - File upload functionality\n");
        result.append("   • Filters: multipart/form-data requests\n\n");
        
        result.append("**6. json_endpoints** - JSON API responses\n");
        result.append("   • Filters: application/json responses\n\n");
        
        result.append("**7. admin_interfaces** - Administrative panels\n");
        result.append("   • Filters: admin, manage, dashboard, config URLs\n\n");
        
        result.append("**8. xss_candidates** - Potential XSS injection points\n");
        result.append("   • Filters: HTML responses with parameters\n\n");
        
        result.append("**9. auth_endpoints** - Login/logout pages\n");
        result.append("   • Filters: login, signin, auth, logout URLs\n\n");
        
        result.append("**10. interesting_status** - Notable HTTP status codes\n");
        result.append("   • Filters: 401, 403, 500, 302 responses\n\n");
        
        result.append("💡 **Usage:** Apply with `action: APPLY_FILTER, preset: <name>`\n");
        
        return textResponse(result.toString());
    }
    
    private Object createCustom(JsonNode arguments, StringBuilder result, boolean verbose) {
        String script = McpUtils.getStringParam(arguments, "customScript", "");
        if (script.isEmpty()) return errorResponse("customScript is required for CREATE_CUSTOM");
        String description = McpUtils.getStringParam(arguments, "description", "Custom filter");
        String location = McpUtils.getStringParam(arguments, "location", "PROXY_HTTP_HISTORY");
        Map<String, Object> data = new HashMap<>();
        data.put("description", description);
        return importFilter(script, description, location, data, verbose);
    }

    private Object getActiveFilter(StringBuilder result, boolean verbose) {
        return errorResponse(Map.of("error", "api_limitation", "supported", false,
            "message", "GET_ACTIVE_FILTER is unsupported: this tool cannot inspect Burp's active Bambda filter.",
            "workaround", "Use the filter bar in the relevant Burp view to inspect its active filter"));
    }

    private static Object textResponse(String text) {
        return Map.of("content", List.of(Map.of("type", "text", "text", text)),
            "structuredContent", Map.of("text", text));
    }

    private static Object errorResponse(String message) {
        return errorResponse(Map.of("error", "bambda_error", "message", message));
    }

    private static Object errorResponse(Map<String, Object> data) {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) McpUtils.createJsonResponse(data);
        result.put("isError", true);
        return result;
    }

    private String getLocationDescription(String location) {
        switch (location) {
            case "PROXY_HTTP_HISTORY":
                return "Proxy → HTTP history";
            case "PROXY_WS_HISTORY":
                return "Proxy → WebSocket history";
            case "SITEMAP":
                return "Target → Site map";
            case "LOGGER":
                return "Logger";
            default:
                return location;
        }
    }
    
    private String getFilterEffect(String location) {
        switch (location) {
            case "PROXY_HTTP_HISTORY":
                return "HTTP proxy history is now filtered to show only matching requests";
            case "PROXY_WS_HISTORY":
                return "WebSocket history is now filtered to show only matching messages";
            case "SITEMAP":
                return "Site map is now filtered to show only matching items";
            case "LOGGER":
                return "Logger view is now filtered to show only matching entries";
            default:
                return "Filter is now active in " + location;
        }
    }
    
    private String getLocationTip(String location) {
        switch (location) {
            case "PROXY_HTTP_HISTORY":
                return "Check Proxy → HTTP history to see filtered results";
            case "PROXY_WS_HISTORY":
                return "Check Proxy → WebSocket history to see filtered WebSocket messages";
            case "SITEMAP":
                return "Check Target → Site map to see filtered site structure";
            case "LOGGER":
                return "Check Logger to see filtered log entries";
            default:
                return "Check the appropriate tab to see filtered results";
        }
    }
}
