package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.bambda.BambdaImportResult;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashMap;
import java.util.Map;
import java.util.List;
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
            "requestResponse.response().mimeType().equals(\"HTML\");");
        
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
        tool.put("description", "Create and apply advanced Bambda filters for intelligent traffic filtering using Java code. " +
            "Bambdas are powerful filters written in Java that can filter Proxy history, Site map, and Logger. " +
            "Actions: APPLY_FILTER (use preset or custom), LIST_PRESETS (available filters), CREATE_CUSTOM (write Java filter), GET_ACTIVE_FILTER. " +
            "Presets include: authenticated_requests, api_endpoints, sql_injection_candidates, error_responses, xss_candidates.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);  // CREATE_CUSTOM modifies filter state
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        properties.put("action", McpUtils.createEnumProperty("string", "Bambda action to perform", SUPPORTED_ACTIONS));
        
        properties.put("preset", McpUtils.createEnumProperty("string", "Pre-defined Bambda filter", 
            List.of("authenticated_requests", "api_endpoints", "sql_injection_candidates", 
                    "error_responses", "file_uploads", "json_endpoints", "admin_interfaces",
                    "xss_candidates", "auth_endpoints", "interesting_status")));
        
        properties.put("customScript", McpUtils.createProperty("string", "Custom Bambda script (Java code)"));
        properties.put("description", McpUtils.createProperty("string", "Description for custom Bambda"));
        
        properties.put("location", McpUtils.createEnumProperty("string", "Where to apply the Bambda (default: PROXY_HTTP_HISTORY)",
            List.of("PROXY_HTTP_HISTORY", "PROXY_WS_HISTORY", "SITEMAP", "LOGGER")));
        
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
                case "APPLY_FILTER":
                    return applyFilter(arguments, result);
                case "LIST_PRESETS":
                    return listPresets(result);
                case "CREATE_CUSTOM":
                    return createCustom(arguments, result);
                case "GET_ACTIVE_FILTER":
                    return getActiveFilter(result);
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error in Bambda tool: " + McpUtils.sanitizeForLogging(e.getMessage()));
            return McpUtils.createErrorResponse("Error in Bambda operation: " + e.getMessage());
        }
    }
    
    private Object applyFilter(JsonNode arguments, StringBuilder result) {
        result.append("🎭 **BAMBDA FILTER APPLICATION**\n\n");
        
        String preset = McpUtils.getStringParam(arguments, "preset", "");
        String customScript = McpUtils.getStringParam(arguments, "customScript", "");
        String location = McpUtils.getStringParam(arguments, "location", "PROXY_HTTP_HISTORY");
        
        if (!preset.isEmpty() && BAMBDA_LIBRARY.containsKey(preset)) {
            // Apply preset Bambda
            String scriptCode = BAMBDA_LIBRARY.get(preset);
            
            // Create proper YAML format for Bambda import
            String bambdaYaml = String.format(
                "id: %s\n" +
                "name: %s\n" +
                "function: VIEW_FILTER\n" +
                "location: %s\n" +
                "source: |\n  %s",
                "mcp-" + preset + "-" + System.currentTimeMillis(),
                "MCP " + preset.replace("_", " "),
                location,
                scriptCode.replace("\n", "\n  ")
            );
            
            try {
                BambdaImportResult importResult = api.bambda().importBambda(bambdaYaml);
                
                if (importResult != null) {
                    // Check the actual status using the Montoya API methods
                    if (importResult.status() == BambdaImportResult.Status.LOADED_WITHOUT_ERRORS) {
                        result.append("✅ **Filter Applied Successfully**\n");
                        result.append("**Type:** ").append(preset).append("\n");
                        result.append("**Location:** ").append(getLocationDescription(location)).append("\n");
                        result.append("**Script:** `").append(scriptCode).append("`\n\n");
                        result.append("📊 **Effect:** ").append(getFilterEffect(location)).append("\n");
                        result.append("💡 **Tip:** ").append(getLocationTip(location)).append("\n");
                    } else if (importResult.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS) {
                        result.append("⚠️ **Filter Applied with Errors**\n");
                        result.append("**Type:** ").append(preset).append("\n");
                        List<String> errors = importResult.importErrors();
                        if (errors != null && !errors.isEmpty()) {
                            result.append("**Errors:**\n");
                            for (String error : errors) {
                                result.append("  • ").append(error).append("\n");
                            }
                        }
                        result.append("\n**Note:** The filter may be partially functional\n");
                    }
                } else {
                    result.append("❌ **Filter Application Failed**\n");
                    result.append("**Error:** Import returned null (this shouldn't happen)\n");
                }
                
            } catch (Exception e) {
                result.append("❌ **Error applying filter:** ").append(e.getMessage()).append("\n");
                result.append("**Possible causes:**\n");
                result.append("  • Syntax error in the Bambda script\n");
                result.append("  • Missing imports or undefined variables\n");
                result.append("  • Invalid Java code\n");
            }
            
        } else if (!customScript.isEmpty()) {
            // Apply custom Bambda
            // Create proper YAML format for Bambda import
            String bambdaYaml = String.format(
                "id: %s\n" +
                "name: %s\n" +
                "function: VIEW_FILTER\n" +
                "location: %s\n" +
                "source: |\n  %s",
                "mcp-custom-" + System.currentTimeMillis(),
                "MCP Custom Filter",
                location,
                customScript.replace("\n", "\n  ")
            );
            
            try {
                BambdaImportResult importResult = api.bambda().importBambda(bambdaYaml);
                
                if (importResult != null) {
                    // Check the actual status using the Montoya API methods
                    if (importResult.status() == BambdaImportResult.Status.LOADED_WITHOUT_ERRORS) {
                        result.append("✅ **Custom Filter Applied Successfully**\n");
                        result.append("**Location:** ").append(getLocationDescription(location)).append("\n");
                        result.append("**Script:** `").append(customScript).append("`\n\n");
                        result.append("📊 **Effect:** ").append(getFilterEffect(location)).append("\n");
                    } else if (importResult.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS) {
                        result.append("⚠️ **Custom Filter Applied with Errors**\n");
                        result.append("**Script:** `").append(customScript).append("`\n\n");
                        List<String> errors = importResult.importErrors();
                        if (errors != null && !errors.isEmpty()) {
                            result.append("**Compilation Errors:**\n");
                            for (String error : errors) {
                                result.append("  • ").append(error).append("\n");
                            }
                        }
                        result.append("\n**Note:** Fix the errors above for the filter to work correctly\n");
                    }
                } else {
                    result.append("❌ **Custom Filter Failed**\n");
                    result.append("**Error:** Import returned null\n");
                }
                
            } catch (Exception e) {
                result.append("❌ **Error with custom filter:** ").append(e.getMessage()).append("\n");
                result.append("**Check:** Ensure your script is valid Java code\n");
            }
            
        } else {
            result.append("❌ **No filter specified**\n");
            result.append("Use 'preset' for pre-defined filters or 'customScript' for custom Java code\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object listPresets(StringBuilder result) {
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
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object createCustom(JsonNode arguments, StringBuilder result) {
        result.append("🎭 **CUSTOM BAMBDA CREATION**\n\n");
        
        String customScript = McpUtils.getStringParam(arguments, "customScript", "");
        String description = McpUtils.getStringParam(arguments, "description", "Custom filter");
        String location = McpUtils.getStringParam(arguments, "location", "PROXY_HTTP_HISTORY");
        
        if (customScript.isEmpty()) {
            result.append("❌ **No custom script provided**\n\n");
            result.append("📝 **Example Custom Bambdas:**\n\n");
            
            result.append("**Find specific header:**\n");
            result.append("```java\n");
            result.append("return requestResponse.request().hasHeader(\"X-API-Key\");\n");
            result.append("```\n\n");
            
            result.append("**Complex parameter filtering:**\n");
            result.append("```java\n");
            result.append("return requestResponse.request().hasParameters() &&\n");
            result.append("       requestResponse.request().parameters().stream()\n");
            result.append("           .anyMatch(p -> p.name().equals(\"action\") && p.value().equals(\"search\"));\n");
            result.append("```\n\n");
            
            result.append("**Response size filtering:**\n");
            result.append("```java\n");
            result.append("return requestResponse.response().body().length() > 10000;\n");
            result.append("```\n\n");
            
            result.append("**HTTP version filtering:**\n");
            result.append("```java\n");
            result.append("if (!requestResponse.hasResponse()) return false;\n");
            result.append("return requestResponse.response().httpVersion().equals(\"HTTP/2\");\n");
            result.append("```\n\n");
            
            result.append("**Available objects in Bambda scripts:**\n");
            result.append("  • `requestResponse` - ProxyHttpRequestResponse object\n");
            result.append("  • `requestResponse.request()` - The HTTP request\n");
            result.append("  • `requestResponse.response()` - The HTTP response (may be null)\n");
            result.append("  • `requestResponse.hasResponse()` - Check if response exists\n");
            
        } else {
            // Create proper YAML format for Bambda import
            String bambdaYaml = String.format(
                "id: %s\n" +
                "name: %s\n" +
                "function: VIEW_FILTER\n" +
                "location: %s\n" +
                "source: |\n  %s",
                "mcp-" + description.toLowerCase().replace(" ", "-") + "-" + System.currentTimeMillis(),
                description,
                location,
                customScript.replace("\n", "\n  ")
            );
            
            try {
                BambdaImportResult importResult = api.bambda().importBambda(bambdaYaml);
                
                if (importResult != null) {
                    // Check the actual status using the Montoya API methods
                    if (importResult.status() == BambdaImportResult.Status.LOADED_WITHOUT_ERRORS) {
                        result.append("✅ **Custom Bambda Created**\n");
                        result.append("**Description:** ").append(description).append("\n");
                        result.append("**Location:** ").append(getLocationDescription(location)).append("\n");
                        result.append("**Status:** Successfully imported and active\n");
                    } else if (importResult.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS) {
                        result.append("⚠️ **Custom Bambda Created with Errors**\n");
                        result.append("**Description:** ").append(description).append("\n");
                        List<String> errors = importResult.importErrors();
                        if (errors != null && !errors.isEmpty()) {
                            result.append("**Errors to fix:**\n");
                            for (String error : errors) {
                                result.append("  • ").append(error).append("\n");
                            }
                        }
                    }
                } else {
                    result.append("❌ **Custom Bambda Failed**\n");
                    result.append("**Error:** Import returned null\n");
                }
                
            } catch (Exception e) {
                result.append("❌ **Error creating custom Bambda:** ").append(e.getMessage()).append("\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getActiveFilter(StringBuilder result) {
        result.append("🎭 **ACTIVE BAMBDA FILTER**\n\n");
        
        // Document the Montoya API limitation
        result.append("⚠️ **Montoya API Limitation:**\n");
        result.append("The Bambda interface in Montoya API 2025.8 only provides:\n");
        result.append("  • `importBambda(String script)` - To import/apply a Bambda\n\n");
        
        result.append("**Not Available via API:**\n");
        result.append("  • Retrieve currently active Bambda filter\n");
        result.append("  • List all available Bambdas in library\n");
        result.append("  • Export Bambda scripts\n");
        result.append("  • Validate Bambda syntax before import\n\n");
        
        result.append("📋 **Manual Workaround:**\n");
        result.append("1. Go to Proxy → HTTP history\n");
        result.append("2. Click the filter bar\n");
        result.append("3. Switch to 'Bambda mode' to see the active script\n");
        result.append("4. Or go to Extensions → Bambda library to manage your Bambdas\n\n");
        
        result.append("💡 **Available Actions:**\n");
        result.append("  • Use `LIST_PRESETS` to see pre-defined filters\n");
        result.append("  • Use `APPLY_FILTER` to apply a new filter\n");
        result.append("  • Use `CREATE_CUSTOM` to create custom filters\n");
        
        return McpUtils.createSuccessResponse(result.toString());
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
