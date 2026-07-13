package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * burp_config — read and write Burp Suite project and user options as JSON, via Montoya's
 * {@code burpSuite().exportProjectOptionsAsJson / importProjectOptionsFromJson} (and the
 * user-options pair). This is the general primitive behind capabilities the typed APIs
 * don't expose — e.g. advanced target scope with "include subdomains", proxy listeners,
 * session-handling rules, upstream proxies, TLS/redirect settings.
 */
public class ConfigTool implements McpTool {
    private final MontoyaApi api;
    private final ObjectMapper mapper = new ObjectMapper();
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "GET_PROJECT_OPTIONS",
        "SET_PROJECT_OPTIONS",
        "GET_USER_OPTIONS",
        "SET_USER_OPTIONS"
    );

    public ConfigTool(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_config");
        tool.put("title", "Burp Configuration (project/user options JSON)");
        tool.put("description",
            "Read and write Burp Suite PROJECT and USER options as JSON. General config primitive for settings the "
            + "typed tools don't expose. Actions: GET_PROJECT_OPTIONS / GET_USER_OPTIONS (export; pass 'path' like "
            + "'target.scope' or 'proxy' to scope the export — omitting it exports EVERYTHING, which can be very large), "
            + "SET_PROJECT_OPTIONS / SET_USER_OPTIONS (import the JSON in 'json'). "
            + "⚠️ SET replaces the options contained in the supplied JSON — always GET the relevant subtree first, modify "
            + "it, then SET the whole modified subtree back (importing a partial array REPLACES that array, so preserve "
            + "existing entries). ⚠️ Exports can contain STORED SECRETS IN CLEARTEXT (platform-authentication credentials, "
            + "upstream-proxy/SOCKS passwords, client-certificate material) — scope the export with 'path' and don't paste "
            + "full dumps into untrusted places. Example (include-subdomains scope): GET path 'target.scope' → set advanced_mode=true and "
            + "append {enabled:true,protocol:'any',host:'^(?:.*\\\\.)?example\\\\.com$',port:'',file:''} to include[] → "
            + "SET_PROJECT_OPTIONS with the modified JSON. For simple scope add/remove use burp_scope instead.");

        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);   // SET_* can overwrite existing configuration
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        annotations.put("title", "Burp Configuration");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "burp settings project user options import export json scope proxy config");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        Map<String, Object> properties = new HashMap<>();

        properties.put("action", McpUtils.createEnumProperty("string",
            "Config action to perform", SUPPORTED_ACTIONS));

        Map<String, Object> pathProperty = new HashMap<>();
        pathProperty.put("type", "string");
        pathProperty.put("description", "GET only: dotted options path to export (e.g. 'target.scope', 'proxy', "
            + "'project_options.connections'). Omit to export ALL options (can be very large). Ignored for SET.");
        properties.put("path", pathProperty);

        Map<String, Object> jsonProperty = new HashMap<>();
        jsonProperty.put("type", "string");
        jsonProperty.put("description", "SET only (required): the options JSON to import, in the same full nested shape "
            + "GET returns (e.g. {\"target\":{\"scope\":{...}}}).");
        properties.put("json", jsonProperty);

        Map<String, Object> verboseProperty = new HashMap<>();
        verboseProperty.put("type", "boolean");
        verboseProperty.put("default", false);
        verboseProperty.put("description", "Return decorated markdown instead of compact JSON.");
        properties.put("verbose", verboseProperty);

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
        String action = actionResolution.getAction().toUpperCase();
        String path = McpUtils.getTrimmedStringParam(arguments, "path");

        try {
            switch (action) {
                case "GET_PROJECT_OPTIONS":
                    return exportOptions(arguments, path, false);
                case "GET_USER_OPTIONS":
                    return exportOptions(arguments, path, true);
                case "SET_PROJECT_OPTIONS":
                    return importOptions(arguments, false);
                case "SET_USER_OPTIONS":
                    return importOptions(arguments, true);
                default:
                    return McpUtils.createErrorResponse("Unsupported action: " + action);
            }
        } catch (Exception e) {
            api.logging().logToError("ConfigTool " + action + " failed: " + McpUtils.sanitizeForLogging(e.getMessage()));
            return McpUtils.createErrorResponse(action + " failed: " + e.getMessage());
        }
    }

    private Object exportOptions(JsonNode arguments, String path, boolean userOptions) {
        String json = (path == null || path.isEmpty())
            ? (userOptions ? api.burpSuite().exportUserOptionsAsJson() : api.burpSuite().exportProjectOptionsAsJson())
            : (userOptions ? api.burpSuite().exportUserOptionsAsJson(path) : api.burpSuite().exportProjectOptionsAsJson(path));

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("action", userOptions ? "GET_USER_OPTIONS" : "GET_PROJECT_OPTIONS");
            data.put("scope", userOptions ? "user" : "project");
            if (path != null && !path.isEmpty()) data.put("path", path);
            data.put("json", json);
            data.put("length", json != null ? json.length() : 0);
            return McpUtils.createJsonResponse(data);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("## ").append(userOptions ? "User" : "Project").append(" options");
        if (path != null && !path.isEmpty()) sb.append(" — path `").append(path).append('`');
        sb.append("\n\n```json\n").append(json).append("\n```\n");
        return McpUtils.createSuccessResponse(sb.toString());
    }

    private Object importOptions(JsonNode arguments, boolean userOptions) {
        String json = McpUtils.getTrimmedStringParam(arguments, "json");
        if (json == null || json.isEmpty()) {
            return McpUtils.createErrorResponse("'json' is required for SET_" + (userOptions ? "USER" : "PROJECT") + "_OPTIONS");
        }
        // Validate it parses before handing it to Burp, for a cleaner error.
        try {
            mapper.readTree(json);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Invalid JSON: " + e.getMessage());
        }

        if (userOptions) {
            api.burpSuite().importUserOptionsFromJson(json);
        } else {
            api.burpSuite().importProjectOptionsFromJson(json);
        }

        List<String> topKeys = new ArrayList<>();
        try {
            JsonNode root = mapper.readTree(json);
            root.fieldNames().forEachRemaining(topKeys::add);
        } catch (Exception ignored) { }

        if (!McpUtils.isVerbose(arguments)) {
            Map<String, Object> data = new HashMap<>();
            data.put("action", userOptions ? "SET_USER_OPTIONS" : "SET_PROJECT_OPTIONS");
            data.put("success", true);
            data.put("importedTopLevelKeys", topKeys);
            return McpUtils.createJsonResponse(data);
        }
        return McpUtils.createSuccessResponse("✅ Imported " + (userOptions ? "user" : "project")
            + " options (top-level keys: " + String.join(", ", topKeys) + ")");
    }
}
