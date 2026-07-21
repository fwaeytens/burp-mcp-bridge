package com.example.burpmcp;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agent-facing metadata overlay.
 *
 * Tool implementations keep their detailed descriptions for burp_help. This
 * class adds the machine-readable contract details agents need during
 * discovery, and provides shorter descriptions for tools/list so the initial
 * inventory is scannable instead of reading like full documentation.
 */
final class AgentToolMetadata {
    static final String ACTION_REQUIREMENTS_KEY = "x-burp-actionRequirements";

    private static final Map<String, String> SHORT_DESCRIPTIONS = Map.ofEntries(
        Map.entry("burp_help", "Discover tools, search capabilities, and fetch detailed parameters, examples, and workflows. Use this first when you are unsure which Burp MCP tool fits."),
        Map.entry("burp_proxy_history", "Read chronological HTTP traffic captured through Burp's proxy. Use list, detail, or iterate; use burp_sitemap_analysis for deduplicated site-wide structure."),
        Map.entry("burp_repeater", "Create Burp Repeater UI tabs for manual testing only. This tool does not send requests; use burp_custom_http for programmatic HTTP."),
        Map.entry("burp_proxy_interceptor", "Manually hold, inspect, modify, forward, or drop browser proxy traffic. Scope enable with filters and trigger held requests non-blocking."),
        Map.entry("burp_scanner", "Start Burp scans and crawls, track progress, retrieve issues, import BChecks, and scan raw requests with targeted insertion points."),
        Map.entry("burp_intruder", "Configure Burp Intruder UI attacks and insertion positions for manual execution. It does not run attacks programmatically."),
        Map.entry("burp_add_issue", "Create custom Burp audit issues with evidence, severity, remediation, and optional proxy-history-derived request/response context."),
        Map.entry("burp_session_management", "Manage tokens, Burp's cookie jar, session validation, and automatic session handling actions."),
        Map.entry("burp_comparer", "Compare requests, responses, text, or proxy entries, or send data to Burp Comparer UI."),
        Map.entry("burp_collaborator", "Generate Burp Collaborator payloads and poll out-of-band DNS, HTTP, HTTPS, and SMTP interactions."),
        Map.entry("burp_scope", "View, add, remove, check, and analyze Burp target scope, including bulk operations."),
        Map.entry("burp_config", "Read and write Burp project or user options JSON for settings not covered by typed tools."),
        Map.entry("burp_organizer", "Send requests to Organizer and query Organizer items, counts, filters, and status."),
        Map.entry("burp_annotate", "Add notes and highlights across Burp data sources, search annotations, and manage auto-annotation rules."),
        Map.entry("burp_sitemap_analysis", "Analyze Burp Site Map structure, technologies, attack surface, response statistics, and site-wide findings."),
        Map.entry("burp_bambda", "Apply preset or custom Bambda filters to Burp views and inspect the active filter."),
        Map.entry("burp_global_interceptor", "Automatically apply auth, headers, match/replace rules, and rate limits across traffic from all Burp tools."),
        Map.entry("burp_custom_http", "Primary programmatic HTTP client for single, parallel, and pipelined requests, protocol analysis, and raw request work."),
        Map.entry("burp_logs", "Read extension logs, write diagnostic entries, raise Burp events, and clear captured logs."),
        Map.entry("burp_websocket", "Inspect WebSocket proxy history and create, send on, list, or close extension WebSocket connections."),
        Map.entry("burp_websocket_interceptor", "Intercept, inspect, modify, forward, or drop WebSocket frames and manage frame filters and auto-modify rules."),
        Map.entry("burp_response_analyzer", "Analyze individual HTTP responses for keywords, variations, reflection points, patterns, and anomalies."),
        Map.entry("burp_utilities", "Use Burp utilities for encoding, hashing, JSON operations, byte search, number conversion, and opt-in shell execution.")
    );

    private static final Map<String, Map<String, Map<String, Object>>> INPUT_PROPERTY_OVERLAYS =
        buildInputPropertyOverlays();

    private AgentToolMetadata() {
    }

    static Map<String, Object> enrichToolInfo(String toolName, Map<String, Object> rawToolInfo) {
        Map<String, Object> toolInfo = deepCopyMap(rawToolInfo);
        ToolDescriptor descriptor = ToolRegistry.get(toolName);
        if (descriptor == null) {
            return toolInfo;
        }

        Map<String, Object> inputSchema = ensureMap(toolInfo, "inputSchema");
        Map<String, Object> properties = ensureMap(inputSchema, "properties");
        Map<String, Map<String, Object>> overlays = INPUT_PROPERTY_OVERLAYS.get(toolName);
        if (overlays != null) {
            for (Map.Entry<String, Map<String, Object>> entry : overlays.entrySet()) {
                Map<String, Object> existing = safeMap(properties.get(entry.getKey()));
                properties.put(entry.getKey(), mergeMaps(existing, entry.getValue()));
            }
        }

        Map<String, List<String>> actionRequirements = actionRequirementsFor(toolName, toolInfo);
        if (!actionRequirements.isEmpty()) {
            inputSchema.put(ACTION_REQUIREMENTS_KEY, actionRequirements);
        }

        Map<String, Object> meta = ensureMap(toolInfo, "_meta");
        meta.put("burp/category", descriptor.getCategory());
        meta.put("burp/help", "Use burp_help with tool='" + toolName + "' for full examples and workflows.");
        if (!actionRequirements.isEmpty()) {
            meta.put("burp/actionRequirements", actionRequirements);
        }

        toolInfo.put("outputSchema", normalizeOutputSchema(toolName, toolInfo.get("outputSchema")));
        return toolInfo;
    }

    static Map<String, Object> forToolsList(String toolName, Map<String, Object> rawToolInfo) {
        Map<String, Object> toolInfo = enrichToolInfo(toolName, rawToolInfo);
        String shortDescription = SHORT_DESCRIPTIONS.get(toolName);
        if (shortDescription != null) {
            toolInfo.put("description", shortDescription);
        }
        return toolInfo;
    }

    static Map<String, List<String>> actionRequirementsFor(String toolName, Map<String, Object> toolInfo) {
        ToolDescriptor descriptor = ToolRegistry.get(toolName);
        if (descriptor == null) {
            return Map.of();
        }

        Map<String, List<String>> curated = descriptor.getActionRequirements();
        List<String> actions = extractActionValues(toolInfo);
        if (actions.isEmpty() && curated.isEmpty()) {
            return Map.of();
        }

        Map<String, List<String>> complete = new LinkedHashMap<>();
        for (String action : actions) {
            complete.put(action, curated.getOrDefault(action, List.of()));
        }
        for (Map.Entry<String, List<String>> entry : curated.entrySet()) {
            complete.putIfAbsent(entry.getKey(), entry.getValue());
        }
        return complete;
    }

    static String shortDescriptionFor(String toolName) {
        return SHORT_DESCRIPTIONS.get(toolName);
    }

    private static Map<String, Object> normalizeOutputSchema(String toolName, Object outputSchemaObj) {
        Map<String, Object> outputSchema = safeMap(outputSchemaObj);
        outputSchema = outputSchema == null ? new LinkedHashMap<>() : deepCopyMap(outputSchema);
        outputSchema.putIfAbsent("type", "object");
        outputSchema.putIfAbsent("description",
            "Action-dependent structured result for " + toolName + ". Compact responses expose action-specific fields; verbose responses expose text.");
        outputSchema.putIfAbsent("additionalProperties", true);

        Map<String, Object> properties = ensureMap(outputSchema, "properties");
        properties.putIfAbsent("text", stringSchema("Human-readable response when verbose output is requested."));
        properties.putIfAbsent("items", arraySchema("Array result when a tool returns a top-level list.", anyJsonSchema("Array item.")));
        properties.putIfAbsent("truncated", booleanSchema("True when the bridge replaced an oversized structured result with a truncation summary."));
        properties.putIfAbsent("originalChars", integerSchema("Serialized result size before bridge truncation."));
        properties.putIfAbsent("limitChars", integerSchema("Bridge result-size limit used for truncation."));
        return outputSchema;
    }

    private static Map<String, Map<String, Map<String, Object>>> buildInputPropertyOverlays() {
        Map<String, Map<String, Map<String, Object>>> overlays = new LinkedHashMap<>();

        overlays.put("burp_proxy_interceptor", Map.of(
            "request_id", stringSchema("Request ID from get_queue. Legacy alias for response_id on response actions."),
            "response_id", stringSchema("Response ID from get_response_queue for response actions."),
            "modifications", objectSchema(
                "Fields to change before forwarding. Request actions use method/path/body/headers; response actions also support status_code and reason_phrase.",
                linkedMap(
                    "add_headers", stringMapSchema("Headers to add or replace."),
                    "remove_headers", arraySchema("Header names to remove.", stringSchema("Header name.")),
                    "replace_body", stringSchema("Replacement body."),
                    "method", stringSchema("Replacement request method."),
                    "path", stringSchema("Replacement request path."),
                    "status_code", integerSchema("Replacement response status code."),
                    "reason_phrase", stringSchema("Replacement response reason phrase.")
                ),
                false),
            "options", objectSchema(
                "Optional request handling behavior for modify_request.",
                linkedMap(
                    "drop", booleanSchema("Drop instead of forwarding the request."),
                    "intercept_ui", booleanSchema("Also show the request in Burp's UI intercept view."),
                    "highlight_color", enumSchema("Annotation highlight color.", List.of("RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY", "NONE")),
                    "description", stringSchema("Annotation description.")
                ),
                false)
        ));

        overlays.put("burp_global_interceptor", Map.of(
            "rule", objectSchema(
                "Rule config used by add_request_rule/add_response_rule/add_websocket_rule. HTTP rules match url_pattern/method/headers/status and modify headers, body, method, path, or status. WebSocket rules use match_pattern/replace_text/direction/drop.",
                linkedMap(
                    "description", stringSchema("Human-readable rule description."),
                    "url_pattern", stringSchema("URL substring or regex to match for HTTP rules."),
                    "use_regex", booleanSchema("Treat url_pattern or match_pattern as a regex."),
                    "method", stringSchema("HTTP method to match for request rules."),
                    "required_headers", stringMapSchema("Headers that must already be present for a request rule to match."),
                    "status_code", integerSchema("Exact response status code to match."),
                    "status_range", stringSchema("Response status range to match, for example 400-499."),
                    "content_type", stringSchema("Response Content-Type substring to match."),
                    "add_headers", stringMapSchema("Headers to add or replace."),
                    "remove_headers", arraySchema("Header names to remove.", stringSchema("Header name.")),
                    "body_search", stringSchema("Body text or regex to replace."),
                    "body_replace", stringSchema("Replacement body text."),
                    "change_method", stringSchema("Replacement request method."),
                    "change_path", stringSchema("Replacement request path."),
                    "change_status", integerSchema("Replacement response status code."),
                    "change_reason", stringSchema("Replacement response reason phrase."),
                    "match_pattern", stringSchema("WebSocket payload text or regex to match."),
                    "replace_text", stringSchema("Replacement WebSocket payload text."),
                    "direction", enumSchema("WebSocket direction filter.", List.of("both", "client_to_server", "server_to_client")),
                    "drop", booleanSchema("Drop matching WebSocket messages.")
                ),
                false),
            "mode", objectSchema(
                "Inline interception mode settings.",
                linkedMap(
                    "intercept_requests", booleanSchema("Enable request transformations."),
                    "intercept_responses", booleanSchema("Enable response transformations."),
                    "intercept_websockets", booleanSchema("Enable WebSocket transformations."),
                    "use_event_queue", booleanSchema("Use the internal event queue.")
                ),
                false),
            "tools", arraySchema("Burp tool sources allowed to pass through the global interceptor.",
                enumSchema("Burp tool source.", List.of("SUITE", "TARGET", "PROXY", "SCANNER", "INTRUDER", "REPEATER", "LOGGER", "SEQUENCER", "DECODER", "COMPARER", "EXTENSIONS", "RECORDED_LOGIN_REPLAYER", "ORGANIZER", "BURP_AI"))),
            "rules_data", objectSchema(
                "Object returned by export_rules and accepted by import_rules.",
                linkedMap(
                    "requestRules", ruleExportArraySchema("Exported request rules."),
                    "responseRules", ruleExportArraySchema("Exported response rules."),
                    "webSocketRules", ruleExportArraySchema("Exported WebSocket rules."),
                    "globalHeaders", stringMapSchema("Global headers."),
                    "settings", objectSchema("Exported interceptor settings.", linkedMap(
                        "requestInterception", booleanSchema("Whether request interception is enabled."),
                        "responseInterception", booleanSchema("Whether response interception is enabled."),
                        "webSocketInterception", booleanSchema("Whether WebSocket interception is enabled."),
                        "rateLimitDelay", integerSchema("Rate limit delay in milliseconds."),
                        "authType", stringSchema("Configured authentication type."),
                        "authValue", stringSchema("Configured authentication value."),
                        "authHeader", stringSchema("Configured authentication header.")
                    ), true)
                ),
                false)
        ));

        overlays.put("burp_scanner", Map.of(
            "headers", stringMapSchema("Additional HTTP headers to include in scan requests."),
            "cookies", stringMapSchema("Cookies to include as name/value pairs."),
            "insertionPoints", arraySchema("Explicit insertion point byte ranges.", objectSchema(
                "Insertion point range.",
                linkedMap(
                    "start", integerSchema("Inclusive start byte offset."),
                    "end", integerSchema("Exclusive end byte offset.")
                ),
                false,
                List.of("start", "end")))
        ));

        overlays.put("burp_add_issue", Map.of(
            "filters", objectSchema(
                "Proxy history filters used to locate evidence requests.",
                linkedMap(
                    "hostname", stringSchema("Hostname substring filter."),
                    "method", stringSchema("HTTP method filter."),
                    "path", stringSchema("URL path substring filter."),
                    "statusCode", integerSchema("Exact response status code."),
                    "statusRange", stringSchema("Response status range, for example 200-299."),
                    "contains", stringSchema("Text to search for in request or response."),
                    "regex", stringSchema("Regex to search for in request or response."),
                    "parameter", stringSchema("Parameter name filter."),
                    "cookieName", stringSchema("Cookie name filter."),
                    "inScopeOnly", booleanSchema("Only use in-scope entries."),
                    "hasResponse", booleanSchema("Require a response.")
                ),
                true)
        ));

        overlays.put("burp_annotate", Map.of(
            "autoRules", objectSchema(
                "Auto-annotation rules applied to matching proxy request URLs.",
                linkedMap(
                    "urlPatterns", arraySchema("URL substrings to match.", stringSchema("URL substring.")),
                    "notes", stringSchema("Notes to apply to matching requests."),
                    "color", enumSchema("Highlight color to apply.", List.of("RED", "ORANGE", "YELLOW", "GREEN", "CYAN", "BLUE", "PINK", "MAGENTA", "GRAY", "NONE"))
                ),
                false)
        ));

        overlays.put("burp_response_analyzer", Map.of(
            "keywords", arraySchema("Keywords to search for in responses.", stringSchema("Keyword.")),
            "urls", arraySchema("URLs to send or analyze for response variations.", stringSchema("URL.")),
            "proxyIds", arraySchema("Proxy history IDs to inspect for reflections.", integerSchema("Proxy history entry ID."))
        ));

        overlays.put("burp_utilities", Map.of(
            "commandArgs", arraySchema("Command and arguments for safe shell_execute.", stringSchema("Command argument.")),
            "envVars", stringMapSchema("Environment variables passed to shell execution.")
        ));

        overlays.put("burp_logs", Map.of(
            "object", objectSchema("Arbitrary JSON object to write with WRITE_LOG.", Map.of(), true)
        ));

        return overlays;
    }

    private static Map<String, Object> ruleExportArraySchema(String description) {
        return arraySchema(description, objectSchema("Exported rule.", linkedMap(
            "id", stringSchema("Rule ID."),
            "priority", integerSchema("Rule priority."),
            "config", objectSchema("Rule config.", Map.of(), true)
        ), false));
    }

    private static List<String> extractActionValues(Map<String, Object> toolInfo) {
        Map<String, Object> inputSchema = safeMap(toolInfo.get("inputSchema"));
        if (inputSchema == null) {
            return List.of();
        }
        Map<String, Object> properties = safeMap(inputSchema.get("properties"));
        if (properties == null) {
            return List.of();
        }
        Map<String, Object> action = safeMap(properties.get("action"));
        if (action == null) {
            return List.of();
        }
        return stringValues(action.get("enum"));
    }

    private static List<String> stringValues(Object value) {
        List<String> values = new ArrayList<>();
        if (value instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (item != null) {
                    values.add(item.toString());
                }
            }
        } else if (value != null && value.getClass().isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                Object item = Array.get(value, i);
                if (item != null) {
                    values.add(item.toString());
                }
            }
        }
        return values;
    }

    private static Map<String, Object> mergeMaps(Map<String, Object> base, Map<String, Object> overlay) {
        Map<String, Object> merged = base == null ? new LinkedHashMap<>() : deepCopyMap(base);
        for (Map.Entry<String, Object> entry : overlay.entrySet()) {
            merged.put(entry.getKey(), deepCopy(entry.getValue()));
        }
        return merged;
    }

    private static Map<String, Object> ensureMap(Map<String, Object> parent, String key) {
        Map<String, Object> existing = safeMap(parent.get(key));
        if (existing != null) {
            return existing;
        }
        Map<String, Object> created = new LinkedHashMap<>();
        parent.put(key, created);
        return created;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> safeMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        return null;
    }

    private static Map<String, Object> deepCopyMap(Map<String, Object> source) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (source != null) {
            for (Map.Entry<String, Object> entry : source.entrySet()) {
                copy.put(entry.getKey(), deepCopy(entry.getValue()));
            }
        }
        return copy;
    }

    private static Object deepCopy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                copy.put(String.valueOf(entry.getKey()), deepCopy(entry.getValue()));
            }
            return copy;
        }
        if (value instanceof Collection<?> collection) {
            List<Object> copy = new ArrayList<>();
            for (Object item : collection) {
                copy.add(deepCopy(item));
            }
            return copy;
        }
        return value;
    }

    private static Map<String, Object> linkedMap(Object... entries) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) {
            map.put((String) entries[i], entries[i + 1]);
        }
        return map;
    }

    private static Map<String, Object> stringSchema(String description) {
        return schema("string", description);
    }

    private static Map<String, Object> integerSchema(String description) {
        return schema("integer", description);
    }

    private static Map<String, Object> booleanSchema(String description) {
        return schema("boolean", description);
    }

    private static Map<String, Object> anyJsonSchema(String description) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("description", description);
        return schema;
    }

    private static Map<String, Object> enumSchema(String description, List<String> values) {
        Map<String, Object> schema = stringSchema(description);
        schema.put("enum", values);
        return schema;
    }

    private static Map<String, Object> arraySchema(String description, Map<String, Object> items) {
        Map<String, Object> schema = schema("array", description);
        schema.put("items", items);
        return schema;
    }

    private static Map<String, Object> stringMapSchema(String description) {
        Map<String, Object> schema = objectSchema(description, Map.of(), true);
        schema.put("additionalProperties", stringSchema("Value."));
        return schema;
    }

    private static Map<String, Object> objectSchema(String description,
                                                     Map<String, Object> properties,
                                                     boolean allowAdditionalProperties) {
        return objectSchema(description, properties, allowAdditionalProperties, List.of());
    }

    private static Map<String, Object> objectSchema(String description,
                                                     Map<String, Object> properties,
                                                     boolean allowAdditionalProperties,
                                                     List<String> required) {
        Map<String, Object> schema = schema("object", description);
        schema.put("properties", properties);
        schema.put("additionalProperties", allowAdditionalProperties);
        if (!required.isEmpty()) {
            schema.put("required", required);
        }
        return schema;
    }

    private static Map<String, Object> schema(String type, String description) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", type);
        schema.put("description", description);
        return schema;
    }
}
