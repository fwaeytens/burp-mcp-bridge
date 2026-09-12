package com.example.burpmcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Action-dependent structured results for HTTP and WebSocket traffic tools. */
final class TrafficOutputSchemas {
    private TrafficOutputSchemas() {}

    static Map<String, Object> forTool(String name) {
        return switch (name) {
            case "burp_proxy_interceptor" -> proxyInterceptor();
            case "burp_global_interceptor" -> globalInterceptor();
            case "burp_websocket" -> webSocket();
            case "burp_websocket_interceptor" -> webSocketInterceptor();
            default -> null;
        };
    }

    private static Map<String, Object> proxyInterceptor() {
        Map<String, Object> request = object("A held HTTP request", fields(
            "requestId", string("ID accepted by request decision actions"),
            "method", string("HTTP method"), "url", string("Request URL"),
            "ageMs", integer("Milliseconds since interception"),
            "willTimeout", bool("Whether the 30 second hold deadline has passed")),
            "requestId", "method", "url", "ageMs", "willTimeout");
        Map<String, Object> response = object("A held HTTP response", fields(
            "id", string("Response ID; alias of responseId"),
            "responseId", string("ID accepted by response decision actions"),
            "statusCode", integer("HTTP status code"),
            "ageMs", integer("Milliseconds since interception")), "id", "responseId", "statusCode", "ageMs");
        return result("Proxy interception status, held traffic, decision acknowledgements, or WebSocket history. Fields depend on action.", fields(
            "enabled", bool("Whether proxy interception is enabled"),
            "alreadyEnabled", bool("enable found interception already enabled"),
            "alreadyDisabled", bool("disable found interception already disabled"),
            "holdFilter", string("Description of the active request hold filter"),
            "queueSize", count("Pending request or response count, according to action"),
            "timeoutMs", count("Request hold timeout in milliseconds; get_queue only"),
            "queue", array("get_queue returns request rows; get_response_queue returns response rows", union(request, response)),
            "success", bool("Whether the decision or statistics reset succeeded"),
            "action", string("Completed modification, forward, drop, or clear_stats action"),
            "requestId", string("Affected HTTP request ID"),
            "responseId", string("Affected HTTP response ID"),
            "intercepted", count("Total HTTP requests intercepted"),
            "modified", count("Total HTTP requests modified"),
            "timeouts", count("Total request hold timeouts"),
            "pendingResponses", count("Outstanding request decision futures (historical field name)"),
            "modificationRatePercent", number("Modified requests as a percentage; omitted when no requests intercepted"),
            "timeoutRatePercent", number("Timed out requests as a percentage; omitted when no requests intercepted"),
            "masterInterceptEnabled", bool("Burp's master proxy interception setting"),
            "activeCount", count("Tracked WebSocket connections"),
            "totalIntercepted", count("Total WebSocket connections intercepted"),
            "totalMessages", count("WebSocket messages intercepted or present in proxy history, according to action"),
            "active", array("Tracked WebSocket connections", object("WebSocket connection", fields(
                "id", string("Connection ID"), "upgradeUrl", string("HTTP upgrade request URL"),
                "ageMs", integer("Milliseconds since interception")), "id", "upgradeUrl", "ageMs")),
            "showing", count("Number of returned WebSocket history messages, at most 20"),
            "messages", array("Recent WebSocket history messages", object("Captured WebSocket message", fields(
                "direction", direction(), "payload", string("Payload preview, at most 100 characters"),
                "payloadTruncated", bool("Present and true when payload was shortened")), "direction", "payload"))));
    }

    private static Map<String, Object> globalInterceptor() {
        Map<String, Object> ruleSummary = object("HTTP rule summary from list_rules", fields(
            "id", nullableString("Rule ID; may be null when omitted from imported configuration"), "priority", integer("Rule execution priority"),
            "description", nullableString("Rule description, which may be explicitly null in rule configuration"),
            "pattern", string("URL regex, present when compiled successfully")), "id", "priority", "description");
        Map<String, Object> httpExport = exportedRule(httpRuleConfig());
        Map<String, Object> wsExport = exportedRule(webSocketRuleConfig());
        Map<String, Object> stats = stats();
        Map<String, Object> properties = fields(
            "enabled", bool("Whether global interception is enabled"),
            "alreadyEnabled", bool("enable found interception already enabled"),
            "alreadyDisabled", bool("disable found interception already disabled"),
            "requestInterception", bool("Whether HTTP request interception is enabled"),
            "responseInterception", bool("Whether HTTP response interception is enabled"),
            "webSocketInterception", bool("Whether WebSocket interception is enabled"),
            "eventQueue", bool("Whether HTTP event queue mode is configured"),
            "rateLimit", integer("Configured request delay in milliseconds; enable only"),
            "rateLimitMs", integer("Configured request delay in milliseconds; status and set_rate_limit"),
            "globalHeaders", union(count("Configured header count in enable/status"), stringMap("Configured headers in export_rules")),
            "requestRules", union(count("Configured request rule count in enable/status"),
                array("Request rule summaries or exported configurations", union(ruleSummary, httpExport))),
            "responseRules", union(count("Configured response rule count in enable/status"),
                array("Response rule summaries or exported configurations", union(ruleSummary, httpExport))),
            "webSocketRules", union(count("Configured WebSocket rule count in enable/status"), array("Exported WebSocket configurations", wsExport)),
            "authType", string("Configured authentication type; omitted from status when unset"),
            "authHeader", nullableString("Configured authentication header name; may be null after importing partial settings"),
            "toolFilter", enumeration("Whether all Burp tool sources are enabled", "all", "custom"),
            "stats", stats,
            "success", bool("Whether the configuration mutation succeeded"),
            "action", string("Completed clear_auth, clear_stats, or import_rules action"),
            "header", string("Header name added or removed"),
            "count", count("Configured global header count"),
            "headers", stringMap("Configured global header names and values"),
            "ruleId", string("Added or removed rule ID"),
            "priority", integer("Assigned rule execution priority"),
            "type", enumeration("Added HTTP rule type", "request", "response"),
            "enabledTools", array("Enabled Burp tool source names", string("Burp tool source")),
            "disabledTools", array("Disabled Burp tool source names", string("Burp tool source")),
            "invalidTools", array("Unrecognized supplied tool source names; omitted when all were valid", string("Unrecognized source")),
            "allEnabled", bool("Whether every Burp tool source is enabled"),
            "enabledCount", count("Enabled tool source count after reset_tool_filter"),
            "samples", count("Retained timing sample count"),
            "avgMs", integer("Mean response time in milliseconds; omitted without samples"),
            "minMs", integer("Minimum response time in milliseconds; omitted without samples"),
            "maxMs", integer("Maximum response time in milliseconds; omitted without samples"),
            "recent", array("Up to ten retained timing samples", object("HTTP timing sample", fields(
                "timestamp", string("Local ISO date-time when the sample was recorded"),
                "method", string("HTTP method"), "url", string("Request URL"),
                "responseTimeMs", integer("Response time in milliseconds"), "toolSource", string("Burp tool source")),
                "timestamp", "method", "url", "responseTimeMs", "toolSource")),
            "settings", object("Settings returned by export_rules", fields(
                "requestInterception", bool("HTTP request interception enabled"),
                "responseInterception", bool("HTTP response interception enabled"),
                "webSocketInterception", bool("WebSocket interception enabled"),
                "rateLimitDelay", integer("Request delay in milliseconds; import_rules retains signed values"),
                "authType", nullableString("Authentication type or null when unset"),
                "authValue", nullableString("Configured authentication header value or null when unset"),
                "authHeader", nullableString("Authentication header name, initially Authorization; may be null after importing partial settings")),
                "requestInterception", "responseInterception", "webSocketInterception", "rateLimitDelay", "authType", "authValue", "authHeader"),
            "rules", array("WebSocket summaries returned by list_websocket_rules", object("WebSocket rule summary", fields(
                "id", nullableString("Rule ID; may be null when omitted from imported configuration"), "priority", integer("Rule execution priority"),
                "description", nullableString("Configured description; may be explicitly null"),
                "pattern", string("Match regex, present when compiled successfully"),
                "replace", string("Replacement text; omitted when explicitly null"),
                "direction", string("Configured direction: both, client_to_server, or server_to_client"),
                "drop", bool("Whether matched messages are dropped")), "id", "priority", "description", "direction", "drop")));
        @SuppressWarnings("unchecked")
        Map<String, Object> statProperties = (Map<String, Object>) stats.get("properties");
        properties.putAll(statProperties);
        return result("Global interception configuration, rules, counters, timings, or mutation acknowledgements. Counts in status become configuration arrays/maps in export_rules.", properties);
    }

    private static Map<String, Object> stats() {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (String key : List.of("requestsIntercepted", "requestsModified", "requestsDropped", "responsesIntercepted",
                "responsesModified", "webSocketMessagesIntercepted", "webSocketMessagesModified", "webSocketMessagesDropped")) {
            fields.put(key, count("Cumulative " + key + " counter since reset"));
        }
        return object("Global interception counters", fields, fields.keySet().toArray(String[]::new));
    }

    private static Map<String, Object> exportedRule(Map<String, Object> config) {
        return object("Exported rule retaining its submitted configuration", fields(
            "id", nullableString("Rule ID; may be null when omitted from imported configuration"), "priority", integer("Rule execution priority"), "config", config), "id", "priority", "config");
    }

    private static Map<String, Object> httpRuleConfig() {
        Map<String, Object> properties = new LinkedHashMap<>();
        for (String name : List.of("description", "url_pattern", "method", "status_range", "content_type", "body_search",
                "body_replace", "change_method", "change_path", "change_reason")) {
            properties.put(name, nullableString("Submitted " + name + " rule setting"));
        }
        properties.put("use_regex", nullable("boolean", "Whether regex matching/replacement is enabled"));
        properties.put("status_code", nullable("integer", "Response status to match"));
        properties.put("change_status", nullable("integer", "Replacement response status"));
        properties.put("required_headers", union(stringMap("Required request headers"), type("null", "Unset")));
        properties.put("add_headers", union(stringMap("Headers to add"), type("null", "Unset")));
        properties.put("remove_headers", union(array("Headers to remove", string("Header name")), type("null", "Unset")));
        return retainedConfig("Original HTTP rule configuration; additional caller-supplied keys are retained on export", properties);
    }

    private static Map<String, Object> webSocketRuleConfig() {
        return retainedConfig("Original WebSocket rule configuration; additional caller-supplied keys are retained on export", fields(
            "description", nullableString("Rule description"), "match_pattern", nullableString("Payload text or regex to match"),
            "replace_text", nullableString("Replacement payload text"),
            "direction", nullableString("both, client_to_server, or server_to_client"),
            "use_regex", nullable("boolean", "Whether regex matching/replacement is enabled"),
            "drop", nullable("boolean", "Whether matched messages are dropped")));
    }

    private static Map<String, Object> retainedConfig(String description, Map<String, Object> properties) {
        Map<String, Object> schema = object(description, properties);
        schema.put("additionalProperties", true);
        return schema;
    }

    private static Map<String, Object> webSocket() {
        return result("WebSocket connection or send acknowledgements, active connections, or captured proxy history. Fields depend on action.", fields(
            "success", bool("Whether create/send/close succeeded"),
            "connectionId", string("Created or affected connection ID"),
            "url", string("WebSocket URL supplied to create"),
            "status", string("Montoya connection creation status"),
            "messageType", enumeration("Sent WebSocket message type", "text", "binary"),
            "totalMessages", count("Total captured proxy WebSocket messages before filtering"),
            "showing", count("Number of history messages returned"),
            "filter", string("Payload substring filter, omitted when empty"),
            "messages", array("Matching proxy WebSocket history, newest first", object("Captured message", fields(
                "url", string("HTTP upgrade request URL"), "direction", direction(),
                "payload", string("Payload preview, truncated to 500 characters"),
                "notes", nullableString("Burp message annotation notes, if available")), "url", "direction", "payload", "notes")),
            "activeCount", count("Number of active extension-created connections"),
            "connections", array("Active extension-created connections", object("Active connection", fields(
                "id", string("Connection ID"), "messageCount", count("Recorded sent and received messages")), "id", "messageCount"))));
    }

    private static Map<String, Object> webSocketInterceptor() {
        Map<String, Object> common = fields("id", string("ID accepted by forward/drop/modify"), "direction", direction());
        Map<String, Object> text = new LinkedHashMap<>(common);
        text.put("type", enumeration("Message type", "text"));
        text.put("payload", string("Text preview, truncated to 200 characters"));
        Map<String, Object> binary = new LinkedHashMap<>(common);
        binary.put("type", enumeration("Message type", "binary"));
        binary.put("payloadBase64", string("Base64 preview truncated to 200 characters; truncation may make it undecodable"));
        binary.put("size", count("Full binary payload size in bytes"));
        return result("WebSocket interceptor status, held message previews, configuration or decision acknowledgements. Fields depend on action.", fields(
            "enabled", bool("Whether WebSocket interception is enabled"),
            "messagesForwarded", count("Pending messages released by disable"),
            "pendingMessages", count("Pending message count in status"),
            "totalIntercepted", count("Total intercepted messages"),
            "totalModified", count("Total modified messages"),
            "totalDropped", count("Total dropped messages"),
            "filters", stringMap("Filter names mapped to regex patterns"),
            "autoModifyRules", stringMap("Rule names mapped to search pattern + ||| + replacement text"),
            "totalPending", count("Pending message count in get_queue"),
            "showing", count("Number of returned message previews, at most ten"),
            "messages", array("Pending text or binary message previews", union(
                object("Text WebSocket message", text, "id", "direction", "type", "payload"),
                object("Binary WebSocket message", binary, "id", "direction", "type", "payloadBase64", "size"))),
            "success", bool("Whether the decision or rule/filter update succeeded"),
            "messageId", string("Affected pending message ID"),
            "action", enumeration("Completed pending-message decision", "forward", "drop", "modify"),
            "filterName", string("Added or removed filter name"),
            "ruleName", string("Added or removed automatic modification rule name")));
    }

    private static Map<String, Object> result(String description, Map<String, Object> properties) {
        properties.put("text", string("Formatted verbose output or error message; errors have outer isError=true"));
        return object(description, properties);
    }

    private static Map<String, Object> object(String description, Map<String, Object> properties, String... required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("description", description);
        schema.put("properties", properties);
        schema.put("additionalProperties", false);
        if (required.length > 0) schema.put("required", List.of(required));
        return schema;
    }

    private static Map<String, Object> fields(Object... entries) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) fields.put((String) entries[i], entries[i + 1]);
        return fields;
    }

    private static Map<String, Object> type(String type, String description) { return Map.of("type", type, "description", description); }
    private static Map<String, Object> string(String description) { return type("string", description); }
    private static Map<String, Object> bool(String description) { return type("boolean", description); }
    private static Map<String, Object> integer(String description) { return type("integer", description); }
    private static Map<String, Object> number(String description) { return type("number", description); }
    private static Map<String, Object> count(String description) { return Map.of("type", "integer", "minimum", 0, "description", description); }
    private static Map<String, Object> nullable(String type, String description) { return Map.of("type", List.of(type, "null"), "description", description); }
    private static Map<String, Object> nullableString(String description) { return nullable("string", description); }
    private static Map<String, Object> direction() { return enumeration("WebSocket message direction", "CLIENT_TO_SERVER", "SERVER_TO_CLIENT"); }
    private static Map<String, Object> enumeration(String description, String... values) { return Map.of("type", "string", "description", description, "enum", List.of(values)); }
    private static Map<String, Object> stringMap(String description) { return Map.of("type", "object", "description", description, "additionalProperties", type("string", "Value")); }
    private static Map<String, Object> array(String description, Map<String, Object> items) { return Map.of("type", "array", "description", description, "items", items); }
    @SafeVarargs
    private static Map<String, Object> union(Map<String, Object>... alternatives) { return Map.of("anyOf", List.of(alternatives)); }
}
