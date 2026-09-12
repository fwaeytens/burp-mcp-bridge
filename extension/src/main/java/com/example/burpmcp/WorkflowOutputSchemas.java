package com.example.burpmcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Domain fields returned by comparison, Bambda and response-analysis workflows. */
final class WorkflowOutputSchemas {
    private WorkflowOutputSchemas() {}

    static Map<String, Object> forTool(String tool) {
        return switch (tool) {
            case "burp_comparer" -> comparer();
            case "burp_bambda" -> bambda();
            case "burp_response_analyzer" -> analysis(true);
            default -> null;
        };
    }

    private static Map<String, Object> comparer() {
        Map<String, Object> fields = common();
        strings(fields, "url1", "url2", "method1", "method2", "path1", "path2", "preview1", "preview2");
        integers(fields, "statusCode1", "statusCode2", "status1", "status2", "bodyLength1", "bodyLength2",
            "headerCount1", "headerCount2", "bodySize1", "bodySize2", "length1", "length2",
            "normalizedLength1", "normalizedLength2");
        booleans(fields, "statusMatch", "lengthMatch", "bodiesIdentical", "methodsMatch", "pathsMatch",
            "ignoreWhitespace", "identical", "sentToComparer", "entry1Found", "entry2Found");
        fields.put("sent", strings("Items added to Comparer UI; no programmatic comparison for SEND_TO_COMPARER."));
        fields.put("errors", strings("Failures while sending individual items to Comparer UI."));
        Map<String, Object> comparison = new LinkedHashMap<>();
        comparison.put("type", enumeration("Selected comparison mode.", "WORDS", "BYTES", "HEADERS_ONLY", "BODY_ONLY"));
        comparison.put("scope", enumeration("Compared content.", "text", "message", "headers", "body"));
        comparison.put("unit", enumeration("Token includes whitespace unless ignored; byte is an exact byte position.", "token", "byte"));
        booleans(comparison, "ignoreWhitespace", "identical", "previewTruncated");
        integers(comparison, "units1", "units2", "commonPrefixUnits", "commonSuffixUnits", "removedUnits", "addedUnits");
        strings(comparison, "removedPreview", "addedPreview");
        comparison.put("previewEncoding", enumeration("Byte previews encode at most 512 bytes; text previews contain at most 1024 characters.", "text", "base64"));
        fields.put("comparison", object("One changed span between the common prefix and suffix. Inputs are limited to 1 MiB each.", comparison, true));
        return object("Action-dependent comparison summaries, UI results, or structured errors. Legacy length fields describe the full original content; comparison describes the selected mode.", fields, false);
    }

    private static Map<String, Object> bambda() {
        Map<String, Object> fields = common();
        strings(fields, "preset", "location", "description", "workaround");
        booleans(fields, "success", "custom", "supported");
        fields.put("status", enumeration("Native import status; NO_RESULT indicates a missing import result.",
            "LOADED_WITHOUT_ERRORS", "LOADED_WITH_ERRORS", "NO_RESULT"));
        fields.put("errors", strings("Native Bambda import diagnostics."));
        fields.put("presets", array("Built-in preset catalog.", object("Preset.", Map.of(
            "name", string("Preset identifier."), "description", string("Preset purpose.")), true)));
        return object("Bambda import outcomes and presets. GET_ACTIVE_FILTER returns supported:false with an error; import success does not establish which filter is active.", fields, false);
    }

    private static Map<String, Object> analysis(boolean combined) {
        Map<String, Object> fields = common();
        fields.put("operation", enumeration("Completed analysis action.", "keywords", "variations", "pattern", "reflection", "rank_anomalies", "all"));
        strings(fields, "pattern", "testString", "algorithm");
        booleans(fields, "caseSensitive");
        integers(fields, "responsesAnalyzed", "matchesFound", "entriesAnalyzed", "reflectionPointsFound");
        for (String name : List.of("keywordsSearched", "variantKeywords", "invariantKeywords", "variantAttributes", "invariantAttributes")) {
            fields.put(name, strings(name + " reported by the native analyzer."));
        }
        Map<String, Object> match = new LinkedHashMap<>();
        strings(match, "url", "method");
        integers(match, "statusCode", "matchCount");
        match.put("samples", strings("At most five regex match previews per response."));
        fields.put("matches", array("Responses containing the requested pattern.", object("Pattern match.", match, true)));
        Map<String, Object> reflection = new LinkedHashMap<>();
        strings(reflection, "url", "method");
        integers(reflection, "responseCode");
        reflection.put("reflections", Map.of("type", "object", "description", "Request parameter/header names mapped to reflection source labels.",
            "additionalProperties", strings("Reflection sources such as URL parameter, Body parameter, or Header.")));
        fields.put("reflectionPoints", array("Observed request values reflected in responses.", object("Reflection point.", reflection, true)));
        fields.put("requestedProxyIds", array("Requested 1-based proxy IDs.", integer("Proxy ID.")));
        fields.put("invalidProxyIds", array("Rejected proxy IDs; may include zero or negative caller input.", Map.of("type", "integer")));
        Map<String, Object> anomaly = new LinkedHashMap<>();
        integers(anomaly, "rank", "statusCode", "size");
        strings(anomaly, "url", "method", "contentType");
        fields.put("topAnomalies", array("Highest-ranked responses; contentType is omitted when absent.",
            object("Anomaly summary.", anomaly, false, "rank", "url", "method", "statusCode", "size")));
        Map<String, Object> distribution = new LinkedHashMap<>();
        integers(distribution, "veryHigh", "high", "medium", "low", "veryLow");
        fields.put("distribution", object("Counts in rank bands >=80, >=60, >=40, >=20, and below 20.", distribution, true));
        if (combined) {
            fields.put("keywords", analysis(false));
            fields.put("variations", analysis(false));
            fields.put("reflection", analysis(false));
        }
        return object("Action-dependent response analysis. all contains keywords, variations and reflection results; each sub-result may instead contain error/message. Verbose and compatibility responses expose text.", fields, false);
    }

    private static Map<String, Object> common() {
        Map<String, Object> fields = new LinkedHashMap<>();
        strings(fields, "text", "error", "message");
        fields.put("truncated", bool("Whether the bridge replaced an oversized result with a summary."));
        integers(fields, "originalChars", "limitChars");
        return fields;
    }

    private static void strings(Map<String, Object> fields, String... names) {
        for (String name : names) fields.put(name, string(name + " for the selected action."));
    }
    private static void integers(Map<String, Object> fields, String... names) {
        for (String name : names) fields.put(name, integer(name + " for the selected action."));
    }
    private static void booleans(Map<String, Object> fields, String... names) {
        for (String name : names) fields.put(name, bool(name + " for the selected action."));
    }
    private static Map<String, Object> string(String description) { return Map.of("type", "string", "description", description); }
    private static Map<String, Object> integer(String description) { return Map.of("type", "integer", "minimum", 0, "description", description); }
    private static Map<String, Object> bool(String description) { return Map.of("type", "boolean", "description", description); }
    private static Map<String, Object> enumeration(String description, String... values) {
        return Map.of("type", "string", "description", description, "enum", List.of(values));
    }
    private static Map<String, Object> strings(String description) { return array(description, string("String item.")); }
    private static Map<String, Object> array(String description, Map<String, Object> items) {
        return Map.of("type", "array", "description", description, "items", items);
    }
    private static Map<String, Object> object(String description, Map<String, Object> fields, boolean allRequired, String... required) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "object");
        result.put("description", description);
        result.put("properties", fields);
        result.put("additionalProperties", false);
        if (allRequired) result.put("required", List.copyOf(fields.keySet()));
        else if (required.length > 0) result.put("required", List.of(required));
        return result;
    }
}
