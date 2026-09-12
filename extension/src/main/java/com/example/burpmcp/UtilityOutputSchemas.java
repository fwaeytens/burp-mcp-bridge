package com.example.burpmcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Compact result contracts for state, configuration, UI, and utility tools. */
final class UtilityOutputSchemas {
    private UtilityOutputSchemas() { }

    static Map<String, Object> forTool(String name) {
        Map<String, Object> fields = switch (name) {
            case "burp_repeater" -> props(
                "success", bool("Whether a Repeater tab was created; this does not send the request."),
                "tabName", str("Created tab name, including automatically assigned MCP names."),
                "url", str("URL copied to the tab."), "method", str("Request method."),
                "bodyLength", count("Submitted body length in characters, when nonempty."),
                "fromProxy", bool("True when an existing proxy request was copied."));
            case "burp_intruder" -> props(
                "success", bool("Whether the request was sent to Intruder's UI; the attack has not executed."),
                "url", str("Configured request URL."), "method", str("Configured request method."),
                "bodyLength", count("Submitted body length in characters, when nonempty."),
                "positionsFound", count("SEND_WITH_POSITIONS: number of insertion positions found in section-sign markers."));
            case "burp_add_issue" -> props(
                "success", bool("Whether the issue was added to Burp's site map."),
                "issue_type", str("Final normalized issue name used for grouping."), "url", str("Issue URL."),
                "severity", str("Assigned severity: HIGH, MEDIUM, LOW, or INFORMATION."),
                "confidence", str("Assigned confidence: CERTAIN, FIRM, or TENTATIVE."));
            case "burp_session_management" -> session();
            case "burp_collaborator" -> collaborator();
            case "burp_scope" -> scope();
            case "burp_config" -> props(
                "action", str("GET_PROJECT_OPTIONS, GET_USER_OPTIONS, SET_PROJECT_OPTIONS, SET_USER_OPTIONS, or RESET_PROJECT_OPTIONS."),
                "scope", str("GET: project or user options."), "path", str("Requested configuration subtree, when provided."),
                "json", nullableString("GET: serialized configuration JSON, or null if the runtime returned no data."),
                "length", count("GET: serialized JSON length in characters."),
                "success", bool("SET/RESET: whether configuration import succeeded."),
                "reset", str("RESET: subtree restored to its supported default."),
                "importedTopLevelKeys", strings("SET: top-level keys present in the imported JSON."));
            case "burp_organizer" -> organizer();
            case "burp_annotate" -> annotate();
            case "burp_logs" -> logs();
            case "burp_utilities" -> utilities();
            default -> null;
        };
        if (fields == null) return null;
        fields.putIfAbsent("message", nullableString("Operation explanation or error diagnostic."));
        fields.putIfAbsent("error", nullableString("Diagnostic for an unavailable operation or failure; also inspect MCP isError and success."));
        fields.put("text", str("Human-readable verbose response or normalized tool error."));
        fields.put("truncated", bool("True when the bridge replaced an oversized result with a summary."));
        fields.put("originalChars", count("Serialized length before bridge truncation."));
        fields.put("limitChars", count("Bridge response length limit."));
        Map<String, Object> schema = object(fields);
        schema.put("description", "Action-dependent compact result for " + name + ". Fields document actual operation results; verbose, error, and truncation responses may contain only the common envelope.");
        return schema;
    }

    private static Map<String, Object> session() {
        Map<String, Object> token = object(props("name", str("Token name."), "value", str("Stored token value."),
            "length", count("Token value length, included when listing stored tokens.")), "name", "value");
        Map<String, Object> cookie = object(props("name", str("Cookie name."), "value", str("Cookie value."),
            "domain", nullableString("Cookie domain."), "path", nullableString("Cookie path."),
            "expires", nullableString("Local ISO date-time of expiration, or null for a session cookie.")), "name", "value", "domain", "path", "expires");
        Map<String, Object> sessionUrls = array("LIST_TOKENS: known session URLs; SESSION_STATUS: the number of those URLs.", str("Session URL."));
        sessionUrls.put("type", List.of("array", "integer"));
        sessionUrls.put("minimum", 0);
        Map<String, Object> setCookie = object(props("name", str("Cookie name."), "value", str("Cookie value.")), "name", "value");
        setCookie.put("type", List.of("object", "string"));
        return props(
            "operation", str("Session operation in camelCase, such as listTokens, cookieJarList, testSession, or analyzeSessionValidity."),
            "success", bool("Whether a mutation or session request succeeded."),
            "processedEntries", count("EXTRACT_TOKENS: proxy entries inspected."), "tokensFound", count("EXTRACT_TOKENS: distinct tokens found."),
            "urlFilter", str("Proxy history URL substring filter."), "tokens", array("Extracted or stored token values.", token),
            "tokenName", str("SET_TOKEN: stored token name."), "tokenValue", str("SET_TOKEN: stored value."),
            "totalTokens", count("SET_TOKEN: token count after the update."), "tokensRemoved", count("CLEAR_TOKENS: removed token count."),
            "tokenCount", count("LIST_TOKENS: stored token count."), "sessionUrls", sessionUrls,
            "url", str("URL requested for session testing or validity analysis."), "statusCode", integer("HTTP response status."),
            "sessionStatus", str("TEST_SESSION: VALID, INVALID, REDIRECT, or UNKNOWN assessment."),
            "redirectLocation", str("Response Location header when present."), "responseLength", count("Response body length in bytes."),
            "setCookies", array("TEST_SESSION returns name/value objects; ANALYZE_SESSION_VALIDITY returns cookie-name strings.", setCookie),
            "baseUrl", str("FIND_LOGOUT: URL filter."), "count", count("FIND_LOGOUT: matching logout endpoints."),
            "endpoints", strings("FIND_LOGOUT: logout endpoint URLs."), "storedTokens", count("SESSION_STATUS: stored token count."),
            "tokenSummary", array("SESSION_STATUS: token names and lengths without values.", object(props("name", str("Token name."), "length", count("Value length.")), "name", "length")),
            "totalProxyEntries", count("SESSION_STATUS: total proxy history entries."), "sessionRequests", count("Requests containing session indicators."),
            "authRequests", count("Requests containing authentication headers."), "totalCookies", count("COOKIE_JAR_LIST: cookie count."),
            "cookies", array("Burp cookie-jar contents, including session-cookie null expirations.", cookie),
            "name", str("Cookie name."), "value", str("Cookie value."), "domain", str("Cookie domain."), "path", str("Cookie path."),
            "expiration", nullableString("COOKIE_JAR_SET: local ISO date-time, or null for a session cookie."),
            "invalidExpiration", bool("Invalid supplied expiration was replaced with a session cookie."),
            "cookiesRemoved", count("COOKIE_JAR_CLEAR: number removed."), "autoRefresh", bool("Legacy flag enabling missing-authentication marking; no login or credential renewal is performed."),
            "wasEnabled", bool("Whether automatic handling was enabled before disabling it."), "active", bool("Whether automatic handling is currently active."),
            "requestsProcessed", count("Automatic handler processed requests."), "sessionsRefreshed", count("Legacy counter of requests marked as lacking authentication; not completed credential renewals."),
            "failedAuthentications", count("Legacy failure counter, currently zero because this handler does not inspect responses."), "lastActivity", str("Automatic handler last-activity local ISO time, or Never before its first request."),
            "handlerName", str("Registered session handler name."), "registrationPresent", bool("A session handler registration exists."),
            "handlerPresent", bool("An in-memory session handler exists."),
            "assessment", str("ANALYZE_SESSION_VALIDITY: VALID, INVALID, POSSIBLY_INVALID, REDIRECT, or UNKNOWN."),
            "keywords", object(props("login", count("Login matches."), "signin", count("Sign-in matches."), "authenticate", count("Authentication matches."),
                "unauthorized", count("Unauthorized matches."), "forbidden", count("Forbidden matches."), "accessDenied", count("Access-denied matches."), "sessionExpired", count("Session-expired matches."))),
            "hasAuthKeywords", bool("Validity analysis found authentication-related response text."));
    }

    private static Map<String, Object> collaborator() {
        Map<String, Object> interaction = object(props("id", str("Interaction identifier."), "type", str("Interaction protocol, such as DNS, HTTP, or SMTP."),
            "timestamp", str("Interaction timestamp from the Collaborator server."), "clientIp", str("Source IP address when available."),
            "clientPort", integer("Source port when available."), "customData", str("Custom payload data when present.")), "id", "type", "timestamp");
        return props(
            "payloadType", str("HOSTNAME, HTTP_URL, HTTPS_URL, or EMAIL payload format."), "count", count("Number of generated payloads."),
            "includeServerLocation", bool("Whether generated payloads include the server location."), "customData", str("Supplied custom data prefix."),
            "payloads", array("New payloads; retain their IDs to identify future callbacks.", object(props("payload", str("Callback hostname, URL, or email."), "id", str("Payload ID."),
                "server", str("Collaborator server address when included."), "isLiteral", str("Legacy string boolean indicating whether server is a literal address."), "customData", str("Per-payload custom data.")), "payload", "id")),
            "totalInteractions", count("Total accumulated interactions."), "filter", str("Applied interaction type, payload, or custom-data filter."),
            "matchingCount", count("CHECK_INTERACTIONS: matching interactions."), "interactions", array("Matching interaction summaries.", interaction),
            "operation", str("RESTORE_CLIENT on successful session restoration."), "success", bool("Whether session restoration succeeded."),
            "note", str("Capability limitation or usage guidance."),
            "payloadTypes", array("Built-in formats; this is not a history of generated payloads.", object(props("type", str("Format name."), "format", str("Example format."), "useFor", str("Typical uses.")), "type", "format", "useFor")),
            "attackScenarios", strings("Suggested out-of-band testing scenarios."), "action", str("CLEAR_INTERACTIONS when reporting its limitation."),
            "supported", bool("False for CLEAR_INTERACTIONS, which the API does not support."), "active", bool("Whether a Collaborator client is available."),
            "latestInteractionTime", str("Latest accumulated interaction timestamp, absent when none exist."),
            "interactionsByType", dictionary("STATUS: interaction counts keyed by protocol.", count("Protocol count.")),
            "secretKey", str("Current client secret used to restore the same Collaborator session."), "usage", str("Secret restoration instructions."),
            "address", str("Collaborator server address."), "isLiteralAddress", bool("Whether the server address is a literal address."),
            "supportedProtocols", strings("Supported callback protocol names."), "totalMatching", count("FILTER_INTERACTIONS: matches before the type filter."),
            "filteredCount", count("FILTER_INTERACTIONS: matches after type filtering."), "typeCounts", dictionary("Filtered interaction counts by protocol.", count("Count.")));
    }

    private static Map<String, Object> scope() {
        Map<String, Object> check = object(props("url", str("Checked URL."), "inScope", bool("Whether the URL is in scope."),
            "error", nullableString("Error evaluating this URL."), "skipped", str("Reason this variation was skipped.")), "url");
        return props("action", str("Scope action, absent from the view result."), "success", bool("Whether a scope mutation succeeded."),
            "recentChanges", strings("Recent scope-change messages."), "scopeChecksPerformed", count("Scope checks tracked by this extension."),
            "knownInScopeCount", count("Known in-scope URLs."), "knownOutOfScopeCount", count("Known out-of-scope URLs."),
            "inScopeUrls", strings("Up to ten known in-scope URLs, not the complete Burp scope configuration."),
            "addedUrls", strings("Successfully added URL variations."), "includeSubdomains", bool("Whether subdomain inclusion was configured."),
            "hostRegex", str("Advanced-scope hostname expression when subdomains were included."), "failedUrls", strings("URL variations that could not be added."),
            "url", str("Removed or checked URL."), "inScope", bool("CHECK: whether the URL is included."), "variations", array("CHECK: outcomes for URL variations.", check),
            "totalRequests", count("ANALYZE: proxy history request count."), "inScopeRequests", count("In-scope history requests."),
            "outOfScopeRequests", count("Out-of-scope history requests."), "inScopePercent", number("Percentage of history requests in scope."),
            "topHosts", array("ANALYZE: most frequent hosts.", object(props("host", str("Hostname."), "requests", count("Request count."), "inScope", bool("Whether the host's checked URL was in scope.")), "host", "requests", "inScope")),
            "recommendation", str("Scope-coverage guidance."), "addedCount", count("BULK_ADD: number added."), "failedCount", count("BULK_ADD: failures."),
            "added", strings("BULK_ADD: submitted URLs successfully added."),
            "failed", array("BULK_ADD: failed URLs with diagnostics.", object(props("url", str("Submitted URL."), "error", nullableString("Failure diagnostic.")), "url", "error")),
            "inScopeCount", count("BULK_CHECK: included URLs."), "outOfScopeCount", count("BULK_CHECK: excluded URLs."), "errorCount", count("BULK_CHECK: failed checks."),
            "results", array("BULK_CHECK: one outcome per submitted URL.", check));
    }

    private static Map<String, Object> organizer() {
        Map<String, Object> item = object(props("id", integer("Organizer item ID."), "status", str("NEW, IN_PROGRESS, POSTPONED, DONE, or IGNORED."),
            "method", str("Request method."), "url", str("Request URL."), "statusCode", integer("HTTP response status when available."),
            "responseBytes", count("Response body bytes when available."), "hasResponse", bool("False when this item has no response."),
            "responseTimeMs", number("Response duration in milliseconds, when timing data is available.")), "id", "status", "method", "url");
        Map<String, Object> response = object(props("statusCode", integer("HTTP status."), "reasonPhrase", str("HTTP reason phrase."),
            "headerCount", count("Response header count."), "bodyLength", count("Response body bytes."), "mimeType", str("Burp's MIME classification.")), "statusCode", "reasonPhrase", "headerCount", "bodyLength", "mimeType");
        response.put("type", List.of("object", "null"));
        return props("operation", str("sendToOrganizer, listItems, listItemsFiltered, getItemById, getItemCount, or getItemStatus."),
            "success", bool("Whether the request was added to Organizer."), "fromProxy", bool("Whether an existing proxy entry was copied."),
            "url", str("Request URL."), "method", str("Request method."), "totalItems", count("Total Organizer items before limiting."),
            "showing", count("Number of returned items."), "items", array("Organizer item summaries.", item),
            "totalMatched", count("LIST_ITEMS_FILTERED: matches before limiting."),
            "filter", object(props("status", str("Status filter."), "urlContains", str("URL substring filter."), "method", str("Request-method filter."))),
            "id", integer("Selected Organizer item ID."), "status", str("Selected item status."),
            "request", object(props("method", str("Request method."), "url", str("Request URL."), "headerCount", count("Request headers."), "bodyLength", count("Request body bytes.")), "method", "url", "headerCount", "bodyLength"),
            "response", response, "responseTimeMs", number("Response duration in milliseconds when known."),
            "notes", str("Nonempty item notes."), "highlightColor", str("Item highlight color when present."));
    }

    private static Map<String, Object> annotate() {
        Map<String, Object> annotation = object(props("source", str("Burp component or local annotation database source."),
            "url", str("Matched request URL when backed by captured traffic."), "method", str("Request method when available."),
            "key", str("Local annotation database key when no native annotation target exists."),
            "notes", nullableString("Stored notes."), "color", nullableString("Stored highlight color, or null when unset.")), "source", "notes");
        Map<String, Object> fields = props("operation", str("Annotation action that produced this result."), "success", bool("Whether the annotation operation succeeded."),
            "location", str("Target Burp component."), "requestedEntryId", integer("Requested proxy history ID."),
            "requestedUrl", nullableString("Requested URL filter."), "requestedMethod", str("Requested request method."),
            "matchedUrl", str("Matched request URL."), "matchedMethod", str("Matched request method."),
            "notes", nullableString("Resulting notes."), "color", nullableString("Resulting color, NONE, or null when unset."),
            "invalidColor", str("Unrecognized requested color."), "url", str("Annotated URL or operation filter."),
            "storage", str("database means extension-local annotation storage, not a native UI annotation."),
            "key", str("Annotation database key."), "issueId", str("Scanner issue identifier."), "messageId", str("WebSocket message identifier."),
            "interactionId", str("Collaborator interaction identifier."), "annotatedCount", count("Number of annotated WebSocket messages."),
            "source", str("Selected component or ALL."), "urlFilter", str("Requested URL filter."), "methodFilter", str("Requested method filter."),
            "items", array("GET_ANNOTATIONS: annotated traffic and database entries.", annotation),
            "webSocketError", nullableString("Diagnostic when WebSocket history cannot be inspected."),
            "filePath", str("Imported or exported annotation file path."), "query", str("Case-insensitive notes search."),
            "matches", array("SEARCH_BY_ANNOTATION: matching notes and their location.", annotation),
            "alreadyEnabled", bool("Automatic annotation was already active."), "wasEnabled", bool("Automatic annotation was active before disabling."),
            "rules", object(props("urlPatterns", strings("URL patterns matched by automatic annotations."), "notes", str("Notes to apply."), "color", str("Color to apply."))),
            "pattern", str("Bulk annotation or clearing URL pattern."), "method", str("Clearing request-method filter."), "entryId", integer("Cleared proxy entry ID."));
        for (String key : List.of("proxyCount", "targetCount", "webSocketCount", "databaseCount", "totalAnnotated", "exportedCount", "importedCount", "skippedCount", "matchCount",
            "proxyAnnotated", "targetAnnotated", "webSocketAnnotated", "proxyCleared", "targetCleared", "databaseCleared", "totalCleared")) fields.put(key, count("Number of " + key + " entries for this operation."));
        return fields;
    }

    private static Map<String, Object> logs() {
        Map<String, Object> entry = object(props("timestamp", str("Local ISO date-time when captured."), "level", str("Captured log level."), "message", str("Captured message.")), "timestamp", "level", "message");
        return props("captureInitialized", bool("Whether explicit MCP log capture is initialized."), "interceptorsInstalled", bool("Legacy alias for captureInitialized; not a mirror of all Burp logs."),
            "outputCount", count("Total captured output entries before limit."), "errorCount", count("Total captured error entries before limit."), "eventCount", count("Total captured events before limit."),
            "outputLogs", array("Most recent output entries.", entry), "errorLogs", array("Most recent error entries.", entry), "eventLogs", array("Most recent raised events.", entry),
            "success", bool("Whether writing, raising, or clearing succeeded."), "level", str("Written log or raised event level."), "withObject", bool("WRITE_LOG included an object."),
            "withException", bool("WRITE_LOG included an exception."), "category", str("Cleared category: OUTPUT, ERROR, EVENT, or ALL."), "clearedCount", count("Removed entries."));
    }

    private static Map<String, Object> utilities() {
        Map<String, Object> fields = props("operation", str("Utility action; json_path returns its read/add/update/remove sub-operation."),
            "input", str("Original input string."), "output", str("Encoded, decoded, generated, converted, or shell output string."),
            "isBinary", bool("Decoded base64 contains binary control characters."), "hex", str("Hexadecimal representation of decoded binary bytes."),
            "algorithm", str("Digest or compression algorithm."), "type", str("Random-data alphabet."), "compressionRatioPercent", number("GZIP size reduction percentage; negative when compression increases the size."),
            "path", str("JSON path expression."), "value", nullableString("JSON path read result as text, or null when absent."),
            "asBoolean", bool("JSON path result interpreted as boolean when available."), "asDouble", number("JSON path result interpreted as a number when available."),
            "asLong", integer("JSON path result interpreted as an integer when available."), "result", str("Serialized JSON after path modification."),
            "addedValue", str("JSON text supplied for addition."), "updatedValue", str("JSON text supplied for replacement."),
            "valid", bool("Whether input is valid JSON."), "rootType", str("Parsed root Java type, such as LinkedHashMap or ArrayList."), "keys", strings("Root object keys."),
            "fromBase", str("Original number base."), "toBase", str("Requested number base."),
            "allBases", object(props("binary", str("Binary representation."), "octal", str("Octal representation."), "decimal", str("Decimal representation."), "hex", str("Hexadecimal representation.")), "binary", "octal", "decimal", "hex"),
            "pattern", str("Byte search pattern."), "useRegex", bool("Whether the byte search uses a regular expression."),
            "firstMatchIndex", integer("First match offset, or -1 when no match exists."),
            "matches", array("Up to ten byte-search match offsets, with matched text for regex searches.", object(props("index", count("Match offset."), "match", str("Regex matched text.")), "index")),
            "contextPreview", str("Text around the first literal-byte match."), "mode", str("Shell mode: safe argument array or dangerous shell-interpreted string."),
            "command", str("Executed command or joined argument array."), "timeoutSeconds", integer("Configured shell timeout in seconds."),
            "mergeStderr", bool("Whether standard error is merged with output."), "allowNonZeroExit", bool("Whether nonzero shell exit codes are accepted."));
        fields.put("inputLength", count("Base64 input character count, or UTF-8 input bytes for byte_search."));
        fields.put("outputLength", count("Base64 encoded or decoded output character count."));
        fields.put("hashLengthBytes", count("Digest size in bytes before hexadecimal encoding."));
        fields.put("length", count("Generated random string length."));
        fields.put("originalSize", count("GZIP original input length in characters."));
        fields.put("compressedSize", count("GZIP compressed bytes before base64 encoding."));
        fields.put("decompressedSize", count("GZIP decompressed byte length."));
        fields.put("originalLength", count("Original JSON character count before formatting."));
        fields.put("beautifiedLength", count("Formatted JSON character count."));
        fields.put("arrayLength", count("Number of root JSON array elements."));
        fields.put("matchCount", count("Total byte-search matches; matches contains at most ten examples."));
        fields.put("executionTimeMs", count("Elapsed shell execution time in milliseconds."));
        return fields;
    }

    private static Map<String, Object> props(Object... entries) {
        Map<String, Object> properties = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) properties.put((String) entries[i], entries[i + 1]);
        return properties;
    }
    private static Map<String, Object> object(Map<String, Object> fields, String... required) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "object"); result.put("properties", fields); result.put("additionalProperties", true);
        if (required.length > 0) result.put("required", List.of(required));
        return result;
    }
    private static Map<String, Object> str(String description) { return SchemaHelper.stringProp(description); }
    private static Map<String, Object> nullableString(String description) { return Map.of("type", List.of("string", "null"), "description", description); }
    private static Map<String, Object> bool(String description) { return SchemaHelper.boolProp(description); }
    private static Map<String, Object> integer(String description) { return SchemaHelper.intProp(description); }
    private static Map<String, Object> count(String description) { return Map.of("type", "integer", "minimum", 0, "description", description); }
    private static Map<String, Object> number(String description) { return Map.of("type", "number", "description", description); }
    private static Map<String, Object> strings(String description) { return array(description, str("String value.")); }
    private static Map<String, Object> array(String description, Map<String, Object> items) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("type", "array"); result.put("description", description); result.put("items", items);
        return result;
    }
    private static Map<String, Object> dictionary(String description, Map<String, Object> values) {
        return Map.of("type", "object", "description", description, "additionalProperties", values);
    }
}
