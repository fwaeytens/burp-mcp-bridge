package com.example.burpmcp;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import java.util.stream.Collectors;

/**
 * Utility class for common MCP tool operations and response formatting.
 */
public class McpUtils {
    
    /**
     * Creates a standardized error response for MCP tools.
     */
    public static Object createErrorResponse(String message) {
        Map<String, Object> errorResult = new HashMap<>();
        errorResult.put("type", "text");
        errorResult.put("text", "❌ " + message);
        return List.of(errorResult);
    }
    
    /**
     * Creates a standardized success response for MCP tools.
     */
    public static Object createSuccessResponse(String message) {
        Map<String, Object> result = new HashMap<>();
        result.put("type", "text");
        result.put("text", message);
        return List.of(result);
    }
    
    /**
     * Creates a property map for tool input schema.
     */
    public static Map<String, Object> createProperty(String type, String description) {
        Map<String, Object> property = new HashMap<>();
        property.put("type", type);
        property.put("description", description);
        return property;
    }
    
    /**
     * Creates a property map with default value for tool input schema.
     */
    public static Map<String, Object> createProperty(String type, String description, Object defaultValue) {
        Map<String, Object> property = createProperty(type, description);
        property.put("default", defaultValue);
        return property;
    }
    
    /**
     * Creates a property map with enum values for tool input schema.
     */
    public static Map<String, Object> createEnumProperty(String type, String description, List<String> enumValues) {
        Map<String, Object> property = createProperty(type, description);
        property.put("enum", enumValues);
        return property;
    }
    
    /**
     * Creates a property map with enum values and default for tool input schema.
     */
    public static Map<String, Object> createEnumProperty(String type, String description, List<String> enumValues, String defaultValue) {
        Map<String, Object> property = createEnumProperty(type, description, enumValues);
        property.put("default", defaultValue);
        return property;
    }
    
    /**
     * Validates that required parameters are present in arguments.
     */
    public static boolean validateRequiredParams(com.fasterxml.jackson.databind.JsonNode arguments, String... requiredParams) {
        for (String param : requiredParams) {
            if (!arguments.has(param) || arguments.get(param).isNull() || 
                arguments.get(param).asText().trim().isEmpty()) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Gets a string parameter from arguments with default value.
     */
    public static String getStringParam(com.fasterxml.jackson.databind.JsonNode arguments, String paramName, String defaultValue) {
        if (arguments.has(paramName) && !arguments.get(paramName).isNull()) {
            return arguments.get(paramName).asText();
        }
        return defaultValue;
    }

    /**
     * Returns a trimmed string parameter or null if missing/blank.
     */
    public static String getTrimmedStringParam(com.fasterxml.jackson.databind.JsonNode arguments, String paramName) {
        String value = getStringParam(arguments, paramName, null);
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Resolves an action name against the allowed list in a case-insensitive fashion.
     * Returns an {@link ActionResolution} describing either the canonical action or the validation issue.
     */
    public static ActionResolution resolveAction(com.fasterxml.jackson.databind.JsonNode arguments, Collection<String> allowedActions) {
        String raw = getTrimmedStringParam(arguments, "action");
        if (raw == null) {
            return ActionResolution.missing();
        }

        if (allowedActions == null || allowedActions.isEmpty()) {
            // No canonical set provided; just normalize spacing
            return ActionResolution.matched(raw);
        }

        for (String candidate : allowedActions) {
            if (candidate.equalsIgnoreCase(raw)) {
                return ActionResolution.matched(candidate);
            }
        }

        String expected = allowedActions.stream()
            .map(v -> "`" + v + "`")
            .collect(Collectors.joining(", "));
        String message = "Unknown action: " + raw + ". Expected one of: " + expected;
        return ActionResolution.unknown(message);
    }

    /**
     * Simple wrapper describing the outcome of resolving an action string.
     */
    public static final class ActionResolution {
        public enum Status { MATCHED, MISSING, UNKNOWN }

        private final Status status;
        private final String action;
        private final String errorMessage;

        private ActionResolution(Status status, String action, String errorMessage) {
            this.status = status;
            this.action = action;
            this.errorMessage = errorMessage;
        }

        public static ActionResolution matched(String action) {
            return new ActionResolution(Status.MATCHED, action, null);
        }

        public static ActionResolution missing() {
            return new ActionResolution(Status.MISSING, null, "action is required");
        }

        public static ActionResolution unknown(String message) {
            return new ActionResolution(Status.UNKNOWN, null, message);
        }

        public boolean hasError() {
            return errorMessage != null;
        }

        public boolean isMissing() {
            return status == Status.MISSING;
        }

        public String getAction() {
            return action;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }
    
    /**
     * Gets an integer parameter from arguments with default value.
     */
    public static int getIntParam(com.fasterxml.jackson.databind.JsonNode arguments, String paramName, int defaultValue) {
        if (arguments.has(paramName) && !arguments.get(paramName).isNull()) {
            return arguments.get(paramName).asInt();
        }
        return defaultValue;
    }
    
    /**
     * Gets a boolean parameter from arguments with default value.
     */
    public static boolean getBooleanParam(com.fasterxml.jackson.databind.JsonNode arguments, String paramName, boolean defaultValue) {
        if (arguments.has(paramName) && !arguments.get(paramName).isNull()) {
            return arguments.get(paramName).asBoolean();
        }
        return defaultValue;
    }
    
    /**
     * Safely truncates text to maximum length with ellipsis.
     */
    public static String truncateText(String text, int maxLength) {
        if (text == null) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength - 3) + "...";
    }
    
    /**
     * Formats file size in human-readable format.
     */
    public static String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " bytes";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
    
    /**
     * Sanitizes input to prevent basic injection attacks in logging.
     */
    public static String sanitizeForLogging(String input) {
        if (input == null) return "";
        return input.replaceAll("[\r\n\t]", "_")
                   .replaceAll("[\\x00-\\x1F\\x7F]", "")
                   .substring(0, Math.min(input.length(), 200));
    }
    
    /**
     * Properly encodes a URL to handle special characters like spaces, quotes, etc.
     * This is essential for SQL injection payloads and other special characters.
     */
    public static String encodeUrl(String url) {
        if (url == null || url.isEmpty()) {
            return url;
        }
        
        // Find the query string start
        int queryIndex = url.indexOf('?');
        if (queryIndex == -1) {
            // No query string, URL should be valid as-is
            return url;
        }
        
        String baseUrl = url.substring(0, queryIndex);
        String queryString = url.substring(queryIndex + 1);
        
        // Manually encode each character in the query string that needs encoding
        StringBuilder encodedQuery = new StringBuilder();
        
        for (char c : queryString.toCharArray()) {
            switch (c) {
                case ' ':
                    encodedQuery.append("%20");
                    break;
                case '\'':
                    encodedQuery.append("%27");
                    break;
                case '"':
                    encodedQuery.append("%22");
                    break;
                case '<':
                    encodedQuery.append("%3C");
                    break;
                case '>':
                    encodedQuery.append("%3E");
                    break;
                case '{':
                    encodedQuery.append("%7B");
                    break;
                case '}':
                    encodedQuery.append("%7D");
                    break;
                case '[':
                    encodedQuery.append("%5B");
                    break;
                case ']':
                    encodedQuery.append("%5D");
                    break;
                case '|':
                    encodedQuery.append("%7C");
                    break;
                case '\\':
                    encodedQuery.append("%5C");
                    break;
                case '^':
                    encodedQuery.append("%5E");
                    break;
                case '`':
                    encodedQuery.append("%60");
                    break;
                case '(':
                    encodedQuery.append("%28");
                    break;
                case ')':
                    encodedQuery.append("%29");
                    break;
                case '#':
                    encodedQuery.append("%23");
                    break;
                case '%':
                    // Only encode % if it's not already part of an encoding
                    if (isAlreadyEncoded(queryString, encodedQuery.length())) {
                        encodedQuery.append(c);
                    } else {
                        encodedQuery.append("%25");
                    }
                    break;
                default:
                    // For characters that need encoding but aren't in our manual list
                    if (c > 127 || Character.isISOControl(c)) {
                        encodedQuery.append(String.format("%%%02X", (int) c));
                    } else {
                        encodedQuery.append(c);
                    }
                    break;
            }
        }
        
        return baseUrl + "?" + encodedQuery.toString();
    }
    
    /**
     * Check if a % character is already part of a URL encoding.
     */
    private static boolean isAlreadyEncoded(String original, int currentPos) {
        // Simple heuristic: if we have at least 2 more chars and they're hex digits
        if (currentPos < original.length() - 2) {
            char next1 = original.charAt(currentPos + 1);
            char next2 = original.charAt(currentPos + 2);
            return isHexDigit(next1) && isHexDigit(next2);
        }
        return false;
    }
    
    /**
     * Check if a character is a hex digit.
     */
    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }
    
    /**
     * Creates an HttpRequest safely, handling URL encoding issues.
     */
    public static burp.api.montoya.http.message.requests.HttpRequest createSafeHttpRequest(String url) throws Exception {
        // Always use our robust encoding first
        String encodedUrl = encodeUrl(url);
        
        // URL encoding applied successfully
        
        try {
            return burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(encodedUrl);
        } catch (Exception e) {
            // If encoding still fails, provide detailed error information
            throw new Exception("Failed to create HTTP request even after URL encoding. Original URL: " + 
                              sanitizeForLogging(url) + ", Encoded URL: " + sanitizeForLogging(encodedUrl) + 
                              ". Error: " + e.getMessage(), e);
        }
    }
}
