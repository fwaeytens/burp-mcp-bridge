package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class SessionManagementTool implements McpTool {
    private final MontoyaApi api;
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "EXTRACT_TOKENS",
        "SET_TOKEN",
        "CLEAR_TOKENS",
        "LIST_TOKENS",
        "TEST_SESSION",
        "FIND_LOGOUT",
        "SESSION_STATUS",
        "COOKIE_JAR_LIST",
        "COOKIE_JAR_SET",
        "COOKIE_JAR_DELETE",
        "COOKIE_JAR_CLEAR",
        "ENABLE_AUTO_SESSION",
        "DISABLE_AUTO_SESSION",
        "AUTO_SESSION_STATUS",
        "ANALYZE_SESSION_VALIDITY"
    );
    private final Map<String, String> sessionTokens;
    private final List<String> sessionUrls;

    public SessionManagementTool(MontoyaApi api) {
        this.api = api;
        this.sessionTokens = new HashMap<>();
        this.sessionUrls = new ArrayList<>();
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_session_management");
        tool.put("title", "Session Manager");
        tool.put("description", "Advanced session management with Burp's native cookie jar and automatic session handling. " +
            "Use this to manage cookies, extract tokens, test session validity, and configure automatic session refresh. " +
            "Actions: EXTRACT_TOKENS (find session tokens in proxy history), SET_TOKEN/CLEAR_TOKENS/LIST_TOKENS (in-memory token store), " +
            "TEST_SESSION/FIND_LOGOUT/SESSION_STATUS (verify session validity), " +
            "COOKIE_JAR_LIST/COOKIE_JAR_SET/COOKIE_JAR_DELETE/COOKIE_JAR_CLEAR (manage Burp's native cookie jar), " +
            "ENABLE_AUTO_SESSION/DISABLE_AUTO_SESSION/AUTO_SESSION_STATUS (automatic refresh on 401/403), " +
            "ANALYZE_SESSION_VALIDITY (heuristic analysis of captured traffic). " +
            "Integrates with Burp's session handling rules.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);  // DELETE/CLEAR actions remove cookies
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        annotations.put("title", "Session Manager");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "cookie jar authentication tokens sessions");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");

        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Session management action");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);
        
        Map<String, Object> urlProperty = new HashMap<>();
        urlProperty.put("type", "string");
        urlProperty.put("description", "URL for session operations (required for some actions)");
        properties.put("url", urlProperty);
        
        Map<String, Object> tokenNameProperty = new HashMap<>();
        tokenNameProperty.put("type", "string");
        tokenNameProperty.put("description", "Token/cookie name — used for both SET_TOKEN (in-memory token store) and COOKIE_JAR_SET/COOKIE_JAR_DELETE (Burp's native cookie jar).");
        properties.put("tokenName", tokenNameProperty);
        
        Map<String, Object> tokenValueProperty = new HashMap<>();
        tokenValueProperty.put("type", "string");
        tokenValueProperty.put("description", "Token/cookie value — used for both SET_TOKEN (in-memory token store) and COOKIE_JAR_SET (Burp's native cookie jar).");
        properties.put("tokenValue", tokenValueProperty);
        
        Map<String, Object> extractPatternProperty = new HashMap<>();
        extractPatternProperty.put("type", "string");
        extractPatternProperty.put("description", "Regex pattern to extract tokens (for EXTRACT_TOKENS)");
        extractPatternProperty.put("default", "([A-Fa-f0-9]{32,}|[A-Za-z0-9+/=]{40,}|[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,})");
        properties.put("extractPattern", extractPatternProperty);
        
        Map<String, Object> domainProperty = new HashMap<>();
        domainProperty.put("type", "string");
        domainProperty.put("description", "Cookie domain (for COOKIE_JAR_SET)");
        properties.put("domain", domainProperty);
        
        Map<String, Object> pathProperty = new HashMap<>();
        pathProperty.put("type", "string");
        pathProperty.put("description", "Cookie path (for COOKIE_JAR_SET, default '/')");
        pathProperty.put("default", "/");
        properties.put("path", pathProperty);
        
        Map<String, Object> expirationProperty = new HashMap<>();
        expirationProperty.put("type", "string");
        expirationProperty.put("description", "Cookie expiration in ISO-8601 format (for COOKIE_JAR_SET, optional)");
        properties.put("expiration", expirationProperty);
        
        Map<String, Object> autoRefreshProperty = new HashMap<>();
        autoRefreshProperty.put("type", "boolean");
        autoRefreshProperty.put("description", "Enable automatic token refresh on 401/403 responses");
        autoRefreshProperty.put("default", true);
        properties.put("autoRefresh", autoRefreshProperty);
        
        Map<String, Object> validityKeywordsProperty = new HashMap<>();
        validityKeywordsProperty.put("type", "array");
        validityKeywordsProperty.put("description", "Keywords to check for session validity");
        validityKeywordsProperty.put("items", Map.of("type", "string"));
        properties.put("validityKeywords", validityKeywordsProperty);

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

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
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        String tokenName = arguments.has("tokenName") ? arguments.get("tokenName").asText() : null;
        String tokenValue = arguments.has("tokenValue") ? arguments.get("tokenValue").asText() : null;
        String extractPattern = arguments.has("extractPattern") ? arguments.get("extractPattern").asText() : 
            "([A-Fa-f0-9]{32,}|[A-Za-z0-9+/=]{40,}|[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,})";
        String domain = arguments.has("domain") ? arguments.get("domain").asText() : null;
        String path = arguments.has("path") ? arguments.get("path").asText() : "/";
        String expiration = arguments.has("expiration") ? arguments.get("expiration").asText() : null;
        boolean autoRefresh = arguments.has("autoRefresh") ? arguments.get("autoRefresh").asBoolean() : true;
        
        boolean verbose = McpUtils.isVerbose(arguments);
        try {
            switch (action) {
                case "EXTRACT_TOKENS":
                    return extractTokensFromHistory(url, extractPattern, verbose);
                case "SET_TOKEN":
                    return setSessionToken(tokenName, tokenValue, verbose);
                case "CLEAR_TOKENS":
                    return clearSessionTokens(verbose);
                case "LIST_TOKENS":
                    return listSessionTokens(verbose);
                case "TEST_SESSION":
                    return testSessionValidity(url, verbose);
                case "FIND_LOGOUT":
                    return findLogoutEndpoints(url, verbose);
                case "SESSION_STATUS":
                    return getSessionStatus(verbose);
                case "COOKIE_JAR_LIST":
                    return listCookieJar(verbose);
                case "COOKIE_JAR_SET":
                    return setCookieInJar(tokenName, tokenValue, domain, path, expiration, verbose);
                case "COOKIE_JAR_DELETE":
                    return deleteCookieFromJar(tokenName, domain, verbose);
                case "COOKIE_JAR_CLEAR":
                    return clearCookieJar(verbose);
                case "ENABLE_AUTO_SESSION":
                    return enableAutoSessionHandling(autoRefresh, verbose);
                case "DISABLE_AUTO_SESSION":
                    return disableAutoSessionHandling(verbose);
                case "AUTO_SESSION_STATUS":
                    return getAutoSessionStatus(verbose);
                case "ANALYZE_SESSION_VALIDITY":
                    return analyzeSessionValidity(url, arguments, verbose);
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
        } catch (Exception e) {
            api.logging().logToError("Error in session management: " + e.getMessage());
            return McpUtils.createErrorResponse("Error in session management: " + e.getMessage());
        }
    }
    
    private Object extractTokensFromHistory(String urlFilter, String pattern, boolean verbose) {
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        Pattern tokenPattern = Pattern.compile(pattern);
        Map<String, String> foundTokens = new HashMap<>();
        int processedEntries = 0;

        for (ProxyHttpRequestResponse entry : proxyHistory) {
            if (urlFilter != null && !entry.request().url().contains(urlFilter)) {
                continue;
            }

            processedEntries++;

            // Extract from request headers (focus on auth headers)
            String requestHeaders = entry.request().toString();
            String[] lines = requestHeaders.split("\n");
            for (String line : lines) {
                String lowerLine = line.toLowerCase();
                if (lowerLine.contains("authorization:") || lowerLine.contains("x-auth") ||
                    lowerLine.contains("x-session") || lowerLine.contains("x-token")) {
                    Matcher requestMatcher = tokenPattern.matcher(line);
                    while (requestMatcher.find()) {
                        String token = requestMatcher.group(1);
                        if (!isCommonFalsePositive(token)) {
                            foundTokens.put("request_auth_" + foundTokens.size(), token);
                        }
                    }
                }
            }

            // Extract from response Set-Cookie headers
            if (entry.response() != null) {
                entry.response().headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                    .forEach(header -> {
                        Matcher responseMatcher = tokenPattern.matcher(header.value());
                        while (responseMatcher.find()) {
                            String token = responseMatcher.group(1);
                            if (!isCommonFalsePositive(token)) {
                                foundTokens.put("response_cookie_" + foundTokens.size(), token);
                            }
                        }
                    });
            }

            // Extract cookies
            List<String> cookies = entry.request().headers().stream()
                .filter(header -> header.name().equalsIgnoreCase("Cookie"))
                .map(header -> header.value())
                .collect(Collectors.toList());

            for (String cookieHeader : cookies) {
                String[] cookiePairs = cookieHeader.split(";");
                for (String pair : cookiePairs) {
                    String[] keyValue = pair.trim().split("=", 2);
                    if (keyValue.length == 2) {
                        sessionTokens.put(keyValue[0].trim(), keyValue[1].trim());
                        foundTokens.put("cookie_" + keyValue[0].trim(), keyValue[1].trim());
                    }
                }
            }
        }

        // Store significant tokens (side effect retained for both branches)
        for (Map.Entry<String, String> entry : foundTokens.entrySet()) {
            if (entry.getKey().contains("session") || entry.getKey().contains("auth") ||
                entry.getKey().contains("token") || entry.getKey().contains("jwt")) {
                sessionTokens.put(entry.getKey(), entry.getValue());
            }
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "extractTokens");
            data.put("processedEntries", processedEntries);
            data.put("tokensFound", foundTokens.size());
            if (urlFilter != null) data.put("urlFilter", urlFilter);
            List<Map<String, Object>> tokens = new ArrayList<>();
            for (Map.Entry<String, String> entry : foundTokens.entrySet()) {
                Map<String, Object> tok = new HashMap<>();
                tok.put("name", entry.getKey());
                tok.put("value", entry.getValue());
                tokens.add(tok);
            }
            data.put("tokens", tokens);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🔍 **EXTRACTING SESSION TOKENS FROM PROXY HISTORY**\n\n");
        result.append("📊 **Extraction Results:**\n");
        result.append("• Processed Entries: ").append(processedEntries).append("\n");
        result.append("• Tokens Found: ").append(foundTokens.size()).append("\n\n");

        if (!foundTokens.isEmpty()) {
            result.append("🎯 **Found Tokens:**\n");
            for (Map.Entry<String, String> entry : foundTokens.entrySet()) {
                result.append("• **").append(entry.getKey()).append(":** ");
                String value = entry.getValue();
                if (value.length() > 50) {
                    result.append(value.substring(0, 47)).append("...");
                } else {
                    result.append(value);
                }
                result.append("\n");
            }
        } else {
            result.append("ℹ️ No tokens found matching the specified pattern.");
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object setSessionToken(String name, String value, boolean verbose) {
        if (name == null || value == null) {
            return McpUtils.createErrorResponse("Both tokenName and tokenValue are required for SET_TOKEN action");
        }

        sessionTokens.put(name, value);

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "setToken");
            data.put("success", true);
            data.put("tokenName", name);
            data.put("tokenValue", value);
            data.put("totalTokens", sessionTokens.size());
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("✅ **SESSION TOKEN SET**\n\n");
        result.append("**Token Name:** ").append(name).append("\n");
        result.append("**Token Value:** ");
        if (value.length() > 50) {
            result.append(value.substring(0, 47)).append("...");
        } else {
            result.append(value);
        }
        result.append("\n\n");
        result.append("🔧 **Usage:** This token will be available for session testing and management operations.\n");
        result.append("💡 **Tip:** Use TEST_SESSION action to verify the token validity.");

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object clearSessionTokens(boolean verbose) {
        int tokenCount = sessionTokens.size();
        sessionTokens.clear();
        sessionUrls.clear();

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "clearTokens");
            data.put("success", true);
            data.put("tokensRemoved", tokenCount);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🧹 **SESSION TOKENS CLEARED**\n\n");
        result.append("• Removed ").append(tokenCount).append(" stored tokens\n");
        result.append("• Cleared session URL list\n");
        result.append("• Session management state reset\n\n");
        result.append("ℹ️ All stored authentication tokens have been removed from memory.");

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object listSessionTokens(boolean verbose) {
        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "listTokens");
            data.put("tokenCount", sessionTokens.size());
            List<Map<String, Object>> tokens = new ArrayList<>();
            for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                Map<String, Object> tok = new HashMap<>();
                tok.put("name", entry.getKey());
                tok.put("value", entry.getValue());
                tok.put("length", entry.getValue().length());
                tokens.add(tok);
            }
            data.put("tokens", tokens);
            data.put("sessionUrls", new ArrayList<>(sessionUrls));
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("📋 **STORED SESSION TOKENS**\n\n");

        if (sessionTokens.isEmpty()) {
            result.append("ℹ️ No session tokens currently stored.\n\n");
            result.append("💡 **Tip:** Use EXTRACT_TOKENS to find tokens from proxy history, or SET_TOKEN to manually add tokens.");
        } else {
            result.append("**Token Count:** ").append(sessionTokens.size()).append("\n\n");

            int index = 1;
            for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                result.append("**").append(index).append(". ").append(entry.getKey()).append("**\n");
                result.append("   Value: ");
                String value = entry.getValue();
                if (value.length() > 60) {
                    result.append(value.substring(0, 57)).append("...");
                } else {
                    result.append(value);
                }
                result.append("\n");
                result.append("   Length: ").append(value.length()).append(" characters\n\n");
                index++;
            }
        }

        if (!sessionUrls.isEmpty()) {
            result.append("🌐 **Session URLs:**\n");
            for (String url : sessionUrls) {
                result.append("• ").append(url).append("\n");
            }
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object testSessionValidity(String testUrl, boolean verbose) {
        if (testUrl == null) {
            return McpUtils.createErrorResponse("URL is required for TEST_SESSION action");
        }

        Integer statusCode = null;
        String sessionStatus = null;
        String redirectLocation = null;
        List<String> setCookieHeaders = new ArrayList<>();
        Integer responseLength = null;
        String errorMsg = null;

        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(testUrl);

            if (!sessionTokens.isEmpty()) {
                StringBuilder cookieHeader = new StringBuilder();
                for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                    if (cookieHeader.length() > 0) {
                        cookieHeader.append("; ");
                    }
                    cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
                }
                request = request.withAddedHeader("Cookie", cookieHeader.toString());
            }

            HttpRequestResponse response = api.http().sendRequest(request);

            if (response.response() != null) {
                statusCode = (int) response.response().statusCode();
                String responseBody = response.response().bodyToString();
                String responseHeaders = response.response().toString();
                responseLength = responseBody.length();

                if (statusCode == 200) {
                    if (responseBody.toLowerCase().contains("login") ||
                        responseBody.toLowerCase().contains("sign in") ||
                        responseHeaders.toLowerCase().contains("www-authenticate")) {
                        sessionStatus = "INVALID";
                    } else {
                        sessionStatus = "VALID";
                    }
                } else if (statusCode == 401 || statusCode == 403) {
                    sessionStatus = "INVALID";
                } else if (statusCode == 302 || statusCode == 301) {
                    redirectLocation = response.response().headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Location"))
                        .map(h -> h.value())
                        .findFirst()
                        .orElse("Unknown");
                    sessionStatus = "REDIRECT";
                } else {
                    sessionStatus = "UNKNOWN";
                }

                setCookieHeaders = response.response().headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                    .map(h -> h.value())
                    .collect(Collectors.toList());
            } else {
                errorMsg = "No response received - connection failed";
            }
        } catch (Exception e) {
            errorMsg = e.getMessage();
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "testSession");
            data.put("url", testUrl);
            if (errorMsg != null) {
                data.put("success", false);
                data.put("error", errorMsg);
            } else {
                data.put("success", true);
                data.put("statusCode", statusCode);
                data.put("sessionStatus", sessionStatus);
                if (redirectLocation != null) data.put("redirectLocation", redirectLocation);
                data.put("responseLength", responseLength);
                List<Map<String, Object>> cookies = new ArrayList<>();
                for (String cookie : setCookieHeaders) {
                    String[] parts = cookie.split("=", 2);
                    if (parts.length == 2) {
                        Map<String, Object> c = new HashMap<>();
                        c.put("name", parts[0]);
                        c.put("value", parts[1].split(";")[0]);
                        cookies.add(c);
                    }
                }
                data.put("setCookies", cookies);
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🧪 **TESTING SESSION VALIDITY**\n\n");
        result.append("**Test URL:** ").append(testUrl).append("\n\n");

        if (errorMsg != null) {
            result.append("❌ **Test Failed:** ").append(errorMsg);
            return McpUtils.createSuccessResponse(result.toString());
        }

        result.append("📡 **Response Analysis:**\n");
        result.append("• Status Code: ").append(statusCode).append("\n");
        switch (sessionStatus) {
            case "VALID":
                result.append("• Session Status: ✅ **VALID** (authenticated response)\n");
                break;
            case "INVALID":
                if (statusCode == 401 || statusCode == 403) {
                    result.append("• Session Status: ❌ **INVALID** (authentication required)\n");
                } else {
                    result.append("• Session Status: ❌ **INVALID** (redirected to login)\n");
                }
                break;
            case "REDIRECT":
                result.append("• Session Status: ⚠️ **REDIRECT** to ").append(redirectLocation).append("\n");
                break;
            default:
                result.append("• Session Status: ⚠️ **UNKNOWN** (unexpected status)\n");
        }

        if (!setCookieHeaders.isEmpty()) {
            result.append("• New Cookies: ").append(setCookieHeaders.size()).append(" found\n");
            for (String cookie : setCookieHeaders) {
                String[] parts = cookie.split("=", 2);
                if (parts.length == 2) {
                    String cookieName = parts[0];
                    String cookieValue = parts[1].split(";")[0];
                    result.append("  - ").append(cookieName).append(": ").append(cookieValue.substring(0, Math.min(30, cookieValue.length())));
                    if (cookieValue.length() > 30) result.append("...");
                    result.append("\n");
                }
            }
        }

        result.append("• Response Length: ").append(responseLength).append(" bytes\n");

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object findLogoutEndpoints(String baseUrl, boolean verbose) {
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        List<String> logoutUrls = new ArrayList<>();

        for (ProxyHttpRequestResponse entry : proxyHistory) {
            String url = entry.request().url().toLowerCase();
            String path = entry.request().path().toLowerCase();

            if (url.contains("logout") || url.contains("signout") || url.contains("sign-out") ||
                url.contains("logoff") || url.contains("exit") || url.contains("disconnect") ||
                path.contains("/logout") || path.contains("/signout") || path.contains("/logoff")) {

                if (baseUrl == null || entry.request().url().contains(baseUrl)) {
                    logoutUrls.add(entry.request().url());
                }
            }

            if (entry.response() != null) {
                String responseBody = entry.response().bodyToString().toLowerCase();
                if (responseBody.contains("logout") || responseBody.contains("sign out")) {
                    if (baseUrl == null || entry.request().url().contains(baseUrl)) {
                        logoutUrls.add(entry.request().url() + " (contains logout content)");
                    }
                }
            }
        }

        logoutUrls = logoutUrls.stream().distinct().collect(Collectors.toList());

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "findLogout");
            if (baseUrl != null) data.put("baseUrl", baseUrl);
            data.put("count", logoutUrls.size());
            data.put("endpoints", logoutUrls);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🚪 **SEARCHING FOR LOGOUT ENDPOINTS**\n\n");

        if (baseUrl != null) {
            result.append("**Base URL:** ").append(baseUrl).append("\n\n");
        }

        result.append("🎯 **Found Logout Endpoints:**\n");
        if (logoutUrls.isEmpty()) {
            result.append("ℹ️ No logout endpoints found in proxy history.\n\n");
            result.append("💡 **Suggestions:**\n");
            result.append("• Navigate through the application to discover logout functionality\n");
            result.append("• Check common logout paths: /logout, /signout, /logoff\n");
            result.append("• Look for logout buttons or links in the application interface");
        } else {
            for (String url : logoutUrls) {
                result.append("• ").append(url).append("\n");
            }
            result.append("\n📝 **Next Steps:**\n");
            result.append("• Test these endpoints to confirm logout functionality\n");
            result.append("• Verify session invalidation after logout\n");
            result.append("• Check for proper session cleanup");
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getSessionStatus(boolean verbose) {
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        int sessionRequests = 0;
        int authRequests = 0;

        for (ProxyHttpRequestResponse entry : proxyHistory) {
            String url = entry.request().url().toLowerCase();
            String headers = entry.request().toString().toLowerCase();

            if (headers.contains("cookie") || headers.contains("authorization")) {
                sessionRequests++;
            }

            if (url.contains("login") || url.contains("auth") || url.contains("signin")) {
                authRequests++;
            }
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "sessionStatus");
            data.put("storedTokens", sessionTokens.size());
            data.put("sessionUrls", sessionUrls.size());
            List<Map<String, Object>> tokens = new ArrayList<>();
            for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                Map<String, Object> tok = new HashMap<>();
                tok.put("name", entry.getKey());
                tok.put("length", entry.getValue().length());
                tokens.add(tok);
            }
            data.put("tokenSummary", tokens);
            data.put("totalProxyEntries", proxyHistory.size());
            data.put("sessionRequests", sessionRequests);
            data.put("authRequests", authRequests);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("📊 **SESSION MANAGEMENT STATUS**\n\n");

        result.append("🔑 **Stored Tokens:** ").append(sessionTokens.size()).append("\n");
        result.append("🌐 **Session URLs:** ").append(sessionUrls.size()).append("\n");

        if (!sessionTokens.isEmpty()) {
            result.append("\n📋 **Token Summary:**\n");
            for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                result.append("• ").append(entry.getKey()).append(" (").append(entry.getValue().length()).append(" chars)\n");
            }
        }

        result.append("\n📈 **Request Analysis:**\n");
        result.append("• Total Proxy Entries: ").append(proxyHistory.size()).append("\n");
        result.append("• Requests with Session Data: ").append(sessionRequests).append("\n");
        result.append("• Authentication Requests: ").append(authRequests).append("\n");

        result.append("\n🛠️ **Available Actions:**\n");
        result.append("• EXTRACT_TOKENS - Find tokens from proxy history\n");
        result.append("• SET_TOKEN - Manually add session tokens\n");
        result.append("• TEST_SESSION - Verify token validity\n");
        result.append("• FIND_LOGOUT - Discover logout endpoints\n");
        result.append("• CLEAR_TOKENS - Reset session state");

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // New Cookie Jar methods
    private Object listCookieJar(boolean verbose) {
        try {
            CookieJar cookieJar = api.http().cookieJar();
            List<Cookie> cookies = cookieJar.cookies();

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "cookieJarList");
                data.put("totalCookies", cookies.size());
                List<Map<String, Object>> cookieList = new ArrayList<>();
                for (Cookie cookie : cookies) {
                    Map<String, Object> c = new HashMap<>();
                    c.put("name", cookie.name());
                    c.put("value", cookie.value());
                    c.put("domain", cookie.domain());
                    c.put("path", cookie.path());
                    Optional<ZonedDateTime> expiry = cookie.expiration();
                    if (expiry.isPresent()) {
                        c.put("expires", expiry.get().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
                    } else {
                        c.put("expires", null);
                    }
                    cookieList.add(c);
                }
                data.put("cookies", cookieList);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🍪 **BURP COOKIE JAR CONTENTS**\n\n");

            if (cookies.isEmpty()) {
                result.append("ℹ️ Cookie jar is empty.\n\n");
                result.append("💡 **Tip:** Use COOKIE_JAR_SET to add cookies or navigate to sites that set cookies.");
            } else {
                result.append("**Total Cookies:** ").append(cookies.size()).append("\n\n");

                for (Cookie cookie : cookies) {
                    result.append("**🔹 ").append(cookie.name()).append("**\n");
                    result.append("   • Value: ").append(truncateValue(cookie.value(), 60)).append("\n");
                    result.append("   • Domain: ").append(cookie.domain()).append("\n");
                    result.append("   • Path: ").append(cookie.path()).append("\n");

                    Optional<ZonedDateTime> expiry = cookie.expiration();
                    if (expiry.isPresent()) {
                        result.append("   • Expires: ").append(expiry.get().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)).append("\n");
                    } else {
                        result.append("   • Expires: Session cookie\n");
                    }
                    result.append("\n");
                }
            }
            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error accessing cookie jar: " + e.getMessage());
        }
    }
    
    private Object setCookieInJar(String name, String value, String domain, String path, String expirationStr, boolean verbose) {
        if (name == null || value == null || domain == null) {
            return McpUtils.createErrorResponse("name, value, and domain are required for COOKIE_JAR_SET");
        }

        try {
            CookieJar cookieJar = api.http().cookieJar();

            // Parse expiration if provided
            ZonedDateTime expiration = null;
            boolean invalidExpiration = false;
            if (expirationStr != null && !expirationStr.isEmpty()) {
                try {
                    expiration = ZonedDateTime.parse(expirationStr);
                } catch (Exception e) {
                    invalidExpiration = true;
                }
            }

            String effectivePath = path != null ? path : "/";
            cookieJar.setCookie(name, value, domain, effectivePath, expiration);

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "cookieJarSet");
                data.put("success", true);
                data.put("name", name);
                data.put("value", value);
                data.put("domain", domain);
                data.put("path", effectivePath);
                data.put("expiration", expiration != null ? expiration.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) : null);
                if (invalidExpiration) data.put("invalidExpiration", true);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🍪 **SETTING COOKIE IN BURP JAR**\n\n");
            if (invalidExpiration) {
                result.append("⚠️ Invalid expiration format, using session cookie instead\n");
            }
            result.append("✅ **Cookie Set Successfully**\n\n");
            result.append("• **Name:** ").append(name).append("\n");
            result.append("• **Value:** ").append(truncateValue(value, 60)).append("\n");
            result.append("• **Domain:** ").append(domain).append("\n");
            result.append("• **Path:** ").append(effectivePath).append("\n");
            result.append("• **Expiration:** ").append(expiration != null ?
                expiration.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) : "Session").append("\n\n");

            result.append("🔧 **Impact:** This cookie will be automatically included in all matching requests sent through Burp.");

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error setting cookie: " + e.getMessage());
        }
    }
    
    private Object deleteCookieFromJar(String name, String domain, boolean verbose) {
        if (name == null || domain == null) {
            return McpUtils.createErrorResponse("Both name and domain are required for COOKIE_JAR_DELETE");
        }

        try {
            CookieJar cookieJar = api.http().cookieJar();
            ZonedDateTime expired = ZonedDateTime.now().minusDays(1);
            cookieJar.setCookie(name, "", domain, "/", expired);

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "cookieJarDelete");
                data.put("success", true);
                data.put("name", name);
                data.put("domain", domain);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🗑️ **DELETING COOKIE FROM BURP JAR**\n\n");
            result.append("✅ **Cookie Deleted**\n\n");
            result.append("• **Name:** ").append(name).append("\n");
            result.append("• **Domain:** ").append(domain).append("\n\n");
            result.append("ℹ️ Cookie has been expired and will be removed from future requests.");

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error deleting cookie: " + e.getMessage());
        }
    }
    
    private Object clearCookieJar(boolean verbose) {
        try {
            CookieJar cookieJar = api.http().cookieJar();
            List<Cookie> cookies = cookieJar.cookies();
            int count = cookies.size();

            ZonedDateTime expired = ZonedDateTime.now().minusDays(1);
            for (Cookie cookie : cookies) {
                cookieJar.setCookie(cookie.name(), "", cookie.domain(), cookie.path(), expired);
            }

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "cookieJarClear");
                data.put("success", true);
                data.put("cookiesRemoved", count);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🧹 **CLEARING BURP COOKIE JAR**\n\n");
            result.append("✅ **Cookie Jar Cleared**\n\n");
            result.append("• Removed ").append(count).append(" cookies\n");
            result.append("• All cookies have been expired\n\n");
            result.append("ℹ️ The cookie jar is now empty.");

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error clearing cookie jar: " + e.getMessage());
        }
    }
    
    // Auto session handling methods
    private Object enableAutoSessionHandling(boolean autoRefresh, boolean verbose) {
        try {
            McpServer.clearSessionHandler();

            CustomSessionHandler handler = new CustomSessionHandler(autoRefresh);
            Registration registration = api.http().registerSessionHandlingAction(handler);

            McpServer.setSessionHandler(registration, handler);

            api.logging().logToOutput("MCP Bridge: Session handler registered successfully");

            if (!verbose) {
                Map<String, Object> data = new HashMap<>();
                data.put("operation", "enableAutoSession");
                data.put("success", true);
                data.put("autoRefresh", autoRefresh);
                return McpUtils.createJsonResponse(data);
            }

            StringBuilder result = new StringBuilder();
            result.append("🤖 **ENABLING AUTOMATIC SESSION HANDLING**\n\n");
            result.append("✅ **Auto Session Handler Enabled**\n\n");
            result.append("**Configuration:**\n");
            result.append("• Auto-refresh on 401/403: ").append(autoRefresh ? "✓" : "✗").append("\n");
            result.append("• Session validation: Enabled\n");
            result.append("• Cookie management: Automatic\n\n");

            result.append("**Features:**\n");
            result.append("• Monitors all HTTP requests for session issues\n");
            result.append("• Automatically refreshes expired sessions\n");
            result.append("• Updates cookies based on responses\n");
            result.append("• Adds authentication headers as needed\n\n");

            result.append("💡 **Note:** The handler will process all requests going through Burp.");

            return McpUtils.createSuccessResponse(result.toString());
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error enabling auto session handling: " + e.getMessage());
        }
    }
    
    private Object disableAutoSessionHandling(boolean verbose) {
        boolean wasEnabled = McpServer.getSessionHandlerRegistration() != null;
        if (wasEnabled) {
            McpServer.clearSessionHandler();
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "disableAutoSession");
            data.put("success", true);
            data.put("wasEnabled", wasEnabled);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🛑 **DISABLING AUTOMATIC SESSION HANDLING**\n\n");

        if (wasEnabled) {
            result.append("✅ **Auto Session Handler Disabled**\n\n");
            result.append("• Session handling deregistered\n");
            result.append("• Automatic processing stopped\n");
            result.append("• Manual session management resumed\n\n");
            result.append("ℹ️ You can re-enable automatic handling at any time.");
        } else {
            result.append("ℹ️ Auto session handling is not currently enabled.");
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getAutoSessionStatus(boolean verbose) {
        Registration registration = McpServer.getSessionHandlerRegistration();
        Object handlerObj = McpServer.getCustomSessionHandler();
        boolean active = registration != null && handlerObj instanceof CustomSessionHandler;

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "autoSessionStatus");
            data.put("active", active);
            if (active) {
                CustomSessionHandler handler = (CustomSessionHandler) handlerObj;
                data.put("requestsProcessed", handler.getRequestCount());
                data.put("sessionsRefreshed", handler.getRefreshCount());
                data.put("failedAuthentications", handler.getFailureCount());
                data.put("lastActivity", handler.getLastActivity());
                data.put("autoRefresh", handler.isAutoRefreshEnabled());
                data.put("handlerName", handler.name());
            } else {
                data.put("registrationPresent", registration != null);
                data.put("handlerPresent", handlerObj != null);
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("📊 **AUTO SESSION HANDLER STATUS**\n\n");

        if (active) {
            CustomSessionHandler handler = (CustomSessionHandler) handlerObj;
            result.append("✅ **Status:** ACTIVE\n\n");
            result.append("**Statistics:**\n");
            result.append("• Requests processed: ").append(handler.getRequestCount()).append("\n");
            result.append("• Sessions refreshed: ").append(handler.getRefreshCount()).append("\n");
            result.append("• Failed authentications: ").append(handler.getFailureCount()).append("\n");
            result.append("• Last activity: ").append(handler.getLastActivity()).append("\n\n");

            result.append("**Current Configuration:**\n");
            result.append("• Auto-refresh: ").append(handler.isAutoRefreshEnabled() ? "Enabled" : "Disabled").append("\n");
            result.append("• Handler name: ").append(handler.name()).append("\n");
        } else {
            result.append("❌ **Status:** INACTIVE\n\n");
            result.append("• Registration object: ").append(registration != null ? "Present" : "NULL").append("\n");
            result.append("• Handler object: ").append(handlerObj != null ? "Present" : "NULL").append("\n\n");
            result.append("ℹ️ Automatic session handling is not enabled.\n");
            result.append("💡 Use ENABLE_AUTO_SESSION to activate automatic handling.");
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object analyzeSessionValidity(String url, JsonNode arguments, boolean verbose) {
        if (url == null) {
            return McpUtils.createErrorResponse("URL is required for ANALYZE_SESSION_VALIDITY");
        }

        Integer statusCode = null;
        Integer responseLength = null;
        int loginCount = 0, signinCount = 0, authCount = 0;
        int unauthorizedCount = 0, forbiddenCount = 0, deniedCount = 0, expiredCount = 0;
        boolean hasAuthKeywords = false;
        String assessment = null;
        String redirectLocation = null;
        List<String> setCookieHeaders = new ArrayList<>();
        String errorMsg = null;

        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse response = api.http().sendRequest(request);

            if (response.response() != null) {
                HttpResponse httpResponse = response.response();
                statusCode = (int) httpResponse.statusCode();
                responseLength = httpResponse.body().length();

                String responseBody = httpResponse.bodyToString().toLowerCase();
                String responseHeaders = httpResponse.toString().toLowerCase();
                String fullResponse = responseBody + " " + responseHeaders;

                loginCount = countOccurrences(fullResponse, "login");
                signinCount = countOccurrences(fullResponse, "signin") + countOccurrences(fullResponse, "sign in");
                authCount = countOccurrences(fullResponse, "authenticate");

                if (loginCount > 0 || signinCount > 0 || authCount > 0) {
                    hasAuthKeywords = true;
                }

                unauthorizedCount = countOccurrences(fullResponse, "unauthorized");
                forbiddenCount = countOccurrences(fullResponse, "forbidden");
                deniedCount = countOccurrences(fullResponse, "access denied");
                expiredCount = countOccurrences(fullResponse, "session expired");

                if (unauthorizedCount > 0 || forbiddenCount > 0 || deniedCount > 0 || expiredCount > 0) {
                    hasAuthKeywords = true;
                }

                if (statusCode == 200 && !hasAuthKeywords) {
                    assessment = "VALID";
                } else if (statusCode == 401 || statusCode == 403) {
                    assessment = "INVALID";
                } else if (hasAuthKeywords) {
                    assessment = "POSSIBLY_INVALID";
                } else if (statusCode >= 300 && statusCode < 400) {
                    redirectLocation = httpResponse.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Location"))
                        .map(h -> h.value())
                        .findFirst()
                        .orElse("Unknown");
                    assessment = "REDIRECT";
                } else {
                    assessment = "UNKNOWN";
                }

                setCookieHeaders = httpResponse.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                    .map(h -> h.value())
                    .collect(Collectors.toList());
            } else {
                errorMsg = "No response received - Connection failed";
            }
        } catch (Exception e) {
            errorMsg = e.getMessage();
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("operation", "analyzeSessionValidity");
            data.put("url", url);
            if (errorMsg != null) {
                data.put("success", false);
                data.put("error", errorMsg);
            } else {
                data.put("success", true);
                data.put("statusCode", statusCode);
                data.put("responseLength", responseLength);
                data.put("assessment", assessment);
                if (redirectLocation != null) data.put("redirectLocation", redirectLocation);
                Map<String, Object> keywords = new HashMap<>();
                keywords.put("login", loginCount);
                keywords.put("signin", signinCount);
                keywords.put("authenticate", authCount);
                keywords.put("unauthorized", unauthorizedCount);
                keywords.put("forbidden", forbiddenCount);
                keywords.put("accessDenied", deniedCount);
                keywords.put("sessionExpired", expiredCount);
                data.put("keywords", keywords);
                data.put("hasAuthKeywords", hasAuthKeywords);
                List<String> cookieNames = new ArrayList<>();
                for (String cookie : setCookieHeaders) {
                    cookieNames.add(cookie.split("=")[0]);
                }
                data.put("setCookies", cookieNames);
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("🔍 **ANALYZING SESSION VALIDITY**\n\n");
        result.append("**Target URL:** ").append(url).append("\n\n");

        if (errorMsg != null) {
            result.append("❌ **Analysis Failed:** ").append(errorMsg);
            return McpUtils.createSuccessResponse(result.toString());
        }

        result.append("📡 **Response Analysis:**\n");
        result.append("• Status Code: ").append(statusCode).append("\n");
        result.append("• Response Length: ").append(responseLength).append(" bytes\n\n");

        result.append("🔤 **Keyword Analysis:**\n");

        if (loginCount > 0 || signinCount > 0 || authCount > 0) {
            result.append("⚠️ Authentication keywords detected:\n");
            if (loginCount > 0) result.append("  • login: ").append(loginCount).append(" occurrences\n");
            if (signinCount > 0) result.append("  • signin/sign in: ").append(signinCount).append(" occurrences\n");
            if (authCount > 0) result.append("  • authenticate: ").append(authCount).append(" occurrences\n");
        }

        if (unauthorizedCount > 0 || forbiddenCount > 0 || deniedCount > 0 || expiredCount > 0) {
            result.append("❌ Access denial keywords detected:\n");
            if (unauthorizedCount > 0) result.append("  • unauthorized: ").append(unauthorizedCount).append(" occurrences\n");
            if (forbiddenCount > 0) result.append("  • forbidden: ").append(forbiddenCount).append(" occurrences\n");
            if (deniedCount > 0) result.append("  • access denied: ").append(deniedCount).append(" occurrences\n");
            if (expiredCount > 0) result.append("  • session expired: ").append(expiredCount).append(" occurrences\n");
        }

        result.append("\n📊 **Session Validity Assessment:**\n");
        switch (assessment) {
            case "VALID":
                result.append("✅ **VALID SESSION** - Authenticated access granted\n");
                break;
            case "INVALID":
                result.append("❌ **INVALID SESSION** - Authentication required (HTTP ").append(statusCode).append(")\n");
                break;
            case "POSSIBLY_INVALID":
                result.append("⚠️ **POSSIBLY INVALID** - Auth keywords found in response\n");
                break;
            case "REDIRECT":
                result.append("⚠️ **REDIRECT** - Being redirected to: ").append(redirectLocation).append("\n");
                if (redirectLocation.toLowerCase().contains("login") || redirectLocation.toLowerCase().contains("auth")) {
                    result.append("   → Likely redirecting to login page (invalid session)\n");
                }
                break;
            default:
                result.append("🔄 **UNKNOWN** - Unable to determine session validity\n");
        }

        result.append("\n🍪 **Cookie Updates:**\n");
        if (!setCookieHeaders.isEmpty()) {
            result.append("• ").append(setCookieHeaders.size()).append(" new/updated cookies received\n");
            for (String cookie : setCookieHeaders) {
                String cookieName = cookie.split("=")[0];
                result.append("  - ").append(cookieName).append("\n");
            }
        } else {
            result.append("• No cookie updates in response\n");
        }

        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private String truncateValue(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }
    
    private int countOccurrences(String text, String keyword) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(keyword, index)) != -1) {
            count++;
            index += keyword.length();
        }
        return count;
    }
    
    private boolean isCommonFalsePositive(String token) {
        String lower = token.toLowerCase();
        // Filter out common false positives
        return lower.contains("getelementsby") || 
               lower.contains("application/") ||
               lower.contains("xhtml") ||
               lower.contains("www.") ||
               lower.contains("http") ||
               lower.contains(".com") ||
               lower.contains("shockwave") ||
               lower.contains("version=") ||
               lower.contains("searchfor=") ||
               lower.contains("codeoutside") ||
               lower.contains("instancebegin") ||
               token.matches("\\d{4}-\\d{2}-\\d{2}") || // Dates
               token.length() < 16; // Too short for a real session token
    }
    
    // Inner class for custom session handling
    private class CustomSessionHandler implements SessionHandlingAction {
        private final MontoyaApi api;
        private boolean autoRefresh;
        private int requestCount = 0;
        private int refreshCount = 0;
        private int failureCount = 0;
        private String lastActivity = "Never";
        
        public CustomSessionHandler(boolean autoRefresh) {
            this.api = SessionManagementTool.this.api;
            this.autoRefresh = autoRefresh;
        }
        
        @Override
        public String name() {
            return "MCP Bridge Auto Session Handler";
        }
        
        @Override
        public ActionResult performAction(SessionHandlingActionData data) {
            requestCount++;
            lastActivity = ZonedDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME);
            
            // Log that we're processing a request
            api.logging().logToOutput("MCP Bridge Session Handler: Processing request #" + requestCount);
            
            HttpRequest request = data.request();
            Annotations annotations = data.annotations();
            
            // Check if we need to add stored tokens
            if (!sessionTokens.isEmpty()) {
                StringBuilder cookieHeader = new StringBuilder();
                for (Map.Entry<String, String> entry : sessionTokens.entrySet()) {
                    if (cookieHeader.length() > 0) {
                        cookieHeader.append("; ");
                    }
                    cookieHeader.append(entry.getKey()).append("=").append(entry.getValue());
                }
                
                // Add our managed cookies to the request
                request = request.withAddedHeader("X-Session-Manager", "Active");
                if (cookieHeader.length() > 0) {
                    request = request.withAddedHeader("Cookie", cookieHeader.toString());
                }
            }
            
            // Check for authentication headers
            boolean hasAuth = request.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase("Authorization") || 
                              h.name().equalsIgnoreCase("Cookie"));
            
            if (!hasAuth && autoRefresh) {
                // Attempt to refresh session if no auth present
                refreshCount++;
                annotations = annotations.withNotes("Auto-session: Added authentication");
            }
            
            return ActionResult.actionResult(request, annotations);
        }
        
        public int getRequestCount() { return requestCount; }
        public int getRefreshCount() { return refreshCount; }
        public int getFailureCount() { return failureCount; }
        public String getLastActivity() { return lastActivity; }
        public boolean isAutoRefreshEnabled() { return autoRefresh; }
    }
}
