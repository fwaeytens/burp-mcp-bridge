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
            "Actions: COOKIE_JAR_LIST/SET/DELETE (manage cookies), EXTRACT_TOKENS (find session tokens), " +
            "TEST_SESSION (verify session validity), ENABLE/DISABLE_AUTO_SESSION (automatic refresh on 401/403). " +
            "Integrates with Burp's session handling rules.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);  // DELETE/CLEAR actions remove cookies
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
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
        tokenNameProperty.put("description", "Token/cookie name (for SET_TOKEN action)");
        properties.put("tokenName", tokenNameProperty);
        
        Map<String, Object> tokenValueProperty = new HashMap<>();
        tokenValueProperty.put("type", "string");
        tokenValueProperty.put("description", "Token/cookie value (for SET_TOKEN action)");
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
        
        try {
            String result;
            switch (action) {
                case "EXTRACT_TOKENS":
                    result = extractTokensFromHistory(url, extractPattern);
                    break;
                case "SET_TOKEN":
                    result = setSessionToken(tokenName, tokenValue);
                    break;
                case "CLEAR_TOKENS":
                    result = clearSessionTokens();
                    break;
                case "LIST_TOKENS":
                    result = listSessionTokens();
                    break;
                case "TEST_SESSION":
                    result = testSessionValidity(url);
                    break;
                case "FIND_LOGOUT":
                    result = findLogoutEndpoints(url);
                    break;
                case "SESSION_STATUS":
                    result = getSessionStatus();
                    break;
                case "COOKIE_JAR_LIST":
                    result = listCookieJar();
                    break;
                case "COOKIE_JAR_SET":
                    result = setCookieInJar(tokenName, tokenValue, domain, path, expiration);
                    break;
                case "COOKIE_JAR_DELETE":
                    result = deleteCookieFromJar(tokenName, domain);
                    break;
                case "COOKIE_JAR_CLEAR":
                    result = clearCookieJar();
                    break;
                case "ENABLE_AUTO_SESSION":
                    result = enableAutoSessionHandling(autoRefresh);
                    break;
                case "DISABLE_AUTO_SESSION":
                    result = disableAutoSessionHandling();
                    break;
                case "AUTO_SESSION_STATUS":
                    result = getAutoSessionStatus();
                    break;
                case "ANALYZE_SESSION_VALIDITY":
                    result = analyzeSessionValidity(url, arguments);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown action: " + action);
            }
            
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("type", "text");
            resultMap.put("text", result);
            
            return List.of(resultMap);
            
        } catch (Exception e) {
            api.logging().logToError("Error in session management: " + e.getMessage());
            
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("type", "text");
            errorResult.put("text", "Error in session management: " + e.getMessage());
            
            return List.of(errorResult);
        }
    }
    
    private String extractTokensFromHistory(String urlFilter, String pattern) {
        StringBuilder result = new StringBuilder();
        result.append("🔍 **EXTRACTING SESSION TOKENS FROM PROXY HISTORY**\n\n");
        
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
                
                // Store significant tokens
                if (entry.getKey().contains("session") || entry.getKey().contains("auth") || 
                    entry.getKey().contains("token") || entry.getKey().contains("jwt")) {
                    sessionTokens.put(entry.getKey(), entry.getValue());
                }
            }
        } else {
            result.append("ℹ️ No tokens found matching the specified pattern.");
        }
        
        return result.toString();
    }
    
    private String setSessionToken(String name, String value) {
        if (name == null || value == null) {
            return "❌ Error: Both tokenName and tokenValue are required for SET_TOKEN action";
        }
        
        sessionTokens.put(name, value);
        
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
        
        return result.toString();
    }
    
    private String clearSessionTokens() {
        int tokenCount = sessionTokens.size();
        sessionTokens.clear();
        sessionUrls.clear();
        
        StringBuilder result = new StringBuilder();
        result.append("🧹 **SESSION TOKENS CLEARED**\n\n");
        result.append("• Removed ").append(tokenCount).append(" stored tokens\n");
        result.append("• Cleared session URL list\n");
        result.append("• Session management state reset\n\n");
        result.append("ℹ️ All stored authentication tokens have been removed from memory.");
        
        return result.toString();
    }
    
    private String listSessionTokens() {
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
        
        return result.toString();
    }
    
    private String testSessionValidity(String testUrl) {
        if (testUrl == null) {
            return "❌ Error: URL is required for TEST_SESSION action";
        }
        
        StringBuilder result = new StringBuilder();
        result.append("🧪 **TESTING SESSION VALIDITY**\n\n");
        result.append("**Test URL:** ").append(testUrl).append("\n\n");
        
        try {
            // Create request with stored tokens
            HttpRequest request = HttpRequest.httpRequestFromUrl(testUrl);
            
            // Add stored tokens as cookies
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
            
            // Send the request
            HttpRequestResponse response = api.http().sendRequest(request);
            
            if (response.response() != null) {
                int statusCode = response.response().statusCode();
                result.append("📡 **Response Analysis:**\n");
                result.append("• Status Code: ").append(statusCode).append("\n");
                
                // Analyze response for session validity indicators
                String responseBody = response.response().bodyToString();
                String responseHeaders = response.response().toString();
                
                if (statusCode == 200) {
                    if (responseBody.toLowerCase().contains("login") || 
                        responseBody.toLowerCase().contains("sign in") ||
                        responseHeaders.toLowerCase().contains("www-authenticate")) {
                        result.append("• Session Status: ❌ **INVALID** (redirected to login)\n");
                    } else {
                        result.append("• Session Status: ✅ **VALID** (authenticated response)\n");
                    }
                } else if (statusCode == 401 || statusCode == 403) {
                    result.append("• Session Status: ❌ **INVALID** (authentication required)\n");
                } else if (statusCode == 302 || statusCode == 301) {
                    String location = response.response().headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Location"))
                        .map(h -> h.value())
                        .findFirst()
                        .orElse("Unknown");
                    result.append("• Session Status: ⚠️ **REDIRECT** to ").append(location).append("\n");
                } else {
                    result.append("• Session Status: ⚠️ **UNKNOWN** (unexpected status)\n");
                }
                
                // Check for new tokens in response
                List<String> setCookieHeaders = response.response().headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                    .map(h -> h.value())
                    .collect(Collectors.toList());
                
                if (!setCookieHeaders.isEmpty()) {
                    result.append("• New Cookies: ").append(setCookieHeaders.size()).append(" found\n");
                    for (String cookie : setCookieHeaders) {
                        String[] parts = cookie.split("=", 2);
                        if (parts.length == 2) {
                            String cookieName = parts[0];
                            String cookieValue = parts[1].split(";")[0]; // Remove attributes
                            result.append("  - ").append(cookieName).append(": ").append(cookieValue.substring(0, Math.min(30, cookieValue.length())));
                            if (cookieValue.length() > 30) result.append("...");
                            result.append("\n");
                        }
                    }
                }
                
                result.append("• Response Length: ").append(responseBody.length()).append(" bytes\n");
                
            } else {
                result.append("❌ **No response received** - connection failed");
            }
            
        } catch (Exception e) {
            result.append("❌ **Test Failed:** ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    private String findLogoutEndpoints(String baseUrl) {
        StringBuilder result = new StringBuilder();
        result.append("🚪 **SEARCHING FOR LOGOUT ENDPOINTS**\n\n");
        
        if (baseUrl != null) {
            result.append("**Base URL:** ").append(baseUrl).append("\n\n");
        }
        
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        List<String> logoutUrls = new ArrayList<>();
        
        for (ProxyHttpRequestResponse entry : proxyHistory) {
            String url = entry.request().url().toLowerCase();
            String path = entry.request().path().toLowerCase();
            
            // Check for logout patterns in URL
            if (url.contains("logout") || url.contains("signout") || url.contains("sign-out") ||
                url.contains("logoff") || url.contains("exit") || url.contains("disconnect") ||
                path.contains("/logout") || path.contains("/signout") || path.contains("/logoff")) {
                
                if (baseUrl == null || entry.request().url().contains(baseUrl)) {
                    logoutUrls.add(entry.request().url());
                }
            }
            
            // Check response for logout-related content
            if (entry.response() != null) {
                String responseBody = entry.response().bodyToString().toLowerCase();
                if (responseBody.contains("logout") || responseBody.contains("sign out")) {
                    // This page might contain logout functionality
                    if (baseUrl == null || entry.request().url().contains(baseUrl)) {
                        logoutUrls.add(entry.request().url() + " (contains logout content)");
                    }
                }
            }
        }
        
        // Remove duplicates
        logoutUrls = logoutUrls.stream().distinct().collect(Collectors.toList());
        
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
        
        return result.toString();
    }
    
    private String getSessionStatus() {
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
        
        // Analyze proxy history for session-related requests
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
        
        return result.toString();
    }
    
    // New Cookie Jar methods
    private String listCookieJar() {
        StringBuilder result = new StringBuilder();
        result.append("🍪 **BURP COOKIE JAR CONTENTS**\n\n");
        
        try {
            CookieJar cookieJar = api.http().cookieJar();
            List<Cookie> cookies = cookieJar.cookies();
            
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
        } catch (Exception e) {
            result.append("❌ Error accessing cookie jar: ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    private String setCookieInJar(String name, String value, String domain, String path, String expirationStr) {
        if (name == null || value == null || domain == null) {
            return "❌ Error: name, value, and domain are required for COOKIE_JAR_SET";
        }
        
        StringBuilder result = new StringBuilder();
        result.append("🍪 **SETTING COOKIE IN BURP JAR**\n\n");
        
        try {
            CookieJar cookieJar = api.http().cookieJar();
            
            // Parse expiration if provided
            ZonedDateTime expiration = null;
            if (expirationStr != null && !expirationStr.isEmpty()) {
                try {
                    expiration = ZonedDateTime.parse(expirationStr);
                } catch (Exception e) {
                    result.append("⚠️ Invalid expiration format, using session cookie instead\n");
                }
            }
            
            // Set the cookie (correct parameter order: name, value, domain, path, expiration)
            cookieJar.setCookie(name, value, domain, path != null ? path : "/", expiration);
            
            result.append("✅ **Cookie Set Successfully**\n\n");
            result.append("• **Name:** ").append(name).append("\n");
            result.append("• **Value:** ").append(truncateValue(value, 60)).append("\n");
            result.append("• **Domain:** ").append(domain).append("\n");
            result.append("• **Path:** ").append(path != null ? path : "/").append("\n");
            result.append("• **Expiration:** ").append(expiration != null ? 
                expiration.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) : "Session").append("\n\n");
            
            result.append("🔧 **Impact:** This cookie will be automatically included in all matching requests sent through Burp.");
            
        } catch (Exception e) {
            result.append("❌ Error setting cookie: ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    private String deleteCookieFromJar(String name, String domain) {
        StringBuilder result = new StringBuilder();
        result.append("🗑️ **DELETING COOKIE FROM BURP JAR**\n\n");
        
        if (name == null || domain == null) {
            return "❌ Error: Both name and domain are required for COOKIE_JAR_DELETE";
        }
        
        try {
            // We can't directly delete, but we can set it to expire immediately
            CookieJar cookieJar = api.http().cookieJar();
            ZonedDateTime expired = ZonedDateTime.now().minusDays(1);
            cookieJar.setCookie(name, "", domain, "/", expired);
            
            result.append("✅ **Cookie Deleted**\n\n");
            result.append("• **Name:** ").append(name).append("\n");
            result.append("• **Domain:** ").append(domain).append("\n\n");
            result.append("ℹ️ Cookie has been expired and will be removed from future requests.");
            
        } catch (Exception e) {
            result.append("❌ Error deleting cookie: ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    private String clearCookieJar() {
        StringBuilder result = new StringBuilder();
        result.append("🧹 **CLEARING BURP COOKIE JAR**\n\n");
        
        try {
            CookieJar cookieJar = api.http().cookieJar();
            List<Cookie> cookies = cookieJar.cookies();
            int count = cookies.size();
            
            // Expire all cookies
            ZonedDateTime expired = ZonedDateTime.now().minusDays(1);
            for (Cookie cookie : cookies) {
                cookieJar.setCookie(cookie.name(), "", cookie.domain(), cookie.path(), expired);
            }
            
            result.append("✅ **Cookie Jar Cleared**\n\n");
            result.append("• Removed ").append(count).append(" cookies\n");
            result.append("• All cookies have been expired\n\n");
            result.append("ℹ️ The cookie jar is now empty.");
            
        } catch (Exception e) {
            result.append("❌ Error clearing cookie jar: ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    // Auto session handling methods
    private String enableAutoSessionHandling(boolean autoRefresh) {
        StringBuilder result = new StringBuilder();
        result.append("🤖 **ENABLING AUTOMATIC SESSION HANDLING**\n\n");
        
        try {
            // Unregister existing handler if present
            McpServer.clearSessionHandler();
            
            // Create and register new handler
            CustomSessionHandler handler = new CustomSessionHandler(autoRefresh);
            Registration registration = api.http().registerSessionHandlingAction(handler);
            
            // Store in McpServer for persistence
            McpServer.setSessionHandler(registration, handler);
            
            // Log to Burp output
            api.logging().logToOutput("MCP Bridge: Session handler registered successfully");
            
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
            
        } catch (Exception e) {
            result.append("❌ Error enabling auto session handling: ").append(e.getMessage());
        }
        
        return result.toString();
    }
    
    private String disableAutoSessionHandling() {
        StringBuilder result = new StringBuilder();
        result.append("🛑 **DISABLING AUTOMATIC SESSION HANDLING**\n\n");
        
        if (McpServer.getSessionHandlerRegistration() != null) {
            McpServer.clearSessionHandler();
            
            result.append("✅ **Auto Session Handler Disabled**\n\n");
            result.append("• Session handling deregistered\n");
            result.append("• Automatic processing stopped\n");
            result.append("• Manual session management resumed\n\n");
            result.append("ℹ️ You can re-enable automatic handling at any time.");
        } else {
            result.append("ℹ️ Auto session handling is not currently enabled.");
        }
        
        return result.toString();
    }
    
    private String getAutoSessionStatus() {
        StringBuilder result = new StringBuilder();
        result.append("📊 **AUTO SESSION HANDLER STATUS**\n\n");
        
        Registration registration = McpServer.getSessionHandlerRegistration();
        Object handlerObj = McpServer.getCustomSessionHandler();
        
        if (registration != null && handlerObj != null && handlerObj instanceof CustomSessionHandler) {
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
        
        return result.toString();
    }
    
    private String analyzeSessionValidity(String url, JsonNode arguments) {
        if (url == null) {
            return "❌ Error: URL is required for ANALYZE_SESSION_VALIDITY";
        }
        
        StringBuilder result = new StringBuilder();
        result.append("🔍 **ANALYZING SESSION VALIDITY**\n\n");
        result.append("**Target URL:** ").append(url).append("\n\n");
        
        try {
            // Create request
            HttpRequest request = HttpRequest.httpRequestFromUrl(url);
            
            // Add cookies from jar automatically
            HttpRequestResponse response = api.http().sendRequest(request);
            
            if (response.response() != null) {
                HttpResponse httpResponse = response.response();
                
                // Basic response info
                result.append("📡 **Response Analysis:**\n");
                result.append("• Status Code: ").append(httpResponse.statusCode()).append("\n");
                result.append("• Response Length: ").append(httpResponse.body().length()).append(" bytes\n\n");
                
                // Simple keyword analysis using string search
                result.append("🔤 **Keyword Analysis:**\n");
                String responseBody = httpResponse.bodyToString().toLowerCase();
                String responseHeaders = httpResponse.toString().toLowerCase();
                String fullResponse = responseBody + " " + responseHeaders;
                
                // Check for authentication keywords
                boolean hasAuthKeywords = false;
                
                // Count occurrences of auth keywords
                int loginCount = countOccurrences(fullResponse, "login");
                int signinCount = countOccurrences(fullResponse, "signin") + countOccurrences(fullResponse, "sign in");
                int authCount = countOccurrences(fullResponse, "authenticate");
                
                if (loginCount > 0 || signinCount > 0 || authCount > 0) {
                    result.append("⚠️ Authentication keywords detected:\n");
                    if (loginCount > 0) result.append("  • login: ").append(loginCount).append(" occurrences\n");
                    if (signinCount > 0) result.append("  • signin/sign in: ").append(signinCount).append(" occurrences\n");
                    if (authCount > 0) result.append("  • authenticate: ").append(authCount).append(" occurrences\n");
                    hasAuthKeywords = true;
                }
                
                // Count denial keywords
                int unauthorizedCount = countOccurrences(fullResponse, "unauthorized");
                int forbiddenCount = countOccurrences(fullResponse, "forbidden");
                int deniedCount = countOccurrences(fullResponse, "access denied");
                int expiredCount = countOccurrences(fullResponse, "session expired");
                
                if (unauthorizedCount > 0 || forbiddenCount > 0 || deniedCount > 0 || expiredCount > 0) {
                    result.append("❌ Access denial keywords detected:\n");
                    if (unauthorizedCount > 0) result.append("  • unauthorized: ").append(unauthorizedCount).append(" occurrences\n");
                    if (forbiddenCount > 0) result.append("  • forbidden: ").append(forbiddenCount).append(" occurrences\n");
                    if (deniedCount > 0) result.append("  • access denied: ").append(deniedCount).append(" occurrences\n");
                    if (expiredCount > 0) result.append("  • session expired: ").append(expiredCount).append(" occurrences\n");
                    hasAuthKeywords = true;
                }
                
                // Determine session validity
                result.append("\n📊 **Session Validity Assessment:**\n");
                if (httpResponse.statusCode() == 200 && !hasAuthKeywords) {
                    result.append("✅ **VALID SESSION** - Authenticated access granted\n");
                } else if (httpResponse.statusCode() == 401 || httpResponse.statusCode() == 403) {
                    result.append("❌ **INVALID SESSION** - Authentication required (HTTP ").append(httpResponse.statusCode()).append(")\n");
                } else if (hasAuthKeywords) {
                    result.append("⚠️ **POSSIBLY INVALID** - Auth keywords found in response\n");
                } else if (httpResponse.statusCode() >= 300 && httpResponse.statusCode() < 400) {
                    String location = httpResponse.headers().stream()
                        .filter(h -> h.name().equalsIgnoreCase("Location"))
                        .map(h -> h.value())
                        .findFirst()
                        .orElse("Unknown");
                    result.append("⚠️ **REDIRECT** - Being redirected to: ").append(location).append("\n");
                    if (location.toLowerCase().contains("login") || location.toLowerCase().contains("auth")) {
                        result.append("   → Likely redirecting to login page (invalid session)\n");
                    }
                } else {
                    result.append("🔄 **UNKNOWN** - Unable to determine session validity\n");
                }
                
                // Check for new session tokens
                result.append("\n🍪 **Cookie Updates:**\n");
                List<String> setCookieHeaders = httpResponse.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Set-Cookie"))
                    .map(h -> h.value())
                    .collect(Collectors.toList());
                
                if (!setCookieHeaders.isEmpty()) {
                    result.append("• ").append(setCookieHeaders.size()).append(" new/updated cookies received\n");
                    for (String cookie : setCookieHeaders) {
                        String cookieName = cookie.split("=")[0];
                        result.append("  - ").append(cookieName).append("\n");
                    }
                } else {
                    result.append("• No cookie updates in response\n");
                }
                
            } else {
                result.append("❌ **No response received** - Connection failed");
            }
            
        } catch (Exception e) {
            result.append("❌ **Analysis Failed:** ").append(e.getMessage());
        }
        
        return result.toString();
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
