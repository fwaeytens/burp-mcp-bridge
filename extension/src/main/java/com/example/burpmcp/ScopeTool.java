package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.scope.ScopeChangeHandler;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;
import java.net.URL;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class ScopeTool implements McpTool {
    private final MontoyaApi api;
    private static final Queue<String> recentScopeChanges = new ConcurrentLinkedQueue<>();
    private static final AtomicInteger scopeCheckCount = new AtomicInteger(0);
    private static Registration scopeChangeRegistration;
    private static final Set<String> knownInScopeUrls = Collections.synchronizedSet(new HashSet<>());
    private static final Set<String> knownOutOfScopeUrls = Collections.synchronizedSet(new HashSet<>());
    private static final List<String> SUPPORTED_ACTIONS = List.of(
        "view",
        "add",
        "remove",
        "check",
        "analyze",
        "bulk_add",
        "bulk_check"
    );

    public ScopeTool(MontoyaApi api) {
        this.api = api;
        
        // Register a scope change handler to track changes
        if (scopeChangeRegistration == null) {
            try {
                scopeChangeRegistration = api.scope().registerScopeChangeHandler(new ScopeChangeHandler() {
                    @Override
                    public void scopeChanged(burp.api.montoya.scope.ScopeChange scopeChange) {
                        String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                        String changeMessage = String.format("[%s] Scope configuration changed", timestamp);
                        recentScopeChanges.offer(changeMessage);
                        
                        // Keep only last 20 changes
                        while (recentScopeChanges.size() > 20) {
                            recentScopeChanges.poll();
                        }
                        
                        api.logging().logToOutput("Scope change detected at " + timestamp);
                    }
                });
                api.logging().logToOutput("Scope change handler registered successfully");
            } catch (Exception e) {
                api.logging().logToError("Failed to register scope change handler: " + e.getMessage());
            }
        }
    }

    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_scope");
        tool.put("title", "Target Scope");
        tool.put("description", "Manage Burp Suite target scope to control which URLs are included in testing. " +
                "Use this to add/remove URLs from scope, check if URLs are in scope, and analyze scope coverage against proxy history. " +
                "Actions: view (current scope with stats), add (include URL), remove (exclude URL), " +
                "check (verify URL status), analyze (scope coverage report), bulk_add/bulk_check.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", true);  // remove action modifies scope
        annotations.put("idempotentHint", false);  // add/remove changes state
        annotations.put("openWorldHint", false);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        inputSchema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProperty = new HashMap<>();
        actionProperty.put("type", "string");
        actionProperty.put("description", "Action to perform");
        actionProperty.put("enum", SUPPORTED_ACTIONS);
        properties.put("action", actionProperty);
        
        Map<String, Object> urlProperty = new HashMap<>();
        urlProperty.put("type", "string");
        urlProperty.put("description", "URL or hostname to add/remove/check. For 'add' action: Can be a full URL (https://example.com) or just a hostname (example.com) which will add all protocols and subdomains");
        properties.put("url", urlProperty);
        
        Map<String, Object> urlsProperty = new HashMap<>();
        urlsProperty.put("type", "array");
        urlsProperty.put("description", "Array of URLs for bulk operations");
        urlsProperty.put("items", Map.of("type", "string"));
        properties.put("urls", urlsProperty);
        
        Map<String, Object> includeSubdomainsProperty = new HashMap<>();
        includeSubdomainsProperty.put("type", "boolean");
        includeSubdomainsProperty.put("default", true);
        includeSubdomainsProperty.put("description", "Include all subdomains when adding to scope");
        properties.put("includeSubdomains", includeSubdomainsProperty);
        
        Map<String, Object> limitProperty = new HashMap<>();
        limitProperty.put("type", "number");
        limitProperty.put("default", 100);
        limitProperty.put("description", "Limit for analyze action");
        properties.put("limit", limitProperty);
        
        inputSchema.put("properties", properties);
        inputSchema.put("required", List.of("action"));
        inputSchema.put("allOf", List.of(
            Map.of(
                "if", Map.of("properties", Map.of("action", Map.of("const", "add"))),
                "then", Map.of("required", List.of("url"))
            ),
            Map.of(
                "if", Map.of("properties", Map.of("action", Map.of("const", "remove"))),
                "then", Map.of("required", List.of("url"))
            ),
            Map.of(
                "if", Map.of("properties", Map.of("action", Map.of("const", "check"))),
                "then", Map.of("required", List.of("url"))
            ),
            Map.of(
                "if", Map.of("properties", Map.of("action", Map.of("const", "bulk_add"))),
                "then", Map.of("required", List.of("urls"))
            ),
            Map.of(
                "if", Map.of("properties", Map.of("action", Map.of("const", "bulk_check"))),
                "then", Map.of("required", List.of("urls"))
            )
        ));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }

    @Override
    public Object execute(JsonNode arguments) throws Exception {
        McpUtils.ActionResolution actionResolution = McpUtils.resolveAction(arguments, SUPPORTED_ACTIONS);
        if (actionResolution.hasError()) {
            return createErrorResponse(actionResolution.getErrorMessage());
        }

        String action = actionResolution.getAction();
        String url = arguments.has("url") ? arguments.get("url").asText() : null;
        boolean includeSubdomains = arguments.has("includeSubdomains") ? 
            arguments.get("includeSubdomains").asBoolean() : true;
        int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 100;
        
        try {
            Scope scope = api.scope();
            StringBuilder result = new StringBuilder();
            
            switch (action.toLowerCase()) {
                case "view":
                    result.append("=== 🎯 Burp Suite Scope Status ===\n\n");
                    
                    // Show recent scope changes
                    result.append("📝 **Recent Scope Changes:**\n");
                    if (recentScopeChanges.isEmpty()) {
                        result.append("• No scope changes detected in this session\n");
                    } else {
                        for (String change : recentScopeChanges) {
                            result.append("• ").append(change).append("\n");
                        }
                    }
                    
                    result.append("\n📊 **Scope Statistics:**\n");
                    result.append("• Scope checks performed: ").append(scopeCheckCount.get()).append("\n");
                    result.append("• Known in-scope URLs: ").append(knownInScopeUrls.size()).append("\n");
                    result.append("• Known out-of-scope URLs: ").append(knownOutOfScopeUrls.size()).append("\n");
                    
                    // Sample some known in-scope URLs
                    if (!knownInScopeUrls.isEmpty()) {
                        result.append("\n✅ **Sample In-Scope URLs:**\n");
                        knownInScopeUrls.stream().limit(10).forEach(u -> 
                            result.append("• ").append(u).append("\n"));
                        if (knownInScopeUrls.size() > 10) {
                            result.append("• ... and ").append(knownInScopeUrls.size() - 10).append(" more\n");
                        }
                    }
                    
                    result.append("\n💡 **Available Actions:**\n");
                    result.append("• add <url> - Add URL to scope\n");
                    result.append("• remove <url> - Remove URL from scope\n");
                    result.append("• check <url> - Check if URL is in scope\n");
                    result.append("• analyze - Analyze proxy history for scope coverage\n");
                    result.append("• bulk_add - Add multiple URLs at once\n");
                    result.append("• bulk_check - Check multiple URLs at once\n");
                    break;
                    
                case "add":
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL or host is required for 'add' action");
                    }
                    
                    // Check if input is a wildcard, host, or full URL
                    String urlToAdd;
                    boolean isWildcard = url.startsWith("*.") || url.contains("*");
                    boolean isHost = !url.contains("://") && !url.startsWith("/") && !isWildcard;
                    
                    if (isWildcard) {
                        // Wildcard patterns not supported through API
                        result.append("❌ **Wildcard patterns not supported**\n\n");
                        result.append("The Montoya API doesn't support wildcard patterns like `").append(url).append("`.\n\n");
                        result.append("**Options:**\n");
                        result.append("• Use Burp's Target > Scope UI to add wildcards with 'Include subdomains' checked\n");
                        result.append("• Add specific subdomains as you discover them (e.g., `api.example.com`)\n");
                        result.append("• Add the base domain without wildcard (e.g., `example.com`)\n");
                        
                    } else if (isHost) {
                        // Input is just a hostname - add both HTTP and HTTPS versions
                        result.append("🌐 Adding host to scope: ").append(url).append("\n\n");
                        
                        boolean addedAny = false;
                        
                        // Add HTTPS version
                        try {
                            String httpsUrl = "https://" + url;
                            scope.includeInScope(httpsUrl);
                            result.append("✅ Added: ").append(httpsUrl).append("\n");
                            knownInScopeUrls.add(httpsUrl);
                            addedAny = true;
                        } catch (Exception e) {
                            result.append("❌ Failed to add HTTPS: ").append(e.getMessage()).append("\n");
                            api.logging().logToError("Failed to add HTTPS: " + e.getMessage());
                        }
                        
                        // Add HTTP version
                        try {
                            String httpUrl = "http://" + url;
                            scope.includeInScope(httpUrl);
                            result.append("✅ Added: ").append(httpUrl).append("\n");
                            knownInScopeUrls.add(httpUrl);
                            addedAny = true;
                        } catch (Exception e) {
                            result.append("❌ Failed to add HTTP: ").append(e.getMessage()).append("\n");
                            api.logging().logToError("Failed to add HTTP: " + e.getMessage());
                        }
                        
                        if (addedAny) {
                            result.append("\n📌 Host added to scope for both HTTP and HTTPS protocols.\n");
                        } else {
                            result.append("\n⚠️ Failed to add host to scope.\n");
                            result.append("💡 The host format might be invalid. Try using a full URL: https://").append(url).append("\n");
                        }
                        
                    } else {
                        // Input is a full URL
                        urlToAdd = normalizeUrl(url);
                        
                        if (includeSubdomains) {
                            try {
                                URL parsedUrl = new URL(urlToAdd);
                                String wildcardUrl = parsedUrl.getProtocol() + "://*." + 
                                    parsedUrl.getHost().replaceFirst("^www\\.", "") + 
                                    (parsedUrl.getPort() != -1 ? ":" + parsedUrl.getPort() : "") + "/*";
                                scope.includeInScope(wildcardUrl);
                                scope.includeInScope(urlToAdd);
                                result.append("✅ Added to scope with subdomains:\n");
                                result.append("  • ").append(urlToAdd).append("\n");
                                result.append("  • ").append(wildcardUrl).append("\n");
                            } catch (Exception e) {
                                // Fall back to simple inclusion
                                scope.includeInScope(urlToAdd);
                                result.append("✅ Added to scope: ").append(urlToAdd).append("\n");
                            }
                        } else {
                            scope.includeInScope(urlToAdd);
                            result.append("✅ Added to scope: ").append(urlToAdd).append("\n");
                        }
                        
                        knownInScopeUrls.add(urlToAdd);
                        knownOutOfScopeUrls.remove(urlToAdd);
                    }
                    
                    // Record the change
                    String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                    recentScopeChanges.offer(String.format("[%s] Added: %s", timestamp, url));
                    while (recentScopeChanges.size() > 20) {
                        recentScopeChanges.poll();
                    }
                    
                    result.append("\n📌 This host/URL and all its subdomains/subpaths are now included in the target scope.\n");
                    break;
                    
                case "remove":
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL is required for 'remove' action");
                    }
                    
                    String urlToRemove = normalizeUrl(url);
                    scope.excludeFromScope(urlToRemove);
                    result.append("❌ Removed from scope: ").append(urlToRemove).append("\n");
                    
                    knownInScopeUrls.remove(urlToRemove);
                    knownOutOfScopeUrls.add(urlToRemove);
                    
                    // Record the change
                    timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                    recentScopeChanges.offer(String.format("[%s] Removed: %s", timestamp, url));
                    while (recentScopeChanges.size() > 20) {
                        recentScopeChanges.poll();
                    }
                    
                    result.append("📌 This URL and its subpaths are now excluded from the target scope.\n");
                    break;
                    
                case "check":
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL is required for 'check' action");
                    }
                    
                    String urlToCheck = normalizeUrl(url);
                    boolean isInScope = scope.isInScope(urlToCheck);
                    scopeCheckCount.incrementAndGet();
                    
                    if (isInScope) {
                        knownInScopeUrls.add(urlToCheck);
                        knownOutOfScopeUrls.remove(urlToCheck);
                        result.append("✅ **IN SCOPE**: ").append(urlToCheck).append("\n");
                    } else {
                        knownOutOfScopeUrls.add(urlToCheck);
                        knownInScopeUrls.remove(urlToCheck);
                        result.append("❌ **NOT IN SCOPE**: ").append(urlToCheck).append("\n");
                    }
                    
                    // Check variations
                    result.append("\n🔍 **Checking variations:**\n");
                    String[] variations = generateUrlVariations(urlToCheck);
                    for (String variation : variations) {
                        try {
                            boolean varInScope = scope.isInScope(variation);
                            result.append("• ").append(variation).append(" - ");
                            result.append(varInScope ? "✅ In Scope" : "❌ Not in Scope").append("\n");
                            scopeCheckCount.incrementAndGet();
                        } catch (IllegalArgumentException e) {
                            // Skip wildcards and invalid URLs (Burp doesn't support wildcards in isInScope)
                            result.append("• ").append(variation).append(" - ⚠️ Skipped (wildcards not supported)\n");
                        }
                    }
                    break;
                    
                case "analyze":
                    result.append("=== 📊 Scope Coverage Analysis ===\n\n");
                    
                    // Analyze proxy history for scope coverage
                    List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                    int totalRequests = 0;
                    int inScopeRequests = 0;
                    Map<String, Integer> hostCounts = new HashMap<>();
                    Map<String, Boolean> hostScopeStatus = new HashMap<>();
                    
                    for (ProxyHttpRequestResponse item : proxyHistory) {
                        if (totalRequests >= limit) break;
                        
                        HttpRequest request = item.finalRequest();
                        String requestUrl = request.url();
                        String host = request.httpService().host();
                        
                        totalRequests++;
                        boolean isRequestInScope = scope.isInScope(requestUrl);
                        
                        if (isRequestInScope) {
                            inScopeRequests++;
                            knownInScopeUrls.add(requestUrl);
                        } else {
                            knownOutOfScopeUrls.add(requestUrl);
                        }
                        
                        hostCounts.merge(host, 1, Integer::sum);
                        hostScopeStatus.put(host, hostScopeStatus.getOrDefault(host, false) || isRequestInScope);
                    }
                    
                    result.append("📈 **Analysis Results:**\n");
                    result.append("• Total requests analyzed: ").append(totalRequests).append("\n");
                    result.append("• In-scope requests: ").append(inScopeRequests)
                        .append(" (").append(String.format("%.1f%%", (inScopeRequests * 100.0 / totalRequests)))
                        .append(")\n");
                    result.append("• Out-of-scope requests: ").append(totalRequests - inScopeRequests)
                        .append(" (").append(String.format("%.1f%%", ((totalRequests - inScopeRequests) * 100.0 / totalRequests)))
                        .append(")\n\n");
                    
                    result.append("🌐 **Host Distribution:**\n");
                    hostCounts.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(10)
                        .forEach(entry -> {
                            String host = entry.getKey();
                            int count = entry.getValue();
                            boolean isHostInScope = hostScopeStatus.get(host);
                            result.append("• ").append(host)
                                .append(" - ").append(count).append(" requests ")
                                .append(isHostInScope ? "✅" : "❌").append("\n");
                        });
                    
                    result.append("\n💡 **Recommendations:**\n");
                    if (inScopeRequests == 0) {
                        result.append("• No in-scope requests found. Consider adding target URLs to scope.\n");
                    } else if (inScopeRequests < totalRequests / 2) {
                        result.append("• Most traffic is out of scope. Consider refining your scope configuration.\n");
                    } else {
                        result.append("• Good scope coverage! Most traffic is within target scope.\n");
                    }
                    break;
                    
                case "bulk_add":
                    if (!arguments.has("urls")) {
                        return createErrorResponse("'urls' array is required for bulk_add action");
                    }
                    
                    result.append("=== 📦 Bulk Add to Scope ===\n\n");
                    JsonNode urlsNode = arguments.get("urls");
                    int addedCount = 0;
                    int failedCount = 0;
                    
                    for (JsonNode urlNode : urlsNode) {
                        String bulkUrl = urlNode.asText();
                        try {
                            String normalizedUrl = normalizeUrl(bulkUrl);
                            scope.includeInScope(normalizedUrl);
                            knownInScopeUrls.add(normalizedUrl);
                            result.append("✅ Added: ").append(bulkUrl).append("\n");
                            addedCount++;
                        } catch (Exception e) {
                            result.append("❌ Failed: ").append(bulkUrl)
                                .append(" - ").append(e.getMessage()).append("\n");
                            failedCount++;
                        }
                    }
                    
                    result.append("\n📊 **Summary:**\n");
                    result.append("• Successfully added: ").append(addedCount).append("\n");
                    result.append("• Failed: ").append(failedCount).append("\n");
                    break;
                    
                case "bulk_check":
                    if (!arguments.has("urls")) {
                        return createErrorResponse("'urls' array is required for bulk_check action");
                    }
                    
                    result.append("=== 🔍 Bulk Scope Check ===\n\n");
                    urlsNode = arguments.get("urls");
                    int inScope = 0;
                    int outScope = 0;
                    
                    for (JsonNode urlNode : urlsNode) {
                        String checkUrl = urlNode.asText();
                        try {
                            String normalizedUrl = normalizeUrl(checkUrl);
                            boolean isIn = scope.isInScope(normalizedUrl);
                            scopeCheckCount.incrementAndGet();
                            
                            if (isIn) {
                                result.append("✅ IN SCOPE: ").append(checkUrl).append("\n");
                                knownInScopeUrls.add(normalizedUrl);
                                inScope++;
                            } else {
                                result.append("❌ NOT IN SCOPE: ").append(checkUrl).append("\n");
                                knownOutOfScopeUrls.add(normalizedUrl);
                                outScope++;
                            }
                        } catch (Exception e) {
                            result.append("⚠️ ERROR checking: ").append(checkUrl)
                                .append(" - ").append(e.getMessage()).append("\n");
                        }
                    }
                    
                    result.append("\n📊 **Summary:**\n");
                    result.append("• In scope: ").append(inScope).append("\n");
                    result.append("• Out of scope: ").append(outScope).append("\n");
                    result.append("• Total checked: ").append(inScope + outScope).append("\n");
                    break;
                    
                default:
                    return createErrorResponse("Unknown action '" + action + 
                        "'. Valid actions are: view, add, remove, check, analyze, bulk_add, bulk_check");
            }
            
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("type", "text");
            resultMap.put("text", result.toString());
            
            return List.of(resultMap);
            
        } catch (Exception e) {
            api.logging().logToError("Error managing scope: " + e.getMessage());
            e.printStackTrace();
            return createErrorResponse("Error managing scope: " + e.getMessage());
        }
    }
    
    private String normalizeUrl(String url) {
        // Ensure URL has a protocol
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        // Validate URL format
        try {
            URL urlObj = new URL(url);
            // Burp's isInScope() requires URLs to have at least a path component
            // If no path is specified, add a trailing slash
            if (urlObj.getPath() == null || urlObj.getPath().isEmpty()) {
                url = url + "/";
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL format: " + url);
        }

        return url;
    }
    
    private String[] generateUrlVariations(String url) {
        List<String> variations = new ArrayList<>();
        
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            String host = parsedUrl.getHost();
            int port = parsedUrl.getPort();
            String path = parsedUrl.getPath();
            
            // HTTP/HTTPS variation
            String altProtocol = protocol.equals("https") ? "http" : "https";
            variations.add(altProtocol + "://" + host + (port != -1 ? ":" + port : "") + path);
            
            // With/without www
            if (host.startsWith("www.")) {
                variations.add(protocol + "://" + host.substring(4) + (port != -1 ? ":" + port : "") + path);
            } else {
                variations.add(protocol + "://www." + host + (port != -1 ? ":" + port : "") + path);
            }
            
            // Root path
            if (!path.isEmpty() && !path.equals("/")) {
                variations.add(protocol + "://" + host + (port != -1 ? ":" + port : "") + "/");
            }
            
            // Wildcard subdomain
            variations.add(protocol + "://*." + host.replaceFirst("^www\\.", "") + "/*");
            
        } catch (Exception e) {
            // Return empty array if URL parsing fails
        }
        
        return variations.toArray(new String[0]);
    }
    
    private Object createErrorResponse(String message) {
        Map<String, Object> errorResult = new HashMap<>();
        errorResult.put("type", "text");
        errorResult.put("text", "❌ Error: " + message);
        return List.of(errorResult);
    }
}
