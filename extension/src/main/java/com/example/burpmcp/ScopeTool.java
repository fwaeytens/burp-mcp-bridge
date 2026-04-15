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
        annotations.put("title", "Target Scope");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "target scope include exclude URL");
        tool.put("_meta", meta);

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
        urlsProperty.put("description", "URL array for bulk_add and bulk_check actions only.");
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

        Map<String, Object> verboseProperty = new HashMap<>();
        verboseProperty.put("type", "boolean");
        verboseProperty.put("default", false);
        verboseProperty.put("description", "Return decorated markdown (for human debugging). Default returns compact JSON.");
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
                    if (!McpUtils.isVerbose(arguments)) {
                        // Compact JSON
                        Map<String, Object> data = new HashMap<>();
                        data.put("recentChanges", new ArrayList<>(recentScopeChanges));
                        data.put("scopeChecksPerformed", scopeCheckCount.get());
                        data.put("knownInScopeCount", knownInScopeUrls.size());
                        data.put("knownOutOfScopeCount", knownOutOfScopeUrls.size());
                        data.put("inScopeUrls", knownInScopeUrls.stream().limit(10).collect(java.util.stream.Collectors.toList()));
                        return McpUtils.createJsonResponse(data);
                    }

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
                    
                case "add": {
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL or host is required for 'add' action");
                    }

                    boolean isWildcard = url.startsWith("*.") || url.contains("*");
                    boolean isHost = !url.contains("://") && !url.startsWith("/") && !isWildcard;
                    List<String> addedUrls = new ArrayList<>();
                    List<String> failedUrls = new ArrayList<>();

                    if (isWildcard) {
                        // Compact JSON
                        if (!McpUtils.isVerbose(arguments)) {
                            Map<String, Object> data = new HashMap<>();
                            data.put("action", "add");
                            data.put("success", false);
                            data.put("url", url);
                            data.put("error", "wildcard_not_supported");
                            data.put("message", "Montoya API doesn't support wildcard patterns. Use Burp UI for 'Include subdomains'.");
                            return McpUtils.createJsonResponse(data);
                        }
                        result.append("❌ **Wildcard patterns not supported**\n\n");
                        result.append("The Montoya API doesn't support wildcard patterns like `").append(url).append("`.\n\n");
                        result.append("**Options:**\n");
                        result.append("• Use Burp's Target > Scope UI to add wildcards with 'Include subdomains' checked\n");
                        result.append("• Add specific subdomains as you discover them (e.g., `api.example.com`)\n");
                        result.append("• Add the base domain without wildcard (e.g., `example.com`)\n");

                    } else if (isHost) {
                        for (String scheme : new String[]{"https://", "http://"}) {
                            String full = scheme + url;
                            try {
                                scope.includeInScope(full);
                                addedUrls.add(full);
                                knownInScopeUrls.add(full);
                            } catch (Exception e) {
                                failedUrls.add(full);
                                api.logging().logToError("Failed to add " + scheme + ": " + e.getMessage());
                            }
                        }
                        if (McpUtils.isVerbose(arguments)) {
                            result.append("🌐 Adding host to scope: ").append(url).append("\n\n");
                            for (String u : addedUrls) result.append("✅ Added: ").append(u).append("\n");
                            for (String u : failedUrls) result.append("❌ Failed to add: ").append(u).append("\n");
                            if (!addedUrls.isEmpty()) {
                                result.append("\n📌 Host added to scope for both HTTP and HTTPS protocols.\n");
                            } else {
                                result.append("\n⚠️ Failed to add host to scope.\n");
                            }
                        }

                    } else {
                        String urlToAdd = normalizeUrl(url);
                        if (includeSubdomains) {
                            try {
                                URL parsedUrl = new URL(urlToAdd);
                                String wildcardUrl = parsedUrl.getProtocol() + "://*." +
                                    parsedUrl.getHost().replaceFirst("^www\\.", "") +
                                    (parsedUrl.getPort() != -1 ? ":" + parsedUrl.getPort() : "") + "/*";
                                scope.includeInScope(wildcardUrl);
                                scope.includeInScope(urlToAdd);
                                addedUrls.add(urlToAdd);
                                addedUrls.add(wildcardUrl);
                            } catch (Exception e) {
                                scope.includeInScope(urlToAdd);
                                addedUrls.add(urlToAdd);
                            }
                        } else {
                            scope.includeInScope(urlToAdd);
                            addedUrls.add(urlToAdd);
                        }
                        knownInScopeUrls.add(urlToAdd);
                        knownOutOfScopeUrls.remove(urlToAdd);

                        if (McpUtils.isVerbose(arguments)) {
                            if (addedUrls.size() > 1) {
                                result.append("✅ Added to scope with subdomains:\n");
                                for (String u : addedUrls) result.append("  • ").append(u).append("\n");
                            } else {
                                result.append("✅ Added to scope: ").append(addedUrls.get(0)).append("\n");
                            }
                        }
                    }

                    // Record the change
                    String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                    recentScopeChanges.offer(String.format("[%s] Added: %s", timestamp, url));
                    while (recentScopeChanges.size() > 20) {
                        recentScopeChanges.poll();
                    }

                    // Compact JSON
                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "add");
                        data.put("success", !addedUrls.isEmpty());
                        data.put("addedUrls", addedUrls);
                        if (!failedUrls.isEmpty()) data.put("failedUrls", failedUrls);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append("\n📌 This host/URL and all its subdomains/subpaths are now included in the target scope.\n");
                    break;
                }
                    
                case "remove": {
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL is required for 'remove' action");
                    }

                    String urlToRemove = normalizeUrl(url);
                    scope.excludeFromScope(urlToRemove);
                    knownInScopeUrls.remove(urlToRemove);
                    knownOutOfScopeUrls.add(urlToRemove);

                    String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                    recentScopeChanges.offer(String.format("[%s] Removed: %s", timestamp, url));
                    while (recentScopeChanges.size() > 20) {
                        recentScopeChanges.poll();
                    }

                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "remove");
                        data.put("success", true);
                        data.put("url", urlToRemove);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append("❌ Removed from scope: ").append(urlToRemove).append("\n");
                    result.append("📌 This URL and its subpaths are now excluded from the target scope.\n");
                    break;
                }
                    
                case "check": {
                    if (url == null || url.trim().isEmpty()) {
                        return createErrorResponse("URL is required for 'check' action");
                    }

                    String urlToCheck = normalizeUrl(url);
                    boolean isInScope = scope.isInScope(urlToCheck);
                    scopeCheckCount.incrementAndGet();

                    if (isInScope) {
                        knownInScopeUrls.add(urlToCheck);
                        knownOutOfScopeUrls.remove(urlToCheck);
                    } else {
                        knownOutOfScopeUrls.add(urlToCheck);
                        knownInScopeUrls.remove(urlToCheck);
                    }

                    // Check variations
                    String[] variations = generateUrlVariations(urlToCheck);
                    List<Map<String, Object>> variationResults = new ArrayList<>();
                    for (String variation : variations) {
                        Map<String, Object> v = new HashMap<>();
                        v.put("url", variation);
                        try {
                            v.put("inScope", scope.isInScope(variation));
                            scopeCheckCount.incrementAndGet();
                        } catch (IllegalArgumentException e) {
                            v.put("skipped", "wildcards_not_supported");
                        }
                        variationResults.add(v);
                    }

                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "check");
                        data.put("url", urlToCheck);
                        data.put("inScope", isInScope);
                        data.put("variations", variationResults);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append(isInScope ? "✅ **IN SCOPE**: " : "❌ **NOT IN SCOPE**: ").append(urlToCheck).append("\n");
                    result.append("\n🔍 **Checking variations:**\n");
                    for (Map<String, Object> v : variationResults) {
                        result.append("• ").append(v.get("url")).append(" - ");
                        if (v.containsKey("skipped")) {
                            result.append("⚠️ Skipped (wildcards not supported)\n");
                        } else {
                            result.append((Boolean) v.get("inScope") ? "✅ In Scope" : "❌ Not in Scope").append("\n");
                        }
                    }
                    break;
                }
                    
                case "analyze": {
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

                    int outOfScopeRequests = totalRequests - inScopeRequests;
                    double inScopePct = totalRequests > 0 ? inScopeRequests * 100.0 / totalRequests : 0;

                    // Build top hosts list
                    List<Map<String, Object>> topHosts = new ArrayList<>();
                    hostCounts.entrySet().stream()
                        .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                        .limit(10)
                        .forEach(entry -> {
                            Map<String, Object> h = new HashMap<>();
                            h.put("host", entry.getKey());
                            h.put("requests", entry.getValue());
                            h.put("inScope", hostScopeStatus.get(entry.getKey()));
                            topHosts.add(h);
                        });

                    String recommendation;
                    if (inScopeRequests == 0) {
                        recommendation = "No in-scope requests found. Consider adding target URLs to scope.";
                    } else if (inScopeRequests < totalRequests / 2) {
                        recommendation = "Most traffic is out of scope. Consider refining your scope configuration.";
                    } else {
                        recommendation = "Good scope coverage! Most traffic is within target scope.";
                    }

                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "analyze");
                        data.put("totalRequests", totalRequests);
                        data.put("inScopeRequests", inScopeRequests);
                        data.put("outOfScopeRequests", outOfScopeRequests);
                        data.put("inScopePercent", Math.round(inScopePct * 10.0) / 10.0);
                        data.put("topHosts", topHosts);
                        data.put("recommendation", recommendation);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append("=== 📊 Scope Coverage Analysis ===\n\n");
                    result.append("📈 **Analysis Results:**\n");
                    result.append("• Total requests analyzed: ").append(totalRequests).append("\n");
                    result.append("• In-scope requests: ").append(inScopeRequests)
                        .append(" (").append(String.format("%.1f%%", inScopePct)).append(")\n");
                    result.append("• Out-of-scope requests: ").append(outOfScopeRequests)
                        .append(" (").append(String.format("%.1f%%", 100 - inScopePct)).append(")\n\n");

                    result.append("🌐 **Host Distribution:**\n");
                    for (Map<String, Object> h : topHosts) {
                        result.append("• ").append(h.get("host"))
                            .append(" - ").append(h.get("requests")).append(" requests ")
                            .append((Boolean) h.get("inScope") ? "✅" : "❌").append("\n");
                    }
                    result.append("\n💡 **Recommendation:** ").append(recommendation).append("\n");
                    break;
                }
                    
                case "bulk_add": {
                    if (!arguments.has("urls")) {
                        return createErrorResponse("'urls' array is required for bulk_add action");
                    }

                    JsonNode urlsNode = arguments.get("urls");
                    List<String> bulkAdded = new ArrayList<>();
                    List<Map<String, String>> bulkFailed = new ArrayList<>();

                    for (JsonNode urlNode : urlsNode) {
                        String bulkUrl = urlNode.asText();
                        try {
                            String normalizedUrl = normalizeUrl(bulkUrl);
                            scope.includeInScope(normalizedUrl);
                            knownInScopeUrls.add(normalizedUrl);
                            bulkAdded.add(bulkUrl);
                        } catch (Exception e) {
                            Map<String, String> f = new HashMap<>();
                            f.put("url", bulkUrl);
                            f.put("error", e.getMessage());
                            bulkFailed.add(f);
                        }
                    }

                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "bulk_add");
                        data.put("addedCount", bulkAdded.size());
                        data.put("failedCount", bulkFailed.size());
                        data.put("added", bulkAdded);
                        if (!bulkFailed.isEmpty()) data.put("failed", bulkFailed);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append("=== 📦 Bulk Add to Scope ===\n\n");
                    for (String u : bulkAdded) result.append("✅ Added: ").append(u).append("\n");
                    for (Map<String, String> f : bulkFailed) {
                        result.append("❌ Failed: ").append(f.get("url")).append(" - ").append(f.get("error")).append("\n");
                    }
                    result.append("\n📊 **Summary:**\n");
                    result.append("• Successfully added: ").append(bulkAdded.size()).append("\n");
                    result.append("• Failed: ").append(bulkFailed.size()).append("\n");
                    break;
                }

                case "bulk_check": {
                    if (!arguments.has("urls")) {
                        return createErrorResponse("'urls' array is required for bulk_check action");
                    }

                    JsonNode urlsNode = arguments.get("urls");
                    List<Map<String, Object>> checkResults = new ArrayList<>();
                    int inScopeCount = 0;
                    int outScopeCount = 0;
                    int errorCount = 0;

                    for (JsonNode urlNode : urlsNode) {
                        String checkUrl = urlNode.asText();
                        Map<String, Object> r = new HashMap<>();
                        r.put("url", checkUrl);
                        try {
                            String normalizedUrl = normalizeUrl(checkUrl);
                            boolean isIn = scope.isInScope(normalizedUrl);
                            scopeCheckCount.incrementAndGet();
                            r.put("inScope", isIn);
                            if (isIn) {
                                knownInScopeUrls.add(normalizedUrl);
                                inScopeCount++;
                            } else {
                                knownOutOfScopeUrls.add(normalizedUrl);
                                outScopeCount++;
                            }
                        } catch (Exception e) {
                            r.put("error", e.getMessage());
                            errorCount++;
                        }
                        checkResults.add(r);
                    }

                    if (!McpUtils.isVerbose(arguments)) {
                        Map<String, Object> data = new HashMap<>();
                        data.put("action", "bulk_check");
                        data.put("inScopeCount", inScopeCount);
                        data.put("outOfScopeCount", outScopeCount);
                        data.put("errorCount", errorCount);
                        data.put("results", checkResults);
                        return McpUtils.createJsonResponse(data);
                    }

                    result.append("=== 🔍 Bulk Scope Check ===\n\n");
                    for (Map<String, Object> r : checkResults) {
                        if (r.containsKey("error")) {
                            result.append("⚠️ ERROR checking: ").append(r.get("url")).append(" - ").append(r.get("error")).append("\n");
                        } else if ((Boolean) r.get("inScope")) {
                            result.append("✅ IN SCOPE: ").append(r.get("url")).append("\n");
                        } else {
                            result.append("❌ NOT IN SCOPE: ").append(r.get("url")).append("\n");
                        }
                    }
                    result.append("\n📊 **Summary:**\n");
                    result.append("• In scope: ").append(inScopeCount).append("\n");
                    result.append("• Out of scope: ").append(outScopeCount).append("\n");
                    result.append("• Total checked: ").append(inScopeCount + outScopeCount).append("\n");
                    break;
                }
                    
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
