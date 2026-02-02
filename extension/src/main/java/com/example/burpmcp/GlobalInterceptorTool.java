package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.websocket.*;
import burp.api.montoya.core.ByteArray;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Optimized Global HTTP and WebSocket Interceptor Tool
 * 
 * Features:
 * - Intercepts ALL HTTP and WebSocket traffic from ALL Burp tools
 * - Uses proper global WebSocket API for complete coverage
 * - Supports dropping WebSocket messages
 * - Captures timing data for performance analysis
 * - Regex-based rule matching
 * - Tool source filtering
 * - Rule priority and ordering
 * - Advanced modification capabilities
 */
public class GlobalInterceptorTool implements McpTool {
    
    // Static state management (persists across tool invocations)
    private static final AtomicBoolean interceptorEnabled = new AtomicBoolean(false);
    private static final AtomicBoolean requestInterceptionEnabled = new AtomicBoolean(true);
    private static final AtomicBoolean responseInterceptionEnabled = new AtomicBoolean(false);
    private static final AtomicBoolean webSocketInterceptionEnabled = new AtomicBoolean(false);
    private static Registration httpHandlerRegistration = null;
    private static Registration webSocketRegistration = null;
    
    // Statistics with more detail
    private static final AtomicLong requestsIntercepted = new AtomicLong(0);
    private static final AtomicLong responsesIntercepted = new AtomicLong(0);
    private static final AtomicLong requestsModified = new AtomicLong(0);
    private static final AtomicLong responsesModified = new AtomicLong(0);
    private static final AtomicLong requestsDropped = new AtomicLong(0);
    private static final AtomicLong webSocketMessagesIntercepted = new AtomicLong(0);
    private static final AtomicLong webSocketMessagesModified = new AtomicLong(0);
    private static final AtomicLong webSocketMessagesDropped = new AtomicLong(0);
    
    // Timing data storage (last 100 requests)
    private static final LinkedBlockingDeque<TimingInfo> timingHistory = new LinkedBlockingDeque<>(100);
    
    // Tool source filtering
    private static final Set<ToolType> enabledToolSources = ConcurrentHashMap.newKeySet();
    static {
        // Enable all tools by default
        enabledToolSources.addAll(Arrays.asList(ToolType.values()));
    }
    
    // Event-driven queue for real-time modification (optional)
    private static final AtomicBoolean useEventQueue = new AtomicBoolean(false);
    private static final BlockingQueue<PendingHttpMessage> pendingQueue = new LinkedBlockingQueue<>();
    private static final Map<String, CompletableFuture<ModificationInstructions>> responseMap = new ConcurrentHashMap<>();
    
    // Rules with priority ordering
    private static final TreeMap<Integer, ModificationRule> requestRules = new TreeMap<>();
    private static final TreeMap<Integer, ModificationRule> responseRules = new TreeMap<>();
    private static final TreeMap<Integer, WebSocketRule> webSocketRules = new TreeMap<>();
    private static int nextRulePriority = 100;
    
    // Global headers to add to all requests
    private static final Map<String, String> globalHeaders = new ConcurrentHashMap<>();
    
    // Authentication settings
    private static String authType = null;
    private static String authValue = null;
    private static String authHeader = "Authorization";
    
    // Rate limiting
    private static final AtomicLong rateLimitDelay = new AtomicLong(0); // milliseconds
    private static volatile long lastRequestTime = 0;
    
    // Request timing tracking
    private static final Map<Integer, Long> requestStartTimes = new ConcurrentHashMap<>();
    
    private final MontoyaApi api;
    private final ObjectMapper objectMapper;
    
    public GlobalInterceptorTool(MontoyaApi api) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
    }
    
    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_global_interceptor");
        tool.put("title", "Global Interceptor");
        tool.put("description", "Global HTTP and WebSocket interceptor for ALL Burp tools (Scanner, Intruder, Repeater, etc.). " +
                "Use this for global authentication injection, header modification across all tools, response manipulation, and WebSocket message interception. " +
                "Supports rule-based automatic mode or event-driven manual control. " +
                "Common use cases: add auth to Scanner, inject headers in WebSocket handshakes, WAF bypass testing.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        tool.put("annotations", annotations);
        
        Map<String, Object> inputSchema = new HashMap<>();
        Map<String, Object> properties = new HashMap<>();
        
        Map<String, Object> actionProp = new HashMap<>();
        actionProp.put("type", "string");
        actionProp.put("enum", Arrays.asList(
            "enable", "disable", "get_status",
            "set_auth", "clear_auth",
            "add_header", "remove_header", "list_headers",
            "add_request_rule", "add_response_rule", "remove_rule", "list_rules",
            "add_websocket_rule", "remove_websocket_rule", "list_websocket_rules",
            "set_mode", "get_stats", "clear_stats",
            "set_tool_filter", "get_tool_filter", "reset_tool_filter",
            "set_rate_limit", "get_timing_data",
            "export_rules", "import_rules"
        ));
        actionProp.put("description", "Action to perform");
        properties.put("action", actionProp);
        
        // Authentication parameters
        Map<String, Object> authTypeProp = new HashMap<>();
        authTypeProp.put("type", "string");
        authTypeProp.put("enum", Arrays.asList("bearer", "basic", "api_key", "custom"));
        authTypeProp.put("description", "Type of authentication");
        properties.put("auth_type", authTypeProp);
        
        Map<String, Object> authValueProp = new HashMap<>();
        authValueProp.put("type", "string");
        authValueProp.put("description", "Authentication value (token, credentials, etc.)");
        properties.put("auth_value", authValueProp);
        
        // Header management
        Map<String, Object> headerNameProp = new HashMap<>();
        headerNameProp.put("type", "string");
        headerNameProp.put("description", "Header name");
        properties.put("header_name", headerNameProp);
        
        Map<String, Object> headerValueProp = new HashMap<>();
        headerValueProp.put("type", "string");
        headerValueProp.put("description", "Header value");
        properties.put("header_value", headerValueProp);
        
        // Rule management
        Map<String, Object> ruleIdProp = new HashMap<>();
        ruleIdProp.put("type", "string");
        ruleIdProp.put("description", "Unique rule identifier");
        properties.put("rule_id", ruleIdProp);
        
        Map<String, Object> ruleProp = new HashMap<>();
        ruleProp.put("type", "object");
        ruleProp.put("description", "Rule definition (pattern, action, priority, etc.)");
        properties.put("rule", ruleProp);
        
        Map<String, Object> priorityProp = new HashMap<>();
        priorityProp.put("type", "integer");
        priorityProp.put("description", "Rule priority (lower numbers execute first)");
        properties.put("priority", priorityProp);
        
        // Mode settings
        Map<String, Object> modeProp = new HashMap<>();
        modeProp.put("type", "object");
        modeProp.put("description", "Mode settings (intercept_requests, intercept_responses, use_event_queue, etc.)");
        properties.put("mode", modeProp);
        
        // Tool filtering
        Map<String, Object> toolsProp = new HashMap<>();
        toolsProp.put("type", "array");
        toolsProp.put("description", "List of tools to filter (PROXY, SCANNER, INTRUDER, etc.)");
        properties.put("tools", toolsProp);
        
        // Rate limiting
        Map<String, Object> delayProp = new HashMap<>();
        delayProp.put("type", "integer");
        delayProp.put("description", "Delay in milliseconds between requests");
        properties.put("delay", delayProp);
        
        // Import/Export
        Map<String, Object> ruleDataProp = new HashMap<>();
        ruleDataProp.put("type", "object");
        ruleDataProp.put("description", "Exported rules data");
        properties.put("rules_data", ruleDataProp);
        
        inputSchema.put("type", "object");
        inputSchema.put("properties", properties);
        inputSchema.put("required", Arrays.asList("action"));
        
        tool.put("inputSchema", inputSchema);
        return tool;
    }
    
    @Override
    public Object execute(JsonNode arguments) throws Exception {
        Map<String, Object> args = objectMapper.convertValue(arguments, Map.class);
        String action = (String) args.get("action");
        
        try {
            switch (action.toLowerCase()) {
                case "enable":
                    return enableInterceptor();
                case "disable":
                    return disableInterceptor();
                case "get_status":
                    return getStatus();
                case "set_auth":
                    return setAuthentication(args);
                case "clear_auth":
                    return clearAuthentication();
                case "add_header":
                    return addGlobalHeader(args);
                case "remove_header":
                    return removeGlobalHeader(args);
                case "list_headers":
                    return listGlobalHeaders();
                case "add_request_rule":
                    return addRequestRule(args);
                case "add_response_rule":
                    return addResponseRule(args);
                case "remove_rule":
                    return removeRule(args);
                case "list_rules":
                    return listRules();
                case "add_websocket_rule":
                    return addWebSocketRule(args);
                case "remove_websocket_rule":
                    return removeWebSocketRule(args);
                case "list_websocket_rules":
                    return listWebSocketRules();
                case "set_mode":
                    return setMode(args);
                case "get_stats":
                    return getStatistics();
                case "clear_stats":
                    return clearStatistics();
                case "set_tool_filter":
                    return setToolFilter(args);
                case "get_tool_filter":
                    return getToolFilter();
                case "reset_tool_filter":
                    return resetToolFilter();
                case "set_rate_limit":
                    return setRateLimit(args);
                case "get_timing_data":
                    return getTimingData();
                case "export_rules":
                    return exportRules();
                case "import_rules":
                    return importRules(args);
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    private Object enableInterceptor() {
        if (interceptorEnabled.get()) {
            return McpUtils.createSuccessResponse("⚠️ Global interceptor already enabled");
        }
        
        // Register the HTTP handler
        Http http = api.http();
        httpHandlerRegistration = http.registerHttpHandler(new OptimizedHttpHandler());
        
        // Register the global WebSocket handler if enabled
        if (webSocketInterceptionEnabled.get()) {
            WebSockets webSockets = api.websockets();
            webSocketRegistration = webSockets.registerWebSocketCreatedHandler(new GlobalWebSocketHandler());
        }
        
        interceptorEnabled.set(true);
        
        StringBuilder message = new StringBuilder();
        message.append("✅ **Global Interceptor Enabled**\n\n");
        message.append("🌐 **Scope**: ALL Burp tools (Scanner, Intruder, Repeater, etc.)\n");
        message.append("📋 **Current Configuration**:\n");
        message.append("  • Request interception: ").append(requestInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        message.append("  • Response interception: ").append(responseInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        message.append("  • WebSocket interception: ").append(webSocketInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        message.append("  • Event queue mode: ").append(useEventQueue.get() ? "✅" : "❌").append("\n");
        message.append("  • Global headers: ").append(globalHeaders.size()).append(" configured\n");
        message.append("  • Request rules: ").append(requestRules.size()).append(" active\n");
        message.append("  • Response rules: ").append(responseRules.size()).append(" active\n");
        message.append("  • WebSocket rules: ").append(webSocketRules.size()).append(" active\n");
        message.append("  • Rate limit: ").append(rateLimitDelay.get() > 0 ? rateLimitDelay.get() + "ms" : "None").append("\n");
        message.append("  • Tool filter: ").append(enabledToolSources.size() < ToolType.values().length ? "Custom" : "All tools").append("\n");
        
        if (authType != null) {
            message.append("  • Authentication: ").append(authType).append(" configured\n");
        }
        
        return McpUtils.createSuccessResponse(message.toString());
    }
    
    private Object disableInterceptor() {
        if (!interceptorEnabled.get()) {
            return McpUtils.createSuccessResponse("⚠️ Global interceptor already disabled");
        }
        
        // Unregister handlers
        if (httpHandlerRegistration != null) {
            httpHandlerRegistration.deregister();
            httpHandlerRegistration = null;
        }
        
        if (webSocketRegistration != null) {
            webSocketRegistration.deregister();
            webSocketRegistration = null;
        }
        
        interceptorEnabled.set(false);
        
        return McpUtils.createSuccessResponse("❌ Global interceptor disabled");
    }
    
    private Object getStatus() {
        StringBuilder status = new StringBuilder();
        status.append("## 🌐 Global Interceptor Status\n\n");
        status.append("**State**: ").append(interceptorEnabled.get() ? "✅ Enabled" : "❌ Disabled").append("\n");
        status.append("**Request Interception**: ").append(requestInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        status.append("**Response Interception**: ").append(responseInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        status.append("**WebSocket Interception**: ").append(webSocketInterceptionEnabled.get() ? "✅" : "❌").append("\n");
        status.append("**Event Queue Mode**: ").append(useEventQueue.get() ? "✅" : "❌").append("\n");
        status.append("**Rate Limit**: ").append(rateLimitDelay.get() > 0 ? rateLimitDelay.get() + "ms" : "None").append("\n\n");
        
        status.append("### Configuration\n");
        status.append("**Global Headers**: ").append(globalHeaders.size()).append("\n");
        status.append("**Request Rules**: ").append(requestRules.size()).append("\n");
        status.append("**Response Rules**: ").append(responseRules.size()).append("\n");
        status.append("**WebSocket Rules**: ").append(webSocketRules.size()).append("\n");
        
        if (authType != null) {
            status.append("**Authentication**: ").append(authType).append(" (").append(authHeader).append(")\n");
        }
        
        // Tool filter status
        if (enabledToolSources.size() < ToolType.values().length) {
            status.append("**Tool Filter**: ");
            for (ToolType tool : enabledToolSources) {
                status.append(tool.name()).append(" ");
            }
            status.append("\n");
        } else {
            status.append("**Tool Filter**: All tools\n");
        }
        
        status.append("\n### Statistics\n");
        status.append("**Requests Intercepted**: ").append(requestsIntercepted.get()).append("\n");
        status.append("**Requests Modified**: ").append(requestsModified.get()).append("\n");
        status.append("**Requests Dropped**: ").append(requestsDropped.get()).append("\n");
        status.append("**Responses Intercepted**: ").append(responsesIntercepted.get()).append("\n");
        status.append("**Responses Modified**: ").append(responsesModified.get()).append("\n");
        status.append("**WebSocket Messages Intercepted**: ").append(webSocketMessagesIntercepted.get()).append("\n");
        status.append("**WebSocket Messages Modified**: ").append(webSocketMessagesModified.get()).append("\n");
        status.append("**WebSocket Messages Dropped**: ").append(webSocketMessagesDropped.get()).append("\n");
        
        if (requestsIntercepted.get() > 0) {
            double modRate = (requestsModified.get() * 100.0) / requestsIntercepted.get();
            status.append("\n**Request Modification Rate**: ").append(String.format("%.1f%%", modRate)).append("\n");
        }
        
        if (!timingHistory.isEmpty()) {
            status.append("\n### Recent Timing Data\n");
            status.append("**Samples**: ").append(timingHistory.size()).append("/100\n");
            
            // Calculate average timing
            long totalTime = 0;
            for (TimingInfo info : timingHistory) {
                totalTime += info.responseTime;
            }
            if (!timingHistory.isEmpty()) {
                status.append("**Average Response Time**: ").append(totalTime / timingHistory.size()).append("ms\n");
            }
        }
        
        return McpUtils.createSuccessResponse(status.toString());
    }
    
    private Object setAuthentication(Map<String, Object> args) {
        String type = (String) args.get("auth_type");
        String value = (String) args.get("auth_value");
        String customHeader = (String) args.get("header_name");
        
        if (type == null || value == null) {
            return McpUtils.createErrorResponse("auth_type and auth_value are required");
        }
        
        authType = type.toLowerCase();
        authValue = value;
        
        // Set up the authentication header based on type
        switch (authType) {
            case "bearer":
                authHeader = "Authorization";
                authValue = "Bearer " + value;
                break;
            case "basic":
                authHeader = "Authorization";
                authValue = "Basic " + value;
                break;
            case "api_key":
                authHeader = customHeader != null ? customHeader : "X-API-Key";
                authValue = value;
                break;
            case "custom":
                authHeader = customHeader != null ? customHeader : "Authorization";
                authValue = value;
                break;
        }
        
        // Add to global headers
        globalHeaders.put(authHeader, authValue);
        
        return McpUtils.createSuccessResponse(
            "✅ Authentication configured\n" +
            "Type: " + authType + "\n" +
            "Header: " + authHeader + "\n" +
            "This will be added to ALL requests from ALL Burp tools"
        );
    }
    
    private Object clearAuthentication() {
        if (authHeader != null) {
            globalHeaders.remove(authHeader);
        }
        authType = null;
        authValue = null;
        authHeader = "Authorization";
        
        return McpUtils.createSuccessResponse("✅ Authentication cleared");
    }
    
    private Object addGlobalHeader(Map<String, Object> args) {
        String name = (String) args.get("header_name");
        String value = (String) args.get("header_value");
        
        if (name == null || value == null) {
            return McpUtils.createErrorResponse("header_name and header_value are required");
        }
        
        globalHeaders.put(name, value);
        
        return McpUtils.createSuccessResponse(
            "✅ Global header added: " + name + "\n" +
            "This will be added to ALL requests from ALL Burp tools"
        );
    }
    
    private Object removeGlobalHeader(Map<String, Object> args) {
        String name = (String) args.get("header_name");
        
        if (name == null) {
            return McpUtils.createErrorResponse("header_name is required");
        }
        
        globalHeaders.remove(name);
        
        return McpUtils.createSuccessResponse("✅ Global header removed: " + name);
    }
    
    private Object listGlobalHeaders() {
        StringBuilder result = new StringBuilder();
        result.append("## 📋 Global Headers\n\n");
        
        if (globalHeaders.isEmpty()) {
            result.append("*No global headers configured*\n");
        } else {
            for (Map.Entry<String, String> header : globalHeaders.entrySet()) {
                result.append("• **").append(header.getKey()).append("**: `")
                      .append(header.getValue().length() > 50 ? 
                             header.getValue().substring(0, 50) + "..." : 
                             header.getValue())
                      .append("`\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object addRequestRule(Map<String, Object> args) {
        String ruleId = (String) args.get("rule_id");
        Map<String, Object> rule = (Map<String, Object>) args.get("rule");
        Integer priority = (Integer) args.get("priority");
        
        if (ruleId == null || rule == null) {
            return McpUtils.createErrorResponse("rule_id and rule are required");
        }
        
        if (priority == null) {
            priority = nextRulePriority++;
        }
        
        ModificationRule modRule = new ModificationRule(ruleId, rule, priority);
        requestRules.put(priority, modRule);
        
        return McpUtils.createSuccessResponse("✅ Request rule added: " + ruleId + " (priority: " + priority + ")");
    }
    
    private Object addResponseRule(Map<String, Object> args) {
        String ruleId = (String) args.get("rule_id");
        Map<String, Object> rule = (Map<String, Object>) args.get("rule");
        Integer priority = (Integer) args.get("priority");
        
        if (ruleId == null || rule == null) {
            return McpUtils.createErrorResponse("rule_id and rule are required");
        }
        
        if (priority == null) {
            priority = nextRulePriority++;
        }
        
        ModificationRule modRule = new ModificationRule(ruleId, rule, priority);
        responseRules.put(priority, modRule);
        
        return McpUtils.createSuccessResponse("✅ Response rule added: " + ruleId + " (priority: " + priority + ")");
    }
    
    private Object removeRule(Map<String, Object> args) {
        String ruleId = (String) args.get("rule_id");
        
        if (ruleId == null) {
            return McpUtils.createErrorResponse("rule_id is required");
        }
        
        boolean removed = false;
        
        // Remove from request rules
        Iterator<Map.Entry<Integer, ModificationRule>> reqIter = requestRules.entrySet().iterator();
        while (reqIter.hasNext()) {
            if (reqIter.next().getValue().id.equals(ruleId)) {
                reqIter.remove();
                removed = true;
                break;
            }
        }
        
        // Remove from response rules
        if (!removed) {
            Iterator<Map.Entry<Integer, ModificationRule>> respIter = responseRules.entrySet().iterator();
            while (respIter.hasNext()) {
                if (respIter.next().getValue().id.equals(ruleId)) {
                    respIter.remove();
                    removed = true;
                    break;
                }
            }
        }
        
        if (removed) {
            return McpUtils.createSuccessResponse("✅ Rule removed: " + ruleId);
        } else {
            return McpUtils.createErrorResponse("Rule not found: " + ruleId);
        }
    }
    
    private Object listRules() {
        StringBuilder result = new StringBuilder();
        result.append("## 📋 Active Rules\n\n");
        
        result.append("### Request Rules (by priority)\n");
        if (requestRules.isEmpty()) {
            result.append("*No request rules configured*\n");
        } else {
            for (Map.Entry<Integer, ModificationRule> entry : requestRules.entrySet()) {
                ModificationRule rule = entry.getValue();
                result.append("• [").append(entry.getKey()).append("] **").append(rule.id).append("**: ")
                      .append(rule.description).append("\n");
                if (rule.pattern != null) {
                    result.append("  Pattern: `").append(rule.patternString).append("`\n");
                }
            }
        }
        
        result.append("\n### Response Rules (by priority)\n");
        if (responseRules.isEmpty()) {
            result.append("*No response rules configured*\n");
        } else {
            for (Map.Entry<Integer, ModificationRule> entry : responseRules.entrySet()) {
                ModificationRule rule = entry.getValue();
                result.append("• [").append(entry.getKey()).append("] **").append(rule.id).append("**: ")
                      .append(rule.description).append("\n");
                if (rule.pattern != null) {
                    result.append("  Pattern: `").append(rule.patternString).append("`\n");
                }
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object setMode(Map<String, Object> args) {
        Map<String, Object> mode = (Map<String, Object>) args.get("mode");
        
        if (mode == null) {
            return McpUtils.createErrorResponse("mode configuration is required");
        }
        
        Boolean interceptRequests = (Boolean) mode.get("intercept_requests");
        Boolean interceptResponses = (Boolean) mode.get("intercept_responses");
        Boolean interceptWebSockets = (Boolean) mode.get("intercept_websockets");
        Boolean eventQueue = (Boolean) mode.get("use_event_queue");
        
        if (interceptRequests != null) {
            requestInterceptionEnabled.set(interceptRequests);
        }
        if (interceptResponses != null) {
            responseInterceptionEnabled.set(interceptResponses);
        }
        if (interceptWebSockets != null) {
            boolean wasEnabled = webSocketInterceptionEnabled.get();
            webSocketInterceptionEnabled.set(interceptWebSockets);
            
            // Register/unregister WebSocket handler based on state change
            if (interceptorEnabled.get()) {
                if (interceptWebSockets && !wasEnabled) {
                    WebSockets webSockets = api.websockets();
                    webSocketRegistration = webSockets.registerWebSocketCreatedHandler(new GlobalWebSocketHandler());
                } else if (!interceptWebSockets && wasEnabled && webSocketRegistration != null) {
                    webSocketRegistration.deregister();
                    webSocketRegistration = null;
                }
            }
        }
        if (eventQueue != null) {
            useEventQueue.set(eventQueue);
        }
        
        return McpUtils.createSuccessResponse(
            "✅ Mode updated\n" +
            "Request interception: " + requestInterceptionEnabled.get() + "\n" +
            "Response interception: " + responseInterceptionEnabled.get() + "\n" +
            "WebSocket interception: " + webSocketInterceptionEnabled.get() + "\n" +
            "Event queue mode: " + useEventQueue.get()
        );
    }
    
    private Object getStatistics() {
        StringBuilder stats = new StringBuilder();
        stats.append("## 📊 Global Interceptor Statistics\n\n");
        stats.append("### HTTP Statistics\n");
        stats.append("**Requests Intercepted**: ").append(requestsIntercepted.get()).append("\n");
        stats.append("**Requests Modified**: ").append(requestsModified.get()).append("\n");
        stats.append("**Requests Dropped**: ").append(requestsDropped.get()).append("\n");
        stats.append("**Responses Intercepted**: ").append(responsesIntercepted.get()).append("\n");
        stats.append("**Responses Modified**: ").append(responsesModified.get()).append("\n");
        
        if (requestsIntercepted.get() > 0) {
            double modRate = (requestsModified.get() * 100.0) / requestsIntercepted.get();
            double dropRate = (requestsDropped.get() * 100.0) / requestsIntercepted.get();
            stats.append("\n**Request Modification Rate**: ").append(String.format("%.1f%%", modRate)).append("\n");
            stats.append("**Request Drop Rate**: ").append(String.format("%.1f%%", dropRate)).append("\n");
        }
        
        if (responsesIntercepted.get() > 0) {
            double modRate = (responsesModified.get() * 100.0) / responsesIntercepted.get();
            stats.append("**Response Modification Rate**: ").append(String.format("%.1f%%", modRate)).append("\n");
        }
        
        stats.append("\n### WebSocket Statistics\n");
        stats.append("**Messages Intercepted**: ").append(webSocketMessagesIntercepted.get()).append("\n");
        stats.append("**Messages Modified**: ").append(webSocketMessagesModified.get()).append("\n");
        stats.append("**Messages Dropped**: ").append(webSocketMessagesDropped.get()).append("\n");
        
        if (webSocketMessagesIntercepted.get() > 0) {
            double modRate = (webSocketMessagesModified.get() * 100.0) / webSocketMessagesIntercepted.get();
            double dropRate = (webSocketMessagesDropped.get() * 100.0) / webSocketMessagesIntercepted.get();
            stats.append("**Message Modification Rate**: ").append(String.format("%.1f%%", modRate)).append("\n");
            stats.append("**Message Drop Rate**: ").append(String.format("%.1f%%", dropRate)).append("\n");
        }
        
        return McpUtils.createSuccessResponse(stats.toString());
    }
    
    private Object clearStatistics() {
        requestsIntercepted.set(0);
        responsesIntercepted.set(0);
        requestsModified.set(0);
        responsesModified.set(0);
        requestsDropped.set(0);
        webSocketMessagesIntercepted.set(0);
        webSocketMessagesModified.set(0);
        webSocketMessagesDropped.set(0);
        timingHistory.clear();
        
        return McpUtils.createSuccessResponse("✅ Statistics cleared");
    }
    
    private Object setToolFilter(Map<String, Object> args) {
        // Handle both List and single String
        Object toolsObj = args.get("tools");
        List<String> tools = null;
        
        if (toolsObj instanceof List) {
            tools = (List<String>) toolsObj;
        } else if (toolsObj instanceof String) {
            String toolStr = (String) toolsObj;
            // Check if it's a JSON array string
            if (toolStr.startsWith("[") && toolStr.endsWith("]")) {
                // Parse JSON array string
                try {
                    toolStr = toolStr.substring(1, toolStr.length() - 1); // Remove brackets
                    String[] toolArray = toolStr.split(",");
                    tools = new ArrayList<>();
                    for (String tool : toolArray) {
                        // Remove quotes and whitespace
                        String cleanTool = tool.trim().replaceAll("\"", "");
                        tools.add(cleanTool);
                    }
                } catch (Exception e) {
                    // If parsing fails, treat as single tool
                    tools = Arrays.asList(toolStr);
                }
            } else {
                // Handle single string as a list
                tools = Arrays.asList(toolStr);
            }
        }
        
        if (tools == null || tools.isEmpty()) {
            return McpUtils.createErrorResponse("tools list is required");
        }
        
        // Don't clear if we're processing tools
        Set<ToolType> newToolSources = new HashSet<>();
        List<String> invalidTools = new ArrayList<>();
        
        for (String toolName : tools) {
            try {
                // Handle both upper and lower case, and trim whitespace
                String normalizedName = toolName.trim().toUpperCase();
                ToolType tool = ToolType.valueOf(normalizedName);
                newToolSources.add(tool);
            } catch (IllegalArgumentException e) {
                // Track invalid tool names for reporting
                invalidTools.add(toolName);
            }
        }
        
        // Only update if we have valid tools
        if (!newToolSources.isEmpty()) {
            enabledToolSources.clear();
            enabledToolSources.addAll(newToolSources);
        } else if (!invalidTools.isEmpty()) {
            return McpUtils.createErrorResponse(
                "No valid tools found. Invalid tools: " + String.join(", ", invalidTools) + "\n" +
                "Valid tools: SUITE, TARGET, PROXY, SCANNER, INTRUDER, REPEATER, LOGGER, " +
                "SEQUENCER, DECODER, COMPARER, EXTENSIONS, RECORDED_LOGIN_REPLAYER, ORGANIZER, BURP_AI"
            );
        }
        
        StringBuilder message = new StringBuilder();
        message.append("✅ Tool filter updated\n");
        message.append("Enabled tools: ").append(enabledToolSources).append("\n");
        
        if (!invalidTools.isEmpty()) {
            message.append("⚠️ Invalid tools ignored: ").append(String.join(", ", invalidTools));
        }
        
        return McpUtils.createSuccessResponse(message.toString());
    }
    
    private Object getToolFilter() {
        StringBuilder result = new StringBuilder();
        result.append("## 🛠️ Tool Filter Configuration\n\n");
        
        if (enabledToolSources.size() == ToolType.values().length) {
            result.append("**All tools enabled**\n");
        } else {
            result.append("**Enabled tools:**\n");
            for (ToolType tool : enabledToolSources) {
                result.append("• ").append(tool.name()).append("\n");
            }
            
            result.append("\n**Disabled tools:**\n");
            for (ToolType tool : ToolType.values()) {
                if (!enabledToolSources.contains(tool)) {
                    result.append("• ").append(tool.name()).append("\n");
                }
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object resetToolFilter() {
        enabledToolSources.clear();
        enabledToolSources.addAll(Arrays.asList(ToolType.values()));
        
        return McpUtils.createSuccessResponse(
            "✅ Tool filter reset\n" +
            "All tools are now enabled (" + enabledToolSources.size() + " tools)"
        );
    }
    
    private Object setRateLimit(Map<String, Object> args) {
        // Handle both Integer and String types from JSON
        Object delayObj = args.get("delay");
        Integer delay = null;
        
        if (delayObj instanceof Integer) {
            delay = (Integer) delayObj;
        } else if (delayObj instanceof Number) {
            delay = ((Number) delayObj).intValue();
        } else if (delayObj instanceof String) {
            try {
                delay = Integer.parseInt((String) delayObj);
            } catch (NumberFormatException e) {
                return McpUtils.createErrorResponse("delay must be a valid integer");
            }
        }
        
        if (delay == null || delay < 0) {
            return McpUtils.createErrorResponse("delay must be a non-negative integer (milliseconds)");
        }
        
        rateLimitDelay.set(delay);
        
        return McpUtils.createSuccessResponse(
            "✅ Rate limit " + (delay > 0 ? "set to " + delay + "ms" : "disabled")
        );
    }
    
    private Object getTimingData() {
        StringBuilder result = new StringBuilder();
        result.append("## ⏱️ Timing Data (Last 100 Requests)\n\n");
        
        if (timingHistory.isEmpty()) {
            result.append("*No timing data available*\n");
        } else {
            result.append("**Total samples**: ").append(timingHistory.size()).append("\n\n");
            
            // Calculate statistics
            long totalTime = 0;
            long minTime = Long.MAX_VALUE;
            long maxTime = 0;
            
            List<TimingInfo> timingList = new ArrayList<>(timingHistory);
            for (TimingInfo info : timingList) {
                totalTime += info.responseTime;
                minTime = Math.min(minTime, info.responseTime);
                maxTime = Math.max(maxTime, info.responseTime);
            }
            
            long avgTime = totalTime / timingList.size();
            
            result.append("### Statistics\n");
            result.append("**Average Response Time**: ").append(avgTime).append("ms\n");
            result.append("**Min Response Time**: ").append(minTime).append("ms\n");
            result.append("**Max Response Time**: ").append(maxTime).append("ms\n\n");
            
            result.append("### Recent Requests\n");
            int count = 0;
            for (TimingInfo info : timingList) {
                if (count++ >= 10) break; // Show only last 10
                result.append("• [").append(info.timestamp).append("] ")
                      .append(info.method).append(" ").append(info.url)
                      .append(" - ").append(info.responseTime).append("ms")
                      .append(" (").append(info.toolSource).append(")\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object exportRules() {
        Map<String, Object> exportData = new HashMap<>();
        
        // Export request rules
        List<Map<String, Object>> reqRuleList = new ArrayList<>();
        for (Map.Entry<Integer, ModificationRule> entry : requestRules.entrySet()) {
            Map<String, Object> ruleData = new HashMap<>();
            ruleData.put("id", entry.getValue().id);
            ruleData.put("priority", entry.getKey());
            ruleData.put("config", entry.getValue().config);
            reqRuleList.add(ruleData);
        }
        exportData.put("requestRules", reqRuleList);
        
        // Export response rules
        List<Map<String, Object>> respRuleList = new ArrayList<>();
        for (Map.Entry<Integer, ModificationRule> entry : responseRules.entrySet()) {
            Map<String, Object> ruleData = new HashMap<>();
            ruleData.put("id", entry.getValue().id);
            ruleData.put("priority", entry.getKey());
            ruleData.put("config", entry.getValue().config);
            respRuleList.add(ruleData);
        }
        exportData.put("responseRules", respRuleList);
        
        // Export WebSocket rules
        List<Map<String, Object>> wsRuleList = new ArrayList<>();
        for (Map.Entry<Integer, WebSocketRule> entry : webSocketRules.entrySet()) {
            Map<String, Object> ruleData = new HashMap<>();
            ruleData.put("id", entry.getValue().id);
            ruleData.put("priority", entry.getKey());
            ruleData.put("config", entry.getValue().config);
            wsRuleList.add(ruleData);
        }
        exportData.put("webSocketRules", wsRuleList);
        
        // Export global headers
        exportData.put("globalHeaders", new HashMap<>(globalHeaders));
        
        // Export settings
        Map<String, Object> settings = new HashMap<>();
        settings.put("requestInterception", requestInterceptionEnabled.get());
        settings.put("responseInterception", responseInterceptionEnabled.get());
        settings.put("webSocketInterception", webSocketInterceptionEnabled.get());
        settings.put("rateLimitDelay", rateLimitDelay.get());
        settings.put("authType", authType);
        settings.put("authValue", authValue);
        settings.put("authHeader", authHeader);
        exportData.put("settings", settings);
        
        // Return as MCP text response with JSON
        try {
            ObjectMapper mapper = new ObjectMapper();
            String jsonData = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(exportData);
            
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("type", "text");
            resultMap.put("text", "## Exported Rules Configuration\n\n```json\n" + jsonData + "\n```");
            
            return List.of(resultMap);
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to export rules: " + e.getMessage());
        }
    }
    
    private Object importRules(Map<String, Object> args) {
        Map<String, Object> rulesData = (Map<String, Object>) args.get("rules_data");
        
        if (rulesData == null) {
            return McpUtils.createErrorResponse("rules_data is required");
        }
        
        try {
            // Import request rules
            List<Map<String, Object>> reqRules = (List<Map<String, Object>>) rulesData.get("requestRules");
            if (reqRules != null) {
                requestRules.clear();
                for (Map<String, Object> ruleData : reqRules) {
                    String id = (String) ruleData.get("id");
                    Integer priority = (Integer) ruleData.get("priority");
                    Map<String, Object> config = (Map<String, Object>) ruleData.get("config");
                    requestRules.put(priority, new ModificationRule(id, config, priority));
                }
            }
            
            // Import response rules
            List<Map<String, Object>> respRules = (List<Map<String, Object>>) rulesData.get("responseRules");
            if (respRules != null) {
                responseRules.clear();
                for (Map<String, Object> ruleData : respRules) {
                    String id = (String) ruleData.get("id");
                    Integer priority = (Integer) ruleData.get("priority");
                    Map<String, Object> config = (Map<String, Object>) ruleData.get("config");
                    responseRules.put(priority, new ModificationRule(id, config, priority));
                }
            }
            
            // Import WebSocket rules
            List<Map<String, Object>> wsRules = (List<Map<String, Object>>) rulesData.get("webSocketRules");
            if (wsRules != null) {
                webSocketRules.clear();
                for (Map<String, Object> ruleData : wsRules) {
                    String id = (String) ruleData.get("id");
                    Integer priority = (Integer) ruleData.get("priority");
                    Map<String, Object> config = (Map<String, Object>) ruleData.get("config");
                    webSocketRules.put(priority, new WebSocketRule(id, config, priority));
                }
            }
            
            // Import global headers
            Map<String, String> headers = (Map<String, String>) rulesData.get("globalHeaders");
            if (headers != null) {
                globalHeaders.clear();
                globalHeaders.putAll(headers);
            }
            
            // Import settings
            Map<String, Object> settings = (Map<String, Object>) rulesData.get("settings");
            if (settings != null) {
                Boolean reqInt = (Boolean) settings.get("requestInterception");
                if (reqInt != null) requestInterceptionEnabled.set(reqInt);
                
                Boolean respInt = (Boolean) settings.get("responseInterception");
                if (respInt != null) responseInterceptionEnabled.set(respInt);
                
                Boolean wsInt = (Boolean) settings.get("webSocketInterception");
                if (wsInt != null) webSocketInterceptionEnabled.set(wsInt);
                
                Long rateLimit = ((Number) settings.get("rateLimitDelay")).longValue();
                if (rateLimit != null) rateLimitDelay.set(rateLimit);
                
                authType = (String) settings.get("authType");
                authValue = (String) settings.get("authValue");
                authHeader = (String) settings.get("authHeader");
            }
            
            return McpUtils.createSuccessResponse("✅ Rules imported successfully");
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to import rules: " + e.getMessage());
        }
    }
    
    private Object addWebSocketRule(Map<String, Object> args) {
        String ruleId = (String) args.get("rule_id");
        Map<String, Object> rule = (Map<String, Object>) args.get("rule");
        Integer priority = (Integer) args.get("priority");
        
        if (ruleId == null || rule == null) {
            return McpUtils.createErrorResponse("rule_id and rule are required");
        }
        
        if (priority == null) {
            priority = nextRulePriority++;
        }
        
        WebSocketRule wsRule = new WebSocketRule(ruleId, rule, priority);
        webSocketRules.put(priority, wsRule);
        
        return McpUtils.createSuccessResponse("✅ WebSocket rule added: " + ruleId + " (priority: " + priority + ")");
    }
    
    private Object removeWebSocketRule(Map<String, Object> args) {
        String ruleId = (String) args.get("rule_id");
        
        if (ruleId == null) {
            return McpUtils.createErrorResponse("rule_id is required");
        }
        
        boolean removed = false;
        Iterator<Map.Entry<Integer, WebSocketRule>> iter = webSocketRules.entrySet().iterator();
        while (iter.hasNext()) {
            if (iter.next().getValue().id.equals(ruleId)) {
                iter.remove();
                removed = true;
                break;
            }
        }
        
        if (removed) {
            return McpUtils.createSuccessResponse("✅ WebSocket rule removed: " + ruleId);
        }
        return McpUtils.createErrorResponse("WebSocket rule not found: " + ruleId);
    }
    
    private Object listWebSocketRules() {
        StringBuilder result = new StringBuilder();
        result.append("## 📝 WebSocket Rules (by priority)\n\n");
        
        if (webSocketRules.isEmpty()) {
            result.append("*No WebSocket rules configured*\n");
        } else {
            for (Map.Entry<Integer, WebSocketRule> entry : webSocketRules.entrySet()) {
                WebSocketRule rule = entry.getValue();
                result.append("• [").append(entry.getKey()).append("] **").append(rule.id).append("**: ")
                      .append(rule.description).append("\n");
                if (rule.matchPattern != null) {
                    result.append("  - **Pattern**: `").append(rule.matchPatternString).append("`\n");
                }
                if (rule.replaceText != null) {
                    result.append("  - **Replace**: `").append(rule.replaceText).append("`\n");
                }
                result.append("  - **Direction**: ").append(rule.direction).append("\n");
                if (rule.dropMessage) {
                    result.append("  - **Action**: DROP\n");
                }
                result.append("\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    /**
     * Optimized HTTP handler with timing data and better filtering
     */
    private class OptimizedHttpHandler implements HttpHandler {
        
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (!interceptorEnabled.get() || !requestInterceptionEnabled.get()) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            
            // Check tool source filter
            ToolSource toolSource = requestToBeSent.toolSource();
            if (!isToolEnabled(toolSource)) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            
            // Apply rate limiting
            if (rateLimitDelay.get() > 0) {
                long now = System.currentTimeMillis();
                long timeSinceLastRequest = now - lastRequestTime;
                if (timeSinceLastRequest < rateLimitDelay.get()) {
                    try {
                        Thread.sleep(rateLimitDelay.get() - timeSinceLastRequest);
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
                lastRequestTime = System.currentTimeMillis();
            }
            
            requestsIntercepted.incrementAndGet();
            
            // Track request start time for timing data
            requestStartTimes.put(requestToBeSent.messageId(), System.currentTimeMillis());
            
            HttpRequest request = requestToBeSent;
            boolean modified = false;
            
            // Apply global headers (including to WebSocket upgrade requests)
            if (!globalHeaders.isEmpty()) {
                for (Map.Entry<String, String> header : globalHeaders.entrySet()) {
                    request = request.withHeader(header.getKey(), header.getValue());
                    modified = true;
                }
                
                // Log if this is a WebSocket upgrade request
                if (request.hasHeader("Upgrade") && 
                    "websocket".equalsIgnoreCase(request.headerValue("Upgrade"))) {
                    api.logging().logToOutput("Global Interceptor: Applied headers to WebSocket upgrade request to " + 
                        request.url());
                }
            }
            
            // Apply request rules in priority order
            for (ModificationRule rule : requestRules.values()) {
                if (rule.matches(request)) {
                    request = rule.apply(request);
                    modified = true;
                }
            }
            
            if (modified) {
                requestsModified.incrementAndGet();
                
                // Add annotation
                Annotations annotations = requestToBeSent.annotations()
                    .withNotes("Modified by Global Interceptor [" + toolSource.toolType().toolName() + "]")
                    .withHighlightColor(HighlightColor.YELLOW);
                
                return RequestToBeSentAction.continueWith(request, annotations);
            }
            
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
        
        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            if (!interceptorEnabled.get() || !responseInterceptionEnabled.get()) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            
            // Check tool source filter
            ToolSource toolSource = responseReceived.toolSource();
            if (!isToolEnabled(toolSource)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            
            responsesIntercepted.incrementAndGet();
            
            // Capture timing data (if available)
            try {
                HttpRequest request = responseReceived.initiatingRequest();
                if (request != null) {
                    // Calculate actual response time
                    Long startTime = requestStartTimes.remove(responseReceived.messageId());
                    long responseTime = 0;
                    if (startTime != null) {
                        responseTime = System.currentTimeMillis() - startTime;
                    }
                    
                    TimingInfo timing = new TimingInfo(
                        request.method(),
                        request.url(),
                        responseTime,
                        toolSource.toolType().toolName()
                    );
                    
                    // Add to history (oldest removed if full)
                    if (timingHistory.size() >= 100) {
                        timingHistory.pollFirst();
                    }
                    timingHistory.offer(timing);
                    
                    // Clean up old entries to prevent memory leak
                    if (requestStartTimes.size() > 1000) {
                        requestStartTimes.clear();
                    }
                }
            } catch (Exception e) {
                // Ignore timing errors
            }
            
            HttpResponse response = responseReceived;
            boolean modified = false;
            
            // Apply response rules in priority order
            for (ModificationRule rule : responseRules.values()) {
                if (rule.matchesResponse(response, responseReceived.initiatingRequest())) {
                    response = rule.applyToResponse(response);
                    modified = true;
                }
            }
            
            if (modified) {
                responsesModified.incrementAndGet();
                
                // Add annotation
                Annotations annotations = responseReceived.annotations()
                    .withNotes("Response modified by Global Interceptor [" + toolSource.toolType().toolName() + "]")
                    .withHighlightColor(HighlightColor.CYAN);
                
                return ResponseReceivedAction.continueWith(response, annotations);
            }
            
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        private boolean isToolEnabled(ToolSource toolSource) {
            return enabledToolSources.contains(toolSource.toolType());
        }
    }
    
    /**
     * Global WebSocket handler using the proper API
     */
    private class GlobalWebSocketHandler implements WebSocketCreatedHandler {
        @Override
        public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
            WebSocket webSocket = webSocketCreated.webSocket();
            ToolSource toolSource = webSocketCreated.toolSource();
            
            // Check if this tool is enabled
            if (!enabledToolSources.contains(toolSource.toolType())) {
                return;
            }
            
            // Register message handler for this WebSocket
            webSocket.registerMessageHandler(new MessageHandler() {
                @Override
                public TextMessageAction handleTextMessage(TextMessage message) {
                    webSocketMessagesIntercepted.incrementAndGet();
                    
                    String payload = message.payload();
                    burp.api.montoya.websocket.Direction direction = message.direction();
                    
                    // Apply WebSocket rules in priority order
                    for (WebSocketRule rule : webSocketRules.values()) {
                        if (rule.matches(payload, direction)) {
                            if (rule.dropMessage) {
                                webSocketMessagesDropped.incrementAndGet();
                                return TextMessageAction.drop();
                            }
                            
                            String modifiedPayload = rule.apply(payload);
                            if (!modifiedPayload.equals(payload)) {
                                webSocketMessagesModified.incrementAndGet();
                                return TextMessageAction.continueWith(modifiedPayload);
                            }
                        }
                    }
                    
                    return TextMessageAction.continueWith(message);
                }
                
                @Override
                public BinaryMessageAction handleBinaryMessage(BinaryMessage message) {
                    webSocketMessagesIntercepted.incrementAndGet();
                    
                    // For now, just pass through binary messages
                    // Could add binary rule support later
                    return BinaryMessageAction.continueWith(message);
                }
            });
        }
    }
    
    /**
     * Enhanced modification rule with regex support
     */
    private static class ModificationRule {
        final String id;
        final String description;
        final Map<String, Object> config;
        final int priority;
        final Pattern pattern;
        final String patternString;
        final boolean useRegex;
        
        ModificationRule(String id, Map<String, Object> config, int priority) {
            this.id = id;
            this.config = config;
            this.priority = priority;
            this.description = (String) config.getOrDefault("description", "No description");
            
            // Check for regex pattern
            this.useRegex = Boolean.TRUE.equals(config.get("use_regex"));
            this.patternString = (String) config.get("url_pattern");
            
            Pattern tempPattern = null;
            if (useRegex && patternString != null) {
                try {
                    tempPattern = Pattern.compile(patternString);
                } catch (Exception e) {
                    // Pattern compilation failed
                }
            }
            this.pattern = tempPattern;
        }
        
        boolean matches(HttpRequest request) {
            // URL pattern matching with regex support
            String urlPattern = (String) config.get("url_pattern");
            if (urlPattern != null) {
                String url = request.url();
                if (useRegex && pattern != null) {
                    return pattern.matcher(url).find();
                } else {
                    return url.contains(urlPattern);
                }
            }
            
            // Method matching
            String method = (String) config.get("method");
            if (method != null && !request.method().equalsIgnoreCase(method)) {
                return false;
            }
            
            // Header matching
            Map<String, String> requiredHeaders = (Map<String, String>) config.get("required_headers");
            if (requiredHeaders != null) {
                for (Map.Entry<String, String> entry : requiredHeaders.entrySet()) {
                    if (!request.hasHeader(entry.getKey(), entry.getValue())) {
                        return false;
                    }
                }
            }
            
            return true;
        }
        
        boolean matchesResponse(HttpResponse response, HttpRequest request) {
            // Status code matching
            Integer statusCode = (Integer) config.get("status_code");
            if (statusCode != null && response.statusCode() != statusCode) {
                return false;
            }
            
            // Status code range matching
            String statusRange = (String) config.get("status_range");
            if (statusRange != null) {
                String[] parts = statusRange.split("-");
                if (parts.length == 2) {
                    try {
                        int min = Integer.parseInt(parts[0]);
                        int max = Integer.parseInt(parts[1]);
                        int code = response.statusCode();
                        if (code < min || code > max) {
                            return false;
                        }
                    } catch (NumberFormatException e) {
                        // Invalid range
                    }
                }
            }
            
            // Content type matching
            String contentType = (String) config.get("content_type");
            if (contentType != null) {
                String responseContentType = response.headerValue("Content-Type");
                if (responseContentType == null || !responseContentType.contains(contentType)) {
                    return false;
                }
            }
            
            // Also check URL pattern if specified
            String urlPattern = (String) config.get("url_pattern");
            if (urlPattern != null && request != null) {
                String url = request.url();
                if (useRegex && pattern != null) {
                    return pattern.matcher(url).find();
                } else {
                    return url.contains(urlPattern);
                }
            }
            
            return true;
        }
        
        HttpRequest apply(HttpRequest request) {
            // Apply modifications based on config
            
            // Add/update headers
            Map<String, String> headers = (Map<String, String>) config.get("add_headers");
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    request = request.withHeader(header.getKey(), header.getValue());
                }
            }
            
            // Remove headers
            List<String> removeHeaders = (List<String>) config.get("remove_headers");
            if (removeHeaders != null) {
                for (String header : removeHeaders) {
                    request = request.withRemovedHeader(header);
                }
            }
            
            // Replace in body
            String searchText = (String) config.get("body_search");
            String replaceText = (String) config.get("body_replace");
            if (searchText != null && replaceText != null) {
                String body = request.bodyToString();
                if (useRegex && pattern != null) {
                    body = body.replaceAll(searchText, replaceText);
                } else {
                    body = body.replace(searchText, replaceText);
                }
                request = request.withBody(body);
            }
            
            // Change method
            String newMethod = (String) config.get("change_method");
            if (newMethod != null) {
                request = request.withMethod(newMethod);
            }
            
            // Change path
            String newPath = (String) config.get("change_path");
            if (newPath != null) {
                request = request.withPath(newPath);
            }
            
            return request;
        }
        
        HttpResponse applyToResponse(HttpResponse response) {
            // Apply response modifications
            
            // Add/update headers
            Map<String, String> headers = (Map<String, String>) config.get("add_headers");
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    response = response.withAddedHeader(header.getKey(), header.getValue());
                }
            }
            
            // Remove headers
            List<String> removeHeaders = (List<String>) config.get("remove_headers");
            if (removeHeaders != null) {
                for (String header : removeHeaders) {
                    response = response.withRemovedHeader(header);
                }
            }
            
            // Replace in body
            String searchText = (String) config.get("body_search");
            String replaceText = (String) config.get("body_replace");
            if (searchText != null && replaceText != null) {
                String body = response.bodyToString();
                if (useRegex) {
                    body = body.replaceAll(searchText, replaceText);
                } else {
                    body = body.replace(searchText, replaceText);
                }
                response = response.withBody(body);
            }
            
            // Change status code
            Integer newStatus = (Integer) config.get("change_status");
            String newReason = (String) config.get("change_reason");
            if (newStatus != null) {
                response = response.withStatusCode((short) newStatus.intValue());
                if (newReason != null) {
                    response = response.withReasonPhrase(newReason);
                }
            }
            
            return response;
        }
    }
    
    /**
     * Enhanced WebSocket rule with regex and drop support
     */
    private static class WebSocketRule {
        final String id;
        final String description;
        final Pattern matchPattern;
        final String matchPatternString;
        final String replaceText;
        final String direction; // "both", "client_to_server", "server_to_client"
        final Map<String, Object> config;
        final int priority;
        final boolean useRegex;
        final boolean dropMessage;
        
        WebSocketRule(String id, Map<String, Object> config, int priority) {
            this.id = id;
            this.config = config;
            this.priority = priority;
            this.description = (String) config.getOrDefault("description", "WebSocket rule");
            this.matchPatternString = (String) config.getOrDefault("match_pattern", "");
            this.replaceText = (String) config.getOrDefault("replace_text", "");
            this.direction = (String) config.getOrDefault("direction", "both");
            this.useRegex = Boolean.TRUE.equals(config.get("use_regex"));
            this.dropMessage = Boolean.TRUE.equals(config.get("drop"));
            
            Pattern tempPattern = null;
            if (useRegex && !matchPatternString.isEmpty()) {
                try {
                    tempPattern = Pattern.compile(matchPatternString);
                } catch (Exception e) {
                    // Pattern compilation failed
                }
            }
            this.matchPattern = tempPattern;
        }
        
        boolean matches(String payload, burp.api.montoya.websocket.Direction direction) {
            if (matchPatternString.isEmpty() && !dropMessage) {
                return false;
            }
            
            // Check direction filter
            if (!"both".equals(this.direction)) {
                String dirStr = direction == burp.api.montoya.websocket.Direction.CLIENT_TO_SERVER ? "client_to_server" : "server_to_client";
                if (!dirStr.equals(this.direction)) {
                    return false;
                }
            }
            
            // If drop is enabled without pattern, drop all messages in the specified direction
            if (dropMessage && matchPatternString.isEmpty()) {
                return true;
            }
            
            // Pattern matching
            if (useRegex && matchPattern != null) {
                return matchPattern.matcher(payload).find();
            } else {
                return payload.contains(matchPatternString);
            }
        }
        
        String apply(String payload) {
            if (matchPatternString.isEmpty() || replaceText == null) {
                return payload;
            }
            
            if (useRegex && matchPattern != null) {
                return matchPattern.matcher(payload).replaceAll(replaceText);
            } else {
                return payload.replace(matchPatternString, replaceText);
            }
        }
    }
    
    /**
     * Timing information for a request
     */
    private static class TimingInfo {
        final String method;
        final String url;
        final long responseTime;
        final String toolSource;
        final String timestamp;
        
        TimingInfo(String method, String url, long responseTime, String toolSource) {
            this.method = method;
            this.url = url;
            this.responseTime = responseTime;
            this.toolSource = toolSource;
            this.timestamp = DateTimeFormatter.ISO_LOCAL_DATE_TIME.format(
                ZonedDateTime.now().toLocalDateTime()
            );
        }
    }
    
    /**
     * Class for event-driven message handling
     */
    private static class PendingHttpMessage {
        final String id;
        final Object message; // HttpRequest or HttpResponse
        final long timestamp;
        
        PendingHttpMessage(String id, Object message, long timestamp) {
            this.id = id;
            this.message = message;
            this.timestamp = timestamp;
        }
    }
    
    /**
     * Instructions for modifying a message
     */
    private static class ModificationInstructions {
        Map<String, String> addHeaders;
        List<String> removeHeaders;
        String bodyReplace;
        boolean drop;
        
        // Additional fields as needed
    }
    
}