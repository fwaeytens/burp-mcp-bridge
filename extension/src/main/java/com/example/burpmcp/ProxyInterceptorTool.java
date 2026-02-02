package com.example.burpmcp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.proxy.websocket.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyInterceptorTool implements McpTool {
    private static final MontoyaApi staticApi;
    private static final Proxy staticProxy;
    private static final AtomicBoolean interceptorEnabled = new AtomicBoolean(false);
    private static final AtomicLong interceptedCount = new AtomicLong(0);
    private static final AtomicLong modifiedCount = new AtomicLong(0);
    private static final AtomicLong timeoutCount = new AtomicLong(0);
    
    // Queue for pending modification requests
    private static final BlockingQueue<PendingModification> pendingQueue = new LinkedBlockingQueue<>();
    private static final Map<String, CompletableFuture<ModificationResponse>> responseMap = new ConcurrentHashMap<>();
    
    // NEW: Response modification queue
    private static final BlockingQueue<PendingResponse> pendingResponseQueue = new LinkedBlockingQueue<>();
    private static final Map<String, CompletableFuture<ModificationResponse>> responseDecisionMap = new ConcurrentHashMap<>();
    private static final AtomicLong responsesIntercepted = new AtomicLong(0);
    private static final AtomicLong responsesModified = new AtomicLong(0);
    private static final AtomicLong responsesDropped = new AtomicLong(0);
    
    // NEW: WebSocket support
    private static final BlockingQueue<PendingWebSocket> pendingWebSocketQueue = new LinkedBlockingQueue<>();
    private static final Map<String, ProxyWebSocket> activeWebSockets = new ConcurrentHashMap<>();
    private static final AtomicLong webSocketsIntercepted = new AtomicLong(0);
    private static final AtomicLong webSocketMessagesIntercepted = new AtomicLong(0);
    
    // Static initialization
    private static ProxyRequestHandler requestHandler;
    private static ProxyResponseHandler responseHandler;
    private static ProxyWebSocketCreationHandler webSocketHandler;
    private static boolean handlersRegistered = false;
    
    // Registration management - CRITICAL FIX
    private static Registration requestHandlerRegistration;
    private static Registration responseHandlerRegistration;
    private static Registration webSocketHandlerRegistration;
    
    // Configuration
    private static final boolean USE_TIMEOUT = false; // Wait indefinitely for MCP response
    private static final long MODIFICATION_TIMEOUT_MS = 30000; // 30 second timeout (only if USE_TIMEOUT is true)
    
    private final MontoyaApi api;
    private final ObjectMapper objectMapper;
    
    static {
        // This will be set by the first instance
        staticApi = null;
        staticProxy = null;
    }
    
    public ProxyInterceptorTool(MontoyaApi api) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        
        // Initialize static handlers on first creation
        synchronized (ProxyInterceptorTool.class) {
            if (!handlersRegistered && api != null) {
                initializeHandlers(api);
            }
        }
    }
    
    private static void initializeHandlers(MontoyaApi api) {
        Proxy proxy = api.proxy();
        
        // Request handler for intercepting and modifying requests
        requestHandler = new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
                // Just pass through at this stage
                return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            }
            
            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
                if (!interceptorEnabled.get()) {
                    return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
                }
                
                interceptedCount.incrementAndGet();
                
                // Create a unique ID for this request
                String requestId = UUID.randomUUID().toString();
                HttpRequest request = interceptedRequest;
                Annotations annotations = interceptedRequest.annotations();
                
                // Create pending modification entry
                PendingModification pending = new PendingModification(
                    requestId,
                    request,
                    System.currentTimeMillis()
                );
                
                // Add to queue for MCP processing
                pendingQueue.offer(pending);
                
                // Create future for response
                CompletableFuture<ModificationResponse> future = new CompletableFuture<>();
                responseMap.put(requestId, future);
                
                try {
                    // Wait for MCP response - either with timeout or indefinitely
                    ModificationResponse response;
                    if (USE_TIMEOUT) {
                        response = future.get(MODIFICATION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    } else {
                        // Wait indefinitely until MCP provides a response
                        response = future.get();
                    }
                    
                    if (response != null && response.isModified()) {
                        modifiedCount.incrementAndGet();
                        
                        // Apply modifications
                        HttpRequest modifiedRequest = applyModifications(request, response);
                        
                        // Add annotations
                        annotations = annotations.withNotes("Modified by MCP: " + response.getDescription());
                        if (response.getHighlightColor() != null) {
                            annotations = annotations.withHighlightColor(response.getHighlightColor());
                        }
                        
                        // Handle special actions
                        if (response.shouldDrop()) {
                            return ProxyRequestToBeSentAction.drop();
                        }
                        
                        // Note: ProxyRequestToBeSentAction doesn't have intercept() method
                        // If intercept is needed, it must be done at RequestReceived stage
                        
                        return ProxyRequestToBeSentAction.continueWith(modifiedRequest, annotations);
                    } else {
                        // Response indicates no modification needed
                        annotations = annotations.withNotes("Inspected by MCP - No modification");
                        return ProxyRequestToBeSentAction.continueWith(request, annotations);
                    }
                } catch (TimeoutException e) {
                    timeoutCount.incrementAndGet();
                    annotations = annotations.withNotes("MCP timeout - request unmodified");
                    annotations = annotations.withHighlightColor(HighlightColor.GRAY);
                    return ProxyRequestToBeSentAction.continueWith(request, annotations);
                } catch (Exception e) {
                    annotations = annotations.withNotes("MCP error: " + e.getMessage());
                    annotations = annotations.withHighlightColor(HighlightColor.RED);
                    return ProxyRequestToBeSentAction.continueWith(request, annotations);
                } finally {
                    // Clean up
                    responseMap.remove(requestId);
                    pendingQueue.removeIf(p -> p.requestId.equals(requestId));
                }
            }
        };
        
        // Response handler with full modification queue
        responseHandler = new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                // Early response interception (before processing)
                if (!interceptorEnabled.get()) {
                    return ProxyResponseReceivedAction.continueWith(interceptedResponse);
                }
                // For now, just pass through at early stage
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }
            
            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                if (!interceptorEnabled.get()) {
                    return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
                }
                
                responsesIntercepted.incrementAndGet();
                
                // Create unique ID for this response
                String responseId = UUID.randomUUID().toString();
                HttpResponse response = interceptedResponse;
                Annotations annotations = interceptedResponse.annotations();
                
                // Create pending modification entry
                PendingResponse pending = new PendingResponse(
                    responseId,
                    response,
                    System.currentTimeMillis()
                );
                
                // Add to queue for MCP processing
                pendingResponseQueue.offer(pending);
                
                // Create future for response decision
                CompletableFuture<ModificationResponse> future = new CompletableFuture<>();
                responseDecisionMap.put(responseId, future);
                
                try {
                    // Wait for MCP response
                    ModificationResponse decision;
                    if (USE_TIMEOUT) {
                        decision = future.get(MODIFICATION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                    } else {
                        decision = future.get();
                    }
                    
                    if (decision != null && decision.isModified()) {
                        responsesModified.incrementAndGet();
                        
                        // Apply modifications to response
                        HttpResponse modifiedResponse = applyResponseModifications(response, decision);
                        
                        // Add annotations
                        annotations = annotations.withNotes("Response modified by MCP: " + decision.getDescription());
                        if (decision.getHighlightColor() != null) {
                            annotations = annotations.withHighlightColor(decision.getHighlightColor());
                        }
                        
                        // Handle special actions
                        if (decision.shouldDrop()) {
                            responsesDropped.incrementAndGet();
                            return ProxyResponseToBeSentAction.drop();
                        }
                        
                        return ProxyResponseToBeSentAction.continueWith(modifiedResponse, annotations);
                    } else {
                        annotations = annotations.withNotes("Response inspected by MCP - No modification");
                        return ProxyResponseToBeSentAction.continueWith(response, annotations);
                    }
                } catch (TimeoutException e) {
                    annotations = annotations.withNotes("MCP timeout - response unmodified");
                    return ProxyResponseToBeSentAction.continueWith(response, annotations);
                } catch (Exception e) {
                    return ProxyResponseToBeSentAction.continueWith(response);
                } finally {
                    // Clean up
                    responseDecisionMap.remove(responseId);
                    pendingResponseQueue.removeIf(p -> p.responseId.equals(responseId));
                }
            }
        };
        
        // NEW: WebSocket creation handler
        webSocketHandler = new ProxyWebSocketCreationHandler() {
            @Override
            public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
                if (!interceptorEnabled.get()) {
                    return;
                }
                
                webSocketsIntercepted.incrementAndGet();
                
                ProxyWebSocket proxyWebSocket = webSocketCreation.proxyWebSocket();
                String webSocketId = UUID.randomUUID().toString();
                
                // Store active WebSocket
                activeWebSockets.put(webSocketId, proxyWebSocket);
                
                // Add to queue for tracking
                PendingWebSocket pending = new PendingWebSocket(
                    webSocketId,
                    webSocketCreation.upgradeRequest(),
                    System.currentTimeMillis()
                );
                pendingWebSocketQueue.offer(pending);
                
                // Register message handler for this WebSocket
                proxyWebSocket.registerProxyMessageHandler(new ProxyMessageHandler() {
                    @Override
                    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedMessage) {
                        webSocketMessagesIntercepted.incrementAndGet();
                        // For now, just pass through
                        return TextMessageReceivedAction.continueWith(interceptedMessage);
                    }
                    
                    @Override
                    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedMessage) {
                        webSocketMessagesIntercepted.incrementAndGet();
                        // For now, just pass through
                        return TextMessageToBeSentAction.continueWith(interceptedMessage);
                    }
                    
                    @Override
                    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedMessage) {
                        webSocketMessagesIntercepted.incrementAndGet();
                        // For now, just pass through
                        return BinaryMessageReceivedAction.continueWith(interceptedMessage);
                    }
                    
                    @Override
                    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedMessage) {
                        webSocketMessagesIntercepted.incrementAndGet();
                        // For now, just pass through
                        return BinaryMessageToBeSentAction.continueWith(interceptedMessage);
                    }
                    
                    @Override
                    public void onClose() {
                        // Clean up when WebSocket closes
                        activeWebSockets.remove(webSocketId);
                        pendingWebSocketQueue.removeIf(p -> p.webSocketId.equals(webSocketId));
                    }
                });
            }
        };
        
        handlersRegistered = true;
    }
    
    private static HttpRequest applyModifications(HttpRequest original, ModificationResponse response) {
        HttpRequest modified = original;
        
        // Add headers
        if (response.getAddHeaders() != null) {
            for (Map.Entry<String, String> header : response.getAddHeaders().entrySet()) {
                modified = modified.withHeader(header.getKey(), header.getValue());
            }
        }
        
        // Remove headers
        if (response.getRemoveHeaders() != null) {
            for (String header : response.getRemoveHeaders()) {
                modified = modified.withRemovedHeader(header);
            }
        }
        
        // Replace body
        if (response.getReplaceBody() != null) {
            modified = modified.withBody(response.getReplaceBody());
        }
        
        // Update method
        if (response.getMethod() != null) {
            modified = modified.withMethod(response.getMethod());
        }
        
        // Update path
        if (response.getPath() != null) {
            modified = modified.withPath(response.getPath());
        }
        
        return modified;
    }
    
    // NEW: Apply modifications to response
    private static HttpResponse applyResponseModifications(HttpResponse original, ModificationResponse response) {
        HttpResponse modified = original;
        
        // Add headers
        if (response.getAddHeaders() != null) {
            for (Map.Entry<String, String> header : response.getAddHeaders().entrySet()) {
                modified = modified.withAddedHeader(header.getKey(), header.getValue());
            }
        }
        
        // Remove headers  
        if (response.getRemoveHeaders() != null) {
            for (String header : response.getRemoveHeaders()) {
                modified = modified.withRemovedHeader(header);
            }
        }
        
        // Replace body
        if (response.getReplaceBody() != null) {
            modified = modified.withBody(response.getReplaceBody());
        }
        
        // Update status code
        if (response.getStatusCode() != null) {
            modified = modified.withStatusCode(response.getStatusCode().shortValue());
        }
        
        // Update reason phrase
        if (response.getReasonPhrase() != null) {
            modified = modified.withReasonPhrase(response.getReasonPhrase());
        }
        
        return modified;
    }
    
    @Override
    public Map<String, Object> getToolInfo() {
        Map<String, Object> tool = new HashMap<>();
        tool.put("name", "burp_proxy_interceptor");
        tool.put("title", "Proxy Interceptor");
        tool.put("description", "Real-time proxy request interception and modification with event-driven control. " +
                "Use this to intercept requests as they pass through Burp Proxy, inspect them, and decide to forward, drop, or modify. " +
                "Actions: enable/disable (MCP interception), master_intercept_on/off (Burp UI button), " +
                "get_queue (pending requests), modify/forward/drop_request. Note: Response modification not yet implemented.");

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
        actionProp.put("enum", Arrays.asList("enable", "disable", "get_queue", 
                "modify_request", "forward_request", "drop_request", "get_stats", "clear_stats",
                "master_intercept_on", "master_intercept_off", "master_intercept_status"));
        actionProp.put("description", "The action to perform");
        properties.put("action", actionProp);
        
        Map<String, Object> requestIdProp = new HashMap<>();
        requestIdProp.put("type", "string");
        requestIdProp.put("description", "ID of the request to modify (from get_queue)");
        properties.put("request_id", requestIdProp);
        
        Map<String, Object> modificationsProp = new HashMap<>();
        modificationsProp.put("type", "object");
        modificationsProp.put("description", "Modifications to apply (add_headers, remove_headers, replace_body, method, path)");
        properties.put("modifications", modificationsProp);
        
        Map<String, Object> optionsProp = new HashMap<>();
        optionsProp.put("type", "object");
        optionsProp.put("description", "Options (drop, intercept_ui, highlight_color, description)");
        properties.put("options", optionsProp);
        
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
                case "get_queue":
                    return getQueuedRequests();
                case "modify_request":
                    return modifyRequest(args);
                case "forward_request":
                    return forwardRequest(args);
                case "drop_request":
                    return dropRequest(args);
                case "get_stats":
                    return getStatistics();
                case "clear_stats":
                    return clearStatistics();
                case "master_intercept_on":
                    return setMasterIntercept(true);
                case "master_intercept_off":
                    return setMasterIntercept(false);
                case "master_intercept_status":
                    return getMasterInterceptStatus();
                // NEW: Response actions
                case "get_response_queue":
                    return getResponseQueue();
                case "modify_response":
                    return modifyResponse(args);
                case "forward_response":
                    return forwardResponse(args);
                case "drop_response":
                    return dropResponse(args);
                // NEW: WebSocket actions  
                case "get_websocket_queue":
                    return getWebSocketQueue();
                case "get_websocket_history":
                    return getWebSocketHistory();
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    private Object enableInterceptor() {
        if (interceptorEnabled.get()) {
            return McpUtils.createSuccessResponse("⚠️ Proxy interceptor already enabled");
        }
        
        if (!handlersRegistered) {
            return McpUtils.createErrorResponse("Handlers not initialized. Please restart the extension.");
        }
        
        // Register handlers with proxy - FIXED: Store Registration objects
        requestHandlerRegistration = api.proxy().registerRequestHandler(requestHandler);
        responseHandlerRegistration = api.proxy().registerResponseHandler(responseHandler);
        webSocketHandlerRegistration = api.proxy().registerWebSocketCreationHandler(webSocketHandler);
        
        interceptorEnabled.set(true);
        
        return McpUtils.createSuccessResponse(
            "✅ **Proxy Interceptor Enabled**\n\n" +
            "Event-driven interception is now active.\n" +
            "⚠️ **IMPORTANT**: All requests will be held indefinitely until you:\n" +
            "  • `forward_request` - Send unmodified\n" +
            "  • `modify_request` - Apply changes and forward\n" +
            "  • `drop_request` - Block the request\n" +
            "\nUse `get_queue` to see pending requests."
        );
    }
    
    private Object disableInterceptor() {
        if (!interceptorEnabled.get()) {
            return McpUtils.createSuccessResponse("⚠️ Proxy interceptor already disabled");
        }
        
        interceptorEnabled.set(false);
        
        // CRITICAL FIX: Properly deregister handlers
        if (requestHandlerRegistration != null && requestHandlerRegistration.isRegistered()) {
            requestHandlerRegistration.deregister();
            requestHandlerRegistration = null;
        }
        if (responseHandlerRegistration != null && responseHandlerRegistration.isRegistered()) {
            responseHandlerRegistration.deregister();
            responseHandlerRegistration = null;
        }
        if (webSocketHandlerRegistration != null && webSocketHandlerRegistration.isRegistered()) {
            webSocketHandlerRegistration.deregister();
            webSocketHandlerRegistration = null;
        }
        
        // Clear pending queue
        pendingQueue.clear();
        
        // Cancel all pending futures
        for (CompletableFuture<ModificationResponse> future : responseMap.values()) {
            future.cancel(true);
        }
        responseMap.clear();
        
        return McpUtils.createSuccessResponse("❌ Proxy interceptor disabled and handlers deregistered");
    }
    
    private Object getQueuedRequests() {
        StringBuilder result = new StringBuilder();
        result.append("## 📋 Queued Requests for Modification\n\n");
        
        List<PendingModification> queue = new ArrayList<>(pendingQueue);
        
        if (queue.isEmpty()) {
            result.append("*No requests currently queued*\n");
        } else {
            result.append("**Queue Size:** ").append(queue.size()).append("\n\n");
            
            for (PendingModification pending : queue) {
                long age = System.currentTimeMillis() - pending.timestamp;
                result.append("### Request ID: `").append(pending.requestId).append("`\n");
                result.append("- **Method:** ").append(pending.request.method()).append("\n");
                result.append("- **URL:** ").append(pending.request.url()).append("\n");
                result.append("- **Age:** ").append(age).append("ms\n");
                
                if (age > MODIFICATION_TIMEOUT_MS) {
                    result.append("- **Status:** ⏱️ Will timeout\n");
                }
                
                result.append("\n");
            }
            
            result.append("**Note:** Requests timeout after ").append(MODIFICATION_TIMEOUT_MS).append("ms\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object modifyRequest(Map<String, Object> args) {
        String requestId = (String) args.get("request_id");
        
        if (requestId == null || requestId.isEmpty()) {
            return McpUtils.createErrorResponse("request_id is required");
        }
        
        CompletableFuture<ModificationResponse> future = responseMap.get(requestId);
        if (future == null) {
            return McpUtils.createErrorResponse("Request ID not found or already processed: " + requestId);
        }
        
        try {
            ModificationResponse response = new ModificationResponse();
            response.setModified(true);
            
            // Parse modifications
            Map<String, Object> modifications = (Map<String, Object>) args.get("modifications");
            if (modifications != null) {
                response.setAddHeaders((Map<String, String>) modifications.get("add_headers"));
                response.setRemoveHeaders((List<String>) modifications.get("remove_headers"));
                response.setReplaceBody((String) modifications.get("replace_body"));
                response.setMethod((String) modifications.get("method"));
                response.setPath((String) modifications.get("path"));
            }
            
            // Parse options
            Map<String, Object> options = (Map<String, Object>) args.get("options");
            if (options != null) {
                response.setDrop((Boolean) options.getOrDefault("drop", false));
                response.setIntercept((Boolean) options.getOrDefault("intercept_ui", false));
                response.setDescription((String) options.get("description"));
                
                String colorStr = (String) options.get("highlight_color");
                if (colorStr != null) {
                    try {
                        response.setHighlightColor(HighlightColor.valueOf(colorStr.toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        // Invalid color, ignore
                    }
                }
            }
            
            // Complete the future with the response
            future.complete(response);
            
            // Remove from pending queue
            pendingQueue.removeIf(p -> p.requestId.equals(requestId));
            
            return McpUtils.createSuccessResponse(
                "✅ **Modifications Applied**\n\n" +
                "Request ID: `" + requestId + "`\n" +
                "The request will be modified and forwarded."
            );
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to apply modifications: " + e.getMessage());
        }
    }
    
    private Object forwardRequest(Map<String, Object> args) {
        String requestId = (String) args.get("request_id");
        
        if (requestId == null || requestId.isEmpty()) {
            return McpUtils.createErrorResponse("request_id is required");
        }
        
        CompletableFuture<ModificationResponse> future = responseMap.get(requestId);
        if (future == null) {
            return McpUtils.createErrorResponse("Request ID not found or already processed: " + requestId);
        }
        
        try {
            // Create response indicating no modification
            ModificationResponse response = new ModificationResponse();
            response.setModified(false);
            response.setDescription("Forwarded unmodified by MCP");
            
            // Complete the future with the response
            future.complete(response);
            
            // Remove from pending queue
            pendingQueue.removeIf(p -> p.requestId.equals(requestId));
            
            return McpUtils.createSuccessResponse(
                "✅ **Request Forwarded**\n\n" +
                "Request ID: `" + requestId + "`\n" +
                "The request has been forwarded without modification."
            );
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to forward request: " + e.getMessage());
        }
    }
    
    private Object dropRequest(Map<String, Object> args) {
        String requestId = (String) args.get("request_id");
        
        if (requestId == null || requestId.isEmpty()) {
            return McpUtils.createErrorResponse("request_id is required");
        }
        
        CompletableFuture<ModificationResponse> future = responseMap.get(requestId);
        if (future == null) {
            return McpUtils.createErrorResponse("Request ID not found or already processed: " + requestId);
        }
        
        try {
            // Create response indicating drop
            ModificationResponse response = new ModificationResponse();
            response.setModified(true);
            response.setDrop(true);
            response.setDescription("Dropped by MCP");
            response.setHighlightColor(HighlightColor.RED);
            
            // Complete the future with the response
            future.complete(response);
            
            // Remove from pending queue
            pendingQueue.removeIf(p -> p.requestId.equals(requestId));
            
            return McpUtils.createSuccessResponse(
                "🚫 **Request Dropped**\n\n" +
                "Request ID: `" + requestId + "`\n" +
                "The request has been blocked and will not be sent."
            );
            
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to drop request: " + e.getMessage());
        }
    }
    
    private Object getStatistics() {
        StringBuilder result = new StringBuilder();
        result.append("## 📊 Proxy Interceptor Statistics\n\n");
        result.append("**Status:** ").append(interceptorEnabled.get() ? "✅ Enabled" : "❌ Disabled").append("\n");
        result.append("**Requests Intercepted:** ").append(interceptedCount.get()).append("\n");
        result.append("**Requests Modified:** ").append(modifiedCount.get()).append("\n");
        result.append("**Timeouts:** ").append(timeoutCount.get()).append("\n");
        result.append("**Queue Size:** ").append(pendingQueue.size()).append("\n");
        result.append("**Pending Responses:** ").append(responseMap.size()).append("\n");
        
        if (interceptedCount.get() > 0) {
            double modRate = (modifiedCount.get() * 100.0) / interceptedCount.get();
            double timeoutRate = (timeoutCount.get() * 100.0) / interceptedCount.get();
            result.append("\n**Modification Rate:** ").append(String.format("%.1f%%", modRate)).append("\n");
            result.append("**Timeout Rate:** ").append(String.format("%.1f%%", timeoutRate)).append("\n");
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object clearStatistics() {
        interceptedCount.set(0);
        modifiedCount.set(0);
        timeoutCount.set(0);
        
        return McpUtils.createSuccessResponse("✅ Statistics cleared");
    }
    
    // NEW FEATURE: Master intercept control
    private Object setMasterIntercept(boolean enable) {
        if (enable) {
            api.proxy().enableIntercept();
            return McpUtils.createSuccessResponse("✅ Master intercept enabled in Burp UI");
        } else {
            api.proxy().disableIntercept();
            return McpUtils.createSuccessResponse("❌ Master intercept disabled in Burp UI");
        }
    }
    
    private Object getMasterInterceptStatus() {
        boolean enabled = api.proxy().isInterceptEnabled();
        return McpUtils.createSuccessResponse(
            "Master intercept status: " + (enabled ? "✅ ENABLED" : "❌ DISABLED") + "\n\n" +
            "Note: This controls Burp's UI intercept button, separate from MCP interception."
        );
    }
    
    // NEW: Response queue methods
    private Object getResponseQueue() {
        StringBuilder result = new StringBuilder();
        result.append("## 📋 Pending Responses\n\n");
        
        List<PendingResponse> queue = new ArrayList<>(pendingResponseQueue);
        if (queue.isEmpty()) {
            result.append("*No responses currently queued*\n");
        } else {
            for (PendingResponse pending : queue) {
                result.append("**ID:** ").append(pending.responseId).append("\n");
                result.append("**Status:** ").append(pending.response.statusCode()).append("\n");
                long age = System.currentTimeMillis() - pending.timestamp;
                result.append("**Age:** ").append(age).append("ms\n");
                result.append("---\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object modifyResponse(Map<String, Object> args) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) {
            return McpUtils.createErrorResponse("Missing response_id parameter");
        }
        
        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) {
            return McpUtils.createErrorResponse("Response ID not found: " + responseId);
        }
        
        Map<String, Object> modifications = (Map<String, Object>) args.get("modifications");
        if (modifications == null) {
            return McpUtils.createErrorResponse("Missing modifications parameter");
        }
        
        ModificationResponse response = new ModificationResponse();
        response.setModified(true);
        response.setDescription("Modified via MCP");
        
        // Parse modifications
        if (modifications.containsKey("add_headers")) {
            response.setAddHeaders((Map<String, String>) modifications.get("add_headers"));
        }
        if (modifications.containsKey("remove_headers")) {
            response.setRemoveHeaders((List<String>) modifications.get("remove_headers"));
        }
        if (modifications.containsKey("replace_body")) {
            response.setReplaceBody((String) modifications.get("replace_body"));
        }
        if (modifications.containsKey("status_code")) {
            response.setStatusCode(((Number) modifications.get("status_code")).intValue());
        }
        if (modifications.containsKey("reason_phrase")) {
            response.setReasonPhrase((String) modifications.get("reason_phrase"));
        }
        
        future.complete(response);
        return McpUtils.createSuccessResponse("✅ Response modifications applied");
    }
    
    private Object forwardResponse(Map<String, Object> args) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) {
            return McpUtils.createErrorResponse("Missing response_id parameter");
        }
        
        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) {
            return McpUtils.createErrorResponse("Response ID not found: " + responseId);
        }
        
        ModificationResponse response = new ModificationResponse();
        response.setModified(false);
        future.complete(response);
        
        return McpUtils.createSuccessResponse("✅ Response forwarded unmodified");
    }
    
    private Object dropResponse(Map<String, Object> args) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) {
            return McpUtils.createErrorResponse("Missing response_id parameter");
        }
        
        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) {
            return McpUtils.createErrorResponse("Response ID not found: " + responseId);
        }
        
        ModificationResponse response = new ModificationResponse();
        response.setModified(true);
        response.setDrop(true);
        response.setDescription("Dropped via MCP");
        future.complete(response);
        
        return McpUtils.createSuccessResponse("✅ Response dropped");
    }
    
    // NEW: WebSocket methods
    private Object getWebSocketQueue() {
        StringBuilder result = new StringBuilder();
        result.append("## 🔌 Active WebSockets\n\n");
        
        List<PendingWebSocket> queue = new ArrayList<>(pendingWebSocketQueue);
        if (queue.isEmpty()) {
            result.append("*No active WebSocket connections*\n");
        } else {
            for (PendingWebSocket pending : queue) {
                result.append("**ID:** ").append(pending.webSocketId).append("\n");
                result.append("**Upgrade URL:** ").append(pending.upgradeRequest.url()).append("\n");
                long age = System.currentTimeMillis() - pending.timestamp;
                result.append("**Age:** ").append(age).append("ms\n");
                result.append("---\n");
            }
        }
        result.append("\n**Total WebSockets:** ").append(webSocketsIntercepted.get()).append("\n");
        result.append("**Total Messages:** ").append(webSocketMessagesIntercepted.get()).append("\n");
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getWebSocketHistory() {
        StringBuilder result = new StringBuilder();
        result.append("## 📜 WebSocket History\n\n");
        
        List<ProxyWebSocketMessage> history = api.proxy().webSocketHistory();
        int count = Math.min(history.size(), 20); // Limit to 20 most recent
        
        if (history.isEmpty()) {
            result.append("*No WebSocket messages in history*\n");
        } else {
            result.append("**Total messages:** ").append(history.size()).append("\n");
            result.append("**Showing:** ").append(count).append(" most recent\n\n");
            
            for (int i = history.size() - count; i < history.size(); i++) {
                ProxyWebSocketMessage msg = history.get(i);
                result.append("**Direction:** ").append(msg.direction()).append("\n");
                result.append("**Payload:** ");
                String payload = msg.payload().toString();
                if (payload.length() > 100) {
                    result.append(payload.substring(0, 100)).append("...");
                } else {
                    result.append(payload);
                }
                result.append("\n---\n");
            }
        }
        
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    // Helper classes
    private static class PendingModification {
        final String requestId;
        final HttpRequest request;
        final long timestamp;
        
        PendingModification(String requestId, HttpRequest request, long timestamp) {
            this.requestId = requestId;
            this.request = request;
            this.timestamp = timestamp;
        }
    }
    
    private static class PendingResponse {
        final String responseId;
        final HttpResponse response;
        final long timestamp;
        
        PendingResponse(String responseId, HttpResponse response, long timestamp) {
            this.responseId = responseId;
            this.response = response;
            this.timestamp = timestamp;
        }
    }
    
    private static class PendingWebSocket {
        final String webSocketId;
        final HttpRequest upgradeRequest;
        final long timestamp;
        
        PendingWebSocket(String webSocketId, HttpRequest upgradeRequest, long timestamp) {
            this.webSocketId = webSocketId;
            this.upgradeRequest = upgradeRequest;
            this.timestamp = timestamp;
        }
    }
    
    private static class ModificationResponse {
        private boolean modified = false;
        private Map<String, String> addHeaders;
        private List<String> removeHeaders;
        private String replaceBody;
        private String method;
        private String path;
        private boolean drop = false;
        private boolean intercept = false;
        private HighlightColor highlightColor;
        private String description;
        private Integer statusCode;
        private String reasonPhrase;
        
        // Getters and setters
        public boolean isModified() { return modified; }
        public void setModified(boolean modified) { this.modified = modified; }
        
        public Map<String, String> getAddHeaders() { return addHeaders; }
        public void setAddHeaders(Map<String, String> addHeaders) { this.addHeaders = addHeaders; }
        
        public List<String> getRemoveHeaders() { return removeHeaders; }
        public void setRemoveHeaders(List<String> removeHeaders) { this.removeHeaders = removeHeaders; }
        
        public String getReplaceBody() { return replaceBody; }
        public void setReplaceBody(String replaceBody) { this.replaceBody = replaceBody; }
        
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        
        public boolean shouldDrop() { return drop; }
        public void setDrop(boolean drop) { this.drop = drop; }
        
        public boolean shouldIntercept() { return intercept; }
        public void setIntercept(boolean intercept) { this.intercept = intercept; }
        
        public HighlightColor getHighlightColor() { return highlightColor; }
        public void setHighlightColor(HighlightColor color) { this.highlightColor = color; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public Integer getStatusCode() { return statusCode; }
        public void setStatusCode(Integer statusCode) { this.statusCode = statusCode; }
        
        public String getReasonPhrase() { return reasonPhrase; }
        public void setReasonPhrase(String reasonPhrase) { this.reasonPhrase = reasonPhrase; }
    }
}