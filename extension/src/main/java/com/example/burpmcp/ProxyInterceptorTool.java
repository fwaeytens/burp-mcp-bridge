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
    // Guards register/deregister of the three Registration fields above so a concurrent
    // enable/disable can't interleave and leak or double-register a handler.
    private static final Object registrationLock = new Object();
    
    // Configuration
    private static final boolean USE_TIMEOUT = true; // Protect Burp proxy threads from hanging
    private static final long MODIFICATION_TIMEOUT_MS = 30000; // 30 second timeout

    // Optional hold filter set on enable(). When any is non-null, ONLY requests matching
    // ALL set criteria are held; everything else passes through untouched. This keeps the
    // browser usable (only the targeted request is held) instead of hanging on every resource.
    private static volatile String filterPath = null;    // substring of URL, or regex when filterRegex
    private static volatile String filterMethod = null;  // exact HTTP method (case-insensitive)
    private static volatile String filterHost = null;    // substring of host
    private static volatile boolean filterRegex = false; // treat filterPath as a regex (matched against full URL)
    
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

                // Hold filter: when set, only matching requests are held; others pass through.
                if (!matchesHoldFilter(interceptedRequest)) {
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
        tool.put("title", "Proxy Interceptor (Browser Only)");
        tool.put("description", "MANUAL hold/modify/forward of BROWSER-PROXY traffic (requests through Burp's proxy listener — by default the agent's own Playwright browser traffic). " +
                "For automatic match/replace rules across ALL Burp tools, use burp_global_interceptor instead. For WebSocket frames, use burp_websocket_interceptor. " +
                "⚠️ Once 'enable' is on, every matching proxy request is held for up to 30s each, then auto-forwarded unmodified. " +
                "SCOPE THE HOLD: pass filter_path (URL substring, or regex with filter_regex=true), filter_method, and/or filter_host to 'enable' so ONLY the request you want is held and the rest of the page loads normally. With no filter, ALL requests are held. " +
                "⚠️ CRITICAL — TRIGGER HELD TRAFFIC NON-BLOCKING, or you deadlock: the agent cannot poll get_queue while it is blocked inside a synchronous browser_navigate/browser_click (the page waits on the held request). " +
                "PROVEN AGENT PATTERN (verified solving a PortSwigger lab): " +
                "(1) enable with a filter so the page stays usable, e.g. {action:'enable', filter_path:'/cart', filter_method:'POST'}; " +
                "(2) trigger the request fire-and-forget so the agent stays free — e.g. Playwright browser_evaluate running an UN-AWAITED fetch('/path',{method:'POST',body:...}), or a background curl through 127.0.0.1:8080; " +
                "(3) get_queue to read the held request and its request_id; " +
                "(4) modify_request (request_id + modifications{replace_body|add_headers|remove_headers|method|path}) which applies changes AND forwards, or forward_request / drop_request; " +
                "(5) disable (else the next navigation hangs). Keep the page otherwise idle so only your triggered request is held. " +
                "Actions: enable/disable (MCP interception), master_intercept_on/off (Burp UI button), " +
                "get_queue/modify_request/forward_request/drop_request (request flow), " +
                "get_response_queue/modify_response/forward_response/drop_response (response flow), " +
                "get_websocket_queue/get_websocket_history (WebSocket), get_stats/clear_stats.");

        // MCP 2025-06-18 annotations
        Map<String, Object> annotations = new HashMap<>();
        annotations.put("readOnlyHint", false);
        annotations.put("destructiveHint", false);
        annotations.put("idempotentHint", false);
        annotations.put("openWorldHint", true);
        annotations.put("title", "Proxy Interceptor (Browser Only)");
        tool.put("annotations", annotations);

        Map<String, Object> meta = new HashMap<>();
        meta.put("anthropic/searchHint", "intercept modify live request response");
        tool.put("_meta", meta);

        Map<String, Object> inputSchema = new HashMap<>();
        Map<String, Object> properties = new HashMap<>();

        Map<String, Object> actionProp = new HashMap<>();
        actionProp.put("type", "string");
        actionProp.put("enum", Arrays.asList("enable", "disable", "get_queue",
                "modify_request", "forward_request", "drop_request", "get_stats", "clear_stats",
                "master_intercept_on", "master_intercept_off", "master_intercept_status",
                "get_response_queue", "modify_response", "forward_response", "drop_response",
                "get_websocket_queue", "get_websocket_history"));
        actionProp.put("description", "The action to perform");
        properties.put("action", actionProp);
        
        Map<String, Object> requestIdProp = new HashMap<>();
        requestIdProp.put("type", "string");
        requestIdProp.put("description", "ID of the request to modify (from get_queue)");
        properties.put("request_id", requestIdProp);
        
        Map<String, Object> modificationsProp = new HashMap<>();
        modificationsProp.put("type", "object");
        modificationsProp.put("description", "Modifications object. Keys: add_headers (object {name:value}), remove_headers (array of names), replace_body (string), method (string), path (string). Only specified keys are modified.");
        properties.put("modifications", modificationsProp);
        
        Map<String, Object> optionsProp = new HashMap<>();
        optionsProp.put("type", "object");
        optionsProp.put("description", "Options object. Keys: drop (boolean — drop instead of forward), intercept_ui (boolean — also show in Burp UI), highlight_color (color name), description (string).");
        properties.put("options", optionsProp);

        // Optional hold filter (used with action=enable). When any is set, ONLY requests
        // matching ALL set criteria are held; everything else passes through untouched —
        // so the browser stays usable and only the request you care about is held.
        Map<String, Object> filterPathProp = new HashMap<>();
        filterPathProp.put("type", "string");
        filterPathProp.put("description", "enable only: hold requests whose URL contains this substring (e.g. \"/cart\"). With filter_regex=true, treated as a regex matched against the full URL.");
        properties.put("filter_path", filterPathProp);

        Map<String, Object> filterMethodProp = new HashMap<>();
        filterMethodProp.put("type", "string");
        filterMethodProp.put("description", "enable only: hold only requests with this HTTP method (e.g. \"POST\"). Case-insensitive.");
        properties.put("filter_method", filterMethodProp);

        Map<String, Object> filterHostProp = new HashMap<>();
        filterHostProp.put("type", "string");
        filterHostProp.put("description", "enable only: hold only requests whose host contains this substring.");
        properties.put("filter_host", filterHostProp);

        properties.put("filter_regex", McpUtils.createProperty("boolean",
            "enable only: treat filter_path as a regex (matched against the full URL) instead of a substring. Default false.", false));

        properties.put("verbose", McpUtils.createProperty("boolean",
            "If true, returns formatted markdown with sections and emoji. Default: compact JSON for token efficiency.", false));

        inputSchema.put("type", "object");
        inputSchema.put("properties", properties);
        inputSchema.put("required", Arrays.asList("action"));


        tool.put("inputSchema", inputSchema);
        return tool;
    }
    
    @SuppressWarnings("unchecked")
    @Override
    public Object execute(JsonNode arguments) throws Exception {
        Map<String, Object> args = objectMapper.convertValue(arguments, Map.class);
        String action = (String) args.get("action");
        boolean verbose = Boolean.TRUE.equals(args.get("verbose"));

        try {
            switch (action.toLowerCase()) {
                case "enable":
                    return enableInterceptor(args, verbose);
                case "disable":
                    return disableInterceptor(verbose);
                case "get_queue":
                    return getQueuedRequests(verbose);
                case "modify_request":
                    return modifyRequest(args, verbose);
                case "forward_request":
                    return forwardRequest(args, verbose);
                case "drop_request":
                    return dropRequest(args, verbose);
                case "get_stats":
                    return getStatistics(verbose);
                case "clear_stats":
                    return clearStatistics(verbose);
                case "master_intercept_on":
                    return setMasterIntercept(true, verbose);
                case "master_intercept_off":
                    return setMasterIntercept(false, verbose);
                case "master_intercept_status":
                    return getMasterInterceptStatus(verbose);
                case "get_response_queue":
                    return getResponseQueue(verbose);
                case "modify_response":
                    return modifyResponse(args, verbose);
                case "forward_response":
                    return forwardResponse(args, verbose);
                case "drop_response":
                    return dropResponse(args, verbose);
                case "get_websocket_queue":
                    return getWebSocketQueue(verbose);
                case "get_websocket_history":
                    return getWebSocketHistory(verbose);
                default:
                    return McpUtils.createErrorResponse("Unknown action: " + action);
            }
        } catch (Exception e) {
            return McpUtils.createErrorResponse("Error: " + e.getMessage());
        }
    }
    
    private Object enableInterceptor(Map<String, Object> args, boolean verbose) {
        if (!handlersRegistered) {
            return McpUtils.createErrorResponse("Handlers not initialized. Please restart the extension.");
        }

        // Read optional hold filter. When any criterion is set, only matching requests are held.
        String fPath = trimToNull(args.get("filter_path"));
        String fMethod = trimToNull(args.get("filter_method"));
        String fHost = trimToNull(args.get("filter_host"));
        boolean fRegex = Boolean.TRUE.equals(args.get("filter_regex"));
        // Validate regex early so a bad pattern fails the enable call rather than silently
        // holding nothing (or everything) at request time.
        if (fRegex && fPath != null) {
            try {
                java.util.regex.Pattern.compile(fPath);
            } catch (java.util.regex.PatternSyntaxException e) {
                return McpUtils.createErrorResponse("Invalid filter_path regex: " + e.getMessage());
            }
        }

        // Check-and-set inside the lock so two concurrent enables can't both pass the guard
        // and double-register handlers (leaking the first set).
        synchronized (registrationLock) {
            if (interceptorEnabled.get()) {
                if (!verbose) return McpUtils.createJsonResponse(Map.of("enabled", true, "alreadyEnabled", true));
                return McpUtils.createSuccessResponse("⚠️ Proxy interceptor already enabled");
            }
            filterPath = fPath;
            filterMethod = fMethod;
            filterHost = fHost;
            filterRegex = fRegex;
            requestHandlerRegistration = api.proxy().registerRequestHandler(requestHandler);
            responseHandlerRegistration = api.proxy().registerResponseHandler(responseHandler);
            webSocketHandlerRegistration = api.proxy().registerWebSocketCreationHandler(webSocketHandler);
            interceptorEnabled.set(true);
        }

        boolean filtered = fPath != null || fMethod != null || fHost != null;
        if (!verbose) {
            Map<String, Object> resp = new HashMap<>();
            resp.put("enabled", true);
            resp.put("alreadyEnabled", false);
            resp.put("holdFilter", describeFilter());
            return McpUtils.createJsonResponse(resp);
        }
        return McpUtils.createSuccessResponse(
            "✅ **Proxy Interceptor Enabled**\n\nEvent-driven interception is now active.\n" +
            (filtered
                ? "🎯 Hold filter active: " + describeFilter() + " — only matching requests are held; others pass through.\n"
                : "⚠️ NO filter set: ALL requests are held until you forward/modify/drop them. " +
                  "Tip: pass filter_path/filter_method/filter_host to hold only the request you care about.\n") +
            "Use get_queue to see pending requests.");
    }

    /** Returns true when the request should be held: no filter set, or all set criteria match. */
    private static boolean matchesHoldFilter(HttpRequest request) {
        String path = filterPath, method = filterMethod, host = filterHost;
        boolean regex = filterRegex;
        if (path == null && method == null && host == null) {
            return true; // backward-compatible: hold everything
        }
        if (method != null && !method.equalsIgnoreCase(request.method())) {
            return false;
        }
        if (host != null) {
            String h = request.httpService() != null ? request.httpService().host() : "";
            if (h == null || !h.contains(host)) {
                return false;
            }
        }
        if (path != null) {
            String url = request.url();
            if (regex) {
                if (url == null || !java.util.regex.Pattern.compile(path).matcher(url).find()) {
                    return false;
                }
            } else if (url == null || !url.contains(path)) {
                return false;
            }
        }
        return true;
    }

    private static String describeFilter() {
        if (filterPath == null && filterMethod == null && filterHost == null) {
            return "none (holding all requests)";
        }
        StringBuilder sb = new StringBuilder();
        if (filterMethod != null) sb.append("method=").append(filterMethod).append(' ');
        if (filterHost != null) sb.append("host~").append(filterHost).append(' ');
        if (filterPath != null) sb.append(filterRegex ? "url=~/" : "url~").append(filterPath).append(filterRegex ? "/" : "");
        return sb.toString().trim();
    }

    private static String trimToNull(Object o) {
        if (!(o instanceof String s)) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private Object disableInterceptor(boolean verbose) {
        // Check-and-clear inside the lock so enable/disable can't interleave on the flag
        // and registration fields.
        synchronized (registrationLock) {
            if (!interceptorEnabled.get()) {
                if (!verbose) return McpUtils.createJsonResponse(Map.of("enabled", false, "alreadyDisabled", true));
                return McpUtils.createSuccessResponse("⚠️ Proxy interceptor already disabled");
            }
            interceptorEnabled.set(false);
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

            // Queue/future cleanup stays INSIDE the lock: deregister only stops new
            // interceptions, but a concurrent enable that re-registers handlers could start
            // queueing fresh requests/responses before this cleanup runs and have them wiped.
            // Holding the lock blocks enable until cleanup is done.
            pendingQueue.clear();
            for (CompletableFuture<ModificationResponse> future : responseMap.values()) {
                future.cancel(true);
            }
            responseMap.clear();

            // Response side — mirror the request-side cleanup. Without this, response handler
            // threads blocked in future.get() stay stuck until the 30s timeout and these
            // collections leak entries across a disable/re-enable cycle. cancel(true) unblocks
            // them immediately; the handler's catch forwards the original (unmodified) response.
            pendingResponseQueue.clear();
            for (CompletableFuture<ModificationResponse> future : responseDecisionMap.values()) {
                future.cancel(true);
            }
            responseDecisionMap.clear();
            pendingWebSocketQueue.clear();

            // Clear the hold filter so a later filterless enable() reverts to holding all.
            filterPath = null;
            filterMethod = null;
            filterHost = null;
            filterRegex = false;
        }

        if (!verbose) return McpUtils.createJsonResponse(Map.of("enabled", false));
        return McpUtils.createSuccessResponse("❌ Proxy interceptor disabled and handlers deregistered");
    }

    private Object getQueuedRequests(boolean verbose) {
        List<PendingModification> queue = new ArrayList<>(pendingQueue);
        long now = System.currentTimeMillis();

        List<Map<String, Object>> jsonQueue = new ArrayList<>();
        for (PendingModification pending : queue) {
            long age = now - pending.timestamp;
            Map<String, Object> e = new HashMap<>();
            e.put("requestId", pending.requestId);
            e.put("method", pending.request.method());
            e.put("url", pending.request.url());
            e.put("ageMs", age);
            e.put("willTimeout", age > MODIFICATION_TIMEOUT_MS);
            jsonQueue.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("queueSize", queue.size());
            data.put("timeoutMs", MODIFICATION_TIMEOUT_MS);
            data.put("queue", jsonQueue);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## 📋 Queued Requests for Modification\n\n");
        if (queue.isEmpty()) {
            result.append("*No requests currently queued*\n");
        } else {
            result.append("**Queue Size:** ").append(queue.size()).append("\n\n");
            for (Map<String, Object> e : jsonQueue) {
                result.append("### Request ID: `").append(e.get("requestId")).append("`\n");
                result.append("- **Method:** ").append(e.get("method")).append("\n");
                result.append("- **URL:** ").append(e.get("url")).append("\n");
                result.append("- **Age:** ").append(e.get("ageMs")).append("ms\n");
                if ((Boolean) e.get("willTimeout")) result.append("- **Status:** ⏱️ Will timeout\n");
                result.append("\n");
            }
        }
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    @SuppressWarnings("unchecked")
    private Object modifyRequest(Map<String, Object> args, boolean verbose) {
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
            
            if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "modify_request", "requestId", requestId));
            return McpUtils.createSuccessResponse(
                "✅ **Modifications Applied**\n\nRequest ID: `" + requestId + "`\nThe request will be modified and forwarded."
            );

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to apply modifications: " + e.getMessage());
        }
    }

    private Object forwardRequest(Map<String, Object> args, boolean verbose) {
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
            
            if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "forward_request", "requestId", requestId));
            return McpUtils.createSuccessResponse(
                "✅ **Request Forwarded**\n\nRequest ID: `" + requestId + "`\nThe request has been forwarded without modification."
            );

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to forward request: " + e.getMessage());
        }
    }

    private Object dropRequest(Map<String, Object> args, boolean verbose) {
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
            
            if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "drop_request", "requestId", requestId));
            return McpUtils.createSuccessResponse(
                "🚫 **Request Dropped**\n\nRequest ID: `" + requestId + "`\nThe request has been blocked and will not be sent."
            );

        } catch (Exception e) {
            return McpUtils.createErrorResponse("Failed to drop request: " + e.getMessage());
        }
    }

    private Object getStatistics(boolean verbose) {
        long intercepted = interceptedCount.get();
        long modified = modifiedCount.get();
        long timeouts = timeoutCount.get();

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("enabled", interceptorEnabled.get());
            data.put("holdFilter", describeFilter());
            data.put("intercepted", intercepted);
            data.put("modified", modified);
            data.put("timeouts", timeouts);
            data.put("queueSize", pendingQueue.size());
            data.put("pendingResponses", responseMap.size());
            if (intercepted > 0) {
                data.put("modificationRatePercent", Math.round((modified * 1000.0) / intercepted) / 10.0);
                data.put("timeoutRatePercent", Math.round((timeouts * 1000.0) / intercepted) / 10.0);
            }
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## 📊 Proxy Interceptor Statistics\n\n");
        result.append("**Status:** ").append(interceptorEnabled.get() ? "✅ Enabled" : "❌ Disabled").append("\n");
        result.append("**Requests Intercepted:** ").append(intercepted).append("\n");
        result.append("**Requests Modified:** ").append(modified).append("\n");
        result.append("**Timeouts:** ").append(timeouts).append("\n");
        result.append("**Queue Size:** ").append(pendingQueue.size()).append("\n");
        result.append("**Pending Responses:** ").append(responseMap.size()).append("\n");
        if (intercepted > 0) {
            double modRate = (modified * 100.0) / intercepted;
            double timeoutRate = (timeouts * 100.0) / intercepted;
            result.append("\n**Modification Rate:** ").append(String.format("%.1f%%", modRate)).append("\n");
            result.append("**Timeout Rate:** ").append(String.format("%.1f%%", timeoutRate)).append("\n");
        }
        return McpUtils.createSuccessResponse(result.toString());
    }

    private Object clearStatistics(boolean verbose) {
        interceptedCount.set(0);
        modifiedCount.set(0);
        timeoutCount.set(0);
        if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "clear_stats"));
        return McpUtils.createSuccessResponse("✅ Statistics cleared");
    }

    private Object setMasterIntercept(boolean enable, boolean verbose) {
        if (enable) api.proxy().enableIntercept();
        else api.proxy().disableIntercept();
        if (!verbose) return McpUtils.createJsonResponse(Map.of("masterInterceptEnabled", enable));
        return McpUtils.createSuccessResponse(enable
            ? "✅ Master intercept enabled in Burp UI"
            : "❌ Master intercept disabled in Burp UI");
    }

    private Object getMasterInterceptStatus(boolean verbose) {
        boolean enabled = api.proxy().isInterceptEnabled();
        if (!verbose) return McpUtils.createJsonResponse(Map.of("masterInterceptEnabled", enabled));
        return McpUtils.createSuccessResponse(
            "Master intercept status: " + (enabled ? "✅ ENABLED" : "❌ DISABLED") + "\n\n" +
            "Note: This controls Burp's UI intercept button, separate from MCP interception.");
    }

    private Object getResponseQueue(boolean verbose) {
        List<PendingResponse> queue = new ArrayList<>(pendingResponseQueue);
        long now = System.currentTimeMillis();

        List<Map<String, Object>> jsonQueue = new ArrayList<>();
        for (PendingResponse pending : queue) {
            Map<String, Object> e = new HashMap<>();
            e.put("id", pending.responseId);
            e.put("statusCode", pending.response.statusCode());
            e.put("ageMs", now - pending.timestamp);
            jsonQueue.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("queueSize", queue.size());
            data.put("queue", jsonQueue);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## 📋 Pending Responses\n\n");
        if (queue.isEmpty()) {
            result.append("*No responses currently queued*\n");
        } else {
            for (Map<String, Object> e : jsonQueue) {
                result.append("**ID:** ").append(e.get("id")).append("\n");
                result.append("**Status:** ").append(e.get("statusCode")).append("\n");
                result.append("**Age:** ").append(e.get("ageMs")).append("ms\n---\n");
            }
        }
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    @SuppressWarnings("unchecked")
    private Object modifyResponse(Map<String, Object> args, boolean verbose) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) return McpUtils.createErrorResponse("Missing response_id parameter");

        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) return McpUtils.createErrorResponse("Response ID not found: " + responseId);

        Map<String, Object> modifications = (Map<String, Object>) args.get("modifications");
        if (modifications == null) return McpUtils.createErrorResponse("Missing modifications parameter");

        ModificationResponse response = new ModificationResponse();
        response.setModified(true);
        response.setDescription("Modified via MCP");
        if (modifications.containsKey("add_headers")) response.setAddHeaders((Map<String, String>) modifications.get("add_headers"));
        if (modifications.containsKey("remove_headers")) response.setRemoveHeaders((List<String>) modifications.get("remove_headers"));
        if (modifications.containsKey("replace_body")) response.setReplaceBody((String) modifications.get("replace_body"));
        if (modifications.containsKey("status_code")) response.setStatusCode(((Number) modifications.get("status_code")).intValue());
        if (modifications.containsKey("reason_phrase")) response.setReasonPhrase((String) modifications.get("reason_phrase"));

        future.complete(response);
        if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "modify_response", "responseId", responseId));
        return McpUtils.createSuccessResponse("✅ Response modifications applied");
    }

    private Object forwardResponse(Map<String, Object> args, boolean verbose) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) return McpUtils.createErrorResponse("Missing response_id parameter");
        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) return McpUtils.createErrorResponse("Response ID not found: " + responseId);

        ModificationResponse response = new ModificationResponse();
        response.setModified(false);
        future.complete(response);
        if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "forward_response", "responseId", responseId));
        return McpUtils.createSuccessResponse("✅ Response forwarded unmodified");
    }

    private Object dropResponse(Map<String, Object> args, boolean verbose) {
        String responseId = (String) args.get("request_id");
        if (responseId == null) return McpUtils.createErrorResponse("Missing response_id parameter");
        CompletableFuture<ModificationResponse> future = responseDecisionMap.get(responseId);
        if (future == null) return McpUtils.createErrorResponse("Response ID not found: " + responseId);

        ModificationResponse response = new ModificationResponse();
        response.setModified(true);
        response.setDrop(true);
        response.setDescription("Dropped via MCP");
        future.complete(response);
        if (!verbose) return McpUtils.createJsonResponse(Map.of("success", true, "action", "drop_response", "responseId", responseId));
        return McpUtils.createSuccessResponse("✅ Response dropped");
    }
    
    private Object getWebSocketQueue(boolean verbose) {
        List<PendingWebSocket> queue = new ArrayList<>(pendingWebSocketQueue);
        long now = System.currentTimeMillis();

        List<Map<String, Object>> jsonQueue = new ArrayList<>();
        for (PendingWebSocket pending : queue) {
            Map<String, Object> e = new HashMap<>();
            e.put("id", pending.webSocketId);
            e.put("upgradeUrl", pending.upgradeRequest.url());
            e.put("ageMs", now - pending.timestamp);
            jsonQueue.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("activeCount", queue.size());
            data.put("totalIntercepted", webSocketsIntercepted.get());
            data.put("totalMessages", webSocketMessagesIntercepted.get());
            data.put("active", jsonQueue);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## 🔌 Active WebSockets\n\n");
        if (queue.isEmpty()) {
            result.append("*No active WebSocket connections*\n");
        } else {
            for (Map<String, Object> e : jsonQueue) {
                result.append("**ID:** ").append(e.get("id")).append("\n");
                result.append("**Upgrade URL:** ").append(e.get("upgradeUrl")).append("\n");
                result.append("**Age:** ").append(e.get("ageMs")).append("ms\n---\n");
            }
        }
        result.append("\n**Total WebSockets:** ").append(webSocketsIntercepted.get()).append("\n");
        result.append("**Total Messages:** ").append(webSocketMessagesIntercepted.get()).append("\n");
        return McpUtils.createSuccessResponse(result.toString());
    }
    
    private Object getWebSocketHistory(boolean verbose) {
        List<ProxyWebSocketMessage> history = api.proxy().webSocketHistory();
        int count = Math.min(history.size(), 20);

        List<Map<String, Object>> jsonHistory = new ArrayList<>();
        for (int i = history.size() - count; i < history.size(); i++) {
            ProxyWebSocketMessage msg = history.get(i);
            String payload = msg.payload().toString();
            Map<String, Object> e = new HashMap<>();
            e.put("direction", msg.direction().toString());
            if (payload.length() > 100) {
                e.put("payload", payload.substring(0, 100));
                e.put("payloadTruncated", true);
            } else {
                e.put("payload", payload);
            }
            jsonHistory.add(e);
        }

        if (!verbose) {
            Map<String, Object> data = new HashMap<>();
            data.put("totalMessages", history.size());
            data.put("showing", count);
            data.put("messages", jsonHistory);
            return McpUtils.createJsonResponse(data);
        }

        StringBuilder result = new StringBuilder();
        result.append("## 📜 WebSocket History\n\n");
        if (history.isEmpty()) {
            result.append("*No WebSocket messages in history*\n");
        } else {
            result.append("**Total messages:** ").append(history.size()).append("\n");
            result.append("**Showing:** ").append(count).append(" most recent\n\n");
            for (Map<String, Object> e : jsonHistory) {
                result.append("**Direction:** ").append(e.get("direction")).append("\n");
                result.append("**Payload:** ").append(e.get("payload"));
                if (Boolean.TRUE.equals(e.get("payloadTruncated"))) result.append("...");
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